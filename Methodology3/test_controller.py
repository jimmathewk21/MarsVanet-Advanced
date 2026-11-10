import json
import unittest
from types import SimpleNamespace as NS
from unittest.mock import patch

from openflow_test_support import Datapath, load_controller

controller = load_controller()


class TestController(unittest.TestCase):
    def setUp(self):
        self.app = controller.ReputationSDNController()
        self.dp = self.connect(1)
        self.dp.sent.clear()

    def tearDown(self):
        self.app.close()

    def connect(self, dpid):
        dp = Datapath(dpid)
        self.app.switch_features_handler(NS(msg=NS(datapath=dp)))
        self.drain(dp)
        return dp

    def reply(self, dp, xid):
        self.app.barrier_reply_handler(NS(msg=NS(datapath=dp, xid=xid)))

    def drain(self, dp):
        for _ in range(50):
            pending = [tx for tx in self.app.pending.values() if tx.datapath is dp]
            if not pending:
                return
            self.reply(dp, pending[0].barrier)
        self.fail("transactions did not settle")

    def send(self, timestamp=1, vehicle_id="sta1", source="10.0.0.1", dp=None, **fields):
        data = dict(vehicle_id=vehicle_id, timestamp=timestamp, x=0, y=0, speed=0)
        data.update(fields)
        return self.app.receive_safety_message(dp or self.dp, source, json.dumps(data).encode())

    def score(self, score, vehicle_id="sta1", dp=None):
        self.app.processor.reputation.get_vehicle(vehicle_id).score = score
        self.app.reconcile(dp or self.dp, vehicle_id)

    def meters(self, dp=None):
        return [msg for msg in (dp or self.dp).sent if msg.kind == "meter"]

    def flows(self, dp=None):
        return [msg for msg in (dp or self.dp).sent if msg.kind == "flow"]

    def test_valid_message_normal_reputation(self):
        result = self.send()
        self.assertTrue(result.consistent)
        self.assertEqual(result.reputation, 1)
        self.assertEqual(self.meters(), [])

    def test_malformed_does_not_change_reputation(self):
        before = self.app.processor.reputation.get_vehicle("sta1").total_messages
        self.assertIsNone(self.app.receive_safety_message(self.dp, "10.0.0.1", b"[]"))
        self.assertEqual(self.app.processor.reputation.get_vehicle("sta1").total_messages, before)
        self.assertEqual(self.app.processor.checker.previous_messages, {})

    def test_identity_mismatch_and_unknown_identity(self):
        for vid, source in (("sta2", "10.0.0.1"), ("unknown", "10.0.0.1"), ("sta1", "10.0.0.99")):
            self.assertIsNone(self.send(vehicle_id=vid, source=source))
        self.assertTrue(all(v.total_messages == 0 for v in self.app.processor.reputation.vehicles.values()))
        self.assertEqual(self.app.processor.checker.previous_messages, {})
        self.assertEqual(self.dp.sent, [])

    def test_progressive_deterioration_and_recovery(self):
        self.send()
        actions = []
        for timestamp in range(2, 9):
            actions.append(self.send(timestamp, speed=100).action)
            self.drain(self.dp)
        for action in ("MONITOR", "LIGHT_THROTTLE", "HEAVY_THROTTLE", "SEVERE_THROTTLE"):
            self.assertIn(action, actions)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 100)
        for timestamp in range(9, 259):
            result = self.send(timestamp)
            self.drain(self.dp)
        self.assertEqual(result.reputation, 1)
        self.assertNotIn((1, "sta1"), self.app.processor.mitigation.installed_meters)
        rates = [m.bands[0].rate for m in self.meters() if m.bands]
        self.assertTrue({100, 200, 500}.issubset(rates))
        self.assertEqual(self.meters()[-1].command, self.dp.ofproto.OFPMC_DELETE)

    def test_meter_add_requires_two_barriers(self):
        self.score(.5)
        self.assertEqual(self.meters()[0].command, self.dp.ofproto.OFPMC_ADD)
        self.assertEqual(self.meters()[0].bands[0].rate, 500)
        self.assertEqual(self.flows(), [])  # Cannot reference an unconfirmed meter.
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.reply(self.dp, self.app.pending[(1, "sta1")].barrier)
        self.assertEqual(self.flows()[0].match, dict(eth_type=0x0800, ipv4_src="10.0.0.1"))
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.drain(self.dp)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 500)

    def test_modify_and_remove_ordering(self):
        self.score(.5)
        self.drain(self.dp)
        self.dp.sent.clear()
        self.score(.3)
        self.assertEqual(self.meters()[0].command, self.dp.ofproto.OFPMC_MODIFY)
        self.assertEqual(self.meters()[0].bands[0].rate, 200)
        self.drain(self.dp)
        self.dp.sent.clear()
        self.score(.9)
        deletion = self.flows()[0]
        self.assertEqual(deletion.command, self.dp.ofproto.OFPFC_DELETE)
        self.assertEqual(deletion.cookie_mask, self.app.COOKIE_MASK)
        self.assertEqual(deletion.match["ipv4_src"], "10.0.0.1")
        self.assertEqual(self.meters(), [])  # Remove references before the meter.
        self.drain(self.dp)
        self.assertEqual(self.meters()[0].command, self.dp.ofproto.OFPMC_DELETE)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})

    def test_latest_decision_wins_during_pending_add(self):
        self.score(.5)
        self.score(1)
        self.assertEqual(len(self.meters()), 1)
        self.drain(self.dp)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.assertEqual(self.meters()[-1].command, self.dp.ofproto.OFPMC_DELETE)

    def test_independent_vehicles_and_source_specific_flows(self):
        self.send(speed=100)
        self.assertEqual(self.send(vehicle_id="sta2", source="10.0.0.2").reputation, 1)
        self.score(.5, "sta1")
        self.score(.3, "sta3")
        self.drain(self.dp)
        self.assertEqual({f.match["ipv4_src"] for f in self.flows()}, {"10.0.0.1", "10.0.0.3"})
        self.assertEqual(len({m.meter_id for m in self.meters()}), 2)
        self.assertNotIn((1, "sta2"), self.app.processor.mitigation.installed_meters)

    def test_handover_retains_history_and_replication(self):
        second = self.connect(0x1000000000000002)
        self.send()
        for timestamp in range(2, 5):
            self.send(timestamp, speed=100)
        self.drain(self.dp)
        self.drain(second)
        before = self.app.processor.reputation.get_vehicle("sta1").score
        result = self.send(5, dp=second)
        self.assertEqual(result.reputation, before)
        self.assertEqual(self.app.processor.reputation.get_vehicle("sta1").total_messages, 5)
        self.assertEqual(self.app.processor.checker.previous_messages["sta1"].timestamp, 5)
        states = self.app.processor.mitigation.installed_meters
        self.assertEqual(states[(self.dp.id, "sta1")], states[(second.id, "sta1")])
        self.assertTrue(all("in_port" not in f.match for f in self.flows() + self.flows(second)))

    def test_switch_reconnect_and_late_old_session_events(self):
        self.score(.3)
        self.drain(self.dp)
        replacement = self.connect(self.dp.id)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 200)
        self.assertEqual(self.meters(replacement)[-1].command, replacement.ofproto.OFPMC_ADD)
        self.app.state_change_handler(NS(datapath=self.dp, state=controller.DEAD_DISPATCHER))
        self.app.error_handler(NS(msg=NS(datapath=self.dp, xid=1, type=12, code=1)))
        self.reply(self.dp, 1)
        self.assertIs(self.app.datapaths[1], replacement)
        self.assertIn(1, self.app.ready)

    def test_disconnect_forgets_enforcement_only(self):
        self.score(.3)
        self.drain(self.dp)
        self.app.state_change_handler(NS(datapath=self.dp, state=controller.DEAD_DISPATCHER))
        self.assertNotIn(1, self.app.datapaths)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.assertEqual(self.app.processor.reputation.get_vehicle("sta1").score, .3)

    def test_reset_fences_inflight_operations_before_cleanup(self):
        self.score(.5)
        self.dp.sent.clear()
        self.app._reset_switch(self.dp)
        self.assertEqual([m.kind for m in self.dp.sent], ["barrier"])
        self.reply(self.dp, self.app.pending[(1, None)].barrier)
        cleanup = self.flows()[0]
        self.assertEqual(cleanup.command, self.dp.ofproto.OFPFC_DELETE)
        self.assertEqual(cleanup.cookie, self.app.COOKIE)
        self.assertEqual(cleanup.cookie_mask, self.app.COOKIE_MASK)
        self.drain(self.dp)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 500)

    def test_meter_error_retries_without_false_confirmation(self):
        self.score(.5)
        failed = self.meters()[0]
        self.app.error_handler(NS(msg=NS(datapath=self.dp, xid=failed.xid, type=12, code=1)))
        self.drain(self.dp)
        self.assertNotIn(1, self.app.ready)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.app.maintenance(now=self.app.retry_at[1] + 1)
        self.drain(self.dp)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 500)

    def test_flow_error_does_not_confirm_meter_enforcement(self):
        self.score(.5)
        self.reply(self.dp, self.app.pending[(1, "sta1")].barrier)
        failed = self.flows()[0]
        self.app.error_handler(NS(msg=NS(datapath=self.dp, xid=failed.xid, type=3, code=0)))
        self.drain(self.dp)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.assertNotIn(1, self.app.ready)

    def test_timeout_and_stale_barrier(self):
        self.score(.5)
        tx = self.app.pending[(1, "sta1")]
        self.app.maintenance(now=tx.started + 6)
        self.reply(self.dp, tx.barrier)
        self.assertEqual(self.app.processor.mitigation.installed_meters, {})
        self.assertNotIn(1, self.app.ready)
        self.app.maintenance(now=self.app.retry_at[1] + 1)
        self.drain(self.dp)
        self.assertIn(1, self.app.ready)

    def test_periodic_refresh_reasserts_flows_and_pipeline(self):
        self.score(.5)
        self.drain(self.dp)
        self.dp.sent.clear()
        self.app.maintenance(now=self.app.refresh_at[1] + 1)
        self.assertEqual(self.meters()[0].command, self.dp.ofproto.OFPMC_MODIFY)
        self.drain(self.dp)
        self.assertTrue(any(f.command == 0 and f.match.get("ipv4_src") == "10.0.0.1" for f in self.flows()))
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 500)
        self.assertTrue(any(f.match.get("udp_dst") == 5005 for f in self.flows()))

    def test_missing_meter_during_refresh_is_recreated(self):
        self.score(.5)
        self.drain(self.dp)
        self.dp.sent.clear()
        self.app.maintenance(now=self.app.refresh_at[1] + 1)
        modification = self.meters()[0]
        self.app.error_handler(NS(msg=NS(datapath=self.dp, xid=modification.xid,
                                        type=12, code=3)))
        self.drain(self.dp)
        self.app.maintenance(now=self.app.retry_at[1] + 1)
        self.drain(self.dp)
        self.assertEqual(self.meters()[-1].command, self.dp.ofproto.OFPMC_ADD)
        self.assertEqual(self.app.processor.mitigation.installed_meters[(1, "sta1")], 500)

    def test_send_failure_schedules_reset(self):
        with patch.object(self.dp, "send_msg", return_value=False):
            self.score(.5)
        self.assertNotIn(1, self.app.ready)
        self.assertIn(1, self.app.retry_at)
        self.assertEqual(self.app.pending, {})

    def test_pipeline_cannot_bypass_meter_via_learning_or_packetout(self):
        baseline = self.app._baseline(self.dp)
        safety = next(f for f in baseline if f.priority == self.app.SAFETY_PRIORITY)
        self.assertEqual(safety.table_id, 0)
        self.assertEqual(safety.match["udp_dst"], 5005)
        self.assertEqual([i.kind for i in safety.instructions], ["actions"])
        self.assertEqual(safety.instructions[0].actions[0].port, self.dp.ofproto.OFPP_CONTROLLER)
        forwarding = next(f for f in baseline if f.table_id == 1)
        self.assertEqual(forwarding.instructions[0].actions[0].port, self.dp.ofproto.OFPP_NORMAL)
        self.score(0)
        self.drain(self.dp)
        enforced = self.flows()[0]
        self.assertEqual(enforced.table_id, 0)
        self.assertLess(enforced.priority, safety.priority)
        self.assertEqual([i.kind for i in enforced.instructions], ["meter_instruction", "goto"])
        self.assertEqual(enforced.instructions[-1].table_id, 1)
        self.assertTrue(all(m.bands[0].rate > 0 for m in self.meters() if m.bands))
        self.assertTrue(all(f.instructions for f in baseline + self.flows() if f.command == 0))
        self.assertTrue(all(m.kind != "packet_out" for m in self.dp.sent))

    def packet_event(self, payload=None, **ip_fields):
        payload = payload or json.dumps(dict(vehicle_id="sta1", timestamp=1, x=0, y=0, speed=0)).encode()
        ip = NS(src="10.0.0.1", offset=0, flags=0, total_length=28 + len(payload), header_length=5)
        ip.__dict__.update(ip_fields)
        datagram = NS(dst_port=5005, total_length=8 + len(payload))
        protocols = {controller.ethernet.ethernet: NS(), controller.ipv4.ipv4: ip,
                     controller.udp.udp: datagram}
        pkt = NS(get_protocol=protocols.get, protocols=list(protocols.values()) + [payload])
        ev = NS(msg=NS(datapath=self.dp, total_len=100, data=b"x" * 100))
        return ev, pkt

    def test_packet_in_valid_safety_message_is_consumed(self):
        ev, pkt = self.packet_event()
        with patch.object(controller.packet, "Packet", return_value=pkt):
            self.app.packet_in_handler(ev)
        self.assertEqual(self.app.processor.reputation.get_vehicle("sta1").total_messages, 1)
        self.assertEqual(self.dp.sent, [])

    def test_dynamic_wireless_ports_support_same_ap_forwarding(self):
        port = NS(port_no=17, name=b"ap1-wlan1\x00")
        self.app.port_description_handler(NS(msg=NS(
            datapath=self.dp, body=[port], flags=1)))
        self.assertEqual(self.app.wireless_ports[1], set())
        self.app.port_description_handler(NS(msg=NS(
            datapath=self.dp, body=[NS(port_no=23, name=b"ap1-eth1")], flags=0)))
        self.drain(self.dp)
        hairpin = next(f for f in self.flows() if f.table_id == 1 and f.priority == 10)
        self.assertEqual(hairpin.match, {"in_port": 17})
        self.assertEqual([a.port for a in hairpin.instructions[0].actions],
                         [self.dp.ofproto.OFPP_NORMAL, self.dp.ofproto.OFPP_IN_PORT])
        self.app.port_status_handler(NS(msg=NS(datapath=self.dp, desc=port,
                                             reason=self.dp.ofproto.OFPPR_DELETE)))
        self.drain(self.dp)
        self.assertEqual(self.app.wireless_ports[1], set())

    def test_packet_in_rejects_fragments_truncation_lengths_and_other_ports(self):
        for fields in ({"offset": 1}, {"flags": 1}, {"total_length": 2}):
            ev, pkt = self.packet_event(**fields)
            with patch.object(controller.packet, "Packet", return_value=pkt):
                self.app.packet_in_handler(ev)
        ev, pkt = self.packet_event()
        ev.msg.total_len = 101
        self.app.packet_in_handler(ev)
        ev, pkt = self.packet_event()
        pkt.protocols[2].dst_port = 9999
        with patch.object(controller.packet, "Packet", return_value=pkt):
            self.app.packet_in_handler(ev)
        self.assertEqual(self.app.processor.reputation.get_vehicle("sta1").total_messages, 0)


if __name__ == "__main__":
    unittest.main()
