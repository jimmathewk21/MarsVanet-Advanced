"""Mock-based tests for the Ryu/OpenFlow Methodology 2 adapter."""

from collections import defaultdict, deque
from pathlib import Path
import sys
import types
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import _bootstrap  # noqa: F401


def _install_ryu_fakes():
    """Provide the small Ryu surface needed to import the controller."""
    if "ryu" in sys.modules:
        return

    ryu = types.ModuleType("ryu")
    base = types.ModuleType("ryu.base")
    app_manager = types.ModuleType("ryu.base.app_manager")
    controller = types.ModuleType("ryu.controller")
    ofp_event = types.ModuleType("ryu.controller.ofp_event")
    handler = types.ModuleType("ryu.controller.handler")
    ofproto = types.ModuleType("ryu.ofproto")
    ofproto13 = types.ModuleType("ryu.ofproto.ofproto_v1_3")
    lib = types.ModuleType("ryu.lib")
    hub = types.ModuleType("ryu.lib.hub")
    packet_pkg = types.ModuleType("ryu.lib.packet")
    packet_mod = types.ModuleType("ryu.lib.packet.packet")
    ethernet_mod = types.ModuleType("ryu.lib.packet.ethernet")
    ipv4_mod = types.ModuleType("ryu.lib.packet.ipv4")
    udp_mod = types.ModuleType("ryu.lib.packet.udp")

    class RyuApp:
        def __init__(self, *args, **kwargs):
            self.logger = SimpleNamespace(
                debug=lambda *a, **k: None,
                info=lambda *a, **k: None,
                warning=lambda *a, **k: None,
                error=lambda *a, **k: None,
            )

    app_manager.RyuApp = RyuApp
    base.app_manager = app_manager

    for event_name in (
        "EventOFPSwitchFeatures", "EventOFPStateChange", "EventOFPErrorMsg",
        "EventOFPPacketIn", "EventOFPFlowStatsReply",
        "EventOFPMeterStatsReply", "EventOFPBarrierReply",
    ):
        setattr(ofp_event, event_name, type(event_name, (), {}))
    handler.MAIN_DISPATCHER = "main"
    handler.CONFIG_DISPATCHER = "config"
    handler.DEAD_DISPATCHER = "dead"
    handler.set_ev_cls = lambda *args, **kwargs: (lambda fn: fn)
    controller.ofp_event = ofp_event
    ofproto13.OFP_VERSION = 4
    ofproto.ofproto_v1_3 = ofproto13

    class Ethernet:
        pass

    class IPv4:
        pass

    class UDP:
        pass

    class Packet:
        def __init__(self, data):
            self.data = data

        def get_protocol(self, protocol):
            return self.data.get(protocol)

    packet_mod.Packet = Packet
    ethernet_mod.ethernet = Ethernet
    ipv4_mod.ipv4 = IPv4
    udp_mod.udp = UDP
    packet_pkg.packet = packet_mod
    packet_pkg.ethernet = ethernet_mod
    packet_pkg.ipv4 = ipv4_mod
    packet_pkg.udp = udp_mod
    hub.spawn = lambda fn, *args, **kwargs: None
    hub.sleep = lambda seconds: None
    lib.hub = hub
    lib.packet = packet_pkg

    for module_name, module in (
        ("ryu", ryu),
        ("ryu.base", base),
        ("ryu.base.app_manager", app_manager),
        ("ryu.controller", controller),
        ("ryu.controller.ofp_event", ofp_event),
        ("ryu.controller.handler", handler),
        ("ryu.ofproto", ofproto),
        ("ryu.ofproto.ofproto_v1_3", ofproto13),
        ("ryu.lib", lib),
        ("ryu.lib.hub", hub),
        ("ryu.lib.packet", packet_pkg),
        ("ryu.lib.packet.packet", packet_mod),
        ("ryu.lib.packet.ethernet", ethernet_mod),
        ("ryu.lib.packet.ipv4", ipv4_mod),
        ("ryu.lib.packet.udp", udp_mod),
    ):
        sys.modules[module_name] = module


_install_ryu_fakes()

import dos_defense_v2 as controller_module
import mobility_detector as md
from med2_config import Med2Config


class FakeMatch(dict):
    pass


class FakeParser:
    def OFPMatch(self, **fields):
        return FakeMatch(fields)

    def OFPFlowMod(self, **kwargs):
        return SimpleNamespace(kind="flow_mod", **kwargs)

    def OFPMeterBandDrop(self, **kwargs):
        return SimpleNamespace(kind="meter_band_drop", **kwargs)

    def OFPMeterMod(self, **kwargs):
        return SimpleNamespace(kind="meter_mod", **kwargs)

    def OFPInstructionMeter(self, meter_id):
        return SimpleNamespace(kind="meter_instruction", meter_id=meter_id)

    def OFPInstructionActions(self, instruction_type, actions):
        return SimpleNamespace(
            kind="actions_instruction", type=instruction_type, actions=actions
        )

    def OFPActionOutput(self, port, max_len=None):
        return SimpleNamespace(kind="output", port=port, max_len=max_len)

    def OFPPacketOut(self, **kwargs):
        return SimpleNamespace(kind="packet_out", **kwargs)

    def OFPFlowStatsRequest(self, *args):
        return SimpleNamespace(kind="flow_stats_request", args=args)

    def OFPMeterStatsRequest(self, *args):
        return SimpleNamespace(kind="meter_stats_request", args=args)

    def OFPBarrierRequest(self, datapath):
        return SimpleNamespace(kind="barrier_request", datapath=datapath)


class FakeOfproto:
    OFPMF_KBPS = 1
    OFPMF_BURST = 4
    OFPMF_STATS = 8
    OFPMC_ADD = 0
    OFPMC_MODIFY = 1
    OFPMC_DELETE = 2
    OFPFC_DELETE_STRICT = 4
    OFPIT_APPLY_ACTIONS = 4
    OFPP_CONTROLLER = 0xFFFFFFFD
    OFPP_FLOOD = 0xFFFFFFFB
    OFP_NO_BUFFER = 0xFFFFFFFF
    OFPTT_ALL = 0xFF
    OFPP_ANY = 0xFFFFFFFF
    OFPG_ANY = 0xFFFFFFFF
    OFPM_ALL = 0xFFFFFFFF
    OFPMPF_REPLY_MORE = 1
    OFPET_METER_MOD_FAILED = 10
    OFPMMFC_METER_EXISTS = 1


class FakeDatapath:
    def __init__(self, dpid=2):
        self.id = dpid
        self.ofproto = FakeOfproto()
        self.ofproto_parser = FakeParser()
        self.sent = []
        self._xid = 100

    def set_xid(self, message):
        message.xid = self._xid
        self._xid += 1
        return message.xid

    def send_msg(self, message):
        self.sent.append(message)


def _stat(entry, packet_count, table_id=controller_module.METER_FLOW_TABLE,
          instructions=()):
    return SimpleNamespace(
        cookie=entry["cookie"],
        priority=controller_module.METER_FLOW_PRIORITY,
        table_id=table_id,
        match=FakeMatch(entry["match"]),
        packet_count=packet_count,
        instructions=instructions,
    )


class ControllerAdapterTest(unittest.TestCase):
    def make_controller(self, **overrides):
        cfg = Med2Config(
            ap2_dpid=2,
            stats_poll_seconds=1.0,
            stage1_dwell_seconds=1.0,
            meter_hard_timeout=15,
            base_threshold_pps=10.0,
            **overrides,
        )
        controller = controller_module.DOSDefense.__new__(
            controller_module.DOSDefense
        )
        controller.cfg = cfg
        controller.logger = SimpleNamespace(
            debug=lambda *a, **k: None,
            info=lambda *a, **k: None,
            warning=lambda *a, **k: None,
            error=lambda *a, **k: None,
        )
        controller.mac_to_port = defaultdict(dict)
        controller.datapaths = {}
        controller.rate_trackers = {}
        controller.source_state = {}
        controller.installed_meters = defaultdict(set)
        controller.meter_ids = {}
        controller.flow_cookies = {}
        controller.active_meter_flows = {}
        controller.flow_install_pending = {}
        controller.flow_stat_samples = {}
        controller.flow_stats_inflight = {}
        controller.meter_stats_inflight = {}
        controller.stats_next_poll = {}
        controller.stats_backoff = defaultdict(int)
        controller.meter_stats_enabled = defaultdict(lambda: True)
        controller.meter_stats = {}
        controller.meter_stats_cursor = defaultdict(int)
        controller.meter_specs = {}
        controller.meter_add_requests = {}
        controller.retired_meters = {}
        controller.datapath_generations = defaultdict(int)
        controller.barrier_requests = {}
        controller.reconcile_state = {}
        controller._local_xid = 1
        controller.mobility_records = []
        controller.handover_events = deque()
        controller.handover_rate = 0.0
        controller.start_time = 0.0
        controller.handover_path = Path("missing-handover.csv")
        return controller

    def install_and_activate(self, controller, datapath, source):
        controller.install_meter(datapath, source)
        barrier = next(
            message for message in reversed(datapath.sent)
            if message.kind == "barrier_request"
        )
        controller.barrier_reply_handler(SimpleNamespace(
            msg=SimpleNamespace(datapath=datapath, xid=barrier.xid)
        ))

    def test_meter_flow_forwards_once_and_has_identity(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        self.install_and_activate(controller, datapath, "10.0.1.3")
        flow_mods = [m for m in datapath.sent if m.kind == "flow_mod"]
        self.assertEqual(len(flow_mods), 2)
        for flow in flow_mods:
            actions = flow.instructions[1].actions
            self.assertEqual([action.port for action in actions], [2])
            self.assertNotEqual(flow.cookie, 0)
        meter_mods = [m for m in datapath.sent if m.kind == "meter_mod"]
        self.assertEqual(len(meter_mods), 2)
        self.assertNotEqual(meter_mods[0].meter_id, meter_mods[1].meter_id)
        self.assertTrue(meter_mods[0].flags & FakeOfproto.OFPMF_STATS)
        self.assertTrue(meter_mods[0].flags & FakeOfproto.OFPMF_BURST)

    def _packet_event(self, datapath, source):
        eth = sys.modules["ryu.lib.packet.ethernet"].ethernet
        ip = sys.modules["ryu.lib.packet.ipv4"].ipv4
        udp = sys.modules["ryu.lib.packet.udp"].udp
        data = {
            eth: SimpleNamespace(src="aa", dst="bb"),
            ip: SimpleNamespace(src=source, dst="10.0.0.2"),
            udp: SimpleNamespace(src_port=1, dst_port=2),
        }
        msg = SimpleNamespace(
            datapath=datapath,
            match=FakeMatch(in_port=1),
            data=data,
            buffer_id=FakeOfproto.OFP_NO_BUFFER,
        )
        return SimpleNamespace(msg=msg)

    def test_normal_packet_in_still_forwards(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        controller.packet_in_handler(self._packet_event(datapath, "10.0.0.3"))
        self.assertTrue(any(m.kind == "packet_out" for m in datapath.sent))

    def test_metered_packet_in_does_not_duplicate_packet_out(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        datapath.sent.clear()
        controller.source_state[(2, "10.0.0.3")] = md.SourceState(
            stage=md.STAGE_METER, metered_at=0.0
        )
        controller.packet_in_handler(self._packet_event(datapath, "10.0.0.3"))
        self.assertFalse(any(m.kind == "packet_out" for m in datapath.sent))

    def test_poll_requests_are_cookie_scoped_and_non_overlapping(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 10.0)
        controller._send_flow_stats_request(datapath, 10.5)
        controller._send_meter_stats_request(datapath, 10.0)
        self.assertEqual(
            len([m for m in datapath.sent if m.kind == "flow_stats_request"]), 1
        )
        request = next(m for m in datapath.sent if m.kind == "flow_stats_request")
        self.assertEqual(request.args[5], controller_module.METER_FLOW_COOKIE_PREFIX)
        self.assertEqual(request.args[6], controller_module.METER_FLOW_COOKIE_MASK)
        self.assertEqual(
            len([m for m in datapath.sent if m.kind == "meter_stats_request"]), 1
        )
        meter_request = next(m for m in datapath.sent
                             if m.kind == "meter_stats_request")
        self.assertEqual(meter_request.args[2],
                         controller._meter_id_for(2, "10.0.0.3"))

    def test_meter_stats_reply_is_telemetry_only(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        meter_id = controller.active_meter_flows[(2, "10.0.0.3")]["meter_id"]
        controller._send_meter_stats_request(datapath, 10.0)
        request = controller.meter_stats_inflight[2]
        stat = SimpleNamespace(
            meter_id=meter_id,
            flow_count=1,
            packet_in_count=200,
            byte_in_count=12000,
            band_stats=(SimpleNamespace(packet_band_count=150),),
        )
        controller.meter_stats_reply_handler(SimpleNamespace(
            msg=SimpleNamespace(datapath=datapath, xid=request["xid"], body=(stat,), flags=0)
        ))
        self.assertEqual(controller.meter_stats[(2, meter_id)]["packet_in_count"], 200)
        self.assertIn((2, "10.0.0.3"), controller.active_meter_flows)
        self.assertNotIn(2, controller.meter_stats_inflight)

    def test_poll_request_failure_is_retryable(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        datapath.send_msg = MagicMock(side_effect=OSError("disconnected"))
        controller._send_flow_stats_request(datapath, 10.0)
        self.assertNotIn(2, controller.flow_stats_inflight)

    def test_counter_delta_uses_monotonic_rate(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 99.0)
        entry = controller.active_meter_flows[(2, "10.0.0.3")]
        controller._apply_polled_rate = MagicMock()
        with patch.object(controller_module.time, "monotonic", side_effect=[100.0, 102.0]):
            controller._process_flow_stat(datapath, _stat(entry, 100))
            controller._process_flow_stat(datapath, _stat(entry, 160))
        controller._apply_polled_rate.assert_called_once_with(
            datapath, "10.0.0.3", 30.0
        )

    def test_counter_reset_only_rebaselines(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 99.0)
        entry = controller.active_meter_flows[(2, "10.0.0.3")]
        controller._apply_polled_rate = MagicMock()
        with patch.object(controller_module.time, "monotonic", side_effect=[100.0, 101.0]):
            controller._process_flow_stat(datapath, _stat(entry, 100))
            controller._process_flow_stat(datapath, _stat(entry, 5))
        controller._apply_polled_rate.assert_not_called()
        self.assertEqual(controller.flow_stat_samples[(2, "10.0.0.3")][0], 5)

    def test_meter_drop_with_persistent_ingress_reaches_block_after_dwell(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        state = controller.source_state[(2, "10.0.0.3")] = md.SourceState(
            stage=md.STAGE_METER, metered_at=100.0
        )
        with patch.object(controller_module.time, "time", return_value=102.0):
            controller._apply_polled_rate(datapath, "10.0.0.3", 100.0)
        self.assertEqual(state.stage, md.STAGE_BLOCK)
        self.assertFalse((2, "10.0.0.3") in controller.active_meter_flows)
        self.assertTrue(any(m.kind == "flow_mod" and m.priority == 100
                            for m in datapath.sent))

    def test_multipart_reply_waits_for_final_part(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 10.0)
        request = controller.flow_stats_inflight[2]
        partial = SimpleNamespace(
            datapath=datapath, xid=request["xid"], body=(),
            flags=FakeOfproto.OFPMPF_REPLY_MORE
        )
        controller.flow_stats_reply_handler(SimpleNamespace(msg=partial))
        self.assertIn(2, controller.flow_stats_inflight)
        final = SimpleNamespace(datapath=datapath, xid=request["xid"], body=(), flags=0)
        with patch.object(controller_module.time, "monotonic", return_value=10.5):
            controller.flow_stats_reply_handler(SimpleNamespace(msg=final))
        self.assertNotIn(2, controller.flow_stats_inflight)

    def test_missing_flow_resets_meter_stage(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller.source_state[(2, "10.0.0.3")] = md.SourceState(
            stage=md.STAGE_METER, metered_at=1.0
        )
        controller.active_meter_flows[(2, "10.0.0.3")]["installed_monotonic"] = 0.0
        controller._send_flow_stats_request(datapath, 0.0)
        request = controller.flow_stats_inflight[2]
        with patch.object(controller_module.time, "monotonic", return_value=10.0):
            controller.flow_stats_reply_handler(SimpleNamespace(msg=SimpleNamespace(
                datapath=datapath, xid=request["xid"], body=(), flags=0
            )))
        self.assertEqual(
            controller.source_state[(2, "10.0.0.3")].stage, md.STAGE_NORMAL
        )
        self.assertNotIn((2, "10.0.0.3"), controller.active_meter_flows)

    def test_disconnect_clears_active_flow_and_allows_reconnect(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        controller.datapaths[2] = datapath
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller.state_change_handler(SimpleNamespace(
            datapath=datapath, state="dead"
        ))
        self.assertNotIn(2, controller.datapaths)
        self.assertFalse(controller.active_meter_flows)
        self.assertFalse(controller.installed_meters)

    def test_block_expiry_and_idle_packet_recover(self):
        controller = self.make_controller(
            stage2_block_seconds=1, detector_reset_seconds=1
        )
        datapath = FakeDatapath()
        key = (2, "10.0.0.3")
        controller.source_state[key] = md.SourceState(
            stage=md.STAGE_BLOCK, blocked_at=100.0, last_seen=100.0
        )
        with patch.object(controller_module.time, "time", return_value=103.0):
            controller._handle_detection(datapath, "10.0.0.3")
        self.assertEqual(controller.source_state[key].stage, md.STAGE_NORMAL)

    def test_reconnect_reconciles_only_owned_meter_flow_and_meter(self):
        controller = self.make_controller()
        old_datapath = FakeDatapath()
        controller._register_datapath(old_datapath)
        self.install_and_activate(controller, old_datapath, "10.0.0.3")
        controller.state_change_handler(SimpleNamespace(
            datapath=old_datapath, state="dead"
        ))
        datapath = FakeDatapath()
        controller._register_datapath(datapath)
        request = controller.flow_stats_inflight[2]
        stale_cookie = controller_module.METER_FLOW_COOKIE_PREFIX | 0x1234
        stale_meter = SimpleNamespace(meter_id=321)
        owned = SimpleNamespace(
            cookie=stale_cookie,
            priority=controller_module.METER_FLOW_PRIORITY,
            table_id=controller_module.METER_FLOW_TABLE,
            match=FakeMatch({
                "in_port": 1, "eth_type": 0x0800, "ip_proto": 17,
                "ipv4_src": "10.0.0.9", "ipv4_dst": "10.0.0.2",
            }),
            instructions=(stale_meter,),
        )
        unrelated = SimpleNamespace(
            cookie=0x55, priority=50, table_id=0, match=FakeMatch({}),
            instructions=(),
        )
        controller.flow_stats_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=request["xid"], body=(owned, unrelated), flags=0
        )))
        deletes = [m for m in datapath.sent if m.kind == "flow_mod" and
                   getattr(m, "command", None) == FakeOfproto.OFPFC_DELETE_STRICT]
        self.assertEqual(len(deletes), 1)
        self.assertEqual(deletes[0].cookie, stale_cookie)
        flow_barrier = next(m for m in reversed(datapath.sent)
                            if m.kind == "barrier_request")
        controller.barrier_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=flow_barrier.xid
        )))
        self.assertTrue(any(m.kind == "meter_mod" and
                            m.command == FakeOfproto.OFPMC_DELETE and
                            m.meter_id == 321 for m in datapath.sent))
        meter_barrier = next(m for m in reversed(datapath.sent)
                             if m.kind == "barrier_request")
        controller.barrier_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=meter_barrier.xid
        )))
        self.assertNotIn(2, controller.reconcile_state)

    def test_xid_timeout_and_delayed_reply_are_ignored(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 0.0)
        xid_one = controller.flow_stats_inflight[2]["xid"]
        controller._send_flow_stats_request(datapath, 3.0)
        self.assertNotIn(2, controller.flow_stats_inflight)
        controller._send_flow_stats_request(datapath, 5.0)
        xid_two = controller.flow_stats_inflight[2]["xid"]
        self.assertNotEqual(xid_one, xid_two)
        entry = controller.active_meter_flows[(2, "10.0.0.3")]
        delayed = _stat(entry, 100)
        controller.flow_stats_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=xid_one, body=(delayed,), flags=0
        )))
        self.assertNotIn((2, "10.0.0.3"), controller.flow_stat_samples)
        controller.flow_stats_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=xid_two, body=(delayed,),
            flags=FakeOfproto.OFPMPF_REPLY_MORE
        )))
        self.assertIn(2, controller.flow_stats_inflight)
        controller.flow_stats_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=xid_two, body=(), flags=0
        )))
        self.assertNotIn(2, controller.flow_stats_inflight)

    def test_unsupported_meter_stats_disables_optional_telemetry(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_meter_stats_request(datapath, 0.0)
        xid = controller.meter_stats_inflight[2]["xid"]
        controller.error_msg_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=xid,
            type=FakeOfproto.OFPET_METER_MOD_FAILED,
            code=99,
        )))
        self.assertFalse(controller.meter_stats_enabled[2])
        count = len([m for m in datapath.sent if m.kind == "meter_stats_request"])
        controller._send_meter_stats_request(datapath, 10.0)
        self.assertEqual(count, len([m for m in datapath.sent
                                    if m.kind == "meter_stats_request"]))

    def test_meter_add_conflict_reconciles_with_modify(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        controller.install_meter(datapath, "10.0.0.3")
        meter_add = next(m for m in datapath.sent
                         if m.kind == "meter_mod" and
                         m.command == FakeOfproto.OFPMC_ADD)
        controller.error_msg_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=meter_add.xid,
            type=FakeOfproto.OFPET_METER_MOD_FAILED,
            code=FakeOfproto.OFPMMFC_METER_EXISTS,
        )))
        self.assertTrue(any(m.kind == "meter_mod" and
                            m.command == FakeOfproto.OFPMC_MODIFY
                            for m in datapath.sent))

    def test_meter_lifecycle_stops_polling_and_deletes_retired_meter(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        key = (2, "10.0.0.3")
        controller.source_state[key] = md.SourceState(
            stage=md.STAGE_METER, metered_at=100.0
        )
        with patch.object(controller_module.time, "time", return_value=102.0):
            controller._apply_polled_rate(datapath, "10.0.0.3", 100.0)
        meter_id = controller.retired_meters[(2, controller._meter_id_for(2, "10.0.0.3"))]["meter_id"]
        self.assertNotIn(key, controller.active_meter_flows)
        self.assertFalse(controller.installed_meters[2])
        retired = next(iter(controller.retired_meters.values()))
        controller._expire_local_meter_flows(retired["delete_at"] + 1.0)
        self.assertTrue(any(m.kind == "meter_mod" and
                            m.command == FakeOfproto.OFPMC_DELETE and
                            m.meter_id == meter_id for m in datapath.sent))
        before = len([m for m in datapath.sent if m.kind == "meter_stats_request"])
        controller._send_meter_stats_request(datapath, retired["delete_at"] + 2.0)
        self.assertEqual(before, len([m for m in datapath.sent
                                      if m.kind == "meter_stats_request"]))

    def test_installation_race_forwards_packet_once_then_suppresses_active(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        controller.install_meter(datapath, "10.0.0.3")
        key = (2, "10.0.0.3")
        controller.source_state[key] = md.SourceState(stage=md.STAGE_METER)
        barrier = next(m for m in datapath.sent if m.kind == "barrier_request")
        datapath.sent.clear()
        controller.packet_in_handler(self._packet_event(datapath, "10.0.0.3"))
        self.assertEqual(len([m for m in datapath.sent if m.kind == "packet_out"]), 1)
        controller.barrier_reply_handler(SimpleNamespace(msg=SimpleNamespace(
            datapath=datapath, xid=barrier.xid
        )))
        datapath.sent.clear()
        controller.packet_in_handler(self._packet_event(datapath, "10.0.0.3"))
        self.assertFalse(any(m.kind == "packet_out" for m in datapath.sent))

    def test_table_mismatch_is_not_a_flow_stat_match(self):
        controller = self.make_controller()
        datapath = FakeDatapath()
        self.install_and_activate(controller, datapath, "10.0.0.3")
        controller._send_flow_stats_request(datapath, 0.0)
        entry = controller.active_meter_flows[(2, "10.0.0.3")]
        controller._process_flow_stat(datapath, _stat(entry, 100, table_id=1))
        self.assertNotIn((2, "10.0.0.3"), controller.flow_stat_samples)


if __name__ == "__main__":
    unittest.main()
