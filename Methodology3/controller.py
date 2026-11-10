"""Independent OpenFlow 1.3 reputation controller for the OVS VANET testbed."""

import sys
import time
import re
from dataclasses import dataclass, field
from pathlib import Path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.ofproto import ofproto_v1_3

sys.path.insert(0, str(Path(__file__).resolve().parent))
from progressive_mitigation import EnforcementOperation
from safety_messages import SAFETY_MESSAGE_PORT, VEHICLE_IPS, parse_safety_message
from vehicle_processor import VehicleProcessor


@dataclass
class Transaction:
    datapath: object
    batches: list
    operation: object = None
    xids: set = field(default_factory=set)
    barrier: int = None
    started: float = 0.0
    failed: bool = False


class ReputationSDNController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]
    SAFETY_MESSAGE_PORT = SAFETY_MESSAGE_PORT
    VEHICLE_IPS = VEHICLE_IPS
    COOKIE = 0x4D33000000000000
    COOKIE_MASK = 0xFFFF000000000000
    SAFETY_PRIORITY = 300
    METER_PRIORITY = 200
    BARRIER_TIMEOUT = 5.0
    RETRY_SECONDS = 2.0
    REFRESH_SECONDS = 10.0

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.processor = VehicleProcessor()
        # Reserve deterministic meter IDs 1000..1002 across controller restarts.
        for vehicle_id in sorted(self.VEHICLE_IPS):
            self.processor.mitigation.get_meter_id(vehicle_id)
        self.datapaths = {}
        self.ready = set()
        self.pending = {}
        self.retry_at = {}
        self.refresh_at = {}
        self.wireless_ports = {}
        self.port_descriptions = {}
        self.worker = hub.spawn(self._maintenance_loop)
        self.logger.info("Methodology 3 started: identities=%s", self.VEHICLE_IPS)

    def close(self):
        hub.kill(self.worker)
        super().close()

    def _flow(self, dp, table, priority, match, instructions):
        return dp.ofproto_parser.OFPFlowMod(
            datapath=dp, cookie=self.COOKIE, table_id=table,
            priority=priority, match=match, instructions=instructions,
        )

    def _delete_flows(self, dp, match=None, table=None):
        p, o = dp.ofproto_parser, dp.ofproto
        return p.OFPFlowMod(
            datapath=dp, cookie=self.COOKIE, cookie_mask=self.COOKIE_MASK,
            command=o.OFPFC_DELETE, table_id=o.OFPTT_ALL if table is None else table,
            match=p.OFPMatch() if match is None else match,
            out_port=o.OFPP_ANY, out_group=o.OFPG_ANY,
        )

    def _meter(self, dp, vehicle_id, command, rate=None):
        p, o = dp.ofproto_parser, dp.ofproto
        return p.OFPMeterMod(
            datapath=dp, command=command, flags=o.OFPMF_KBPS | o.OFPMF_STATS,
            meter_id=self.processor.mitigation.get_meter_id(vehicle_id),
            bands=[] if rate is None else [p.OFPMeterBandDrop(rate=rate, burst_size=0)],
        )

    def _baseline(self, dp):
        p, o = dp.ofproto_parser, dp.ofproto
        flows = [
            self._flow(dp, 0, self.SAFETY_PRIORITY, p.OFPMatch(
                eth_type=0x0800, ip_proto=17, udp_dst=self.SAFETY_MESSAGE_PORT,
            ), [p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, [
                p.OFPActionOutput(o.OFPP_CONTROLLER, o.OFPCML_NO_BUFFER),
            ])]),
            self._flow(dp, 0, 0, p.OFPMatch(), [p.OFPInstructionGotoTable(1)]),
            self._flow(dp, 1, 0, p.OFPMatch(), [
                p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, [
                    p.OFPActionOutput(o.OFPP_NORMAL),
                ]),
            ]),
        ]
        # An isolated BSS shares one OVS radio ingress. NORMAL never outputs
        # back to ingress, so explicitly hairpin it using the discovered port.
        for port in self.wireless_ports.get(dp.id, set()):
            flows.append(self._flow(dp, 1, 10, p.OFPMatch(in_port=port), [
                p.OFPInstructionActions(o.OFPIT_APPLY_ACTIONS, [
                    p.OFPActionOutput(o.OFPP_NORMAL), p.OFPActionOutput(o.OFPP_IN_PORT),
                ]),
            ]))
        return flows

    def _start_transaction(self, key, dp, batches, operation=None):
        tx = Transaction(dp, batches, operation)
        self.pending[key] = tx
        self._send_batch(key, tx)

    def _send_batch(self, key, tx):
        dp = tx.datapath
        messages = tx.batches.pop(0)
        barrier = dp.ofproto_parser.OFPBarrierRequest(dp)
        for message in messages + [barrier]:
            dp.set_xid(message)
            tx.xids.add(message.xid)
        tx.barrier = barrier.xid
        tx.started = time.monotonic()
        try:
            for message in messages + [barrier]:
                if dp.send_msg(message) is False:
                    raise OSError("datapath send queue closed")
        except Exception:
            self.logger.exception("OpenFlow send failed: switch=%s", dp.id)
            self._invalidate(dp)

    def _invalidate(self, dp):
        """Partial failure means switch state is uncertain, never confirmed."""
        if self.datapaths.get(dp.id) is not dp:
            return
        self.ready.discard(dp.id)
        for key in list(self.pending):
            if key[0] == dp.id:
                del self.pending[key]
        self.processor.mitigation.forget_switch(dp.id)
        self.retry_at[dp.id] = time.monotonic() + self.RETRY_SECONDS

    def _reset_switch(self, dp):
        self._invalidate(dp)
        self.logger.info("Resetting owned enforcement: switch=%s", dp.id)
        # Each dependency has its own barrier: flows -> meters -> pipeline.
        self._start_transaction((dp.id, None), dp, [
            [],  # Fence older in-flight operations before deleting their state.
            [self._delete_flows(dp)],
            [self._meter(dp, vid, dp.ofproto.OFPMC_DELETE) for vid in self.VEHICLE_IPS],
            self._baseline(dp),
        ])

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        dp = ev.msg.datapath
        self.datapaths[dp.id] = dp
        self.wireless_ports[dp.id] = set()
        self.port_descriptions[dp.id] = []
        self._reset_switch(dp)
        dp.send_msg(dp.ofproto_parser.OFPPortDescStatsRequest(dp, 0))

    @staticmethod
    def _is_wireless(port):
        name = port.name.decode("utf-8", errors="replace") if isinstance(port.name, bytes) else port.name
        return re.fullmatch(r".+-wlan\d+", name.rstrip("\x00")) is not None

    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_description_handler(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        if self.datapaths.get(dp.id) is not dp:
            return
        descriptions = self.port_descriptions.setdefault(dp.id, [])
        descriptions.extend(msg.body)
        if msg.flags & dp.ofproto.OFPMPF_REPLY_MORE:
            return
        ports = {port.port_no for port in descriptions if self._is_wireless(port)}
        self.port_descriptions[dp.id] = []
        if ports != self.wireless_ports.get(dp.id, set()):
            self.wireless_ports[dp.id] = ports
            self.logger.info("Wireless ports discovered: switch=%s ports=%s", dp.id, sorted(ports))
            self._reset_switch(dp)

    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg, dp = ev.msg, ev.msg.datapath
        if self.datapaths.get(dp.id) is not dp:
            return
        ports = self.wireless_ports.setdefault(dp.id, set())
        previous = ports.copy()
        ports.discard(msg.desc.port_no)
        if msg.reason != dp.ofproto.OFPPR_DELETE and self._is_wireless(msg.desc):
            ports.add(msg.desc.port_no)
        if ports != previous:
            self._reset_switch(dp)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        dp = ev.datapath
        # Features handler owns registration; ignore late events from old sessions.
        if ev.state == DEAD_DISPATCHER and self.datapaths.get(dp.id) is dp:
            self._invalidate(dp)
            del self.datapaths[dp.id]
            self.retry_at.pop(dp.id, None)
            self.refresh_at.pop(dp.id, None)
            self.wireless_ports.pop(dp.id, None)
            self.port_descriptions.pop(dp.id, None)
            self.logger.warning("Switch disconnected: %s; reputation retained", dp.id)

    def reconcile(self, dp, vehicle_id, refresh=False):
        key = (dp.id, vehicle_id)
        if dp.id not in self.ready or key in self.pending:
            return
        decision = self.processor.reputation.get_decision(vehicle_id)
        op = self.processor.mitigation.update(dp.id, decision)
        if op.operation == "NO_CHANGE":
            if not refresh:
                return
            op = EnforcementOperation(vehicle_id, dp.id,
                "REMOVE" if decision.rate_limit_kbps is None else "MODIFY",
                self.processor.mitigation.get_meter_id(vehicle_id), decision.rate_limit_kbps)
        p, o = dp.ofproto_parser, dp.ofproto
        match = p.OFPMatch(eth_type=0x0800, ipv4_src=self.VEHICLE_IPS[vehicle_id])
        if op.operation == "REMOVE":
            batches = [
                [self._delete_flows(dp, match, table=0)],
                [self._meter(dp, vehicle_id, o.OFPMC_DELETE)],
            ]
        else:
            batches = [
                [self._meter(dp, vehicle_id,
                    o.OFPMC_ADD if op.operation == "ADD" else o.OFPMC_MODIFY,
                    op.rate_kbps)],
                [self._flow(dp, 0, self.METER_PRIORITY, match, [
                    p.OFPInstructionMeter(op.meter_id), p.OFPInstructionGotoTable(1),
                ])],
            ]
        self.logger.info("Enforcement requested: switch=%s vehicle=%s op=%s kbps=%s",
                         dp.id, vehicle_id, op.operation, op.rate_kbps)
        self._start_transaction(key, dp, batches, op)

    @set_ev_cls(ofp_event.EventOFPBarrierReply, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def barrier_reply_handler(self, ev):
        dp = ev.msg.datapath
        if self.datapaths.get(dp.id) is not dp:
            return
        for key, tx in list(self.pending.items()):
            if tx.datapath is not dp or tx.barrier != ev.msg.xid:
                continue
            if tx.failed:
                self._invalidate(dp)
            elif tx.batches:
                self._send_batch(key, tx)
            else:
                del self.pending[key]
                if tx.operation is None:
                    self.ready.add(dp.id)
                    self.retry_at.pop(dp.id, None)
                    self.refresh_at[dp.id] = time.monotonic() + self.REFRESH_SECONDS
                    self.logger.info("Switch pipeline ready: %s", dp.id)
                    for vid in self.VEHICLE_IPS:
                        self.reconcile(dp, vid)
                else:
                    self.processor.mitigation.confirm(tx.operation)
                    self.logger.info("Enforcement confirmed: switch=%s vehicle=%s op=%s",
                                     dp.id, key[1], tx.operation.operation)
                    # A reputation update may have arrived while this was pending.
                    self.reconcile(dp, key[1])
            break

    @set_ev_cls(ofp_event.EventOFPErrorMsg, [CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_handler(self, ev):
        msg = ev.msg
        if self.datapaths.get(msg.datapath.id) is not msg.datapath:
            return
        self.logger.error("OpenFlow error: switch=%s xid=%s type=%s code=%s",
                          msg.datapath.id, msg.xid, msg.type, msg.code)
        for tx in self.pending.values():
            if tx.datapath is msg.datapath and msg.xid in tx.xids:
                tx.failed = True
                return
        # An uncorrelated error can still indicate externally stale state.
        self._invalidate(msg.datapath)

    def maintenance(self, now=None):
        now = time.monotonic() if now is None else now
        for dp in list(self.datapaths.values()):
            transactions = [tx for tx in self.pending.values() if tx.datapath is dp]
            if any(now - tx.started >= self.BARRIER_TIMEOUT for tx in transactions):
                self.logger.error("Barrier timeout: switch=%s; scheduling reset", dp.id)
                self._invalidate(dp)
                continue
            if dp.id not in self.ready:
                if not transactions and now >= self.retry_at.get(dp.id, 0):
                    self._reset_switch(dp)
            elif now >= self.refresh_at.get(dp.id, 0):
                # Reassert flows, detect missing meters via MODIFY errors, and
                # remove stale normal-state meters even without new telemetry.
                self.refresh_at[dp.id] = now + self.REFRESH_SECONDS
                self._start_transaction((dp.id, None), dp, [self._baseline(dp)])
                for vid in self.VEHICLE_IPS:
                    self.reconcile(dp, vid, refresh=True)

    def _maintenance_loop(self):
        while True:
            hub.sleep(1)
            self.maintenance()

    def parse_vehicle_message(self, raw_data):
        try:
            return parse_safety_message(raw_data)
        except ValueError as error:
            self.logger.warning("Invalid safety message: %s", error)
            return None

    def receive_safety_message(self, dp, source_ip, payload):
        message = self.parse_vehicle_message(payload)
        if message is None:
            return None
        if self.VEHICLE_IPS.get(message.vehicle_id) != source_ip:
            self.logger.warning("Identity rejected: vehicle=%s source=%s expected=%s",
                                message.vehicle_id, source_ip,
                                self.VEHICLE_IPS.get(message.vehicle_id))
            return None
        result = self.processor.process(dp.id, message)
        self.logger.info("Vehicle=%s switch=%s consistent=%s reason=%s reputation=%.2f "
                         "action=%s kbps=%s", result.vehicle_id, dp.id, result.consistent,
                         result.reason, result.reputation, result.action, result.rate_limit_kbps)
        # State is keyed by identity, replicated on every connected switch so a
        # handover does not require discovering or trusting an ingress port.
        for connected in list(self.datapaths.values()):
            self.reconcile(connected, result.vehicle_id)
        return result

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        if self.datapaths.get(msg.datapath.id) is not msg.datapath:
            return
        if msg.total_len != len(msg.data):
            self.logger.warning("Truncated PacketIn rejected")
            return
        try:
            pkt = packet.Packet(msg.data)
            eth = pkt.get_protocol(ethernet.ethernet)
            ip = pkt.get_protocol(ipv4.ipv4)
            datagram = pkt.get_protocol(udp.udp)
            if eth is None or ip is None or datagram is None:
                return
            if datagram.dst_port != self.SAFETY_MESSAGE_PORT:
                return
            payload = pkt.protocols[-1]
            if (ip.offset or ip.flags & 1 or not isinstance(payload, bytes)
                    or datagram.total_length != 8 + len(payload)
                    or ip.total_length != ip.header_length * 4 + datagram.total_length):
                self.logger.warning("Fragmented/inconsistent safety datagram rejected")
                return
            self.receive_safety_message(msg.datapath, ip.src, payload)
        except (ValueError, TypeError, IndexError):
            self.logger.warning("Malformed packet rejected", exc_info=True)
        # Reserved telemetry is consumed here. No PacketOut can bypass a meter
        # or duplicate the observation at downstream switches.
