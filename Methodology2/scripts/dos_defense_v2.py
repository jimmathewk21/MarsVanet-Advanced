"""Mobility-aware progressive DoS mitigation controller (Ryu, OpenFlow 1.3).

Methodology 2 controller. Detection/decision logic lives in the
runtime-independent modules ``med2_config`` and ``mobility_detector`` so it can
be unit-tested without Ryu; this file is the thin Ryu/OpenFlow adapter that
applies those decisions.

Progressive mitigation:
    Stage 0 (normal)  : monitor, learn L2, forward.
    Stage 1 (meter)   : rate-limit the offending source with an OFPMeterMod
                        drop band. The controller polls the matching flow
                        counters instead of mirroring every packet to itself.
    Stage 2 (block)   : install a temporary drop flow with a hard timeout.
                        After the block expires and traffic subsides, the
                        per-source detector is reset so legitimate traffic
                        recovers (no indefinite re-blocking).

IMPORTANT — live validation still required. The AP2 ingress/output ports and
DPID are configurable assumptions (see med2_config); confirm them against
`ovs-ofctl -O OpenFlow13 show ap2` before interpreting mitigation behaviour.
This source cannot be run in a plain container (needs Ryu + a live switch).
"""

import ipaddress
import os
import sys
import time
from collections import defaultdict, deque
from pathlib import Path

# Make the sibling pure-Python modules importable regardless of the working
# directory ryu-manager is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER,
    CONFIG_DISPATCHER,
    DEAD_DISPATCHER,
    set_ev_cls,
)
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.lib import hub

import med2_config
import mobility_detector as md


METER_FLOW_PRIORITY = 60
METER_FLOW_TABLE = 0
METER_FLOW_COOKIE_PREFIX = 0x4D32000000000000
METER_FLOW_COOKIE_MASK = 0xFFFF000000000000
STATS_REQUEST_TIMEOUT_SECONDS = 2.0
STATS_MAX_BACKOFF_SECONDS = 8.0


class DOSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(DOSDefense, self).__init__(*args, **kwargs)

        self.cfg = med2_config.Med2Config.from_env()

        self.mac_to_port = defaultdict(dict)
        self.datapaths = {}

        # Per-source sliding-window rate trackers and detector state.
        self.rate_trackers = {}          # key -> PacketRateTracker
        self.source_state = {}           # key -> md.SourceState
        self.installed_meters = defaultdict(set)   # dpid -> {meter_id}
        self.meter_ids = {}              # (dpid, source) -> stable meter id
        self.flow_cookies = {}           # (dpid, source) -> controller cookie
        self.active_meter_flows = {}     # (dpid, source) -> flow metadata
        self.flow_install_pending = {}   # (dpid, source) -> barrier-pending flow
        self.flow_stat_samples = {}      # key -> (packet_count, monotonic time)
        self.flow_stats_inflight = {}    # dpid -> generation/xid request state
        self.meter_stats_inflight = {}   # dpid -> generation/xid request state
        self.stats_next_poll = {}
        self.stats_backoff = defaultdict(int)
        self.meter_stats_enabled = defaultdict(lambda: True)
        self.meter_stats = {}            # (dpid, meter_id) -> latest telemetry
        self.meter_stats_cursor = defaultdict(int)
        self.meter_specs = {}             # (dpid, meter_id) -> meter config
        self.meter_add_requests = {}     # (dpid, generation, xid) -> meter config
        self.retired_meters = {}         # (dpid, meter_id) -> delayed cleanup
        self.datapath_generations = defaultdict(int)
        self.barrier_requests = {}       # xid -> generation-scoped context
        self.reconcile_state = {}        # dpid -> reconnect cleanup state
        self._local_xid = 1

        self.start_time = time.time()

        # Mobility features (validated, with documented fallback).
        self.mobility_records, report = md.load_mobility_features(
            self.cfg.mobility_csv
        )
        if report.ok:
            self.logger.info(
                "Loaded %s mobility records from %s (skipped %s rows)",
                report.record_count, report.path, report.skipped_rows,
            )
        else:
            self.logger.warning(
                "Mobility features unavailable (%s): %s -> base threshold "
                "fallback", report.path, report.error,
            )

        # Handover tracking.
        self.handover_path = Path(self.cfg.handover_csv)
        self.handover_events = deque()
        self.seen_handovers = set()
        self.handover_rate = 0.0
        self.last_handover_check = 0.0

        self.logger.info("Config: %s", self.cfg.as_dict())
        self.logger.info("Handover CSV path: %s", self.handover_path)

        hub.spawn(self.monitor_handovers)
        hub.spawn(self.monitor_openflow_stats)

    # --- helpers -----------------------------------------------------------

    def _key(self, dpid, source_ip):
        return (dpid, source_ip)

    def _generation(self, dpid):
        return self.datapath_generations.get(dpid, 0)

    def _assign_xid(self, datapath, message):
        """Assign an xid before send_msg so replies can be generation-scoped."""
        setter = getattr(datapath, "set_xid", None)
        if setter is not None:
            setter(message)
        if getattr(message, "xid", None) is None:
            message.xid = self._local_xid
            self._local_xid += 1
        return message.xid

    def _send_barrier(self, datapath, context):
        parser = datapath.ofproto_parser
        barrier = parser.OFPBarrierRequest(datapath)
        xid = self._assign_xid(datapath, barrier)
        self.barrier_requests[xid] = {
            "generation": self._generation(datapath.id),
            "datapath": datapath,
            "sent_monotonic": time.monotonic(),
            **context,
        }
        try:
            datapath.send_msg(barrier)
        except Exception:
            self.barrier_requests.pop(xid, None)
            raise
        return xid

    def _clear_datapath_local_state(self, dpid):
        for mapping in (
            self.active_meter_flows,
            self.flow_install_pending,
            self.flow_stat_samples,
            self.source_state,
            self.rate_trackers,
            self.flow_cookies,
            self.meter_ids,
        ):
            for key in [key for key in mapping if key[0] == dpid]:
                mapping.pop(key, None)
        self.installed_meters.pop(dpid, None)
        for key in [key for key in self.retired_meters if key[0] == dpid]:
            self.retired_meters.pop(key, None)
        for key in [key for key in self.meter_specs if key[0] == dpid]:
            self.meter_specs.pop(key, None)
        for key in [key for key in self.meter_stats if key[0] == dpid]:
            self.meter_stats.pop(key, None)
        for xid, spec in list(self.meter_add_requests.items()):
            if spec.get("datapath").id == dpid:
                self.meter_add_requests.pop(xid, None)
        for xid, context in list(self.barrier_requests.items()):
            if context["datapath"].id == dpid:
                self.barrier_requests.pop(xid, None)
        self.flow_stats_inflight.pop(dpid, None)
        self.meter_stats_inflight.pop(dpid, None)
        self.stats_next_poll.pop(dpid, None)
        self.stats_backoff.pop(dpid, None)
        self.meter_stats_enabled[dpid] = True
        self.meter_stats_cursor.pop(dpid, None)
        self.reconcile_state.pop(dpid, None)

    def _reset_meter_install(self, key):
        """Return a failed/pending Stage 1 install to NORMAL safely."""
        self.flow_install_pending.pop(key, None)
        self.flow_stat_samples.pop(key, None)
        state = self.source_state.get(key)
        if state is not None and state.stage == md.STAGE_METER:
            state.stage = md.STAGE_NORMAL
            state.metered_at = 0.0
            state.trust = 1.0

    def _tracker(self, key):
        tracker = self.rate_trackers.get(key)
        if tracker is None:
            tracker = md.PacketRateTracker(self.cfg.window_seconds)
            self.rate_trackers[key] = tracker
        return tracker

    def _state(self, key):
        state = self.source_state.get(key)
        if state is None:
            state = md.SourceState()
            self.source_state[key] = state
        return state

    def current_threshold(self):
        elapsed = time.time() - self.start_time
        sample = md.nearest_sample(
            self.mobility_records, elapsed, self.cfg.mobility_max_age_seconds
        )
        self._update_handover_rate()
        threshold, _reason = md.select_threshold(
            self.cfg, sample, self.handover_rate
        )
        return threshold, sample

    def _update_handover_rate(self):
        now = time.time()
        window = self.cfg.handover_window_seconds
        while self.handover_events and now - self.handover_events[0] > window:
            self.handover_events.popleft()
        self.handover_rate = len(self.handover_events) * 60.0 / window

    # --- handover monitor --------------------------------------------------

    def monitor_handovers(self):
        while True:
            try:
                if self.handover_path.exists():
                    import csv
                    with open(self.handover_path, newline="") as handle:
                        for row in csv.DictReader(handle):
                            if row.get("current_ap") in (None, "", "NONE"):
                                continue
                            if row.get("previous_ap") in (None, "", "NONE"):
                                continue
                            try:
                                timestamp = float(row["timestamp_unix"])
                            except (ValueError, KeyError, TypeError):
                                continue
                            handover_id = (
                                timestamp,
                                row.get("station", ""),
                                row.get("previous_ap", ""),
                                row.get("current_ap", ""),
                            )
                            if handover_id in self.seen_handovers:
                                continue
                            self.seen_handovers.add(handover_id)
                            self.handover_events.append(timestamp)
                            self.logger.info(
                                "Handover observed: %s -> %s at %.3f",
                                row.get("previous_ap"),
                                row.get("current_ap"),
                                timestamp,
                            )

                self._update_handover_rate()
                now = time.time()
                if now - self.last_handover_check >= 10:
                    self.logger.info(
                        "Recent handovers=%s; handover rate=%.2f/min",
                        len(self.handover_events), self.handover_rate,
                    )
                    self.last_handover_check = now
            except OSError as error:
                self.logger.warning("Could not read handover CSV: %s", error)

            hub.sleep(self.cfg.handover_poll_seconds)

    # --- flow / meter installation ----------------------------------------

    def add_flow(self, datapath, priority, match, actions=None,
                 instructions=None, hard_timeout=0, cookie=0,
                 table_id=METER_FLOW_TABLE):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        if instructions is None:
            actions = actions or []
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ]
        flow = parser.OFPFlowMod(
            datapath=datapath,
            table_id=table_id,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout,
            cookie=cookie,
        )
        datapath.send_msg(flow)

    def _meter_id_for(self, dpid, source_ip):
        """Return a stable, unique meter ID for one active source/datapath."""
        key = self._key(dpid, source_ip)
        if key in self.meter_ids:
            return self.meter_ids[key]

        used = {
            meter_id for (meter_dpid, _), meter_id in self.meter_ids.items()
            if meter_dpid == dpid
        }
        candidate = 100
        while candidate in used:
            candidate += 1
        self.meter_ids[key] = candidate
        return candidate

    def _flow_cookie_for(self, dpid, source_ip):
        """Return a controller-owned cookie identifying a source flow."""
        key = self._key(dpid, source_ip)
        if key not in self.flow_cookies:
            try:
                source_value = int(ipaddress.ip_address(source_ip))
            except ValueError:
                source_value = abs(hash(source_ip)) & 0xFFFFFFFF
            dpid_value = int(dpid) & 0xFFFF
            self.flow_cookies[key] = (
                METER_FLOW_COOKIE_PREFIX
                | (dpid_value << 32)
                | source_value
            )
        return self.flow_cookies[key]

    def _delete_meter(self, datapath, meter_id):
        """Delete an unreferenced meter and stop telemetry for it."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        try:
            meter = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_DELETE,
                flags=0,
                meter_id=meter_id,
                bands=[],
            )
            self._assign_xid(datapath, meter)
            datapath.send_msg(meter)
        except Exception as error:
            self.logger.warning(
                "Meter delete failed for dpid=%s meter=%s: %s",
                datapath.id, meter_id, error,
            )
            return
        self.installed_meters[datapath.id].discard(meter_id)
        self.meter_specs.pop((datapath.id, meter_id), None)
        self.meter_stats.pop((datapath.id, meter_id), None)
        for request_key, spec in list(self.meter_add_requests.items()):
            if (spec.get("datapath") is datapath
                    and spec.get("meter_id") == meter_id):
                self.meter_add_requests.pop(request_key, None)
        for source_key, assigned_id in list(self.meter_ids.items()):
            if source_key[0] == datapath.id and assigned_id == meter_id:
                self.meter_ids.pop(source_key, None)

    def _retire_meter_flow(self, key, flow_present):
        entry = self.active_meter_flows.pop(key, None)
        self.flow_stat_samples.pop(key, None)
        if entry is None:
            return
        self.installed_meters[entry["datapath"].id].discard(entry["meter_id"])
        if flow_present:
            delete_at = time.monotonic() + self.cfg.meter_hard_timeout
            self.retired_meters[(key[0], entry["meter_id"])] = {
                "datapath": entry["datapath"],
                "meter_id": entry["meter_id"],
                "delete_at": delete_at,
            }
        else:
            self._delete_meter(entry["datapath"], entry["meter_id"])

    def install_meter(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        key = self._key(datapath.id, source_ip)
        meter_id = self._meter_id_for(datapath.id, source_ip)
        cookie = self._flow_cookie_for(datapath.id, source_ip)

        # Add the meter only once per datapath to avoid OFPMC_ADD conflicts.
        if meter_id not in self.installed_meters[datapath.id]:
            band = parser.OFPMeterBandDrop(
                rate=self.cfg.meter_rate_kbps, burst_size=self.cfg.meter_burst
            )
            meter_flags = ofproto.OFPMF_KBPS
            # The configured burst is intentional. Do not advertise burst
            # support when the target OpenFlow implementation lacks the flag.
            if self.cfg.meter_burst and hasattr(ofproto, "OFPMF_BURST"):
                meter_flags |= ofproto.OFPMF_BURST
            # Statistics are optional in OpenFlow 1.3; request them when the
            # parser exposes the standard flag and fall back cleanly otherwise.
            if self.meter_stats_enabled.get(datapath.id, True) and hasattr(
                ofproto, "OFPMF_STATS"
            ):
                meter_flags |= ofproto.OFPMF_STATS
            meter = parser.OFPMeterMod(
                datapath=datapath,
                command=ofproto.OFPMC_ADD,
                flags=meter_flags,
                meter_id=meter_id,
                bands=[band],
            )
            meter_xid = self._assign_xid(datapath, meter)
            meter_spec = {
                "datapath": datapath,
                "meter_id": meter_id,
                "flags": meter_flags,
                "bands": [band],
                "generation": self._generation(datapath.id),
            }
            self.meter_specs[(datapath.id, meter_id)] = meter_spec
            request_key = (
                datapath.id, self._generation(datapath.id), meter_xid
            )
            self.meter_add_requests[request_key] = meter_spec
            try:
                datapath.send_msg(meter)
            except Exception as error:
                self.meter_add_requests.pop(request_key, None)
                self.meter_specs.pop((datapath.id, meter_id), None)
                self.logger.warning(
                    "Meter install failed for dpid=%s src=%s: %s",
                    datapath.id, source_ip, error,
                )
                self._reset_meter_install(key)
                return
            self.installed_meters[datapath.id].add(meter_id)

        match = parser.OFPMatch(
            in_port=self.cfg.ap2_in_port,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.cfg.destination_ip,
        )

        # Stage 1: meter + forward to the victim. Rate observation is performed
        # by periodic flow-statistics polling, so this flow must not mirror
        # packets to the controller or create a second forwarding path.
        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(self.cfg.ap2_out_port)],
            ),
        ]
        try:
            self.add_flow(
                datapath, METER_FLOW_PRIORITY, match, instructions=instructions,
                hard_timeout=self.cfg.meter_hard_timeout, cookie=cookie,
            )
        except Exception as error:
            self.logger.warning(
                "Meter flow install failed for dpid=%s src=%s: %s",
                datapath.id, source_ip, error,
            )
            self._delete_meter(datapath, meter_id)
            self._reset_meter_install(key)
            return
        self.flow_install_pending[key] = {
            "datapath": datapath,
            "source_ip": source_ip,
            "meter_id": meter_id,
            "cookie": cookie,
            "match": match,
            "table_id": METER_FLOW_TABLE,
            "installed_monotonic": time.monotonic(),
            "generation": self._generation(datapath.id),
        }
        try:
            self._send_barrier(
                datapath,
                {"kind": "meter_flow_install", "key": key},
            )
        except Exception as error:
            self.flow_install_pending.pop(key, None)
            self.logger.warning(
                "Meter-flow barrier failed for dpid=%s src=%s: %s",
                datapath.id, source_ip, error,
            )

    def install_temporary_block(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        cookie = self._flow_cookie_for(datapath.id, source_ip)
        match = parser.OFPMatch(
            in_port=self.cfg.ap2_in_port,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.cfg.destination_ip,
        )
        # Drop (empty instruction set) with a hard timeout. No periodic refresh
        # -> the block self-expires and the detector resets, enabling recovery.
        self.add_flow(
            datapath, 100, match, instructions=[],
            table_id=METER_FLOW_TABLE,
            hard_timeout=self.cfg.stage2_block_seconds, cookie=cookie,
        )
        key = self._key(datapath.id, source_ip)
        self._retire_meter_flow(key, flow_present=True)
        self.logger.warning(
            "Stage 2 temporary UDP block: src=%s dst=%s duration=%ss",
            source_ip, self.cfg.destination_ip, self.cfg.stage2_block_seconds,
        )

    # --- OpenFlow statistics polling --------------------------------------

    def _stat_match_value(self, match, field):
        try:
            return match.get(field)
        except AttributeError:
            return None

    def _flow_stat_matches(self, entry, stat):
        """Verify cookie, priority and all fields of a metered flow identity."""
        if getattr(stat, "cookie", None) != entry["cookie"]:
            return False
        if getattr(stat, "priority", None) != METER_FLOW_PRIORITY:
            return False
        if getattr(stat, "table_id", None) != METER_FLOW_TABLE:
            return False
        stat_match = getattr(stat, "match", None)
        if stat_match is None:
            return False
        expected = {
            "in_port": self.cfg.ap2_in_port,
            "eth_type": 0x0800,
            "ip_proto": 17,
            "ipv4_src": entry["source_ip"],
            "ipv4_dst": self.cfg.destination_ip,
        }
        return all(
            self._stat_match_value(stat_match, field) == value
            for field, value in expected.items()
        )

    def _apply_polled_rate(self, datapath, source_ip, rate):
        """Apply one flow-counter rate sample to the existing state machine."""
        key = self._key(datapath.id, source_ip)
        state = self._state(key)
        # A reply can race with a block installation. Never re-run the state
        # machine for a source that is no longer in the metered stage.
        if state.stage != md.STAGE_METER or key not in self.active_meter_flows:
            return

        now = time.time()
        threshold, sample = self.current_threshold()
        decision = md.decide(state, rate, threshold, now, self.cfg)
        if decision.action != md.ACTION_NONE or decision.over_threshold:
            self.logger.warning(
                "FLOW-STATS DECISION %s",
                md.format_decision_log(source_ip, sample, decision),
            )
        if decision.action == md.ACTION_INSTALL_BLOCK:
            self.install_temporary_block(datapath, source_ip)

    def _process_flow_stat(self, datapath, stat):
        """Consume one flow-stat entry and derive a monotonic counter rate.

        OpenFlow defines the flow packet counter as a counter of packets that
        matched the entry before its meter instruction. The target OVS version
        must still be checked live, especially when hardware/TC offload is in
        use, before treating this as a verified raw-ingress measurement.
        """
        dpid = datapath.id
        entry = None
        key = None
        for candidate_key, candidate in self.active_meter_flows.items():
            if candidate_key[0] != dpid:
                continue
            if self._flow_stat_matches(candidate, stat):
                key = candidate_key
                entry = candidate
                break
        if entry is None:
            return

        pending = self.flow_stats_inflight.get(dpid)
        if pending is None or pending.get("kind") != "poll":
            return
        pending["seen"].add(key)
        source_ip = entry["source_ip"]
        packet_count = int(getattr(stat, "packet_count", 0))
        now = time.monotonic()
        previous = self.flow_stat_samples.get(key)
        self.flow_stat_samples[key] = (packet_count, now)
        if previous is None:
            self.logger.debug(
                "Initial meter-flow counter sample: dpid=%s src=%s packets=%s",
                dpid, source_ip, packet_count,
            )
            return

        previous_count, previous_time = previous
        elapsed = now - previous_time
        delta = packet_count - previous_count
        # Counter reset/replacement or a non-positive clock interval: retain
        # the new baseline and wait for a clean next interval.
        if elapsed <= 0 or delta < 0:
            self.logger.debug(
                "Reset meter-flow counter baseline: dpid=%s src=%s "
                "previous=%s current=%s",
                dpid, source_ip, previous_count, packet_count,
            )
            return
        self._apply_polled_rate(datapath, source_ip, delta / elapsed)

    def _mark_meter_flow_missing(self, key):
        """Forget a disappeared Stage 1 flow and make the detector recoverable."""
        entry = self.active_meter_flows.get(key)
        if entry is None:
            return
        self._retire_meter_flow(key, flow_present=False)
        state = self.source_state.get(key)
        if state is not None and state.stage == md.STAGE_METER:
            state.stage = md.STAGE_NORMAL
            state.metered_at = 0.0
            state.trust = 1.0
            state.last_seen = 0.0
        self.logger.warning(
            "Meter flow missing/expired: dpid=%s src=%s; detector reset",
            key[0], key[1],
        )

    def _flow_stats_request(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        return parser.OFPFlowStatsRequest(
            datapath,
            0,
            METER_FLOW_TABLE,
            ofproto.OFPP_ANY,
            ofproto.OFPG_ANY,
            METER_FLOW_COOKIE_PREFIX,
            METER_FLOW_COOKIE_MASK,
            parser.OFPMatch(),
        )

    def _request_timed_out(self, pending, now):
        return now - pending["sent_monotonic"] >= STATS_REQUEST_TIMEOUT_SECONDS

    def _next_backoff(self, dpid):
        self.stats_backoff[dpid] = min(
            self.stats_backoff.get(dpid, 0) + 1, 3
        )
        return min(
            STATS_MAX_BACKOFF_SECONDS,
            self.cfg.stats_poll_seconds * (2 ** self.stats_backoff[dpid]),
        )

    def _send_reconcile_request(self, datapath, now):
        dpid = datapath.id
        retries = self.reconcile_state.get(dpid, {}).get("retries", 0)
        try:
            request = self._flow_stats_request(datapath)
            xid = self._assign_xid(datapath, request)
            self.flow_stats_inflight[dpid] = {
                "datapath": datapath,
                "generation": self._generation(dpid),
                "xid": xid,
                "sent_monotonic": now,
                "kind": "reconcile",
                "meter_ids": set(),
                "deleted_cookies": set(),
            }
            self.reconcile_state[dpid] = {
                "generation": self._generation(dpid),
                "status": "flow_stats",
                "retries": retries,
            }
            datapath.send_msg(request)
        except Exception as error:
            self.flow_stats_inflight.pop(dpid, None)
            self.reconcile_state.pop(dpid, None)
            self.logger.warning(
                "Reconnect reconciliation request failed for dpid=%s: %s",
                dpid, error,
            )

    def _service_reconcile_timeouts(self, now):
        for dpid, pending in list(self.flow_stats_inflight.items()):
            if pending.get("kind") != "reconcile":
                continue
            if not self._request_timed_out(pending, now):
                continue
            state = self.reconcile_state.get(dpid)
            self.flow_stats_inflight.pop(dpid, None)
            retries = 0 if state is None else state.get("retries", 0) + 1
            if state is not None and retries <= 3:
                state["retries"] = retries
                self.stats_next_poll[dpid] = now + self._next_backoff(dpid)
                self.logger.warning(
                    "Reconnect reconciliation timed out for dpid=%s; retry=%s",
                    dpid, retries,
                )
            else:
                self.reconcile_state.pop(dpid, None)
                self.logger.error(
                    "Reconnect reconciliation abandoned for dpid=%s after retries",
                    dpid,
                )

        for xid, context in list(self.barrier_requests.items()):
            if now - context["sent_monotonic"] < STATS_REQUEST_TIMEOUT_SECONDS:
                continue
            self.barrier_requests.pop(xid, None)
            dpid = context["datapath"].id
            if context["kind"] == "meter_flow_install":
                self._reset_meter_install(context["key"])
            elif context["kind"].startswith("reconcile_"):
                self.reconcile_state.pop(dpid, None)
            self.logger.warning(
                "OpenFlow barrier timed out for dpid=%s kind=%s",
                dpid, context["kind"],
            )

    def _send_flow_stats_request(self, datapath, now):
        dpid = datapath.id
        if self.reconcile_state.get(dpid):
            return
        if not any(key[0] == dpid for key in self.active_meter_flows):
            return
        previous = self.flow_stats_inflight.get(dpid)
        if previous is not None:
            if previous["generation"] != self._generation(dpid):
                self.flow_stats_inflight.pop(dpid, None)
            elif not self._request_timed_out(previous, now):
                return
            else:
                self.flow_stats_inflight.pop(dpid, None)
                self.stats_next_poll[dpid] = now + self._next_backoff(dpid)
                self.logger.warning(
                    "Flow-stats request timed out for dpid=%s xid=%s",
                    dpid, previous["xid"],
                )
                return
        if now < self.stats_next_poll.get(dpid, 0.0):
            return
        if not any(key[0] == dpid for key in self.active_meter_flows):
            return
        try:
            request = self._flow_stats_request(datapath)
            xid = self._assign_xid(datapath, request)
            self.flow_stats_inflight[dpid] = {
                "datapath": datapath,
                "generation": self._generation(dpid),
                "xid": xid,
                "sent_monotonic": now,
                "kind": "poll",
                "seen": set(),
            }
            datapath.send_msg(request)
        except Exception as error:
            self.flow_stats_inflight.pop(dpid, None)
            self.stats_next_poll[dpid] = now + self._next_backoff(dpid)
            self.logger.warning(
                "Flow-stats request failed for dpid=%s: %s", dpid, error
            )

    def _send_meter_stats_request(self, datapath, now):
        dpid = datapath.id
        if not self.meter_stats_enabled.get(dpid, True):
            return
        if not self.installed_meters.get(dpid):
            return
        meter_ids = sorted(self.installed_meters[dpid])
        previous = self.meter_stats_inflight.get(dpid)
        if previous is not None:
            if previous["generation"] != self._generation(dpid):
                self.meter_stats_inflight.pop(dpid, None)
            elif not self._request_timed_out(previous, now):
                return
            else:
                self.meter_stats_inflight.pop(dpid, None)
                self.stats_next_poll[dpid] = now + self._next_backoff(dpid)
                self.logger.warning(
                    "Meter-stats request timed out for dpid=%s xid=%s",
                    dpid, previous["xid"],
                )
                return
        if now < self.stats_next_poll.get(dpid, 0.0):
            return
        try:
            parser = datapath.ofproto_parser
            meter_id = meter_ids[
                self.meter_stats_cursor[dpid] % len(meter_ids)
            ]
            self.meter_stats_cursor[dpid] += 1
            request = parser.OFPMeterStatsRequest(
                datapath, 0, meter_id
            )
            xid = self._assign_xid(datapath, request)
            self.meter_stats_inflight[dpid] = {
                "datapath": datapath,
                "generation": self._generation(dpid),
                "xid": xid,
                "sent_monotonic": now,
            }
            datapath.send_msg(request)
        except Exception as error:
            self.meter_stats_inflight.pop(dpid, None)
            self.stats_next_poll[dpid] = now + self._next_backoff(dpid)
            self.logger.warning(
                "Meter-stats request failed for dpid=%s: %s", dpid, error
            )

    def _expire_local_meter_flows(self, now):
        timeout = float(self.cfg.meter_hard_timeout)
        for key, entry in list(self.active_meter_flows.items()):
            if now - entry["installed_monotonic"] >= timeout:
                self._mark_meter_flow_missing(key)
        for key, retired in list(self.retired_meters.items()):
            if now >= retired["delete_at"]:
                self.retired_meters.pop(key, None)
                self._delete_meter(retired["datapath"], retired["meter_id"])

    def monitor_openflow_stats(self):
        """Poll flow and meter counters without overlapping requests."""
        while True:
            now = time.monotonic()
            self._expire_local_meter_flows(now)
            self._service_reconcile_timeouts(now)
            for datapath in list(self.datapaths.values()):
                if (
                    self.reconcile_state.get(datapath.id)
                    and datapath.id not in self.flow_stats_inflight
                    and now >= self.stats_next_poll.get(datapath.id, 0.0)
                ):
                    self._send_reconcile_request(datapath, now)
                self._send_flow_stats_request(datapath, now)
                self._send_meter_stats_request(datapath, now)
            hub.sleep(max(0.1, self.cfg.stats_poll_seconds))

    def _collect_reconcile_stat(self, datapath, stat, pending):
        cookie = getattr(stat, "cookie", 0)
        if (cookie & METER_FLOW_COOKIE_MASK) != METER_FLOW_COOKIE_PREFIX:
            return
        if getattr(stat, "table_id", None) != METER_FLOW_TABLE:
            return
        if getattr(stat, "priority", None) != METER_FLOW_PRIORITY:
            return
        if cookie in pending["deleted_cookies"]:
            return
        pending["deleted_cookies"].add(cookie)
        for instruction in getattr(stat, "instructions", ()):
            meter_id = getattr(instruction, "meter_id", None)
            if meter_id is not None:
                pending["meter_ids"].add(meter_id)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        delete = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE_STRICT,
            table_id=METER_FLOW_TABLE,
            priority=METER_FLOW_PRIORITY,
            cookie=cookie,
            cookie_mask=METER_FLOW_COOKIE_MASK,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY,
            match=stat.match,
        )
        datapath.send_msg(delete)

    def _finish_reconcile(self, datapath, pending):
        dpid = datapath.id
        state = self.reconcile_state.get(dpid)
        if state is None or state["generation"] != pending["generation"]:
            return
        state["status"] = "wait_flow_barrier"
        try:
            self._send_barrier(
                datapath,
                {
                    "kind": "reconcile_flow_delete",
                    "meter_ids": set(pending["meter_ids"]),
                },
            )
        except Exception as error:
            self.reconcile_state.pop(dpid, None)
            self.logger.warning("Reconcile barrier failed for dpid=%s: %s", dpid, error)

    def _activate_pending_meter_flow(self, key):
        entry = self.flow_install_pending.pop(key, None)
        if entry is None:
            return
        if entry["generation"] != self._generation(key[0]):
            return
        entry["installed_monotonic"] = time.monotonic()
        self.active_meter_flows[key] = entry
        self.flow_stat_samples.pop(key, None)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pending = self.flow_stats_inflight.get(datapath.id)
        if (
            pending is None
            or pending.get("datapath") is not datapath
            or pending["generation"] != self._generation(datapath.id)
            or getattr(msg, "xid", None) != pending["xid"]
        ):
            self.logger.debug("Ignoring stale flow-stats reply for dpid=%s", datapath.id)
            return
        for stat in getattr(msg, "body", ()):
            if pending["kind"] == "reconcile":
                self._collect_reconcile_stat(datapath, stat, pending)
            else:
                self._process_flow_stat(datapath, stat)
        flags = getattr(msg, "flags", 0)
        more = getattr(datapath.ofproto, "OFPMPF_REPLY_MORE", 1)
        if not flags & more:
            self.flow_stats_inflight.pop(datapath.id, None)
            if pending["kind"] == "reconcile":
                self._finish_reconcile(datapath, pending)
            else:
                self.stats_backoff[datapath.id] = 0
                self.stats_next_poll[datapath.id] = time.monotonic()
                seen = pending.get("seen", set())
                grace = max(2.0, self.cfg.stats_poll_seconds * 2.0)
                now = time.monotonic()
                for key, entry in list(self.active_meter_flows.items()):
                    if key[0] != datapath.id or key in seen:
                        continue
                    if now - entry["installed_monotonic"] >= grace:
                        self._mark_meter_flow_missing(key)

    @set_ev_cls(ofp_event.EventOFPMeterStatsReply, MAIN_DISPATCHER)
    def meter_stats_reply_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        pending = self.meter_stats_inflight.get(datapath.id)
        if (
            pending is None
            or pending.get("datapath") is not datapath
            or pending["generation"] != self._generation(datapath.id)
            or getattr(msg, "xid", None) != pending["xid"]
        ):
            self.logger.debug("Ignoring stale meter-stats reply for dpid=%s", datapath.id)
            return
        now = time.monotonic()
        for stat in getattr(msg, "body", ()):
            if stat.meter_id not in self.installed_meters.get(datapath.id, ()):
                continue
            self.meter_stats[(datapath.id, stat.meter_id)] = {
                "flow_count": getattr(stat, "flow_count", 0),
                "packet_in_count": getattr(stat, "packet_in_count", 0),
                "byte_in_count": getattr(stat, "byte_in_count", 0),
                "band_stats": getattr(stat, "band_stats", ()),
                "monotonic": now,
            }
        flags = getattr(msg, "flags", 0)
        more = getattr(datapath.ofproto, "OFPMPF_REPLY_MORE", 1)
        if not flags & more:
            self.meter_stats_inflight.pop(datapath.id, None)
            self.stats_backoff[datapath.id] = 0
            self.stats_next_poll[datapath.id] = time.monotonic()

    @set_ev_cls(ofp_event.EventOFPBarrierReply, MAIN_DISPATCHER)
    def barrier_reply_handler(self, ev):
        msg = ev.msg
        context = self.barrier_requests.pop(getattr(msg, "xid", None), None)
        if context is None:
            return
        datapath = msg.datapath
        if context["generation"] != self._generation(datapath.id):
            return
        if context["kind"] == "meter_flow_install":
            meter_id = self.flow_install_pending.get(
                context["key"], {}
            ).get("meter_id")
            for request_key, spec in list(self.meter_add_requests.items()):
                if (spec.get("datapath") is datapath
                        and spec.get("meter_id") == meter_id):
                    self.meter_add_requests.pop(request_key, None)
            self._activate_pending_meter_flow(context["key"])
            return
        if context["kind"] == "reconcile_flow_delete":
            state = self.reconcile_state.get(datapath.id)
            if state is None:
                return
            state["status"] = "wait_meter_barrier"
            for meter_id in context["meter_ids"]:
                self._delete_meter(datapath, meter_id)
            if context["meter_ids"]:
                self._send_barrier(
                    datapath, {"kind": "reconcile_meter_delete"}
                )
            else:
                self.reconcile_state.pop(datapath.id, None)
            return
        if context["kind"] == "reconcile_meter_delete":
            self.reconcile_state.pop(datapath.id, None)

    # --- switch lifecycle --------------------------------------------------

    def _register_datapath(self, datapath):
        dpid = datapath.id
        if self.datapaths.get(dpid) is datapath:
            return
        self.datapath_generations[dpid] += 1
        self.datapaths[dpid] = datapath
        self._clear_datapath_local_state(dpid)
        self._send_reconcile_request(datapath, time.monotonic())

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self._register_datapath(datapath)
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Clean any stale high-priority drop left from a previous run, but only
        # when a specific attacker is configured. With no configured attacker
        # there is nothing to pre-clean.
        if self.cfg.attacker_ip:
            old_match = parser.OFPMatch(
                eth_type=0x0800, ipv4_src=self.cfg.attacker_ip, ip_proto=17
            )
            datapath.send_msg(parser.OFPFlowMod(
                datapath=datapath,
                command=ofproto.OFPFC_DELETE,
                table_id=0,
                priority=100,
                match=old_match,
                out_port=ofproto.OFPP_ANY,
                out_group=ofproto.OFPG_ANY,
            ))

        # Table-miss -> controller (L2 learning).
        self.add_flow(
            datapath, 0, parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
        )

        # On AP2, copy victim-bound UDP to the controller for rate monitoring.
        if datapath.id == self.cfg.ap2_dpid:
            self.add_flow(
                datapath, 50,
                parser.OFPMatch(
                    in_port=self.cfg.ap2_in_port,
                    eth_type=0x0800,
                    ip_proto=17,
                    ipv4_dst=self.cfg.destination_ip,
                ),
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)],
            )
            self.logger.info(
                "AP2 monitor flow installed (dpid=%s in_port=%s dst=%s)",
                datapath.id, self.cfg.ap2_in_port, self.cfg.destination_ip,
            )

        self.logger.info("Switch ready: dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        """Track datapaths so a disconnected switch is not used for sends."""
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id is not None:
                self._register_datapath(datapath)
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.warning("Switch disconnected: dpid=%s", datapath.id)
                del self.datapaths[datapath.id]
            self.datapath_generations[datapath.id] += 1
            self._clear_datapath_local_state(datapath.id)
            self.flow_stats_inflight.pop(datapath.id, None)
            self.meter_stats_inflight.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPErrorMsg, MAIN_DISPATCHER)
    def error_msg_handler(self, ev):
        msg = ev.msg
        self.logger.error(
            "OpenFlow error: type=0x%02x code=0x%02x", msg.type, msg.code
        )
        datapath = msg.datapath
        dpid = datapath.id
        xid = getattr(msg, "xid", None)
        flow_pending = self.flow_stats_inflight.get(dpid)
        if (flow_pending and flow_pending.get("datapath") is datapath
                and flow_pending["generation"] == self._generation(dpid)
                and xid == flow_pending["xid"]):
            self.flow_stats_inflight.pop(dpid, None)
            self.stats_next_poll[dpid] = (
                time.monotonic() + self._next_backoff(dpid)
            )
        meter_pending = self.meter_stats_inflight.get(dpid)
        if (meter_pending and meter_pending.get("datapath") is datapath
                and meter_pending["generation"] == self._generation(dpid)
                and xid == meter_pending["xid"]):
            self.meter_stats_inflight.pop(dpid, None)
            self.meter_stats_enabled[dpid] = False
            self.logger.warning(
                "Meter telemetry disabled after unsupported/error reply for dpid=%s",
                dpid,
            )

        request_key = (dpid, self._generation(dpid), xid)
        meter_spec = self.meter_add_requests.pop(request_key, None)
        if (meter_spec is not None
                and meter_spec.get("datapath") is datapath
                and meter_spec.get("generation") == self._generation(dpid)):
            ofproto = datapath.ofproto
            meter_exists = (
                getattr(msg, "type", None)
                == getattr(ofproto, "OFPET_METER_MOD_FAILED", object())
                and getattr(msg, "code", None)
                == getattr(ofproto, "OFPMMFC_METER_EXISTS", object())
            )
            if meter_exists:
                parser = datapath.ofproto_parser
                modify = parser.OFPMeterMod(
                    datapath=datapath,
                    command=ofproto.OFPMC_MODIFY,
                    flags=meter_spec["flags"],
                    meter_id=meter_spec["meter_id"],
                    bands=meter_spec["bands"],
                )
                modify_xid = self._assign_xid(datapath, modify)
                self.meter_add_requests[(
                    dpid, self._generation(dpid), modify_xid
                )] = meter_spec
                datapath.send_msg(modify)
            else:
                self.installed_meters[dpid].discard(meter_spec["meter_id"])

    # --- packet in ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        # Detection path: victim-bound UDP arriving on the AP2 ingress port.
        monitored = (
            datapath.id == self.cfg.ap2_dpid
            and in_port == self.cfg.ap2_in_port
            and ip_pkt is not None
            and udp_pkt is not None
            and ip_pkt.dst == self.cfg.destination_ip
        )
        if monitored:
            key = self._key(datapath.id, ip_pkt.src)
            # A PacketIn that races with installation of the priority-60 flow
            # has already been handled by that forwarding flow. Sending a
            # PacketOut here would create a duplicate victim-bound packet.
            meter_flow_was_active = key in self.active_meter_flows
            blocked = self._handle_detection(datapath, ip_pkt.src)
            if blocked or meter_flow_was_active:
                return

        # L2 learning switch for everything else.
        dpid = datapath.id
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]
        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port, eth_src=eth.src, eth_dst=eth.dst
            )
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None,
        )
        datapath.send_msg(out)

    def _handle_detection(self, datapath, source_ip):
        """Run the detector for one monitored UDP packet.

        Returns True when the source is in the blocked stage (caller should not
        forward), False otherwise.
        """
        # If a specific attacker IP is configured, only mitigate that source;
        # other sources still get L2 forwarding.
        if self.cfg.attacker_ip and source_ip != self.cfg.attacker_ip:
            return False

        key = self._key(datapath.id, source_ip)
        now = time.time()

        tracker = self._tracker(key)
        tracker.add(now)
        rate = tracker.rate(now)

        threshold, sample = self.current_threshold()
        state = self._state(key)
        decision = md.decide(state, rate, threshold, now, self.cfg)

        if decision.action != md.ACTION_NONE or decision.over_threshold:
            self.logger.warning(
                "DECISION %s", md.format_decision_log(source_ip, sample, decision)
            )

        if decision.action == md.ACTION_INSTALL_METER:
            self.install_meter(datapath, source_ip)
        elif decision.action == md.ACTION_INSTALL_BLOCK:
            self.install_temporary_block(datapath, source_ip)
        elif decision.action == md.ACTION_RESET:
            self.logger.info("Detector reset for src=%s", source_ip)

        return state.stage == md.STAGE_BLOCK
