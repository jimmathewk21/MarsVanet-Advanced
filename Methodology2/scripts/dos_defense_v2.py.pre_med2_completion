
import csv
import os
import time
from collections import defaultdict, deque
from pathlib import Path

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
from ryu.lib import hub


class DOSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    AP2_DPID = 0x1000000000000002
    WINDOW_SECONDS = 5
    BASE_THRESHOLD = 120
    METER_RATE_KBPS = 500

    ATTACKER_IP = "10.0.0.3"
    DESTINATION_IP = "10.0.0.2"

    HANDOVER_WINDOW_SECONDS = 60
    HIGH_HANDOVER_RATE = 2.0
    HANDOVER_POLL_SECONDS = 2

    def __init__(self, *args, **kwargs):
        super(DOSDefense, self).__init__(*args, **kwargs)

        self.mac_to_port = defaultdict(dict)
        self.datapaths = {}
        self.packet_times = defaultdict(deque)
        self.trust = defaultdict(lambda: 1.0)
        self.stage = defaultdict(int)

        self.start_time = time.time()
        self.mobility_data = self.load_mobility()

        self.handover_path = (
            Path(__file__).resolve().parents[1]
            / "handover_test"
            / "handover_log.csv"
        )

        self.handover_events = deque()
        self.seen_handovers = set()
        self.handover_rate = 0.0
        self.last_handover_check = 0

        self.logger.info(
            "Handover CSV path: %s",
            self.handover_path
        )

        hub.spawn(self.refresh_blocks)
        hub.spawn(self.monitor_handovers)

    def load_mobility(self):
        path = "/home/ev/sdn_vanet_sumo/mobility_features.csv"
        data = []

        if not os.path.exists(path):
            self.logger.warning("Mobility CSV not found: %s", path)
            return data

        try:
            with open(path, newline="") as file:
                reader = csv.DictReader(file)

                for row in reader:
                   data.append({
                       "time": float(row["time"]),
                       "vehicle_count": int(row["vehicle_count"]),
                       "avg_speed": float(row["average_speed"])
                   })

            self.logger.info(
                "Loaded %s mobility records",
                len(data)
            )

        except (OSError, ValueError, KeyError) as error:
            self.logger.error("Mobility CSV error: %s", error)

        return data

    def get_threshold(self):
        threshold = self.BASE_THRESHOLD

        if self.mobility_data:
            elapsed = time.time() - self.start_time

            nearest = min(
                self.mobility_data,
                key=lambda row: abs(row["time"] - elapsed)
            )

            count = nearest["vehicle_count"]
            speed = nearest["avg_speed"]

            if count >= 5 or speed < 5:
                threshold = 90
            elif count <= 2 and speed >= 10:
                threshold = 150

        now = time.time()

        while (
            self.handover_events
            and now - self.handover_events[0] > self.HANDOVER_WINDOW_SECONDS
        ):
            self.handover_events.popleft()

        self.handover_rate = (
            len(self.handover_events)
            * 60.0
            / self.HANDOVER_WINDOW_SECONDS
        )

        if self.handover_rate >= self.HIGH_HANDOVER_RATE:
            threshold = max(threshold, 150)

        return threshold

    def monitor_handovers(self):
        while True:
            try:
                if self.handover_path.exists():
                    with open(
                        self.handover_path,
                        newline=""
                    ) as file:
                        reader = csv.DictReader(file)

                        for row in reader:
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
                                row.get("current_ap", "")
                            )

                            if handover_id in self.seen_handovers:
                                continue

                            self.seen_handovers.add(handover_id)
                            self.handover_events.append(timestamp)

                            self.logger.info(
                                "Handover observed: %s -> %s at %.3f",
                                row.get("previous_ap"),
                                row.get("current_ap"),
                                timestamp
                            )

                now = time.time()

                while (
                    self.handover_events
                    and now - self.handover_events[0]
                    > self.HANDOVER_WINDOW_SECONDS
                ):
                    self.handover_events.popleft()

                self.handover_rate = (
                    len(self.handover_events)
                    * 60.0
                    / self.HANDOVER_WINDOW_SECONDS
                )

                if now - self.last_handover_check >= 10:
                    self.logger.info(
                        "Recent handovers=%s; handover rate=%.2f/min",
                        len(self.handover_events),
                        self.handover_rate
                    )
                    self.last_handover_check = now

            except (OSError, csv.Error) as error:
                self.logger.warning(
                    "Could not read handover CSV: %s",
                    error
                )

            hub.sleep(self.HANDOVER_POLL_SECONDS)

    def add_flow(
        self,
        datapath,
        priority,
        match,
        actions=None,
        instructions=None,
        hard_timeout=0
    ):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        if instructions is None:
            actions = actions or []
            instructions = [
                parser.OFPInstructionActions(
                    ofproto.OFPIT_APPLY_ACTIONS,
                    actions
                )
            ]

        flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            hard_timeout=hard_timeout
        )

        datapath.send_msg(flow)

    def install_meter(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        meter_id = 100 + int(source_ip.split(".")[-1])

        band = parser.OFPMeterBandDrop(
            rate=self.METER_RATE_KBPS,
            burst_size=100
        )

        meter = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS,
            meter_id=meter_id,
            bands=[band]
        )
        datapath.send_msg(meter)

        match = parser.OFPMatch(
            in_port=1,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.DESTINATION_IP
        )

        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(2)]
            )
        ]

        self.add_flow(
            datapath,
            60,
            match,
            instructions=instructions,
            hard_timeout=15
        )

    def install_temporary_block(self, datapath, source_ip):
        parser = datapath.ofproto_parser

        match = parser.OFPMatch(
            in_port=1,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst=self.DESTINATION_IP
        )

        self.add_flow(
            datapath,
            100,
            match,
            instructions=[],
            hard_timeout=30
        )

        self.logger.warning(
            "Temporary UDP block refreshed: source=%s destination=%s duration=30s",
            source_ip,
            self.DESTINATION_IP
        )

    def refresh_blocks(self):
        while True:
            hub.sleep(20)

            for key, stage in list(self.stage.items()):
                if stage != 2:
                    continue

                dpid, source_ip = key
                datapath = self.datapaths.get(dpid)

                if datapath is not None:
                    self.install_temporary_block(datapath, source_ip)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        self.datapaths[datapath.id] = datapath

        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        old_match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=self.ATTACKER_IP,
            ip_proto=17
        )

        delete_old = parser.OFPFlowMod(
            datapath=datapath,
            command=ofproto.OFPFC_DELETE,
            table_id=0,
            priority=100,
            match=old_match,
            out_port=ofproto.OFPP_ANY,
            out_group=ofproto.OFPG_ANY
        )
        datapath.send_msg(delete_old)

        self.add_flow(
            datapath,
            0,
            parser.OFPMatch(),
            [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
        )

        if datapath.id == self.AP2_DPID:
            self.add_flow(
                datapath,
                50,
                parser.OFPMatch(
                    in_port=1,
                    eth_type=0x0800,
                    ip_proto=17,
                    ipv4_dst=self.DESTINATION_IP
                ),
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER)]
            )

        self.logger.info("Switch ready: dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match.get("in_port")

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        udp_pkt = pkt.get_protocol(udp.udp)

        if eth is None:
            return

        if (
            datapath.id == self.AP2_DPID
            and in_port == 1
            and ip_pkt is not None
            and udp_pkt is not None
            and ip_pkt.dst == self.DESTINATION_IP
        ):
            source_ip = ip_pkt.src
            key = (datapath.id, source_ip)
            now = time.time()

            timestamps = self.packet_times[key]
            timestamps.append(now)

            while timestamps and now - timestamps[0] > self.WINDOW_SECONDS:
                timestamps.popleft()

            rate = len(timestamps) / self.WINDOW_SECONDS
            threshold = self.get_threshold()

            if rate >= threshold:
                current_trust = self.trust[key]

                self.logger.warning(
                    "High UDP rate: source=%s rate=%.1f pps threshold=%s trust=%.2f",
                    source_ip,
                    rate,
                    threshold,
                    current_trust
                )

                if self.stage[key] == 0:
                    self.trust[key] = max(0.0, current_trust - 0.4)
                    self.stage[key] = 1
                    self.install_meter(datapath, source_ip)

                    self.logger.warning(
                        "Stage 1: applying %s kbps meter to %s; trust=%.2f",
                        self.METER_RATE_KBPS,
                        source_ip,
                        self.trust[key]
                    )

                elif self.stage[key] == 1:
                    self.trust[key] = max(0.0, current_trust - 0.4)
                    self.stage[key] = 2
                    self.install_temporary_block(datapath, source_ip)

                if self.stage[key] == 2:
                    return

        dpid = datapath.id
        self.mac_to_port[dpid][eth.src] = in_port

        out_port = self.mac_to_port[dpid].get(
            eth.dst,
            ofproto.OFPP_FLOOD
        )
        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(
                in_port=in_port,
                eth_src=eth.src,
                eth_dst=eth.dst
            )
            self.add_flow(datapath, 1, match, actions)

        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        )
        datapath.send_msg(out)
