import csv
import time
from collections import defaultdict, deque

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp


class DOSDefenseV2(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    AP2_DPID = 0x1000000000000002
    WINDOW_SECONDS = 5
    BASE_THRESHOLD = 120
    METER_RATE_KBPS = 500

    def __init__(self, *args, **kwargs):
        super(DOSDefenseV2, self).__init__(*args, **kwargs)
        self.mac_to_port = defaultdict(dict)
        self.packet_times = defaultdict(deque)
        self.trust = defaultdict(lambda: 1.0)
        self.stage = defaultdict(int)
        self.start_time = time.time()
        self.mobility_rows = []
        self.load_mobility()

    def load_mobility(self):
        path = "/home/ev/sdn_vanet_sumo/mobility_features.csv"
        try:
            with open(path, newline="") as file:
                self.mobility_rows = [
                    row for row in csv.DictReader(file)
                ]
            self.logger.info(
                "Loaded %s SUMO mobility records",
                len(self.mobility_rows)
            )
        except (OSError, csv.Error) as error:
            self.logger.warning("Mobility data unavailable: %s", error)

    def get_threshold(self):
        threshold = self.BASE_THRESHOLD
        if not self.mobility_rows:
            return threshold

        elapsed = time.time() - self.start_time
        row = min(
            self.mobility_rows,
            key=lambda item: abs(float(item["time"]) - elapsed)
        )
        count = int(row["vehicle_count"])
        speed = float(row["average_speed"])

        if count >= 5 or speed < 5:
            threshold = 90
        elif count <= 2 and speed >= 10:
            threshold = 150

        return threshold

    def add_flow(self, datapath, priority, match, actions=None,
                 instructions=None, hard_timeout=0):
        parser = datapath.ofproto_parser
        if instructions is None:
            actions = actions or []
            instructions = [
                parser.OFPInstructionActions(
                    datapath.ofproto.OFPIT_APPLY_ACTIONS, actions
                )
            ] if actions else []

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
        meter_id = 100 + int(source_ip.split(".")[-1])

        band = parser.OFPMeterBandDrop(
            rate=self.METER_RATE_KBPS,
            burst_size=100
        )
        meter = parser.OFPMeterMod(
            datapath=datapath,
            command=datapath.ofproto.OFPMC_ADD,
            flags=datapath.ofproto.OFPMF_KBPS
                  | datapath.ofproto.OFPMF_STATS,
            meter_id=meter_id,
            bands=[band]
        )
        datapath.send_msg(meter)

        match = parser.OFPMatch(
            in_port=1,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst="10.0.0.2"
        )
        instructions = [
            parser.OFPInstructionMeter(meter_id),
            parser.OFPInstructionActions(
                datapath.ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(2)]
            )
        ]
        self.add_flow(
            datapath, 80, match,
            instructions=instructions, hard_timeout=15
        )

    def install_temporary_block(self, datapath, source_ip):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            in_port=1,
            eth_type=0x0800,
            ip_proto=17,
            ipv4_src=source_ip,
            ipv4_dst="10.0.0.2"
        )
        self.add_flow(
            datapath, 100, match,
            instructions=[], hard_timeout=30
        )
        self.logger.warning(
            "Temporary UDP block: source=%s destination=10.0.0.2 duration=30s",
            source_ip
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        # Remove the previous unconditional UDP drop rule.
        old_match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src="10.0.0.3",
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
            datapath, 0, parser.OFPMatch(),
            [parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )]
        )

        if datapath.id == self.AP2_DPID:
            match = parser.OFPMatch(
                in_port=1,
                eth_type=0x0800,
                ip_proto=17,
                ipv4_dst="10.0.0.2"
            )
            self.add_flow(
                datapath, 50, match,
                [parser.OFPActionOutput(
                    ofproto.OFPP_CONTROLLER,
                    ofproto.OFPCML_NO_BUFFER
                )]
            )

        self.logger.info("Switch ready: dpid=%s", datapath.id)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        ip = pkt.get_protocol(ipv4.ipv4)
        transport = pkt.get_protocol(udp.udp)

        if eth is None or eth.ethertype == 0x88cc:
            return

        if (
            datapath.id == self.AP2_DPID
            and in_port == 1
            and ip is not None
            and transport is not None
            and ip.dst == "10.0.0.2"
        ):
            now = time.time()
            source_ip = ip.src
            key = (datapath.id, source_ip)
            times = self.packet_times[key]
            times.append(now)

            while times and now - times[0] > self.WINDOW_SECONDS:
                times.popleft()

            rate = len(times) / self.WINDOW_SECONDS
            threshold = self.get_threshold()

            if rate >= threshold:
                current_trust = self.trust[key]
                self.logger.warning(
                    "High UDP rate: source=%s rate=%.1f pps threshold=%s trust=%.2f",
                    source_ip, rate, threshold, current_trust
                )

                if self.stage[key] == 0:
                    self.trust[key] = max(0.0, current_trust - 0.4)
                    self.stage[key] = 1
                    self.install_meter(datapath, source_ip)
                    self.logger.warning(
                        "Stage 1: applying %s kbps meter to %s; trust=%.2f",
                        self.METER_RATE_KBPS, source_ip, self.trust[key]
                    )
                elif self.trust[key] <= 0.6:
                    self.trust[key] = max(0.0, current_trust - 0.4)
                    self.stage[key] = 2
                    self.install_temporary_block(datapath, source_ip)

                if self.stage[key] == 2:
                    return

            actions = [parser.OFPActionOutput(2)]
            out = parser.OFPPacketOut(
                datapath=datapath,
                buffer_id=ofproto.OFP_NO_BUFFER,
                in_port=in_port,
                actions=actions,
                data=msg.data
            )
            datapath.send_msg(out)
            return

        dpid = datapath.id
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(
            eth.dst, ofproto.OFPP_FLOOD
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
