
from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, ether_types
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
import csv
import os
import time

OUTPUT = os.path.expanduser("~/sdn_vanet_sumo/network_stats.csv")


class MobilityMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MobilityMonitor, self).__init__(*args, **kwargs)
        self.datapaths = {}
        self.previous = {}
        self.monitor_thread = hub.spawn(self._monitor)
        os.makedirs(os.path.dirname(OUTPUT), exist_ok=True)

        with open(OUTPUT, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "switch_id", "ipv4_src", "ipv4_dst",
                "protocol", "packet_count", "byte_count",
                "packet_rate_pps", "byte_rate_Bps"
            ])

    @set_ev_cls(ofp_event.EventOFPStateChange,
                [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            self.datapaths.pop(datapath.id, None)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg = ev.msg
        pkt = packet.Packet(msg.data)
        ip_pkt = pkt.get_protocol(ipv4.ipv4)

        if ip_pkt is None:
            return

        now = time.time()
        src = ip_pkt.src
        dst = ip_pkt.dst
        proto = ip_pkt.proto
        key = (src, dst, proto)

        old = self.previous.get(key)
        if old:
            elapsed = now - old[0]
            packet_rate = 1 / elapsed if elapsed > 0 else 0
        else:
            packet_rate = 0

        self.previous[key] = (now, 0, 0)

        with open(OUTPUT, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                round(now, 3), ev.msg.datapath.id, src, dst, proto,
                1, len(msg.data), round(packet_rate, 2), 0
            ])
    def _monitor(self):
        while True:
            for datapath in list(self.datapaths.values()):
                parser = datapath.ofproto_parser
                request = parser.OFPFlowStatsRequest(datapath)
                datapath.send_msg(request)
            hub.sleep(5)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def flow_stats_reply_handler(self, ev):
        now = time.time()
        datapath = ev.msg.datapath

        with open(OUTPUT, "a", newline="") as f:
            writer = csv.writer(f)

            for stat in ev.msg.body:
                if stat.priority == 0:
                    continue

                match = stat.match
                src = match.get("ipv4_src", "")
                dst = match.get("ipv4_dst", "")
                proto = match.get("ip_proto", "")

                key = (
                    datapath.id, stat.table_id, stat.priority,
                    src, dst, proto, match.get("in_port", "")
                )

                packets = stat.packet_count
                byte_count = stat.byte_count
                old = self.previous.get(key)

                if old:
                    elapsed = now - old[0]
                    packet_rate = max(0, packets - old[1]) / elapsed
                    byte_rate = max(0, byte_count - old[2]) / elapsed
                else:
                    packet_rate = 0
                    byte_rate = 0

                self.previous[key] = (now, packets, byte_count)

                writer.writerow([
                    round(now, 3), datapath.id, src, dst, proto,
                    packets, byte_count,
                    round(packet_rate, 2), round(byte_rate, 2)
                ])
