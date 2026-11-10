from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, udp
import time


class DOSDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    ATTACKER_IP = "10.0.0.3"
    METER_ID = 1
    WINDOW = 2
    RATE_THRESHOLD = 100
    BLOCK_THRESHOLD = 3

    def __init__(self, *args, **kwargs):
        super(DOSDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.packet_counts = {}
        self.high_windows = {}
        self.blocked = set()
        self.trust = {}

    def add_flow(self, datapath, priority, match, actions=None,
                 instructions=None, idle_timeout=0, hard_timeout=0):
        parser = datapath.ofproto_parser
        if instructions is None:
            instructions = [
                parser.OFPInstructionActions(
                    datapath.ofproto.OFPIT_APPLY_ACTIONS,
                    actions or []
                )
            ]
        flow = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=instructions,
            idle_timeout=idle_timeout,
            hard_timeout=hard_timeout
        )
        datapath.send_msg(flow)

    def install_meter(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        bands = [
            parser.OFPMeterBandDrop(
                rate=500,
                burst_size=100
            )
        ]
        meter = parser.OFPMeterMod(
            datapath=datapath,
            command=ofproto.OFPMC_ADD,
            flags=ofproto.OFPMF_KBPS | ofproto.OFPMF_BURST,
            meter_id=self.METER_ID,
            bands=bands
        )
        datapath.send_msg(meter)

    def apply_rate_limit(self, datapath):
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=self.ATTACKER_IP,
            ip_proto=17
        )
        instructions = [
            parser.OFPInstructionMeter(self.METER_ID),
            parser.OFPInstructionActions(
                ofproto.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                        ofproto.OFPCML_NO_BUFFER)]
            )
        ]
        self.add_flow(
            datapath, 60, match,
            instructions=instructions,
            hard_timeout=30
        )
        self.logger.warning(
            "RATE LIMIT enabled for %s on switch %s",
            self.ATTACKER_IP, datapath.id
        )

    def apply_block(self, datapath):
        parser = datapath.ofproto_parser
        match = parser.OFPMatch(
            eth_type=0x0800,
            ipv4_src=self.ATTACKER_IP,
            ip_proto=17
        )
        self.add_flow(
            datapath, 100, match, actions=[],
            hard_timeout=10
        )
        self.logger.warning(
            "TEMPORARY BLOCK enabled for %s on switch %s",
            self.ATTACKER_IP, datapath.id
        )

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto

        self.install_meter(datapath)

        table_miss = parser.OFPMatch()
        actions = [
            parser.OFPActionOutput(
                ofproto.OFPP_CONTROLLER,
                ofproto.OFPCML_NO_BUFFER
            )
        ]
        self.add_flow(datapath, 0, table_miss, actions)

        self.logger.info(
            "Progressive defense ready on switch %s", datapath.id
        )

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

        if ip and transport and ip.src == self.ATTACKER_IP:
            now = time.time()
            key = (datapath.id, ip.src)
            count, start = self.packet_counts.get(key, (0, now))

            if now - start >= self.WINDOW:
                high = count >= self.RATE_THRESHOLD
                self.high_windows[key] = (
                    self.high_windows.get(key, 0) + 1 if high else 0
                )
                count, start = 0, now

                if high:
                    self.trust[key] = max(
                        0, self.trust.get(key, 100) - 30
                    )
                    self.logger.warning(
                        "High UDP rate from %s; trust=%s",
                        ip.src, self.trust[key]
                    )

                if self.high_windows[key] >= self.BLOCK_THRESHOLD:
                    self.apply_block(datapath)
                    self.blocked.add(key)
                    return

                if high:
                    self.apply_rate_limit(datapath)

            self.packet_counts[key] = (count + 1, start)

        self.mac_to_port.setdefault(datapath.id, {})
        self.mac_to_port[datapath.id][eth.src] = in_port
        out_port = self.mac_to_port[datapath.id].get(
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

        data = msg.data if msg.buffer_id == ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(
            datapath=datapath,
            buffer_id=msg.buffer_id,
            in_port=in_port,
            actions=actions,
            data=data
        )
        datapath.send_msg(out)
