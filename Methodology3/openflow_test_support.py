"""Small isolated Ryu/OpenFlow doubles; never installed into application imports."""
import importlib.util
import logging
import sys
from pathlib import Path
from types import ModuleType, SimpleNamespace as NS
from unittest.mock import Mock, patch


class RyuApp:
    def __init__(self, *args, **kwargs):
        self.logger = logging.getLogger("methodology3-test")
        self.logger.addHandler(logging.NullHandler())
        self.logger.propagate = False

    def close(self):
        pass


def load_controller():
    names = ["ryu", "ryu.base", "ryu.base.app_manager", "ryu.controller",
             "ryu.controller.ofp_event", "ryu.controller.handler", "ryu.lib",
             "ryu.lib.hub", "ryu.lib.packet", "ryu.ofproto", "ryu.ofproto.ofproto_v1_3"]
    names += ["ryu.lib.packet." + name for name in ("packet", "ethernet", "ipv4", "udp")]
    modules = {name: ModuleType(name) for name in names}
    for name, module in modules.items():
        parent, _, child = name.rpartition(".")
        if parent in modules:
            setattr(modules[parent], child, module)
    modules["ryu.base.app_manager"].RyuApp = RyuApp
    events = modules["ryu.controller.ofp_event"]
    for name in ("EventOFPSwitchFeatures", "EventOFPStateChange", "EventOFPBarrierReply",
                 "EventOFPErrorMsg", "EventOFPPacketIn", "EventOFPPortDescStatsReply",
                 "EventOFPPortStatus"):
        setattr(events, name, type(name, (), {}))
    handler = modules["ryu.controller.handler"]
    for name in ("CONFIG_DISPATCHER", "MAIN_DISPATCHER", "DEAD_DISPATCHER"):
        setattr(handler, name, name)
    handler.set_ev_cls = lambda *args: lambda function: function
    modules["ryu.ofproto.ofproto_v1_3"].OFP_VERSION = 4
    for name in ("ethernet", "ipv4", "udp"):
        setattr(modules["ryu.lib.packet." + name], name, type(name, (), {}))
    modules["ryu.lib.packet.packet"].Packet = Mock()
    for name in ("spawn", "sleep", "kill"):
        setattr(modules["ryu.lib.hub"], name, Mock())
    spec = importlib.util.spec_from_file_location("med3_controller_tested", Path(__file__).with_name("controller.py"))
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, dict(modules, med3_controller_tested=module)):
        spec.loader.exec_module(module)
    return module


def record(kind, **kwargs):
    return NS(kind=kind, **kwargs)


class Parser:
    def OFPFlowMod(self, **kwargs):
        defaults = dict(command=0, table_id=0, priority=32768, instructions=[], cookie=0,
                        cookie_mask=0, idle_timeout=0, hard_timeout=0)
        defaults.update(kwargs)
        return record("flow", **defaults)

    def OFPMatch(self, **kwargs):
        return kwargs

    def OFPActionOutput(self, port, max_len=0):
        return record("output", port=port, max_len=max_len)

    def OFPInstructionActions(self, type_, actions):
        return record("actions", type=type_, actions=actions)

    def OFPInstructionGotoTable(self, table_id):
        return record("goto", table_id=table_id)

    def OFPInstructionMeter(self, meter_id):
        return record("meter_instruction", meter_id=meter_id)

    def OFPMeterBandDrop(self, rate, burst_size=0):
        return record("band_drop", rate=rate, burst_size=burst_size)

    def OFPMeterMod(self, datapath, command=0, flags=1, meter_id=1, bands=None):
        return record("meter", datapath=datapath, command=command, flags=flags,
                      meter_id=meter_id, bands=bands)

    def OFPBarrierRequest(self, datapath):
        return record("barrier", datapath=datapath)

    def OFPPortDescStatsRequest(self, datapath, flags=0):
        return record("port_request", datapath=datapath, flags=flags)


class Datapath:
    ofproto = NS(OFPFC_ADD=0, OFPFC_DELETE=3, OFPTT_ALL=255,
                 OFPP_ANY=0xffffffff, OFPG_ANY=0xffffffff,
                 OFPP_NORMAL=0xfffffffa, OFPP_CONTROLLER=0xfffffffd, OFPP_IN_PORT=0xfffffff8,
                 OFPCML_NO_BUFFER=0xffff, OFPIT_APPLY_ACTIONS=4,
                 OFPMC_ADD=0, OFPMC_MODIFY=1, OFPMC_DELETE=2,
                 OFPMF_KBPS=1, OFPMF_STATS=8, OFPMPF_REPLY_MORE=1, OFPPR_DELETE=1)

    def __init__(self, dpid):
        self.id = dpid
        self.ofproto_parser = Parser()
        self.sent = []
        self.next_xid = 0

    def set_xid(self, message):
        self.next_xid += 1
        message.xid = self.next_xid

    def send_msg(self, message):
        self.sent.append(message)
        return True
