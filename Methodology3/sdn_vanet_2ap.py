#!/usr/bin/env python3
"""Isolated Methodology 3 testbed; run with root in the Mininet-WiFi VM.

Matches Methodology 2's stations and AP backbone, with explicit OF1.3 DPIDs
and client isolation so same-AP traffic traverses OpenFlow. Move sta1 from
the CLI when ready instead of racing an automatic 20-second handover.
"""

import os
import re
import time

from mininet.log import info, setLogLevel
from mininet.node import OVSSwitch, RemoteController
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import OVSKernelAP

from safety_messages import VEHICLE_IPS


def _checked(node, *command):
    """Run an argv command in the node's namespace and surface failures."""
    output, error, code = node.pexec(list(command))
    if code:
        raise RuntimeError("%s: %s failed: %s" % (
            node.name, " ".join(command), (error or output).strip(),
        ))
    return output.strip()


def ensure_ap_wireless_ports(ap, timeout=10):
    """Repair missing radio bridge membership after OVS startup, never flows."""
    if not ap.wintfs:
        raise RuntimeError("%s has no configured wireless interfaces" % ap.name)
    for radio in ap.wintfs.values():
        ports = _checked(ap, "ovs-vsctl", "--timeout=5", "list-ports", ap.name)
        if radio.name not in ports.splitlines():
            info("*** Attaching missing radio %s to %s\n" % (radio.name, ap.name))
            # --may-exist is idempotent; a port on another bridge is an error.
            # Do not request a port number or recreate the bridge/controller.
            _checked(ap, "ovs-vsctl", "--timeout=5", "--may-exist",
                     "add-port", ap.name, radio.name)
        deadline = time.monotonic() + timeout
        while True:
            ports = _checked(ap, "ovs-vsctl", "--timeout=5", "list-ports", ap.name)
            ofport = _checked(ap, "ovs-vsctl", "--timeout=5",
                              "get", "Interface", radio.name, "ofport")
            if radio.name in ports.splitlines() and ofport.isdigit() and int(ofport) > 0:
                info("*** Verified %s on %s (ofport %s)\n" % (radio.name, ap.name, ofport))
                break
            if time.monotonic() >= deadline:
                raise RuntimeError("%s: radio %s not ready in OVS (ofport=%s)" % (
                    ap.name, radio.name, ofport,
                ))
            time.sleep(0.25)


def associate_station(station, ap, timeout=10):
    """Seed one initial association; leave subsequent mobility to Mininet-WiFi."""
    if len(station.wintfs) != 1 or len(ap.wintfs) != 1:
        raise RuntimeError("Initial association expects one radio per station/AP")
    radio, = station.wintfs.values()
    ap_radio, = ap.wintfs.values()
    bssid = ap_radio.mac or ap_radio.getMAC()
    if not bssid or not re.fullmatch(r"(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}", bssid):
        raise RuntimeError("%s: cannot determine AP BSSID" % ap.name)
    deadline = time.monotonic() + timeout
    retry_at = 0
    while True:
        link = _checked(station, "iw", "dev", radio.name, "link")
        connected = re.search(r"Connected to ([0-9a-fA-F:]{17})\b", link)
        if connected and connected.group(1).lower() == bssid.lower():
            info("*** Verified %s -> %s (%s)\n" % (station.name, ap.name, bssid))
            return
        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError("%s failed to associate with %s (%s): %s" % (
                station.name, ap.name, bssid, link,
            ))
        if now >= retry_at:
            # Older versions can mark an attempted association as successful.
            # Clear that stale state via the API before requesting a new one.
            if radio.associatedTo:
                radio.disconnect(radio.associatedTo)
            station.setAssociation(ap, intf=radio.name)
            retry_at = now + 2
        time.sleep(0.25)


def topology():
    net = Mininet_wifi(switch=OVSSwitch, accessPoint=OVSKernelAP)
    positions = {"sta1": "10,30,0", "sta2": "20,30,0", "sta3": "60,30,0"}
    stations = {}
    for vehicle_id, address in VEHICLE_IPS.items():
        stations[vehicle_id] = net.addStation(
            vehicle_id, ip=address + "/24", position=positions[vehicle_id])
    ap1 = net.addAccessPoint(
        "ap1", dpid="1000000000000001", protocols="OpenFlow13",
        ssid="sdnvanet", mode="g", channel="1", position="15,30,0",
        range=35, client_isolation=True,
    )
    ap2 = net.addAccessPoint(
        "ap2", dpid="1000000000000002", protocols="OpenFlow13",
        ssid="sdnvanet", mode="g", channel="6", position="55,30,0",
        range=35, client_isolation=True,
    )
    backbone = net.addSwitch("s1", dpid="0000000000000001", protocols="OpenFlow13")
    net.addController(
        "c0", controller=RemoteController,
        ip=os.environ.get("M3_CONTROLLER_IP", "127.0.0.1"),
        port=int(os.environ.get("M3_CONTROLLER_PORT", "6653")),
    )
    try:
        net.setPropagationModel(model="logDistance", exp=3)
        net.configureNodes()
        # configureNodes() has already registered radios. Explicit wired port
        # numbers can overwrite those entries (notably AP1's radio at port 1).
        net.addLink(ap1, backbone)
        net.addLink(ap2, backbone)
        net.build()
        net.start()  # Includes the library's OVS batch-startup handling.
        for ap in (ap1, ap2):
            ensure_ap_wireless_ports(ap)
        for vehicle_id, ap in (("sta1", ap1), ("sta2", ap1), ("sta3", ap2)):
            associate_station(stations[vehicle_id], ap)
        info("*** Move sta1 when ready: py sta1.setPosition('65,30,0')\n")
        CLI(net)
    finally:
        net.stop()


if __name__ == "__main__":
    setLogLevel("info")
    topology()
