#!/usr/bin/env python3
"""Two-access-point Mininet-WiFi topology with a live AP handover monitor.

The controller endpoint is configurable via the environment so the same script
runs against controllers on different hosts/ports:
    DOS_CONTROLLER_IP   (default 127.0.0.1)
    DOS_CONTROLLER_PORT (default 6653)
"""

import csv
import os
import time
import threading
from pathlib import Path

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSSwitch
from handover_tracker import HandoverTracker

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "handover_test"
    / "handover_log.csv"
)

CONTROLLER_IP = os.environ.get("DOS_CONTROLLER_IP", "127.0.0.1")
CONTROLLER_PORT = int(os.environ.get("DOS_CONTROLLER_PORT", "6653"))

# Radio parameters, overridable so stations near a cell edge can be made to
# associate reliably without editing the script. logDistance exp=3 is quite
# lossy; if sta2/sta3 do not associate, lower DOS_PROP_EXP (e.g. 2.0-2.5) or
# raise DOS_AP_RANGE / DOS_AP_TXPOWER.
PROP_EXP = float(os.environ.get("DOS_PROP_EXP", "3"))
AP_RANGE = int(os.environ.get("DOS_AP_RANGE", "35"))
# Optional explicit AP transmit power in dBm; empty means use the mn-wifi default.
_txp = os.environ.get("DOS_AP_TXPOWER", "")
AP_TXPOWER = int(_txp) if _txp else None

# Intended station->AP placement so the attack flow crosses the MONITORED AP.
# Detection watches victim-bound UDP ingressing AP2, so the attacker (sta3)
# must sit on AP2 and the victim (sta2) on AP1. sta1 is left unpinned so it can
# roam for the handover demonstration. Override with e.g.
#   DOS_STATION_AP_MAP="sta2:ap1,sta3:ap2"
STATION_AP_MAP = os.environ.get("DOS_STATION_AP_MAP", "sta2:ap1,sta3:ap2")


def _ap_kwargs(channel, position):
    """Common addAccessPoint kwargs, adding txpower only when configured."""
    kwargs = dict(
        ssid='sdnvanet',
        mode='g',
        channel=channel,
        position=position,
        range=AP_RANGE,
        client_isolation=False,
    )
    if AP_TXPOWER is not None:
        kwargs['txpower'] = AP_TXPOWER
    return kwargs


def ensure_ap_wireless_port(ap):
    """Ensure the AP's managed wireless interface is a port on its OVS bridge.

    In some Mininet-WiFi / OVS versions the AP's wlan interface is NOT attached
    to the bridge automatically (observed here for ap1 while ap2 was fine),
    leaving any station associated to that AP with no datapath into the bridge
    and so no connectivity. This is idempotent and symmetric: it attaches the
    port only if it is missing, for whichever AP needs it, then prints the
    resulting membership so the fix can be confirmed.
    """
    try:
        wlan = ap.wintfs[0].name
    except (AttributeError, IndexError):
        wlan = '%s-wlan1' % ap.name
    ports = ap.cmd('ovs-vsctl list-ports %s' % ap.name)
    if wlan not in ports:
        info('*** Attaching %s to OVS bridge %s (was missing)\n'
             % (wlan, ap.name))
        ap.cmd('ovs-vsctl add-port %s %s' % (ap.name, wlan))
    else:
        info('*** %s already attached to %s\n' % (wlan, ap.name))
    info('*** %s bridge ports now: %s\n'
         % (ap.name, ap.cmd('ovs-vsctl list-ports %s' % ap.name).strip()))


def bring_up_stations(net):
    """Bring every station's wlan interface up and report association state.

    Addresses the 'interfaces are down / Wi-Fi disconnected' symptom for static
    stations. If a station still shows 'Not connected' after this, the cause is
    radio-layer (propagation/positions/txpower), not OVS; adjust DOS_PROP_EXP /
    DOS_AP_RANGE / DOS_AP_TXPOWER or the station positions.
    """
    for sta in net.stations:
        try:
            wlan = sta.wintfs[0].name
        except (AttributeError, IndexError):
            wlan = '%s-wlan0' % sta.name
        sta.cmd('ip link set %s up' % wlan)
        link = sta.cmd('iw dev %s link' % wlan).strip().splitlines()
        state = link[0] if link else 'unknown'
        info('*** %s (%s): %s\n' % (sta.name, wlan, state))


def _ap_bssid(ap):
    """Return the BSSID (wlan MAC) of an access point, or None."""
    try:
        wlan = ap.wintfs[0].name
    except (AttributeError, IndexError):
        wlan = '%s-wlan1' % ap.name
    out = ap.cmd('iw dev %s info' % wlan)
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('addr '):
            return line.split()[1]
    try:
        return ap.wintfs[0].mac
    except (AttributeError, IndexError):
        return None


def associate_stations_to_aps(net, mapping):
    """Pin specific stations to specific APs by BSSID.

    Both APs share SSID 'sdnvanet', so the driver may associate a station to
    the wrong AP by signal. Connecting to a specific BSSID makes the placement
    deterministic, which is required so the attacker's traffic ingresses the
    monitored AP (AP2). Open network, so a plain `iw connect` is enough.
    """
    nodes = {n.name: n for n in net.stations}
    for ap in getattr(net, 'aps', []):
        nodes[ap.name] = ap
    for sta_name, ap_name in mapping.items():
        sta = nodes.get(sta_name)
        ap = nodes.get(ap_name)
        if sta is None or ap is None:
            info('*** skip association %s->%s (unknown node)\n'
                 % (sta_name, ap_name))
            continue
        try:
            wlan = sta.wintfs[0].name
        except (AttributeError, IndexError):
            wlan = '%s-wlan0' % sta.name
        bssid = _ap_bssid(ap)
        if bssid:
            sta.cmd('iw dev %s connect sdnvanet %s' % (wlan, bssid))
            info('*** %s -> %s (bssid %s)\n' % (sta_name, ap_name, bssid))
        else:
            sta.cmd('iw dev %s connect sdnvanet' % wlan)
            info('*** %s -> %s (ssid only; bssid unknown)\n'
                 % (sta_name, ap_name))


def _parse_station_ap_map(spec):
    mapping = {}
    for pair in spec.split(','):
        pair = pair.strip()
        if ':' in pair:
            sta, ap = pair.split(':', 1)
            mapping[sta.strip()] = ap.strip()
    return mapping


def topology():
    net = Mininet_wifi(switch=OVSSwitch)

    info("*** Creating nodes\n")

    sta1 = net.addStation(
        'sta1',
        ip='10.0.0.1/24',
        position='10,30,0'
    )

    net.addStation(
        'sta2',
        ip='10.0.0.2/24',
        position='20,30,0'
    )

    net.addStation(
        'sta3',
        ip='10.0.0.3/24',
        position='60,30,0'
    )

    ap1 = net.addAccessPoint('ap1', **_ap_kwargs('1', '15,30,0'))
    ap2 = net.addAccessPoint('ap2', **_ap_kwargs('6', '55,30,0'))

    s1 = net.addSwitch('s1')

    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip=CONTROLLER_IP,
        port=CONTROLLER_PORT
    )

    info("*** Configuring wireless nodes\n")
    net.setPropagationModel(model='logDistance', exp=PROP_EXP)
    net.configureNodes()

    net.addLink(ap1, s1, port1=1, port2=1)
    net.addLink(ap2, s1, port1=2, port2=2)

    info("*** Configuring station mobility\n")
    net.startMobility(time=0)
    net.mobility(sta1, 'start', time=1, position='10,30,0')
    net.mobility(sta1, 'stop', time=20, position='65,30,0')
    net.stopMobility(time=21)

    info("*** Building network\n")
    net.build()

    c0.start()
    s1.start([c0])
    ap1.start([c0])
    ap2.start([c0])

    # Fix 1 (confirmed problem): some Mininet-WiFi/OVS versions attach ap2's
    # wireless interface to its bridge but not ap1's. A missing wlan port means
    # stations on that AP have no datapath into the bridge, so pings fail even
    # though association succeeds. Attach each AP's wlan port if (and only if)
    # it is missing, symmetrically, and print the result so it can be verified.
    # (An earlier revision removed the original blind `add-port ap1 ap1-wlan1`
    # on the assumption mn-wifi always auto-attaches; live testing showed ap1
    # is not reliably attached, so a verified idempotent attach is restored.)
    info("*** Ensuring AP wireless interfaces are bridged\n")
    ensure_ap_wireless_port(ap1)
    ensure_ap_wireless_port(ap2)

    # Fix 2 (station interfaces down / not associated): bring station wlan
    # interfaces up and report association. If any station is still "Not
    # connected", the cause is radio-layer, not OVS -- adjust DOS_PROP_EXP /
    # DOS_AP_RANGE / DOS_AP_TXPOWER or the station positions (see README).
    info("*** Bringing station interfaces up and checking association\n")
    bring_up_stations(net)

    # Fix 3 (traffic path): pin the attacker to AP2 and the victim to AP1 so the
    # attack flow ingresses the monitored AP. sta1 is left to roam. Give the
    # association a moment to settle, then re-report.
    mapping = _parse_station_ap_map(STATION_AP_MAP)
    if mapping:
        info("*** Pinning stations to intended APs: %s\n" % STATION_AP_MAP)
        associate_stations_to_aps(net, mapping)
        time.sleep(2)
        bring_up_stations(net)

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    stop_monitor = threading.Event()
    handover_state = HandoverTracker()

    start_time = time.time()

    def get_associated_ap():
        intf = sta1.wintfs[0]
        associated = intf.associatedTo

        if not associated:
            return 'NONE'

        node = getattr(associated, 'node', None)

        if node is not None:
            return node.name

        return str(associated)

    def monitor_association():
        current_ap = get_associated_ap()
        handover_state.observe(current_ap, time.time())

        with open(OUTPUT, 'w', newline='', buffering=1) as file:
            writer = csv.writer(file)
            writer.writerow([
                'timestamp_unix',
                'time_seconds',
                'station',
                'previous_ap',
                'current_ap',
                'handover_count'
            ])

            writer.writerow([
                f'{time.time():.3f}',
                f'{time.time() - start_time:.3f}',
                'sta1',
                'NONE',
                current_ap,
                0
            ])

            info(f"*** Initial association: sta1 -> {current_ap}\n")

            while not stop_monitor.is_set():
                try:
                    new_ap = get_associated_ap()
                    now = time.time()
                    transition = handover_state.observe(new_ap, now)
                    if transition is not None:
                        old_ap, current_ap, handover_count, completed = transition
                        elapsed = now - start_time
                        writer.writerow([
                            f'{now:.3f}',
                            f'{elapsed:.3f}',
                            'sta1',
                            old_ap,
                            current_ap,
                            handover_count
                        ])
                        if completed:
                            info(
                                f"*** HANDOVER: sta1 {old_ap} -> {current_ap}; "
                                f"total={handover_count}\n"
                            )
                        else:
                            info(
                                f"*** Association change: sta1 "
                                f"{old_ap} -> {current_ap}\n"
                            )

                    stop_monitor.wait(0.2)

                except Exception as error:
                    info(f"*** Handover monitor error: {error}\n")
                    stop_monitor.wait(1)

    monitor_thread = threading.Thread(
        target=monitor_association,
        daemon=True
    )

    info("*** Starting live AP handover monitor\n")
    info(f"*** CSV output: {OUTPUT}\n")

    monitor_thread.start()

    try:
        CLI(net)
    finally:
        stop_monitor.set()
        monitor_thread.join(timeout=2)
        net.stop()

    print("Handover log:", OUTPUT)
    print("Observed completed handovers:", handover_state.handovers)


if __name__ == '__main__':
    setLogLevel('info')
    topology()
