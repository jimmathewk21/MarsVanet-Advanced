
#!/usr/bin/env python3

import csv
import time
import threading
from pathlib import Path

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSSwitch

OUTPUT = (
    Path(__file__).resolve().parents[1]
    / "handover_test"
    / "handover_log.csv"
)


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

    ap1 = net.addAccessPoint(
        'ap1',
        ssid='sdnvanet',
        mode='g',
        channel='1',
        position='15,30,0',
        range=35,
        client_isolation=False
    )

    ap2 = net.addAccessPoint(
        'ap2',
        ssid='sdnvanet',
        mode='g',
        channel='6',
        position='55,30,0',
        range=35,
        client_isolation=False
    )

    s1 = net.addSwitch('s1')

    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    info("*** Configuring wireless nodes\n")
    net.setPropagationModel(model='logDistance', exp=3)
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
    ap1.cmd('ovs-vsctl', 'add-port', 'ap1', 'ap1-wlan1')

    OUTPUT.parent.mkdir(parents=True, exist_ok=True)

    stop_monitor = threading.Event()
    handover_state = {
        'previous_ap': None,
        'pending_departure': None,
        'handovers': 0
    }

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
        handover_state['previous_ap'] = current_ap

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
                    old_ap = handover_state['previous_ap']

                    if new_ap != old_ap:
                        now = time.time()
                        elapsed = now - start_time
                        handover_count = 0

                        if new_ap == 'NONE':
                            handover_state['pending_departure'] = (
                                old_ap,
                                now
                            )

                        elif handover_state['pending_departure'] is not None:
                            departed_ap, departed_time = (
                                handover_state['pending_departure']
                            )

                            if (
                                 new_ap != departed_ap
                                 and now - departed_time <= 5 
                            ):
                                handover_state['handovers'] += 1
                                handover_count = handover_state['handovers']

                                writer.writerow([
                                    f'{now:.3f}',
                                    f'{elapsed:.3f}',
                                    'sta1',
                                    departed_ap,
                                    new_ap,
                                    handover_count
                                ])

                                info(
                                    f"*** HANDOVER: sta1 {departed_ap} "
                                    f"-> {new_ap}; total="
                                    f"{handover_count}\n"
                                )

                            handover_state['pending_departure'] = None

                        writer.writerow([
                            f'{now:.3f}',
                            f'{elapsed:.3f}',
                            'sta1',
                            old_ap,
                            new_ap,
                            handover_count
                        ])

                        info(
                            f"*** Association change: sta1 "
                            f"{old_ap} -> {new_ap}\n"
                        )
                        handover_state['previous_ap'] = new_ap

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
    print("Observed completed handovers:", handover_state['handovers'])


if __name__ == '__main__':
    setLogLevel('info')
    topology()
