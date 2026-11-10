
#!/usr/bin/env python3

import csv
import time
from pathlib import Path

from mininet.log import setLogLevel, info
from mininet.node import Controller
from mn_wifi.net import Mininet_wifi

OUTPUT = Path(__file__).resolve().parent / "handover_log.csv"
HANDOVER_GAP_LIMIT = 5.0


def topology():
    net = Mininet_wifi(controller=Controller)

    sta1 = net.addStation(
        'sta1',
        ip='10.0.0.1/24',
        position='10,30,0'
    )

    ap1 = net.addAccessPoint(
        'ap1',
        ssid='handover-net',
        mode='g',
        channel='1',
        position='15,30,0',
        range=35
    )

    ap2 = net.addAccessPoint(
        'ap2',
        ssid='handover-net',
        mode='g',
        channel='6',
        position='55,30,0',
        range=35
    )

    net.setPropagationModel(model='logDistance', exp=3)
    net.configureNodes()

    net.startMobility(time=0)
    net.mobility(sta1, 'start', time=1, position='10,30,0')
    net.mobility(sta1, 'stop', time=20, position='65,30,0')
    net.stopMobility(time=21)

    info("*** Building handover test network\n")
    net.build()

    ap1.start([])
    ap2.start([])

    sta_intf = sta1.wintfs[0]
    previous_ap = None
    start = time.monotonic()
    records = []
    pending_departure = None
    handovers = 0

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
        file.flush()

        info("*** Monitoring station association for 30 seconds\n")

        try:
            while time.monotonic() - start < 30:
                associated = sta_intf.associatedTo
                current_ap = associated.node.name if associated else "NONE"

                if current_ap != previous_ap:
                    now_unix = time.time()
                    elapsed = round(time.monotonic() - start, 3)
                    old_ap = previous_ap or "NONE"

                    if old_ap != 'NONE' and current_ap == 'NONE':
                        pending_departure = (now_unix, old_ap)

                    elif old_ap == 'NONE' and current_ap != 'NONE':
                        if pending_departure is not None:
                            departure_time, departed_ap = pending_departure
                            gap = now_unix - departure_time

                            if (
                                departed_ap != current_ap
                                and 0 <= gap <= HANDOVER_GAP_LIMIT
                            ):
                                handovers += 1

                        pending_departure = None

                    row = [
                        round(now_unix, 3),
                        elapsed,
                        sta1.name,
                        old_ap,
                        current_ap,
                        handovers
                    ]

                    records.append(row)
                    writer.writerow(row)
                    file.flush()

                    info(
                        f"Association change: {old_ap} -> {current_ap}; "
                        f"completed handovers={handovers}\n"
                    )

                    previous_ap = current_ap

                time.sleep(0.2)

        finally:
            net.stop()

    print(f"Handover log: {OUTPUT}")
    print(f"Association transitions: {len(records)}")
    print(f"Observed AP handovers: {handovers}")


if __name__ == '__main__':
    setLogLevel('info')
    topology()
