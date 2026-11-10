#!/usr/bin/env python3

from mininet.log import setLogLevel, info
from mn_wifi.cli import CLI
from mn_wifi.net import Mininet_wifi
from mininet.node import RemoteController, OVSSwitch


def topology():

    net = Mininet_wifi(switch=OVSSwitch)

    info("*** Creating nodes\n")

    sta1 = net.addStation(
        'sta1',
        ip='10.0.0.1/24'
    )

    sta2 = net.addStation(
        'sta2',
        ip='10.0.0.2/24'
    )

    sta3 = net.addStation(
        'sta3',
        ip='10.0.0.3/24'
    )

    ap1 = net.addAccessPoint(
        'ap1',
        ssid='sdnvanet',
        mode='g',
        channel='5',
        client_isolation=False
    )

    s1 = net.addSwitch(
        's1'
    )

    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6653
    )

    info("*** Configuring nodes\n")
    net.configureNodes()

    info("*** Creating links\n")

    net.addLink(sta1, ap1)
    net.addLink(sta2, ap1)
    net.addLink(sta3, ap1)

    net.addLink(ap1, s1)

    info("*** Starting network\n")

    net.build()

    c0.start()
    s1.start([c0])
    ap1.start([c0])

    info("*** Running CLI\n")
    CLI(net)

    info("*** Stopping network\n")
    net.stop()


if __name__ == '__main__':
    setLogLevel('info')
    topology()
