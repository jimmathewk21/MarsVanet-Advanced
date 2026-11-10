"""Lazy Mininet-WiFi adapter for the common benchmark topology.

Importing this module is safe on Windows. Network construction imports
Mininet-WiFi only when explicitly requested by a later live runner.
"""

from dataclasses import dataclass
import re

try:
    from .topology_spec import TOPOLOGY_SPEC, validate_topology_spec
except ImportError:  # direct ``python benchmark/mininet_topology.py`` use
    from topology_spec import TOPOLOGY_SPEC, validate_topology_spec


class MininetDependencyError(RuntimeError):
    """Raised when live topology construction is requested without Mininet."""


@dataclass
class TopologyHandles:
    net: object
    stations: dict
    access_points: dict
    backbone: object
    controller: object
    spec: dict
    links: list


def _load_mininet():
    try:
        from mininet.node import OVSSwitch, RemoteController
        from mn_wifi.net import Mininet_wifi
        from mn_wifi.node import OVSKernelAP
    except (ImportError, ModuleNotFoundError) as error:
        raise MininetDependencyError(
            "Mininet-WiFi topology construction is unavailable; install and "
            "run it only on the intended Ubuntu test host. No topology was created."
        ) from error
    return Mininet_wifi, OVSSwitch, OVSKernelAP, RemoteController


def create_topology(controller_ip=None, controller_port=None, spec=None):
    """Create, but do not build/start, the declarative Mininet-WiFi topology.

    The caller remains responsible for explicitly starting/stopping the
    returned network. This function creates no mobility schedule or traffic.
    """
    spec = TOPOLOGY_SPEC if spec is None else spec
    errors = validate_topology_spec(spec)
    if errors:
        raise ValueError("invalid benchmark topology spec: " + "; ".join(errors))
    Mininet_wifi, OVSSwitch, OVSKernelAP, RemoteController = _load_mininet()

    net = Mininet_wifi(switch=OVSSwitch, accessPoint=OVSKernelAP)
    stations = {}
    for name, values in spec["stations"].items():
        stations[name] = net.addStation(
            name, ip=values["ip"], position=values["position"]
        )

    access_points = {}
    for name, values in spec["access_points"].items():
        access_points[name] = net.addAccessPoint(
            name,
            dpid=values["dpid"],
            protocols=values["protocols"],
            ssid=values["ssid"],
            mode=values["mode"],
            channel=values["channel"],
            position=values["position"],
            range=values["range"],
            client_isolation=values["client_isolation"],
        )

    switch_spec = spec["switch"]
    backbone = net.addSwitch(
        switch_spec["name"], dpid=switch_spec["dpid"],
        protocols=switch_spec["protocols"],
    )
    endpoint = spec["controller_endpoint"]
    controller = net.addController(
        "c0", controller=RemoteController,
        ip=controller_ip or endpoint["ip"],
        port=int(controller_port or endpoint["port"]),
    )
    net.setPropagationModel(
        model=spec["rf"]["propagation_model"],
        exp=spec["rf"]["propagation_exponent"],
    )
    # Mininet-WiFi registers radio ports during configureNodes. Request the AP
    # wired port as 2 so AP2's radio/wired intent matches M2's defaults; actual
    # resulting OVS ofports must still pass the live validator.
    net.configureNodes()
    links = []
    for link in spec["links"]:
        links.append(net.addLink(
            access_points[link["node1"]], backbone,
            port1=link["port1"], port2=link["port2"],
        ))

    return TopologyHandles(net, stations, access_points, backbone,
                           controller, spec, links)


def _interfaces(node):
    values = node.wintfs
    return list(values.values()) if hasattr(values, "values") else list(values)


def _read_ofport(node, interface):
    output, error, code = node.pexec([
        "ovs-vsctl", "--timeout=5", "get", "Interface", interface, "ofport",
    ])
    value = output.strip()
    if code or not value.isdigit() or int(value) <= 0:
        raise RuntimeError(
            f"{node.name}: interface {interface} has unusable OVS ofport "
            f"{value!r}: {(error or output).strip()}"
        )
    return int(value)


def _interface_at_port(node, requested_port):
    """Resolve a Mininet interface from its node port maps and verify its port."""
    intfs = getattr(node, "intfs", {})
    interface = intfs.get(requested_port) if hasattr(intfs, "get") else None
    if interface is None:
        ports = getattr(node, "ports", {})
        if hasattr(ports, "items"):
            interface = next(
                (intf for intf, port in ports.items() if port == requested_port),
                None,
            )
    if interface is None:
        raise RuntimeError(
            f"{node.name}: Mininet has no interface assigned to requested port "
            f"{requested_port}"
        )
    ports = getattr(node, "ports", {})
    actual_port = ports.get(interface) if hasattr(ports, "get") else None
    if actual_port is not None and actual_port != requested_port:
        raise RuntimeError(
            f"{node.name}: interface {interface.name} is mapped to port "
            f"{actual_port}, expected {requested_port}"
        )
    return interface


def _resolve_wired_link(handles, link_spec, link_result=None):
    """Find wired AP/backbone interfaces even when addLink returns None.

    Node port maps are authoritative. When Mininet supplies a link object, its
    interfaces are also checked against those maps so the fallback does not
    weaken validation for implementations that return link objects.
    """
    ap = handles.access_points[link_spec["node1"]]
    switch = handles.backbone
    ap_interface = _interface_at_port(ap, link_spec["port1"])
    switch_interface = _interface_at_port(switch, link_spec["port2"])

    if ap_interface in _interfaces(ap):
        raise RuntimeError(
            f"{ap.name}: requested wired port {link_spec['port1']} resolves to "
            "a wireless interface"
        )
    if link_result is not None:
        if (getattr(getattr(link_result, "intf1", None), "name", None)
                != ap_interface.name):
            raise RuntimeError(
                f"{ap.name}: returned link interface does not match requested "
                f"port {link_spec['port1']}"
            )
        if (getattr(getattr(link_result, "intf2", None), "name", None)
                != switch_interface.name):
            raise RuntimeError(
                f"{switch.name}: returned link interface does not match requested "
                f"port {link_spec['port2']}"
            )
    return ap_interface.name, switch_interface.name


def _verify_wired_links(handles):
    """Verify every declared wired link through node maps and OVS ofports."""
    for index, link_spec in enumerate(handles.spec["links"]):
        ap = handles.access_points[link_spec["node1"]]
        link_result = handles.links[index] if index < len(handles.links) else None
        ap_interface, switch_interface = _resolve_wired_link(
            handles, link_spec, link_result
        )
        ap_port = _read_ofport(ap, ap_interface)
        switch_port = _read_ofport(handles.backbone, switch_interface)
        if ap_port != link_spec["port1"] or switch_port != link_spec["port2"]:
            raise RuntimeError(
                f"requested ports {link_spec['node1']}:{link_spec['port1']} / "
                f"{link_spec['node2']}:{link_spec['port2']} but OVS reports "
                f"{ap_port}/{switch_port}"
            )


def _read_dpid(node):
    output, error, code = node.pexec([
        "ovs-vsctl", "--timeout=5", "get", "Bridge", node.name,
        "other_config:datapath-id",
    ])
    value = output.strip().strip('"').replace(":", "").lower()
    if code or not value:
        raise RuntimeError(f"{node.name}: could not read configured datapath ID")
    if value.startswith("0x"):
        value = value[2:]
    return value.zfill(16)


def _verify_bridge_protocol(node, expected):
    output, error, code = node.pexec([
        "ovs-vsctl", "--timeout=5", "get", "Bridge", node.name, "protocols",
    ])
    if code or expected not in output:
        raise RuntimeError(
            f"{node.name}: expected OpenFlow protocol {expected}; "
            f"OVS reports {(error or output).strip()}"
        )


def _associate_station(station, ap, timeout=10):
    import time

    station_radios, ap_radios = _interfaces(station), _interfaces(ap)
    if len(station_radios) != 1 or len(ap_radios) != 1:
        raise RuntimeError("common topology requires one station/AP radio each")
    radio, ap_radio = station_radios[0], ap_radios[0]
    bssid = ap_radio.mac or ap_radio.getMAC()
    if not bssid:
        raise RuntimeError(f"{ap.name}: cannot determine AP BSSID")
    deadline = time.monotonic() + timeout
    retry_at = 0.0
    while True:
        output, error, code = station.pexec(["iw", "dev", radio.name, "link"])
        connected = re.search(r"Connected to ([0-9a-fA-F:]{17})\b", output)
        if code == 0 and connected and connected.group(1).lower() == bssid.lower():
            return
        now = time.monotonic()
        if now >= deadline:
            raise RuntimeError(
                f"{station.name} failed to associate with {ap.name}: "
                f"{(error or output).strip()}"
            )
        if now >= retry_at:
            if radio.associatedTo:
                radio.disconnect(radio.associatedTo)
            station.setAssociation(ap, intf=radio.name)
            retry_at = now + 2.0
        time.sleep(0.25)


def _verify_wireless_ports(ap, timeout=10):
    """Match Methodology 3's idempotent radio bridge check."""
    import time

    radios = list(ap.wintfs.values())
    if not radios:
        raise RuntimeError(f"{ap.name} has no configured wireless interfaces")
    for radio in radios:
        output, error, code = ap.pexec([
            "ovs-vsctl", "--timeout=5", "list-ports", ap.name,
        ])
        if code:
            raise RuntimeError(f"could not inspect {ap.name} ports: {(error or output).strip()}")
        if radio.name not in output.splitlines():
            output, error, code = ap.pexec([
                "ovs-vsctl", "--timeout=5", "--may-exist", "add-port",
                ap.name, radio.name,
            ])
            if code:
                raise RuntimeError(f"could not attach {radio.name}: {(error or output).strip()}")
        deadline = time.monotonic() + timeout
        while True:
            output, error, code = ap.pexec([
                "ovs-vsctl", "--timeout=5", "get", "Interface",
                radio.name, "ofport",
            ])
            ofport = output.strip()
            if code == 0 and ofport.isdigit() and int(ofport) > 0:
                break
            if time.monotonic() >= deadline:
                raise RuntimeError(f"{ap.name}: {radio.name} has no usable OVS ofport")
            time.sleep(0.25)


def start_topology(handles):
    """Start the supplied topology and associate stations to fixed APs.

    No mobility schedule or workload is started. AP association follows the
    spec to keep RF and role placement stable across benchmark conditions.
    """
    handles.net.build()
    handles.net.start()
    for ap in handles.access_points.values():
        _verify_wireless_ports(ap)
    nodes = {**handles.access_points, handles.backbone.name: handles.backbone}
    for name, node in nodes.items():
        expected = (handles.spec["access_points"].get(name)
                    or handles.spec["switch"])
        if _read_dpid(node) != expected["dpid"].lower().zfill(16):
            raise RuntimeError(f"{name}: OVS datapath ID does not match topology spec")
        _verify_bridge_protocol(node, expected["protocols"])
    # Verify requested OVS port maps rather than treating Mininet arguments as
    # proof that the resulting OpenFlow ports match Methodology 2 defaults.
    _verify_wired_links(handles)

    for station_name, values in handles.spec["stations"].items():
        station = handles.stations[station_name]
        ap = handles.access_points[values["ap"]]
        ap_radios = _interfaces(ap)
        if len(ap_radios) != 1:
            raise RuntimeError("common topology requires one AP radio each")
        ap_radio = ap_radios[0]
        ap_ofport = _read_ofport(ap, ap_radio.name)
        radio_port_expectation = handles.spec.get("expected_wireless_port", {}).get("port")
        if radio_port_expectation is not None and ap_ofport != radio_port_expectation:
            raise RuntimeError(
                f"{ap.name} wireless ingress port expected {radio_port_expectation}, "
                f"OVS reports {ap_ofport}"
            )
        _associate_station(station, ap)
    return handles
