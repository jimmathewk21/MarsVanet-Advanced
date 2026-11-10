"""Declarative common two-AP topology used by the benchmark planner."""

TOPOLOGY_SPEC = {
    "id": "common_2ap_candidate_v1",
    "stations": {
        "sta1": {"ip": "10.0.0.1/24", "ap": "ap1", "position": "10,30,0"},
        "sta2": {"ip": "10.0.0.2/24", "ap": "ap1", "position": "20,30,0"},
        "sta3": {"ip": "10.0.0.3/24", "ap": "ap2", "position": "60,30,0"},
    },
    "access_points": {
        "ap1": {
            "dpid": "1000000000000001", "protocols": "OpenFlow13",
            "ssid": "sdnvanet", "mode": "g", "channel": "1",
            "position": "15,30,0", "range": 35,
            "client_isolation": False,
        },
        "ap2": {
            "dpid": "1000000000000002", "protocols": "OpenFlow13",
            "ssid": "sdnvanet", "mode": "g", "channel": "6",
            "position": "55,30,0", "range": 35,
            "client_isolation": True,
        },
    },
    "switch": {"name": "s1", "dpid": "0000000000000001", "protocols": "OpenFlow13"},
    # Port numbering requested from Mininet-WiFi. Actual OVS ofports still
    # require live verification because versions may add/reorder radio ports.
    "links": [
        {"node1": "ap1", "node2": "s1", "port1": 2, "port2": 1},
        {"node1": "ap2", "node2": "s1", "port1": 2, "port2": 2},
    ],
    "expected_ap2_ports": {
        "wireless_ingress": {"port": 1, "verification": "runtime_required"},
        "backbone_egress": {"port": 2, "verification": "runtime_required"},
    },
    "expected_wireless_port": {"port": 1, "verification": "runtime_required"},
    "rf": {
        "propagation_model": "logDistance", "propagation_exponent": 3,
        "mobility_enabled": False,
    },
    "controller_endpoint": {"ip": "127.0.0.1", "port": 6653},
    "runtime_validation": "not_performed",
}


def validate_topology_spec(spec=None):
    """Validate declared topology consistency without Mininet imports."""
    spec = TOPOLOGY_SPEC if spec is None else spec
    errors = []
    stations = spec.get("stations", {})
    aps = spec.get("access_points", {})
    if len(aps) != 2:
        errors.append("exactly two access points are required")
    if len([name for name in stations if name in {"sta1", "sta2", "sta3"}]) != 3:
        errors.append("sta1, sta2, and sta3 must be declared")
    ips = [entry.get("ip", "").split("/")[0] for entry in stations.values()]
    if len(ips) != len(set(ips)):
        errors.append("station IP addresses must be unique")
    for name, station in stations.items():
        if station.get("ap") not in aps:
            errors.append(f"{name} references an unknown AP")
    dpids = [entry.get("dpid") for entry in aps.values()]
    switch = spec.get("switch", {})
    if switch.get("dpid"):
        dpids.append(switch["dpid"])
    if len(dpids) != len(set(dpids)):
        errors.append("AP and backbone DPIDs must be unique")
    if any(entry.get("protocols") != "OpenFlow13" for entry in aps.values()):
        errors.append("all APs must request OpenFlow13")
    if switch.get("protocols") != "OpenFlow13":
        errors.append("backbone switch must request OpenFlow13")
    links = spec.get("links", [])
    if (len(links) != len(aps)
            or {link.get("node1") for link in links} != set(aps)):
        errors.append("each AP must have exactly one declared backbone link")
    backbone_ports = [link.get("port2") for link in links]
    if len(backbone_ports) != len(set(backbone_ports)):
        errors.append("backbone link ports must be unique")
    if spec.get("rf", {}).get("mobility_enabled") is not False:
        errors.append("mobility must remain disabled in the common topology")
    return errors
