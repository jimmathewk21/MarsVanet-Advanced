"""Static controller/topology compatibility checks (never runtime proof)."""

import ast
import argparse
import json
from pathlib import Path

try:
    from .topology_spec import TOPOLOGY_SPEC, validate_topology_spec
except ImportError:  # direct ``python benchmark/compatibility.py`` invocation
    from topology_spec import TOPOLOGY_SPEC, validate_topology_spec


def _read(path):
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return None


def _class_constants(source, class_name):
    if source is None:
        return {}
    tree = ast.parse(source)
    cls = next((node for node in tree.body
                if isinstance(node, ast.ClassDef) and node.name == class_name), None)
    if cls is None:
        return {}
    result = {}
    for node in cls.body:
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            target, value = node.target, node.value
        elif isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
            target, value = node.targets[0], node.value
        else:
            continue
        try:
            result[target.id] = ast.literal_eval(value)
        except (ValueError, TypeError):
            continue
    return result


def _result(status, findings, source_files):
    return {
        "status": status,
        "static_source_compatible": status in {
            "source_compatible_runtime_unverified",
            "conditional_runtime_port_verification_required",
        },
        "can_operate_correctly": None,
        "findings": findings,
        "source_files": source_files,
        "evidence_scope": "static source/spec comparison only; not proof of runtime compatibility",
        "runtime_validation": "not_performed",
    }


def validate_controller_compatibility(repo_root=None, spec=None):
    """Compare source-level controller assumptions with the topology spec.

    Every result carries runtime_validation=not_performed. AP OpenFlow port
    numbers, packet forwarding, and OVS behavior require a live smoke test.
    """
    root = (Path(repo_root).resolve() if repo_root is not None
            else Path(__file__).resolve().parents[1])
    spec = TOPOLOGY_SPEC if spec is None else spec
    topology_errors = validate_topology_spec(spec)
    m1_path = root / "Methodology1/scripts/dos_defense_static.py"
    m2_path = root / "Methodology2/scripts/dos_defense_v2.py"
    m2_config_path = root / "Methodology2/scripts/med2_config.py"
    m3_controller_path = root / "Methodology3/controller.py"
    m3_safety_path = root / "Methodology3/safety_messages.py"
    m1, m2, m2_config = _read(m1_path), _read(m2_path), _read(m2_config_path)
    m3, m3_safety = _read(m3_controller_path), _read(m3_safety_path)

    reports = {
        "no_defense": _result("runtime_dependency_unverified", [
            "The live runner uses Ryu's built-in ryu.app.simple_switch_13 baseline.",
            "The installed Ryu app and end-to-end forwarding must be verified on the Ubuntu test host.",
        ], ["ryu.app.simple_switch_13 (installed Ryu distribution)"]),
    }

    m1_findings = []
    m1_source_ok = m1 is not None and "OFP_VERSION" in m1
    m1_drop_ok = m1 is not None and 'ipv4_src="10.0.0.3"' in m1 and "ip_proto=17" in m1
    if not m1:
        m1_findings.append("Methodology 1 controller source file is missing.")
    elif not m1_source_ok:
        m1_findings.append("OpenFlow 1.3 declaration was not found in Methodology 1 source.")
    if not m1_drop_ok:
        m1_findings.append("Static UDP source-drop rule did not match expected sta3 source.")
    else:
        m1_findings.append(
            "Static priority-100 rule drops IPv4 UDP from sta3 (10.0.0.3) on every connected datapath, including safety UDP/5005."
        )
        m1_findings.append(
            "Table-miss learning and PacketOut exist in source; end-to-end forwarding remains unverified."
        )
    m1_findings.append("Runtime dependency: Ryu with an OpenFlow 1.3 datapath; not probed by this validator.")
    if topology_errors:
        m1_findings.extend("Topology spec: " + item for item in topology_errors)
    reports["methodology1"] = _result(
        "source_compatible_runtime_unverified" if m1_source_ok and m1_drop_ok and not topology_errors else "blocked",
        m1_findings, [str(m1_path.relative_to(root))],
    )

    m2_values = _class_constants(m2_config, "Med2Config")
    ap2_dpid = int(spec.get("access_points", {}).get("ap2", {}).get("dpid", "0"), 16)
    m2_expected = {
        "ap2_dpid": ap2_dpid,
        "ap2_in_port": spec.get("expected_ap2_ports", {}).get("wireless_ingress", {}).get("port"),
        "ap2_out_port": spec.get("expected_ap2_ports", {}).get("backbone_egress", {}).get("port"),
        "destination_ip": spec.get("stations", {}).get("sta2", {}).get("ip", "").split("/")[0],
    }
    m2_checks = {name: m2_values.get(name) == value
                 for name, value in m2_expected.items()}
    ap2_link = next((link for link in spec.get("links", [])
                     if link.get("node1") == "ap2"), None)
    ap2_link_matches = bool(
        ap2_link and ap2_link.get("port1") == m2_expected["ap2_out_port"]
    )
    m2_findings = []
    if not m2 or not m2_config:
        m2_findings.append("Methodology 2 controller or config source is missing.")
    if m2 and "OFP_VERSION" not in m2:
        m2_findings.append("OpenFlow 1.3 declaration was not found in Methodology 2 source.")
    for name, passed in m2_checks.items():
        m2_findings.append(
            f"{name}: {'matches' if passed else 'MISMATCH'}; controller default="
            f"{m2_values.get(name)!r}, topology expected={m2_expected[name]!r}."
        )
    m2_findings.append(
        "AP2 requested wired-link port matches M2 output default: "
        f"{ap2_link_matches}; actual OVS ofport remains runtime-unverified."
    )
    m2_findings.append(
        "The adapter requests AP2 radio ingress=1 and backbone egress=2, and checks resulting OVS ofports on start; those checks have not been run here."
    )
    m2_findings.append(
        "Before Stage 1, the priority-50 monitor punts matching traffic to the controller and PacketIn handling sends PacketOut; Stage 1 uses the configured AP2 output port. Both paths need forwarding smoke tests."
    )
    m2_findings.append(
        "M2 matches UDP to 10.0.0.2 without a destination-port restriction; rate threshold/state determine enforcement. Its traffic-rate detector is not M3 safety consistency scoring."
    )
    m2_findings.append(
        "DOS_AP2_DPID, DOS_AP2_IN_PORT, DOS_AP2_OUT_PORT and destination-IP environment overrides can change these defaults; the validator does not apply or validate live environment overrides."
    )
    m2_findings.append("Runtime dependencies include Ryu and OVS OpenFlow 1.3 meter support; neither has been exercised here.")
    m2_static_ok = bool(m2 and "OFP_VERSION" in m2 and all(m2_checks.values())
                        and ap2_link_matches and not topology_errors)
    reports["methodology2"] = _result(
        "conditional_runtime_port_verification_required" if m2_static_ok else "blocked",
        m2_findings, [str(m2_path.relative_to(root)), str(m2_config_path.relative_to(root))],
    )

    m3_values = {}
    # SAFETY_MESSAGE_PORT and VEHICLE_IPS are module-level assignments.
    if m3_safety:
        for node in ast.parse(m3_safety).body:
            if isinstance(node, ast.Assign) and len(node.targets) == 1 and isinstance(node.targets[0], ast.Name):
                try:
                    m3_values[node.targets[0].id] = ast.literal_eval(node.value)
                except (ValueError, TypeError):
                    pass
    m3_port = m3_values.get("SAFETY_MESSAGE_PORT")
    m3_ips = m3_values.get("VEHICLE_IPS", {})
    topology_ips = {
        station: entry.get("ip", "").split("/")[0]
        for station, entry in spec.get("stations", {}).items()
    }
    m3_identity_ok = all(m3_ips.get(station) == address
                         for station, address in topology_ips.items())
    m3_structure_ok = bool(m3 and "OFP_VERSION" in m3 and "OFPPortDescStatsRequest" in m3)
    m3_telemetry_ok = bool(
        m3 and "datagram.dst_port != self.SAFETY_MESSAGE_PORT" in m3
        and "SAFETY_MESSAGE_PORT = 5005" in (m3_safety or "")
    )
    m3_findings = [
        f"M3 safety port is {m3_port!r}; topology safety workload must use UDP/5005.",
        f"Configured vehicle identities match station IPs: {m3_identity_ok}.",
        "Controller UDP/5005 source check present: " + str(m3_telemetry_ok) + "; telemetry is consumed after JSON, identity, truncation and datagram checks without PacketOut.",
        "M3 uses a two-table OFPP_NORMAL pipeline and discovers wlan ports for hairpin forwarding; realized port descriptions and data forwarding are unverified.",
        "Runtime dependencies include Ryu, OpenFlow 1.3 multi-table support, OVS meters, and usable port-description replies; not probed here.",
        "Volumetric UDP on other ports is not a Methodology 3 flood-detection workload.",
    ]
    if not m3_structure_ok:
        m3_findings.append("OpenFlow 1.3 / dynamic wireless-port discovery evidence missing from source.")
    reports["methodology3"] = _result(
        "source_compatible_runtime_unverified" if m3_structure_ok and m3_telemetry_ok and m3_port == 5005 and m3_identity_ok and not topology_errors else "blocked",
        m3_findings, [str(m3_controller_path.relative_to(root)), str(m3_safety_path.relative_to(root))],
    )

    reports["workload_scope"] = {
        "volumetric_udp": {
            "methodology3": "not_applicable: the controller only handles structurally valid UDP/5005 safety messages",
        },
        "safety_consistency": {
            "methodology1": "source-based UDP block of sta3; does not distinguish physical consistency",
            "methodology2": "rate-based UDP detector; the planned low-rate telemetry does not test M3 consistency semantics",
            "methodology3": "valid-format UDP/5005 with identity and physical-consistency checks",
        },
    }

    return {
        "topology_id": spec.get("id"),
        "topology_spec_errors": topology_errors,
        "runtime_validation": "not_performed",
        "reports": reports,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repo-root", type=Path,
                        default=Path(__file__).resolve().parents[1])
    args = parser.parse_args(argv)
    report = validate_controller_compatibility(args.repo_root)
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
