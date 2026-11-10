import sys
import types
import unittest
from unittest.mock import patch

from benchmark.compatibility import validate_controller_compatibility
from benchmark.mininet_topology import (
    MininetDependencyError, _resolve_wired_link, _verify_wired_links,
    create_topology,
)
from benchmark.topology_spec import TOPOLOGY_SPEC, validate_topology_spec


class TopologySpecificationTest(unittest.TestCase):
    def test_station_ap_ip_dpid_and_port_mapping(self):
        self.assertEqual(validate_topology_spec(), [])
        self.assertEqual({name: row["ip"] for name, row in
                          TOPOLOGY_SPEC["stations"].items()}, {
            "sta1": "10.0.0.1/24", "sta2": "10.0.0.2/24",
            "sta3": "10.0.0.3/24",
        })
        self.assertEqual({name: row["ap"] for name, row in
                          TOPOLOGY_SPEC["stations"].items()}, {
            "sta1": "ap1", "sta2": "ap1", "sta3": "ap2",
        })
        self.assertEqual(TOPOLOGY_SPEC["access_points"]["ap1"]["dpid"],
                         "1000000000000001")
        self.assertEqual(TOPOLOGY_SPEC["access_points"]["ap2"]["dpid"],
                         "1000000000000002")
        self.assertFalse(TOPOLOGY_SPEC["access_points"]["ap1"]["client_isolation"])
        self.assertTrue(TOPOLOGY_SPEC["access_points"]["ap2"]["client_isolation"])
        self.assertEqual(TOPOLOGY_SPEC["switch"]["dpid"],
                         "0000000000000001")
        self.assertEqual(TOPOLOGY_SPEC["expected_ap2_ports"]["wireless_ingress"]["port"], 1)
        self.assertEqual(TOPOLOGY_SPEC["expected_wireless_port"]["port"], 1)
        self.assertEqual(TOPOLOGY_SPEC["links"][1]["port1"], 2)
        self.assertFalse(TOPOLOGY_SPEC["rf"]["mobility_enabled"])

    def test_spec_validator_catches_duplicate_dpid_and_unknown_ap(self):
        broken = {
            **TOPOLOGY_SPEC,
            "stations": {**TOPOLOGY_SPEC["stations"],
                         "sta3": {**TOPOLOGY_SPEC["stations"]["sta3"], "ap": "ap9"}},
            "access_points": {**TOPOLOGY_SPEC["access_points"],
                              "ap2": {**TOPOLOGY_SPEC["access_points"]["ap2"],
                                      "dpid": TOPOLOGY_SPEC["access_points"]["ap1"]["dpid"]}},
        }
        errors = validate_topology_spec(broken)
        self.assertTrue(any("unknown AP" in error for error in errors))
        self.assertTrue(any("DPIDs must be unique" in error for error in errors))


class LazyMininetAdapterTest(unittest.TestCase):
    def _wired_link_fixture(self):
        class FakeInterface:
            def __init__(self, name):
                self.name = name

        ap_wired = FakeInterface("ap2-eth2")
        switch_wired = FakeInterface("s1-eth2")
        radio = types.SimpleNamespace(name="ap2-wlan1")
        ap = types.SimpleNamespace(
            name="ap2", intfs={2: ap_wired}, ports={ap_wired: 2},
            wintfs={1: radio},
        )
        switch = types.SimpleNamespace(
            name="s1", intfs={2: switch_wired}, ports={switch_wired: 2},
        )
        ap.pexec = lambda command: ("2", "", 0)
        switch.pexec = lambda command: ("2", "", 0)
        handles = types.SimpleNamespace(
            access_points={"ap2": ap}, backbone=switch,
        )
        spec = {"node1": "ap2", "node2": "s1", "port1": 2, "port2": 2}
        link = types.SimpleNamespace(intf1=ap_wired, intf2=switch_wired)
        handles.spec = {"links": [spec]}
        handles.links = [link]
        return handles, spec, link

    def test_wired_link_resolution_accepts_link_object_and_checks_mapping(self):
        handles, spec, link = self._wired_link_fixture()
        self.assertEqual(
            _resolve_wired_link(handles, spec, link),
            ("ap2-eth2", "s1-eth2"),
        )

    def test_wired_link_resolution_handles_none_return_via_node_port_maps(self):
        handles, spec, _link = self._wired_link_fixture()
        self.assertEqual(
            _resolve_wired_link(handles, spec, None),
            ("ap2-eth2", "s1-eth2"),
        )

    def test_startup_wired_port_verification_accepts_link_object_and_none(self):
        handles, _spec, _link = self._wired_link_fixture()
        # Exercise the same helper called by start_topology, including actual
        # OVS ofport checks, for both Mininet addLink return conventions.
        for returned in (handles.links[0], None):
            with self.subTest(link_returned=returned is not None):
                handles.links = [returned]
                _verify_wired_links(handles)

    def test_startup_wired_port_verification_rejects_ovs_port_mismatch(self):
        handles, _spec, _link = self._wired_link_fixture()
        handles.backbone.pexec = lambda command: ("3", "", 0)
        with self.assertRaisesRegex(RuntimeError, "OVS reports 2/3"):
            _verify_wired_links(handles)

    def test_wired_link_resolution_does_not_ignore_wrong_requested_port(self):
        handles, spec, _link = self._wired_link_fixture()
        with self.assertRaisesRegex(RuntimeError, "no interface assigned"):
            _resolve_wired_link(handles, {**spec, "port1": 3}, None)

    def test_wired_link_object_must_agree_with_node_port_maps(self):
        handles, spec, link = self._wired_link_fixture()
        wrong = types.SimpleNamespace(
            intf1=types.SimpleNamespace(name="ap2-eth9"),
            intf2=link.intf2,
        )
        with self.assertRaisesRegex(RuntimeError, "returned link interface"):
            _resolve_wired_link(handles, spec, wrong)

    def test_missing_mininet_dependency_fails_before_creating_network(self):
        with patch.dict(sys.modules, {
            "mininet": None, "mininet.node": None,
            "mn_wifi": None, "mn_wifi.net": None, "mn_wifi.node": None,
        }):
            with self.assertRaisesRegex(MininetDependencyError,
                                        "No topology was created"):
                create_topology()

    def test_topology_adapter_uses_spec_and_does_not_start_mobility_or_traffic(self):
        instances = []

        class FakeNode:
            def __init__(self, name, **kwargs):
                self.name, self.kwargs = name, kwargs

        class FakeNet:
            def __init__(self, **kwargs):
                self.constructor = kwargs
                self.stations, self.aps, self.links = {}, {}, []
                self.calls = []
                instances.append(self)

            def addStation(self, name, **kwargs):
                node = FakeNode(name, **kwargs)
                self.stations[name] = node
                return node

            def addAccessPoint(self, name, **kwargs):
                node = FakeNode(name, **kwargs)
                self.aps[name] = node
                return node

            def addSwitch(self, name, **kwargs):
                return FakeNode(name, **kwargs)

            def addController(self, name, **kwargs):
                return FakeNode(name, **kwargs)

            def setPropagationModel(self, **kwargs):
                self.calls.append(("propagation", kwargs))

            def configureNodes(self):
                self.calls.append(("configureNodes", {}))

            def addLink(self, node1, node2, **kwargs):
                self.links.append((node1.name, node2.name, kwargs))
                intf1 = types.SimpleNamespace(name=f"{node1.name}-eth{kwargs['port1']}")
                intf2 = types.SimpleNamespace(name=f"{node2.name}-eth{kwargs['port2']}")
                return types.SimpleNamespace(intf1=intf1, intf2=intf2)

        modules = {}
        for name in ("mininet", "mininet.node", "mn_wifi", "mn_wifi.net", "mn_wifi.node"):
            modules[name] = types.ModuleType(name)
        modules["mininet"].node = modules["mininet.node"]
        modules["mn_wifi"].net = modules["mn_wifi.net"]
        modules["mn_wifi"].node = modules["mn_wifi.node"]
        modules["mininet.node"].OVSSwitch = type("OVSSwitch", (), {})
        modules["mininet.node"].RemoteController = type("RemoteController", (), {})
        modules["mn_wifi.net"].Mininet_wifi = FakeNet
        modules["mn_wifi.node"].OVSKernelAP = type("OVSKernelAP", (), {})

        with patch.dict(sys.modules, modules):
            handles = create_topology()

        net = instances[0]
        self.assertEqual(net.stations["sta1"].kwargs["ip"], "10.0.0.1/24")
        self.assertEqual(net.stations["sta2"].kwargs["ip"], "10.0.0.2/24")
        self.assertEqual(net.stations["sta3"].kwargs["ip"], "10.0.0.3/24")
        self.assertEqual(net.aps["ap2"].kwargs["dpid"], "1000000000000002")
        self.assertEqual(net.links[1], ("ap2", "s1", {"port1": 2, "port2": 2}))
        self.assertEqual(handles.spec["rf"]["mobility_enabled"], False)
        self.assertFalse(any("mobility" in name.lower() or "traffic" in name.lower()
                             for name, _ in net.calls))


class ControllerCompatibilityTest(unittest.TestCase):
    def test_validator_reports_controller_specific_source_findings(self):
        report = validate_controller_compatibility()
        reports = report["reports"]
        self.assertEqual(report["runtime_validation"], "not_performed")
        self.assertEqual(reports["no_defense"]["status"],
                         "runtime_dependency_unverified")
        self.assertEqual(reports["methodology1"]["status"],
                         "source_compatible_runtime_unverified")
        self.assertEqual(reports["methodology1"]["can_operate_correctly"], None)
        self.assertEqual(reports["methodology2"]["status"],
                         "conditional_runtime_port_verification_required")
        self.assertTrue(any("ap2_in_port: matches" in finding
                            for finding in reports["methodology2"]["findings"]))
        self.assertTrue(any("OVS ofports" in finding
                            for finding in reports["methodology2"]["findings"]))
        self.assertEqual(reports["methodology3"]["status"],
                         "source_compatible_runtime_unverified")
        self.assertTrue(any("UDP/5005" in finding
                            for finding in reports["methodology3"]["findings"]))
        self.assertIn("not_applicable", reports["workload_scope"]["volumetric_udp"]["methodology3"])
        for name in ("methodology1", "methodology2", "methodology3"):
            self.assertEqual(reports[name]["runtime_validation"], "not_performed")


if __name__ == "__main__":
    unittest.main()
