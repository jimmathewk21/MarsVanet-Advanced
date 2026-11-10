"""Startup regressions using isolated Mininet doubles; no root or services."""

import importlib.util
import sys
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace as NS
from unittest.mock import Mock, call, patch


def load_topology():
    modules = {name: ModuleType(name) for name in (
        "mininet", "mininet.log", "mininet.node", "mn_wifi", "mn_wifi.cli",
        "mn_wifi.net", "mn_wifi.node",
    )}
    modules["mininet.log"].info = Mock()
    modules["mininet.log"].setLogLevel = Mock()
    modules["mininet.node"].OVSSwitch = object
    modules["mininet.node"].RemoteController = object
    modules["mn_wifi.node"].OVSKernelAP = object
    modules["mn_wifi.net"].Mininet_wifi = Mock()
    modules["mn_wifi.cli"].CLI = Mock()
    spec = importlib.util.spec_from_file_location(
        "med3_topology_tested", Path(__file__).with_name("sdn_vanet_2ap.py"))
    module = importlib.util.module_from_spec(spec)
    with patch.dict(sys.modules, modules):
        spec.loader.exec_module(module)
    return module


topology = load_topology()


class Clock:
    def __init__(self):
        self.now = 0

    def monotonic(self):
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class TestTopologyStartup(unittest.TestCase):
    def setUp(self):
        self.clock = Clock()
        self.time_patch = patch.object(topology, "time", self.clock)
        self.time_patch.start()
        self.addCleanup(self.time_patch.stop)
        # Non-default names/keys ensure no wlan0/wlan1/index assumptions.
        self.ap_radio = NS(name="radio-ap7", mac="02:11:22:33:44:55")
        self.ap = NS(name="ap-test", wintfs={7: self.ap_radio}, pexec=Mock())
        self.radio = NS(name="radio-sta9", associatedTo=None, disconnect=Mock())
        self.station = NS(name="sta-test", wintfs={9: self.radio},
                          pexec=Mock(), setAssociation=Mock())

    def ovs(self, attached=True, ofports=("23",), add_error=None):
        state = {"attached": attached, "ports": list(ofports)}

        def command(argv):
            if "list-ports" in argv:
                return ("wired\n" + (self.ap_radio.name + "\n" if state["attached"] else ""), "", 0)
            if "add-port" in argv:
                if add_error:
                    return "", add_error, 1
                state["attached"] = True
                return "", "", 0
            if "get" in argv:
                value = state["ports"][0]
                if len(state["ports"]) > 1:
                    state["ports"].pop(0)
                return value, "", 0
            raise AssertionError("Unexpected OVS command: %r" % argv)

        self.ap.pexec.side_effect = command

    def test_existing_radio_is_verified_without_mutation(self):
        self.ovs()
        topology.ensure_ap_wireless_ports(self.ap)
        commands = [c.args[0] for c in self.ap.pexec.call_args_list]
        self.assertFalse(any("add-port" in c for c in commands))
        self.assertTrue(any(c[-3:] == ["Interface", "radio-ap7", "ofport"] for c in commands))

    def test_missing_radio_is_attached_idempotently(self):
        self.ovs(attached=False)
        topology.ensure_ap_wireless_ports(self.ap)
        topology.ensure_ap_wireless_ports(self.ap)
        additions = [c.args[0] for c in self.ap.pexec.call_args_list if "add-port" in c.args[0]]
        self.assertEqual(additions, [["ovs-vsctl", "--timeout=5", "--may-exist",
                                      "add-port", "ap-test", "radio-ap7"]])

    def test_waits_for_ovs_port_assignment(self):
        self.ovs(ofports=("[]", "-1", "23"))
        topology.ensure_ap_wireless_ports(self.ap)
        self.assertEqual(self.clock.now, .5)

    def test_missing_or_failed_port_does_not_report_success(self):
        self.ovs(ofports=("-1",))
        with self.assertRaisesRegex(RuntimeError, "not ready in OVS"):
            topology.ensure_ap_wireless_ports(self.ap, timeout=.5)

    def test_wrong_bridge_or_add_failure_is_not_overridden(self):
        self.ovs(attached=False, add_error="already exists on another bridge")
        with self.assertRaisesRegex(RuntimeError, "another bridge"):
            topology.ensure_ap_wireless_ports(self.ap)
        self.assertFalse(any("del-port" in c.args[0] for c in self.ap.pexec.call_args_list))

    def test_successful_add_still_requires_bridge_membership(self):
        self.ap.pexec.side_effect = lambda argv: (
            ("23", "", 0) if "get" in argv else ("", "", 0))
        with self.assertRaisesRegex(RuntimeError, "not ready in OVS"):
            topology.ensure_ap_wireless_ports(self.ap, timeout=.5)

    def test_query_error_is_reported_without_attempting_attachment(self):
        self.ap.pexec.return_value = ("", "database unavailable", 1)
        with self.assertRaisesRegex(RuntimeError, "database unavailable"):
            topology.ensure_ap_wireless_ports(self.ap)
        self.assertEqual(self.ap.pexec.call_count, 1)

    def test_association_uses_api_and_checks_actual_bssid(self):
        self.station.pexec.side_effect = [
            ("Not connected.", "", 0),
            ("Connected to 02:11:22:33:44:55 (on radio-sta9)\n", "", 0),
        ]
        topology.associate_station(self.station, self.ap)
        self.station.setAssociation.assert_called_once_with(self.ap, intf="radio-sta9")
        self.station.pexec.assert_called_with(["iw", "dev", "radio-sta9", "link"])

    def test_correct_association_is_not_disrupted(self):
        self.station.pexec.return_value = ("Connected to 02:11:22:33:44:55", "", 0)
        topology.associate_station(self.station, self.ap)
        self.station.setAssociation.assert_not_called()
        self.radio.disconnect.assert_not_called()

    def test_stale_association_metadata_is_cleared_before_retry(self):
        self.radio.associatedTo = self.ap_radio
        order = Mock()
        order.attach_mock(self.radio.disconnect, "disconnect")
        order.attach_mock(self.station.setAssociation, "associate")
        self.station.pexec.side_effect = [
            ("Not connected.", "", 0),
            ("Connected to 02:11:22:33:44:55", "", 0),
        ]
        topology.associate_station(self.station, self.ap)
        self.assertEqual(order.mock_calls, [call.disconnect(self.ap_radio),
                         call.associate(self.ap, intf="radio-sta9")])

    def test_wrong_bssid_times_out_with_bounded_retries(self):
        self.station.pexec.return_value = ("Connected to 02:aa:bb:cc:dd:ee", "", 0)
        with self.assertRaisesRegex(RuntimeError, "failed to associate"):
            topology.associate_station(self.station, self.ap, timeout=3)
        self.assertEqual(self.clock.now, 3)
        self.assertEqual(self.station.setAssociation.call_count, 2)

    def test_missing_or_ambiguous_radios_fail_clearly(self):
        self.ap.wintfs = {}
        with self.assertRaisesRegex(RuntimeError, "no configured wireless"):
            topology.ensure_ap_wireless_ports(self.ap)
        with self.assertRaisesRegex(RuntimeError, "one radio"):
            topology.associate_station(self.station, self.ap)

    def test_topology_orders_startup_preserves_policy_and_cleans_up(self):
        for fail in (False, True):
            with self.subTest(fail=fail):
                net = Mock()
                nodes = {name: NS(name=name) for name in ("sta1", "sta2", "sta3", "ap1", "ap2", "s1")}
                for method in ("addStation", "addAccessPoint", "addSwitch"):
                    getattr(net, method).side_effect = lambda name, **kw: nodes[name]
                order = Mock()
                order.attach_mock(net, "net")
                with patch.object(topology, "Mininet_wifi", return_value=net), \
                     patch.object(topology, "ensure_ap_wireless_ports") as ensure, \
                     patch.object(topology, "associate_station") as associate, \
                     patch.object(topology, "CLI") as cli:
                    order.attach_mock(ensure, "ensure")
                    order.attach_mock(associate, "associate")
                    order.attach_mock(cli, "cli")
                    if fail:
                        ensure.side_effect = RuntimeError("radio unavailable")
                        with self.assertRaisesRegex(RuntimeError, "radio unavailable"):
                            topology.topology()
                        cli.assert_not_called()
                    else:
                        topology.topology()
                        self.assertEqual(net.addLink.call_args_list, [
                            call(nodes["ap1"], nodes["s1"]), call(nodes["ap2"], nodes["s1"]),
                        ])
                        for ap_call in net.addAccessPoint.call_args_list:
                            self.assertTrue(ap_call.kwargs["client_isolation"])
                            self.assertEqual(ap_call.kwargs["protocols"], "OpenFlow13")
                        self.assertEqual(net.addSwitch.call_args.kwargs["protocols"], "OpenFlow13")
                        self.assertEqual(associate.call_args_list, [
                            call(nodes["sta1"], nodes["ap1"]), call(nodes["sta2"], nodes["ap1"]),
                            call(nodes["sta3"], nodes["ap2"]),
                        ])
                        stages = [c[0] for c in order.mock_calls]
                        self.assertLess(stages.index("net.configureNodes"), stages.index("net.addLink"))
                        self.assertLess(stages.index("net.build"), stages.index("net.start"))
                        self.assertLess(stages.index("net.start"), stages.index("ensure"))
                        self.assertLess(stages.index("ensure"), stages.index("associate"))
                        self.assertLess(stages.index("associate"), stages.index("cli"))
                    net.start.assert_called_once_with()
                    net.stop.assert_called_once_with()


if __name__ == "__main__":
    unittest.main()
