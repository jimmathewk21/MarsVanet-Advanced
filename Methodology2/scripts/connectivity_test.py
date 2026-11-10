#!/usr/bin/env python3
"""Reproducible connectivity / packet-path diagnosis for the two-AP topology.

Purpose
-------
The project previously hit "stations associate with their AP but cannot ping
each other", with no confirmed root cause. This script performs a structured,
repeatable diagnosis so the cause can be seen instead of guessed, and so the
fix is NOT an arbitrary high-priority forwarding rule that bypasses the defence
logic.

Where to run
------------
Inside the Mininet-WiFi VM, from the Mininet CLI's perspective. It must be run
with the network already built (by sdn_vanet_2ap.py) because it inspects the
live OVS bridges and station interfaces. It shells out to `ovs-vsctl`,
`ovs-ofctl` and the station network commands; it therefore needs root and the
OVS/Mininet-WiFi runtime and CANNOT run in a plain container.

Two ways to use it:

1. Standalone, from the VM shell, to inspect the APs directly:
       sudo python3 connectivity_test.py --aps ap1 ap2

2. From inside sdn_vanet_2ap.py's CLI by running the equivalent commands shown
   in CHECKLIST below (the script also prints them so they can be copy-pasted).

It prints a PASS/WARN/FAIL line per check and exits non-zero if any FAIL.
No check installs or deletes flows; it is read-only diagnosis.
"""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys


CHECKLIST = """\
Manual equivalents (run from the Mininet-WiFi CLI, replacing names as needed):

  # 1. Station IP + association
  mn-wifi> sta1 ip addr show
  mn-wifi> sta1 iw dev sta1-wlan0 link

  # 2. AP wireless interface is a member of the AP's OVS bridge
  sh ovs-vsctl list-ports ap1
  sh ovs-vsctl list-ports ap2

  # 3. Controller connection state (should be is_connected: true)
  sh ovs-vsctl -- get-controller ap1 ap2 s1
  sh ovs-vsctl show

  # 4. Installed flows and priorities on AP2 (the monitored AP)
  sh ovs-ofctl -O OpenFlow13 dump-flows ap2

  # 5. ARP / neighbour resolution before and after a ping
  mn-wifi> sta1 ip neigh
  mn-wifi> sta1 ping -c 3 10.0.0.2

  # 6. Confirm the UDP packet path reaches AP2 ingress and the controller
  #    (watch the controller log for 'AP2 monitor flow' PacketIn activity)
  mn-wifi> sta3 ping -c 2 10.0.0.2
  sh ovs-ofctl -O OpenFlow13 dump-flows ap2 | grep udp
"""


def _run(cmd):
    """Run a command, returning (rc, stdout, stderr). rc=127 if missing."""
    exe = cmd[0]
    if shutil.which(exe) is None:
        return 127, "", f"{exe} not found"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=20
        )
        return proc.returncode, proc.stdout, proc.stderr
    except (subprocess.TimeoutExpired, OSError) as error:
        return 1, "", str(error)


class Report:
    def __init__(self):
        self.failures = 0

    def check(self, level, name, detail=""):
        assert level in ("PASS", "WARN", "FAIL")
        if level == "FAIL":
            self.failures += 1
        print(f"[{level}] {name}" + (f": {detail}" if detail else ""))


def diagnose(aps, controller_port):
    report = Report()

    if shutil.which("ovs-vsctl") is None:
        report.check(
            "FAIL", "runtime",
            "ovs-vsctl not found. Run this inside the Mininet-WiFi VM as root.",
        )
        print()
        print(CHECKLIST)
        return report.failures

    # Check 1: each AP bridge exists and lists a wireless port member.
    for ap in aps:
        rc, out, err = _run(["ovs-vsctl", "list-ports", ap])
        if rc != 0:
            report.check("FAIL", f"{ap} bridge", err.strip() or "no such bridge")
            continue
        ports = [p for p in out.split() if p]
        wlan_ports = [p for p in ports if "wlan" in p]
        if not ports:
            report.check("FAIL", f"{ap} ports", "bridge has no ports")
        elif not wlan_ports:
            report.check(
                "WARN", f"{ap} wireless port",
                f"no *wlan* port among {ports}; stations may associate at the "
                "radio layer but have no bridged datapath (classic cause of "
                "'associated but cannot ping')",
            )
        else:
            report.check("PASS", f"{ap} wireless port", ", ".join(wlan_ports))

    # Check 2: controller connection state per bridge.
    for bridge in list(aps) + ["s1"]:
        rc, out, err = _run(["ovs-vsctl", "get-controller", bridge])
        if rc != 0:
            report.check("WARN", f"{bridge} controller", err.strip() or "unknown")
            continue
        target = out.strip() or "(none set)"
        rc2, show, _ = _run(["ovs-vsctl", "show"])
        connected = "is_connected: true" in show
        if "(none" in target:
            report.check("FAIL", f"{bridge} controller", "no controller set")
        elif connected:
            report.check("PASS", f"{bridge} controller", f"{target} connected")
        else:
            report.check(
                "WARN", f"{bridge} controller",
                f"{target} set but not reported connected; check the Ryu "
                f"process on port {controller_port}",
            )

    # Check 3: AP2 flow table sanity (monitor + any mitigation flows).
    rc, out, err = _run(["ovs-ofctl", "-O", "OpenFlow13", "dump-flows", aps[-1]])
    if rc != 0:
        report.check("WARN", f"{aps[-1]} flows", err.strip() or "cannot dump")
    else:
        has_miss = "priority=0" in out
        has_monitor = "CONTROLLER" in out and "udp" in out.lower()
        report.check(
            "PASS" if has_miss else "WARN",
            f"{aps[-1]} table-miss", "present" if has_miss else "missing",
        )
        report.check(
            "PASS" if has_monitor else "WARN",
            f"{aps[-1]} UDP monitor flow",
            "present" if has_monitor else
            "not seen; controller may not be observing victim-bound UDP",
        )

    print()
    print(CHECKLIST)
    return report.failures


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--aps", nargs="+", default=["ap1", "ap2"],
        help="AP bridge names, last one is treated as the monitored AP",
    )
    parser.add_argument(
        "--controller-port", type=int, default=6653,
        help="Expected Ryu OpenFlow port (for the hint message only)",
    )
    args = parser.parse_args(argv)
    failures = diagnose(args.aps, args.controller_port)
    if failures:
        print(f"\n{failures} check(s) FAILED.")
        return 1
    print("\nAll connectivity checks passed (or only warnings).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
