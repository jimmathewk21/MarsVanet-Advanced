# Methodology 3: trust and reputation with progressive DoS mitigation

An independent Ryu OpenFlow 1.3 controller implementing per-vehicle consistency
checks, reputation, and progressive bandwidth limits. It does not load either
Methodology 1 or Methodology 2's controller, detector, or mitigation policy.

**Validation status:** 62 Methodology 3 unit tests pass on Python 3.12.10,
including isolated Ryu/OpenFlow doubles. Methodology 2's 45 unit tests and five
standalone assertion scripts also pass. Methodology 3 syntax compilation and
the sender's CLI help smoke check pass.
These tests do not demonstrate wireless connectivity, successful OVS enforcement,
measured throughput, or a live handover. A user-reported Ubuntu 24.04 run achieved
same-AP and cross-AP connectivity after manual associations and attaching AP1's
missing radio. The automated startup fix below has not yet been verified in that
VM; no live SDN testbed was run by this agent.

## Architecture and inspected topology

`UDP/5005 -> safety_messages -> VehicleProcessor -> MessageConsistencyChecker ->
ReputationEngine -> ProgressiveMitigation -> controller OpenFlow transactions`.

| Module | Responsibility |
|---|---|
| `safety_messages.py` | Bounded, strict JSON parsing and trusted simulation ID/IP configuration |
| `message_consistency.py` | Physical plausibility against the last accepted observation |
| `reputation_engine.py` | Independent vehicle scores, classifications, recovery and bounded history |
| `progressive_mitigation.py` | Plan against confirmed state; explicit confirmation and disconnect invalidation |
| `vehicle_processor.py` | Combine consistency, reputation and enforcement planning |
| `controller.py` | PacketIn handling, two-table pipeline, meter transactions and reconciliation |
| `send_safety_messages.py` | Synthetic normal, violation, recovery and combined demonstrations |
| `sdn_vanet_2ap.py` | Separate Mininet-WiFi testbed with client isolation and manual mobility |

Inspection of Methodology 2 found:

* Three stations: `sta1=10.0.0.1`, `sta2=10.0.0.2`, `sta3=10.0.0.3`.
  Initially sta1/sta2 are near AP1 and sta3 is near AP2. Association is determined
  by the live wireless runtime, not guaranteed by these initial positions.
* Backbone: `ap1 -- s1 -- ap2`. The script requests AP1 wired port 1 to s1 port 1,
  and AP2 wired port 2 to s1 port 2. Wireless port numbering must be inspected.
  Cross-AP traffic uses this backbone; same-AP traffic can remain local.
* Methodology 2's topology does not explicitly set DPIDs. Its configuration
  assumes AP2 `0x1000000000000002`; live DPIDs cannot be established from that
  assumption. Its controller monitors UDP to `10.0.0.2` on assumed AP2 ingress 1
  at priority 50; meter priority 60 outputs to assumed port 2; priority 100 is a
  temporary block. Priority-1 MAC forwarding and a table miss also exist.
* Historical AP2 evidence contains port numbers 1 and 2, but does not identify
  their interfaces. Its meter 103 has `flow_count:0` and zero packet counters.
  Those files and passing Python tests do not prove working live mitigation.
* `mobility_features.csv` contains `time,vehicle_count,average_speed` plus min/max
  speeds and coordinate bounds. The detector consumes aggregate samples, applies
  a nearest-sample age guard, and falls back to its base threshold. These are not
  per-vehicle safety messages. Handover logs use
  `timestamp_unix,time_seconds,station,previous_ap,current_ap,handover_count`.
  SUMO elapsed time and Unix/controller time are different clocks.
* Methodology 2 disables client isolation. Same-BSS traffic may bypass OpenFlow;
  the Methodology 3 testbed enables isolation. See the upstream
  [Mininet-WiFi explanation](https://mininet-wifi.github.io/advanced/).

The new testbed retains the station IPs, AP positions and backbone connections, explicitly
sets AP1/AP2 DPIDs to `1000000000000001`/`1000000000000002` and s1 to
`0000000000000001` (hex), and requests OpenFlow13. The controller accepts any DPID
and discovers radio ports named `*-wlan<number>` via port descriptions/status.
It never assumes a vehicle's ingress or destination output port. OVS's native MAC
learning replaces the original controller's persistent MAC-to-port flows.

### Startup reliability

The topology now lets Mininet allocate wired ports, uses `net.start()` after
`configureNodes()` and `build()`, verifies both AP radio attachments, and requests
sta1/sta2 -> AP1 and sta3 -> AP2 through `setAssociation()`. Interface names and
BSSIDs come from the configured wireless objects; no radio index, BSSID or wired
OpenFlow port number is hard-coded.

The reported missing AP1 radio and successful manual repair are confirmed by the
user's observations. A likely cause is the old `addLink(ap1, ..., port1=1)`:
radio configuration can already occupy port 1, and assigning a wired interface
there can overwrite the interface registry used by OVS startup. AP2's former
explicit port 2 explains the observed asymmetry. This is a source-based diagnosis,
not a reproduction against the VM's installed Mininet-WiFi version.

Upstream `configureNodes()` creates radios/hostapd; `build()` attempts automatic
association; AP startup recreates the OVS bridge from its registered interfaces.
The original sequence is not inherently invalid, but forced port allocation and
unchecked association attempts make it fragile. `net.start()` also runs the
library's batch-startup hooks. See upstream [node.py](https://github.com/intrig-unicamp/mininet-wifi/blob/master/mn_wifi/node.py)
and [net.py](https://github.com/intrig-unicamp/mininet-wifi/blob/master/mn_wifi/net.py).

After startup, only a missing radio gets `ovs-vsctl --may-exist add-port`; bridge
membership and a positive `ofport` are then checked with bounded polling. A port
already owned by another bridge or an OVS command failure raises an error, rather
than moving the port. No controller, flow, meter or protocol setting is changed.
Association polls `iw ... link` for the intended BSSID, retries through the API
every two seconds, and clears stale attempted-association state via `disconnect()`.
The default readiness/association timeout is ten seconds per radio/station.
Failures prevent entry to the CLI and trigger normal testbed cleanup.

These are startup-only checks: automatic association remains enabled, no BSSID is
persistently pinned, and `setPosition()` continues to drive later handovers.
Client isolation and OpenFlow13 remain enabled. On the VM, repeat a fresh startup
without manual repairs, verify all three `iw ... link` outputs and both APs'
`ovs-vsctl list-ports`, then run same-AP/cross-AP pings and the handover experiment.
Capture the installed Mininet-WiFi revision and startup logs if it still fails.

## Safety messages and identity

Send a single UTF-8 JSON object in an unfragmented IPv4 UDP datagram to port 5005:

```json
{"vehicle_id":"sta1","timestamp":1.0,"x":0.0,"y":0.0,"speed":10.0}
```

Coordinates are metres, speed is metres/second, timestamp is seconds on one
increasing clock per vehicle. Use the same clock across a handover. The controller
does not require alignment with the separate Methodology 2 mobility trace.

Payloads must be 1–1024 bytes with exactly these five keys. Duplicate/extra/missing
fields, invalid UTF-8, non-object JSON, numeric strings, booleans and non-finite
numbers are rejected. IDs must be strings of 1–64 characters. Encoding bounds are
`0 <= timestamp <= 1e12`, `abs(x),abs(y) <= 1e7`, `abs(speed) <= 1e4`. Physical
violations inside these broad encoding bounds are scored, not discarded.
Truncated PacketIns, fragments and inconsistent IP/UDP lengths are rejected.

Only configured `VEHICLE_IPS` entries are accepted; the IPv4 source must equal the
IP assigned to the JSON vehicle ID. Malformed/unknown/mismatched messages never
update any vehicle's reputation or accepted position. The mapping is simulation
configuration, not cryptographic authentication: spoofing both ID and IP remains
possible. Update `safety_messages.py` and the testbed together for other vehicles;
reserve the deterministic meter IDs starting at 1000 for this controller.

## Consistency, scoring and recovery

The first physically valid observation establishes a baseline. Subsequent accepted
messages require increasing timestamps and these checks:

| Check | Default | Violation severity |
|---|---|---|
| Reported speed | 0–55 m/s | 0.8 |
| Increasing timestamp | `dt > 0` | 0.8 |
| Displacement | `distance <= max(previous_speed,speed)*dt + 0.5*8*dt² + 10` | 1.0 |
| Acceleration | `abs(speed-previous_speed)/dt <= 8 m/s²` | 0.7 |

Violations do not replace the last accepted observation. Scores start at 1.0;
each violation subtracts `0.20 * severity`, floored at 0. Five consecutive
consistent messages restore 0.02, capped at 1.0; a violation resets that streak.
Scores are rounded to ten decimal places to keep threshold boundaries stable.
The latest 1000 history entries are retained per vehicle. Recovery is driven by
valid messages, not by waiting or changing APs.

| Reputation | Classification/action | Data rate |
|---|---|---|
| `[0.80, 1.00]` | Trusted / NORMAL | Unrestricted |
| `[0.60, 0.80)` | Under observation / MONITOR | Unrestricted |
| `[0.40, 0.60)` | Suspicious / LIGHT_THROTTLE | 500 kbps |
| `[0.20, 0.40)` | High risk / HEAVY_THROTTLE | 200 kbps |
| `[0.00, 0.20)` | Critical / SEVERE_THROTTLE | 100 kbps |

Recovery modifies the meter upward and removes it at score 0.60. There is no
zero-rate band, attack drop flow, or binary blocking stage.

## OpenFlow pipeline and reconciliation

| Table / priority | Match | Behavior |
|---|---|---|
| 0 / 300 | IPv4 UDP destination 5005 | Full packet to controller; consumed |
| 0 / 200 | IPv4 source equals one throttled vehicle's IP | Vehicle meter, then table 1 |
| 0 / 0 | Remaining traffic | Go to table 1 |
| 1 / 10 | Dynamically discovered radio ingress | NORMAL plus IN_PORT |
| 1 / 0 | Remaining traffic | OVS NORMAL forwarding |

The radio rule explicitly sends a copy back through the shared wireless ingress
for communication within an isolated BSS; NORMAL suppresses that ingress itself.
Both actions occur after table-0 enforcement. MAC learning is performed by OVS,
which relearns on arriving data frames following movement. No controller
PacketOut skips metering, and no learned forwarding flow competes with table-0
meters. The topology must provide every protected data path through OpenFlow.

Port 5005 is **reserved controller telemetry**, not an application forwarding
service. It is exempt from vehicle data meters so deterioration and recovery
remain observable, and is consumed at the first AP to avoid repeated scoring at
downstream switches. No receiver process is needed. Ordinary IPv4 traffic from
the vehicle, including TCP/UDP/ICMP and unknown-unicast traffic, is metered; other
vehicles' IPs and ARP are unaffected. IPv6 is outside this policy.

The same reputation decision is installed on every connected switch, including
s1. This avoids waiting to infer a handover and also covers local AP forwarding.
Meters are per-switch, not one distributed aggregate bandwidth budget; a packet
can encounter the same nominal cap at multiple hops.

`ProgressiveMitigation.update()` only plans. It does not mark an operation as
installed. The controller serializes each vehicle's transaction:

1. ADD/MODIFY the meter, then wait for an error-free barrier.
2. Install/reassert the source-specific meter-and-goto flow, then wait for another
   error-free barrier before calling `confirm()`.
3. For removal, delete the owned source flow and await a barrier before deleting
   the meter and awaiting final confirmation.

Errors are correlated by transaction IDs. Barrier completion without reported
errors confirms command processing, not measured traffic performance. A changed
decision during a pending operation is reconciled immediately on completion.
Timeouts (5 s), send failures and errors invalidate state and schedule a reset
after 2 s. Reconnects clear cached enforcement, retain reputation, fence prior
operations, remove owned flows/meters with barriers, rebuild the pipeline, and
reapply current decisions.
Late events from an old connection are ignored.

Meter MODIFY preserves top-level counters but resets band counters according to
the [OpenFlow specification](https://opennetworking.org/wp-content/uploads/2014/10/openflow-switch-v1.3.5.pdf).
Compare band-counter samples within a refresh interval and retain throughput logs.

Every 10 s the controller reasserts the pipeline and active enforcement, modifies
known meters (a missing-meter error triggers rebuilding), and removes stale
normal-state enforcement. Cookie prefix `0x4d33` scopes flow cleanup; only the
reserved per-vehicle meter IDs are deleted. Run on fresh bridges with a single
controller: foreign higher-priority rules are intentionally not deleted and can
invalidate the pipeline. Logs distinguish requested and confirmed enforcement,
and include consistency reasons, scores, decisions, switch errors and retries.
See [Ryu OpenFlow 1.3 structures](https://ryu.readthedocs.io/en/latest/ofproto_v1_3_ref.html)
and [OVS NORMAL behavior](https://docs.openvswitch.org/en/latest/ref/ovs-actions.7/).

## Unit tests

From the repository root (use `python3` instead of `python` in the Linux VM):

```sh
python -m unittest discover -s Methodology3 -p 'test_*.py' -v
python -m unittest discover -s Methodology2/tests -p 'test_*.py' -v
```

No Ryu, OVS, Mininet or third-party libraries are needed for these suites.
The 13 tests in `test_topology_startup.py` isolate Mininet imports and mock node
commands/time. They cover port allocation/startup ordering, bridge repair and
verification, command failures, BSSID selection, stale metadata and bounded retries.
`openflow_test_support.py` loads the controller with isolated Ryu stubs and
recording datapaths; PacketIn decoding is mocked. Tests check validation, vehicle
isolation, progressive deterioration/recovery, actual requested OpenFlow objects,
barrier ordering, errors/timeouts, reconnection, handover state, port discovery and
absence of block flows. They do not execute real Ryu serialization or a switch.
The original four test modules remain; enforcement tests now explicitly confirm
successful operations instead of assuming that planning installs them.

## Run the controller and live experiments

Use the project's Linux VM with a working Ryu/eventlet installation, Python 3.8+
(controller compatibility still requires a VM smoke test), Mininet-WiFi, OVS with
OpenFlow 1.3 **meter support**, `iw`, and iperf2. Use fresh testbed bridges and only
this controller. Commands below are preparation instructions, not executed results.
No Methodology 1 or 2 files are written by this testbed.

Terminal 1, from the repository root:

```sh
mkdir -p Methodology3/results
ryu-manager --ofp-tcp-listen-port 6653 Methodology3/controller.py 2>&1 | tee Methodology3/results/controller.log
```

Terminal 2, from the same directory:

```sh
sudo python3 Methodology3/sdn_vanet_2ap.py
```

Use `M3_CONTROLLER_IP` and `M3_CONTROLLER_PORT` in the topology process environment
to change the endpoint. At the Mininet-WiFi prompt, establish connectivity and
check real port/interface mappings before any attack:

```text
sta1 iw dev sta1-wlan0 link
sta3 iw dev sta3-wlan0 link
sta1 ping -c 5 10.0.0.2
sta3 ping -c 5 10.0.0.2
sh ovs-ofctl -O OpenFlow13 show ap1
sh ovs-ofctl -O OpenFlow13 show ap2
sh ovs-ofctl -O OpenFlow13 show s1
sh ovs-ofctl -O OpenFlow13 dump-meter-features ap1
sh ovs-ofctl -O OpenFlow13 dump-flows ap1
```

Confirm the controller reports all switches ready and discovers their `*-wlan*`
ports. Test both same-AP and cross-AP ping; do not add bypass flows to fix failures.
Capture baseline throughput, then generate violations separately from load:

```text
sta2 iperf -s -u -p 5001 > Methodology3/results/victim.log 2>&1 &
sta1 iperf -c 10.0.0.2 -u -p 5001 -b 2M -t 180 -i 1 > Methodology3/results/sta1-load.log 2>&1 &
sta3 ping -i 0.5 -c 300 10.0.0.2 > Methodology3/results/legitimate-ping.log 2>&1 &
sta1 python3 Methodology3/send_safety_messages.py sta1 --scenario normal --count 10
sta1 python3 Methodology3/send_safety_messages.py sta1 --scenario deteriorate --count 7 --interval 1
sh ovs-ofctl -O OpenFlow13 dump-flows ap1
sh ovs-ofctl -O OpenFlow13 meter-stats ap1
sh ovs-ofctl -O OpenFlow13 meter-stats ap2
sh ovs-ofctl -O OpenFlow13 meter-stats s1
```

Seven speed violations reduce the score to zero; expect successive positive
500/200/100 kbps limits. Confirm a matching meter flow, `flow_count > 0`, increasing
meter/band counters on switches actually traversed, and measured rate reduction.
An unused switch's meter counters may remain zero. Check legitimate sta3 ping and
repeat with sta3 throughput as a control. Inspect during transitions or use logs
to distinguish transient states from confirmed rules.

While sta1 remains throttled and the load is still running, move it and inspect:

```text
py sta1.setPosition('65,30,0')
sta1 iw dev sta1-wlan0 link
sta1 ping -c 5 10.0.0.2
sh ovs-ofctl -O OpenFlow13 meter-stats ap2
sta1 python3 Methodology3/send_safety_messages.py sta1 --scenario recover --count 250 --interval 0.2
sh ovs-ofctl -O OpenFlow13 dump-meters ap2
sh ovs-ofctl -O OpenFlow13 dump-flows ap2
```

Expect the same vehicle history and score after movement, followed by gradual
recovery. From zero, 150 valid messages reach 0.60 and remove throttling; 250 reach
1.0. Recheck throughput and legitimate traffic. The sender uses stationary
synthetic positions and Unix timestamps; it does not measure the station or SUMO
position. A real trajectory producer must publish actual x/y/speed observations.
`--scenario demo --count 300` provides 10 normal, 7 violating, then valid messages.
Choose a different `--destination` when sending from sta2 to avoid local routing.

For a controlled reconnect experiment in this disposable testbed, record the
score, run `sh ovs-appctl -t ovs-vswitchd bridge/reconnect ap2`, and verify new
reset/confirmation logs and restored meter counters. Do not restart the controller
for this check: controller restarts intentionally reset in-memory reputations.
Save fresh `show`, `dump-flows`, `dump-meters`, `meter-stats`, association output,
version information, offered-load settings, loss/latency and throughput logs under
`Methodology3/results/`. Repeat baseline, violation, handover and recovery runs;
report actual measurements and observed failures rather than inferring success
from unit tests. Exit the Mininet CLI normally to stop this testbed.

## Current limitations and maintenance

* Live Ryu loading, wire serialization, wireless hairpin forwarding, association,
  handover, meter support/accuracy and throughput remain unvalidated here.
* Trust is based on claimed kinematic consistency. A sender that omits safety
  messages, submits plausible false messages, spoofs an entire identity, or floods
  while remaining consistent can evade this model. This is not a complete DoS
  detector or authenticated vehicle-identity system.
* UDP/5005 is unmetered controller-only telemetry. High-rate safety traffic and
  logs can exhaust the control plane. Rate-aware admission and controller policing
  are future work; valid-message recovery is not limited by wall-clock time.
* Reputation and last accepted observations survive AP/switch changes within the
  running controller, but not controller process restarts. Timestamp resets are
  violations until the sender catches up or the experiment restarts.
* Reconciliation is eventual. Errors/reset windows can interrupt forwarding or
  temporarily remove limits; retries never silently declare enforcement success.
  Unsupported meters remain errors, not successful mitigation. Periodic reassertion
  does not replace switch statistics or independent throughput validation.
* The design assumes a loop-free OVS topology, reserved meter IDs, the documented
  radio naming convention, and no competing controller/rules. It does not police
  IPv6, non-IP attacks, traffic bypassing the AP bridge, or other tenants.
* Preserve `confirm()` semantics when extending enforcement. Keep identity maps,
  testbed configuration, thresholds, documentation and tests synchronized. Treat
  `results/` as local experiment output; retain only reviewed evidence for publishing.
