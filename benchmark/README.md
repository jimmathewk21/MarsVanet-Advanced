# MarsVanet benchmark

The benchmark provides deterministic experiment planning, compatibility
reports, metric definitions, and one-trial live adapters for `volumetric_udp`
and Methodology 3 `safety_consistency`. Live execution requires the Ubuntu
Mininet-WiFi host and is never selected by default. Planning remains
dependency-free.

## What the source currently does

The common topology adapter in `mininet_topology.py` uses Methodology 3's AP
DPIDs and vehicle identities (`10.0.0.1` / `.2` / `.3`), with the same two
channels, positions, propagation model, and fixed AP associations. AP1 uses
`client_isolation=False` and AP2 uses `True`, matching the benchmark topology
spec. It requests OpenFlow 1.3 and explicit AP/backbone links. On
start it checks requested OVS link ofports, AP2 radio ingress, and station
associations. These are runtime checks in the adapter; they have not been run
on this machine or confirmed on the target Mininet-WiFi version.

The topology has two AP bridges (`ap1`, `ap2`) plus one wired backbone switch
(`s1`). Each AP radio is expected on AP port 1 and its wired link is requested
on AP port 2; the backbone links use ports 1 and 2 for ap1 and ap2 respectively.
The `configureNodes()` call precedes explicit wired
links, matching the existing Mininet-WiFi setup order. Creating/starting the
network is a separate explicit API call; importing or validating the spec
does not import Mininet or touch OVS. Startup has no mobility schedule and
does not generate workload traffic.

Controller compatibility is source/spec analysis only. Use the lazy validator
on Windows without Mininet-WiFi:

```powershell
python benchmark/compatibility.py
```

It reports static source compatibility separately from unverified runtime
operation. The existing controller/topology scripts still do not establish a
safe common run as-is:

* Methodology 2 needs AP2 DPID `0x1000000000000002`, ingress port 1, output port
  2, and destination `10.0.0.2`. Its topology uses a different startup path,
  and its controller documents the port values as assumptions requiring live
  confirmation. The Methodology 3 topology leaves AP/backbone port allocation
  to Mininet-WiFi and cannot guarantee those port numbers.
* Methodology 1 installs a priority-100 drop for every IPv4 UDP packet from
  `10.0.0.3` on each switch. It does not distinguish flood traffic from safety
  telemetry and its packet-in learning pipeline differs from Methodology 3's
  two-table `NORMAL` pipeline.
* Methodology 2 is a rate-based UDP detector with a meter and later block.
  Methodology 3 consumes structurally valid UDP/5005 messages, checks vehicle
  identity, and scores physical consistency/reputation. Methodology 3 is not a
  volumetric-flood detector; those matrix cells are explicitly not applicable.
* No defense uses Ryu's built-in `ryu.app.simple_switch_13`; forwarding and
  same-radio behavior still need live verification.

Because of these differences, matrix entries carry both applicability and
compatibility status. A blocked entry is never silently treated as a completed
comparison. See `experiment_spec.json` for the source assumptions and profiles.

## Workload and schedule specification

Volumetric trials use a 30 s pre-attack baseline, 60 s attack interval, and
30 s recovery interval. Safety-consistency trials use 30 s / 2 s / 42 s,
respectively. The legitimate stream uses sta1 to sta2. The attack
source uses sta3 to sta2, matching Methodology 1's fixed source rule and
Methodology 3's `sta3` identity. Planned offered loads are 20 legitimate UDP
packets/s, 500 flood packets/s, or safety telemetry at 5 messages/s. Data-plane
probe payloads are 256 bytes; safety JSON uses compact encoding. Matched
configurations share the same seed for a workload/repetition.

The `volumetric_udp` family combines legitimate traffic with UDP flooding to
port 5001. The live `safety_consistency` profile is Methodology 3 only. sta3
sends valid UDP/5005 telemetry at 5 messages/s during the 30 s baseline, five
severe impossible-displacement messages during a 2 s transient attack, then 200
physically plausible messages during a 42 s reputation recovery window. The
trajectory uses Methodology 3's actual `MessageConsistencyChecker` and
`ReputationEngine`.

The UDP/5001 probe runs continuously from transient attack start through
recovery and both measurement intervals. sta1's 20 packet/s legitimate stream
also remains active. After the transient attack, the runner waits up to 10 s
for the expected decision prefix and AP2's confirmed 100-kbps meter operation.
Only then does the default 10 s `severe_throttle_measurement` begin; recovery
telemetry is gated until this interval ends. After the 42 s recovery sequence,
the runner waits up to 5 s for the complete expected decision trace ending in
reputation >=0.80/action NORMAL and AP2 REMOVE confirmation. Only then does the
default 10 s `post_recovery_normal_measurement` begin. Set interval lengths with
`--severe-measurement-seconds` and `--normal-measurement-seconds` (each in
`(0,60]`). If normal state is not confirmed, its measurement and metrics are
unavailable rather than represented as zero. Phase boundaries and traffic
counts are retained in each run summary.

For each probe interval, throughput is receiver-observed attack UDP/5001
payload bytes timestamped in the half-open interval divided by its duration.
Sent counts use sender timestamps in that interval. PDR/loss joins interval
send sequence numbers to receiver records across the full trial, so boundary-
late arrivals count as delivered; throughput remains based strictly on receive
time. UDP/5005 is controller telemetry, not receiver data-plane traffic.
Controller decisions, OpenFlow operation/barrier acknowledgements, and
receiver-observed traffic are separate evidence. A barrier confirms switch
processing of an operation, not packet-level enforcement. The current logs do
not carry telemetry sequence IDs or mapped monotonic event times, so decision
matching is ordered trace comparison and detection/mitigation delays remain
null. `recovery_time_seconds` is null when legitimate traffic was never
impaired; reputation recovery and restored-normal measurement are reported
separately instead of assigning a misleading zero.

## Windows planning

No root, Ryu, Mininet-WiFi, OVS, SUMO, or third-party Python package is needed:

```powershell
python benchmark/run_benchmark.py --root-seed 2026 --repetitions 5
```

The default is dry-run and prints JSON to stdout. To save a plan, pass an
`--output` path inside `benchmark/`; existing files are never overwritten.
Planning does not execute the printed controller command descriptions. Tests:

```powershell
python -m unittest discover -s benchmark/tests -v
```

## Ubuntu live trial

The live slice supports `volumetric_udp` with no defense, Methodology 1, or
Methodology 2; `safety_consistency` is supported with Methodology 3 only.
Volumetric UDP with Methodology 3 and safety consistency with other controllers
are rejected. Per-packet CSV evidence, controller output, JSON metrics, CSV
metrics, and environment metadata are written beneath `benchmark/`.

On the Ubuntu VM:

1. Install/configure Mininet-WiFi and OVS using the VM's established setup.
   The benchmark does not install packages or reset OVS state.
2. Ensure Ryu is available at `~/sdn-vanet/ryu-venv/bin/ryu-manager` and that
   `/usr/bin/python3` can import `mn_wifi` and Mininet. For Methodology 2,
   install its existing Python requirements in the Ryu environment.
3. From the repository root, run one configuration at a time. This example is
   the no-defense baseline:

```bash
sudo env "PATH=$HOME/sdn-vanet/ryu-venv/bin:$PATH" /usr/bin/python3 \
  benchmark/run_benchmark.py --live --workload volumetric_udp \
  --configuration no_defense --root-seed 2026 --repetitions 1 \
  --artifacts benchmark/artifacts
```

Use `--configuration methodology1` or `--configuration methodology2` for the
other supported flood trials. The runner starts one Ryu process, constructs and
checks the common topology, starts only its own workload processes, stops its
own network, and terminates its controller. It does not kill unrelated
processes or clear OVS state. Existing artifacts are never overwritten; use a
new artifact directory/run seed for a repeated trial. Run only in the isolated
Ubuntu test VM because Mininet-WiFi requires root.

The adapter validates DPID, OpenFlow 1.3, wired ofports, wireless ofports, and
station associations at startup. Those checks do not prove forwarding or
controller defense effectiveness. In particular, the Methodology 2 ingress
counter interpretation and stage transitions still need live observation.
Latency is calculated from sender and receiver readings of the same host's
monotonic clock, with the clock's reported resolution recorded as uncertainty;
it does not claim cross-host timing accuracy. Detection delay, mitigation
delay, and false positives remain null because this slice does not collect
stable controller decision/enforcement events. Controller logs and raw packet
timestamps are retained as evidence. Software version probing is not yet
implemented and is recorded as unavailable.

For the Methodology 3 trial, synchronize the updated `benchmark/` sources to
the Ubuntu checkout and run:

```bash
sudo env "PATH=$HOME/sdn-vanet/ryu-venv/bin:$PATH" /usr/bin/python3 \
  benchmark/run_benchmark.py --live --workload safety_consistency \
  --configuration methodology3 --root-seed 2026 --repetitions 1 \
  --severe-measurement-seconds 10 --normal-measurement-seconds 10 \
  --artifacts benchmark/artifacts
```

Ryu is launched with its working directory set to `Methodology3` so its local
imports resolve. The schedule is 30 s baseline, 2 s transient attack, a
controller-gated severe-throttle measurement (10 s default), 42 s recovery,
then a controller-gated normal measurement (10 s default), plus bounded state
waits and startup/drain margins. The runner waits for all three switch
pipelines before sending telemetry. It records the expected policy trace and
compares it with controller decision logs, while separately recording
enforcement requests, barrier confirmations, and receiver-observed
data-plane traffic. Decisions are order-correlated because the existing
controller logs do not include telemetry sequence IDs. Detection and
mitigation delays remain null because log event times are not mapped to the
trial monotonic clock; a barrier confirmation is not packet-level mitigation
confirmation. False positives remain null without an independent oracle.

If the VM sees the Windows checkout through a VirtualBox shared folder mounted
at `/media/sf_MarsVanet`, synchronize without deleting destination files:

```bash
rsync -a --backup --suffix=.pre-m3 --exclude='artifacts/' \
  /media/sf_MarsVanet/benchmark/ \
  "$HOME/MarsVanet/benchmark/"
cd "$HOME/MarsVanet"
```

The shared-folder and checkout paths are assumptions and must match the VM.
Use a fresh seed or artifact directory for another run; existing evidence is
never overwritten.

Further live benchmark work should provide and validate:

1. Run a forwarding smoke test and confirm DPIDs, wireless
   bridge membership, requested OVS ofports, station associations and OpenFlow
   1.3 support for every selected controller. In particular, verify AP2 radio
   ingress port 1 and backbone port 2 for Methodology 2.
2. Add controller/switch event collection with monotonic event timestamps for
   detection and confirmed enforcement.
3. Probe Ryu, Mininet-WiFi, OVS, kernel, radio, and SUMO versions, and live
   validation of Methodology 2 flow-counter semantics.

The live adapters remain unvalidated on Ubuntu. Continue using the isolated
testbed, runner-owned process cleanup, and unique artifact directories.

## Metrics and collection

`core.py` defines throughput, loss/PDR, latency, attack throughput, detection
and mitigation delay, recovery time, and false-positive definitions. Per-run
metrics use `{ "value": number | null, "explanation": string | null }` records.
Unavailable observations remain null with a reason. The planning-mode empty artifact
template explicitly says no live measurement was collected.

Planning artifact helpers write `{run_id}.raw.log`, `{run_id}.metrics.json`,
and `{run_id}.environment.json` and refuse to overwrite existing files. Live
trials additionally write sender/receiver packet CSVs, controller logs, and a
`{run_id}.metrics.csv` summary. The
environment template captures Python/platform and explicitly leaves unprobed
Ryu, Mininet-WiFi, OVS, and SUMO versions null. Summarize collected trials with:

```powershell
python benchmark/run_benchmark.py --summarize benchmark/artifacts
```

The summary reports a two-sided 95% Student-t interval over available,
independent trial values. Fewer than two observations produce a null interval;
missing trial counts and explanations are retained.

`traffic_metrics`, `latency_metric`, `event_delay_metric`, and
`recovery_time_metric` calculate values only from supplied observations. The
latency record carries the caller-provided clock uncertainty; it does not
correct measurements using an assumed clock offset.
