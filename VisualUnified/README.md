# MarsNet / MarsVanet — Visual Unified SDN-VANET Simulator

**Windows-first graphical SDN-VANET experiment environment** with moving vehicles, stationary roadside units, real-time messages, one combined security policy pipeline, adjustable flow rules, charts, and experiment exports.

> **What this is:** a discrete-event *network and defense simulation* with software-enforced match/action rules. It does **not** run Ryu, Open vSwitch, Mininet-WiFi, real UDP sockets, IEEE 802.11p radios, or real OpenFlow switches. Existing MarsVanet Mininet/OVS benchmark evidence is a different class of experiment and should be kept separate. Optional SUMO/TraCI provides **genuine SUMO microscopic mobility** while the network and SDN behavior remain simulated.

## 1 — Start on Windows (no VM, no dependencies beyond Python)

You already have Python 3 installed on Windows. Extract the supplied ZIP into a folder. Open `VisualUnified` and **double-click `START_WINDOWS.bat`**.

Or open PowerShell inside `VisualUnified`:

```powershell
cd C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified
.\START_WINDOWS.bat
```

The browser should open automatically at **http://127.0.0.1:8765**. If it does not, copy that address into Edge/Chrome. Keep the console running; close it with **Ctrl+C** when finished.

The launcher checks for a working Python 3.10+ interpreter. On this Windows
checkout, `py` is unavailable and the Windows Store `python` alias can fail;
the launcher also checks the already installed
`C:\msys64\ucrt64\bin\python.exe`. You can launch it directly with
`& "C:\msys64\ucrt64\bin\python.exe" run.py`.

Use Python **3.10 or newer**. For a server without automatically opening a tab:

```powershell
.\START_WINDOWS.bat --no-browser --port 8765
```

`START_WINDOWS.bat --no-browser --port 8766` forwards the same options. The
server listens only on `127.0.0.1`; Ctrl+C stops its simulation worker and closes
its optional SUMO connection. A busy port produces a clear startup error.
The browser assets use local files and system fonts; built-in mode works offline.

### Add to your existing MarsVanet project

Extract the ZIP so your existing repository looks like this:

```text
C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\
├── Methodology1\      # keep intact
├── Methodology2\      # keep intact
├── Methodology3\      # keep intact
├── Unified\           # keep intact, if present
└── VisualUnified\     # NEW — all these files go here
    ├── START_WINDOWS.bat
    ├── run.py
    ├── engine.py
    ├── sumo_tools.py
    ├── static\
    ├── tests\
    └── docs\
```

The supplied ZIP starts with `VisualUnified/`; it intentionally does not overwrite your original three methodology folders or existing unified Ryu controller.

**You alone decide whether to commit or push these files.** No Git operations are performed by the package.

## 2 — What is visualized

- **12 moving vehicles** following offset driving lanes with rounded turns, gradual speed changes, same-lane following, and modeled junction stops, including a selectable attacker and victim.
- **3 fixed roadside units (RSU-1/2/3)** beside the carriageway, optional wireless coverage circles, and automatic association/handover. Click an RSU to inspect associated vehicles and modeled path outcomes.
- Vehicle-to-RSU association lines are hidden by default. Click a vehicle to inspect its current association, or enable **All associations** in **Map Display**. These lines are visual aids, not measured radio links.
- **Vehicle-to-vehicle (V2V)** local safety messages and **vehicle-to-infrastructure (V2I)** safety and telemetry messages; **infrastructure-to-vehicle (I2V)** RSU beacons.
- **Short packet pulses**, color-coded cyan normal data, teal safety, red attacks/drops, and amber throttling. Crosses mark sampled drops; the display limits simultaneous effects and does not alter packet accounting.
- A completed RSU handover briefly highlights the vehicle. **Map Display** independently controls coverage, associations, packet effects, labels, attack indicators, and low effects. Reduced-motion system preferences stop vehicle interpolation and decorative motion.
- **Per-vehicle inspector** showing reputation, packets/s, speed, RSU, handovers, and security state.
- The inspector exposes M2 stage/threshold, M3 reputation policy, current victim-UDP policy preview and the latest actual packet decision. **SDN Control Center** shows selected/applied packet-path rule hits with last-match timestamps. These counters are independent of the sampled map effects and are not packet-drop counts.
- **Traffic chart**, source-specific counters, packet delivery ratios, and a timestamped controller audit log.
- **Run / pause / reset / simulation speed** and scenario selection at runtime.

### Short guided demonstration

On **Live simulation**, choose attacker and victim, then click **Start guided demo**. The dashboard resets simulation counters and vehicles while retaining saved policies and controller parameters. It shows five simulated seconds of normal traffic, starts a UDP flood, waits for observed M2 Stage 1 metering and Stage 2 blocking, stops the attack, then waits for the timed block to expire. The progress text explains each step; **Stop guided demo** stops the attack and cancels automation. Pause also pauses progression. A matching enabled M1 DROP rule is reported before the run because it prevents M2 from observing that flood. If Stage 2 is not observed within 45 simulated seconds, the guide stops the attack and reports that instead of claiming mitigation. Detection and recovery timing depend on mobility, coverage, and the selected rules. This is a software simulation, not OpenFlow packet evidence.

In **SDN Control Center** (the former Policy Studio), create or edit a rule, choose its action and scope, and save it. Enable/disable and delete buttons provide immediate feedback; deletion asks before removal. Rules support synthetic source/destination IPv4, node identities, protocol and ports. **Check draft** reports overlap/shadow/safety warnings without installing it. Valid intentional overrides remain allowed; ALLOW still cannot bypass M2/M3.

Use the **Simulated flows**, **Rule Studio**, **Packet sandbox** and **Timeline** links to navigate advanced controls. The sandbox does not observe a packet or debit tokens. Timeline filters and **Clear displayed history** only affect this browser's view. Old saved rules load with wildcard defaults for the additional fields. See [SDN_CONTROL_CENTER.md](docs/SDN_CONTROL_CENTER.md) for schema, precedence, counter semantics and a demonstration walkthrough.

The moving positions and packets are live software-simulation state, not pre-recorded footage. The default route model uses approximately 1 world coordinate unit per meter; it is illustrative rather than a fully calibrated vehicle dynamics or radio propagation model.

The browser fetches authoritative snapshots about every 450 ms while the engine steps about every 100 ms. Vehicles interpolate along bounded authoritative motion traces, including turns and association changes, with no extrapolation during delayed updates. Pausing and resetting stop or clear animation state. The map caps drawing at 30 frames/s, or 10 frames/s with low effects or reduced motion. Mouse-wheel or **+/−** zoom, drag to pan, and **Reset view** retain correct vehicle/RSU hit testing. Visual smoothing does not change packet accounting or policy decisions.

### Phase 1 lane model and evidence compatibility

`SimEngine(seed=14)` now selects `lane_v2`. It uses 10 m lateral lane offsets,
14 m quadratic corner rounding, acceleration up to 1.6 m/s², braking at 3 m/s²,
an 8 m/s turn target, 34 m minimum center spacing (cars are visually oversized),
and deterministic cruise-speed variation of ±3.5%. Six junctions use a 32 s
teaching signal cycle: horizontal green 0–14 s, vertical green 16–30 s, otherwise
all red. Cars too close to brake safely when a phase changes clear the junction.
These are fixed model constants in `mobility.py`, not calibrated traffic data.
RSU overlap hysteresis is 12 m and never extends the configured coverage radius;
the existing five-second reconnect handover window is preserved.

The experiment runners explicitly select `SimEngine(..., mobility_model='legacy')`
to retain the original constant-speed centerline protocol. `experiments/study-v1`
was not regenerated or edited. Its source fingerprints correctly differ after
this implementation; use the explicit saved-ledger audit mode to check archived
artifacts without claiming current source identity:

```powershell
& "C:\msys64\ucrt64\bin\python.exe" validate_experiments.py experiments/study-v1 --allow-source-drift
```

See [Phase 1 progress and limitations](docs/MARSNET_V2_PROGRESS.md) and the
[actual health-smoke output](docs/PHASE1_SMOKE_RESULTS.json). Health-smoke runs
are not a replacement for the 90-trial study.

## 3 — One combined controller (the three methodologies)

| Stage | Behavior | Controller configuration |
|---|---|---|
| **M1 — Static flow rules** | Priority-ordered match on source vehicle, traffic type and ingress RSU. Actions are **DROP**, **ALLOW**, or **METER**. An ALLOW is not an override of later security protection. | Policy Studio → Rule editor; individual enable/disable buttons. |
| **M2 — Mobility-aware DoS** | Original **5-second observed-span packet tracker** for victim-bound modeled UDP, followed by **one-second pre-meter counter deltas** in Stage 1. Base **120 pps**; dense/slow context selects **90**, sparse/fast **150**, high handover churn raises the floor to **150**. **500 kbps** Stage 1, **10-second minimum dwell**, **30-second block**. | Policy Studio → Controller configuration; advanced settings via `/api/config`. |
| **M3 — Safety-message trust** | Original strict JSON parser, physical consistency checker and reputation rules. Wire-style reports use **m/s**; UI speed uses km/h. Default penalty is **0.20 × severity** (speed violation: **0.16**, displacement: **0.20**). Five valid observations restore **0.02**. Original **500 / 200 / 100 kbps** bands remain. | Policy Studio → Methodology switches and reputation parameters. |

**Policy precedence:** the highest-priority matching static rule is selected first. Its DROP stops forwarding and M2 observation; otherwise M2's timed victim-UDP DROP takes precedence over meters. Applicable M1, M2 and M3 budgets jointly constrain delivery; the strictest steady rate is displayed. ALLOW never bypasses dynamic protections. Normal packets and attacker packets traverse the same backend simulation engine.

This **unifies the three primary defense mechanisms**, rather than running three unrelated controllers. The old Methodology 2 Paillier proof of concept is retained only in the original repository and is **not wired into this simulator**.

Safety reports update controller reputation once, when the controller-bound copy
is delivered to an associated RSU; peer copies do not update it again. SAFETY is
exempt from M2 detection/blocks and M3 metering so recovery remains possible.
Explicit M1 rules may still drop or meter SAFETY. M3 uses one source budget for
all non-safety data; M2 uses a victim-bound UDP budget and M1 uses a matching-rule budget.
All applicable budgets constrain delivery, with the strictest rate shown in the
UI. An unrelated unmetered packet cannot reset these budgets. Finite initial
bursts mean short-window throughput can differ from the configured steady rate.

`methodology.py` loads the original pure Python M2/M3 policy helpers from the
sibling `Methodology2/` and `Methodology3/` directories, without importing Ryu.
Keep VisualUnified inside this repository; copying that directory alone no
longer supplies its policy dependencies. See [the fidelity comparison](docs/METHODOLOGY_FIDELITY.md)
for exact source references and intentional simulation adaptations.

Stage 1 remains installed when traffic subsides until its original **15-second
flow lifetime** expires; only M2 state/budget resets then. Stage 2's deadline is
fixed when installed, and dropped packets do not extend it. After 30 seconds,
observation resumes with the original detector recovery decision. M3 recovery
never removes an active M2 restriction, and M2 recovery never clears reputation.
The flow lifetime must exceed the configured dwell. Saved settings remain user
overrides; existing 4/12-second profiles are not silently rewritten.

### Reputation-to-meter bands

| Reputation | State | Meter |
|---|---|---|
| 0.00–0.19 | Severe throttle | 100 kbps |
| 0.20–0.39 | Heavy throttle | 200 kbps |
| 0.40–0.59 | Light throttle | 500 kbps |
| 0.60–0.79 | Monitor | none |
| 0.80–1.00 | Normal | none |

## 4 — Live demonstration walkthrough

For the short presentation, follow the
[five-minute demonstration checklist](docs/FINAL_DEMO_CHECKLIST.md).

1. Launch the app. On **Live Simulation**, watch cars moving, RSU attachment, V2V safety messages and I2V beacons. The normal baseline should show high legitimate PDR, though some simulated radio losses can occur.
2. Select attacker **V07**, victim **V02**. Click **UDP flooding**. Monitor the controller events and traffic chart. M2 detects sustained high packet rate, meters the attacker, and escalates to a temporary block. On Policy Studio, check the **effective runtime flow policies**.
3. Click **Normal traffic** and let M2 recover. Click **False safety data**. Watch V07's reputation deteriorate through 500 → 200 → **100 kbps**; read controller log entries.
4. Click **Combined attack**. Now M2's packet-rate defense and M3's reputation defense operate simultaneously, on **the same source**. Inspect the active M2/M3 row in the runtime flow view.
5. For **M1**, go to **Policy Studio**, add a static rule: `source=V07`, `traffic=UDP_FLOOD`, `RSU=*`, `priority=900`, `action=DROP`, `enabled=true`. Keep combined attack active. M1 static-drop counters rise; disable the rule to let the dynamic defenses act again.
6. Use **Controller configuration** to edit the detector threshold or meter rate live, run further experiments, then **Evidence & Logs → Export JSON report**.
7. Use **Reset** for a new measurement run. Reset retains your configured rules and parameters; toggling the mobility source also resets the experiment. **Rules and controller settings are automatically saved in `controller_settings.json`** and reloaded at your next launch (the file is excluded by `.gitignore`).

**Recommended experimental comparisons:** run separate reset trials with (a) all three defenses off, (b) only M1, (c) only M2, (d) only M3, and (e) all three enabled, under the same threat scenario. Export each JSON report and analyze receiver delivery ratios and losses. This compares **simulated workloads**, not validated OVS benchmarking.

## 5 — Native Windows SUMO mobility (optional)

The built-in road mobility already moves cars in the browser and requires no extra packages. For a more realistic academic mobility component, use **Eclipse SUMO** natively on Windows. This still **does not** require Ubuntu, WSL or VirtualBox.

1. Install SUMO for Windows from [official SUMO downloads](https://sumo.dlr.de/docs/Downloads.html), or in a PowerShell terminal:
   ```powershell
   winget install --name sumo
   ```
2. The adapter uses an installed TraCI package or discovers the `tools/traci`
   bundled beside the native SUMO executable. No additional installation is
   needed when that bundle is present. Missing optional tools produce a clear
   error and leave built-in mode available.
3. Open a new PowerShell after installing SUMO. Check:
   ```powershell
   where.exe sumo
   where.exe netconvert
   ```
   If they are not found, add the SUMO `bin` directory to PATH or set `SUMO_HOME` to its installation root (for example, the directory that contains `bin`).
4. Start `.\START_WINDOWS.bat`, switch the toolbar **Built-in mobility → Native SUMO**. The backend automatically builds a road network using `netconvert` and uses TraCI to step actual SUMO vehicles with IDs V01–V12. The map badge identifies the active provider.

Generated SUMO input files are placed under `VisualUnified/sumo/`. They can be opened separately in `sumo-gui` if desired (see the SUMO installation guide), but the MarsNet browser is the central dashboard.

**What changes in SUMO mode:** positions, headings and speeds come from SUMO/TraCI. Network normalization offsets are removed before converting to screen coordinates. Elapsed requests accumulate against SUMO's step grid. Departed/arrived vehicles remain identified but inactive, generate no traffic, and have no association; reappearing IDs retain policy and reputation state. Switching providers resets run counters. Connection failure resets to built-in mode and pauses, avoiding a silent jump between mobility systems.

**What stays simulated:** V2V/V2I radio delivery, security messages, token-bucket rate limiting, SDN policies, congestion and packet losses. On 2026-11-10, installed native SUMO 1.27.1 passed a bounded 10-second headless bridge check and a separate 10-second engine/TraCI integration check with 12 active vehicles and zero invalid-safety detections. Long sessions, GUI rendering, and late route arrivals remain unverified.

## 6 — Test commands

From `VisualUnified`:

```powershell
& "C:\msys64\ucrt64\bin\python.exe" -m unittest discover -s tests -v
node --test tests/test_dashboard_ui.js
& "C:\msys64\ucrt64\bin\python.exe" smoke_phase1.py
```

The project ships with tests of movement, handovers, packet forwarding, static-rule priority, M2 detection/staged blocking, M3 deterioration, combined defense, pause/reset, configuration validation, SUMO input generation and more. Fidelity regressions also compare mobility thresholds, packet rates and severity/reputation traces against the original helpers and check independent recovery under combined enforcement.

### Reproducible comparison across all defense profiles

For the instrumented study with matched traffic/mobility, five seeds,
baseline/attack/recovery windows, semantic packet labels, 95% intervals,
CSV evidence and standalone graphs, run:

```powershell
py -3 run_experiments.py --output experiments/study-v1-repeat
```

See [experiment design and metric definitions](docs/EXPERIMENTS.md). Choose a
new, unused output directory for each rerun; existing directories are protected.
This runner does not load saved dashboard
settings or alter defense algorithms. Results are generated by simulator
execution, not measured OpenFlow performance. The simpler comparison below
remains available for compatibility.

The [executed 90-run study report](experiments/study-v1/REPORT.md) includes actual
simulator results and links through the study directory to CSV summaries,
complete packet evidence, and nine SVG comparison figures. Validate the saved
evidence with `py -3 validate_experiments.py experiments/study-v1`.

Run the following in PowerShell to produce an illustrative **simulated** ablation CSV (no VM needed):

```powershell
py -3 run_comparison.py --seconds 35 --scenario combined --output comparison_simulation.csv
```

It runs No Defense, M1-only, M2-only, M3-only, Unified Dynamic, and Unified + M1 Static with the same seed, traffic model, time interval and attacker/victim. A sample is included in `docs/sample_simulated_ablation.csv`; it came with the ZIP before the integration fixes and is not a current regression reference. Existing output files are protected from overwrite. **Overall PDR includes blocked attack packets in the denominator, so a more effective defense can make overall PDR *lower*. Compare attacker-delivered packets and legitimate PDR separately.** These numbers are not OpenFlow benchmark results.

The `legitimate_*` counters/PDR classify non-UDP_FLOOD packets, including safety
traffic, by traffic type rather than excluding every packet from the selected
attacker. They are not a semantic false-positive oracle: invalid safety content
is still classified as non-flood traffic. Per-attacker vehicle counters include
all that vehicle's packet types. Reports include the seed, configuration and
simulation-only label. Metrics are packet counts/PDR, not measured latency or
real switch throughput. Empty PDR windows retain the UI's 100% default and
must not be interpreted as evidence of delivery without checking sent counts.

### HTTP API

Runs bound to **127.0.0.1 only**. Requests use JSON (`Content-Type: application/json`).

```text
GET  /api/state       # live snapshot, vehicles, packets, rules and telemetry
GET  /api/report      # downloadable simulation evidence JSON
GET  /api/flows       # logical flow rows and bounded rule warnings
GET  /api/events      # newest 180 controller events
POST /api/policy-preview # hypothetical synthetic packet; read-only
POST /api/rules-analyze  # validate/check a rule draft; read-only
POST /api/scenario    {"scenario":"combined","attacker":"V07","victim":"V02"}
POST /api/run         {"running":false}
POST /api/speed       {"factor":2}
POST /api/reset       {}
POST /api/mobility    {"mode":"builtin"} or {"mode":"sumo"}
POST /api/config      {"base_pps":160,"m2_meter_kbps":300}
POST /api/rules       {"label":"Example","source":"V07","traffic":"UDP_FLOOD","rsu":"*","priority":900,"action":"DROP","enabled":true}
POST /api/rules/{id}  # update existing rule with complete rule object
POST /api/rules/{id}/toggle {}
POST /api/rules-delete {"id":"rule-1"}
```

The API is intended for the single local operator, not exposed to the Internet.

## 7 — Scientific and technical limitations

- **No physical or protocol-level OpenFlow enforcement in this build**: the rules are an OpenFlow-*like* controller model, not rules pushed into OVS. Keep any live Ryu+OVS reports and their captured measurements as separate evidence.
- **No real network sockets or radios**: packet traffic is generated and evaluated inside Python with size, timing, source, destination, path and security decisions. Visual trails represent simulated packets. This is suitable for an interactive teaching/research *simulation*.
- **Simplified radio and routing**: fixed V2V and RSU ranges, backhaul connectivity, token-bucket rate limits, probabilistic radio loss. Not a wireless channel/802.11p/WAVE MAC implementation, propagation test, or attack deployment.
- **Safety plausibility is not authentication**: an adversary could spoof a source identity or manipulate plausible claims. Trust decisions are model-specific.
- **Traffic modeling**: packets/s is attempted ingress packet count; PDR is delivered/generated from the simulator. These measures cannot be directly compared with historical Mininet/OVS receiver counters.
- **SUMO mode is optional**: native Windows SUMO produces car mobility only; it does not create a real SDN forwarding plane.
- **No Paillier wire integration**: the former small-key educational Paillier experiment was separate from live forwarding, and is not part of the new core simulation.

## 8 — Suggested architecture for a future real OpenFlow-backed demo

Keep this visual dashboard and policy editor as the UI; replace the Python simulation backend's forwarding function with an adapter to a **real** Ryu/OVS controller where accessible. Mapping SDN policies to actual OpenFlow 1.3 flow mods and meters requires an OpenFlow-capable data plane; Mininet-WiFi remains most natural on supported Linux kernels. The visual demo is useful now without promising OpenFlow-level validation it does not provide.

## 9 — Files

```text
VisualUnified/
├── START_WINDOWS.bat      # double-click launcher
├── run.py                 # local HTTP server + simulation loop
├── run_comparison.py      # reproducible six-profile simulation comparison
├── run_experiments.py     # seeded baseline/attack/recovery study
├── validate_experiments.py # saved packet-ledger and artifact verification
├── engine.py              # common mobility, packet, detection, policy model
├── methodology.py         # adapter to original pure M2/M3 policy helpers
├── sumo_tools.py          # optional SUMO network generator + TraCI bridge
├── static/
│   ├── index.html         # dashboard, scenario lab, policy studio, evidence
│   ├── styles.css         # UI styling, responsive layout
│   └── app.js             # canvas animation + live controls
├── tests/
│   ├── test_engine.py     # engine behavior
│   ├── test_methodology_fidelity.py # parity and simultaneous policy regressions
│   ├── test_experiments.py # experiment metrics and artifact regressions
│   └── test_sumo_inputs.py # SUMO input generation
├── experiments/study-v1/ # 90 executed simulation trials and figures
└── docs/
    ├── EXPERIMENTS.md
    ├── FINAL_DEMO_CHECKLIST.md
    └── INTEGRATION_AND_DEMO.md
```

MarsVanet Team 14 — VIT Vellore. The historical Methodology1/2/3 files and evidence remain separate and unmodified.
