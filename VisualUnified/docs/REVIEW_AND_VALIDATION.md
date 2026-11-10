# VisualUnified integration review

The later [methodology fidelity review](METHODOLOGY_FIDELITY.md) supersedes the
package's original teaching-policy equations and short default timings.

The implementation was imported from the Desktop package
`MarsVanet_VisualUnified_Windows.zip`, SHA256
`E1EE772D906DFFB4511D6CF49A5F81A6A755816B98A4750707B7553495740AD7`.
Every archive member was checked to stay inside the new `VisualUnified/`
directory, and extraction refused existing target files. No methodology or
benchmark implementation was replaced. `Unified/` was absent in this checkout
when integration started; the application does not require or recreate it.

## Implemented locally

* Python simulation of 12 vehicles, three RSUs, coverage association, direct
  V2V routes, RSU-backed routes, congestion/loss and packet delivery accounting.
* Concurrent static match/action rules, flood-rate detection with staged
  mitigation, safety consistency checks and reputation updates/recovery.
* Local HTTP state/configuration/rule APIs, persisted settings, browser canvas
  frontend, event history and JSON simulation report export.
* Optional SUMO input XML generation and a TraCI mobility adapter. Network and
  security behavior still run inside the simulator when SUMO supplies motion.

## Reproducible bugs corrected

* Meter state no longer resets when an unmetered packet is interleaved. M1
  per-rule budgets, M2 victim-UDP budgets and shared M3 source data budgets retain
  their tokens. RSU-source M1 meters also enforce their configured rate.
* SAFETY packets do not enter M2 flood counts or M3 data budgets. A delivered
  controller-bound report updates reputation once, while peer duplicates and
  packets dropped before the controller do not create observations. Static M1
  restrictions still apply to telemetry as configured.
* Accelerated simulation advances through at most 0.1-second simulated steps;
  the previous large-step cap silently reduced offered floods and altered
  bucket refill behavior. Display sampling has a separate RNG, and network
  radio-loss draws occur once per offered packet across seeded comparisons.
* Rejected configuration/scenario changes leave state unchanged. Invalid zero
  and nonfinite meter rates are rejected. Disabling M2 clears its current
  enforcement even when paused.
* Direct handovers and reconnects to another RSU within five seconds count
  once. Initial association, same-RSU reconnects, disconnect-only events and
  reconnects outside that window do not count. Vehicle policy persists.
* Concurrent HTTP mutations/save operations serialize under the engine lock;
  tests use temporary settings and cannot overwrite a saved user profile.
  Importing the server no longer loads user settings as a side effect.
* Shutdown stops the owned simulation worker and closes its SUMO connection.
  Port binding happens before the worker starts; the batch launcher passes
  CLI options through. Reset preserves the seed and recalculates association
  using the retained coverage settings.
* Reports classify non-flood delivery by traffic type, independent of attacker
  identity. The UI shows the effective flood action/rate, including static
  rules and the stricter of M2/M3 limits. Comparison durations preserve a final
  fractional step, reject nonfinite durations and protect existing CSV output.

## Validation commands

On Windows, the integrated application suite passes **71 tests** (the package
originally supplied 32). The existing benchmark suite passes 41 tests,
Methodology 2 passes 72, and Methodology 3 passes 62. Python compilation and
JavaScript syntax checks pass. All are local automated checks; no Mininet,
Ryu, SUMO, VirtualBox or physical network validation was performed.
All 61 literal frontend DOM references resolve to supplied HTML elements.
A six-profile comparison smoke check ran 35 simulated seconds per profile,
verified equal generated packet loads and simulation-only labels, and wrote
no result artifacts. These checks do not establish browser rendering quality
or measured network performance.

## File inventory

The ZIP supplied `.gitignore`, `README.md`, `START_WINDOWS.bat`, `engine.py`,
`run.py`, `run_comparison.py`, `sumo_tools.py`, `static/app.js`,
`static/index.html`, `static/styles.css`, `docs/INTEGRATION_AND_DEMO.md`,
`docs/sample_simulated_ablation.csv`, `tests/test_engine.py`,
`tests/test_http_api.py` and `tests/test_sumo_inputs.py`.

Integration changed `engine.py`, `run.py`, `run_comparison.py`,
`START_WINDOWS.bat`, `static/app.js`, `README.md`,
`docs/INTEGRATION_AND_DEMO.md`, `tests/test_http_api.py` and
`tests/test_sumo_inputs.py`. It added `tests/test_regressions.py` and this
review. The repository root `README.md` now links to the application and gives
the Windows launch command. The supplied sample CSV is preserved unchanged.
The fidelity update adds `methodology.py`, `tests/test_methodology_fidelity.py`
and `docs/METHODOLOGY_FIDELITY.md`, and updates the engine, default-timing tests,
configuration UI and methodology documentation. It changes no original policy
source file.

From the repository root in Windows PowerShell:

```powershell
cd C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified
python -m unittest discover -s tests -v
python -m py_compile engine.py methodology.py run.py run_comparison.py sumo_tools.py
node --check static/app.js
python run.py --no-browser --port 8765
```

`node` is optional for JavaScript syntax checking and is not an application
dependency. API tests start an owned HTTP server on an ephemeral loopback port,
exercise successful/error/concurrent requests and static assets, and shut it
down. SUMO tests generate XML and use mocks; they do not start SUMO. Regression
tests cover policy precedence, token accounting, simultaneous detection and
reputation recovery, handovers, speed changes and invalid API inputs.

## Limits and remaining work

* No Ryu app, OpenFlow connection, switch flow/meter statistics, packet capture,
  real UDP workloads, physical radio model, Mininet or VirtualBox integration
  is provided. HTTP server traffic is real local TCP; displayed VANET traffic
  is simulated.
* The engine now reuses original pure M2/M3 policy helpers, with intentional
  simulated input and topology adaptations. Victim-bound modeled UDP enters
  M2 regardless of attack label; M3 uses the strict parser and source-bound
  simulated IDs. Pure policy parity does not establish real network source
  authenticity, runtime enforcement parity or equivalent radio behavior.
* Direct V2V traffic is policy-checked centrally in Python even without an RSU
  datapath. Handover continuity represents shared controller state, not actual
  OpenFlow replication or a radio handover protocol.
* SUMO runtime startup, coordinate mapping, route exhaustion, late vehicle
  insertion/departure and connectivity remain unverified without installed
  SUMO/TraCI. Missing TraCI positions currently leave a modeled vehicle at its
  previous/default location. Live validation is needed before using this mode
  as an accurate SUMO/network coupled experiment. Built-in mode needs no SUMO.
* Browser rendering, responsive layout and the batch-file double-click flow
  need a later human smoke check. HTTP/static-asset and JavaScript checks do
  not establish visual quality. No interactive user testing is required now.
* Packet outcomes use simulation tick timestamps; queues, transport latency,
  OpenFlow barrier timing, cryptographic authenticity and calibrated wireless
  interference are not measured. Recent windows are bounded to 60,000 records;
  event/history/pulse logs are bounded rather than complete packet captures.
* A 100% PDR default when no packets were sent is a UI convention, not a measured
  result. No statistical significance or real-world performance follows from
  the included sample or a single seeded simulated run.
* Settings persistence serializes one application process. Run only one server
  against a settings file; multi-process coordination and authentication are
  outside the scope of this loopback teaching application.

Optional future work is to validate SUMO on the target installation and add a
separately tested Ryu/OVS adapter. Neither is needed to use built-in Windows mode.
