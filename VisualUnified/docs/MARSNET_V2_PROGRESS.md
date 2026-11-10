# MarsNet 2.0 — Phase 1 progress

Updated 2026-11-10. **Simulation only:** the dashboard does not program Ryu,
OpenFlow or OVS. Native SUMO supplies mobility only.

## Completed

- Default `lane_v2` built-in mobility: right-hand lane offsets, continuous rounded
  turns, deterministic cruise variation, bounded acceleration/braking, same-lane
  following and fixed-time junction signals. Original M2/M3 helpers and thresholds
  are unchanged. Vehicle IDs, reputation and defense state persist at handover.
- Twelve-metre RSU overlap hysteresis reduces boundary chatter without extending
  coverage. Direct and brief-disconnect handovers retain the existing five-second
  rule. Rendering never increments handover counters.
- Bounded authoritative pose traces drive browser interpolation through turns,
  stopping, resets and association changes. After a long missing update, the
  renderer resynchronizes instead of drawing an invented path across the map.
- Default map overlays are quiet. Selection exposes the relevant association or
  coverage. Packet effects use actual sampled events, with a maximum of 14 visible
  effects (five flood effects); low effects allows five total/two flood effects.
  These limits never change packet generation or accounting.
- V2V safety is a teal square pulse; other safety is teal, telemetry/data cyan,
  RSU beacons violet rings, floods/drops red and throttling amber. Reduced motion
  uses fixed packet markers and authoritative car positions. Low effects removes
  shadows and reduces map refresh to ten frames/second.
- Vehicle inspection adds modeled movement status, coverage margin and sent/
  received/source-drop counts. RSU inspection adds associations and explicitly
  labeled end-to-end path outcomes. One packet can appear in multiple RSU path
  counters; they must not be summed as unique network packets or switch counters.
- Wheel/button zoom, bounded drag pan, reset view and inverse-transformed hit
  testing. Road markings, signal indications and RSU placement separate lanes
  from infrastructure. Labels avoid nearby cars and RSU badges.
- SUMO: normalized network offsets are removed, heading/velocity units are
  converted, elapsed requests accumulate rather than drifting with rounded
  steps, configured seeds are passed, and each connection has a unique label.
  Unknown IDs are ignored. Absent vehicles stop generating traffic and disappear
  from the map; known IDs retain their state on reappearance. Missing tools leave
  the current simulation intact. Runtime connection failure resets to built-in
  mode and pauses instead of silently mixing positions and counters.
- The existing HTTP endpoints, configurable defense rules, profile format and
  guided demo are retained. Added snapshot fields are optional for old clients.

## Architecture and reproducibility

`run.py` owns the approximately 100 ms engine worker. `engine.py` owns the clock,
traffic, counters, associations and unified policy pipeline. `mobility.py` plans
every car against the same previous snapshot and computes lane poses. It imports
no policy code and uses no traffic random-number draws. `sumo_tools.py` is the
optional mobility provider. `static/app.js` interpolates the bounded pose history
and renders canvas effects; it does not decide packet outcomes.

Fixed teaching-model constants are documented in the README: 10 m lane offset,
14 m corner rounding, 1.6/3 m/s² acceleration/braking, 8 m/s turn-speed target,
34 m center spacing, ±3.5% cruise variation and a 32 s signal cycle. The rendered
car size and spacing are exaggerated for readability. A car already too close
to stop safely when a signal changes clears the junction. The model is not a
calibrated collision-free traffic microsimulator.

`run_comparison.py` and `run_experiments.py` explicitly use `legacy` mobility.
The 90-trial study remains byte-for-byte untouched. Source fingerprints now
differ, so the strict validator correctly refuses a current-source identity
claim. `--allow-source-drift` only permits a read-only saved-ledger audit and
reports the differing sources; all artifact hashes and metric checks still run.
Two individual archived seed-14 trials (normal and combined, unified_dynamic)
were replayed with legacy mobility: packet counts, offered-packet hashes and
mobility hashes matched exactly. This is not a full rerun of the 90-trial study.

## Verified checks

- **100 Python unit/integration tests passed**, including the new lane, signal,
  following, seed replay, boundary handover, inactive-SUMO, transform/timing,
  optional-tool failure, connection cleanup and source-drift audit regressions.
- **12 JavaScript tests passed**: interpolation/trace turns, handover association
  timing, bounded effects, zoom/hit testing, display options, RSU inspection,
  cleanup, and existing guided sequence contracts.
- Python source compilation, JavaScript syntax and `git diff --check` passed.
- Isolated local HTTP smoke on port 8766 passed for the dashboard assets and
  snapshot API with 12 vehicles, pose traces and RSU stats. Temporary settings
  were used; the owned server/worker were stopped.
- Built-in health runs: seed 14, 12 vehicles, 5 s baseline + 20 s scenario window
  + 120 s recovery, normal and combined. Exact counters and source hashes are in
  [PHASE1_SMOKE_RESULTS.json](PHASE1_SMOKE_RESULTS.json). Normal: 9,040 generated,
  8,955 delivered, 85 dropped, zero invalid-safety detections. Combined: 15,440
  generated, 9,291 delivered, 6,149 dropped; M2 NORMAL/METER/BLOCK were observed,
  the attacker returned to NORMAL and reputation recovered from 0.00 to 0.86.
  These are two deterministic health runs, not a statistical performance study.
- Saved study audit: 90 runs, **1,362,030 packet records**, 287 artifact hashes
  and nine SVGs checked. Artifact/ledger PASS; current source identity DIFFERENT.
- **Actual native SUMO 1.27.1 headless check passed** in a temporary generated
  network: at requested 1/5/10 seconds, SUMO time was exactly 1/5/10 seconds and
  all 12 expected IDs were present. The network offset was (-90, -70), correctly
  removed. A separate 10-second engine/TraCI integration produced 568 simulated
  messages, zero invalid-safety detections and one modeled handover. Only the
  connections created for these checks were closed. No dependencies were installed.
- Browser automation was attempted. The browser access host was unavailable;
  native browser input was then stopped by the tool because it could not verify
  the current URL. **No browser visual/smoothness or click-through pass is claimed.**

## Commands

From PowerShell in `VisualUnified`:

```powershell
.\START_WINDOWS.bat
# Checks use the working interpreter already installed on this machine:
& "C:\msys64\ucrt64\bin\python.exe" -m unittest discover -s tests -v
node --test tests/test_dashboard_ui.js
node --check static/app.js
& "C:\msys64\ucrt64\bin\python.exe" smoke_phase1.py
& "C:\msys64\ucrt64\bin\python.exe" validate_experiments.py experiments/study-v1 --allow-source-drift
```

`smoke_phase1.py --output <unused-name.json>` records a new result exclusively;
it rejects existing files. The default prints results without writing settings
or evidence. Select **Native SUMO** in the toolbar to use an available native
installation; the badge confirms the provider. This resets the current run.

## Remaining work and roadmap

1. Browser visual QA at common laptop resolutions: evaluate actual smoothness,
   inspect both node types, drag/zoom, reduced motion, flooding, policy edits and
   a complete guided recovery. Automated contracts cannot prove visual quality.
2. Strengthen cross-route merging and intersection conflict resolution. Current
   longitudinal following and deterministic signals do not guarantee collision
   avoidance for every custom layout, merge or simultaneous turn. There is no
   lane changing, overtaking or calibrated queue-capacity model.
3. Longer native SUMO sessions: late arrivals, route exhaustion, live rerouting,
   disconnection and GUI interoperability. Mock tests cover absent/reappearing
   IDs and updated poses; only bounded native sessions were executed. SUMO uses
   priority junctions from the generated network, not built-in traffic lights;
   the browser accordingly hides teaching signal indicators in SUMO mode.
4. A future separate study may compare lane_v2 profiles with its own protocol,
   seeds and output directory. Do not relabel study-v1 as lane_v2 evidence.
5. Real radio, OpenFlow acknowledgements and measured data-plane enforcement
   require a separate validated live adapter and independent instrumentation.

Estimated Phase 1 completion: **about 85%**, measured against the requested
dashboard/mobility foundation. Remaining focused QA and traffic-model work is
approximately **6–12 engineering hours**, with roughly ±50% uncertainty depending
on browser findings and how strong merge/conflict guarantees need to be. This
does not estimate a production traffic simulator or real OpenFlow integration.
No immediate user action is required; browser verification remains pending.

## Files changed in this phase

All paths are relative to `VisualUnified/`:

- Runtime: new `mobility.py`; updated `engine.py`, `run.py`, `sumo_tools.py`.
- Frontend: `static/app.js`, `static/index.html`, `static/styles.css`.
- Study compatibility/auditing: `run_comparison.py`, `run_experiments.py`,
  `validate_experiments.py`.
- Health check: new `smoke_phase1.py` and `docs/PHASE1_SMOKE_RESULTS.json`.
- Tests: new `tests/test_mobility.py`, `tests/test_phase1_smoke.py`; updated
  `tests/test_dashboard_ui.js`, `tests/test_experiments.py`.
- Documentation: `README.md`, `docs/EXPERIMENTS.md`,
  `docs/FINAL_DEMO_CHECKLIST.md`, `docs/INTEGRATION_AND_DEMO.md`,
  `docs/METHODOLOGY_FIDELITY.md`, and this new progress record.

Original methodology files, `Unified/`, `benchmark/`, historical study artifacts
and saved controller settings were not changed. No Git state mutations or
publishing operations were performed.
