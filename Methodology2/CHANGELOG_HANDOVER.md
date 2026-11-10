# Change Log and Handover

This revision completes the runtime-independent MED-2 work, fixes source-level
bugs in the controller and topology, makes the system configurable, and adds
automated tests, scenarios and documentation. It was prepared in a Python-only
environment; no live SDN/SUMO run was performed here (see
`PENDING_WORK_AND_VALIDATION.md`).

## Added

* `Methodology2/scripts/med2_config.py` — central, env-overridable configuration
  (thresholds, window, meter rate, ports, DPID, paths, handover). Removes
  scattered hardcoded constants.
* `Methodology2/scripts/mobility_detector.py` — runtime-independent detection
  logic: mobility feature loading/validation, stale-sample guard, threshold
  policy with documented fallback, sliding-window rate (observed-duration
  divisor), and the progressive-mitigation decision state machine with
  reset/recovery.
* `Methodology2/scripts/trust_aggregation.py` — privacy-preserving aggregation
  with explicit Observer / Aggregator / Decryptor roles; aggregator never
  decrypts; threshold applied after decryption; bounds + overflow guard; the
  encrypted DoS-evidence pipeline (documented, separately testable, not wired
  into the controller fast path).
* `Methodology2/scripts/connectivity_test.py` — read-only connectivity /
  packet-path diagnosis for the live VM (bridge membership, controller state,
  AP2 flows, ARP, ping path) instead of guessing the root cause.
* `Methodology2/scripts/detector_demo.py` — runnable demonstration of threshold
  selection and the stage progression (logic only, no fabricated metrics).
* `Methodology2/tests/` — 45 unittest cases (Paillier, trust/evidence
  aggregation, mobility detection, DoS-evidence) + `_bootstrap.py`.
* `Methodology2/run_tests.sh` — runs the unittest suite and the 5 original check
  scripts.
* `Methodology2/scenarios/urban/` and `scenarios/highway/` — comparable SUMO
  scenarios (nodes/edges/routes/sumocfg) + `build_networks.sh` + `README.md`.
* `Methodology2/EXPERIMENTS.md` — reproducible experiment matrix with exact
  commands; `Methodology2/IMPLEMENTATION_STATUS.md`; `Methodology2/results/`
  (fresh measured benchmarks + README).
* `requirements.txt` (repo root).

## Changed

* `Methodology2/scripts/dos_defense_v2.py`
  - Imports `med2_config` + `mobility_detector`; all parameters come from config.
  - **Removed the hardcoded `/home/ev/sdn_vanet_sumo/mobility_features.csv`
    path**; mobility file is configurable and defaults to the CSV shipped in
    `Methodology2/`.
  - **Stage 1 meter flow now also forwards matching packets to the controller**
    (in addition to the victim port) so packet-rate observation continues and
    Stage 2 escalation is possible. Previously it output only to the victim
    port, silently preventing escalation.
  - **Removed the periodic 20 s Stage 2 re-block** that could extend a 30 s
    block indefinitely; the block now self-expires and the per-source detector
    resets after the block window + an idle gap, enabling recovery.
  - Corrected early-window packet-rate calculation (observed duration).
  - Added a stale-mobility-sample age guard (clock-misalignment protection).
  - Added `EventOFPStateChange` (drop disconnected datapaths) and
    `EventOFPErrorMsg` handlers; de-duplicated meter installation.
  - Original file preserved as `dos_defense_v2.py.pre_med2_completion`.
* `Methodology2/scripts/sdn_vanet_2ap.py`
  - **Bridge-port attach, revised after live testing.** The original blind
    `ap1.cmd('ovs-vsctl','add-port','ap1','ap1-wlan1')` was first removed on the
    assumption Mininet-WiFi always auto-attaches each AP's wlan interface. Live
    testing in the target VM showed that is NOT reliable: ap2 was attached but
    ap1 was not, leaving ap1's stations with no datapath into the bridge. The
    attach is therefore restored, but now **idempotent, symmetric and verified**
    via `ensure_ap_wireless_port()` (attaches only if missing, for both APs, and
    prints the resulting `list-ports`). See `CONNECTIVITY_FIX.md`.
  - Added `bring_up_stations()` to bring every station wlan interface up and
    report association, addressing the "interfaces down / not associated"
    symptom (radio-layer issues are then diagnosed, not masked).
  - Radio parameters made configurable: `DOS_PROP_EXP` (propagation exponent,
    default 3), `DOS_AP_RANGE` (default 35), `DOS_AP_TXPOWER` (optional) so
    edge stations can be made to associate without editing the script.
  - Controller IP/port configurable via `DOS_CONTROLLER_IP` /
    `DOS_CONTROLLER_PORT`.
  - Original preserved as `sdn_vanet_2ap.py.pre_med2_completion`.
* `Methodology2/scripts/paillier_crypto.py`
  - **Removed the `sympy` dependency**; prime generation now uses a
    standard-library Miller-Rabin test, so the crypto tests run with no
    third-party packages.
  - Added `add_plaintext`, `aggregate`, `encode`, `decode`; kept the original
    `generate_keys/encrypt/decrypt/add_ciphertexts` API unchanged.
* `Methodology2/mobility_features.py` — resolves paths relative to the script
  and accepts optional `input`/`output` arguments (was CWD-dependent).
* `Methodology2/collect_mobility.py` — parameterised (`--net/--routes/--output`)
  with a clear error if `traci`/SUMO is missing; defaults unchanged.
* `Methodology2/scripts/benchmark_multi_observer.py`,
  `scripts/compare_trust_aggregation.py`,
  `scripts/save_paillier_results.py` — write to `Methodology2/results/` by
  default (override `BENCH_OUTPUT`) so committed evidence in `final_evidence/`
  is never overwritten. `save_paillier_results.py` now measures real numbers
  instead of writing a fixed hand-entered table.
* `README.md` (repo root) — updated with setup, tests, scenarios and honest
  status; see that file.

## Removed

* Nothing deleted. The fabricated behaviour of `save_paillier_results.py` was
  replaced with a real measurement; pre-change controller/topology files are
  retained as `*.pre_med2_completion` alongside the project's existing
  `*.backup` / `*.pre_revision` copies.

## Not done (needs the live testbed)

Live association/handover, meter enforcement, Stage 2 recovery, end-to-end
connectivity and all network performance measurements. Do not read this
revision as proof those passed. See `PENDING_WORK_AND_VALIDATION.md`.
