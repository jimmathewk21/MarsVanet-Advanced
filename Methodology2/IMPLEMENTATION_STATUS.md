# MED-2 Implementation Status

A concise, honest status of each MED-2 feature after this revision. Legend:

* **Done (tested here)** — implemented and verified by automated tests that ran
  in the preparation environment (Python only).
* **Done (source)** — implemented at source level but needs the live
  SDN/SUMO testbed to validate end to end; not run here.
* **Scaffolded** — configuration/scripts/commands provided; requires the
  testbed to execute.

| Area | Status | Notes |
|------|--------|-------|
| Central configuration (`med2_config.py`) | Done (tested here) | All thresholds/ports/paths configurable via env; no machine-specific hardcoded paths. |
| Mobility feature validation + fallback (`mobility_detector.load_mobility_features`, `nearest_sample`) | Done (tested here) | Schema/missing/stale handling; documented base-threshold fallback; stale-sample age guard. |
| Mobility-aware threshold policy (`select_threshold`) | Done (tested here) | Dense/slow lowers, sparse/fast raises, handover floor; mobility never alone implies attack. |
| Sliding-window rate (`PacketRateTracker`) | Done (tested here) | Observed-duration divisor fixes early-window underestimate. |
| Progressive-mitigation decision logic (`decide`) | Done (tested here) | Stage 0→1→2, no false escalation, block hold, reset/recovery after expiry. |
| Ryu controller wiring (`dos_defense_v2.py`) | Done (source) | Stage 1 forwards only to the victim; controller-owned cookies and periodic OpenFlow flow statistics drive Stage 2 without per-packet mirroring. Meter statistics are telemetry only. Needs live OVS validation. |
| Two-AP topology (`sdn_vanet_2ap.py`) | Done (source) | Removed the asymmetric manual `add-port ap1 ap1-wlan1`; controller endpoint configurable. Needs testbed. |
| Connectivity / packet-path diagnosis (`connectivity_test.py`) | Done (source) | Read-only structured diagnosis of bridge membership, controller state, flows, ARP, ping path. Needs testbed. |
| Paillier crypto (`paillier_crypto.py`) | Done (tested here) | sympy dependency removed (stdlib Miller-Rabin); encode/decode, scalar add, aggregate added; input validation. |
| Privacy-preserving aggregation (`trust_aggregation.py`) | Done (tested here) | Observer/Aggregator/Decryptor roles; aggregator never decrypts; threshold applied post-decryption; bounds + overflow guard. |
| Encrypted DoS-evidence aggregation | Done (tested here) | Implemented as a documented, separately-testable pipeline (`run_privacy_preserving_aggregation`); NOT integrated into the controller fast path (documented). |
| Urban + highway scenarios (`scenarios/`) | Scaffolded | Valid SUMO node/edge/route/sumocfg + build script; `.net.xml` must be built with netconvert; traces need SUMO. |
| Experiment matrix (`EXPERIMENTS.md`) | Scaffolded | Exact commands for all 10 rows; crypto rows executed here, network rows require the testbed. |
| Benchmarks (`results/`) | Done (tested here) | Real measured crypto micro-benchmarks; written to `results/`, not over committed evidence. |
| Automated tests (`tests/`, `run_tests.sh`) | Done (tested here) | 65 unittest cases + 5 original check scripts, all passing. |

## What is explicitly NOT claimed

* No live wireless association, handover, meter enforcement, Stage 2 recovery,
  or end-to-end ping/throughput result is claimed from the preparation
  environment.
* The committed `final_evidence/final_meter_stats.txt` still shows
  `flow_count: 0`; it is historical and does not demonstrate Stage 1
  enforcement. A fresh live run is required.
* Paillier here is a didactic proof of concept with small keys; it is not
  production-grade and is not wired into the controller's packet path.

See `PENDING_WORK_AND_VALIDATION.md` for the required live validation steps.
