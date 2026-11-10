# Methodology 2 — Pending Work and Validation Status

This revision completed the source-level and runtime-independent work and made
the detection/mitigation logic configurable and unit-tested. It does **not**
claim a complete live Mininet-WiFi / Ryu / SUMO validation, because that
privileged wireless runtime was not available in the preparation environment.

## Done and verified without the testbed

* Dependency-free Paillier crypto, privacy-preserving aggregation and encrypted
  DoS-evidence pipeline, with unit tests and real micro-benchmarks.
* Mobility feature loading/validation, mobility-aware threshold selection with a
  documented base-threshold fallback and a stale-sample age guard.
* Sliding-window rate estimation with a corrected early-window divisor.
* Progressive-mitigation decision state machine (Stage 0→1→2, hold, and
  reset/recovery) with unit tests.
* 65 unittest cases + the 5 original check scripts all pass:
  `bash Methodology2/run_tests.sh`.

## Source-level fixes that STILL require live confirmation

1. **AP2 OpenFlow port assumptions.** Stage 1/2 flows match `in_port=1` and
   output `port=2` on AP2 by default. Confirm against
   `ovs-ofctl -O OpenFlow13 show ap2` and set `DOS_AP2_IN_PORT` /
   `DOS_AP2_OUT_PORT` before interpreting mitigation behaviour.
2. **Stage 1 meter enforcement and counter semantics.** The committed
   `final_evidence/final_meter_stats.txt` reports `flow_count: 0` and zero meter
   counters. Stage 1 now forwards only to the victim; the controller polls the
   cookie-scoped priority-60 flow approximately once per second and uses packet
   counter deltas for escalation. OpenFlow defines flow counters as counters for
   matched entries before instructions, but whether the target OVS datapath
   exposes those counters as the desired raw ingress signal must be confirmed
   live. Meter and band counters are validation telemetry only and are never
   used as per-source evidence. A fresh run must show the matching flow, stable
   counter deltas, and (when supported) per-active-meter statistics; telemetry
   is round-robin and never used as per-source evidence. Confirm usable
   legitimate traffic.
3. **Stage 2 expiry and recovery.** The indefinite 20 s re-block was removed and
   replaced with a self-expiring block plus a detector reset. Confirm with a
   live attack that the drop counters rise during the attack and that traffic
   recovers after the hard timeout.
4. **End-to-end connectivity.** Live testing confirmed one concrete cause:
   ap1's wireless interface was missing from its OVS bridge (ap2's was present).
   The topology now attaches each AP's wlan port idempotently and verifiably via
   `ensure_ap_wireless_port()` (see `CONNECTIVITY_FIX.md`). A second, still-open
   symptom is sta2/sta3 not associating (interfaces down); this is a radio-layer
   issue, addressed with `bring_up_stations()` plus the configurable
   `DOS_PROP_EXP` / `DOS_AP_RANGE` / `DOS_AP_TXPOWER` knobs, and must be
   confirmed in the VM. Resolve both before interpreting mitigation, and do NOT
   mask them with a high-priority bypass forwarding rule.
5. **Mobility clock alignment.** SUMO sample time starts at 0 while the
   controller uses process-elapsed time. The stale-sample guard
   (`DOS_MOBILITY_MAX_AGE`) prevents far-away rows from adjusting the threshold,
   but for faithful experiments start the mobility producer and controller in a
   coordinated way or add an explicit simulation-time offset.
6. **Mobility input is a static trace.** The shipped/produced feature CSV is a
   recorded trace, not evidence that the controller is receiving live mobility
   updates.

7. **OpenFlow statistics compatibility.** The controller uses standard
   OpenFlow 1.3 flow and meter statistics requests, multipart replies,
   controller-owned cookies, and a one-second default poll interval.
   Ryu/OVS versions can differ in optional meter-stat support and counter
   offload semantics. Verify `dump-flows`, `meter-stats`, and observed counter
   deltas on the target OVS version before claiming raw-ingress-rate
   measurements.

## Required live validation before claiming completion

* Verify station association and `sta1 -> sta2` ping before any attack.
* Capture `ovs-ofctl -O OpenFlow13 show ap1`, `show ap2`, and `dump-flows ap2`.
* Run a normal-traffic baseline and record packet loss, latency, throughput.
* Run UDP attack traffic and verify the controller's detection rate/window.
* Confirm the Stage 1 meter has a matching flow with non-zero counters and that
  legitimate traffic remains usable.
* Confirm Stage 2 drop counters increase during a fresh attack and that the
  block expires and traffic recovers afterward.
* Repeat for both urban and highway scenarios, saving configs, commands and
  machine-readable outputs.
* Report Paillier aggregation results separately from the live SDN results.

## Paillier / cryptography limitations

* Additive homomorphism only. The controller does not and cannot compare
  ciphertexts directly; the detection threshold is applied by the authorised
  decryptor *after* decrypting the aggregate.
* Confidentiality is not integrity or authenticity. A compromised observer can
  submit a false but in-range contribution. Observer authentication, replay
  protection and contribution integrity are out of scope for this module and
  remain future work.
* The demonstration keys are small. Re-benchmark with >= 2048-bit keys and a
  reviewed cryptographic library before making any security-performance claim.
* The aggregation module is a separately-testable component with a documented
  interface; it is intentionally NOT integrated into the live controller's fast
  path. Integration is future work.
