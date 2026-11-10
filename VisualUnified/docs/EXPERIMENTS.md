# Reproducible VisualUnified simulation experiments

Run from the existing repository, with Python 3.10 or newer. No VM, sockets,
SUMO, plotting packages or dashboard interaction is required:

```powershell
cd C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified
py -3 run_experiments.py --output experiments/study-v1-repeat
```

The completed `experiments/study-v1` directory is preserved. The output
directory must not exist; choose another unused name if `study-v1-repeat`
already exists. The
runner never loads or saves `controller_settings.json`. The existing
`run_comparison.py` CLI and dashboard remain compatible; their historical CSV
is not replaced. All results are **SIMULATION_ONLY**, never OpenFlow evidence.

The completed default study is preserved in
[experiments/study-v1/REPORT.md](../experiments/study-v1/REPORT.md), with
[trial metrics](../experiments/study-v1/metrics.csv),
[95% interval summaries](../experiments/study-v1/summary.csv),
[packet counts](../experiments/study-v1/traffic_counts.csv), and nine SVG figures.
For example, [combined malicious delivery](../experiments/study-v1/combined__malicious_delivery_pct.svg)
compares all six profiles without mixing benign traffic from V07 into attack delivery.

In those five-seed combined trials, mean malicious delivery was 76.04% with No
Defense, 12.72% with M2 only, 10.86% with M3 only, and 6.54% with Unified Dynamic.
M1 only and Unified Static delivered 0.99% because their known-source rule
blocked all flood packets but allowed the false safety copies. No Defense's
23.96% malicious loss was entirely non-policy loss, showing why total suppression
must not be presented as defense-attributed suppression. In the flood-only
control, M3 matched No Defense: valid safety reports did not trigger generic
flood detection. The enabled detectors had no observed benign-source false
alarms or benign policy drops in this workload, which does not establish a
general zero false-positive rate.

Mean M2 recovery was 20.5 simulated seconds after attack end (the remaining
portion of its 30-second block). For M3-enabled combined runs, meter removal
took 104.9 seconds and trust >=0.80 restoration took 130.4 seconds. These are
different policy recovery definitions, not measured throughput recovery. The
full trial values, confidence intervals, observation counts and caveats are
preserved alongside the report.

## Design

The default study executes 90 actual simulator runs: six policy profiles ×
three scenarios × five independent radio-loss seeds (14–18). Profiles are
No Defense, M1 only, M2 only, M3 only, Unified Dynamic (M1 enabled with no active
static rule), and Unified Static (M1+M2+M3 with the same active M1 rule as M1
only). The extra unified profile exposes dynamic interactions otherwise hidden
by the static DROP. No original controller or policy helper is changed.

Every trial uses a fresh `SimEngine`, the same defaults, attacker V07, victim
V02, built-in routes and speeds, 0.1-second steps, 10 seconds normal baseline,
20 seconds attack, and 150 seconds recovery with attacks disabled. The longer
recovery window permits gradual M3 trust restoration; it does not force it.
Scenarios are normal (no-attack control), flood, and combined flood/false safety.
All profiles within each scenario/seed have identical scheduled traffic and
mobility. Hashes check every generated endpoint packet's time, identity, size,
and ground truth plus every 0.1-second position/RSU association. A mismatch
fails the study. Seed variation affects modeled loss, not the fixed mobility
population. The seed is reset for every matched profile.

- UDP flood: configured 320 packet/s, 1024 bytes, attack window only. Actual
  generated counts are recorded, including the engine's fractional scheduler
  behavior; the configured rate is never substituted for packet counts.
- Safety: 2 schedule opportunities/s/vehicle, 220 bytes/copy, to an associated
  RSU and nearest peer in range. Combined changes V07's reported speed to
  280 km/h (converted to m/s) during attack. Both injected false copies are
  labeled malicious; only successful RSU deliveries reach M3 consistency checks.
- Other traffic: telemetry opportunities at 1.3/s/vehicle (420 bytes) when
  associated; approximately 1 Hz RSU beacons (100 bytes). Association and peer
  availability determine which endpoint copies are instantiated.
- Static rule: V07 / UDP_FLOOD / any RSU / priority 900 / DROP. It is installed
  before baseline and remains installed. This favorable known-source,
  attack-class rule is a simulation policy experiment; it does not estimate
  discovery accuracy or collateral from the original controller's all-UDP block.
- Default M2/M3 thresholds, dwell, rate budgets, reputation scoring and recovery
  are unchanged. SAFETY remains exempt from M2/M3 metering in the unified model.

Phases own scheduled steps: baseline `(0,B]`, attack `(B,B+A]`, recovery
`(B+A,end]`. Phase labels are explicit in raw evidence, so the last baseline
packet and the first attack packet cannot share a mislabeled measurement.
Timing is quantized to the existing 0.1-second simulation step.

## Measurements and accounting

`EvidenceEngine` is an observation subclass. It calls the existing engine's
methods and records their outcomes; a parity test checks unchanged behavior.
Complete packet ledgers replace sampled visual dots or bounded event deques.

| Measure | Definition |
|---|---|
| Generated | Instantiated endpoint `_send` attempts, including attempts subsequently dropped. Not all high-level message schedule opportunities. |
| Transmitted | Null with explanation: no independent MAC/radio transmission stage exists in the model. |
| Received | Successful logical endpoint delivery from the engine. Not a real receiver counter. |
| Dropped | Generated minus received; reasons separate policy, no route, radio loss and congestion. |
| Rate-limited | Actual `RATE_LIMIT` packet outcomes, a subset of dropped. A meter rate or flow match does not increment this metric. |
| Benign PDR | Benign received/generated in the exact phase. Includes valid traffic from the attacker vehicle. Empty denominators are null. |
| Malicious delivery/suppression | Received/generated and dropped/generated for injected flood/false-safety packets. Separate class metrics and safety controller-copy delivery are also recorded. |
| Policy-attributed suppression | Malicious packets dropped with M1_STATIC_DROP, M2_TEMP_BLOCK or RATE_LIMIT reasons / malicious generated. Does not count radio/no-route/congestion loss as defense success. |
| M2 detection delay | First actual attacker Stage 1 event minus attack start. Null when disabled, masked by M1, or not observed. |
| M3 detection delay | First injected false report received by the controller and failing consistency checks minus attack start. Not first packet enforcement. |
| M1 detection delay | Null: a preconfigured rule performs no dynamic detection. Its first observed malicious drop is reported separately. |
| Policy duration | Attacker M2 METER/BLOCK and M3 restrictive-band durations integrated independently by phase. Not equivalent to outage or packet-drop duration. |
| Recovery | Time after attack end until a stable policy-normal tail of at least 1 s. M2 NORMAL, M3 meter removal, and M3 trust >=0.80 are distinct; unresolved cases are right-censored nulls. |
| False-positive measures | Fraction of eligible benign-intent vehicle sources with M2 alerts or failed M3 checks; separately, fraction with restrictive states. These are workload-conditioned source fractions, not real-world packet classifier specificity. |
| Collateral packet loss | Actual policy drops of benign packets / benign generated, distinct from source alerts or policy matches. |
| Network/throughput recovery latency | Null where no modeled delay or stationary capacity restoration criterion exists. Healthy legitimate PDR alone never implies zero recovery time. |

Benign-source denominators use all 12 vehicles in baseline and the normal
control; flood/combined attack and recovery exclude V07 (11 vehicles). Recovery
does not relabel carried-over restrictions of the prior attacker false alarms.
Incidental physical inconsistencies of the scripted normal mobility remain
benign-intent workload errors and are exposed by the normal control. Detector
disabled means null, not a fabricated zero false-positive rate.

If several budgets are exhausted, meter-drop attribution follows the first
exhausted budget recorded by the engine. This is accounting attribution rather
than proof that only that method caused a drop. M1 and M2 precedence can hide
traffic from dynamic detection. Safety delivery and consistency rejection are
different events: a rejected false report has already reached the controller.

The existing dashboard's `sent` means attempted/generated, its `legitimate_*`
fields mean non-UDP_FLOOD (including false safety), and per-attacker counters
include all that vehicle's traffic. Its legitimate PDR is rolling over 10 seconds.
The new study uses exact phase counts and malicious payload labels, audits the
classification discrepancy, and preserves the existing API/dashboard semantics.

## Artifacts and statistics

- `manifest.json`: exact settings/specification, Python/platform and source SHA256.
- Per run: `packets.csv.gz` (every endpoint packet), `states.csv.gz` (one-second
  samples), `result.json` (metrics, counter audits, complete controller events,
  safety decisions, policy transitions and boundary states).
- `traffic_counts.csv`: separate ground-truth/phase counters; transmitted is blank/null.
- `metrics.csv`: per-trial metric values and missing-value explanations.
- `summary.csv`: mean, two-sided 95% Student-t interval, n and missing count.
- `paired_differences.csv`: profile-minus-No-Defense attack metrics in percentage
  points, paired by seed, with trial-level intervals.
- Nine standalone SVG comparison graphs and `REPORT.md` with actual results.
  Graphs use a small standard-library renderer because plotting packages are
  absent; intervals are not truncated to 0–100%.
- `equivalence.json`, `completion.json`, `artifact_sha256.json`: matching,
  completion and evidence-integrity checks. A failed run retains evidence and
  creates `failure.json` instead of silently producing a successful summary.

The existing `benchmark.core.confidence_interval_95` helper is reused for 2–31
independent seeded trials (one trial gives no CI). Packets are not treated as
independent experimental repetitions. Timing summaries exclude censored/null
trials and expose the observed n. Intervals apply to this fixed simulated
workload; no significance or real-world generalization claim is made.

Independently recount saved packet evidence and verify all checksums without
running new experiments:

```powershell
py -3 validate_experiments.py experiments/study-v1
```

This read-only validator checks source and artifact hashes, contiguous packet
identities, time/phase boundaries, traffic/reason counters, PDR and suppression,
first observed policy-drop timing, the full matched matrix, summaries, and SVG
XML. Changing source code after a run intentionally causes its source-hash check
to fail; the original evidence is retained for inspection rather than relabeled.

Phase 1 now defaults the dashboard to `lane_v2`, while both comparison runners
explicitly retain `legacy` mobility. After these source changes, use
`validate_experiments.py experiments/study-v1 --allow-source-drift` for a saved
artifact/packet audit. This explicit option still checks every artifact hash and
ledger metric, reports `source_identity: DIFFERENT`, and makes no current-code
replay claim. Two seed-14 legacy replays matched archived counts and both traffic
and mobility hashes; the full 90 trials were not rerun. The new lane health runs
and bounded native SUMO checks are described in [Phase 1 progress](MARSNET_V2_PROGRESS.md),
not folded into the published study results.

To run fewer trials or different windows, use explicit options and a fresh
output directory. For example:

```powershell
py -3 run_experiments.py --seeds 14 15 --scenarios combined --baseline-seconds 10 --attack-seconds 20 --recovery-seconds 150 --output experiments/two-seed-check
py -3 -m unittest discover -s tests -p test_experiments.py -v
```

Shorter recovery can legitimately produce censored results. The study does not
model OpenFlow switch behavior, physical radio contention, propagation delays,
real UDP receiver traffic, hardware performance, SUMO validation, or adversarial
adaptation. Preserve all existing live benchmark evidence separately.
