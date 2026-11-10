# Methodology 2 — reproducible experiment guide

This guide gives the exact, reproducible steps for the MED-2 experiments. It is
split into **(A) runtime-independent** steps that run anywhere with Python, and
**(B) live SDN/SUMO** steps that require the testbed described in
`../requirements.txt` (Open vSwitch, Mininet-WiFi, Ryu, SUMO/TraCI, root).

> Honesty note. The environment used to prepare this revision has Python only.
> Everything in section A below was executed and its results recorded. Nothing
> in section B was executed here, because the privileged wireless SDN runtime is
> not available. No live packet-delivery, throughput, latency, detection-delay
> or recovery numbers are claimed from this environment. The commands in
> section B are provided so the experiments can be run on the real testbed.

---

## A. Runtime-independent (executed in this revision)

```
# All crypto + detection + mitigation decision-logic unit tests:
bash Methodology2/run_tests.sh

# Cryptographic micro-benchmarks (write real numbers to Methodology2/results/):
python3 Methodology2/scripts/benchmark_paillier.py
python3 Methodology2/scripts/save_paillier_results.py
python3 Methodology2/scripts/benchmark_multi_observer.py
python3 Methodology2/scripts/compare_trust_aggregation.py

# Mobility-aware threshold + progressive-mitigation logic demonstration:
python3 Methodology2/scripts/detector_demo.py
```

These cover experiment-matrix rows 7, 8 and 9 (static-vs-mobility threshold
logic, plaintext-vs-Paillier aggregation, and aggregation overhead vs observer
count) at the logic/crypto level. Rows that need live traffic (1–6, 10) are in
section B.

---

## B. Live SDN + SUMO experiments (require the testbed)

### B.0 One-time build

```
bash Methodology2/scenarios/build_networks.sh      # needs netconvert (SUMO)
```

### B.1 Record mobility and extract features (per scenario)

```
# Urban
python3 Methodology2/collect_mobility.py \
    --net    Methodology2/scenarios/urban/urban.net.xml \
    --routes Methodology2/scenarios/urban/urban.rou.xml \
    --output Methodology2/scenarios/urban/mobility_data.csv
python3 Methodology2/mobility_features.py \
    Methodology2/scenarios/urban/mobility_data.csv \
    Methodology2/scenarios/urban/mobility_features.csv

# Highway (same commands with highway/ paths)
```

### B.2 Start the controller

```
# Point the controller at the scenario's feature file and (optionally) override
# the AP2 OpenFlow assumptions once confirmed with ovs-ofctl (see B.4).
export DOS_MOBILITY_CSV=Methodology2/scenarios/urban/mobility_features.csv
# export DOS_AP2_IN_PORT=1 DOS_AP2_OUT_PORT=2 DOS_DESTINATION_IP=10.0.0.2
ryu-manager Methodology2/scripts/dos_defense_v2.py
```

### B.3 Start the topology (separate terminal, as root)

```
sudo -E python3 Methodology2/scripts/sdn_vanet_2ap.py
# optional: DOS_CONTROLLER_IP / DOS_CONTROLLER_PORT to reach a remote controller
```

### B.4 Confirm connectivity and the packet path BEFORE any attack

This is the step that previously failed ("associated but cannot ping"). Resolve
it before interpreting any mitigation result. Do **not** paper over it with a
high-priority forwarding rule that bypasses the defence logic.

```
sudo python3 Methodology2/scripts/connectivity_test.py --aps ap1 ap2
# then, inside the Mininet-WiFi CLI:
mn-wifi> sta1 ping -c 3 10.0.0.2
sh ovs-ofctl -O OpenFlow13 show ap2        # confirm real ingress/output ports
sh ovs-ofctl -O OpenFlow13 dump-flows ap2
```

If the confirmed AP2 ingress/output ports differ from the defaults (1/2), set
`DOS_AP2_IN_PORT` / `DOS_AP2_OUT_PORT` and restart the controller.

### B.5 Experiment matrix

Run each row and save its logs + measurements under a per-run directory. Use a
fixed-rate UDP generator for repeatability (e.g. a small `iperf3 -u -b <rate>`
or a controlled packet generator). Keep normal and attack rates comparable
across urban and highway.

| # | Condition                         | How |
|---|-----------------------------------|-----|
| 1 | Urban, normal traffic             | legitimate UDP below threshold; record PDR, latency, throughput |
| 2 | Urban, DoS traffic (no defence)   | high-rate UDP from attacker; controller monitoring only |
| 3 | Urban, DoS under progressive mitigation | same attack with the controller enforcing Stage 1/2 |
| 4 | Highway, normal traffic           | as row 1 with highway scenario |
| 5 | Highway, DoS traffic (no defence) | as row 2 with highway scenario |
| 6 | Highway, DoS under mitigation     | as row 3 with highway scenario |
| 7 | Static vs mobility-aware detection | run with a fixed threshold (set dense=sparse=base) vs the adaptive policy |
| 8 | Plaintext vs Paillier aggregation | `compare_trust_aggregation.py` (section A) |
| 9 | Observer count vs overhead        | `benchmark_multi_observer.py` (section A) |
| 10| Recovery after attack stops       | stop the attack; confirm the Stage 2 block expires and traffic recovers |

For static-vs-mobility (row 7) the adaptive policy is disabled by making the
context thresholds equal to the base:

```
export DOS_DENSE_THRESHOLD_PPS=120 DOS_SPARSE_THRESHOLD_PPS=120 \
       DOS_HANDOVER_THRESHOLD_FLOOR_PPS=120
```

### B.6 Measurements to collect (where the runtime supports them)

Detection delay, mitigation delay, packet delivery ratio, packet loss,
throughput, false-positive rate, false-negative rate (where ground-truth labels
exist), recovery time, handover count/rate, the selected detection threshold,
and the Paillier encryption/aggregation/decryption latency.

Record the exact commands, software versions, and raw outputs alongside the
machine-readable results. Keep newly generated results separate from the
committed historical evidence in `final_evidence/` (that is what
`Methodology2/results/` is for).
