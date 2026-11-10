# MarsVanet

### SDN-Based VANET Security: Static Filtering, Mobility-Aware Rate Defense, and Trust-Based Progressive Mitigation

**Computer Networks project | Team 14 | Vellore Institute of Technology, Vellore**

**Authors:** Jim Mathew K and Vignesh Ekambaram

MarsVanet is an experimental **software-defined vehicular ad hoc network (SDN-VANET)** security project. It investigates how different OpenFlow policies affect suspicious UDP traffic in a small Mininet-WiFi network, while measuring whether legitimate traffic remains deliverable.

The repository contains **three separately implemented defense methodologies**, a benchmark harness, and a Windows-first [VisualUnified application](VisualUnified/README.md). The original methodologies remain separate experiments; VisualUnified combines their concepts in an explicitly labeled software simulation.

To run the visual application in PowerShell (Python 3.10 or newer, standard library only):

```powershell
cd C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet
python VisualUnified\run.py
```

Open `http://127.0.0.1:8765`. The visual application simulates network forwarding and security decisions; its exports are separate from the historical Mininet/OVS measurements below. See [VisualUnified's integration review](VisualUnified/docs/REVIEW_AND_VALIDATION.md) for fixes, validation, and limitations.

> **Research scope:** Controlled emulation with three stations, two access points, a software switch, and a Ryu controller. Results are specific to the stated workloads and do not establish production readiness.

## 1. Project objectives

- Demonstrate the effect of UDP overload on communication latency and the ability of OpenFlow to suppress a known source.
- Explore packet-rate detection with thresholds conditioned on mobility context and staged mitigation.
- Evaluate safety-message plausibility, per-vehicle reputation, reversible OpenFlow metering, and recovery.
- Record reproducible, receiver-observed traffic measurements and controller enforcement evidence.

## 2. Technologies

| Component | Role |
|---|---|
| **Mininet-WiFi** | Emulated wireless vehicles and access points |
| **Ryu / OpenFlow 1.3** | Programmable SDN control |
| **Open vSwitch (OVS)** | Forwarding, flow rules, and meter enforcement |
| **Python 3** | Controllers, message generation, tests, benchmark tooling |
| **SUMO-derived mobility features** | Context inputs for Methodology 2 (not live-coupled in the reported common benchmark) |
| **Paillier cryptosystem** | Separate experimental encrypted aggregation prototype |

### Example benchmark topology

```text
                    Ryu SDN controller
                     127.0.0.1:6653
                            |
                        OpenFlow
                            |
                  +-------------------+
                  |     OVS s1        |
                  +-------------------+
                    /             \
                 ap1               ap2
                /   \                \
         sta1 (.1)  sta2 (.2)       sta3 (.3)
         legitimate  receiver        attacker

         10.0.0.0/24 emulated network
```

The precise station roles and association states can vary between historical manual tests and the newer benchmark; the diagram shows the **newer benchmark** configuration.

## 3. Defense methodologies

### Methodology 1 — Static OpenFlow source filtering

A known attacker source is matched by an OpenFlow UDP rule and its packets are dropped. This provides an auditable baseline, but assumes accurate source attribution and does not provide graded recovery.

Historical team evidence recorded a rise in mean ICMP latency from **0.792 ms** to **68.305 ms** during UDP overload (20/20 ICMP replies in both conditions). A static drop rule recorded **18,036 filtered packets** (**27,270,432 bytes**). These historical observations are **separate from** the newer common benchmark below.

### Methodology 2 — Mobility-aware detection and staged response

A packet-rate detector uses a default **120 packets/s** threshold, with optional SUMO-derived context such as vehicle density, speed, and handover behavior. The design can progress from **NORMAL** to a **500 kbps meter** and then a temporary **BLOCK** state after sustained elevated rate.

Historical live Stage-1 evidence showed a matching flow reaching **meter 103**, with **2,844 matched packets** and **6,844 cumulative meter-band drops**. A newer isolated volumetric benchmark also completed successfully. However, the benchmark did **not** exercise synchronized SUMO mobility, and historical Stage-2 block/handover behavior is **not independently established by the cited evidence**.

The Methodology 2 Paillier scripts form a **separate, small-key proof of concept** for encrypted score aggregation; they are **not connected to live packet forwarding**.

### Methodology 3 — Safety-message consistency and reputation

This method inspects generated safety messages (JSON over **UDP/5005**) with fields such as `vehicle_id`, `timestamp`, `x`, `y`, and `speed`. Plausibility checks include speed, acceleration, and displacement consistency. A violation decreases reputation; sustained valid behavior allows gradual recovery.

**Important:** This is **semantic misbehavior detection**, not a general-purpose volumetric DoS detector. A sender transmitting plausible messages at a high rate may evade this particular trigger.

**Reputation policy**

| Reputation | State | Enforcement |
|---|---|---|
| `[0.00, 0.20)` | SEVERE_THROTTLE | 100 kbps meter |
| `[0.20, 0.40)` | HEAVY_THROTTLE | 200 kbps meter |
| `[0.40, 0.60)` | LIGHT_THROTTLE | 500 kbps meter |
| `[0.60, 0.80)` | MONITOR | Restrictive meter removed |
| `[0.80, 1.00]` | NORMAL | Normal forwarding |

Reputation starts at `1.0`. An invalid observation incurs a penalty of up to `0.20` (scaled by violation severity). Every **five consecutive valid messages** adds `0.02`, up to `1.0`. From `0.0`, **200 valid messages** can restore the score to `0.8` if no further violations occur.

The live tests confirmed controller decision sequences and OpenFlow meter modification/removal acknowledgements. Receiver-observed throughput was measured separately from controller requests.

## 4. Experimental results

### 4.1 Common *volumetric UDP* workload

These three configurations were tested using the same benchmark topology, traffic-generation approach, and metric definitions. Each has **one completed live trial**; do not treat the results as confidence intervals or broad performance guarantees.

| Configuration | Attacker throughput (Mbps) | Legitimate throughput (Mbps) | Legitimate PDR | Legitimate latency (ms) |
|---|---:|---:|---:|---:|
| No Defense | **1.0237** | 0.04096 | 100% | 1.1500 |
| Methodology 1 | **0.0000** | 0.04096 | 100% | 1.2180 |
| Methodology 2 (isolated) | **0.1650** | 0.04096 | 100% | 0.9978 |

In this workload, Methodology 2's measured attacker throughput was approximately **83.9% lower** than the no-defense case. Methodology 1's static drop suppressed the tested attacker flow entirely.

### 4.2 Methodology 3 *safety-consistency* workload

Two separately seeded live trials used **10-second steady severe-throttle** and **10-second post-recovery normal** observation windows. The severe phase began only after enforcement acknowledgement; the normal phase began after meter removal was acknowledged.

| Metric | Trial 1 (seed 2026) | Trial 2 (seed 2027) |
|---|---:|---:|
| Severe-throttle attacker throughput | **0.094208 Mbps** | **0.0923648 Mbps** |
| Severe-throttle attacker packet loss | **90.798%** | **90.980%** |
| Post-recovery attacker throughput | **1.024 Mbps** | **1.024 Mbps** |
| Post-recovery packet loss | **0%** | **0%** |
| Legitimate throughput | 0.04096 Mbps | 0.04096 Mbps |
| Legitimate PDR | 100% | 100% |
| Legitimate latency | 1.0447 ms | 0.8354 ms |
| Expected vs observed decision trace | **355/355 matched** | **355/355 matched** |

**Across the two trials:** mean severe-throttle throughput was **0.0932864 Mbps** (~93.3 kbps), and mean severe-throttle packet loss was **90.889%**. Both runs restored measured post-recovery traffic to 1.024 Mbps with zero observed packet loss. The sequence included five invalid safety messages followed by 200 valid recovery messages.

**Do not directly rank Methodology 3 against the first three rows:** it uses a different workload and phase-specific measurement windows.

A separate earlier manual iperf check observed approximately **116 kbps UDP payload** under a configured **100 kbps meter**. The newer gated steady-state trials measured ~92–94 kbps. The earlier overshoot remains a measurement discrepancy to investigate (e.g., meter bursts or interval alignment); it should not be explained away by assuming L2 accounting increases payload throughput.

### 4.3 Automated validation

The enhanced benchmark suite passed **41 tests**, and the Methodology 3 suite passed **62 tests** (**103 passing tests** across these two suites). Earlier Methodology 2 documentation separately recorded **45 unit tests**; these counts refer to different test collections and should not be summed as if all were unique current tests.

## 5. Repository layout

```text
MarsVanet/
├── Methodology1/       # Historical baseline and static filtering
├── Methodology2/       # Mobility-aware detector and Paillier prototype
├── Methodology3/       # Safety consistency, reputation, OpenFlow mitigation
└── benchmark/          # Common harness, live workloads, tests, artifacts
```

See the methodology-specific documentation and `benchmark/README.md` for component-specific execution instructions. Not all scripts use the same runtime or dependency environment.

## 6. Reproducing the benchmark

**Environment:** A Linux/Ubuntu VM with a working Mininet-WiFi, Open vSwitch, Ryu installation, and the project’s Python dependencies. The tested live setup used `/usr/bin/python3` for Mininet-WiFi and a separate Ryu virtual environment. Live runs require `sudo` and a functioning SDN emulation environment; they will not run as ordinary Windows Python scripts.

From the **Ubuntu benchmark working directory**:

```bash
cd ~/sdn-vanet/MarsVanet-LiveTest

# Review all supported options before running
python3 benchmark/run_benchmark.py --help

# Example: reproduce one Methodology 3 live trial
sudo env \
  "PATH=$HOME/sdn-vanet/ryu-venv/bin:$PATH" \
  /usr/bin/python3 benchmark/run_benchmark.py \
  --live \
  --workload safety_consistency \
  --configuration methodology3 \
  --root-seed 2026 \
  --repetitions 1 \
  --artifacts benchmark/artifacts-m3-new
```

**Live runner constraint:** Use `--repetitions 1` for each live invocation. Run separate commands with distinct seeds and artifact directories for additional repetitions. Running a live trial will create network namespaces, controller processes, and output files; do so only in an isolated test VM.

For automated tests, use the instructions in `benchmark/README.md` and `Methodology3/README.md`, since test discovery and environment requirements may vary.

### Evidence artifact directories

| Directory (under `benchmark/`) | Experiment |
|---|---|
| `artifacts-retry2/` | Valid No Defense volumetric trial |
| `artifacts-m1/` | Methodology 1 volumetric trial |
| `artifacts-m2-static/` | Isolated Methodology 2 volumetric trial |
| `artifacts-m3-steady1/` | Methodology 3, seed 2026 |
| `artifacts-m3-steady-repeat2/` | Methodology 3, seed 2027 |

Each completed live trial produced metrics and supporting logs/CSVs. **These paths refer to the Ubuntu experiment workspace; they are not guaranteed to be present in a GitHub checkout unless deliberately copied and committed.** Avoid committing large raw logs or private VM/environment details without review.

## 7. Limitations and research integrity

- **Scale:** Three emulated vehicles; no large-scale fleet or production wireless deployment.
- **Workload equivalence:** Only No Defense, Methodology 1, and Methodology 2 share the volumetric benchmark. Methodology 3 uses a distinct safety-consistency workload.
- **Statistical strength:** One completed volumetric trial per configuration and two Methodology 3 live trials; no defensible confidence intervals or generalizable significance tests.
- **Unmeasured outcomes:** Independent detection delay, mitigation delay, false-positive rate, and legitimate-flow recovery time were not established. The scheduled recovery phase duration is **not** a measured recovery latency.
- **Identity:** Source-IP/vehicle-ID attribution can be spoofed without cryptographic authentication.
- **Controller exposure:** Avoid mirroring all metered attack traffic to the Ryu controller; use data-plane forwarding with targeted telemetry and counters.
- **Mobility:** The reported isolated Methodology 2 benchmark did not verify live SUMO-to-wireless synchronization; handover robustness remains unproven.
- **Paillier:** The historical small-key prototype is not a production-secure deployment or a live controller integration.

## 8. Research report

**Title:** *Mobility-Aware Trust and Progressive OpenFlow Mitigation for Denial-of-Service Attacks in Vehicular Networks*

The revised manuscript contains the background, experimental design, results, discussion, limitations, and references. Add the reviewed PDF to the repository only after checking that it contains the intended final title and author details. If you commit it, link its actual repository-relative path here rather than an unverified filename.

## 9. Authors and repository

- **Jim Mathew K** 
- **Vignesh Ekambaram** 
- **Institution:** School of Computer Science and Engineering, Vellore Institute of Technology, Vellore, India
- **Repository:** https://github.com/jimmathewk21/MarsVanet

This is an academic research and emulation project. Use it only in networks and virtual environments where you are authorized to run traffic-generation and security experiments.
