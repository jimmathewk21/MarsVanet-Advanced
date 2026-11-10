# Methodology fidelity in VisualUnified

The simulation uses the original policy helpers where they are independent of
Ryu. This establishes policy agreement for equivalent inputs and configuration;
it does not establish OpenFlow, radio, packet-level enforcement or SUMO parity.
All changes are inside VisualUnified. Original methodology files remain intact.

## Source comparison and corrections

| Concern | Original source / behavior | Correction or intentional VisualUnified behavior |
|---|---|---|
| M1 static filtering | `Methodology1/scripts/dos_defense_static.py::switch_features_handler` drops IPv4 UDP from `10.0.0.3` at priority 100 on every switch. | Intentional extension: configurable source/traffic/RSU priority rules with DROP, METER and ALLOW. Default example is disabled, so a selected attacker is not silently blocked. M1 DROP precedes M2 observation; ALLOW remains subject to dynamic defenses. |
| M2 input scope | `dos_defense_v2.py::packet_in_handler` monitors any configured source's UDP toward the configured victim on AP2's configured ingress. It does not know an attack label. | Corrected: modeled TELEMETRY UDP as well as UDP_FLOOD toward the selected victim enter detection, independent of attacker identity. Non-victim traffic does not. `m2_monitored_rsu` defaults to `*`; select `RSU-2` for a closer AP2-only demonstration. SAFETY is a deliberate combined-pipeline exemption required by M3 interception. |
| M2 normal rate | `mobility_detector.py::PacketRateTracker` uses a 5-second window and the observed span with a one-second minimum divisor; `decide` uses `rate >= threshold`. | Actual helper reused. Previous one-second counts and strict-greater comparison removed. |
| Mobility threshold | `mobility_detector.py::select_threshold` uses base 120; dense count >=5 or speed <5 m/s selects 90; count <=2 and speed >=10 m/s selects 150; handover rate >=2/min raises the floor to 150. | Actual helper reused. Previous density multiplier, which raised rather than lowered dense-traffic thresholds, removed. UI km/h is converted to m/s. |
| Mobility inputs | `dos_defense_v2.py::current_threshold` consumes fresh nearest CSV samples and separately reads a handover CSV over 60 seconds. | Intentional adaptation: current associated-RSU vehicle count and mean speed provide a fresh modeled sample; no association means base fallback. Completed simulated handovers supply the 60-second churn window. The original sample-age loader is not exercised because no CSV sample is read. |
| M2 Stage 1 | Original `install_meter` uses 500 kbps, 15-second hard timeout; `decide` requires 10-second dwell before persistent-rate escalation. | Defaults restored from the former 4-second visual dwell. Decisions reuse `SourceState` and `decide`. Below-threshold samples retain Stage 1 until flow expiry; expiry clears only M2 state, as `_mark_meter_flow_missing` does. |
| Stage 1 evidence | `_process_flow_stat` derives rate from monotonic flow-counter deltas; initial samples establish a baseline. Switch pre-meter semantics require live OVS validation. | Intentional simulation: exact qualifying ingress attempts increment a synthetic counter before all applicable meters. One-second simulated polls establish a baseline then calculate deltas, so M3 drops cannot conceal sustained input. No real switch counters, requests or acknowledgements are produced. |
| M2 Stage 2 | `install_temporary_block` installs a 30-second drop without refreshing it. Blocked packets do not produce detection PacketIn events. | Default restored from 12 seconds; deadline no longer extends on blocked input. Controller decisions ignore blocked packets and use the original reset decision at expiry before new traffic is evaluated. |
| M3 parsing / identity | `safety_messages.py::parse_safety_message` validates exact JSON fields, types, finite numbers, bounds, duplicate keys and size; controller binds `vehicle_id` to source IP. | Actual parser reused. Canonical reports have `vehicle_id,timestamp,x,y,speed`, with speed in m/s. The modeled sender ID must exist and equal the report ID. Malformed or identity-mismatched input is rejected without reputation change. V01–V12 model identities replace three configured IP identities; there is no actual IP packet or authentication. |
| M3 consistency | `message_consistency.py::MessageConsistencyChecker`: max speed 55 m/s, acceleration 8 m/s², tolerance 10 m; displacement bound includes `0.5*a*dt²`. Only accepted samples advance history. | Actual checker reused. Replaced visual speed limit 140 km/h, acceleration 18 m/s² and alternate displacement formula. UI default speed limit is 198 km/h =55 m/s. Invalid history does not advance. Legacy internal `speed_kmh` helper input converts to canonical units. |
| M3 reputation | `reputation_engine.py::ReputationEngine`: penalty factor .20 times severity; speed/timestamp .8, displacement 1, acceleration .7; +.02 after each five valid messages. Exact .2/.4/.6/.8 bands. | Actual scorer and band decisions reused with configurable parameters. Former uniform .16 penalty replaced: speed remains .16, displacement becomes .20, acceleration .14. Five severe displacement violations reach zero; 200 valid reports recover to .80. Restriction disappears at MONITOR (.60), while NORMAL starts at .80. |
| Handover | M3 controller retains identity history and reconciles reputation on connected switches; original M2 detector state is keyed by datapath/source. | Intentional global simulation: vehicle identity owns M2 and M3 state across RSU handovers. No actual flow replication occurs. Completed direct and <=5-second reconnect handovers count once and affect threshold churn. |
| Combined precedence | The original M1/M2/M3 apps are separate experiments and do not define a shared precedence. M3 intercepts UDP/5005 above its meter flow. | Intentional composition: selected M1 DROP > scoped M2 temporary DROP > all applicable budgets > forwarding. M1 may explicitly restrict SAFETY; M2/M3 dynamic data limits exempt it. Recovery or disabling one defense never deletes another defense's rules, budgets or history. |

## Defaults, overrides and compatibility

The existing configuration keys and HTTP routes remain available. In particular,
`stage2_after_sec` now defaults to 10 and `block_duration_sec` to 30. Existing
saved settings are preserved as overrides. To use original defaults, run with
a new/default profile or explicitly set the parameters; there is no automatic
profile deletion or migration of a user's chosen values.

Additional `/api/config` keys are:

| Key | Default | Meaning |
|---|---:|---|
| `m2_window_sec` | 5 | Original normal-stage packet tracker window |
| `m2_meter_lifetime_sec` | 15 | Simulated Stage 1 flow hard timeout; must exceed dwell |
| `m2_reset_sec` | 30 | Original detector reset parameter |
| `dense_pps` / `sparse_pps` | 90 /150 | Absolute mobility-selected thresholds; independently configurable from base |
| `handover_floor_pps` | 150 | Floor under original high-churn condition |
| `m2_monitored_rsu` | `*` | All modeled RSU ingresses, or an explicit RSU ID |
| `max_acceleration_mps2` | 8 | Original motion checker acceleration bound |
| `position_tolerance_m` | 10 | Original motion checker displacement tolerance |

All simulation times use simulated seconds. A block lasts 30 simulated seconds
at default settings regardless of wall-clock speed. M2 polls occur on simulation
steps, with approximately 0.1-second quantization; this is not Ryu event timing.
The original pure modules are loaded under private module names so importing
VisualUnified does not launch Ryu, read historical traces into the simulation,
or reuse host `DOS_*` environment overrides.

## Enforcement and evidence limitations

Budgets remain simulated token buckets, with an initial burst and per-policy
scope. M3 shares a source data budget; M2 scopes its budget to victim UDP; M1
scopes its budget to the matching static rule. All applicable budgets must
admit a packet. Their minimum rate is the reported steady-rate cap, not proof
of a single OpenFlow meter or exact OVS burst behavior. Runtime policy rows
refer to UDP toward `effective_udp_destination`, which is exported explicitly.
The vehicle `pps` field is the last M2 observed/sampled victim-UDP rate, not all
vehicle traffic or an independently measured switch throughput. While blocked,
there is no fresh M2 ingress observation; its last rate is retained until reset.

The simulator continues to forward peer safety copies as an illustrative VANET
broadcast, while controller state updates only once for a delivered RSU copy.
The original M3 controller consumes telemetry at the first switch instead.
Simulated radio/backhaul loss can prevent a report from being observed. With
M3 disabled, reports do not update accepted history or reputation.

No new traffic transport or real OpenFlow pipeline is introduced. Mininet,
Ryu, OVS counters, meter flags/IDs/barriers, timing races and shared-switch
reconnect cleanup are outside this engine's validation. SUMO remains optional
mobility input. Phase 1 added coordinate/timing/lifecycle regressions and passed
two bounded native SUMO 1.27.1 headless checks; long sessions and GUI behavior
remain unverified. The lane_v2 dashboard now supplies gradual mobility inputs
to the same original helpers, while archived-study runners retain legacy motion.
See [Phase 1 progress](MARSNET_V2_PROGRESS.md) for the exact validation scope.
These limitations prevent treating simulation output as a reproduction of
historical real-network results, even when the pure policy decisions agree.

## Automated validation

`tests/test_methodology_fidelity.py` compares default configuration, mobility
selection, observed-span packet rates, motion severities and the entire
five-severe-plus-200-valid reputation trace against the original helpers. It
also checks unlabelled victim UDP, scope exemptions, strict M1 precedence,
pre-meter Stage 2 evidence, fixed block expiry, Stage 1 flow expiry, recovery
isolation, handover state, concurrent M1/M2/M3 and other-vehicle preservation.
The application suite also exercises HTTP APIs, frontend assets, launcher
behavior, rule editing, persistence, simulation pacing and optional SUMO failure.

```powershell
cd C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified
python -m unittest discover -s tests -v
```

These are source-policy and simulated-system checks, not live SDN validation.
