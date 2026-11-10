# Integration, validation, and professor demo notes

## Copy into the existing repository

This package is a drop-in sibling folder, **not a replacement for the older Ryu scripts**. On Windows, extract `MarsVanet_VisualUnified_Windows.zip` into your existing MarsVanet project root. Ensure `MarsVanet/VisualUnified/run.py` exists. Do not copy files into `Unified/` or overwrite `Methodology1/2/3`. See [the integration review](REVIEW_AND_VALIDATION.md) for validation and corrected model behavior.

## Verify the Windows setup

1. `cd "C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified"`
2. `py -3 -m unittest discover -s tests -v`
3. `py -3 run.py`
4. Open `http://127.0.0.1:8765` in Edge/Chrome.
5. Confirm 12 moving vehicles, three roadside units, sampled packet pulses, dashboard counters and event stream. Coverage and association overlays are hidden by default; inspect a node or use **Map Display**. Use the Windows launcher when `py` is unavailable.

The Phase 1 dashboard defaults to lane-based mobility; comparison runners retain
the legacy study model. See [Phase 1 progress](MARSNET_V2_PROGRESS.md) for fixed
driving-model assumptions, the bounded native SUMO checks, and pending browser QA.

## First walkthrough — 5-minute story

For a shorter M2 presentation, select V07 and V02 on **Live simulation** and press **Start guided demo**. It resets counters and vehicle positions while keeping saved rules/settings, runs a five-simulated-second normal baseline, then waits for observed Stage 1 and Stage 2 before stopping the flood and waiting for timed recovery. The guide reports a stalled defense instead of advancing without evidence. A matching M1 DROP must be disabled for the M2 portion. Packet dots and handover links are sampled/illustrative; use counters and events for the actual modeled decisions.

**00:00–00:50 — What is a VANET?** Show multiple moving cars. Point to the three roadside units and wireless coverage. Click different vehicles and observe their association, speed, V2V packet paths and handovers. Explain that RSUs are stationary infrastructure and that the SDN control plane sets policies on the traffic flow (simulated in this application).

**00:50–01:30 — Unified controller, not three separate programs.** Open Policy Studio and show all M1/M2/M3 enabled at the same time. Explain static match/action rules, the sliding-window rate detector, and independent reputation tracking. Explain strictest-meter precedence.

**01:30–02:25 — Mobility-aware DoS (M2).** Select attacker V07 and victim V02, start UDP flooding. Read packets/s crossing the adjusted threshold; see Stage 1 500 kbps meter then Stage 2 temporary drop. Show packet drops on map, controller logs and traffic chart. Avoid claiming the number of dropped dots equals the number of dropped packets: visual pulses are sampled.

**02:25–03:20 — False safety data (M3).** Return to normal, then start False safety data. Show reported speed plausibility failures and trust bands NORMAL → MONITOR → LIGHT → HEAVY → SEVERE. Mention the 100 kbps meter is applied by the simulation model, not OVS.

**03:20–04:10 — Both dynamic methods on the same traffic.** Start Combined attack. Open Policy Studio → Effective runtime flow policies and show V07 with M2 and M3 statuses together. Discuss how one packet is subject to both rules and the strictest meter (unless blocked).

**04:10–05:00 — Configure M1 live.** Add static rule `V07 / UDP_FLOOD / DROP / priority 900`, press Save. Observe M1 static drop counter increase, then disable it. Export the JSON report. State which parts are simulations and which historical tests prove real OVS enforcement.

## How to show evidence without overclaiming

- **Simulated data in this package**: model PDR and drops, synthesized traffic, moving positions (built-in or SUMO), trust trajectories, live rule decisions.
- **Existing live OVS evidence**: keep the old Methodology1/2/3 benchmark artifacts and live controller logs separate. Do not copy those numbers into this simulator's new tables as if they came from the same run.
- **Proposed next research step**: longer native SUMO mobility validation plus a validated Ryu/OVS adapter if real packet forwarding is required. Native SUMO passed bounded headless checks; radio delivery and SDN enforcement remain simulated.

## Reproducibility checklist

- Use the same engine mode and settings across comparison trials.
- Reset before each trial; pick the same attacker and victim.
- Wait until the same simulation time before exporting reports.
- Run tests before presenting.
- Record which security mechanisms are enabled; note attack intensities and recovery timing.
- For the real OpenFlow benchmarks, preserve packet capture, flow/meter statistics and receiver-observed throughput as independent measurements.

## Troubleshooting

**Double-click launches then closes:** Run `py -3 run.py` from PowerShell to see the error. `START_WINDOWS.bat` is supposed to keep its window open after completion.

**Port 8765 in use:** `py -3 run.py --port 8899` then visit `http://127.0.0.1:8899`.

**Cars aren't moving:** Click Resume, check simulation speed, refresh page, and ensure the terminal is still running.

**Native SUMO can't start:** That's optional. Switch back to Built-in mobility. To enable native SUMO install the Windows SUMO package and `py -3 -m pip install traci`. Ensure `where.exe sumo` and `where.exe netconvert` work in a freshly opened PowerShell.

**M2 not triggering:** Use V07 as attacker and run UDP flooding. Stage 1 starts at the mobility-selected threshold; default Stage 2 requires at least 10 simulated seconds of Stage 1 plus polling/sample timing. Blocks last 30 simulated seconds. If the vehicle is outside RSU coverage or a configured monitored RSU, packet delivery and monitoring may change. See [the fidelity review](METHODOLOGY_FIDELITY.md) for scope and recovery details.

**M3 not recovering immediately:** Recovery is intentionally gradual: 0.02 reputation gain every five valid BSMs. Try 4× speed to demonstrate faster, then reset for comparative trials.

**My actual SDN switch is not appearing:** This Windows program models flow rules; it does not launch Ryu/OVS. Use the historical Linux benchmark for real OpenFlow evidence.
