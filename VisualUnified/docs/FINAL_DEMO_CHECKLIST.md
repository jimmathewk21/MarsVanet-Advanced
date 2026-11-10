# Final five-minute VisualUnified demonstration

## Start on Windows

Open PowerShell in the existing MarsVanet checkout:

```powershell
cd "C:\Users\jimk7\Desktop\Projects\ComputerNetworks\MarsVanet\VisualUnified"
.\START_WINDOWS.bat
```

If the browser does not open, visit **http://127.0.0.1:8765**. Keep the
PowerShell window open and press **Ctrl+C** after the demonstration. The app
needs the sibling `Methodology2/` and `Methodology3/` policy helper files.
Built-in mobility needs no VM or extra package.
The launcher selects a working Python interpreter, including the installed
`C:\msys64\ucrt64\bin\python.exe` fallback on this machine.

## What to show

| Time | Controls to click | Expected observation and explanation |
|---|---|---|
| 0:00–0:40 | **Live simulation**. Select vehicle **V07** on the map. | Twelve cars move through three RSU coverage areas. The selected vehicle shows its attached RSU, speed, M2 rate/threshold, M3 trust, and handovers. Packet pulses illustrate attempted transmission, delivery, and modeled drops. |
| 0:40–1:50 | Set **Attacker V07**, **Victim V02**, click **Start guided demo**, then set **4× speed** in the toolbar. | The guide resets the simulation while keeping rules/settings, shows five simulated seconds of normal traffic, starts a UDP flood, waits for **M2 METER**, then **M2 BLOCK**, stops the attack, and waits for **NORMAL** recovery. Point to the guide text, vehicle inspector, traffic chart, and event stream. Default Stage 1 dwell is 10 simulated seconds; the Stage 2 block lasts 30 simulated seconds. |
| 1:50–2:35 | Open **Policy studio**. In **Rule editor**, add `Demo block`, source **V07**, traffic **UDP flood**, any RSU, priority **900**, action **DROP**, enabled. Click **Save SDN rule**. Click **UDP flooding** on the main tab, then return to the rule list and click **Disable**. | The rule appears in the configured table. While enabled, **M1 static drops** increase and M2 cannot observe the blocked flood. Disabling it allows M2 detection again. Use **Edit** to change the rule or **Delete** to remove it. Disable any matching M1 DROP before starting the guided M2 demo again. |
| 2:35–3:30 | Click **Reset** and confirm. Select **4× speed** again, then **False safety data**. Inspect V07 and **Evidence & logs**. | Physically inconsistent safety reports lower V07's reputation and can activate M3 rate limits. Return to **Normal traffic** to show gradual reputation recovery. The simulator uses original pure Python M3 consistency and reputation helpers. |
| 3:30–4:15 | Click **Reset**, choose **4× speed**, then **Combined attack**. Open **Policy studio → Effective runtime flow policies**. | With the demo M1 rule disabled, M2 and M3 can apply together. M2's victim-bound UDP meter/block and M3's reputation limit appear independently; the model applies the stricter applicable limit. |
| 4:15–5:00 | Open [the saved 90-run report](../experiments/study-v1/REPORT.md) and [combined attack graph](../experiments/study-v1/combined__malicious_delivery_pct.svg). | Across five seeded simulated trials, mean malicious delivery was **76.04% No Defense**, **12.72% M2 only**, **10.86% M3 only**, and **6.54% Unified Dynamic**. The preconfigured M1 rule yielded **0.99%** by already knowing V07 and the flood class. Show [CSV confidence intervals](../experiments/study-v1/summary.csv). **Export JSON report** describes only the current interactive run; the saved 90-run study is separate. |

## If something differs

- **No page or stale page:** Check the server terminal; visit the printed local
  URL and reload. If port 8765 is busy, run `py -3 run.py --port 8899` and use
  `http://127.0.0.1:8899`.
- **Cars do not move:** Click **Resume** and use **Built-in mobility**. Reset
  restores normal simulation speed, so select **4×** again after reset/start.
- **Guided attack does not reach M2:** Confirm M2 is enabled and any V07 flood
  M1 DROP is disabled. The guide reports a stalled stage instead of claiming
  success. RSU coverage and configured ingress scope also affect detection.
- **M3 recovery looks slow:** After returning to Normal traffic, M3 gains 0.02
  trust for each five accepted valid reports. The fixed study measured mean
  meter removal after 104.9 simulated seconds and trust ≥0.80 after 130.4
  simulated seconds from attack end; the interactive trajectory can differ.
- **Study command refuses the directory:** This protects existing results.
  Use a new output path, such as `experiments/study-v1-repeat`.

## Evidence boundary

The dashboard models roads, radios, traffic, SDN-like policies and packet
outcomes in Python. It does **not** send OpenFlow rules to Ryu/OVS or measure
actual switch, wireless, or receiver performance. Built-in mobility is a
scripted route model; optional SUMO can supply mobility only. Colored dots
are sampled visualization, not packet counts. Use counters for the current
simulated run and keep historical Mininet/OVS evidence separate.

The saved study passed its packet-ledger validator: 90 trials, 1,362,030
packets recounted, and all 15 profile groups matched for offered traffic and
mobility. Check it again without rerunning experiments:

```powershell
& "C:\msys64\ucrt64\bin\python.exe" validate_experiments.py experiments/study-v1 --allow-source-drift
```

Browser click-through was unavailable during the final automated audit. The
local HTTP smoke test and dashboard/engine unit tests passed; a live browser
visual check remains pending for the presentation machine.

Phase 1 uses new lane mobility in the dashboard. The archived study retains its
original centerline model; the explicit audit flag reports source drift while
still checking every saved artifact and ledger. Coverage is now hidden until
inspection or toggled in **Map Display**. Click an RSU for traffic/path counters;
wheel or **+/−** zooms and **Reset view** restores the map. See
[the Phase 1 progress record](MARSNET_V2_PROGRESS.md) for validation boundaries.
