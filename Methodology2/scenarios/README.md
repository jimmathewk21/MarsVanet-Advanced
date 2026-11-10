# Urban and highway scenarios

Two SUMO scenarios are provided so detection and mitigation can be evaluated
under different mobility contexts. They are deliberately comparable (similar
total injected vehicle count) so the urban-vs-highway difference is about
mobility context, not raw demand.

| Property            | Urban                         | Highway                    |
|---------------------|-------------------------------|----------------------------|
| Road                | 1 km arterial, 1 lane         | 2 km straight, 3 lanes     |
| Junction            | one signalised junction (u1)  | none                       |
| Free-flow speed     | 13.89 m/s (50 km/h)           | 33.33 m/s (120 km/h)       |
| Demand              | 1200 veh/h for 120 s          | 600 veh/h for 120 s        |
| Resulting context   | dense / slow (stop-go)        | sparse / fast              |

## Why this matters for detection

The mobility-aware threshold policy (`scripts/mobility_detector.py`) adapts the
packets-per-second threshold to the current context:

* **Urban (dense/slow)** → threshold is *lowered* (default 90 pps). Dense, slow
  traffic should not itself produce high per-source UDP rates, so a lower bar is
  appropriate.
* **Highway (sparse/fast)** → threshold is *raised* (default 150 pps) to avoid
  misreading the bursts that accompany fast movement and frequent handovers.

Mobility only shifts the threshold; it is never treated as evidence of an
attack on its own (see the project README and `PENDING_WORK_AND_VALIDATION.md`).

You can see the exact mapping without any runtime:

```
python3 Methodology2/scripts/detector_demo.py
```

## Building and running (requires SUMO)

```
# 1. Build the .net.xml files (needs netconvert from SUMO)
bash Methodology2/scenarios/build_networks.sh

# 2. Record a mobility trace via TraCI, e.g. for highway:
python3 Methodology2/collect_mobility.py \
    --net    Methodology2/scenarios/highway/highway.net.xml \
    --routes Methodology2/scenarios/highway/highway.rou.xml \
    --output Methodology2/scenarios/highway/mobility_data.csv

# 3. Turn the raw trace into per-timestep features:
python3 Methodology2/mobility_features.py \
    Methodology2/scenarios/highway/mobility_data.csv \
    Methodology2/scenarios/highway/mobility_features.csv

# 4. Point the controller at that feature file:
export DOS_MOBILITY_CSV=Methodology2/scenarios/highway/mobility_features.csv
```

See `../EXPERIMENTS.md` for the full experiment matrix and the SDN run steps.
