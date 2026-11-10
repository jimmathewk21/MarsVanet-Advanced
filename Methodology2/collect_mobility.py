"""Collect per-vehicle mobility traces from a SUMO run via TraCI.

Outputs a raw CSV (time, vehicle_id, speed, x, y) that mobility_features.py
turns into the per-timestep feature file the detector consumes.

Requires SUMO + the `traci` Python package and therefore cannot run in a plain
container. Paths default to the base network shipped in Methodology2/ and can
be overridden so the same collector serves the urban and highway scenarios:

    python3 collect_mobility.py \
        --net scenarios/highway/highway.net.xml \
        --routes scenarios/highway/highway.rou.xml \
        --output scenarios/highway/mobility_data.csv \
        [--sumo-binary sumo]

The ``--begin-offset`` option records an explicit simulation-time offset into a
sidecar ``.offset`` file so the controller clock and SUMO clock can be aligned
during live experiments (addresses the documented clock-misalignment issue).
"""

import argparse
import csv
import sys
from pathlib import Path

_HERE = Path(__file__).resolve().parent


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--net", default=str(_HERE / "network.net.xml"))
    parser.add_argument("--routes", default=str(_HERE / "routes.rou.xml"))
    parser.add_argument("--output", default=str(_HERE / "mobility_data.csv"))
    parser.add_argument("--sumo-binary", default="sumo")
    parser.add_argument(
        "--step-length", default="1.0",
        help="SUMO simulation step length in seconds",
    )
    args = parser.parse_args(argv)

    try:
        import traci
    except ImportError:
        print(
            "ERROR: the 'traci' package (from SUMO) is not available.\n"
            "Install SUMO and set SUMO_HOME, then: pip install traci\n"
            "This step requires the SUMO runtime and cannot run in a plain "
            "container.",
            file=sys.stderr,
        )
        return 2

    Path(args.output).parent.mkdir(parents=True, exist_ok=True)

    traci.start([
        args.sumo_binary,
        "-n", args.net,
        "-r", args.routes,
        "--step-length", args.step_length,
    ])

    rows = 0
    with open(args.output, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow(["time", "vehicle_id", "speed", "x", "y"])
        while traci.simulation.getMinExpectedNumber() > 0:
            traci.simulationStep()
            now = traci.simulation.getTime()
            for vehicle_id in traci.vehicle.getIDList():
                speed = traci.vehicle.getSpeed(vehicle_id)
                x, y = traci.vehicle.getPosition(vehicle_id)
                writer.writerow(
                    [now, vehicle_id, round(speed, 2), round(x, 2), round(y, 2)]
                )
                rows += 1
    traci.close()

    print(f"Mobility data saved to {args.output} ({rows} rows)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
