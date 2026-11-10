"""Extract per-timestep mobility features from a raw SUMO trace CSV.

Reads a raw mobility CSV (columns: time, vehicle_id, speed, x, y) and writes a
per-timestep feature CSV (vehicle_count, average/min/max speed, x/y bounds).

Paths default to the files shipped in this Methodology2 directory and are
resolved relative to THIS script, so it runs from any working directory.
Override with positional arguments:

    python3 mobility_features.py [input_csv] [output_csv]
"""

import csv
import sys
from collections import defaultdict
from pathlib import Path

_HERE = Path(__file__).resolve().parent
DEFAULT_INPUT = _HERE / "mobility_data.csv"
DEFAULT_OUTPUT = _HERE / "mobility_features.csv"


def extract(input_path, output_path):
    data = defaultdict(list)
    with open(input_path, newline="") as file:
        reader = csv.DictReader(file)
        for row in reader:
            time = float(row["time"])
            data[time].append({
                "id": row["vehicle_id"],
                "speed": float(row["speed"]),
                "x": float(row["x"]),
                "y": float(row["y"]),
            })

    with open(output_path, "w", newline="") as file:
        writer = csv.writer(file)
        writer.writerow([
            "time", "vehicle_count", "average_speed",
            "minimum_speed", "maximum_speed",
            "x_min", "x_max", "y_min", "y_max",
        ])
        for time in sorted(data):
            vehicles = data[time]
            speeds = [v["speed"] for v in vehicles]
            xs = [v["x"] for v in vehicles]
            ys = [v["y"] for v in vehicles]
            writer.writerow([
                time,
                len(set(v["id"] for v in vehicles)),
                round(sum(speeds) / len(speeds), 2),
                min(speeds),
                max(speeds),
                min(xs),
                max(xs),
                min(ys),
                max(ys),
            ])

    return len(data)


def main(argv):
    input_path = Path(argv[1]) if len(argv) > 1 else DEFAULT_INPUT
    output_path = Path(argv[2]) if len(argv) > 2 else DEFAULT_OUTPUT
    steps = extract(input_path, output_path)
    print("Mobility feature extraction completed")
    print(f"Read: {input_path}")
    print(f"Timesteps processed: {steps}")
    print(f"Output saved to: {output_path}")


if __name__ == "__main__":
    main(sys.argv)
