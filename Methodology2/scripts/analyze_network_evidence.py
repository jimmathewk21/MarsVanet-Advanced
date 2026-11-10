import csv
import os

FILES = {
    "network_stats": os.path.expanduser("~/sdn_vanet_sumo/network_stats.csv"),
    "method2_network_stats": os.path.expanduser("~/sdn_vanet_sumo/method2_network_stats.csv"),
}

def analyze(name, path):
    with open(path, newline="") as file:
        rows = list(csv.DictReader(file))

    print(f"\n=== {name} ===")
    print("Samples:", len(rows))

    if len(rows) < 2:
        print("INSUFFICIENT DATA: Need at least two samples.")
        return

    rates = []

    for previous, current in zip(rows, rows[1:]):
        elapsed = float(current["timestamp"]) - float(previous["timestamp"])
        packet_delta = int(current["flow_packets"]) - int(previous["flow_packets"])

        if elapsed <= 0:
            print("Invalid timestamp interval; skipped.")
            continue

        if packet_delta < 0:
            print("Counter reset detected; interval skipped.")
            continue

        rates.append(packet_delta / elapsed)

    if not rates:
        print("INSUFFICIENT DATA: No valid measurement intervals.")
        return

    active_rates = [rate for rate in rates if rate > 0]

    print("Valid intervals:", len(rates))
    print("Intervals with packet increases:", len(active_rates))
    print("Maximum observed rate:", round(max(rates), 4), "packets/second")
    print("Mean observed rate:", round(sum(rates) / len(rates), 4), "packets/second")

    if not active_rates:
        print("Evidence score: NOT ASSESSED")
        print("Reason: No packet-counter increases in the recorded intervals.")
    else:
        print("Evidence score: NOT ASSESSED")
        print("Reason: A validated detection threshold and aligned mobility data are required.")

for name, path in FILES.items():
    analyze(name, path)
