#!/usr/bin/env python3
"""Send synthetic safety observations from a Mininet station namespace."""

import argparse
import json
import math
import socket
import time

from safety_messages import SAFETY_MESSAGE_PORT, VEHICLE_IPS


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("vehicle_id", choices=sorted(VEHICLE_IPS))
    parser.add_argument("--destination", default="10.0.0.2")
    parser.add_argument("--scenario", choices=("normal", "deteriorate", "recover", "demo"), default="normal")
    parser.add_argument("--count", type=int, default=300)
    parser.add_argument("--interval", type=float, default=0.2)
    args = parser.parse_args()
    if args.count <= 0 or not math.isfinite(args.interval) or args.interval <= 0:
        parser.error("count and interval must be positive and finite")
    if args.destination == VEHICLE_IPS[args.vehicle_id]:
        parser.error("destination must be another station so traffic reaches the AP")
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind((VEHICLE_IPS[args.vehicle_id], 0))
        for index in range(args.count):
            violation = args.scenario == "deteriorate" or (
                args.scenario == "demo" and 10 <= index < 17)
            message = dict(vehicle_id=args.vehicle_id, timestamp=time.time(),
                           x=0, y=0, speed=100 if violation else 0)
            sock.sendto(json.dumps(message).encode("utf-8"),
                        (args.destination, SAFETY_MESSAGE_PORT))
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
