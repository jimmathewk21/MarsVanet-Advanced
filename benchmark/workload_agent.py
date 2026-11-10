"""Small namespace-local UDP sender/receiver used by one live trial."""

import argparse
import csv
import json
import os
import socket
import struct
import time

try:
    from .safety_workload import build_safety_sequence
except ImportError:
    from safety_workload import build_safety_sequence

PAYLOAD_BYTES = 256
HEADER = struct.Struct("!BId")
ROLE = {"legitimate": 1, "attack": 2}


def receive(bind_ip, port, duration, output):
    deadline = time.monotonic() + duration
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, open(
        output, "w", newline="", encoding="utf-8"
    ) as stream:
        sock.bind((bind_ip, port))
        sock.settimeout(0.2)
        writer = csv.writer(stream)
        writer.writerow(("received_monotonic", "source_ip", "role", "sequence",
                         "sent_monotonic", "payload_bytes"))
        stream.flush()
        while time.monotonic() < deadline:
            try:
                payload, address = sock.recvfrom(65535)
            except socket.timeout:
                continue
            received_at = time.monotonic()
            if len(payload) != PAYLOAD_BYTES or len(payload) < HEADER.size:
                continue
            role, sequence, sent_at = HEADER.unpack_from(payload)
            role_name = "legitimate" if role == ROLE["legitimate"] else (
                "attack" if role == ROLE["attack"] else "unknown")
            writer.writerow((f"{received_at:.9f}", address[0], role_name,
                             sequence, f"{sent_at:.9f}", len(payload)))
            stream.flush()


def send(source_ip, destination_ip, port, role_name, pps, delay, duration, output,
         start_at=None):
    active_at = (time.monotonic() if start_at is None else start_at) + delay
    end_at = active_at + duration
    role = ROLE[role_name]
    sequence = 0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, open(
        output, "w", newline="", encoding="utf-8"
    ) as stream:
        sock.bind((source_ip, 0))
        writer = csv.writer(stream)
        writer.writerow(("sent_monotonic", "source_ip", "role", "sequence",
                         "payload_bytes"))
        while True:
            target = active_at + sequence / pps
            remaining = target - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            sent_at = time.monotonic()
            if sent_at >= end_at:
                break
            packet = HEADER.pack(role, sequence, sent_at)
            payload = packet + bytes(PAYLOAD_BYTES - len(packet))
            sock.sendto(payload, (destination_ip, port))
            writer.writerow((f"{sent_at:.9f}", source_ip, role_name,
                             sequence, len(payload)))
            stream.flush()
            sequence += 1


def send_safety(source_ip, destination_ip, port, repository_root, start_at,
                baseline_seconds, attack_seconds, recovery_seconds,
                severe_transition_seconds, severe_measurement_seconds,
                recovery_pps, output, recovery_gate=None, gate_timeout=75.0):
    trace = build_safety_sequence(repository_root,
                                  baseline_seconds=baseline_seconds,
                                  attack_seconds=attack_seconds,
                                  severe_transition_seconds=severe_transition_seconds,
                                  severe_measurement_seconds=severe_measurement_seconds,
                                  recovery_pps=recovery_pps)
    step = 1.0 / recovery_pps
    baseline_index = attack_index = recovery_index = 0
    recovery_start = None

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, open(
        output, "w", newline="", encoding="utf-8"
    ) as stream:
        sock.bind((source_ip, 0))
        writer = csv.writer(stream)
        writer.writerow(("sent_monotonic", "scheduled_monotonic", "sequence",
                         "phase", "source_ip", "destination_ip", "port",
                         "vehicle_id", "timestamp", "x", "y", "speed",
                         "expected_consistent", "expected_reputation",
                         "expected_action", "payload_bytes", "payload_json"))
        stream.flush()
        for item in trace:
            if item["phase"] == "baseline":
                scheduled = start_at + baseline_index * step
                baseline_index += 1
            elif item["phase"] == "attack":
                scheduled = start_at + baseline_seconds + attack_index * step
                attack_index += 1
            else:
                if recovery_start is None:
                    if recovery_gate:
                        deadline = time.monotonic() + gate_timeout
                        while not os.path.exists(recovery_gate):
                            if time.monotonic() >= deadline:
                                raise TimeoutError("recovery phase gate was not released")
                            time.sleep(0.05)
                        with open(recovery_gate, encoding="utf-8") as gate_stream:
                            recovery_start = float(json.load(gate_stream)["recovery_start_monotonic"])
                    else:
                        recovery_start = (start_at + baseline_seconds + attack_seconds
                                          + severe_transition_seconds
                                          + severe_measurement_seconds)
                scheduled = recovery_start + recovery_index * step
                recovery_index += 1
            if scheduled >= start_at + baseline_seconds + attack_seconds + severe_transition_seconds + severe_measurement_seconds + recovery_seconds:
                raise ValueError("telemetry trace exceeds its configured phase schedule")
            remaining = scheduled - time.monotonic()
            if remaining > 0:
                time.sleep(remaining)
            sent_at = time.monotonic()
            sock.sendto(item["payload"], (destination_ip, port))
            writer.writerow((f"{sent_at:.9f}", f"{scheduled:.9f}",
                             item["sequence"], item["phase"], source_ip,
                             destination_ip, port, item["vehicle_id"],
                             item["timestamp"], item["x"], item["y"],
                             item["speed"], item["consistent"],
                             item["reputation"], item["action"],
                             len(item["payload"]),
                             item["payload"].decode("utf-8")))
            stream.flush()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="mode", required=True)
    receiver = sub.add_parser("receive")
    receiver.add_argument("--bind", required=True)
    receiver.add_argument("--port", type=int, required=True)
    receiver.add_argument("--duration", type=float, required=True)
    receiver.add_argument("--output", required=True)
    sender = sub.add_parser("send")
    sender.add_argument("--source", required=True)
    sender.add_argument("--destination", required=True)
    sender.add_argument("--port", type=int, required=True)
    sender.add_argument("--role", choices=ROLE, required=True)
    sender.add_argument("--pps", type=float, required=True)
    sender.add_argument("--delay", type=float, default=0)
    sender.add_argument("--start-at", type=float,
                        help="absolute shared monotonic timestamp for the schedule")
    sender.add_argument("--duration", type=float, required=True)
    sender.add_argument("--output", required=True)
    safety = sub.add_parser("safety")
    safety.add_argument("--source", required=True)
    safety.add_argument("--destination", required=True)
    safety.add_argument("--port", type=int, default=5005)
    safety.add_argument("--repository-root", required=True)
    safety.add_argument("--start-at", type=float, required=True)
    safety.add_argument("--baseline", type=float, required=True)
    safety.add_argument("--attack", type=float, required=True)
    safety.add_argument("--recovery", type=float, required=True)
    safety.add_argument("--severe-transition", type=float, default=10.0)
    safety.add_argument("--severe-measurement", type=float, default=10.0)
    safety.add_argument("--recovery-pps", type=float, default=5.0)
    safety.add_argument("--recovery-gate")
    safety.add_argument("--gate-timeout", type=float, default=75.0)
    safety.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    if args.mode == "receive":
        receive(args.bind, args.port, args.duration, args.output)
    elif args.mode == "send":
        send(args.source, args.destination, args.port, args.role, args.pps,
             args.delay, args.duration, args.output, args.start_at)
    else:
        send_safety(args.source, args.destination, args.port,
                    args.repository_root, args.start_at, args.baseline,
                    args.attack, args.recovery, args.severe_transition,
                    args.severe_measurement, args.recovery_pps, args.output,
                    args.recovery_gate, args.gate_timeout)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
