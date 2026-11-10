"""Deterministic Methodology 3 trace, checked by its actual policy classes."""

from __future__ import annotations

import importlib
import json
from pathlib import Path
import sys


def _methodology3_types(repository_root):
    module_dir = str(Path(repository_root) / "Methodology3")
    added = module_dir not in sys.path
    if added:
        sys.path.insert(0, module_dir)
    try:
        consistency = importlib.import_module("message_consistency")
        reputation = importlib.import_module("reputation_engine")
        safety = importlib.import_module("safety_messages")
        return (consistency.MessageConsistencyChecker,
                reputation.ReputationEngine, safety.parse_safety_message)
    finally:
        if added:
            sys.path.remove(module_dir)


def build_safety_sequence(repository_root, *, baseline_seconds=30.0,
                          attack_seconds=2.0,
                          severe_transition_seconds=10.0,
                          severe_measurement_seconds=10.0,
                          telemetry_attack_count=5, recovery_valid_count=200,
                          recovery_pps=5.0):
    """Create compact JSON messages and derive expected policy outcomes.

    No reputation thresholds are duplicated here: consistency and reputation
    values are produced by Methodology 3's MessageConsistencyChecker and
    ReputationEngine. Every serialized message also passes its strict parser.
    """
    if telemetry_attack_count != 5:
        raise ValueError("the live safety trace requires exactly five violations")
    if recovery_valid_count < 200:
        raise ValueError("the live safety trace requires at least 200 recovery messages")
    if (recovery_pps <= 0 or baseline_seconds <= 0 or attack_seconds <= 0
            or severe_transition_seconds < 0 or severe_measurement_seconds <= 0):
        raise ValueError("baseline duration and recovery rate must be positive")
    Checker, ReputationEngine, parse_message = _methodology3_types(repository_root)
    checker, reputation = Checker(), ReputationEngine()
    trace = []
    logical_time = 1_700_000_000.0

    def append(phase, timestamp, x, y, speed):
        payload = json.dumps({
            "vehicle_id": "sta3", "timestamp": timestamp,
            "x": x, "y": y, "speed": speed,
        }, separators=(",", ":")).encode("utf-8")
        parsed = parse_message(payload)
        consistency = checker.check(parsed)
        decision = reputation.update("sta3", consistency.consistent,
                                    consistency.severity)
        trace.append({
            "sequence": len(trace), "phase": phase, "payload": payload,
            "vehicle_id": parsed.vehicle_id, "timestamp": parsed.timestamp,
            "x": parsed.x, "y": parsed.y, "speed": parsed.speed,
            "consistent": consistency.consistent, "reason": consistency.reason,
            "severity": consistency.severity, "reputation": decision.reputation,
            "action": decision.action, "rate_limit_kbps": decision.rate_limit_kbps,
        })

    step = 1.0 / recovery_pps
    baseline_valid_count = int(round(baseline_seconds * recovery_pps))
    if baseline_valid_count < 1:
        raise ValueError("baseline must schedule at least one valid message")
    accepted_x = 0.0
    for index in range(baseline_valid_count):
        logical_time = 1_700_000_000.0 + index * step
        accepted_x = index * 0.4
        append("baseline", logical_time, accepted_x, 0.0, 2.0)

    attack_start_time = 1_700_000_000.0 + baseline_seconds
    for index in range(telemetry_attack_count):
        logical_time = attack_start_time + index * step
        # The large jump exceeds the checker displacement bound while all
        # fields remain within its JSON encoding bounds.
        append("attack", logical_time, 1000.0 + 100.0 * index, 0.0, 2.0)
    recovery_start_time = (attack_start_time + attack_seconds
                           + severe_transition_seconds + severe_measurement_seconds)
    for index in range(recovery_valid_count):
        logical_time = recovery_start_time + index * step
        # Resume from the last accepted baseline position; invalid displacement
        # samples never advance Methodology 3's checker state.
        # The 0.4 m step at 2 m/s is within the real checker tolerance.
        append("recovery", logical_time, accepted_x + 0.4 * (index + 1), 0.0, 2.0)

    if any(right["timestamp"] <= left["timestamp"]
           for left, right in zip(trace, trace[1:])):
        raise AssertionError("safety trace timestamps must strictly increase")
    if (not all(item["consistent"] for item in trace if item["phase"] == "baseline")
            or any(item["consistent"] for item in trace if item["phase"] == "attack")
            or not all(item["consistent"] for item in trace if item["phase"] == "recovery")):
        raise AssertionError("safety trace did not match Methodology 3 consistency policy")
    if trace[-1]["reputation"] < 0.80:
        raise AssertionError("safety trace does not recover reputation to 0.80")
    return trace


def expected_action_transitions(trace):
    transitions = []
    previous = None
    for item in trace:
        action = item["action"]
        if action != previous:
            transitions.append({"sequence": item["sequence"],
                                "phase": item["phase"],
                                "reputation": item["reputation"],
                                "action": action})
            previous = action
    return transitions
