"""Deterministic, dependency-free benchmark planning and metric summaries.

This phase deliberately does not launch Mininet, Ryu, OVS, or traffic. The
compatibility gate keeps a plan from being mistaken for a comparable run.
"""

from __future__ import annotations

from dataclasses import dataclass, asdict
from datetime import datetime, timezone
import hashlib
import json
import math
from statistics import median
import platform
from pathlib import Path
import re
import sys
from typing import Any, Iterable, Optional


CONFIGURATIONS = ("no_defense", "methodology1", "methodology2", "methodology3")
WORKLOADS = ("volumetric_udp", "safety_consistency")
WINDOWS = {"baseline_seconds": 30, "attack_seconds": 60, "recovery_seconds": 30}
WORKLOAD_WINDOWS = {
    "volumetric_udp": WINDOWS,
    "safety_consistency": {
        "baseline_seconds": 30, "attack_seconds": 2, "recovery_seconds": 42,
    },
}
OFFERED_LOADS = {
    "volumetric_udp": {
        "legitimate_pps": 20,
        "attack_pps": 500,
        "udp_payload_bytes": 256,
        "destination_port": 5001,
    },
    "safety_consistency": {
        "legitimate_safety_pps": 5,
        "inconsistent_safety_pps": 5,
        "legitimate_data_plane_pps": 20,
        "data_plane_probe_pps": 500,
        "data_plane_payload_bytes": 256,
        "destination_port": 5005,
        "data_plane_probe_port": 5001,
    },
}

# Student-t two-sided 95% critical values (df=1..30); for larger samples use
# the conservative normal limit. No external statistics package is required.
_T95 = [
    12.706, 4.303, 3.182, 2.776, 2.571, 2.447, 2.365, 2.306, 2.262, 2.228,
    2.201, 2.179, 2.160, 2.145, 2.131, 2.120, 2.110, 2.101, 2.093, 2.086,
    2.080, 2.074, 2.069, 2.064, 2.060, 2.056, 2.052, 2.048, 2.045, 2.042,
]


@dataclass(frozen=True)
class RunSpec:
    run_id: str
    workload: str
    configuration: str
    repetition: int
    seed: int
    applicable: bool
    compatibility: str
    compatibility_reasons: tuple[str, ...]
    windows: dict[str, int]
    offered_loads: dict[str, int]
    topology_id: str = "common_2ap_candidate_v1"


def _token(value: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_-]+", "-", value).strip("-").lower()


def derive_seed(root_seed: int, workload: str, repetition: int) -> int:
    """Matched seed shared by every configuration in a workload repetition."""
    material = f"marsvanet-v1|{root_seed}|{workload}|{repetition}".encode()
    return int.from_bytes(hashlib.sha256(material).digest()[:4], "big")


def make_run_id(workload: str, configuration: str, repetition: int, seed: int) -> str:
    return f"{_token(workload)}-{_token(configuration)}-r{repetition:03d}-s{seed:08x}"


def workload_applicable(workload: str, configuration: str) -> bool:
    return not (workload == "volumetric_udp" and configuration == "methodology3")


def compatibility_reasons(workload: str, configuration: str) -> tuple[str, ...]:
    reasons = [
        "Live topology startup checks run on the Ubuntu test host; controller "
        "forwarding effectiveness is not established by static validation."
    ]
    # The M3 topology provides explicit stable AP DPIDs and station identities;
    # M2's source controller assumes AP2 ingress=1/output=2, unverified there.
    if configuration == "methodology2":
        reasons.append(
            "M2 requires AP2 DPID 0x1000000000000002 and AP2 ingress/output "
            "ports 1/2; the adapter requests these values, but actual OVS IDs "
            "and ofports remain unverified until a live topology start."
        )
    if configuration == "methodology1" and workload == "safety_consistency":
        # M1 is still meaningfully testable as a static UDP source drop, but it
        # does not classify valid versus physically inconsistent safety data.
        pass
    if configuration == "no_defense":
        reasons.append(
            "The live runner uses Ryu's built-in simple_switch_13 baseline; "
            "end-to-end forwarding still requires live observation."
        )
    return tuple(reasons)


def generate_matrix(root_seed: int = 1, repetitions: int = 3,
                    workloads: Iterable[str] = WORKLOADS) -> list[RunSpec]:
    if repetitions < 1:
        raise ValueError("repetitions must be at least 1")
    if root_seed < 0:
        raise ValueError("root_seed must be non-negative")
    result = []
    for workload in workloads:
        if workload not in WORKLOADS:
            raise ValueError(f"unknown workload: {workload}")
        for repetition in range(1, repetitions + 1):
            seed = derive_seed(root_seed, workload, repetition)
            for configuration in CONFIGURATIONS:
                applicable = workload_applicable(workload, configuration)
                reasons = compatibility_reasons(workload, configuration)
                if not applicable:
                    reasons = reasons + (
                        "M3 consumes and scores structurally valid UDP/5005 safety messages; "
                        "it is not a general volumetric UDP flood detector.",
                    )
                result.append(RunSpec(
                    make_run_id(workload, configuration, repetition, seed),
                    workload, configuration, repetition, seed, applicable,
                    ("not_applicable" if not applicable else
                     "conditional_runtime_port_verification_required"
                     if configuration == "methodology2" else
                     "runtime_unverified"),
                    reasons, dict(WORKLOAD_WINDOWS[workload]),
                    dict(OFFERED_LOADS[workload]),
                ))
    return result


def confidence_interval_95(values: Iterable[float]) -> dict[str, Any]:
    data = [float(value) for value in values]
    if any(not math.isfinite(value) for value in data):
        raise ValueError("confidence interval values must be finite")
    n = len(data)
    if n < 2:
        return {"mean": (sum(data) / n if n else None), "low": None, "high": None,
                "n": n, "explanation": "At least two independent trials are required."}
    mean = sum(data) / n
    variance = sum((value - mean) ** 2 for value in data) / (n - 1)
    critical = _T95[n - 2] if n <= 31 else 1.96
    margin = critical * math.sqrt(variance / n)
    return {"mean": mean, "low": mean - margin, "high": mean + margin,
            "n": n, "explanation": None}


METRIC_DEFINITIONS = {
    "legitimate_throughput_mbps": "Successfully received application payload bits / attack window seconds / 1e6.",
    "packet_loss_ratio": "1 - received legitimate sequence count / sent legitimate sequence count.",
    "packet_delivery_ratio": "Received legitimate sequence count / sent legitimate sequence count.",
    "latency_ms": "Median receiver timestamp minus sender timestamp, with clock synchronization uncertainty recorded.",
    "attack_throughput_mbps": "Successfully received attack payload bits / attack window seconds / 1e6.",
    "detection_delay_seconds": "First controller evidence timestamp minus attack start; null when controller evidence is unavailable.",
    "mitigation_delay_seconds": "First confirmed enforcement timestamp minus attack start; null unless confirmation is observable.",
    "recovery_time_seconds": "Time from attack end until legitimate throughput returns within 5% of baseline for 5 consecutive seconds.",
    "false_positive_count": "Legitimate sources/vehicles incorrectly flagged or restricted during baseline and attack windows.",
}


def empty_metrics(explanations: Optional[dict[str, str]] = None) -> dict[str, dict[str, Any]]:
    explanations = explanations or {}
    return {name: {"value": None, "explanation": explanations.get(
        name, "No live measurement collected in Phase 1 planning mode.")}
        for name in METRIC_DEFINITIONS}


def metric_record(value: Any, explanation: Optional[str] = None) -> dict[str, Any]:
    return {"value": value, "explanation": explanation if value is None else None}


def traffic_metrics(sent_packets: Optional[int], received_packets: Optional[int],
                    received_payload_bytes: Optional[int],
                    measurement_seconds: Optional[float]) -> dict[str, dict[str, Any]]:
    """Calculate receiver-observed traffic values; unavailable inputs stay null."""
    result = {}
    if sent_packets is None or received_packets is None:
        reason = "Sender and receiver sequence counts are required."
        result["packet_delivery_ratio"] = metric_record(None, reason)
        result["packet_loss_ratio"] = metric_record(None, reason)
    elif (sent_packets < 0 or received_packets < 0
          or received_packets > sent_packets):
        raise ValueError("packet counts must satisfy 0 <= received <= sent")
    elif sent_packets == 0:
        result["packet_delivery_ratio"] = metric_record(None, "No packets were offered.")
        result["packet_loss_ratio"] = metric_record(None, "No packets were offered.")
    else:
        pdr = received_packets / sent_packets
        result["packet_delivery_ratio"] = metric_record(pdr)
        result["packet_loss_ratio"] = metric_record(1.0 - pdr)

    if received_payload_bytes is None or measurement_seconds is None:
        result["legitimate_throughput_mbps"] = metric_record(
            None, "Received payload bytes and a measurement duration are required."
        )
    elif received_payload_bytes < 0 or measurement_seconds <= 0:
        raise ValueError("payload bytes must be non-negative and duration positive")
    else:
        result["legitimate_throughput_mbps"] = metric_record(
            received_payload_bytes * 8 / measurement_seconds / 1_000_000
        )
    return result


def latency_metric(samples_ms: Optional[Iterable[float]],
                   clock_uncertainty_ms: Optional[float]) -> dict[str, Any]:
    if samples_ms is None or clock_uncertainty_ms is None:
        return metric_record(None, "Latency samples and clock uncertainty are required.")
    samples = [float(sample) for sample in samples_ms]
    if not samples:
        return metric_record(None, "No latency samples were received.")
    if any(not math.isfinite(value) or value < 0 for value in samples):
        raise ValueError("latency samples must be finite and non-negative")
    if not math.isfinite(clock_uncertainty_ms) or clock_uncertainty_ms < 0:
        raise ValueError("clock uncertainty must be finite and non-negative")
    result = metric_record(median(samples))
    result["clock_uncertainty_ms"] = clock_uncertainty_ms
    return result


def event_delay_metric(start_time: Optional[float],
                       event_time: Optional[float],
                       unavailable_reason: str) -> dict[str, Any]:
    if start_time is None or event_time is None:
        return metric_record(None, unavailable_reason)
    delay = event_time - start_time
    if delay < 0 or not math.isfinite(delay):
        raise ValueError("event time must be finite and no earlier than start")
    return metric_record(delay)


def recovery_time_metric(samples: Optional[Iterable[tuple[float, float]]],
                         attack_end: Optional[float],
                         baseline_mbps: Optional[float]) -> dict[str, Any]:
    """Return first 5-sample recovery streak at/after attack end, sampled each second."""
    if samples is None or attack_end is None or baseline_mbps is None:
        return metric_record(None, "Recovery samples, attack end, and baseline are required.")
    points = sorted((float(t), float(rate)) for t, rate in samples)
    if baseline_mbps <= 0 or not math.isfinite(baseline_mbps):
        return metric_record(None, "Recovery is undefined without positive baseline throughput.")
    streak = []
    for timestamp, rate in points:
        if timestamp < attack_end:
            continue
        if not math.isfinite(timestamp) or not math.isfinite(rate):
            raise ValueError("recovery samples must be finite")
        if rate >= baseline_mbps * 0.95:
            if streak:
                gap = timestamp - streak[-1]
                if gap < 0.5 or gap > 1.5:
                    streak = []
            streak.append(timestamp)
            if len(streak) == 5:
                return metric_record(streak[0] - attack_end)
        else:
            streak = []
    return metric_record(None, "No five-consecutive-second recovery streak was observed.")


def summarize_metric_records(records: Iterable[dict[str, Any]]) -> dict[str, Any]:
    """Aggregate one metric's per-trial {value, explanation} records."""
    values = []
    missing = 0
    reasons = []
    for record in records:
        value = record.get("value")
        if value is None:
            missing += 1
            if record.get("explanation"):
                reasons.append(record["explanation"])
        else:
            values.append(float(value))
    summary = confidence_interval_95(values)
    summary["missing_trials"] = missing
    summary["missing_explanations"] = sorted(set(reasons))
    return summary


def environment_metadata() -> dict[str, Any]:
    return {
        "captured_at_utc": datetime.now(timezone.utc).isoformat(),
        "platform": platform.platform(),
        "python": sys.version,
        "software_versions": {
            name: {"version": None, "explanation":
                  "Not probed in safe Phase 1 planning mode."}
            for name in ("ryu", "mininet_wifi", "ovs", "sumo")
        },
        "benchmark_phase": 1,
        "live_validation": False,
    }


def write_run_artifacts(output_dir: Path, spec: RunSpec,
                        raw_log: str = "", metrics: Optional[dict[str, Any]] = None,
                        metadata: Optional[dict[str, Any]] = None) -> tuple[Path, Path, Path]:
    """Create unique per-run artifacts without overwriting existing files."""
    output_dir.mkdir(parents=True, exist_ok=True)
    stem = spec.run_id
    raw_path = output_dir / f"{stem}.raw.log"
    metrics_path = output_dir / f"{stem}.metrics.json"
    meta_path = output_dir / f"{stem}.environment.json"
    for path in (raw_path, metrics_path, meta_path):
        if path.exists():
            raise FileExistsError(f"refusing to overwrite benchmark artifact: {path}")
    raw_path.write_text(raw_log, encoding="utf-8")
    metrics_path.write_text(json.dumps({
        "run": asdict(spec), "metrics": metrics or empty_metrics(),
    }, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    meta_path.write_text(json.dumps(metadata or environment_metadata(),
                                    indent=2, sort_keys=True) + "\n",
                          encoding="utf-8")
    return raw_path, metrics_path, meta_path


def summarize_metric_files(paths: Iterable[Path]) -> dict[str, Any]:
    """Load per-run JSON artifacts and summarize each workload/config metric."""
    groups: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for path in paths:
        document = json.loads(Path(path).read_text(encoding="utf-8"))
        run = document["run"]
        groups.setdefault((run["workload"], run["configuration"]), []).append(
            document.get("metrics", {})
        )
    output = {}
    for (workload, configuration), metric_documents in sorted(groups.items()):
        output[f"{workload}/{configuration}"] = {
            name: summarize_metric_records(
                document.get(name, {"value": None,
                                    "explanation": "Metric not recorded."})
                for document in metric_documents
            )
            for name in METRIC_DEFINITIONS
        }
    return output
