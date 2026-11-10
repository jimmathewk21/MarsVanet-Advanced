"""Process-owned single-trial live runner for the volumetric UDP workload."""

from __future__ import annotations

import csv
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import subprocess
import sys
import time

try:
    from .core import (
        METRIC_DEFINITIONS, WORKLOAD_WINDOWS, empty_metrics, latency_metric, metric_record,
        recovery_time_metric, traffic_metrics,
    )
    from .mininet_topology import create_topology, start_topology
    from .safety_workload import build_safety_sequence, expected_action_transitions
except ImportError:
    from core import (
        METRIC_DEFINITIONS, WORKLOAD_WINDOWS, empty_metrics, latency_metric, metric_record,
        recovery_time_metric, traffic_metrics,
    )
    from mininet_topology import create_topology, start_topology
    from safety_workload import build_safety_sequence, expected_action_transitions


WINDOWS = {"baseline": 30.0, "attack": 60.0, "recovery": 30.0}
UDP_PORT = 5001
PAYLOAD_BYTES = 256
LIVE_CONFIGURATIONS = {"no_defense", "methodology1", "methodology2"}
SAFETY_WINDOWS = {
    "baseline": float(WORKLOAD_WINDOWS["safety_consistency"]["baseline_seconds"]),
    "attack": float(WORKLOAD_WINDOWS["safety_consistency"]["attack_seconds"]),
    "recovery": float(WORKLOAD_WINDOWS["safety_consistency"]["recovery_seconds"]),
}
SAFETY_RECOVERY_PPS = 5.0
SEVERE_TRANSITION_TIMEOUT_SECONDS = 10.0
NORMAL_CONFIRMATION_TIMEOUT_SECONDS = 5.0
MAX_STEADY_MEASUREMENT_SECONDS = 60.0


def _require_live_host():
    if os.name != "posix" or not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise RuntimeError("live execution requires root on the Ubuntu Mininet-WiFi host")


def controller_command(root: Path, configuration: str, ryu_manager: str,
                       port: int) -> tuple[list[str], Path]:
    if configuration == "no_defense":
        return ([ryu_manager, "--ofp-tcp-listen-port", str(port),
                 "ryu.app.simple_switch_13"], root)
    controller_files = {
        "methodology1": "Methodology1/scripts/dos_defense_static.py",
        "methodology2": "Methodology2/scripts/dos_defense_v2.py",
        "methodology3": "Methodology3/controller.py",
    }
    if configuration not in controller_files:
        raise ValueError(f"unsupported live configuration: {configuration}")
    path = root / controller_files[configuration]
    return ([ryu_manager, "--ofp-tcp-listen-port", str(port), str(path)], path.parent)


def _wait_controller(process, address, timeout=15.0, clock=time.monotonic,
                     sleep=time.sleep, connect=socket.create_connection):
    deadline = clock() + timeout
    while clock() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Ryu controller exited before accepting connections")
        try:
            with connect(address, timeout=0.25):
                return
        except OSError:
            sleep(0.1)
    raise TimeoutError(f"controller did not listen at {address} within {timeout}s")


def _read_csv(path):
    if not path.exists():
        return []
    with path.open(newline="", encoding="utf-8") as stream:
        return list(csv.DictReader(stream))


def _in_window(rows, timestamp_key, start, end):
    return [row for row in rows
            if start <= float(row[timestamp_key]) < end]


def _trial_metrics(received, legitimate_sent, attack_sent, t0, windows=WINDOWS):
    attack_start = t0 + windows["baseline"]
    attack_end = attack_start + windows["attack"]
    rx_legit = _in_window([r for r in received if r["role"] == "legitimate"],
                          "received_monotonic", attack_start, attack_end)
    rx_attack = _in_window([r for r in received if r["role"] == "attack"],
                           "received_monotonic", attack_start, attack_end)
    tx_legit = _in_window(legitimate_sent, "sent_monotonic", attack_start, attack_end)
    tx_attack = _in_window(attack_sent, "sent_monotonic", attack_start, attack_end)
    metrics = empty_metrics({
        "detection_delay_seconds": "Controller detection events are not exposed through a stable adapter.",
        "mitigation_delay_seconds": "Confirmed enforcement timestamps are not collected; controller log text is not treated as confirmation.",
        "false_positive_count": "Per-source controller decision events are not available for this configuration.",
    })
    legitimate = traffic_metrics(
        len(tx_legit), len(rx_legit), len(rx_legit) * PAYLOAD_BYTES,
        windows["attack"],
    )
    metrics.update(legitimate)
    latency_samples = [
        (float(row["received_monotonic"]) - float(row["sent_monotonic"])) * 1000
        for row in rx_legit
    ]
    clock_resolution_ms = time.get_clock_info("monotonic").resolution * 1000
    metrics["latency_ms"] = latency_metric(latency_samples, clock_resolution_ms)
    metrics["attack_throughput_mbps"] = metric_record(
        len(rx_attack) * PAYLOAD_BYTES * 8 / windows["attack"] / 1_000_000
    )

    baseline_start = t0
    baseline_packets = [r for r in received if r["role"] == "legitimate"
                        and baseline_start <= float(r["received_monotonic"]) < attack_start]
    baseline_mbps = (len(baseline_packets) * PAYLOAD_BYTES * 8 /
                     windows["baseline"] / 1_000_000)
    recovery_samples = []
    for second in range(int(windows["recovery"])):
        left = attack_end + second
        right = left + 1
        packets = [r for r in received if r["role"] == "legitimate"
                   and left <= float(r["received_monotonic"]) < right]
        recovery_samples.append((left, len(packets) * PAYLOAD_BYTES * 8 / 1_000_000))
    metrics["recovery_time_seconds"] = recovery_time_metric(
        recovery_samples, attack_end, baseline_mbps
    )
    # Sent counts are retained in trial evidence; PDR/loss are explicitly for
    # legitimate packets received/offered in the attack window.
    return metrics


def phase_boundaries(start, windows):
    """Return unambiguous monotonic half-open boundaries for each phase."""
    boundaries = {}
    cursor = float(start)
    for name in ("baseline", "attack", "recovery"):
        end = cursor + float(windows[name])
        boundaries[name] = {"start_monotonic": cursor, "end_monotonic": end,
                            "duration_seconds": float(windows[name])}
        cursor = end
    return boundaries


def safety_phase_boundaries(t0, *, attack_end, severe_start, severe_end,
                            recovery_start, recovery_end, normal_start,
                            normal_end, normal_duration,
                            normal_confirmation_end):
    """Build non-overlapping safety phase windows from observed gate times."""
    baseline_end = t0 + SAFETY_WINDOWS["baseline"]

    def record(start, end, status="measured"):
        return {"start_monotonic": float(start), "end_monotonic": float(end),
                "duration_seconds": float(end - start), "status": status}

    result = {
        "baseline": record(t0, baseline_end),
        "transient_attack": record(baseline_end, attack_end),
        "severe_transition_wait": record(attack_end, severe_start,
                                          "controller_state_wait"),
        "severe_throttle_measurement": record(severe_start, severe_end),
        "reputation_recovery": record(recovery_start, recovery_end),
        "normal_state_confirmation_wait": record(
            recovery_end, normal_start if normal_start is not None else normal_confirmation_end,
            "controller_trace_and_AP2_REMOVE_ack_wait"),
    }
    if normal_start is not None and normal_end is not None:
        result["post_recovery_normal_measurement"] = record(normal_start, normal_end)
    else:
        result["post_recovery_normal_measurement"] = {
            "start_monotonic": None, "end_monotonic": None,
            "duration_seconds": float(normal_duration), "status": "unavailable",
            "explanation": "No exact final NORMAL decision trace plus AP2 REMOVE barrier confirmation was observed before the bounded timeout.",
        }
    return result


def _phase_traffic_counts(received, legitimate_sent, attack_sent, telemetry_sent,
                          boundaries):
    counts = {}
    for name, bounds in boundaries.items():
        start, end = bounds["start_monotonic"], bounds["end_monotonic"]
        rx = _in_window(received, "received_monotonic", start, end)
        legit_tx = _in_window(legitimate_sent, "sent_monotonic", start, end)
        attack_tx = _in_window(attack_sent, "sent_monotonic", start, end)
        counts[name] = {
            "data_plane": {
                "legitimate_sent": len(legit_tx),
                "legitimate_received": sum(row["role"] == "legitimate" for row in rx),
                "attack_sent": len(attack_tx),
                "attack_received": sum(row["role"] == "attack" for row in rx),
                "attack_received_payload_bytes": sum(
                    int(row["payload_bytes"]) for row in rx if row["role"] == "attack"
                ),
            },
            "safety_telemetry_sent": sum(
                start <= float(row["sent_monotonic"]) < end for row in telemetry_sent
            ),
            "safety_telemetry_decisions_observed": {
                "value": None,
                "explanation": "Methodology 3 logs do not include the sender sequence or phase tag.",
            },
        }
    return counts


def _data_plane_interval_metrics(received, attack_sent, start, end):
    """Measure attack probe over a half-open monotonic interval.

    Throughput counts attack packets received inside the interval. Delivery/loss
    is joined by sender sequence for packets offered inside the interval, with
    receiver records from the entire trial (including boundary-late arrivals).
    """
    duration = float(end) - float(start)
    if duration <= 0:
        raise ValueError("measurement interval must have positive duration")
    sent = _in_window(attack_sent, "sent_monotonic", start, end)
    sent_sequences = {int(row["sequence"]) for row in sent}
    attack_received = [row for row in received if row["role"] == "attack"]
    received_during = _in_window(attack_received, "received_monotonic", start, end)
    delivered = {int(row["sequence"]) for row in attack_received
                 if int(row["sequence"]) in sent_sequences}
    delivery = traffic_metrics(len(sent), len(delivered), None, None)
    received_bytes = sum(int(row["payload_bytes"]) for row in received_during)
    return {
        "start_monotonic": float(start), "end_monotonic": float(end),
        "duration_seconds": duration,
        "attack_packets_sent": len(sent),
        "attack_packets_received_during_interval": len(received_during),
        "attack_packets_delivered_from_interval_sends": len(delivered),
        "attack_payload_bytes_received_during_interval": received_bytes,
        "attack_throughput_mbps": received_bytes * 8 / duration / 1_000_000,
        "packet_delivery_ratio": delivery["packet_delivery_ratio"],
        "packet_loss_ratio": delivery["packet_loss_ratio"],
        "counting_definition": (
            "Throughput uses receiver timestamps inside the interval. PDR/loss "
            "joins interval sends to receiver sequence IDs across the complete trial."
        ),
    }


def _decision_events(log_text):
    import re

    event_pattern = re.compile(
        r"Vehicle=sta3 switch=\d+ consistent=(True|False) reason=.*? "
        r"reputation=([0-9]+(?:\.[0-9]+)?) action=([A-Z_]+) kbps=(None|\d+)"
    )
    return [{
        "consistent": match.group(1) == "True",
        "reputation": float(match.group(2)), "action": match.group(3),
        "rate_limit_kbps": None if match.group(4) == "None" else int(match.group(4)),
    } for match in event_pattern.finditer(log_text)]


def _expected_decisions(trace):
    return [{key: item[key] for key in (
        "consistent", "reputation", "action", "rate_limit_kbps")}
        for item in trace]


def _decisions_match(observed, expected):
    if len(observed) < len(expected):
        return False
    for got, want in zip(observed, expected):
        if (got["consistent"] != want["consistent"]
                or got["action"] != want["action"]
                or got["rate_limit_kbps"] != want["rate_limit_kbps"]
                or round(got["reputation"], 2) != round(want["reputation"], 2)):
            return False
    return True


def _confirmed_meter_operations(log_text):
    import re

    request_re = re.compile(
        r"Enforcement requested: switch=(\d+) vehicle=sta3 op=([A-Z_]+) kbps=(None|\d+)"
    )
    confirm_re = re.compile(
        r"Enforcement confirmed: switch=(\d+) vehicle=sta3 op=([A-Z_]+)"
    )
    pending = {}
    confirmed = []
    for line in log_text.splitlines():
        request = request_re.search(line)
        if request:
            switch, operation, rate = request.groups()
            pending.setdefault((int(switch), operation), []).append(
                None if rate == "None" else int(rate))
            continue
        confirmation = confirm_re.search(line)
        if confirmation:
            switch, operation = int(confirmation.group(1)), confirmation.group(2)
            rates = pending.get((switch, operation), [])
            rate = rates.pop(0) if rates else None
            confirmed.append({"switch": switch, "operation": operation,
                              "rate_limit_kbps": rate})
    return confirmed


def _wait_for_severe_enforcement(process, log_path, expected_prefix, ap2_dpid,
                                 timeout=10.0, clock=time.monotonic,
                                 sleep=time.sleep):
    deadline = clock() + timeout
    while clock() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Methodology 3 exited before severe meter confirmation")
        try:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        observed = _decision_events(log_text)
        confirmations = _confirmed_meter_operations(log_text)
        severe_decision = _decisions_match(observed, expected_prefix)
        severe_meter = any(item["switch"] == int(ap2_dpid)
                            and item["rate_limit_kbps"] == 100
                            for item in confirmations)
        if severe_decision and severe_meter:
            return {"decision_trace_prefix_verified": True,
                    "ap2_severe_meter_acknowledged": True,
                    "controller_decisions_observed": len(observed),
                    "ap2_confirmed_operations": [item for item in confirmations
                                                  if item["switch"] == int(ap2_dpid)]}
        sleep(min(0.1, max(0.0, deadline - clock())))
    raise TimeoutError("severe decision and AP2 100-kbps meter were not both confirmed")


def _wait_for_normal_state(process, log_path, expected_trace, ap2_dpid,
                           timeout=5.0, clock=time.monotonic,
                           sleep=time.sleep):
    deadline = clock() + timeout
    expected = _expected_decisions(expected_trace)
    while clock() < deadline:
        if process.poll() is not None:
            return None
        try:
            log_text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            log_text = ""
        observed = _decision_events(log_text)
        confirmations = _confirmed_meter_operations(log_text)
        normal_decision = (len(observed) == len(expected)
                           and _decisions_match(observed, expected)
                           and observed[-1]["action"] == "NORMAL"
                           and observed[-1]["reputation"] >= 0.80)
        meter_removed = any(item["switch"] == int(ap2_dpid)
                            and item["operation"] == "REMOVE"
                            for item in confirmations)
        if normal_decision and meter_removed:
            return {"final_normal_decision_verified": True,
                    "ap2_remove_acknowledged": True,
                    "controller_decisions_observed": len(observed)}
        sleep(min(0.1, max(0.0, deadline - clock())))
    return None


def _sleep_until(target, *, clock=time.monotonic, sleep=time.sleep):
    while clock() < target:
        sleep(min(0.1, max(0.0, target - clock())))


def _parse_methodology3_log(log_text, expected_trace):
    import re
    observed = _decision_events(log_text)
    expected = _expected_decisions(expected_trace)
    exact_trace = len(observed) == len(expected) and _decisions_match(observed, expected)
    requested = [{"switch": int(switch), "operation": operation,
                  "rate_limit_kbps": None if rate == "None" else int(rate)}
                 for switch, operation, rate in re.findall(
                     r"Enforcement requested: switch=(\d+) vehicle=sta3 "
                     r"op=([A-Z_]+) kbps=(None|\d+)", log_text)]
    observed_transitions = []
    previous = None
    for index, item in enumerate(observed):
        if item["action"] != previous:
            observed_transitions.append({"observed_decision_index": index,
                                         "reputation": item["reputation"],
                                         "action": item["action"]})
            previous = item["action"]
    confirmations = _confirmed_meter_operations(log_text)
    return {
        "decisions_observed": len(observed),
        "decisions_expected": len(expected),
        "decision_trace_matches_expected": exact_trace,
        "observed_decision_trace": observed,
        "expected_action_transitions": expected_action_transitions(expected_trace),
        "observed_action_transitions": observed_transitions,
        "enforcement_requests": requested,
        "enforcement_confirmations": confirmations,
        "enforcement_confirmation_explanation": (
            "Controller logs report barrier-confirmed operations; this is distinct "
            "from PacketIn decisions and from measured data-plane throughput."
        ),
    }


def _wait_methodology3_ready(process, log_path, expected_dpids,
                             require_wireless_dpids=(), timeout=20.0,
                             clock=time.monotonic, sleep=time.sleep):
    import re

    expected = {int(dpid) for dpid in expected_dpids}
    deadline = clock() + timeout
    while clock() < deadline:
        if process.poll() is not None:
            raise RuntimeError("Methodology 3 exited before switch pipelines became ready")
        try:
            text = log_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            text = ""
        ready = set()
        wireless_discovered = set()
        for line in text.splitlines():
            discovered = re.search(r"Wireless ports discovered: switch=(\d+)", line)
            if discovered:
                dpid = int(discovered.group(1))
                wireless_discovered.add(dpid)
                ready.discard(dpid)
            pipeline = re.search(r"Switch pipeline ready: (\d+)", line)
            if pipeline:
                ready.add(int(pipeline.group(1)))
        required_wireless = {int(dpid) for dpid in require_wireless_dpids}
        if expected.issubset(ready) and required_wireless.issubset(wireless_discovered):
            return
        sleep(0.2)
    raise TimeoutError("Methodology 3 did not confirm every switch pipeline ready")


def _write_metrics_csv(path, metrics):
    with path.open("x", newline="", encoding="utf-8") as stream:
        writer = csv.writer(stream)
        writer.writerow(("metric", "value", "explanation"))
        for name, item in metrics.items():
            writer.writerow((name, item.get("value"), item.get("explanation")))


def _stop_process(process):
    if process is None:
        return
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)


def run_live_trial(root, run_spec, artifact_dir, *, ryu_manager="ryu-manager",
                   controller_port=6653, process_factory=subprocess.Popen,
                   topology_factory=create_topology, topology_starter=start_topology,
                   clock=time.monotonic, sleep=time.sleep,
                   host_check=_require_live_host):
    """Run exactly one volumetric UDP trial; requires root on Ubuntu/Linux."""
    root, artifact_dir = Path(root).resolve(), Path(artifact_dir).resolve()
    host_check()
    if run_spec.workload != "volumetric_udp":
        raise ValueError("live runner supports only volumetric_udp")
    if run_spec.configuration not in LIVE_CONFIGURATIONS:
        raise ValueError(f"unsupported live configuration: {run_spec.configuration}")
    if controller_port < 1 or controller_port > 65535:
        raise ValueError("controller port must be in 1..65535")
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stem = run_spec.run_id
    paths = {suffix: artifact_dir / f"{stem}.{suffix}" for suffix in (
        "raw.log", "metrics.json", "metrics.csv", "environment.json",
        "receiver.csv", "legitimate-sender.csv", "attack-sender.csv",
        "controller.log",
    )}
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite benchmark artifacts: " + ", ".join(existing))

    command, cwd = controller_command(root, run_spec.configuration,
                                      ryu_manager, controller_port)
    executable = shutil.which(command[0]) if not Path(command[0]).is_absolute() else command[0]
    if not executable:
        raise FileNotFoundError(f"Ryu manager executable not found: {command[0]}")
    command[0] = executable
    controller_output = paths["controller.log"].open("x", encoding="utf-8")
    controller = None
    handles = None
    agent_processes = []
    try:
        controller = process_factory(command, cwd=str(cwd), stdout=controller_output,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        _wait_controller(controller, ("127.0.0.1", controller_port), clock=clock,
                         sleep=sleep)
        handles = topology_factory(controller_ip="127.0.0.1",
                                   controller_port=controller_port)
        topology_starter(handles)

        agent = str(root / "benchmark" / "workload_agent.py")
        receiver = handles.stations["sta2"].popen([
            sys.executable, agent, "receive", "--bind", "10.0.0.2", "--port",
            str(UDP_PORT), "--duration", str(sum(WINDOWS.values()) + 2),
            "--output", str(paths["receiver.csv"]),
        ])
        agent_processes.append(receiver)
        ready_deadline = clock() + 5
        while clock() < ready_deadline:
            if receiver.poll() is not None:
                raise RuntimeError("receiver workload process exited during startup")
            try:
                with paths["receiver.csv"].open(encoding="utf-8") as stream:
                    if stream.readline().startswith("received_monotonic,"):
                        break
            except OSError:
                pass
            sleep(0.05)
        else:
            raise TimeoutError("receiver did not become ready")

        # Shared monotonic launch time lets both namespace-local senders use
        # the same phase boundaries, independent of subprocess startup order.
        t0 = clock() + 1.0
        legitimate = handles.stations["sta1"].popen([
            sys.executable, agent, "send", "--source", "10.0.0.1", "--destination",
            "10.0.0.2", "--port", str(UDP_PORT), "--role", "legitimate", "--pps",
            "20", "--delay", "0", "--start-at", str(t0), "--duration",
            str(sum(WINDOWS.values())),
            "--output", str(paths["legitimate-sender.csv"]),
        ])
        attack = handles.stations["sta3"].popen([
            sys.executable, agent, "send", "--source", "10.0.0.3", "--destination",
            "10.0.0.2", "--port", str(UDP_PORT), "--role", "attack", "--pps",
            "500", "--delay", str(WINDOWS["baseline"]), "--start-at", str(t0), "--duration",
            str(WINDOWS["attack"]), "--output", str(paths["attack-sender.csv"]),
        ])
        agent_processes.extend((legitimate, attack))
        sleep(sum(WINDOWS.values()) + 3)
        if controller.poll() is not None:
            raise RuntimeError("Ryu controller exited during the workload")
        for process in agent_processes:
            if process.wait(timeout=5) != 0:
                raise RuntimeError("a namespace-local workload process failed")

        received = _read_csv(paths["receiver.csv"])
        legitimate_sent = _read_csv(paths["legitimate-sender.csv"])
        attack_sent = _read_csv(paths["attack-sender.csv"])
        metrics = _trial_metrics(received, legitimate_sent, attack_sent, t0)
        metadata = {
            "platform": platform.platform(), "python": sys.version,
            "benchmark_phase": 2, "live_run": True,
            "host_clock": "Python monotonic clock shared by local namespaces",
            "ryu_manager": executable, "controller_command": command,
            "controller": run_spec.configuration,
            "runtime_topology_checks": "start_topology completed successfully",
            "workload": {"port": UDP_PORT, "payload_bytes": PAYLOAD_BYTES,
                         "legitimate_pps": 20, "attack_pps": 500,
                         "windows_seconds": WINDOWS},
            "measurement_anchor_monotonic": t0,
            "versions": {"ryu": None, "mininet_wifi": None, "ovs": None,
                         "explanation": "Version probes are not yet implemented."},
        }
        raw = (
            "Controller stdout/stderr is in controller.log.\n"
            f"Receiver records: {len(received)}\n"
            f"Legitimate sender records: {len(legitimate_sent)}\n"
            f"Attack sender records: {len(attack_sent)}\n"
            "Receiver/sender CSV files are the per-packet raw evidence.\n"
        )
        # Exclusive creation protects pre-existing files, including across runs.
        with paths["raw.log"].open("x", encoding="utf-8") as stream:
            stream.write(raw)
        with paths["metrics.json"].open("x", encoding="utf-8") as stream:
            json.dump({"run": run_spec.__dict__, "metrics": metrics}, stream,
                      indent=2, sort_keys=True)
            stream.write("\n")
        _write_metrics_csv(paths["metrics.csv"], metrics)
        with paths["environment.json"].open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, sort_keys=True)
            stream.write("\n")
        return {"run_id": stem, "status": "completed",
                "artifacts": {key: str(path) for key, path in paths.items()},
                "metrics": metrics}
    finally:
        for process in reversed(agent_processes):
            _stop_process(process)
        if handles is not None:
            try:
                handles.net.stop()
            except Exception:
                pass
        _stop_process(controller)
        controller_output.close()


def run_methodology3_safety_trial(
        root, run_spec, artifact_dir, *, ryu_manager="ryu-manager",
        controller_port=6653, process_factory=subprocess.Popen,
        topology_factory=create_topology, topology_starter=start_topology,
        clock=time.monotonic, sleep=time.sleep, host_check=_require_live_host,
        pipeline_waiter=_wait_methodology3_ready,
        severe_measurement_seconds=10.0, normal_measurement_seconds=10.0,
        severe_transition_timeout=SEVERE_TRANSITION_TIMEOUT_SECONDS,
        normal_confirmation_timeout=NORMAL_CONFIRMATION_TIMEOUT_SECONDS):
    """Run one bounded M3 consistency/reputation trial with a data-plane probe."""
    root, artifact_dir = Path(root).resolve(), Path(artifact_dir).resolve()
    host_check()
    if run_spec.workload != "safety_consistency" or run_spec.configuration != "methodology3":
        raise ValueError("M3 live trial requires safety_consistency/methodology3")
    if not 1 <= controller_port <= 65535:
        raise ValueError("controller port must be in 1..65535")
    for name, value in (("severe measurement", severe_measurement_seconds),
                        ("normal measurement", normal_measurement_seconds)):
        if not 0 < float(value) <= MAX_STEADY_MEASUREMENT_SECONDS:
            raise ValueError(f"{name} interval must be in (0, {MAX_STEADY_MEASUREMENT_SECONDS}] seconds")

    # Preflight the exact trace against Methodology 3's checker and reputation
    # engine before any controller or Mininet process is started.
    expected_trace = build_safety_sequence(
        root, baseline_seconds=SAFETY_WINDOWS["baseline"],
        attack_seconds=SAFETY_WINDOWS["attack"],
        severe_transition_seconds=severe_transition_timeout,
        severe_measurement_seconds=severe_measurement_seconds,
        recovery_valid_count=200, recovery_pps=SAFETY_RECOVERY_PPS,
    )
    artifact_dir.mkdir(parents=True, exist_ok=True)
    stem = run_spec.run_id
    paths = {suffix: artifact_dir / f"{stem}.{suffix}" for suffix in (
        "raw.log", "metrics.json", "metrics.csv", "environment.json",
        "receiver.csv", "legitimate-sender.csv", "attack-sender.csv",
        "safety-telemetry.csv", "controller.log", "phase-coordination.json",
    )}
    existing = [str(path) for path in paths.values() if path.exists()]
    if existing:
        raise FileExistsError("refusing to overwrite benchmark artifacts: " + ", ".join(existing))

    command, cwd = controller_command(root, "methodology3", ryu_manager,
                                      controller_port)
    executable = shutil.which(command[0]) if not Path(command[0]).is_absolute() else command[0]
    if not executable:
        raise FileNotFoundError(f"Ryu manager executable not found: {command[0]}")
    command[0] = executable
    controller_output = paths["controller.log"].open("x", encoding="utf-8")
    controller = None
    handles = None
    agent_processes = []
    network_stopped = False
    controller_stopped = False
    output_closed = False
    try:
        controller = process_factory(command, cwd=str(cwd), stdout=controller_output,
                                     stderr=subprocess.STDOUT, start_new_session=True)
        _wait_controller(controller, ("127.0.0.1", controller_port), clock=clock,
                         sleep=sleep)
        handles = topology_factory(controller_ip="127.0.0.1",
                                   controller_port=controller_port)
        topology_starter(handles)
        expected_dpids = [int(values["dpid"], 16)
                          for values in handles.spec["access_points"].values()]
        expected_dpids.append(int(handles.spec["switch"]["dpid"], 16))
        ap_dpids = [int(values["dpid"], 16)
                    for values in handles.spec["access_points"].values()]
        pipeline_waiter(controller, paths["controller.log"], expected_dpids,
                        require_wireless_dpids=ap_dpids,
                        clock=clock, sleep=sleep)

        agent = str(root / "benchmark" / "workload_agent.py")
        maximum_total_seconds = (
            SAFETY_WINDOWS["baseline"] + SAFETY_WINDOWS["attack"]
            + severe_transition_timeout + severe_measurement_seconds
            + SAFETY_WINDOWS["recovery"] + normal_confirmation_timeout
            + normal_measurement_seconds
        )
        receiver = handles.stations["sta2"].popen([
            sys.executable, agent, "receive", "--bind", "10.0.0.2", "--port",
            str(UDP_PORT), "--duration", str(maximum_total_seconds + 3),
            "--output", str(paths["receiver.csv"]),
        ])
        agent_processes.append(receiver)
        ready_deadline = clock() + 5
        while clock() < ready_deadline:
            if receiver.poll() is not None:
                raise RuntimeError("receiver workload process exited during startup")
            try:
                with paths["receiver.csv"].open(encoding="utf-8") as stream:
                    if stream.readline().startswith("received_monotonic,"):
                        break
            except OSError:
                pass
            sleep(0.05)
        else:
            raise TimeoutError("receiver did not become ready")

        t0 = clock() + 1.0
        legitimate = handles.stations["sta1"].popen([
            sys.executable, agent, "send", "--source", "10.0.0.1", "--destination",
            "10.0.0.2", "--port", str(UDP_PORT), "--role", "legitimate", "--pps",
            "20", "--delay", "0", "--start-at", str(t0), "--duration",
            str(maximum_total_seconds), "--output", str(paths["legitimate-sender.csv"]),
        ])
        attack_duration = maximum_total_seconds - SAFETY_WINDOWS["baseline"]
        attack = handles.stations["sta3"].popen([
            sys.executable, agent, "send", "--source", "10.0.0.3", "--destination",
            "10.0.0.2", "--port", str(UDP_PORT), "--role", "attack", "--pps",
            "500", "--delay", str(SAFETY_WINDOWS["baseline"]), "--start-at",
            str(t0), "--duration", str(attack_duration),
            "--output", str(paths["attack-sender.csv"]),
        ])
        telemetry = handles.stations["sta3"].popen([
            sys.executable, agent, "safety", "--source", "10.0.0.3",
            "--destination", "10.0.0.2", "--port", "5005",
            "--repository-root", str(root), "--start-at", str(t0),
            "--baseline", str(SAFETY_WINDOWS["baseline"]), "--attack",
            str(SAFETY_WINDOWS["attack"]), "--recovery",
            str(SAFETY_WINDOWS["recovery"]), "--severe-transition",
            str(severe_transition_timeout), "--severe-measurement",
            str(severe_measurement_seconds), "--recovery-gate",
            str(paths["phase-coordination.json"]), "--gate-timeout",
            str(severe_transition_timeout + severe_measurement_seconds + 5),
            "--recovery-pps",
            str(SAFETY_RECOVERY_PPS), "--output", str(paths["safety-telemetry.csv"]),
        ])
        agent_processes.extend((legitimate, attack, telemetry))

        baseline_end = t0 + SAFETY_WINDOWS["baseline"]
        transient_attack_start = baseline_end
        transient_attack_end = transient_attack_start + SAFETY_WINDOWS["attack"]
        _sleep_until(transient_attack_end, clock=clock, sleep=sleep)
        attack_decision_count = sum(item["phase"] != "recovery"
                                    for item in expected_trace)
        severe_evidence = _wait_for_severe_enforcement(
            controller, paths["controller.log"],
            _expected_decisions(expected_trace[:attack_decision_count]),
            int(handles.spec["access_points"]["ap2"]["dpid"], 16),
            timeout=severe_transition_timeout, clock=clock, sleep=sleep,
        )
        severe_start = clock()
        severe_end = severe_start + severe_measurement_seconds
        _sleep_until(severe_end, clock=clock, sleep=sleep)

        recovery_start = clock()
        with paths["phase-coordination.json"].open("x", encoding="utf-8") as gate:
            json.dump({"recovery_start_monotonic": recovery_start}, gate)
            gate.write("\n")
            gate.flush()
        recovery_end = recovery_start + SAFETY_WINDOWS["recovery"]
        _sleep_until(recovery_end, clock=clock, sleep=sleep)
        if controller.poll() is not None:
            raise RuntimeError("Methodology 3 exited during the workload")

        normal_confirmation = _wait_for_normal_state(
            controller, paths["controller.log"], expected_trace,
            int(handles.spec["access_points"]["ap2"]["dpid"], 16),
            timeout=normal_confirmation_timeout, clock=clock, sleep=sleep,
        )
        normal_start = clock() if normal_confirmation is not None else None
        normal_end = (normal_start + normal_measurement_seconds
                      if normal_start is not None else None)
        if normal_end is not None:
            _sleep_until(normal_end, clock=clock, sleep=sleep)
        if telemetry.wait(timeout=5) != 0:
            raise RuntimeError("safety telemetry sender failed")

        # The two data senders are intentionally bounded to the latest possible
        # phase end; terminate their remaining tail after a short successful run.
        for process in (attack, legitimate, receiver):
            _stop_process(process)
        if controller.poll() is not None:
            raise RuntimeError("Methodology 3 exited during the workload")

        handles.net.stop()
        network_stopped = True
        _stop_process(controller)
        controller_stopped = True
        controller_output.flush()
        controller_output.close()
        output_closed = True

        received = _read_csv(paths["receiver.csv"])
        legitimate_sent = _read_csv(paths["legitimate-sender.csv"])
        attack_sent = _read_csv(paths["attack-sender.csv"])
        telemetry_sent = _read_csv(paths["safety-telemetry.csv"])
        metrics = _trial_metrics(received, legitimate_sent, attack_sent, t0,
                                 windows=SAFETY_WINDOWS)
        metrics["detection_delay_seconds"] = {
            "value": None,
            "explanation": "Controller decision logs have no monotonic event timestamp mapped to the trial clock.",
        }
        metrics["mitigation_delay_seconds"] = {
            "value": None,
            "explanation": "Barrier-confirmed operations are logged, but their timestamps are not mapped to the trial monotonic clock; acknowledgement is not packet-level mitigation confirmation.",
        }
        metrics["recovery_time_seconds"] = {
            "value": None,
            "explanation": "Legitimate throughput was not impaired, so zero would misstate recovery. Reputation recovery is verified separately from decision logs; its event time is not mapped to the runner monotonic clock.",
        }
        metrics["false_positive_count"] = {
            "value": None,
            "explanation": "No independent false-positive oracle or per-source false restriction measurement is collected.",
        }

        boundaries = safety_phase_boundaries(
            t0, attack_end=transient_attack_end,
            severe_start=severe_start, severe_end=severe_end,
            recovery_start=recovery_start, recovery_end=recovery_end,
            normal_start=normal_start, normal_end=normal_end,
            normal_duration=normal_measurement_seconds,
            normal_confirmation_end=clock(),
        )

        count_boundaries = {name: value for name, value in boundaries.items()
                            if value.get("start_monotonic") is not None}
        phase_counts = _phase_traffic_counts(received, legitimate_sent,
                                             attack_sent, telemetry_sent,
                                             count_boundaries)
        if normal_start is None:
            phase_counts["post_recovery_normal_measurement"] = {
                "status": "unavailable",
                "explanation": boundaries["post_recovery_normal_measurement"]["explanation"],
                "data_plane": {"attack_sent": None, "attack_received": None,
                               "attack_received_payload_bytes": None},
                "safety_telemetry_sent": 0,
                "safety_telemetry_decisions_observed": {
                    "value": None,
                    "explanation": "Normal operation was not confirmed; no normal measurement interval was started.",
                },
            }
        measurements = {
            "transient_attack": _data_plane_interval_metrics(
                received, attack_sent, transient_attack_start, transient_attack_end),
            "severe_throttle": _data_plane_interval_metrics(
                received, attack_sent, severe_start, severe_end),
            "post_recovery_normal": (
                _data_plane_interval_metrics(received, attack_sent,
                                             normal_start, normal_end)
                if normal_start is not None else {
                    "available": False,
                    "explanation": boundaries["post_recovery_normal_measurement"]["explanation"],
                    "start_monotonic": None, "end_monotonic": None,
                    "duration_seconds": float(normal_measurement_seconds),
                    "attack_packets_sent": None,
                    "attack_packets_received_during_interval": None,
                    "attack_packets_delivered_from_interval_sends": None,
                    "attack_payload_bytes_received_during_interval": None,
                    "attack_throughput_mbps": None,
                    "packet_delivery_ratio": None, "packet_loss_ratio": None,
                }
            ),
        }
        for phase_name, interval in measurements.items():
            for metric_name in (
                "start_monotonic", "end_monotonic", "duration_seconds",
                "attack_packets_sent", "attack_packets_received_during_interval",
                "attack_packets_delivered_from_interval_sends",
                "attack_payload_bytes_received_during_interval",
                "attack_throughput_mbps",
            ):
                value = interval.get(metric_name)
                explanation = interval.get("explanation") if value is None else None
                metrics[f"{phase_name}_{metric_name}"] = metric_record(value, explanation)
            for ratio in ("packet_delivery_ratio", "packet_loss_ratio"):
                ratio_record = interval.get(ratio)
                metrics[f"{phase_name}_{ratio}"] = (
                    ratio_record if isinstance(ratio_record, dict)
                    else metric_record(ratio_record, interval.get("explanation"))
                )

        controller_log = paths["controller.log"].read_text(
            encoding="utf-8", errors="replace")
        observations = _parse_methodology3_log(controller_log, expected_trace)
        observations["telemetry_sender_records"] = len(telemetry_sent)
        observations["severe_measurement_readiness"] = severe_evidence
        observations["post_recovery_normal_readiness"] = normal_confirmation
        observations["decision_coverage"] = {
            "value": (observations["decisions_observed"] / len(telemetry_sent)
                      if telemetry_sent else None),
            "explanation": (None if telemetry_sent else "Telemetry sender produced no records."),
        }
        observations["trace_verification_limitation"] = (
            "The controller log does not include telemetry sequence IDs. An exact ordered trace match is strong evidence from one sender socket, but does not independently prove packet-by-packet identity."
        )
        observations["observation_status"] = (
            "verified_ordered_trace" if observations["decision_trace_matches_expected"]
            else "incomplete_or_mismatched_controller_trace"
        )
        metadata = {
            "platform": platform.platform(), "python": sys.version,
            "benchmark_phase": 2, "live_run": True,
            "controller": "methodology3",
            "controller_command": command, "controller_cwd": str(cwd),
            "host_clock": "Python monotonic clock shared by local namespaces",
            "runtime_topology_checks": "start_topology completed successfully",
            "workload": {
                "safety_telemetry": {"source": "10.0.0.3", "destination": "10.0.0.2",
                                     "port": 5005, "baseline_pps": SAFETY_RECOVERY_PPS,
                                     "recovery_pps": SAFETY_RECOVERY_PPS,
                                     "baseline_valid_count": sum(x["phase"] == "baseline" for x in expected_trace),
                                     "attack_invalid_count": 5,
                                     "recovery_valid_count": 200},
                "data_plane_probe": {"port": UDP_PORT, "payload_bytes": PAYLOAD_BYTES,
                                     "legitimate_pps": 20, "attack_pps": 500,
                                     "attack_sender_runs_during": [
                                         "transient_attack", "severe_throttle_measurement",
                                         "reputation_recovery", "post_recovery_normal_measurement",
                                     ]},
                "phase_windows_seconds": SAFETY_WINDOWS,
                "severe_transition_timeout_seconds": severe_transition_timeout,
                "severe_throttle_measurement_seconds": severe_measurement_seconds,
                "normal_measurement_seconds": normal_measurement_seconds,
                "normal_confirmation_timeout_seconds": normal_confirmation_timeout,
            },
            "phase_boundaries_monotonic": boundaries,
            "versions": {"ryu": None, "mininet_wifi": None, "ovs": None,
                         "explanation": "Version probes are not implemented."},
        }
        summary = {
            "run_id": stem, "phase_boundaries_monotonic": boundaries,
            "traffic_counts_by_phase": phase_counts,
            "data_plane_measurement_intervals": measurements,
            "controller_observations": observations,
            "decision_vs_enforcement_note": (
                "Vehicle decision records, enforcement requests, barrier confirmations, and receiver-observed data-plane counts are separate evidence streams."
            ),
        }
        with paths["raw.log"].open("x", encoding="utf-8") as stream:
            stream.write(json.dumps(summary, indent=2, sort_keys=True) + "\n")
        with paths["metrics.json"].open("x", encoding="utf-8") as stream:
            json.dump({"run": run_spec.__dict__, "metrics": metrics,
                       "safety_consistency": summary}, stream,
                      indent=2, sort_keys=True)
            stream.write("\n")
        _write_metrics_csv(paths["metrics.csv"], metrics)
        with paths["environment.json"].open("x", encoding="utf-8") as stream:
            json.dump(metadata, stream, indent=2, sort_keys=True)
            stream.write("\n")
        complete = (observations["decision_trace_matches_expected"]
                    and normal_confirmation is not None)
        return {"run_id": stem,
                "status": ("completed" if complete
                           else "completed_observation_incomplete"),
                "artifacts": {key: str(path) for key, path in paths.items()},
                "metrics": metrics, "safety_consistency": summary}
    finally:
        for process in reversed(agent_processes):
            _stop_process(process)
        if handles is not None and not network_stopped:
            try:
                handles.net.stop()
            except Exception:
                pass
        if not controller_stopped:
            _stop_process(controller)
        if not output_closed:
            controller_output.close()
