import tempfile
import io
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

from benchmark.core import generate_matrix
from benchmark import live_trial, run_benchmark
from benchmark.safety_workload import build_safety_sequence


ROOT = Path(__file__).resolve().parents[2]


class _Process:
    def __init__(self, stdout=None):
        self.stdout = stdout
        self.finished = False
        self.terminated = False

    def poll(self):
        return 0 if self.finished else None

    def wait(self, timeout=None):
        self.finished = True
        return 0

    def terminate(self):
        self.terminated = True
        self.finished = True


class _Net:
    def __init__(self):
        self.stop_count = 0

    def stop(self):
        self.stop_count += 1


class _Node:
    def popen(self, command):
        return _Process()


class _Handles:
    def __init__(self):
        self.stations = {name: _Node() for name in ("sta1", "sta2", "sta3")}
        self.net = _Net()
        from benchmark.topology_spec import TOPOLOGY_SPEC
        self.spec = TOPOLOGY_SPEC


def _safety_run():
    return next(item for item in generate_matrix(
        2026, 1, workloads=("safety_consistency",))
        if item.configuration == "methodology3")


class SafetyWorkloadTest(unittest.TestCase):
    def test_trace_uses_real_checker_and_reputation_and_recovers(self):
        trace = build_safety_sequence(ROOT)
        self.assertEqual(sum(item["phase"] == "baseline" for item in trace), 150)
        attack = [item for item in trace if item["phase"] == "attack"]
        recovery = [item for item in trace if item["phase"] == "recovery"]
        self.assertEqual(len(attack), 5)
        self.assertTrue(all(not item["consistent"] and item["severity"] == 1.0
                            and item["reason"] == "Implausible vehicle displacement"
                            for item in attack))
        self.assertEqual(len(recovery), 200)
        self.assertTrue(all(item["consistent"] for item in recovery))
        self.assertTrue(all(right["timestamp"] > left["timestamp"]
                            for left, right in zip(trace, trace[1:])))
        self.assertGreaterEqual(trace[-1]["reputation"], 0.80)
        self.assertEqual(attack[-1]["action"], "SEVERE_THROTTLE")
        self.assertEqual(recovery[-1]["action"], "NORMAL")

    def test_trace_places_recovery_after_severe_measurement(self):
        trace = build_safety_sequence(
            ROOT, severe_transition_seconds=12.0,
            severe_measurement_seconds=11.0)
        first_recovery = next(item for item in trace if item["phase"] == "recovery")
        expected = 1_700_000_000.0 + 30.0 + 2.0 + 12.0 + 11.0
        self.assertAlmostEqual(first_recovery["timestamp"], expected)
        self.assertEqual(sum(item["phase"] == "attack" for item in trace), 5)
        self.assertEqual(sum(item["phase"] == "recovery" for item in trace), 200)

    def test_methodology3_controller_launch_uses_local_import_directory(self):
        command, cwd = live_trial.controller_command(
            ROOT, "methodology3", "ryu-manager", 6653)
        self.assertEqual(command[-1], str(ROOT / "Methodology3/controller.py"))
        self.assertEqual(cwd, ROOT / "Methodology3")

    def test_pipeline_ready_requires_wireless_discovery_and_post_discovery_barrier(self):
        with tempfile.TemporaryDirectory() as temp:
            log = Path(temp) / "controller.log"
            log.write_text(
                "Switch pipeline ready: 1\n"
                "Switch pipeline ready: 2\n"
                "Wireless ports discovered: switch=1 ports=[1]\n"
                "Switch pipeline ready: 1\n",
                encoding="utf-8",
            )
            live_trial._wait_methodology3_ready(
                _Process(), log, [1, 2], require_wireless_dpids=[1],
                timeout=0.1,
            )

    def test_controller_log_trace_is_compared_to_expected_decisions_and_acks(self):
        trace = build_safety_sequence(ROOT)
        lines = [
            "Vehicle=sta3 switch=1152921504606846978 consistent=%s reason=test "
            "reputation=%.2f action=%s kbps=%s" % (
                item["consistent"], item["reputation"], item["action"],
                item["rate_limit_kbps"] if item["rate_limit_kbps"] is not None else "None",
            ) for item in trace
        ]
        lines.extend((
            "Enforcement requested: switch=1 vehicle=sta3 op=ADD kbps=500",
            "Enforcement confirmed: switch=1 vehicle=sta3 op=ADD",
        ))
        observed = live_trial._parse_methodology3_log("\n".join(lines), trace)
        self.assertTrue(observed["decision_trace_matches_expected"])
        self.assertEqual(observed["decisions_observed"], len(trace))
        self.assertEqual(observed["enforcement_confirmations"],
                         [{"switch": 1, "operation": "ADD",
                           "rate_limit_kbps": 500}])
        self.assertEqual(observed["observed_action_transitions"][-1]["action"],
                         "NORMAL")

    def test_live_cli_routes_safety_consistency_only_to_m3_adapter(self):
        run = _safety_run()
        with patch.object(live_trial, "run_methodology3_safety_trial",
                          return_value={"status": "mocked"}) as m3:
            result = run_benchmark.execute_live_trial(
                ROOT, run, Path("artifacts"), ryu_manager="ryu-manager",
                controller_port=6653,
            )
        self.assertEqual(result["status"], "mocked")
        m3.assert_called_once()

    def test_cli_live_safety_selects_methodology3_and_workload(self):
        with redirect_stdout(io.StringIO()), \
             patch("benchmark.live_trial._require_live_host"), \
             patch("benchmark.run_benchmark.execute_live_trial",
                   return_value={"run_id": "safety", "status": "mocked"}) as execute:
            self.assertEqual(run_benchmark.main([
                "--live", "--workload", "safety_consistency",
                "--configuration", "methodology3", "--repetitions", "1",
                "--severe-measurement-seconds", "12",
                "--normal-measurement-seconds", "8",
            ]), 0)
        self.assertEqual(execute.call_args.args[1].workload, "safety_consistency")
        self.assertEqual(execute.call_args.args[1].configuration, "methodology3")
        self.assertEqual(execute.call_args.kwargs["severe_measurement_seconds"], 12.0)
        self.assertEqual(execute.call_args.kwargs["normal_measurement_seconds"], 8.0)

    def test_phase_boundaries_and_half_open_counts_are_unambiguous(self):
        windows = {"baseline": 10.0, "attack": 2.0, "recovery": 3.0}
        bounds = live_trial.phase_boundaries(100.0, windows)
        self.assertEqual(bounds["baseline"]["end_monotonic"], 110.0)
        self.assertEqual(bounds["attack"]["start_monotonic"], 110.0)
        received = [
            {"received_monotonic": "109.9", "role": "legitimate", "payload_bytes": "256"},
            {"received_monotonic": "110.0", "role": "attack", "payload_bytes": "256"},
            {"received_monotonic": "112.0", "role": "attack", "payload_bytes": "256"},
        ]
        counts = live_trial._phase_traffic_counts(received, [], [], [], bounds)
        self.assertEqual(counts["baseline"]["data_plane"]["attack_received"], 0)
        self.assertEqual(counts["attack"]["data_plane"]["attack_received"], 1)
        self.assertEqual(counts["recovery"]["data_plane"]["attack_received"], 1)
        self.assertIsNone(counts["attack"]["safety_telemetry_decisions_observed"]["value"])

    def test_phase_metric_uses_attack_window_not_recovery_window(self):
        windows = {"baseline": 30.0, "attack": 2.0, "recovery": 42.0}
        received = [
            {"received_monotonic": "130.1", "role": "attack",
             "payload_bytes": "256", "sent_monotonic": "130.0"},
            {"received_monotonic": "132.1", "role": "attack",
             "payload_bytes": "256", "sent_monotonic": "132.0"},
        ]
        attack_sent = [
            {"sent_monotonic": "130.0"}, {"sent_monotonic": "132.0"},
        ]
        result = live_trial._trial_metrics(received, [], attack_sent, 100.0,
                                           windows=windows)
        self.assertAlmostEqual(result["attack_throughput_mbps"]["value"],
                               256 * 8 / 2 / 1_000_000)

    def test_steady_intervals_are_separate_and_half_open(self):
        bounds = live_trial.safety_phase_boundaries(
            100.0, attack_end=132.0, severe_start=134.0, severe_end=144.0,
            recovery_start=144.0, recovery_end=186.0, normal_start=188.0,
            normal_end=198.0, normal_duration=10.0,
            normal_confirmation_end=188.0)
        self.assertEqual(bounds["transient_attack"]["start_monotonic"], 130.0)
        self.assertEqual(bounds["transient_attack"]["end_monotonic"], 132.0)
        self.assertEqual(bounds["severe_throttle_measurement"]["start_monotonic"], 134.0)
        self.assertEqual(bounds["reputation_recovery"]["start_monotonic"], 144.0)
        self.assertEqual(bounds["post_recovery_normal_measurement"]["start_monotonic"], 188.0)
        self.assertEqual(bounds["severe_throttle_measurement"]["status"], "measured")

    def test_probe_metrics_count_interval_receive_and_late_delivery_separately(self):
        sent = [
            {"sent_monotonic": "10.0", "sequence": "1"},
            {"sent_monotonic": "10.5", "sequence": "2"},
            {"sent_monotonic": "11.0", "sequence": "3"},
        ]
        received = [
            {"received_monotonic": "10.1", "role": "attack",
             "sequence": "1", "payload_bytes": "256"},
            {"received_monotonic": "11.1", "role": "attack",
             "sequence": "2", "payload_bytes": "256"},
            {"received_monotonic": "11.2", "role": "attack",
             "sequence": "3", "payload_bytes": "256"},
        ]
        result = live_trial._data_plane_interval_metrics(received, sent, 10.0, 11.0)
        self.assertEqual(result["attack_packets_sent"], 2)
        self.assertEqual(result["attack_packets_received_during_interval"], 1)
        self.assertEqual(result["attack_packets_delivered_from_interval_sends"], 2)
        self.assertEqual(result["packet_delivery_ratio"]["value"], 1.0)
        self.assertAlmostEqual(result["attack_throughput_mbps"], 256 * 8 / 1_000_000)

    def test_missing_normal_confirmation_marks_interval_unavailable(self):
        bounds = live_trial.safety_phase_boundaries(
            100.0, attack_end=132.0, severe_start=133.0, severe_end=143.0,
            recovery_start=143.0, recovery_end=185.0, normal_start=None,
            normal_end=None, normal_duration=10.0, normal_confirmation_end=190.0)
        normal = bounds["post_recovery_normal_measurement"]
        self.assertIsNone(normal["start_monotonic"])
        self.assertEqual(normal["status"], "unavailable")
        self.assertIn("NORMAL decision", normal["explanation"])

    def test_artifact_collision_refuses_to_overwrite_existing_evidence(self):
        run = _safety_run()
        with tempfile.TemporaryDirectory() as temp:
            artifact_dir = Path(temp)
            protected = artifact_dir / f"{run.run_id}.safety-telemetry.csv"
            protected.write_text("preserve this evidence\n", encoding="utf-8")
            with self.assertRaises(FileExistsError):
                live_trial.run_methodology3_safety_trial(
                    ROOT, run, artifact_dir, host_check=lambda: None)
            self.assertEqual(protected.read_text(encoding="utf-8"),
                             "preserve this evidence\n")

    def test_failure_after_controller_start_cleans_only_owned_resources(self):
        run = _safety_run()
        handles = _Handles()
        created = []
        launch_calls = []

        def process_factory(*args, **kwargs):
            process = _Process(kwargs.get("stdout"))
            created.append(process)
            launch_calls.append((args, kwargs))
            return process

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            (root / "Methodology3").mkdir()
            (root / "benchmark").mkdir()
            # The preflight checker must use this repo's Methodology 3 sources.
            with patch.object(live_trial, "_wait_controller"), \
                 patch.object(live_trial, "_wait_methodology3_ready"), \
                 patch.object(live_trial.shutil, "which", return_value="/fake/ryu-manager"):
                with self.assertRaisesRegex(RuntimeError, "topology startup failed"):
                    live_trial.run_methodology3_safety_trial(
                        ROOT, run, root / "artifacts", process_factory=process_factory,
                        topology_factory=lambda **kwargs: handles,
                        topology_starter=lambda value: (_ for _ in ()).throw(
                            RuntimeError("topology startup failed")),
                        host_check=lambda: None,
                    )
        self.assertEqual(handles.net.stop_count, 1)
        self.assertTrue(created[0].terminated)
        self.assertEqual(launch_calls[0][1]["cwd"], str(ROOT / "Methodology3"))
        self.assertEqual(launch_calls[0][0][0][3],
                         str(ROOT / "Methodology3/controller.py"))


if __name__ == "__main__":
    unittest.main()
