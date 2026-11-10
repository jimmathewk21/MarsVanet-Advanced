import csv
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from benchmark.core import generate_matrix
from benchmark import live_trial


class _Process:
    def __init__(self):
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


class _Node:
    def __init__(self, base):
        self.base = Path(base)

    def popen(self, command):
        process = _Process()
        output = Path(command[command.index("--output") + 1])
        if "receive" in command:
            header = ("received_monotonic", "source_ip", "role", "sequence",
                      "sent_monotonic", "payload_bytes")
        else:
            header = ("sent_monotonic", "source_ip", "role", "sequence",
                      "payload_bytes")
        with output.open("w", newline="", encoding="utf-8") as stream:
            csv.writer(stream).writerow(header)
        return process


class _Network:
    def __init__(self):
        self.stopped = False

    def stop(self):
        self.stopped = True


class _Handles:
    def __init__(self):
        self.stations = {name: _Node(".") for name in ("sta1", "sta2", "sta3")}
        self.net = _Network()


class LiveTrialTest(unittest.TestCase):
    def test_no_defense_uses_standard_ryu_forwarding_app(self):
        command, cwd = live_trial.controller_command(
            Path("/repo"), "no_defense", "ryu-manager", 6653)
        self.assertEqual(command[-1], "ryu.app.simple_switch_13")
        self.assertEqual(command[2], "6653")
        self.assertEqual(cwd, Path("/repo"))

    def test_receiver_metrics_derive_packet_counts_and_null_unobservable_events(self):
        t0 = 100.0
        received = [
            {"received_monotonic": "130.1", "sent_monotonic": "130.0",
             "role": "legitimate"},
            {"received_monotonic": "130.2", "role": "attack"},
            {"received_monotonic": "131.1", "sent_monotonic": "131.0",
             "role": "legitimate"},
        ]
        legitimate_sent = [
            {"sent_monotonic": "130.0"}, {"sent_monotonic": "131.0"},
        ]
        attack_sent = [{"sent_monotonic": "130.0"}]
        result = live_trial._trial_metrics(received, legitimate_sent, attack_sent, t0)
        self.assertAlmostEqual(result["packet_delivery_ratio"]["value"], 1.0)
        self.assertAlmostEqual(result["legitimate_throughput_mbps"]["value"],
                               2 * 256 * 8 / 60 / 1_000_000)
        self.assertAlmostEqual(result["attack_throughput_mbps"]["value"],
                               256 * 8 / 60 / 1_000_000)
        self.assertAlmostEqual(result["latency_ms"]["value"], 100.0)
        self.assertIsNotNone(result["latency_ms"]["clock_uncertainty_ms"])
        self.assertIsNone(result["detection_delay_seconds"]["value"])
        self.assertIsNone(result["mitigation_delay_seconds"]["value"])

    def test_mocked_vertical_slice_writes_artifacts_and_cleans_only_owned_processes(self):
        run = next(item for item in generate_matrix(7, 1, workloads=("volumetric_udp",))
                   if item.configuration == "no_defense")
        controller = _Process()
        handles = _Handles()
        calls = []

        def process_factory(*args, **kwargs):
            calls.append((args, kwargs))
            return controller

        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            benchmark_dir = root / "benchmark"
            benchmark_dir.mkdir()
            (benchmark_dir / "workload_agent.py").write_text("# fake\n", encoding="utf-8")
            output = benchmark_dir / "artifacts"
            with patch.object(live_trial, "_wait_controller") as wait_controller, \
                 patch.object(live_trial.shutil, "which", return_value="/fake/ryu-manager"):
                result = live_trial.run_live_trial(
                    root, run, output, process_factory=process_factory,
                    topology_factory=lambda **kwargs: handles,
                    topology_starter=lambda value: value,
                    host_check=lambda: None, sleep=lambda _: None,
                )
            wait_controller.assert_called_once()
            self.assertEqual(result["status"], "completed")
            self.assertTrue(handles.net.stopped)
            self.assertTrue(controller.terminated)
            self.assertEqual(len(calls), 1)
            for name in ("raw.log", "metrics.json", "metrics.csv", "environment.json",
                         "receiver.csv", "legitimate-sender.csv", "attack-sender.csv",
                         "controller.log"):
                self.assertTrue((output / f"{run.run_id}.{name}").exists(), name)

    def test_safety_consistency_is_rejected_as_unsupported(self):
        run = next(item for item in generate_matrix(7, 1,
                                                    workloads=("safety_consistency",))
                   if item.configuration == "no_defense")
        with tempfile.TemporaryDirectory() as temp:
            with self.assertRaisesRegex(ValueError, "only volumetric_udp"):
                live_trial.run_live_trial(temp, run, Path(temp) / "out",
                                          host_check=lambda: None)


if __name__ == "__main__":
    unittest.main()
