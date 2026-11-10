import json
import io
from pathlib import Path
import tempfile
import unittest
from contextlib import redirect_stdout, redirect_stderr

from benchmark.core import (
    CONFIGURATIONS, derive_seed, empty_metrics, event_delay_metric,
    generate_matrix, latency_metric, make_run_id, recovery_time_metric,
    summarize_metric_files, summarize_metric_records, traffic_metrics,
    write_run_artifacts,
)
from benchmark.run_benchmark import main, plan_document


class BenchmarkCoreTest(unittest.TestCase):
    def test_matrix_covers_workloads_and_configurations(self):
        matrix = generate_matrix(root_seed=10, repetitions=2)
        self.assertEqual(len(matrix), 2 * 2 * len(CONFIGURATIONS))
        self.assertEqual({run.workload for run in matrix},
                         {"volumetric_udp", "safety_consistency"})

    def test_seeds_are_repeatable_and_matched_across_configurations(self):
        first = generate_matrix(42, 2)
        second = generate_matrix(42, 2)
        self.assertEqual([run.seed for run in first], [run.seed for run in second])
        by_trial = {}
        for run in first:
            by_trial.setdefault((run.workload, run.repetition), set()).add(run.seed)
        self.assertTrue(all(len(seeds) == 1 for seeds in by_trial.values()))
        self.assertNotEqual(derive_seed(42, "volumetric_udp", 1),
                            derive_seed(42, "safety_consistency", 1))

    def test_matched_comparisons_keep_identical_loads_and_windows(self):
        matrix = generate_matrix(4, 1)
        for workload in ("volumetric_udp", "safety_consistency"):
            runs = [run for run in matrix if run.workload == workload]
            self.assertEqual(len({json.dumps(run.offered_loads, sort_keys=True)
                                  for run in runs}), 1)
            self.assertEqual(len({json.dumps(run.windows, sort_keys=True)
                                  for run in runs}), 1)

    def test_run_ids_are_deterministic_and_filesystem_safe(self):
        one = make_run_id("Safety Consistency", "Methodology 3", 2, 123)
        self.assertEqual(one, make_run_id("Safety Consistency", "Methodology 3", 2, 123))
        self.assertNotIn(" ", one)
        self.assertEqual(one, "safety-consistency-methodology-3-r002-s0000007b")

    def test_student_t_confidence_interval(self):
        result = summarize_metric_records([
            {"value": 1.0}, {"value": 2.0}, {"value": 3.0},
        ])
        self.assertEqual(result["n"], 3)
        self.assertAlmostEqual(result["mean"], 2.0)
        self.assertLess(result["low"], 2.0)
        self.assertGreater(result["high"], 2.0)
        self.assertIsNone(result["explanation"])

    def test_missing_metric_is_null_with_reason_and_excluded_from_ci(self):
        metric = summarize_metric_records([
            {"value": None, "explanation": "No enforcement event stream."},
            {"value": 2.0},
        ])
        self.assertEqual(metric["n"], 1)
        self.assertEqual(metric["missing_trials"], 1)
        self.assertIsNone(metric["low"])
        self.assertIn("No enforcement event stream.", metric["missing_explanations"])
        self.assertTrue(all(item["value"] is None for item in empty_metrics().values()))

    def test_metric_helpers_calculate_observed_values_and_null_reasons(self):
        values = traffic_metrics(100, 90, 9000, 10)
        self.assertAlmostEqual(values["packet_delivery_ratio"]["value"], 0.9)
        self.assertAlmostEqual(values["packet_loss_ratio"]["value"], 0.1)
        self.assertAlmostEqual(values["legitimate_throughput_mbps"]["value"], 0.0072)
        self.assertIsNone(event_delay_metric(1.0, None, "No event feed.")["value"])
        latency = latency_metric([2.0, 4.0, 3.0], 0.5)
        self.assertEqual(latency["value"], 3.0)
        self.assertEqual(latency["clock_uncertainty_ms"], 0.5)
        self.assertEqual(recovery_time_metric(
            [(10, 9.5), (11, 9.6), (12, 9.6), (13, 9.6), (14, 9.6)],
            10, 10.0,
        )["value"], 0)
        too_close = [(10 + i * 0.1, 9.6) for i in range(5)]
        self.assertIsNone(recovery_time_metric(too_close, 10, 10.0)["value"])
        self.assertIsNone(recovery_time_metric(None, 10, 10.0)["value"])

    def test_artifact_naming_and_overwrite_refusal(self):
        spec = generate_matrix(1, 1, workloads=("safety_consistency",))[0]
        with tempfile.TemporaryDirectory() as temp:
            paths = write_run_artifacts(Path(temp), spec, raw_log="raw\n")
            self.assertTrue(all(path.exists() for path in paths))
            self.assertTrue(paths[0].name.endswith(".raw.log"))
            self.assertEqual(paths[0].read_text(encoding="utf-8"), "raw\n")
            with self.assertRaises(FileExistsError):
                write_run_artifacts(Path(temp), spec)
            summary = summarize_metric_files([paths[1]])
            self.assertIn("safety_consistency/no_defense", summary)

    def test_default_cli_is_dry_run_and_does_not_execute_commands(self):
        with redirect_stdout(io.StringIO()):
            self.assertEqual(main(["--root-seed", "7", "--repetitions", "1"]), 0)

    def test_live_cli_refuses_to_start_on_unsupported_windows_host(self):
        with redirect_stdout(io.StringIO()), redirect_stderr(io.StringIO()):
            self.assertEqual(main(["--live", "--repetitions", "1"]), 2)

    def test_methodology_applicability_is_explicit(self):
        doc = plan_document(root_seed=1, repetitions=1)
        flood_m3 = next(run for run in doc["runs"]
                        if run["workload"] == "volumetric_udp"
                        and run["configuration"] == "methodology3")
        self.assertFalse(flood_m3["applicable"])
        self.assertTrue(flood_m3["compatibility_reasons"])
        self.assertFalse(doc["executed"])
        m2 = next(run for run in doc["runs"]
                  if run["workload"] == "volumetric_udp"
                  and run["configuration"] == "methodology2")
        self.assertTrue(m2["applicable"])
        self.assertEqual(m2["compatibility"],
                         "conditional_runtime_port_verification_required")
        self.assertEqual(doc["topology_status"],
                         "runtime_checks_available_not_run_in_plan_mode")
        self.assertEqual(doc["compatibility_report"]["runtime_validation"],
                         "not_performed")

    def test_specification_is_valid_json(self):
        path = Path(__file__).parents[1] / "experiment_spec.json"
        parsed = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(parsed["schema_version"], 1)


if __name__ == "__main__":
    unittest.main()
