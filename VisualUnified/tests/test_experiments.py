"""Metric and artifact tests against real, lightweight simulator execution."""
from dataclasses import replace
import csv
import gzip
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from xml.etree import ElementTree
from contextlib import redirect_stdout

from engine import SimEngine, DEFAULT_CONFIG, RULES_PRESET
from run_experiments import (EvidenceEngine, StudySpec, PROFILES, PHASES, CLASSES,
                             run_trial, run_id, matrix, metric, ratio, recovery_delay,
                             audit_counters, summarize, verify_equivalence, execute_study,
                             calculate_metrics)
from validate_experiments import validate_study


class ExperimentTests(unittest.TestCase):
    def setUp(self):
        self.spec = StudySpec(seeds=(14,), scenarios=('combined',),
                              baseline_seconds=1, attack_seconds=3, recovery_seconds=2)

    def test_matrix_seed_repetition_and_names(self):
        spec = replace(self.spec, seeds=(14, 15), scenarios=('normal', 'combined'))
        self.assertEqual(len(matrix(spec)), 24)
        names = [run_id(p, s, seed, spec) for p, s, seed in matrix(spec)]
        self.assertEqual(len(set(names)), 24)
        self.assertEqual(names, [run_id(p, s, seed, spec) for p, s, seed in matrix(spec)])
        for invalid in (replace(spec, seeds=(14, 14)), replace(spec, seeds=()),
                        replace(spec, attack_seconds=float('nan')), replace(spec, step_seconds=.2),
                        replace(spec, recovery_seconds=1.05)):
            with self.assertRaises(ValueError): invalid.validate()

    def test_counter_semantics_and_ground_truth(self):
        sim = EvidenceEngine(self.spec, 14)
        route = [{'x': 0, 'y': 0}, {'x': 1, 'y': 1}]
        # A configured meter on a forwarded packet is not a rate-limit drop.
        sim._record_packet('V07', 'V02', 'TELEMETRY', 420, True, 'FORWARDED', route, 'V2V', 100)
        sim.injected_safety = True
        sim._record_packet('V07', 'RSU-1', 'SAFETY', 220, True, 'FORWARDED', route, 'V2I', None)
        sim._record_packet('V07', 'V02', 'UDP_FLOOD', 1024, False, 'M1_STATIC_DROP', route, 'V2V', None)
        sim.totals['m3_meter_drops'] += 1
        sim._record_packet('V01', 'V02', 'TELEMETRY', 420, False, 'RATE_LIMIT', route, 'V2V', 100)
        benign = sim.counts[('baseline', 'benign')]
        self.assertEqual((benign['generated'], benign['received'], benign['dropped']), (2, 1, 1))
        self.assertEqual(benign['rate_limited'], 1)
        self.assertEqual(sim.counts[('baseline', 'malicious_safety')]['controller_received'], 1)
        audit = audit_counters(sim)
        self.assertEqual(audit['legacy_non_flood_generated'], 3)
        self.assertEqual(audit['semantic_benign_generated'], 2)
        self.assertEqual(audit['malicious_safety_counted_as_non_flood_by_dashboard'], 1)

    def test_missing_metrics_require_explanations_and_empty_pdr_is_null(self):
        with self.assertRaises(ValueError): metric()
        self.assertIsNone(ratio(0, 0)['value'])
        self.assertIsNotNone(ratio(0, 0)['explanation'])
        self.assertEqual(ratio(0, 5)['value'], 0)

    def test_static_blocking_is_not_dynamic_detection(self):
        row = run_trial(self.spec, 'm1_only', 'combined', 14)
        metrics = row['metrics']['attack']
        self.assertIsNone(metrics['m1_detection_delay_s']['value'])
        self.assertIsNone(metrics['m2_detection_delay_s']['value'])
        self.assertGreater(metrics['m1_first_malicious_drop_delay_s']['value'], 0)
        flood = row['counts']['attack']['malicious_flood']
        self.assertEqual(flood['policy_dropped'], flood['generated'])
        self.assertEqual(flood['rate_limited'], 0)
        self.assertEqual(flood['received'], 0)

    def test_reproducibility_and_paired_profile_equivalence(self):
        first = run_trial(self.spec, 'm3_only', 'combined', 14)
        second = run_trial(self.spec, 'm3_only', 'combined', 14)
        self.assertEqual(first, second)
        rows = [run_trial(self.spec, p, 'combined', 14) for p in PROFILES]
        self.assertEqual(verify_equivalence(rows)['status'], 'PASS')
        rows[0]['mobility_sha256'] = 'corrupted'
        with self.assertRaises(AssertionError): verify_equivalence(rows)

    def test_observer_does_not_change_engine_behavior(self):
        sim = SimEngine(seed=14, mobility_model='legacy')
        sim.set_config({'m1_enabled': False, 'm2_enabled': True, 'm3_enabled': True})
        observed = EvidenceEngine(self.spec, 14)
        observed.set_config({'m1_enabled': False, 'm2_enabled': True, 'm3_enabled': True})
        observed.previous_policy = observed.policy_snapshot()
        for phase, duration in zip(PHASES, (1, 3, 2)):
            scenario = 'combined' if phase == 'attack' else 'normal'
            observed.phase = phase
            for engine in (sim, observed):
                engine.set_scenario(scenario)
                for _ in range(duration * 10): engine.step(.1)
        self.assertEqual(sim.totals, observed.totals)
        self.assertEqual(sim.reasons, observed.reasons)
        self.assertEqual(sim.status(), observed.status())

    def test_profiles_do_not_leak_rules_config_or_saved_settings(self):
        defaults, rules = dict(DEFAULT_CONFIG), [dict(r) for r in RULES_PRESET]
        first = run_trial(self.spec, 'no_defense', 'combined', 14)
        run_trial(self.spec, 'unified_static', 'combined', 14)
        last = run_trial(self.spec, 'no_defense', 'combined', 14)
        self.assertEqual(first, last)
        self.assertEqual(DEFAULT_CONFIG, defaults)
        self.assertEqual(RULES_PRESET, rules)
        self.assertFalse(any(r['enabled'] for r in last['rules']))

    def test_phase_labels_and_no_safety_penalty_before_delivery(self):
        packets = []
        row = run_trial(self.spec, 'm3_only', 'combined', 14, packet_sink=packets.append)
        for packet in packets:
            start, end = {'baseline': (0, 1), 'attack': (1, 4), 'recovery': (4, 6)}[packet['phase']]
            self.assertGreater(packet['time'], start)
            self.assertLessEqual(packet['time'], end)
            if packet['ground_truth'] != 'benign': self.assertEqual(packet['phase'], 'attack')
        self.assertTrue(row['decisions'])
        for decision in row['decisions']:
            self.assertTrue(any(p['time'] == decision['time'] and p['source'] == decision['vehicle']
                                and p['traffic'] == 'SAFETY' and p['destination'].startswith('RSU-')
                                and p['received'] for p in packets))

    def test_recovery_is_policy_based_and_right_censored(self):
        self.assertIsNone(recovery_delay([], 10, 20, bool, False)['value'])
        self.assertIsNone(recovery_delay([(10, False), (19.5, True)], 10, 20, bool, True)['value'])
        self.assertEqual(recovery_delay([(10, False), (15, True), (20, True)], 10, 20, bool, True)['value'], 5)
        self.assertIsNone(recovery_delay([(10, True), (18, False)], 10, 20, bool, True)['value'])

    def test_false_positive_denominator_uses_benign_sources(self):
        sim = EvidenceEngine(self.spec, 14)
        sim.phase = 'attack'
        sim._observe_reputation(sim.vehicles['V01'], True, 'fixture inconsistency', .8)
        sim.alerts[('attack', 'm3')].add('V07')
        boundary = {phase: {'m2': 'NORMAL', 'm3': 'NORMAL', 'reputation': 1} for phase in PHASES}
        metrics = calculate_metrics(sim, 'unified_dynamic', 'combined', boundary)
        self.assertAlmostEqual(metrics['attack']['m3_benign_source_alert_rate_pct']['value'], 100 / 11)

    def test_summary_ci_and_missing_counts(self):
        rows = [run_trial(self.spec, 'm1_only', 'combined', 14)]
        summary = summarize(rows)
        pdr = next(r for r in summary if r['phase'] == 'attack' and r['metric'] == 'legitimate_pdr_pct')
        self.assertEqual(pdr['n'], 1)
        self.assertIsNone(pdr['ci95_low'])
        missing = next(r for r in summary if r['phase'] == 'attack' and r['metric'] == 'm1_detection_delay_s')
        self.assertEqual((missing['n'], missing['missing']), (0, 1))
        self.assertIsNotNone(missing['explanation'])

    def test_confidence_interval_uses_trials_not_packet_pseudoreplication(self):
        records = [dict(scenario='normal', profile='no_defense', metrics={
            'attack': {'legitimate_pdr_pct': metric(value)}}) for value in (3, 7)]
        row = summarize(records)[0]
        self.assertEqual(row['n'], 2)
        self.assertEqual(row['mean'], 5)
        self.assertAlmostEqual(row['ci95_low'], 5 - 12.706 * 2)
        self.assertAlmostEqual(row['ci95_high'], 5 + 12.706 * 2)

    def test_artifacts_raw_ledger_and_overwrite_protection(self):
        spec = replace(self.spec, scenarios=('normal',), baseline_seconds=.1,
                       attack_seconds=.2, recovery_seconds=.2)
        with tempfile.TemporaryDirectory() as tmp, redirect_stdout(io.StringIO()):
            output = Path(tmp) / 'study'
            rows = execute_study(spec, output)
            self.assertEqual(len(rows), 6)
            self.assertEqual(json.loads((output / 'completion.json').read_text())['status'], 'PASS')
            self.assertTrue((output / 'normal__legitimate_pdr_pct.svg').is_file())
            graph = ElementTree.parse(output / 'normal__legitimate_pdr_pct.svg')
            texts = [node.text for node in graph.iter('{http://www.w3.org/2000/svg}text')]
            for profile in PROFILES: self.assertIn(profile, texts)
            self.assertTrue(any('SIMULATION ONLY' in text for text in texts))
            for row in rows:
                with gzip.open(output / row['run_id'] / 'packets.csv.gz', 'rt') as stream:
                    packets = list(csv.DictReader(stream))
                self.assertEqual(len(packets), row['counter_audit']['ledger_generated'])
            self.assertEqual(validate_study(output)['runs'], 6)
            manifest=json.loads((output/'manifest.json').read_text())
            source_root=Path(tmp)/'changed_sources'
            for relative in manifest['sources_sha256']:
                target=source_root/relative;target.parent.mkdir(parents=True,exist_ok=True)
                target.write_bytes((Path(__file__).resolve().parents[2]/relative).read_bytes())
            with (source_root/'VisualUnified/engine.py').open('a') as stream:stream.write('\n# changed source\n')
            with patch('validate_experiments.ROOT',source_root):
                with self.assertRaisesRegex(AssertionError,'Source changed'):validate_study(output)
                audit=validate_study(output,allow_source_drift=True)
                self.assertEqual(audit['source_identity'],'DIFFERENT')
                self.assertEqual(audit['runs'],6)
                self.assertEqual(audit['source_drift'],['VisualUnified/engine.py'])
            before = (output / 'manifest.json').read_bytes()
            with self.assertRaises(FileExistsError): execute_study(spec, output)
            self.assertEqual((output / 'manifest.json').read_bytes(), before)
            (output / rows[0]['run_id'] / 'result.json').write_text('{}', encoding='utf-8')
            with self.assertRaisesRegex(AssertionError, 'checksum'):
                validate_study(output)


if __name__ == '__main__':
    unittest.main()
