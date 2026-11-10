"""Regression coverage for the integrated visual simulator; no SUMO required."""
import unittest
from unittest.mock import patch

from engine import SimEngine
from run_comparison import PROFILES, run_trial


class IntegrationRegressions(unittest.TestCase):
    def setUp(self):
        self.sim = SimEngine(seed=35)
        self.sim.set_config({'loss_probability': 0})

    def test_rejected_config_and_scenario_are_atomic(self):
        config = dict(self.sim.config)
        with self.assertRaises(ValueError):
            self.sim.set_config({'base_pps': 200, 'flood_pps': -10})
        self.assertEqual(self.sim.config, config)
        with self.assertRaises(ValueError):
            self.sim.set_scenario('combined', attacker='V02')
        self.assertEqual(self.sim.attacker, 'V07')

    def test_zero_or_nonfinite_rule_rate_is_rejected(self):
        for value in (0, float('inf'), float('nan')):
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.sim.upsert_rule({'action': 'METER', 'rate_kbps': value})

    def test_unmetered_safety_does_not_reset_flood_budget(self):
        self.sim.set_config({'m2_enabled': False, 'm3_enabled': False})
        self.sim.upsert_rule({'source': 'V07', 'traffic': 'UDP_FLOOD',
                              'action': 'METER', 'rate_kbps': 100})
        v = self.sim.vehicles['V07']
        with patch.object(self.sim, '_route', return_value=([{'x': 0, 'y': 0}], 'V2V')):
            self.sim._send(v.id, 'V02', 'UDP_FLOOD', 1024)
            tokens = next(iter(v.meter_buckets.values()))['tokens']
            self.sim._send(v.id, 'V02', 'SAFETY', 220)
            self.assertEqual(next(iter(v.meter_buckets.values()))['tokens'], tokens)
            self.sim.t += 1
            self.assertTrue(self.sim._send(v.id, 'V02', 'UDP_FLOOD', 1024))

    def test_m3_budget_is_shared_across_data_traffic_classes(self):
        self.sim.set_config({'m2_enabled': False})
        self.sim.vehicles['V07'].reputation = 0
        with patch.object(self.sim, '_route', return_value=([{'x': 0, 'y': 0}], 'V2V')):
            for _ in range(20):
                self.sim._send('V07', 'V02', 'UDP_FLOOD', 1024)
                self.sim._send('V07', 'V02', 'TELEMETRY', 420)
        self.assertGreater(self.sim.reasons['RATE_LIMIT'], 0)
        self.assertEqual(len(self.sim.vehicles['V07'].meter_buckets), 1)
        self.assertLessEqual(self.sim.totals['delivered_bytes'], 3125)

    def test_m2_does_not_count_safety_traffic(self):
        for _ in range(200):
            self.sim._send('V07', 'RSU-2', 'SAFETY', 220)
        self.assertEqual(len(self.sim.vehicles['V07'].tx_times), 0)
        self.assertEqual(self.sim.vehicles['V07'].m2_stage, 'NORMAL')

    def test_controller_observes_safety_once_and_only_after_delivery(self):
        v = self.sim.vehicles['V07']
        with patch.object(self.sim, '_send', return_value=False):
            self.sim._send_safety(v, True)
        self.assertEqual(v.reputation, 1)
        with patch.object(self.sim, '_send', return_value=True):
            self.sim._send_safety(v, True)
        self.assertAlmostEqual(v.reputation, 0.84)
        self.assertEqual(self.sim.totals['invalid_safety'], 1)

    def test_static_drop_precedes_temporary_block_and_meters(self):
        v = self.sim.vehicles['V07']
        v.blocked_until = 100
        v.reputation = 0
        self.sim.upsert_rule({'source': v.id, 'traffic': 'UDP_FLOOD', 'action': 'DROP'})
        self.sim._send(v.id, 'V02', 'UDP_FLOOD', 1024)
        self.assertEqual(self.sim.reasons['M1_STATIC_DROP'], 1)
        self.assertEqual(self.sim.reasons['M2_TEMP_BLOCK'], 0)

    def test_effective_policy_reports_stricter_m2_and_static_drop(self):
        v = self.sim.vehicles['V07']
        v.reputation, v.m2_stage = 0, 'METER'
        self.sim.set_config({'m2_meter_kbps': 50})
        policy = next(p for p in self.sim.status()['runtime_policies'] if p['vehicle'] == v.id)
        self.assertEqual(policy['effective_udp_meter_kbps'], 50)
        self.sim.upsert_rule({'source': v.id, 'traffic': 'UDP_FLOOD', 'action': 'DROP'})
        policy = next(p for p in self.sim.status()['runtime_policies'] if p['vehicle'] == v.id)
        self.assertEqual(policy['effective_udp_action'], 'DROP')
        self.assertIsNone(policy['effective_udp_meter_kbps'])

    def test_rsu_source_static_meter_is_enforced(self):
        self.sim.upsert_rule({'source': 'RSU-2', 'traffic': 'BEACON',
                              'action': 'METER', 'rate_kbps': 10})
        with patch.object(self.sim, '_route', return_value=([{'x': 0, 'y': 0}], 'V2V')):
            for _ in range(100): self.sim._send('RSU-2', 'V07', 'BEACON', 100)
        self.assertGreater(self.sim.totals['m1_meter_drops'], 0)

    def test_static_safety_drop_prevents_controller_reputation_update(self):
        self.sim.upsert_rule({'source': 'V07', 'traffic': 'SAFETY', 'action': 'DROP'})
        self.sim._send_safety(self.sim.vehicles['V07'], True)
        self.assertEqual(self.sim.vehicles['V07'].reputation, 1)
        self.assertGreater(self.sim.reasons['M1_STATIC_DROP'], 0)

    def test_m3_can_recover_while_m2_blocks_data(self):
        v = self.sim.vehicles['V07']
        v.reputation, v.blocked_until, v.m2_stage = 0, 200, 'BLOCK'
        with patch.object(self.sim, '_send', return_value=True):
            for i in range(200):
                self.sim.t = i / 2
                self.sim._send_safety(v, False)
        self.assertAlmostEqual(v.reputation, .8)
        self.assertEqual(v.m2_stage, 'BLOCK')

    def test_fast_simulation_preserves_offered_load(self):
        slow, fast = SimEngine(), SimEngine()
        for sim in (slow, fast):
            sim.set_config({'flood_pps': 800})
            sim.set_scenario('combined')
        fast.set_speed(4)
        for _ in range(40): slow.step(.1)
        for _ in range(4): fast.step(.25)
        self.assertAlmostEqual(slow.t, fast.t)
        self.assertEqual(slow.totals, fast.totals)
        self.assertEqual(slow.reasons, fast.reasons)

    def test_disable_m2_clears_enforcement_even_while_paused(self):
        v = self.sim.vehicles['V07']
        v.m2_stage, v.blocked_until = 'BLOCK', 100
        self.sim.set_running(False)
        self.sim.set_config({'m2_enabled': False})
        self.assertEqual(v.m2_stage, 'NORMAL')
        self.assertEqual(v.blocked_until, 0)

    def test_handover_preserves_policy_and_counts_brief_disconnect_once(self):
        v = self.sim.vehicles['V07']
        v.reputation, v.m2_stage = .16, 'METER'
        v.x, v.y, v.rsu = 300, 185, 'RSU-1'
        self.sim._associate()
        v.x, v.y = -1000, -1000
        self.sim._associate()
        self.sim.t += 1
        v.x, v.y = 825, 185
        self.sim._associate()
        self.sim._associate()
        self.assertEqual(v.handovers, 1)
        self.assertEqual(v.reputation, .16)
        self.assertEqual(v.m2_stage, 'METER')

    def test_same_rsu_or_late_reconnect_is_not_a_handover(self):
        v = self.sim.vehicles['V07']
        for delay, position in ((1, (300, 185)), (6, (825, 185))):
            v.rsu, v.x, v.y = 'RSU-1', -1000, -1000
            self.sim._associate()
            self.sim.t += delay
            v.x, v.y = position
            self.sim._associate()
        self.assertEqual(v.handovers, 0)

    def test_reset_keeps_seed_and_recomputes_associations(self):
        self.sim.set_config({'rsu_range': 130})
        self.sim.reset()
        self.assertEqual(self.sim.seed, 35)
        for v in self.sim.vehicles.values():
            if v.rsu:
                rsu = next(r for r in self.sim.rsus if r['id'] == v.rsu)
                self.assertLessEqual(((v.x-rsu['x'])**2+(v.y-rsu['y'])**2)**.5, 130)
        self.assertEqual(self.sim.totals['handovers'], 0)

    def test_comparison_fractional_duration_and_nonflood_delivery(self):
        result = run_trial(PROFILES[0], seconds=1.05, scenario='normal')
        self.assertEqual(result['simulated_seconds'], 1.05)
        self.assertGreater(result['legitimate_PDR_whole_run_pct'], 0)


if __name__ == '__main__':
    unittest.main()
