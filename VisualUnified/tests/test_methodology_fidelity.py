"""Policy parity and unified simulation tests; no Ryu/SUMO runtime required."""
import json
import unittest
from unittest.mock import patch

from engine import SimEngine, DEFAULT_CONFIG, reputation_policy
from methodology import md, Med2Config, ReputationEngine, consistency


def payload(timestamp, x=0, y=0, speed=0, vehicle='V07'):
    return json.dumps(dict(vehicle_id=vehicle, timestamp=timestamp,
                           x=x, y=y, speed=speed)).encode()


class MethodologyFidelityTests(unittest.TestCase):
    def setUp(self):
        self.sim = SimEngine(seed=14)
        self.sim.set_config({'loss_probability': 0, 'rsu_backhaul_mbps': 50})
        self.v = self.sim.vehicles['V07']

    def ingress(self, count, *, traffic='UDP_FLOOD', destination='V02'):
        for _ in range(count):
            self.sim._send('V07', destination, traffic, 1024)

    def fixed_threshold(self):
        return patch.object(self.sim, '_threshold_context', return_value=(120, 'fixed test context'))

    def stage_one(self):
        self.ingress(120)
        self.assertEqual(self.v.m2_stage, 'METER')

    def sustain(self, start, end):
        for tick in range(start, end):
            self.sim.t = tick / 10
            self.ingress(32)

    def test_default_timings_and_limits_match_original_config(self):
        cfg = Med2Config()
        self.assertEqual(DEFAULT_CONFIG['m2_window_sec'], cfg.window_seconds)
        self.assertEqual(DEFAULT_CONFIG['stage2_after_sec'], cfg.stage1_dwell_seconds)
        self.assertEqual(DEFAULT_CONFIG['block_duration_sec'], cfg.stage2_block_seconds)
        self.assertEqual(DEFAULT_CONFIG['m2_meter_kbps'], cfg.meter_rate_kbps)
        self.assertEqual(DEFAULT_CONFIG['m2_meter_lifetime_sec'], cfg.meter_hard_timeout)

    def test_dense_slow_sparse_and_missing_context_use_original_thresholds(self):
        cfg = Med2Config()
        for count, speed in ((5, 60), (2, 60), (3, 10), (3, 30), (0, 60)):
            with self.subTest(count=count, speed=speed):
                self.v.rsu = 'RSU-1' if count else None
                others = [v for v in self.sim.vehicles.values() if v.id != self.v.id]
                for index, other in enumerate(others):
                    other.rsu = 'RSU-1' if index < count - 1 else 'RSU-3'
                    other.speed = speed
                self.v.speed = speed
                sample = ({'vehicle_count': count, 'average_speed': speed / 3.6}
                          if count else None)
                expected, _ = md.select_threshold(cfg, sample, 0)
                self.assertEqual(self.sim._threshold(self.v), expected)

    def test_high_handover_churn_raises_floor_then_ages_out(self):
        for v in self.sim.vehicles.values(): v.rsu = 'RSU-1'
        self.assertEqual(self.sim._threshold(self.v), 90)
        self.sim.handover_times.extend([0, 0])
        self.assertEqual(self.sim._threshold(self.v), 150)
        self.sim.t = 60.1
        self.assertEqual(self.sim._threshold(self.v), 90)

    def test_exact_threshold_and_unlabelled_victim_udp_trigger_m2(self):
        with self.fixed_threshold():
            self.ingress(119, traffic='TELEMETRY')
            self.assertEqual(self.v.m2_stage, 'NORMAL')
            self.ingress(1, traffic='TELEMETRY')
        self.assertEqual(self.v.m2_stage, 'METER')
        self.assertEqual(self.v.m2_rate, 120)

    def test_packet_tracker_keeps_original_observed_span_and_window(self):
        oracle = md.PacketRateTracker(5)
        with patch.object(self.sim, '_threshold_context', return_value=(800, 'test')):
            for now in (0, .5, 1.5, 3.0, 6.0):
                self.sim.t = now
                self.ingress(1, traffic='TELEMETRY')
                oracle.add(now)
                self.assertEqual(self.v.m2_rate, oracle.rate(now))

    def test_safety_nonvictim_udp_and_unmonitored_ingress_do_not_trigger(self):
        with self.fixed_threshold():
            self.ingress(200, traffic='SAFETY')
            self.ingress(200, destination='V03')
            self.sim.set_config({'m2_monitored_rsu': 'RSU-1'})
            self.v.rsu = 'RSU-2'
            self.ingress(200)
        self.assertEqual(self.v.m2_stage, 'NORMAL')
        self.assertEqual(len(self.v.rate_tracker), 0)

    def test_static_drop_precedes_detection_but_allow_cannot_bypass_block(self):
        state = self.sim.upsert_rule({'source': 'V07', 'traffic': 'UDP_FLOOD', 'action': 'DROP'})
        rule_id = state['rules'][-1]['id']
        with self.fixed_threshold():
            self.ingress(200)
            self.assertEqual(self.v.m2_stage, 'NORMAL')
            self.assertEqual(len(self.v.rate_tracker), 0)
            self.sim.upsert_rule({'source': 'V07', 'traffic': 'UDP_FLOOD', 'action': 'ALLOW'}, rule_id)
            self.stage_one()
            self.sustain(1, 112)
        self.assertEqual(self.v.m2_stage, 'BLOCK')
        self.assertGreater(self.sim.reasons['M2_TEMP_BLOCK'], 0)

    def test_stage2_uses_premeter_attempts_despite_severe_reputation_drops(self):
        self.v.reputation = 0
        with self.fixed_threshold():
            self.stage_one()
            self.sustain(1, 100)
            self.assertEqual(self.v.m2_stage, 'METER')
            self.sustain(100, 112)
        self.assertEqual(self.v.m2_stage, 'BLOCK')
        self.assertEqual(self.sim.totals['m2_blocks'], 1)
        self.assertGreater(self.sim.totals['m3_meter_drops'], 0)

    def test_subsided_stage1_persists_until_original_flow_expiry(self):
        with self.fixed_threshold():
            self.stage_one()
            self.v.meter_buckets[('m3', 'm3')] = {'tokens': 20, 'rate': 100, 'at': 0}
            self.v.reputation = .16
            self.sim.t = 5
            self.sim._detect_attack(self.v)
            self.assertEqual(self.v.m2_stage, 'METER')
            self.sim.t = 15
            self.sim._detect_attack(self.v)
        self.assertEqual(self.v.m2_stage, 'NORMAL')
        self.assertIn(('m3', 'm3'), self.v.meter_buckets)
        self.assertEqual(self.v.reputation, .16)

    def test_block_does_not_extend_on_dropped_packets_and_low_rate_recovers(self):
        with self.fixed_threshold():
            self.stage_one()
            self.sustain(1, 112)
            expiry = self.v.blocked_until
            self.sustain(112, 180)
            self.assertEqual(self.v.blocked_until, expiry)
            self.sim.t = expiry
            self.sim._detect_attack(self.v)
            self.ingress(1, traffic='TELEMETRY')
        self.assertEqual(self.v.m2_stage, 'NORMAL')
        self.assertEqual(self.v.detector.trust, 1)

    def test_safety_severity_matches_original_motion_and_reputation(self):
        for stamp, x, speed in ((1, 0, 56), (0, 0, 0), (1, 1000, 0), (1, 0, 20)):
            with self.subTest(stamp=stamp, x=x, speed=speed):
                sim = SimEngine()
                sim.receive_safety_message('V07', payload(0))
                checker = consistency.MessageConsistencyChecker()
                checker.check(consistency.VehicleMessage('V07', 0, 0, 0, 0))
                expected = checker.check(consistency.VehicleMessage('V07', stamp, x, 0, speed))
                actual = sim.receive_safety_message('V07', payload(stamp, x=x, speed=speed))
                oracle = ReputationEngine()
                oracle.update('V07', True)
                decision = oracle.update('V07', expected.consistent, expected.severity)
                self.assertEqual(actual, expected)
                self.assertEqual(sim.vehicles['V07'].reputation, decision.reputation)

    def test_original_strict_parser_and_source_identity_do_not_penalize_malformed(self):
        for value in (b'{}', payload(1, vehicle='V08'), payload(1, speed=float('nan')),
                      b'{"vehicle_id":"V07","vehicle_id":"V08"}', b'x' * 1025):
            self.assertIsNone(self.sim.receive_safety_message('V07', value))
        self.assertEqual(self.v.reputation, 1)
        self.assertIsNone(self.v.last_report)
        self.assertEqual(self.sim.totals['observed_safety'], 0)
        self.assertEqual(self.sim.totals['rejected_safety'], 5)

    def test_five_severe_violations_then_200_valid_messages_match_full_original_trace(self):
        oracle = ReputationEngine()
        self.sim.receive_safety_message('V07', payload(0))
        oracle.update('V07', True)
        for i in range(5):
            self.sim.receive_safety_message('V07', payload((i+1)/10, x=1e6))
            decision = oracle.update('V07', False, 1)
            self.assertEqual(self.v.reputation, decision.reputation)
        self.assertEqual(reputation_policy(self.v.reputation), (100, 'SEVERE_THROTTLE'))
        for i in range(200):
            self.sim.receive_safety_message('V07', payload(1+i/5))
            decision = oracle.update('V07', True)
            self.assertEqual(self.v.reputation, decision.reputation)
            self.assertEqual(reputation_policy(self.v.reputation),
                             (decision.rate_limit_kbps, decision.action))
        self.assertEqual(self.v.reputation, .8)

    def test_reputation_recovery_does_not_remove_active_m2_meter(self):
        with self.fixed_threshold():
            self.stage_one()
        self.v.reputation = .58
        for i in range(5): self.sim.receive_safety_message('V07', payload(i))
        self.assertEqual(reputation_policy(self.v.reputation), (None, 'MONITOR'))
        self.assertEqual(self.v.m2_stage, 'METER')
        policy = next(p for p in self.sim.status()['runtime_policies'] if p['vehicle'] == 'V07')
        self.assertEqual(policy['effective_udp_meter_kbps'], 500)

    def test_handover_retains_m3_history_and_m2_dwell_without_cross_vehicle_leakage(self):
        with self.fixed_threshold():
            self.stage_one()
        started = self.v.detector.metered_at
        self.sim.receive_safety_message('V07', payload(0))
        previous = self.v.last_report
        self.v.x, self.v.y = 300, 185
        self.sim._associate()
        self.v.x, self.v.y = 825, 185
        self.sim._associate()
        self.assertEqual(self.v.detector.metered_at, started)
        self.assertEqual(self.v.last_report, previous)
        result = self.sim.receive_safety_message('V07', payload(1, x=1000))
        self.assertFalse(result.consistent)
        other = self.sim.vehicles['V08']
        self.assertEqual(other.reputation, 1)
        self.assertEqual(other.m2_stage, 'NORMAL')

    def test_combined_attack_preserves_other_vehicles_and_concurrent_m1_rules(self):
        self.sim.upsert_rule({'source': 'V07', 'traffic': 'UDP_FLOOD', 'action': 'METER', 'rate_kbps': 200})
        self.sim.set_scenario('combined')
        with patch.object(self.sim, '_move'):
            for _ in range(140): self.sim.step(.1)
        self.assertGreater(self.sim.totals['m2_blocks'], 0)
        self.assertLess(self.v.reputation, .2)
        self.assertGreater(self.sim.reasons['RATE_LIMIT'], 0)
        for v in self.sim.vehicles.values():
            if v.id == 'V07': continue
            self.assertEqual(v.dropped, 0, v.id)
            self.assertEqual(v.reputation, 1, v.id)
            self.assertEqual(v.m2_stage, 'NORMAL', v.id)


if __name__ == '__main__':
    unittest.main()
