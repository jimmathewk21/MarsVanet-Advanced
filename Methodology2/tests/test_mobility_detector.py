"""Unit tests for mobility-aware detection logic (threshold + rate + decide)."""

import os
import tempfile
import unittest

import _bootstrap  # noqa: F401
import mobility_detector as md
from med2_config import Med2Config


def _write_csv(text):
    fd, path = tempfile.mkstemp(suffix=".csv")
    with os.fdopen(fd, "w") as handle:
        handle.write(text)
    return path


class MobilityLoadTest(unittest.TestCase):
    def test_load_valid(self):
        path = _write_csv(
            "time,vehicle_count,average_speed\n"
            "1.0,3,12.0\n2.0,4,11.5\n"
        )
        try:
            records, report = md.load_mobility_features(path)
            self.assertTrue(report.ok)
            self.assertEqual(report.record_count, 2)
            self.assertEqual(records[0]["vehicle_count"], 3)
        finally:
            os.remove(path)

    def test_missing_columns(self):
        path = _write_csv("time,foo\n1.0,2\n")
        try:
            records, report = md.load_mobility_features(path)
            self.assertFalse(report.ok)
            self.assertIn("average_speed", report.missing_columns)
            self.assertEqual(records, [])
        finally:
            os.remove(path)

    def test_malformed_rows_skipped(self):
        path = _write_csv(
            "time,vehicle_count,average_speed\n"
            "1.0,3,12.0\n"
            "bad,row,here\n"
            "3.0,-1,10.0\n"      # negative count -> rejected
            "4.0,5,11.0\n"
        )
        try:
            records, report = md.load_mobility_features(path)
            self.assertTrue(report.ok)
            self.assertEqual(report.record_count, 2)
            self.assertEqual(report.skipped_rows, 2)
        finally:
            os.remove(path)

    def test_missing_file(self):
        records, report = md.load_mobility_features("/nonexistent/path.csv")
        self.assertFalse(report.ok)
        self.assertEqual(records, [])


class NearestSampleTest(unittest.TestCase):
    def setUp(self):
        self.records = [
            {"time": 1.0, "vehicle_count": 1, "average_speed": 14.0},
            {"time": 10.0, "vehicle_count": 8, "average_speed": 3.0},
        ]

    def test_returns_closest_within_age(self):
        s = md.nearest_sample(self.records, elapsed=9.5, max_age=5.0)
        self.assertEqual(s["time"], 10.0)

    def test_stale_guard_returns_none(self):
        # elapsed far from any sample time -> stale -> None (base fallback)
        self.assertIsNone(md.nearest_sample(self.records, 100.0, max_age=5.0))

    def test_empty_records(self):
        self.assertIsNone(md.nearest_sample([], 1.0, max_age=5.0))


class SelectThresholdTest(unittest.TestCase):
    def setUp(self):
        self.cfg = Med2Config()

    def test_base_when_no_sample(self):
        t, reason = md.select_threshold(self.cfg, None, handover_rate=0.0)
        self.assertEqual(t, self.cfg.base_threshold_pps)
        self.assertIn("base", reason)

    def test_dense_slow_lowers_threshold(self):
        sample = {"vehicle_count": 6, "average_speed": 4.0}
        t, _ = md.select_threshold(self.cfg, sample, 0.0)
        self.assertEqual(t, self.cfg.dense_threshold_pps)

    def test_sparse_fast_raises_threshold(self):
        sample = {"vehicle_count": 1, "average_speed": 14.0}
        t, _ = md.select_threshold(self.cfg, sample, 0.0)
        self.assertEqual(t, self.cfg.sparse_threshold_pps)

    def test_high_handover_applies_floor(self):
        sample = {"vehicle_count": 6, "average_speed": 4.0}  # would be 90
        t, reason = md.select_threshold(self.cfg, sample, handover_rate=3.0)
        self.assertEqual(t, self.cfg.handover_threshold_floor_pps)
        self.assertIn("handover", reason)


class PacketRateTrackerTest(unittest.TestCase):
    def test_early_window_not_underestimated(self):
        # 10 packets arriving within ~1s should read ~10 pps, not 10/5=2 pps.
        tracker = md.PacketRateTracker(window_seconds=5.0)
        t0 = 1000.0
        for i in range(10):
            tracker.add(t0 + i * 0.1)
        rate = tracker.rate(t0 + 0.9)
        self.assertGreaterEqual(rate, 9.0)

    def test_old_samples_evicted(self):
        tracker = md.PacketRateTracker(window_seconds=5.0)
        tracker.add(1000.0)
        tracker.add(1001.0)
        # Query well after the window: old samples gone.
        self.assertEqual(len(tracker), 2)
        _ = tracker.rate(1010.0)
        self.assertEqual(len(tracker), 0)


class DecideTest(unittest.TestCase):
    def setUp(self):
        self.cfg = Med2Config()

    def test_normal_traffic_no_action(self):
        state = md.SourceState()
        d = md.decide(state, rate=50, threshold=120, now=1000.0, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_NONE)
        self.assertEqual(state.stage, md.STAGE_NORMAL)

    def test_escalation_stage0_to_stage1(self):
        state = md.SourceState()
        d = md.decide(state, rate=200, threshold=120, now=1000.0, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_INSTALL_METER)
        self.assertEqual(state.stage, md.STAGE_METER)
        self.assertLess(state.trust, 1.0)

    def test_escalation_stage1_to_stage2(self):
        state = md.SourceState(stage=md.STAGE_METER)
        d = md.decide(state, rate=200, threshold=120, now=1000.0, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_INSTALL_BLOCK)
        self.assertEqual(state.stage, md.STAGE_BLOCK)

    def test_no_accidental_escalation_for_normal(self):
        state = md.SourceState(stage=md.STAGE_METER)
        d = md.decide(state, rate=10, threshold=120, now=1000.0, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_NONE)
        self.assertEqual(state.stage, md.STAGE_METER)  # no escalation

    def test_block_holds_while_over_threshold(self):
        now = 1000.0
        state = md.SourceState(stage=md.STAGE_BLOCK, blocked_at=now,
                               last_seen=now)
        d = md.decide(state, rate=200, threshold=120, now=now + 5, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_NONE)
        self.assertEqual(state.stage, md.STAGE_BLOCK)

    def test_recovery_after_block_expiry_and_idle(self):
        now = 1000.0
        state = md.SourceState(stage=md.STAGE_BLOCK, blocked_at=now,
                               last_seen=now)
        # Far enough past both the block window and the idle reset gap.
        future = now + self.cfg.stage2_block_seconds + \
            self.cfg.detector_reset_seconds + 1
        d = md.decide(state, rate=0, threshold=120, now=future, cfg=self.cfg)
        self.assertEqual(d.action, md.ACTION_RESET)
        self.assertEqual(state.stage, md.STAGE_NORMAL)
        self.assertEqual(state.trust, 1.0)

    def test_repeatable_decisions(self):
        # Same inputs -> same stage transitions, deterministically.
        for _ in range(5):
            state = md.SourceState()
            md.decide(state, 200, 120, 1000.0, self.cfg)
            self.assertEqual(state.stage, md.STAGE_METER)


if __name__ == "__main__":
    unittest.main()
