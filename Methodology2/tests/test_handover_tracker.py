"""Mininet-free tests for association handover counting."""

import unittest

import _bootstrap  # noqa: F401
from handover_tracker import HandoverTracker


class HandoverTrackerTest(unittest.TestCase):
    def test_initial_association_is_only_a_baseline(self):
        tracker = HandoverTracker()
        self.assertIsNone(tracker.observe("ap1", 1.0))
        self.assertEqual(tracker.handovers, 0)

    def test_direct_ap_transition_counts_once(self):
        tracker = HandoverTracker(previous_ap="ap1")
        self.assertEqual(tracker.observe("ap2", 2.0),
                         ("ap1", "ap2", 1, True))
        self.assertIsNone(tracker.observe("ap2", 2.1))
        self.assertEqual(tracker.handovers, 1)

    def test_brief_disconnect_then_different_ap_counts_once(self):
        tracker = HandoverTracker(previous_ap="ap1")
        self.assertEqual(tracker.observe("NONE", 2.0),
                         ("ap1", "NONE", 0, False))
        self.assertEqual(tracker.observe("ap2", 6.9),
                         ("NONE", "ap2", 1, True))
        self.assertEqual(tracker.handovers, 1)

    def test_disconnect_only_does_not_count(self):
        tracker = HandoverTracker(previous_ap="ap1")
        tracker.observe("NONE", 2.0)
        self.assertEqual(tracker.handovers, 0)

    def test_reconnect_to_same_ap_does_not_count(self):
        tracker = HandoverTracker(previous_ap="ap1")
        tracker.observe("NONE", 2.0)
        self.assertEqual(tracker.observe("ap1", 3.0),
                         ("NONE", "ap1", 0, False))
        self.assertEqual(tracker.handovers, 0)

    def test_reconnect_after_window_does_not_count(self):
        tracker = HandoverTracker(previous_ap="ap1")
        tracker.observe("NONE", 2.0)
        self.assertEqual(tracker.observe("ap2", 7.001),
                         ("NONE", "ap2", 0, False))
        self.assertEqual(tracker.handovers, 0)

    def test_each_logged_transition_carries_cumulative_count(self):
        tracker = HandoverTracker(previous_ap="ap1")
        first = tracker.observe("ap2", 2.0)
        second = tracker.observe("NONE", 3.0)
        third = tracker.observe("ap1", 4.0)
        self.assertEqual(first, ("ap1", "ap2", 1, True))
        self.assertEqual(second, ("ap2", "NONE", 1, False))
        self.assertEqual(third, ("NONE", "ap1", 2, True))


if __name__ == "__main__":
    unittest.main()
