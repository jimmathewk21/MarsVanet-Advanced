import unittest

from reputation_engine import ReputationEngine


class TestReputationEngine(unittest.TestCase):

    def setUp(self):
        self.engine = ReputationEngine()

    def test_initial_reputation(self):
        decision = self.engine.get_decision("vehicle_1")

        self.assertEqual(decision.reputation, 1.0)
        self.assertEqual(decision.action, "NORMAL")

    def test_single_violation(self):
        decision = self.engine.update(
            "vehicle_1",
            consistent=False,
            severity=1.0,
        )

        self.assertAlmostEqual(decision.reputation, 0.8)
        self.assertEqual(decision.action, "NORMAL")

    def test_progressive_mitigation(self):
        actions = []

        for _ in range(5):
            decision = self.engine.update(
                "vehicle_1",
                consistent=False,
                severity=1.0,
            )

            actions.append(decision.action)

        self.assertIn("MONITOR", actions)
        self.assertIn("LIGHT_THROTTLE", actions)
        self.assertIn("HEAVY_THROTTLE", actions)
        self.assertEqual(actions[-1], "SEVERE_THROTTLE")

    def test_reputation_recovery(self):
        self.engine.update(
            "vehicle_1",
            consistent=False,
            severity=1.0,
        )

        for _ in range(5):
            decision = self.engine.update(
                "vehicle_1",
                consistent=True,
            )

        self.assertAlmostEqual(decision.reputation, 0.82)

    def test_independent_vehicles(self):
        self.engine.update(
            "vehicle_1",
            consistent=False,
            severity=1.0,
        )

        decision = self.engine.get_decision("vehicle_2")

        self.assertEqual(decision.reputation, 1.0)


if __name__ == "__main__":
    unittest.main()