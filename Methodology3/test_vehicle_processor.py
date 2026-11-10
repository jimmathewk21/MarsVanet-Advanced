import unittest

from message_consistency import VehicleMessage
from vehicle_processor import VehicleProcessor


class TestVehicleProcessor(unittest.TestCase):

    def setUp(self):
        self.processor = VehicleProcessor()

    def test_normal_vehicle(self):
        result = self.processor.process(
            1,
            VehicleMessage("sta1", 1.0, 0.0, 0.0, 10.0),
        )

        self.assertTrue(result.consistent)
        self.assertEqual(result.reputation, 1.0)
        self.assertEqual(result.action, "NORMAL")

    def test_suspicious_vehicle(self):
        self.processor.process(
            1,
            VehicleMessage("sta3", 1.0, 0.0, 0.0, 10.0),
        )

        result = self.processor.process(
            1,
            VehicleMessage("sta3", 2.0, 900.0, 0.0, 10.0),
        )

        self.assertFalse(result.consistent)
        self.assertAlmostEqual(result.reputation, 0.8)

    def test_progressive_enforcement(self):
        self.processor.process(
            1,
            VehicleMessage("sta3", 1.0, 0.0, 0.0, 10.0),
        )

        operations = []

        for timestamp in range(2, 7):
            result = self.processor.process(
                1,
                VehicleMessage(
                    "sta3",
                    float(timestamp),
                    float(timestamp * 900),
                    0.0,
                    10.0,
                ),
            )

            operations.append(result.operation)
            # Simulate the OpenFlow adapter's error-free barrier confirmation.
            operation = self.processor.mitigation.update(
                1, self.processor.reputation.get_decision("sta3"),
            )
            self.processor.mitigation.confirm(operation)

        self.assertIn("ADD", operations)
        self.assertIn("MODIFY", operations)
        self.assertEqual(
            result.action,
            "SEVERE_THROTTLE",
        )

    def test_independent_vehicle_reputation(self):
        self.processor.process(
            1,
            VehicleMessage("sta3", 1.0, 0.0, 0.0, 10.0),
        )

        self.processor.process(
            1,
            VehicleMessage("sta3", 2.0, 900.0, 0.0, 10.0),
        )

        legitimate = self.processor.process(
            1,
            VehicleMessage("sta1", 1.0, 0.0, 0.0, 10.0),
        )

        self.assertEqual(legitimate.reputation, 1.0)
        self.assertEqual(legitimate.action, "NORMAL")


if __name__ == "__main__":
    unittest.main()
