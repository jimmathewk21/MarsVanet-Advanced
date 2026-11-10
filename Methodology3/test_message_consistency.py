import unittest

from message_consistency import (
    MessageConsistencyChecker,
    VehicleMessage,
)


class TestMessageConsistency(unittest.TestCase):

    def setUp(self):
        self.checker = MessageConsistencyChecker()

    def test_first_message(self):
        message = VehicleMessage(
            vehicle_id="vehicle_1",
            timestamp=1.0,
            x=0.0,
            y=0.0,
            speed=10.0,
        )

        result = self.checker.check(message)

        self.assertTrue(result.consistent)

    def test_normal_movement(self):
        self.checker.check(
            VehicleMessage("vehicle_1", 1.0, 0.0, 0.0, 10.0)
        )

        result = self.checker.check(
            VehicleMessage("vehicle_1", 2.0, 10.0, 0.0, 10.0)
        )

        self.assertTrue(result.consistent)

    def test_position_spoofing(self):
        self.checker.check(
            VehicleMessage("vehicle_1", 1.0, 0.0, 0.0, 10.0)
        )

        result = self.checker.check(
            VehicleMessage("vehicle_1", 2.0, 900.0, 0.0, 10.0)
        )

        self.assertFalse(result.consistent)
        self.assertEqual(
            result.reason,
            "Implausible vehicle displacement",
        )

    def test_invalid_timestamp(self):
        self.checker.check(
            VehicleMessage("vehicle_1", 5.0, 0.0, 0.0, 10.0)
        )

        result = self.checker.check(
            VehicleMessage("vehicle_1", 4.0, 10.0, 0.0, 10.0)
        )

        self.assertFalse(result.consistent)


if __name__ == "__main__":
    unittest.main()