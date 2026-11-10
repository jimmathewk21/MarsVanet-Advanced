import unittest

from progressive_mitigation import ProgressiveMitigation
from reputation_engine import MitigationDecision


class TestProgressiveMitigation(unittest.TestCase):

    def setUp(self):
        self.mitigation = ProgressiveMitigation()

    def decision(self, vehicle_id, action, rate):
        return MitigationDecision(
            vehicle_id=vehicle_id,
            reputation=0.5,
            classification="Test",
            action=action,
            rate_limit_kbps=rate,
        )

    def test_normal_vehicle(self):
        operation = self.mitigation.update(
            1,
            self.decision("vehicle_1", "NORMAL", None),
        )

        self.assertEqual(operation.operation, "NO_CHANGE")

    def test_add_meter(self):
        operation = self.mitigation.update(
            1,
            self.decision("vehicle_1", "LIGHT_THROTTLE", 500),
        )

        self.assertEqual(operation.operation, "ADD")
        self.assertEqual(operation.rate_kbps, 500)

    def test_modify_meter(self):
        first = self.mitigation.update(
            1,
            self.decision("vehicle_1", "LIGHT_THROTTLE", 500),
        )
        self.mitigation.confirm(first)

        operation = self.mitigation.update(
            1,
            self.decision("vehicle_1", "HEAVY_THROTTLE", 200),
        )

        self.assertEqual(operation.operation, "MODIFY")
        self.assertEqual(operation.rate_kbps, 200)

    def test_remove_meter(self):
        first = self.mitigation.update(
            1,
            self.decision("vehicle_1", "LIGHT_THROTTLE", 500),
        )
        self.mitigation.confirm(first)

        operation = self.mitigation.update(
            1,
            self.decision("vehicle_1", "NORMAL", None),
        )

        self.assertEqual(operation.operation, "REMOVE")
        self.assertIn((1, "vehicle_1"), self.mitigation.installed_meters)
        self.mitigation.confirm(operation)
        self.assertNotIn((1, "vehicle_1"), self.mitigation.installed_meters)

    def test_unconfirmed_operation_is_retried(self):
        decision = self.decision("vehicle_1", "LIGHT_THROTTLE", 500)
        first = self.mitigation.update(1, decision)
        self.assertEqual(self.mitigation.installed_meters, {})
        self.assertEqual(self.mitigation.update(1, decision), first)
        self.mitigation.confirm(first)
        self.assertEqual(self.mitigation.update(1, decision).operation, "NO_CHANGE")

    def test_forget_only_disconnected_switch(self):
        decision = self.decision("vehicle_1", "LIGHT_THROTTLE", 500)
        for switch in (1, 2):
            self.mitigation.confirm(self.mitigation.update(switch, decision))
        self.mitigation.forget_switch(1)
        self.assertEqual(self.mitigation.update(1, decision).operation, "ADD")
        self.assertEqual(self.mitigation.update(2, decision).operation, "NO_CHANGE")

    def test_independent_vehicles(self):
        first = self.mitigation.update(
            1,
            self.decision("vehicle_1", "LIGHT_THROTTLE", 500),
        )

        second = self.mitigation.update(
            1,
            self.decision("vehicle_2", "HEAVY_THROTTLE", 200),
        )

        self.assertNotEqual(first.meter_id, second.meter_id)

    def test_vehicle_handover(self):
        decision = self.decision(
            "vehicle_1",
            "LIGHT_THROTTLE",
            500,
        )

        first = self.mitigation.update(1, decision)
        second = self.mitigation.update(2, decision)

        self.assertEqual(first.operation, "ADD")
        self.assertEqual(second.operation, "ADD")
        self.assertEqual(first.meter_id, second.meter_id)


if __name__ == "__main__":
    unittest.main()
