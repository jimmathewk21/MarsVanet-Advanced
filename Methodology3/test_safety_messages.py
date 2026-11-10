import json
import unittest

from safety_messages import parse_safety_message


class TestSafetyMessages(unittest.TestCase):
    def setUp(self):
        self.message = dict(vehicle_id="sta1", timestamp=1, x=0, y=0, speed=10)

    def test_valid(self):
        result = parse_safety_message(json.dumps(self.message).encode())
        self.assertEqual(result.vehicle_id, "sta1")
        self.assertEqual(result.speed, 10)

    def test_bad_structure_size_encoding_and_duplicates(self):
        for payload in (b"", b"x" * 1025, b"[]", b"null", b"1", b"{", b"\xff",
                        b'{"x":1,"x":2}', b"[" * 1000, "not bytes"):
            with self.subTest(payload=repr(payload)[:50]), self.assertRaises(ValueError):
                parse_safety_message(payload)

    def test_missing_or_extra_fields(self):
        missing = self.message.copy()
        missing.pop("x")
        for data in (missing, dict(self.message, extra=1)):
            with self.assertRaises(ValueError):
                parse_safety_message(json.dumps(data).encode())

    def test_strict_field_types_and_finite_numbers(self):
        for key in ("timestamp", "x", "y", "speed"):
            for value in (True, None, "10", [], {}, float("inf"), float("nan"), 10**400):
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    parse_safety_message(json.dumps(dict(self.message, **{key: value})).encode())
        for value in (1, None, "", "a" * 65, []):
            with self.subTest(vehicle_id=value), self.assertRaises(ValueError):
                parse_safety_message(json.dumps(dict(self.message, vehicle_id=value)).encode())

    def test_encoding_bounds(self):
        for key, value in (("timestamp", -1), ("timestamp", 1e13), ("x", 1e8),
                           ("y", -1e8), ("speed", 1e5)):
            with self.subTest(key=key), self.assertRaises(ValueError):
                parse_safety_message(json.dumps(dict(self.message, **{key: value})).encode())

    def test_physical_violations_are_scoreable(self):
        for speed in (-1, 60):
            result = parse_safety_message(json.dumps(dict(self.message, speed=speed)).encode())
            self.assertEqual(result.speed, speed)


if __name__ == "__main__":
    unittest.main()
