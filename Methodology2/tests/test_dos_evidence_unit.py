"""Unit tests for the DoS evidence scoring function (boundaries + validation)."""

import unittest

import _bootstrap  # noqa: F401
from dos_evidence import calculate_dos_evidence


class DosEvidenceTest(unittest.TestCase):
    def test_scoring_bands(self):
        cases = [
            (50, 100, 0),     # below threshold
            (100, 100, 25),   # exactly at threshold (ratio 1.0)
            (149, 100, 25),
            (150, 100, 50),
            (199, 100, 50),
            (200, 100, 75),
            (299, 100, 75),
            (300, 100, 100),
            (10000, 100, 100),
        ]
        for rate, threshold, expected in cases:
            self.assertEqual(
                calculate_dos_evidence(rate, threshold), expected,
                msg=f"rate={rate} threshold={threshold}",
            )

    def test_zero_rate(self):
        self.assertEqual(calculate_dos_evidence(0, 100), 0)

    def test_reject_negative_rate(self):
        with self.assertRaises(ValueError):
            calculate_dos_evidence(-1, 100)

    def test_reject_nonpositive_threshold(self):
        with self.assertRaises(ValueError):
            calculate_dos_evidence(100, 0)
        with self.assertRaises(ValueError):
            calculate_dos_evidence(100, -5)


if __name__ == "__main__":
    unittest.main()
