"""Unit tests for the privacy-preserving trust / evidence aggregation module."""

import unittest

import _bootstrap  # noqa: F401
import paillier_crypto as pc
import trust_aggregation as ta
from dos_evidence import calculate_dos_evidence


class TrustAggregationTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.keys = pc.generate_keys(128)  # (private, public)

    def test_multi_observer_sum_correct(self):
        result = ta.run_privacy_preserving_aggregation(
            [40, 40, 20], threshold=100, keys=self.keys
        )
        self.assertEqual(result.observer_count, 3)
        self.assertEqual(result.decrypted_total, 100)
        self.assertTrue(result.over_threshold)

    def test_below_threshold(self):
        result = ta.run_privacy_preserving_aggregation(
            [10, 10], threshold=100, keys=self.keys
        )
        self.assertEqual(result.decrypted_total, 20)
        self.assertFalse(result.over_threshold)

    def test_aggregator_never_decrypts_individuals(self):
        # The aggregator only ever holds the public key and a running product.
        _private, public = self.keys
        aggregator = ta.Aggregator(public, max_contribution=100)
        self.assertFalse(hasattr(aggregator, "private_key"))
        observer = ta.Observer(public)
        aggregator.add(observer.contribute(30))
        aggregator.add(observer.contribute(25))
        self.assertEqual(aggregator.count, 2)
        # Only the Decryptor (with the private key) can reveal the aggregate.
        decryptor = ta.Decryptor(self.keys[0])
        self.assertEqual(decryptor.reveal(aggregator.ciphertext), 55)

    def test_out_of_range_contribution_rejected(self):
        _private, public = self.keys
        observer = ta.Observer(public, max_contribution=100)
        with self.assertRaises(ta.ContributionError):
            observer.contribute(101)
        with self.assertRaises(ta.ContributionError):
            observer.contribute(-1)
        with self.assertRaises(ta.ContributionError):
            observer.contribute(3.5)

    def test_empty_aggregate_is_zero(self):
        _private, public = self.keys
        aggregator = ta.Aggregator(public)
        decryptor = ta.Decryptor(self.keys[0])
        self.assertEqual(decryptor.reveal(aggregator.ciphertext), 0)

    def test_encrypted_dos_evidence_pipeline(self):
        # Observers compute DoS-evidence scores, encrypt them, aggregate without
        # decryption, then the authorised decryptor reveals the sum and the
        # threshold is applied AFTER decryption (Paillier cannot compare
        # ciphertexts directly).
        observations = [(150, 100), (200, 100), (300, 100)]
        scores = [calculate_dos_evidence(r, t) for r, t in observations]
        result = ta.run_privacy_preserving_aggregation(
            scores, threshold=120, keys=self.keys, max_contribution=100
        )
        self.assertEqual(result.decrypted_total, sum(scores))
        self.assertTrue(result.over_threshold)


if __name__ == "__main__":
    unittest.main()
