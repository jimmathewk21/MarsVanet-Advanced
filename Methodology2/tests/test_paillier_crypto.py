"""Unit tests for the Paillier module (stdlib-only, no third-party deps)."""

import unittest

import _bootstrap  # noqa: F401  (sets sys.path)
import paillier_crypto as pc


class PaillierCoreTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = pc.generate_keys(64)
        (cls.n,) = cls.public_key

    def test_encrypt_decrypt_roundtrip(self):
        for m in (0, 1, 2, 7, 42, 100, 255):
            c = pc.encrypt(m, self.public_key)
            self.assertEqual(pc.decrypt(c, self.private_key), m)

    def test_ciphertext_is_randomised(self):
        # Same plaintext encrypts to different ciphertexts (semantic security).
        c1 = pc.encrypt(5, self.public_key)
        c2 = pc.encrypt(5, self.public_key)
        self.assertNotEqual(c1, c2)
        self.assertEqual(pc.decrypt(c1, self.private_key), 5)
        self.assertEqual(pc.decrypt(c2, self.private_key), 5)

    def test_homomorphic_addition(self):
        a, b = 40, 60
        ca = pc.encrypt(a, self.public_key)
        cb = pc.encrypt(b, self.public_key)
        total = pc.add_ciphertexts(ca, cb, self.public_key)
        self.assertEqual(pc.decrypt(total, self.private_key), a + b)

    def test_add_plaintext_constant(self):
        c = pc.encrypt(10, self.public_key)
        c2 = pc.add_plaintext(c, 15, self.public_key)
        self.assertEqual(pc.decrypt(c2, self.private_key), 25)

    def test_aggregate_list(self):
        values = [10, 20, 30, 40]
        cts = [pc.encrypt(v, self.public_key) for v in values]
        agg = pc.aggregate(cts, self.public_key)
        self.assertEqual(pc.decrypt(agg, self.private_key), sum(values))

    def test_aggregate_empty_is_zero(self):
        agg = pc.aggregate([], self.public_key)
        self.assertEqual(pc.decrypt(agg, self.private_key), 0)

    def test_zero_and_boundary(self):
        c0 = pc.encrypt(0, self.public_key)
        self.assertEqual(pc.decrypt(c0, self.private_key), 0)
        c_max = pc.encrypt(self.n - 1, self.public_key)
        self.assertEqual(pc.decrypt(c_max, self.private_key), self.n - 1)

    def test_reject_negative_message(self):
        with self.assertRaises(ValueError):
            pc.encrypt(-1, self.public_key)

    def test_reject_too_large_message(self):
        with self.assertRaises(ValueError):
            pc.encrypt(self.n, self.public_key)

    def test_reject_non_int_message(self):
        with self.assertRaises(ValueError):
            pc.encrypt(3.5, self.public_key)

    def test_reject_invalid_ciphertext(self):
        with self.assertRaises(ValueError):
            pc.decrypt(0, self.private_key)
        with self.assertRaises(ValueError):
            pc.decrypt(self.n, self.private_key)  # gcd(n, n) != 1


class PaillierEncodingTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_key, cls.public_key = pc.generate_keys(128)
        (cls.n,) = cls.public_key

    def test_encode_decode_positive(self):
        enc = pc.encode(1.23, 100, self.n)
        self.assertEqual(enc, 123)
        self.assertAlmostEqual(pc.decode(enc, 100, self.n), 1.23)

    def test_encode_decode_negative(self):
        enc = pc.encode(-0.4, 100, self.n)
        self.assertAlmostEqual(pc.decode(enc, 100, self.n), -0.4)

    def test_signed_homomorphic_sum(self):
        # (+1.0) + (-0.4) + (+0.2) = 0.8, computed on ciphertexts.
        values = [1.0, -0.4, 0.2]
        scale = 100
        cts = [pc.encrypt(pc.encode(v, scale, self.n), self.public_key)
               for v in values]
        agg = pc.aggregate(cts, self.public_key)
        decoded = pc.decode(pc.decrypt(agg, self.private_key), scale, self.n)
        self.assertAlmostEqual(decoded, 0.8, places=6)

    def test_encode_rejects_bad_scale(self):
        with self.assertRaises(ValueError):
            pc.encode(1.0, 0, self.n)


if __name__ == "__main__":
    unittest.main()
