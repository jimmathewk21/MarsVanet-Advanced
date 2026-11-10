"""Paillier additively-homomorphic encryption (self-contained, stdlib only).

This is a *didactic* implementation used as a privacy-preserving aggregation
proof of concept for the VANET trust / DoS-evidence experiments. It is NOT a
production cryptographic library and must not be used to protect real data.

Public API (unchanged from the original project so existing tests keep working):

    generate_keys(bits)          -> (private_key, public_key)
    encrypt(message, public_key) -> ciphertext
    decrypt(ciphertext, private_key) -> message
    add_ciphertexts(a, b, public_key) -> ciphertext  (adds plaintexts mod N)

Key tuples:
    public_key  = (n,)
    private_key = (n, phi)

Additional helpers added for Methodology 2:

    add_plaintext(ciphertext, k, public_key)   homomorphic add of a constant
    aggregate(ciphertexts, public_key)         sum a list of ciphertexts
    encode(value, scale, n)                    scaled/signed int encoding
    decode(message, scale, n)                  inverse of encode

Change from the original: primality testing no longer depends on ``sympy``.
A standard Miller-Rabin test from the Python standard library is used instead,
so the module (and every test and benchmark that imports it) runs in a plain
Python environment with no third-party packages.
"""

from __future__ import annotations

from math import gcd
from secrets import randbelow


# --- Primality (stdlib Miller-Rabin) --------------------------------------

# Small primes for a quick trial-division pre-filter.
_SMALL_PRIMES = (
    2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61,
    67, 71, 73, 79, 83, 89, 97,
)


def _is_probable_prime(n: int, rounds: int = 40) -> bool:
    """Miller-Rabin probabilistic primality test."""
    if n < 2:
        return False
    for p in _SMALL_PRIMES:
        if n == p:
            return True
        if n % p == 0:
            return False

    # Write n-1 as d * 2^r.
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1

    for _ in range(rounds):
        a = 2 + randbelow(n - 3)  # witness in [2, n-2]
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _random_prime(bits: int) -> int:
    """Return a random probable prime in [2^(bits-1), 2^bits)."""
    if bits < 2:
        raise ValueError("bits must be >= 2")
    low = 1 << (bits - 1)
    span = low  # range length so result stays below 2^bits
    while True:
        candidate = low + randbelow(span)
        candidate |= 1          # make odd
        candidate |= (1 << (bits - 1))  # ensure top bit set (full size)
        if _is_probable_prime(candidate):
            return candidate


# --- Key generation --------------------------------------------------------

def generate_keys(bits: int = 256):
    """Generate a Paillier key pair.

    Returns ``(private_key, public_key)`` with
    ``public_key = (n,)`` and ``private_key = (n, phi)``.

    ``bits`` is the approximate size of the modulus N. A minimum of 32 bits is
    enforced only so the small demonstration keys used by the functional tests
    still work; real use needs >= 2048-bit keys.
    """
    if bits < 32:
        raise ValueError("Use at least 32 bits for functional tests")

    half = bits // 2
    while True:
        p = _random_prime(half)
        q = _random_prime(half)
        if p == q:
            continue
        n = p * q
        phi = (p - 1) * (q - 1)
        # For g = 1 + n, decryption needs gcd(phi, n) == 1 and phi invertible.
        if gcd(phi, n) == 1:
            return (n, phi), (n,)


# --- Core operations -------------------------------------------------------

def encrypt(message: int, public_key) -> int:
    """Encrypt an integer message in [0, N) under g = 1 + N."""
    (n,) = public_key
    if not isinstance(message, int) or not 0 <= message < n:
        raise ValueError("Message must be an integer in [0, N)")

    n_squared = n * n
    while True:
        r = randbelow(n - 1) + 1
        if gcd(r, n) == 1:
            break

    return (pow(1 + n, message, n_squared) * pow(r, n, n_squared)) % n_squared


def decrypt(ciphertext: int, private_key) -> int:
    """Decrypt a ciphertext back to its integer message."""
    n, phi = private_key
    n_squared = n * n

    if not 0 <= ciphertext < n_squared or gcd(ciphertext, n) != 1:
        raise ValueError("Invalid Paillier ciphertext")

    powered = pow(ciphertext, phi, n_squared)
    numerator = powered - 1
    if numerator % n != 0:
        raise ValueError("Ciphertext does not satisfy the decryption equation")

    message_factor = (numerator // n) % n
    return (message_factor * pow(phi, -1, n)) % n


def add_ciphertexts(ciphertext_a: int, ciphertext_b: int, public_key) -> int:
    """Homomorphically add two ciphertexts (adds their plaintexts mod N)."""
    (n,) = public_key
    n_squared = n * n
    return (ciphertext_a * ciphertext_b) % n_squared


# --- Added helpers for Methodology 2 --------------------------------------

def add_plaintext(ciphertext: int, constant: int, public_key) -> int:
    """Add a plaintext constant to an encrypted value (homomorphic)."""
    (n,) = public_key
    if not isinstance(constant, int) or not 0 <= constant < n:
        raise ValueError("Constant must be an integer in [0, N)")
    n_squared = n * n
    return (ciphertext * pow(1 + n, constant, n_squared)) % n_squared


def aggregate(ciphertexts, public_key) -> int:
    """Sum an iterable of ciphertexts. Empty input encrypts to 0 deterministically.

    An empty aggregate returns the trivial encryption of 0 (``1``), which
    decrypts to 0; callers that need semantic security for the empty case
    should encrypt(0) explicitly.
    """
    (n,) = public_key
    n_squared = n * n
    total = 1
    for ciphertext in ciphertexts:
        total = (total * ciphertext) % n_squared
    return total


def encode(value, scale: int, n: int) -> int:
    """Encode a (possibly negative, possibly fractional) value as an int in [0, N).

    ``value`` is multiplied by ``scale`` and rounded to the nearest integer.
    Negative encoded values are represented as ``N + v`` (two's-complement style
    in Z_N), which is standard for Paillier signed arithmetic as long as the
    true magnitude of every intermediate sum stays well below N/2.
    """
    if scale <= 0:
        raise ValueError("scale must be a positive integer")
    scaled = round(value * scale)
    if scaled >= 0:
        if scaled >= n:
            raise ValueError("encoded value out of range (too large for N)")
        return scaled
    neg = n + scaled
    if neg < 0:
        raise ValueError("encoded value out of range (too negative for N)")
    return neg


def decode(message: int, scale: int, n: int) -> float:
    """Inverse of :func:`encode`. Values above N/2 are interpreted as negative."""
    if scale <= 0:
        raise ValueError("scale must be a positive integer")
    if message > n // 2:
        message = message - n
    return message / scale
