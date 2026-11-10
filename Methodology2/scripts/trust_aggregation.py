"""Privacy-preserving trust / DoS-evidence aggregation over Paillier.

This module defines a small, clearly-scoped architecture on top of
``paillier_crypto`` that aggregates per-observer contributions *without the
aggregation component ever seeing an individual plaintext contribution*.

Roles and trust model
----------------------
* **Observer** — a vehicle or edge node that computes a local, bounded numeric
  contribution (a trust penalty, or a DoS-evidence score from
  ``dos_evidence.calculate_dos_evidence``) and encrypts it with the shared
  Paillier **public** key. It never holds the private key.
* **Aggregator** — combines ciphertexts homomorphically. It holds only the
  public key, so it can add contributions but cannot read any individual value
  or the running sum. This is the component from which individual contributions
  are hidden.
* **Decryptor** — the single authorised party that holds the **private** key.
  It decrypts *only the aggregate* and then applies the detection threshold to
  the decrypted sum.

What Paillier does and does not provide here
--------------------------------------------
* Provides: confidentiality of each observer's contribution from the
  aggregator, and additive homomorphism so the sum can be computed on
  ciphertexts.
* Does NOT provide: arbitrary comparisons or threshold tests on ciphertexts.
  Paillier is additively homomorphic only. The threshold is therefore applied
  *after* the authorised Decryptor decrypts the aggregate — never on ciphertext
  directly.
* Does NOT provide: authenticity or honesty of a contribution. A compromised
  observer can still submit a false (but in-range) value. Confidentiality is
  not integrity. Observer authentication, replay protection and contribution
  bounds must be enforced separately; this module enforces *bounds and type*
  only, and documents the rest as out of scope.

This is a proof-of-concept module with a documented interface. It is NOT
integrated into the live Ryu controller's fast path (see
PENDING_WORK_AND_VALIDATION.md); it is exercised by the offline experiment /
benchmark scripts and unit tests.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional

import paillier_crypto as paillier


class ContributionError(ValueError):
    """Raised when an observer contribution is malformed or out of range."""


@dataclass
class Observer:
    """An observer that encrypts bounded integer contributions.

    ``max_contribution`` bounds each value; the aggregator separately checks
    that the number of accepted contributions cannot overflow N (see
    :class:`Aggregator`).
    """

    public_key: tuple
    name: str = "observer"
    max_contribution: int = 100

    def contribute(self, value: int) -> int:
        if not isinstance(value, int):
            raise ContributionError(f"{self.name}: contribution must be int")
        if value < 0:
            raise ContributionError(f"{self.name}: contribution must be >= 0")
        if value > self.max_contribution:
            raise ContributionError(
                f"{self.name}: contribution {value} exceeds max "
                f"{self.max_contribution}"
            )
        return paillier.encrypt(value, self.public_key)


@dataclass
class Aggregator:
    """Combines ciphertexts without ever decrypting them.

    Holds only the public key. Tracks how many contributions have been added
    and refuses contributions once the worst-case plaintext sum could approach
    N (overflow guard), so the decrypted aggregate is always correct.
    """

    public_key: tuple
    max_contribution: int = 100
    _total: Optional[int] = field(default=None, init=False)
    _count: int = field(default=0, init=False)

    def __post_init__(self):
        (self._n,) = self.public_key
        # Leave a large safety margin below N.
        self._max_count = max(1, (self._n // 2) // max(1, self.max_contribution))

    def add(self, ciphertext: int) -> None:
        if self._count + 1 > self._max_count:
            raise ContributionError(
                "aggregation overflow guard: too many contributions for N"
            )
        if self._total is None:
            self._total = ciphertext % (self._n * self._n)
        else:
            self._total = paillier.add_ciphertexts(
                self._total, ciphertext, self.public_key
            )
        self._count += 1

    @property
    def count(self) -> int:
        return self._count

    @property
    def ciphertext(self) -> int:
        """The encrypted aggregate. Encrypts 0 when nothing was added."""
        if self._total is None:
            return paillier.encrypt(0, self.public_key)
        return self._total


@dataclass
class Decryptor:
    """The only party holding the private key. Reveals the aggregate only."""

    private_key: tuple

    def reveal(self, aggregate_ciphertext: int) -> int:
        return paillier.decrypt(aggregate_ciphertext, self.private_key)


@dataclass
class AggregationResult:
    observer_count: int
    decrypted_total: int
    average: float
    over_threshold: bool
    threshold: float


def run_privacy_preserving_aggregation(
    contributions: List[int],
    threshold: float,
    key_bits: int = 256,
    max_contribution: int = 100,
    keys=None,
):
    """End-to-end privacy-preserving aggregation + post-decryption threshold.

    Each contribution is encrypted by an :class:`Observer`, combined by an
    :class:`Aggregator` that never decrypts, then the aggregate alone is
    revealed by the :class:`Decryptor` and the threshold is applied to the
    decrypted sum.

    Returns an :class:`AggregationResult`. Raises :class:`ContributionError`
    on any malformed/out-of-range contribution.
    """
    if keys is None:
        private_key, public_key = paillier.generate_keys(key_bits)
    else:
        private_key, public_key = keys

    aggregator = Aggregator(public_key, max_contribution=max_contribution)
    for value in contributions:
        observer = Observer(public_key, max_contribution=max_contribution)
        aggregator.add(observer.contribute(value))

    decryptor = Decryptor(private_key)
    total = decryptor.reveal(aggregator.ciphertext)
    count = aggregator.count
    average = (total / count) if count else 0.0
    return AggregationResult(
        observer_count=count,
        decrypted_total=total,
        average=average,
        over_threshold=total >= threshold,
        threshold=threshold,
    )
