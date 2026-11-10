"""Mobility-aware DoS detection logic (runtime-independent, unit-testable).

This module holds the *decision logic* for Methodology 2. It deliberately does
NOT import Ryu, Mininet or SUMO so it can be imported and tested in a plain
Python environment. The Ryu controller (``dos_defense_v2.py``) imports these
functions and classes and applies the resulting decisions to OpenFlow.

Responsibilities:

* Load and validate the SUMO mobility feature CSV (schema, timestamps, missing
  values, stale data).
* Select a detection threshold from the current mobility context, with a
  documented fallback to the configured base threshold when no fresh sample is
  available.
* Measure packet rate over a sliding window using the *observed* duration so
  early-window rates are not underestimated.
* Decide the progressive-mitigation stage transition from the measured rate,
  the selected threshold and the current per-source state, including reset /
  recovery after a temporary block.

Design principle (honesty): vehicle mobility is used only to *adjust the
threshold*. Mobility alone is never treated as proof of an attack. An attack
decision always requires the measured packet rate to exceed the selected
threshold.
"""

from __future__ import annotations

import csv
from collections import deque
from dataclasses import dataclass, field
from typing import Optional


# Columns the detector relies on in the mobility feature CSV. Extra columns are
# ignored; these three must be present and parseable.
REQUIRED_COLUMNS = ("time", "vehicle_count", "average_speed")


@dataclass
class MobilityLoadReport:
    """Outcome of loading the mobility feature file."""

    path: str
    ok: bool
    record_count: int = 0
    skipped_rows: int = 0
    error: Optional[str] = None
    missing_columns: tuple = ()


def load_mobility_features(path: str):
    """Load and validate mobility features.

    Returns ``(records, report)`` where ``records`` is a list of dicts with
    keys ``time``, ``vehicle_count`` and ``average_speed``. Rows with missing
    or non-numeric values are skipped and counted; the detector can safely
    operate on the remaining rows (or on an empty list -> base-threshold
    fallback).
    """
    records = []
    try:
        with open(path, newline="") as handle:
            reader = csv.DictReader(handle)
            header = reader.fieldnames or []
            missing = tuple(c for c in REQUIRED_COLUMNS if c not in header)
            if missing:
                return records, MobilityLoadReport(
                    path=path,
                    ok=False,
                    error="missing required columns",
                    missing_columns=missing,
                )

            skipped = 0
            for row in reader:
                try:
                    record = {
                        "time": float(row["time"]),
                        "vehicle_count": int(float(row["vehicle_count"])),
                        "average_speed": float(row["average_speed"]),
                    }
                except (TypeError, ValueError, KeyError):
                    skipped += 1
                    continue
                # Reject physically impossible values rather than trusting them.
                if record["vehicle_count"] < 0 or record["average_speed"] < 0:
                    skipped += 1
                    continue
                records.append(record)

        records.sort(key=lambda r: r["time"])
        return records, MobilityLoadReport(
            path=path,
            ok=True,
            record_count=len(records),
            skipped_rows=skipped,
        )
    except OSError as error:
        return records, MobilityLoadReport(
            path=path, ok=False, error=str(error)
        )


def nearest_sample(records, elapsed, max_age):
    """Return the mobility record closest in time to ``elapsed`` seconds.

    Returns ``None`` when there are no records, or when the closest record is
    older/farther than ``max_age`` seconds (stale-data guard). This prevents an
    unrelated far-away SUMO trace row from silently adjusting the threshold when
    the SUMO clock and controller clock are not aligned.
    """
    if not records:
        return None
    sample = min(records, key=lambda r: abs(r["time"] - elapsed))
    if abs(sample["time"] - elapsed) > max_age:
        return None
    return sample


def select_threshold(cfg, sample, handover_rate):
    """Select the packets-per-second threshold and explain the choice.

    Parameters
    ----------
    cfg : Med2Config
    sample : dict or None
        A fresh mobility sample (``nearest_sample`` result) or ``None``.
    handover_rate : float
        Current handover rate in events per minute.

    Returns ``(threshold, reason)``.
    """
    threshold = cfg.base_threshold_pps
    reasons = []

    if sample is None:
        reasons.append("no fresh mobility sample -> base threshold")
    else:
        count = sample["vehicle_count"]
        speed = sample["average_speed"]
        if count >= cfg.dense_vehicle_count or speed < cfg.slow_speed_mps:
            threshold = cfg.dense_threshold_pps
            reasons.append(
                f"dense/slow (count={count}, speed={speed:.1f}) "
                f"-> {threshold:.0f} pps"
            )
        elif count <= cfg.sparse_vehicle_count and speed >= cfg.fast_speed_mps:
            threshold = cfg.sparse_threshold_pps
            reasons.append(
                f"sparse/fast (count={count}, speed={speed:.1f}) "
                f"-> {threshold:.0f} pps"
            )
        else:
            reasons.append(
                f"nominal mobility (count={count}, speed={speed:.1f}) "
                f"-> base {threshold:.0f} pps"
            )

    # High legitimate handover churn raises the threshold floor so that the
    # traffic bursts that accompany re-association are not misread as an attack.
    if handover_rate >= cfg.high_handover_rate:
        if threshold < cfg.handover_threshold_floor_pps:
            threshold = cfg.handover_threshold_floor_pps
            reasons.append(
                f"high handover rate {handover_rate:.2f}/min -> floor "
                f"{threshold:.0f} pps"
            )
        else:
            reasons.append(
                f"high handover rate {handover_rate:.2f}/min (floor already met)"
            )

    return threshold, "; ".join(reasons)


class PacketRateTracker:
    """Sliding-window packet-rate estimator.

    Uses the *observed* span of timestamps inside the window as the divisor so
    that during the first few seconds (before the window is full) the rate is
    not underestimated by dividing by the full window length.
    """

    def __init__(self, window_seconds):
        self.window_seconds = float(window_seconds)
        self._times = deque()

    def add(self, now):
        self._times.append(now)
        self._evict(now)

    def _evict(self, now):
        cutoff = now - self.window_seconds
        while self._times and self._times[0] < cutoff:
            self._times.popleft()

    def rate(self, now):
        """Packets per second over the observed span."""
        self._evict(now)
        count = len(self._times)
        if count == 0:
            return 0.0
        span = now - self._times[0]
        # Use a small floor so a burst arriving in <1s is not divided by ~0.
        if span < 1.0:
            span = min(1.0, self.window_seconds)
        return count / span

    def __len__(self):
        return len(self._times)


# Stage / action constants -------------------------------------------------
STAGE_NORMAL = 0
STAGE_METER = 1       # Stage 1: rate limit
STAGE_BLOCK = 2       # Stage 2: temporary drop

ACTION_NONE = "none"
ACTION_INSTALL_METER = "install_meter"
ACTION_INSTALL_BLOCK = "install_block"
ACTION_RESET = "reset"


@dataclass
class SourceState:
    """Per-source detector state."""

    stage: int = STAGE_NORMAL
    trust: float = 1.0
    last_seen: float = 0.0
    blocked_at: float = 0.0
    metered_at: float = 0.0


@dataclass
class Decision:
    action: str
    stage: int
    rate: float
    threshold: float
    trust: float
    reason: str
    over_threshold: bool = False


def decide(state: SourceState, rate, threshold, now, cfg):
    """Decide the next stage/action for one source. Pure function.

    Progression:
        NORMAL --over threshold--> METER (Stage 1, rate limit)
        METER  --still over-------> BLOCK (Stage 2, temporary drop)
        BLOCK  --block expired & idle gap elapsed--> RESET -> NORMAL

    The function mutates and returns the ``state`` for convenience and also
    returns a :class:`Decision` describing what the controller should do and
    why. Mobility never triggers mitigation on its own: an escalation requires
    ``rate >= threshold``.
    """
    over = rate >= threshold

    # Recovery: once a temporary block has expired and we have seen an idle gap,
    # reset the source so legitimate traffic is observed again from scratch.
    if state.stage == STAGE_BLOCK:
        block_expired = (now - state.blocked_at) >= cfg.stage2_block_seconds
        idle_gap = (now - state.last_seen) >= cfg.detector_reset_seconds
        if block_expired and (idle_gap or not over):
            state.stage = STAGE_NORMAL
            state.trust = 1.0
            state.last_seen = now
            return Decision(
                action=ACTION_RESET,
                stage=state.stage,
                rate=rate,
                threshold=threshold,
                trust=state.trust,
                reason="stage 2 block expired and traffic subsided -> reset",
                over_threshold=over,
            )

    state.last_seen = now

    if not over:
        return Decision(
            action=ACTION_NONE,
            stage=state.stage,
            rate=rate,
            threshold=threshold,
            trust=state.trust,
            reason="rate below threshold",
            over_threshold=False,
        )

    # Over threshold: escalate one stage at a time.
    if state.stage == STAGE_NORMAL:
        state.stage = STAGE_METER
        state.metered_at = now
        state.trust = max(0.0, state.trust - cfg.trust_penalty)
        return Decision(
            action=ACTION_INSTALL_METER,
            stage=state.stage,
            rate=rate,
            threshold=threshold,
            trust=state.trust,
            reason="rate >= threshold at stage 0 -> stage 1 meter",
            over_threshold=True,
        )

    if state.stage == STAGE_METER:
        # Only escalate to Stage 2 once the source has been rate-limited for at
        # least the dwell time AND is still over threshold (persistent abuse).
        # During the dwell, hold Stage 1 so the meter actually rate-limits.
        if (now - state.metered_at) < cfg.stage1_dwell_seconds:
            return Decision(
                action=ACTION_NONE,
                stage=state.stage,
                rate=rate,
                threshold=threshold,
                trust=state.trust,
                reason="rate >= threshold but within stage 1 dwell -> hold meter",
                over_threshold=True,
            )
        state.stage = STAGE_BLOCK
        state.trust = max(0.0, state.trust - cfg.trust_penalty)
        state.blocked_at = now
        return Decision(
            action=ACTION_INSTALL_BLOCK,
            stage=state.stage,
            rate=rate,
            threshold=threshold,
            trust=state.trust,
            reason="rate still >= threshold after stage 1 dwell -> stage 2 block",
            over_threshold=True,
        )

    # Already blocked and still over threshold: hold the block, no new rule.
    state.blocked_at = now
    return Decision(
        action=ACTION_NONE,
        stage=state.stage,
        rate=rate,
        threshold=threshold,
        trust=state.trust,
        reason="rate still >= threshold while blocked -> hold block",
        over_threshold=True,
    )


def format_decision_log(source_ip, sample, decision: Decision):
    """Build a single structured log line for a detection decision."""
    if sample is None:
        mob = "mobility=none"
    else:
        mob = (
            f"mobility(count={sample['vehicle_count']},"
            f"speed={sample['average_speed']:.1f})"
        )
    return (
        f"src={source_ip} {mob} rate={decision.rate:.1f}pps "
        f"threshold={decision.threshold:.0f}pps over={decision.over_threshold} "
        f"stage={decision.stage} action={decision.action} "
        f"trust={decision.trust:.2f} reason=\"{decision.reason}\""
    )