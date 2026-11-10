"""Illustrate the mobility-aware detection + progressive-mitigation logic.

This runs the REAL decision code from ``mobility_detector`` against synthetic
inputs so the behaviour can be seen without the SDN/SUMO runtime. It is a logic
demonstration, NOT a network experiment: it produces no packet-delivery,
throughput or latency numbers (those require the live testbed).

    python3 detector_demo.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from med2_config import Med2Config
import mobility_detector as md


def show_threshold(label, sample, handover_rate, cfg):
    threshold, reason = md.select_threshold(cfg, sample, handover_rate)
    print(f"  {label}: threshold={threshold:.0f} pps  ({reason})")


def main():
    cfg = Med2Config()
    print("Mobility-aware threshold selection")
    print("-" * 60)
    show_threshold(
        "urban (dense/slow: 8 veh, 4 m/s)",
        {"vehicle_count": 8, "average_speed": 4.0}, 0.0, cfg,
    )
    show_threshold(
        "highway (sparse/fast: 2 veh, 30 m/s)",
        {"vehicle_count": 2, "average_speed": 30.0}, 0.0, cfg,
    )
    show_threshold(
        "nominal (3 veh, 12 m/s)",
        {"vehicle_count": 3, "average_speed": 12.0}, 0.0, cfg,
    )
    show_threshold("no mobility sample (fallback)", None, 0.0, cfg)
    show_threshold(
        "high handover churn (dense sample + 3/min)",
        {"vehicle_count": 8, "average_speed": 4.0}, 3.0, cfg,
    )

    print()
    print("Progressive-mitigation decision trace (attacker at 200 pps,")
    print("threshold 120 pps, urban context):")
    print("-" * 60)
    state = md.SourceState()
    threshold = 120
    now = 1000.0
    # Attack sustained -> escalate 0->1->2, then hold.
    for step, rate in [(0, 200), (1, 200), (2, 200), (3, 200)]:
        t = now + step
        d = md.decide(state, rate, threshold, t, cfg)
        print(f"  t+{step}s rate={rate}: {d.action:<16} stage={d.stage} "
              f"trust={d.trust:.2f}  ({d.reason})")

    # Attack stops; after block expiry + idle gap the detector resets.
    recover_t = now + cfg.stage2_block_seconds + cfg.detector_reset_seconds + 5
    d = md.decide(state, 0, threshold, recover_t, cfg)
    print(f"  t+{int(recover_t - now)}s rate=0: {d.action:<16} stage={d.stage} "
          f"trust={d.trust:.2f}  ({d.reason})")


if __name__ == "__main__":
    main()
