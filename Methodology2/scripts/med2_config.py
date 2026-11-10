"""Central configuration for Methodology 2 (mobility-aware progressive DoS mitigation).

All tunable parameters live here instead of being scattered as hardcoded
constants across the controller and helper scripts. Every value can be
overridden with an environment variable so the same source runs in different
Mininet-WiFi / Ryu environments without editing code.

Nothing in this module imports Ryu, Mininet or SUMO, so it can be imported and
unit-tested in a plain Python environment.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict, field
from pathlib import Path


# Repository-relative default for the mobility feature file. This is the CSV
# that ships inside Methodology2/. It is resolved relative to THIS file so the
# path is portable and does not depend on any particular home directory.
_METHODOLOGY2_DIR = Path(__file__).resolve().parents[1]
_DEFAULT_MOBILITY_CSV = _METHODOLOGY2_DIR / "mobility_features.csv"
_DEFAULT_HANDOVER_CSV = _METHODOLOGY2_DIR / "handover_test" / "handover_log.csv"


def _env_str(name: str, default: str) -> str:
    value = os.environ.get(name)
    return value if value not in (None, "") else default


def _env_int(name: str, default: int) -> int:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    try:
        return int(value)
    except ValueError:
        return default


def _env_float(name: str, default: float) -> float:
    value = os.environ.get(name)
    if value in (None, ""):
        return default
    try:
        return float(value)
    except ValueError:
        return default


def _env_opt_str(name: str):
    """Return an optional string: unset/empty -> None."""
    value = os.environ.get(name)
    return value if value not in (None, "") else None


@dataclass
class Med2Config:
    """Runtime configuration for detection and progressive mitigation.

    Defaults preserve the original project behaviour (5 s window, 120 pps base
    threshold, 500 kbps meter, AP2 ingress port 1 / output port 2) so existing
    experiments remain comparable. Override any field with the matching
    environment variable shown in brackets.
    """

    # --- Topology / OpenFlow assumptions -------------------------------------
    # [DOS_AP2_DPID]  Datapath ID of the access point that sees the victim's
    # ingress traffic. Hex or decimal accepted.
    ap2_dpid: int = 0x1000000000000002
    # [DOS_AP2_IN_PORT]  Ingress OpenFlow port on AP2 that attack/legit UDP
    # arrives on. MUST be confirmed with `ovs-ofctl show ap2` in the live VM.
    ap2_in_port: int = 1
    # [DOS_AP2_OUT_PORT]  Output OpenFlow port toward the victim on AP2.
    ap2_out_port: int = 2

    # --- Traffic / detection -------------------------------------------------
    # [DOS_WINDOW_SECONDS]  Sliding window used to measure packet rate.
    window_seconds: float = 5.0
    # [DOS_BASE_THRESHOLD_PPS]  Baseline packets-per-second threshold used when
    # no (fresh) mobility sample is available.
    base_threshold_pps: float = 120.0
    # [DOS_DESTINATION_IP]  Victim / protected destination.
    destination_ip: str = "10.0.0.2"
    # [DOS_ATTACKER_IP]  Optional. If set, only this source is subject to
    # progressive mitigation; if unset (default) ANY source that exceeds the
    # threshold toward the destination is handled on its own per-source state.
    attacker_ip = _env_opt_str("DOS_ATTACKER_IP")

    # --- Mitigation ----------------------------------------------------------
    # [DOS_METER_RATE_KBPS]  Stage 1 rate-limit meter band rate.
    meter_rate_kbps: int = 500
    # [DOS_METER_BURST]  Stage 1 meter burst size.
    meter_burst: int = 100
    # [DOS_METER_HARD_TIMEOUT]  Stage 1 meter flow hard timeout (s).
    meter_hard_timeout: int = 15
    # [DOS_STAGE1_DWELL_SECONDS]  Minimum time a source stays at Stage 1
    # (rate-limited by the meter) before it may escalate to Stage 2, as long as
    # it remains over threshold. This gives the Stage 1 meter a real window to
    # rate-limit, matching the "Stage 2 on PERSISTENT suspicious behaviour"
    # intent, instead of jumping to a block on the next packet. Keep it below
    # meter_hard_timeout so the meter flow is still present during the dwell.
    stage1_dwell_seconds: float = 10.0
    # [DOS_STATS_POLL_SECONDS]  Periodic OpenFlow flow/meter statistics poll.
    stats_poll_seconds: float = 1.0
    # [DOS_STAGE2_BLOCK_SECONDS]  Stage 2 temporary drop duration (s).
    stage2_block_seconds: int = 30
    # [DOS_DETECTOR_RESET_SECONDS]  Idle gap after a block expires before the
    # per-source detector state is reset so legitimate traffic can recover.
    detector_reset_seconds: float = 30.0
    # Trust penalty applied at each escalation step (diagnostic only).
    # [DOS_TRUST_PENALTY]
    trust_penalty: float = 0.4

    # --- Mobility adaptation -------------------------------------------------
    # [DOS_MOBILITY_CSV]  Mobility feature file. Defaults to the CSV shipped in
    # Methodology2/. MOBILITY_FEATURES_CSV is also honoured for backward
    # compatibility.
    mobility_csv: str = field(
        default_factory=lambda: _env_str(
            "DOS_MOBILITY_CSV",
            _env_str("MOBILITY_FEATURES_CSV", str(_DEFAULT_MOBILITY_CSV)),
        )
    )
    # [DOS_MOBILITY_MAX_AGE]  A mobility sample is only used to adapt the
    # threshold when its |sample_time - elapsed| is within this many seconds.
    # Otherwise the base threshold is used (documented fallback). This guards
    # against the SUMO-clock vs controller-clock misalignment.
    mobility_max_age_seconds: float = 5.0
    # Mobility adaptation thresholds. Dense/slow traffic lowers the threshold;
    # sparse/fast traffic raises it.
    dense_vehicle_count: int = 5          # [DOS_DENSE_VEHICLE_COUNT]
    slow_speed_mps: float = 5.0           # [DOS_SLOW_SPEED_MPS]
    sparse_vehicle_count: int = 2         # [DOS_SPARSE_VEHICLE_COUNT]
    fast_speed_mps: float = 10.0          # [DOS_FAST_SPEED_MPS]
    dense_threshold_pps: float = 90.0     # [DOS_DENSE_THRESHOLD_PPS]
    sparse_threshold_pps: float = 150.0   # [DOS_SPARSE_THRESHOLD_PPS]

    # --- Handover ------------------------------------------------------------
    handover_csv: str = field(
        default_factory=lambda: _env_str(
            "DOS_HANDOVER_CSV", str(_DEFAULT_HANDOVER_CSV)
        )
    )
    handover_window_seconds: float = 60.0   # [DOS_HANDOVER_WINDOW_SECONDS]
    high_handover_rate: float = 2.0         # [DOS_HIGH_HANDOVER_RATE] per minute
    handover_poll_seconds: float = 2.0      # [DOS_HANDOVER_POLL_SECONDS]
    # Threshold floor applied when the handover rate is high (legitimate churn).
    handover_threshold_floor_pps: float = 150.0  # [DOS_HANDOVER_THRESHOLD_FLOOR_PPS]

    @classmethod
    def from_env(cls) -> "Med2Config":
        """Build a configuration, applying environment overrides."""
        cfg = cls()
        cfg.ap2_dpid = _parse_dpid(_env_str("DOS_AP2_DPID", hex(cfg.ap2_dpid)))
        cfg.ap2_in_port = _env_int("DOS_AP2_IN_PORT", cfg.ap2_in_port)
        cfg.ap2_out_port = _env_int("DOS_AP2_OUT_PORT", cfg.ap2_out_port)

        cfg.window_seconds = _env_float("DOS_WINDOW_SECONDS", cfg.window_seconds)
        cfg.base_threshold_pps = _env_float(
            "DOS_BASE_THRESHOLD_PPS", cfg.base_threshold_pps
        )
        cfg.destination_ip = _env_str("DOS_DESTINATION_IP", cfg.destination_ip)
        cfg.attacker_ip = _env_opt_str("DOS_ATTACKER_IP")

        cfg.meter_rate_kbps = _env_int("DOS_METER_RATE_KBPS", cfg.meter_rate_kbps)
        cfg.meter_burst = _env_int("DOS_METER_BURST", cfg.meter_burst)
        cfg.meter_hard_timeout = _env_int(
            "DOS_METER_HARD_TIMEOUT", cfg.meter_hard_timeout
        )
        cfg.stage1_dwell_seconds = _env_float(
            "DOS_STAGE1_DWELL_SECONDS", cfg.stage1_dwell_seconds
        )
        cfg.stats_poll_seconds = _env_float(
            "DOS_STATS_POLL_SECONDS", cfg.stats_poll_seconds
        )
        cfg.stage2_block_seconds = _env_int(
            "DOS_STAGE2_BLOCK_SECONDS", cfg.stage2_block_seconds
        )
        cfg.detector_reset_seconds = _env_float(
            "DOS_DETECTOR_RESET_SECONDS", cfg.detector_reset_seconds
        )
        cfg.trust_penalty = _env_float("DOS_TRUST_PENALTY", cfg.trust_penalty)

        # mobility_csv / handover_csv already resolved via field defaults, but
        # re-read here so from_env() reflects the current environment.
        cfg.mobility_csv = _env_str(
            "DOS_MOBILITY_CSV",
            _env_str("MOBILITY_FEATURES_CSV", str(_DEFAULT_MOBILITY_CSV)),
        )
        cfg.mobility_max_age_seconds = _env_float(
            "DOS_MOBILITY_MAX_AGE", cfg.mobility_max_age_seconds
        )
        cfg.dense_vehicle_count = _env_int(
            "DOS_DENSE_VEHICLE_COUNT", cfg.dense_vehicle_count
        )
        cfg.slow_speed_mps = _env_float("DOS_SLOW_SPEED_MPS", cfg.slow_speed_mps)
        cfg.sparse_vehicle_count = _env_int(
            "DOS_SPARSE_VEHICLE_COUNT", cfg.sparse_vehicle_count
        )
        cfg.fast_speed_mps = _env_float("DOS_FAST_SPEED_MPS", cfg.fast_speed_mps)
        cfg.dense_threshold_pps = _env_float(
            "DOS_DENSE_THRESHOLD_PPS", cfg.dense_threshold_pps
        )
        cfg.sparse_threshold_pps = _env_float(
            "DOS_SPARSE_THRESHOLD_PPS", cfg.sparse_threshold_pps
        )

        cfg.handover_csv = _env_str("DOS_HANDOVER_CSV", str(_DEFAULT_HANDOVER_CSV))
        cfg.handover_window_seconds = _env_float(
            "DOS_HANDOVER_WINDOW_SECONDS", cfg.handover_window_seconds
        )
        cfg.high_handover_rate = _env_float(
            "DOS_HIGH_HANDOVER_RATE", cfg.high_handover_rate
        )
        cfg.handover_poll_seconds = _env_float(
            "DOS_HANDOVER_POLL_SECONDS", cfg.handover_poll_seconds
        )
        cfg.handover_threshold_floor_pps = _env_float(
            "DOS_HANDOVER_THRESHOLD_FLOOR_PPS", cfg.handover_threshold_floor_pps
        )
        return cfg

    def as_dict(self) -> dict:
        return asdict(self)


def _parse_dpid(value: str) -> int:
    """Parse a DPID given as hex ('0x...') or decimal string."""
    value = value.strip()
    try:
        if value.lower().startswith("0x"):
            return int(value, 16)
        return int(value)
    except ValueError:
        # Fall back to the documented default rather than crashing the import.
        return 0x1000000000000002


if __name__ == "__main__":
    import json

    print(json.dumps(Med2Config.from_env().as_dict(), indent=2, default=str))
