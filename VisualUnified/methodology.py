"""Load original, standard-library-only policies without importing Ryu.

Private module names avoid shadowing callers' imports. The safety parser's one
absolute import is resolved while loading and then restored immediately.
"""
import importlib.util
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]


def _load(name, relative_path):
    name = '_visual_original_' + name
    if name in sys.modules:
        return sys.modules[name]
    path = ROOT / relative_path
    if not path.is_file():
        raise RuntimeError(f'Required original policy file is missing: {path}')
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module  # dataclasses resolve their defining module here.
    try:
        spec.loader.exec_module(module)
    except Exception:
        sys.modules.pop(name, None)
        raise
    return module


md = _load('mobility_detector', 'Methodology2/scripts/mobility_detector.py')
Med2Config = _load('med2_config', 'Methodology2/scripts/med2_config.py').Med2Config
consistency = _load('consistency', 'Methodology3/message_consistency.py')
ReputationEngine = _load('reputation', 'Methodology3/reputation_engine.py').ReputationEngine
_previous = sys.modules.get('message_consistency')
try:
    sys.modules['message_consistency'] = consistency
    parse_safety_message = _load('safety', 'Methodology3/safety_messages.py').parse_safety_message
finally:
    if _previous is None:
        sys.modules.pop('message_consistency', None)
    else:
        sys.modules['message_consistency'] = _previous


def detector_config(config):
    """Explicit simulation settings, independent of the host's DOS_* env vars."""
    cfg = Med2Config()
    cfg.base_threshold_pps = config['base_pps']
    cfg.window_seconds = config['m2_window_sec']
    cfg.stage1_dwell_seconds = config['stage2_after_sec']
    cfg.stage2_block_seconds = config['block_duration_sec']
    cfg.meter_hard_timeout = config['m2_meter_lifetime_sec']
    cfg.detector_reset_seconds = config['m2_reset_sec']
    cfg.dense_threshold_pps = config['dense_pps']
    cfg.sparse_threshold_pps = config['sparse_pps']
    cfg.handover_threshold_floor_pps = config['handover_floor_pps']
    return cfg


def reputation_policy(score):
    engine = ReputationEngine()
    engine.get_vehicle('vehicle').score = score
    decision = engine.get_decision('vehicle')
    return decision.rate_limit_kbps, decision.action


def update_reputation(score, streak, consistent, severity, config):
    engine = ReputationEngine(config['reputation_penalty'],
                              config['recovery_gain'], config['recovery_every'])
    vehicle = engine.get_vehicle('vehicle')
    vehicle.score, vehicle.consecutive_valid = score, streak
    decision = engine.update('vehicle', consistent, severity)
    return decision.reputation, vehicle.consecutive_valid


def check_motion(message, previous, config):
    checker = consistency.MessageConsistencyChecker(
        max_speed=config['max_reported_speed_kmh'] / 3.6,
        max_acceleration=config['max_acceleration_mps2'],
        position_tolerance=config['position_tolerance_m'])
    if previous is not None:
        checker.previous_messages[message.vehicle_id] = previous
    return checker.check(message)
