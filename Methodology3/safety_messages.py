"""Strict, runtime-independent UDP safety-message boundary."""

import json
from math import isfinite

from message_consistency import VehicleMessage

SAFETY_MESSAGE_PORT = 5005
MAX_MESSAGE_BYTES = 1024
VEHICLE_IPS = {"sta1": "10.0.0.1", "sta2": "10.0.0.2", "sta3": "10.0.0.3"}
FIELDS = {"vehicle_id", "timestamp", "x", "y", "speed"}


def _unique_fields(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON field")
        result[key] = value
    return result


def parse_safety_message(payload):
    """Raise ValueError for malformed input; physical violations remain scoreable."""
    if not isinstance(payload, bytes) or not 1 <= len(payload) <= MAX_MESSAGE_BYTES:
        raise ValueError("payload must contain 1..1024 bytes")
    try:
        data = json.loads(payload.decode("utf-8"), object_pairs_hook=_unique_fields)
        if not isinstance(data, dict) or set(data) != FIELDS:
            raise ValueError("expected exactly vehicle_id, timestamp, x, y, speed")
        vehicle_id = data["vehicle_id"]
        if not isinstance(vehicle_id, str) or not 1 <= len(vehicle_id) <= 64:
            raise ValueError("invalid vehicle_id")
        for key in FIELDS - {"vehicle_id"}:
            value = data[key]
            if type(value) not in (int, float) or not isfinite(value):
                raise ValueError("%s must be a finite JSON number" % key)
        # Broad encoding bounds, separate from the physical consistency policy.
        if not 0 <= data["timestamp"] <= 1e12:
            raise ValueError("timestamp outside supported range")
        if any(abs(data[key]) > 1e7 for key in ("x", "y")):
            raise ValueError("coordinates outside supported range")
        if abs(data["speed"]) > 1e4:
            raise ValueError("speed outside supported range")
        return VehicleMessage(**data)
    except (UnicodeError, TypeError, OverflowError, RecursionError) as error:
        raise ValueError("invalid safety JSON") from error
