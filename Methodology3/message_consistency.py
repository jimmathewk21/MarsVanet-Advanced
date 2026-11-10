from dataclasses import dataclass
from math import hypot, isfinite


@dataclass(frozen=True)
class VehicleMessage:
    vehicle_id: str
    timestamp: float
    x: float
    y: float
    speed: float  # metres per second


@dataclass(frozen=True)
class ConsistencyResult:
    consistent: bool
    reason: str
    severity: float


class MessageConsistencyChecker:
    """
    Checks whether consecutive vehicle messages are physically plausible.

    Coordinates are assumed to be in metres.
    Speed is assumed to be in metres per second.
    """

    def __init__(
        self,
        max_speed=55.0,
        max_acceleration=8.0,
        position_tolerance=10.0,
    ):
        self.max_speed = max_speed
        self.max_acceleration = max_acceleration
        self.position_tolerance = position_tolerance

        self.previous_messages = {}

    def check(self, message: VehicleMessage) -> ConsistencyResult:

        if (
            not message.vehicle_id
            or not all(
                isfinite(value)
                for value in (
                    message.timestamp,
                    message.x,
                    message.y,
                    message.speed,
                )
            )
        ):
            return ConsistencyResult(
                False,
                "Invalid vehicle message",
                1.0,
            )

        if message.speed < 0 or message.speed > self.max_speed:
            return ConsistencyResult(
                False,
                "Reported speed exceeds allowed range",
                0.8,
            )

        previous = self.previous_messages.get(message.vehicle_id)

        if previous is None:
            self.previous_messages[message.vehicle_id] = message

            return ConsistencyResult(
                True,
                "First observation",
                0.0,
            )

        dt = message.timestamp - previous.timestamp

        if dt <= 0:
            return ConsistencyResult(
                False,
                "Non-increasing timestamp",
                0.8,
            )

        distance = hypot(
            message.x - previous.x,
            message.y - previous.y,
        )

        max_distance = (
            max(previous.speed, message.speed) * dt
            + 0.5 * self.max_acceleration * dt * dt
            + self.position_tolerance
        )

        if distance > max_distance:
            return ConsistencyResult(
                False,
                "Implausible vehicle displacement",
                1.0,
            )

        acceleration = abs(
            message.speed - previous.speed
        ) / dt

        if acceleration > self.max_acceleration:
            return ConsistencyResult(
                False,
                "Implausible acceleration",
                0.7,
            )

        self.previous_messages[message.vehicle_id] = message

        return ConsistencyResult(
            True,
            "Message consistent",
            0.0,
        )