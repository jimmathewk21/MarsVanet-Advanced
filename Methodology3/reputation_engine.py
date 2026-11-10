from dataclasses import dataclass, field
from typing import Optional


@dataclass
class VehicleReputation:
    vehicle_id: str
    score: float = 1.0
    total_messages: int = 0
    violations: int = 0
    consecutive_valid: int = 0
    history: list = field(default_factory=list)


@dataclass(frozen=True)
class MitigationDecision:
    vehicle_id: str
    reputation: float
    classification: str
    action: str
    rate_limit_kbps: Optional[int]


class ReputationEngine:

    def __init__(
        self,
        penalty_factor=0.20,
        recovery_factor=0.02,
        recovery_interval=5,
    ):
        self.vehicles = {}

        self.penalty_factor = penalty_factor
        self.recovery_factor = recovery_factor
        self.recovery_interval = recovery_interval

    def get_vehicle(self, vehicle_id):
        if vehicle_id not in self.vehicles:
            self.vehicles[vehicle_id] = VehicleReputation(
                vehicle_id=vehicle_id
            )

        return self.vehicles[vehicle_id]

    def update(self, vehicle_id, consistent, severity=0.0):

        vehicle = self.get_vehicle(vehicle_id)
        vehicle.total_messages += 1

        if not consistent:
            vehicle.violations += 1
            vehicle.consecutive_valid = 0

            penalty = self.penalty_factor * max(
                0.0,
                min(1.0, severity),
            )

            vehicle.score = round(max(
                0.0,
                vehicle.score - penalty,
            ), 10)

        else:
            vehicle.consecutive_valid += 1

            if (
                vehicle.consecutive_valid
                >= self.recovery_interval
            ):
                vehicle.score = round(min(
                    1.0,
                    vehicle.score + self.recovery_factor,
                ), 10)

                vehicle.consecutive_valid = 0

        decision = self.get_decision(vehicle_id)

        vehicle.history.append({
            "message": vehicle.total_messages,
            "consistent": consistent,
            "severity": severity,
            "reputation": vehicle.score,
            "action": decision.action,
        })
        # Keep diagnostics bounded during long-running simulations.
        del vehicle.history[:-1000]

        return decision

    def get_decision(self, vehicle_id):

        vehicle = self.get_vehicle(vehicle_id)
        score = vehicle.score

        if score >= 0.80:
            return MitigationDecision(
                vehicle_id,
                score,
                "Trusted",
                "NORMAL",
                None,
            )

        elif score >= 0.60:
            return MitigationDecision(
                vehicle_id,
                score,
                "Under observation",
                "MONITOR",
                None,
            )

        elif score >= 0.40:
            return MitigationDecision(
                vehicle_id,
                score,
                "Suspicious",
                "LIGHT_THROTTLE",
                500,
            )

        elif score >= 0.20:
            return MitigationDecision(
                vehicle_id,
                score,
                "High risk",
                "HEAVY_THROTTLE",
                200,
            )

        else:
            return MitigationDecision(
                vehicle_id,
                score,
                "Critical",
                "SEVERE_THROTTLE",
                100,
            )
        
