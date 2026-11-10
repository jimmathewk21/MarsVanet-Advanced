from __future__ import annotations

from dataclasses import dataclass

from message_consistency import (
    MessageConsistencyChecker,
    VehicleMessage,
)
from reputation_engine import ReputationEngine
from progressive_mitigation import ProgressiveMitigation


@dataclass(frozen=True)
class ProcessingResult:
    vehicle_id: str
    consistent: bool
    reason: str
    reputation: float
    action: str
    rate_limit_kbps: int | None
    operation: str


class VehicleProcessor:
    """
    Combines consistency checking, reputation scoring,
    and progressive mitigation decisions.

    Does not send OpenFlow messages directly. The adapter must confirm the
    planned operation through mitigation.confirm() after switch acknowledgement.
    """

    def __init__(self):
        self.checker = MessageConsistencyChecker()
        self.reputation = ReputationEngine()
        self.mitigation = ProgressiveMitigation()

    def process(self, switch_id: int, message: VehicleMessage):

        consistency = self.checker.check(message)

        decision = self.reputation.update(
            vehicle_id=message.vehicle_id,
            consistent=consistency.consistent,
            severity=consistency.severity,
        )

        operation = self.mitigation.update(
            switch_id=switch_id,
            decision=decision,
        )

        return ProcessingResult(
            vehicle_id=message.vehicle_id,
            consistent=consistency.consistent,
            reason=consistency.reason,
            reputation=decision.reputation,
            action=decision.action,
            rate_limit_kbps=decision.rate_limit_kbps,
            operation=operation.operation,
        )
