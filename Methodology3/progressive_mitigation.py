from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class EnforcementOperation:
    vehicle_id: str
    switch_id: int
    operation: str
    meter_id: Optional[int]
    rate_kbps: Optional[int]


class ProgressiveMitigation:
    """
    Plans operations against confirmed OpenFlow state per switch and vehicle.

    This module generates enforcement operations.
    It does not communicate with a switch directly.
    """

    def __init__(self):
        self.vehicle_meter_ids = {}
        self.next_meter_id = 1000
        self.installed_meters = {}

    def get_meter_id(self, vehicle_id):
        if vehicle_id not in self.vehicle_meter_ids:
            self.vehicle_meter_ids[vehicle_id] = self.next_meter_id
            self.next_meter_id += 1

        return self.vehicle_meter_ids[vehicle_id]

    def update(self, switch_id, decision):

        vehicle_id = decision.vehicle_id
        key = (switch_id, vehicle_id)

        desired_rate = decision.rate_limit_kbps
        current_rate = self.installed_meters.get(key)

        if desired_rate is None:

            if current_rate is None:
                return EnforcementOperation(
                    vehicle_id,
                    switch_id,
                    "NO_CHANGE",
                    None,
                    None,
                )

            return EnforcementOperation(
                vehicle_id,
                switch_id,
                "REMOVE",
                self.get_meter_id(vehicle_id),
                None,
            )

        meter_id = self.get_meter_id(vehicle_id)

        if current_rate is None:
            return EnforcementOperation(
                vehicle_id,
                switch_id,
                "ADD",
                meter_id,
                desired_rate,
            )

        if current_rate != desired_rate:
            return EnforcementOperation(
                vehicle_id,
                switch_id,
                "MODIFY",
                meter_id,
                desired_rate,
            )

        return EnforcementOperation(
            vehicle_id,
            switch_id,
            "NO_CHANGE",
            meter_id,
            desired_rate,
        )

    def confirm(self, operation):
        """Commit only after the adapter receives an error-free barrier reply."""
        key = (operation.switch_id, operation.vehicle_id)
        if operation.operation in ("ADD", "MODIFY"):
            self.installed_meters[key] = operation.rate_kbps
        elif operation.operation == "REMOVE":
            self.installed_meters.pop(key, None)

    def forget_switch(self, switch_id):
        """A disconnected/uncertain switch must be reset before reconciliation."""
        for key in list(self.installed_meters):
            if key[0] == switch_id:
                del self.installed_meters[key]
