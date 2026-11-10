"""Pure association transition tracking for the Methodology 2 demo."""

from dataclasses import dataclass
from typing import Optional, Tuple


@dataclass
class HandoverTracker:
    """Track completed AP changes, including short NONE gaps."""

    previous_ap: Optional[str] = None
    handovers: int = 0
    pending_departure: Optional[Tuple[str, float]] = None
    reconnect_window_seconds: float = 5.0

    def observe(self, current_ap: str, now: float):
        """Return (previous, current, cumulative_count, is_handover).

        The initial observation establishes a baseline without a handover.
        A transition through NONE counts only when another AP is reached within
        the configured window. Same-AP reconnects, disconnect-only events,
        and reconnects after the window do not increment the count.
        """
        old_ap = self.previous_ap
        if old_ap is None:
            self.previous_ap = current_ap
            return None
        if current_ap == old_ap:
            return None

        completed = False
        if current_ap == "NONE":
            if old_ap != "NONE":
                self.pending_departure = (old_ap, now)
        elif old_ap == "NONE":
            pending = self.pending_departure
            self.pending_departure = None
            if pending is not None:
                departed_ap, departed_at = pending
                if (current_ap != departed_ap
                        and now - departed_at <= self.reconnect_window_seconds):
                    completed = True
        else:
            # A direct AP-to-AP change is a completed handover.
            self.pending_departure = None
            completed = True

        if completed:
            self.handovers += 1
        self.previous_ap = current_ap
        return old_ap, current_ap, self.handovers, completed
