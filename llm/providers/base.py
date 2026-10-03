"""Common interface every provider implements."""

from abc import ABC, abstractmethod

HEAVY = "heavy"   # analysis, type reconstruction, code reconstruction
FAST = "fast"     # cheap housekeeping calls (JSON repair)


class BaseProvider(ABC):
    @abstractmethod
    def complete(self, system: str, user: str, tier: str = HEAVY) -> str:
        """Send a system + user prompt and return the model's text response."""
        raise NotImplementedError
