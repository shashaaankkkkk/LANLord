

from dataclasses import dataclass
from enum import Enum
from typing import Optional


class PortState(str, Enum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"


@dataclass(slots=True)
class Port:
    port: int
    protocol: str
    state: PortState
    service: Optional[str] = None
    banner: Optional[str] = None
