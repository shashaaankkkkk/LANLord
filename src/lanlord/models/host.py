

from dataclasses import dataclass, field
from enum import Enum
from typing import List, Optional
from .port import Port


class HostStatus(str, Enum):
    ALIVE = "alive"
    DEAD = "dead"
    UNKNOWN = "unknown"


@dataclass(slots=True)
class Host:
    ip: str
    status: HostStatus = HostStatus.UNKNOWN
    latency: Optional[float] = None
    hostname: Optional[str] = None
    ports: List[Port] = field(default_factory=list)
    os: Optional[str] = None
    mac: Optional[str] = None
    vendor: Optional[str] = None
    http_title: Optional[str] = None
    ssl_info: Optional[str] = None


