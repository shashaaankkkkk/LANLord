

from dataclasses import dataclass, field
from typing import List
from .host import Host


@dataclass(slots=True)
class ScanResult:
    target: str
    hosts: List[Host] = field(default_factory=list)
