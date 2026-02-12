from dataclasses import dataclass
from typing import List

@dataclass
class ScanResult:
    ip: str
    alive: bool
    hostname: str
    ports: List[int]
