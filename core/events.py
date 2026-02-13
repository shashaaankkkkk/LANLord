from dataclasses import dataclass
from typing import Any


@dataclass(slots=True)
class ScanEvent:
    type: str
    payload: Any
