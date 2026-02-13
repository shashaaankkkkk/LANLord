

from dataclasses import dataclass
from typing import List


@dataclass(slots=True)
class ScanProfile:
    name: str
    ports: List[int]
    host_timeout: float
    port_timeout: float
    concurrency: int
    detect_os: bool
    grab_banner: bool


QUICK = ScanProfile(
    name="quick",
    ports=list(range(1, 101)),
    host_timeout=1.0,
    port_timeout=1.0,
    concurrency=100,
    detect_os=False,
    grab_banner=False
)


AGGRESSIVE = ScanProfile(
    name="aggressive",
    ports=list(range(1, 65536)),
    host_timeout=0.5,
    port_timeout=0.5,
    concurrency=500,
    detect_os=True,
    grab_banner=True
)
