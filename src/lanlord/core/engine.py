import asyncio
from typing import List, Optional

from lanlord.models.result import ScanResult
from lanlord.models.host import HostStatus
from lanlord.core.discovery import Discovery
from lanlord.core.portscan import PortScanner
from lanlord.core.service import ServiceDetector
from lanlord.core.state import ScanState


class ScanEngine:
    """
    Stable production-safe scan engine.

    Phase 1:
    - Host discovery
    - Limited port scan
    - Safe concurrency

    Advanced enrichment intentionally removed
    until core stability is verified.
    """

    def __init__(self, profile):

        self.profile = profile
        self.state = ScanState.IDLE
        self._cancelled = False

        # Core components
        self.discovery = Discovery(timeout=profile.host_timeout)
        self.port_scanner = PortScanner(timeout=profile.port_timeout)
        self.service_detector = ServiceDetector()

        # Concurrency control
        self.host_limiter = asyncio.Semaphore(profile.concurrency)
        self.port_limiter = asyncio.Semaphore(100)

        self.last_result: Optional[ScanResult] = None

    # ------------------------------------------------------------------
    # PUBLIC METHODS
    # ------------------------------------------------------------------

    async def scan(self, target: str) -> ScanResult:
        """
        Full scan using CIDR input.
        """
        from lanlord.utils.network import expand_target

        self.state = ScanState.RUNNING
        self._cancelled = False

        ips = expand_target(target)

        tasks = [self._scan_host(ip) for ip in ips]
        hosts = await asyncio.gather(*tasks)

        result = ScanResult(
            target=target,
            hosts=[h for h in hosts if h]
        )

        self.last_result = result
        self.state = ScanState.COMPLETED

        return result

    async def scan_ip_range(self, ips: List[str]):
        """
        Scan explicit IP list (used by TUI).
        """
        self.state = ScanState.RUNNING
        self._cancelled = False

        results = []

        tasks = [self._scan_host(ip) for ip in ips]

        for future in asyncio.as_completed(tasks):

            if self._cancelled:
                break

            host = await future

            if host:
                results.append(host)
                yield host

        self.state = ScanState.COMPLETED

    def cancel(self):
        self._cancelled = True
        self.state = ScanState.CANCELLED

    # ------------------------------------------------------------------
    # INTERNAL METHODS
    # ------------------------------------------------------------------

    async def _scan_host(self, ip: str):

        if self._cancelled:
            return None

        async with self.host_limiter:

            try:
                # ---- Host discovery ----
                host = await self.discovery.probe_host(ip)

                if host.status != HostStatus.ALIVE:
                    host.ports = []
                    return host

                # ---- Limited port scan ----
                host.ports = await self._scan_ports(ip)

                return host

            except Exception:
                return None

    async def _scan_ports(self, ip: str):

        async def scan_single(port):

            if self._cancelled:
                return None

            async with self.port_limiter:
                result = await self.port_scanner.scan_port(ip, port)
                self.service_detector.detect(result)
                return result

        tasks = [scan_single(p) for p in self.profile.ports]
        scanned = await asyncio.gather(*tasks)

        return [p for p in scanned if p]
