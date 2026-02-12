

import asyncio
from typing import List

from lanlord.models.result import ScanResult
from lanlord.utils.network import expand_target
from lanlord.utils.rate_limit import RateLimiter
from lanlord.utils.logger import get_logger
from lanlord.core.discovery import Discovery
from lanlord.core.portscan import PortScanner


logger = get_logger("lanlord.engine")


class ScanEngine:

    def __init__(
        self,
        timeout: float = 1.0,
        max_concurrent: int = 100,
        ports: List[int] | None = None,
    ):
        self.timeout = timeout
        self.rate_limiter = RateLimiter(max_concurrent)
        self.discovery = Discovery(timeout=timeout)
        self.port_scanner = PortScanner(timeout=timeout)
        self.ports = ports or list(range(1, 1025))

    async def _scan_host(self, ip: str):
        async with self.rate_limiter:
            host = await self.discovery.probe_host(ip)

            if host.status.value == "alive":
                host.ports = await self.port_scanner.scan_ports(ip, self.ports)

            return host

    async def scan(self, target: str) -> ScanResult:
        logger.info(f"Starting scan for {target}")
        ips = expand_target(target)

        tasks = [self._scan_host(ip) for ip in ips]
        hosts = await asyncio.gather(*tasks)

        result = ScanResult(target=target, hosts=hosts)
        logger.info("Scan completed")
        return result
