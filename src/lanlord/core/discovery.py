
import asyncio
import socket
import time
from typing import Optional

from lanlord.models.host import Host, HostStatus
from lanlord.utils.logger import get_logger


logger = get_logger("lanlord.discovery")


class Discovery:

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    async def probe_host(self, ip: str) -> Host:
        host = Host(ip=ip)
        start = time.perf_counter()

        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, 80),
                timeout=self.timeout
            )

            latency = time.perf_counter() - start
            host.status = HostStatus.ALIVE
            host.latency = latency

            writer.close()
            await writer.wait_closed()

        except Exception:
            host.status = HostStatus.DEAD

        try:
            host.hostname = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass

        return host
