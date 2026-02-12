

import asyncio
from typing import List

from lanlord.models.port import Port, PortState
from lanlord.utils.logger import get_logger


logger = get_logger("lanlord.portscan")


class PortScanner:

    def __init__(self, timeout: float = 1.0):
        self.timeout = timeout

    async def scan_port(self, ip: str, port: int) -> Port:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )

            writer.close()
            await writer.wait_closed()

            return Port(
                port=port,
                protocol="tcp",
                state=PortState.OPEN
            )

        except asyncio.TimeoutError:
            return Port(
                port=port,
                protocol="tcp",
                state=PortState.FILTERED
            )

        except Exception:
            return Port(
                port=port,
                protocol="tcp",
                state=PortState.CLOSED
            )

    async def scan_port(self, ip: str, port: int) -> Port:
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=self.timeout
            )

            banner = None

            try:
                writer.write(b"\r\n")
                await writer.drain()
                banner_data = await asyncio.wait_for(reader.read(1024), timeout=1)
                banner = banner_data.decode(errors="ignore").strip() or None
            except Exception:
                pass

            writer.close()
            await writer.wait_closed()

            return Port(
                port=port,
                protocol="tcp",
                state=PortState.OPEN,
                banner=banner
            )

        except asyncio.TimeoutError:
            return Port(
                port=port,
                protocol="tcp",
                state=PortState.FILTERED
            )

        except Exception:
            return Port(
                port=port,
                protocol="tcp",
                state=PortState.CLOSED
            )

