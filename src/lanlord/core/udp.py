

import asyncio
from lanlord.models.port import Port, PortState


class UDPScanner:

    async def scan_port(self, ip: str, port: int) -> Port:
        try:
            loop = asyncio.get_running_loop()
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: asyncio.DatagramProtocol(),
                remote_addr=(ip, port),
            )

            transport.sendto(b"\x00")
            await asyncio.sleep(1)

            transport.close()

            return Port(
                port=port,
                protocol="udp",
                state=PortState.OPEN
            )

        except Exception:
            return Port(
                port=port,
                protocol="udp",
                state=PortState.CLOSED
            )
