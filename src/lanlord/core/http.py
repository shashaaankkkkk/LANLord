

import asyncio
import re
from typing import Optional


class HTTPInspector:

    async def get_title(self, ip: str, port: int = 80) -> Optional[str]:
        try:
            reader, writer = await asyncio.open_connection(ip, port)

            request = f"GET / HTTP/1.1\r\nHost: {ip}\r\n\r\n"
            writer.write(request.encode())
            await writer.drain()

            response = await asyncio.wait_for(reader.read(4096), timeout=2)

            writer.close()
            await writer.wait_closed()

            match = re.search(
                rb"<title>(.*?)</title>",
                response,
                re.IGNORECASE | re.DOTALL
            )

            if match:
                return match.group(1).decode(errors="ignore").strip()

        except Exception:
            return None
