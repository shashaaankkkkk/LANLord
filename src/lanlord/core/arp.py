

import asyncio
import platform
import re
from typing import Optional


class ARPScanner:

    async def get_mac(self, ip: str) -> Optional[str]:
        system = platform.system().lower()

        if system not in ("linux", "darwin"):
            return None

        proc = await asyncio.create_subprocess_exec(
            "arp", "-n", ip,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE
        )

        stdout, _ = await proc.communicate()
        output = stdout.decode()

        match = re.search(r"(([0-9a-f]{2}:){5}[0-9a-f]{2})", output.lower())
        return match.group(1) if match else None
