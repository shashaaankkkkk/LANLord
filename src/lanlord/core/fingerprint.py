

import subprocess
import platform
import re
from typing import Optional


class Fingerprint:

    def detect_os(self, ip: str) -> Optional[str]:
        try:
            system = platform.system().lower()

            if system == "linux" or system == "darwin":
                cmd = ["ping", "-c", "1", ip]
            else:
                cmd = ["ping", "-n", "1", ip]

            result = subprocess.run(cmd, capture_output=True, text=True)

            match = re.search(r"ttl[=\s](\d+)", result.stdout.lower())
            if not match:
                return None

            ttl = int(match.group(1))

            if ttl >= 120:
                return "Windows (Likely)"
            elif ttl >= 60:
                return "Linux/Unix (Likely)"
            else:
                return "Unknown"

        except Exception:
            return None
