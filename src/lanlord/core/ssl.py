

import ssl
import socket
from typing import Optional


class SSLInspector:

    def get_certificate_info(self, ip: str, port: int = 443) -> Optional[str]:
        try:
            context = ssl.create_default_context()
            with socket.create_connection((ip, port), timeout=3) as sock:
                with context.wrap_socket(sock, server_hostname=ip) as ssock:
                    cert = ssock.getpeercert()
                    return cert.get("subject", None)
        except Exception:
            return None
