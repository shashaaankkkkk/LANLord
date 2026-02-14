# src/lanlord/core/service.py

from lanlord.models.port import Port


COMMON_PORTS = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    143: "imap",
    443: "https",
    3306: "mysql",
    5432: "postgresql",
}


class ServiceDetector:
    """
    Basic service detection based on port number and banner heuristics.
    """

    def detect(self, port: Port) -> None:
        # Port-based detection
        if port.port in COMMON_PORTS:
            port.service = COMMON_PORTS[port.port]

        # Banner-based refinement
        if port.banner:
            banner_upper = port.banner.upper()

            if "HTTP" in banner_upper:
                port.service = "http"
            elif "SSH" in banner_upper:
                port.service = "ssh"
            elif "SMTP" in banner_upper:
                port.service = "smtp"
