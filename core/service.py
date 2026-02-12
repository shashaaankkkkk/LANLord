

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

    def detect(self, port: Port) -> None:
        if port.port in COMMON_PORTS:
            port.service = COMMON_PORTS[port.port]
        elif port.banner:
            if "HTTP" in port.banner:
                port.service = "http"
            elif "SSH" in port.banner:
                port.service = "ssh"
