

import asyncio
from typing import List

from lanlord.models.result import ScanResult
from lanlord.utils.network import expand_target
from lanlord.utils.rate_limit import RateLimiter
from lanlord.utils.logger import get_logger
from lanlord.core.discovery import Discovery
from lanlord.core.portscan import PortScanner

from lanlord.core.service import ServiceDetector
from lanlord.core.fingerprint import Fingerprint

from lanlord.core.arp import ARPScanner
from lanlord.core.http import HTTPInspector
from lanlord.core.ssl import SSLInspector
from lanlord.utils.vendor_lookup import lookup_vendor


from lanlord.core.state import ScanState

logger = get_logger("lanlord.engine")
self.state = ScanState.IDLE

class ScanEngine:

    def __init__(self, profile):
        self.profile = profile

        self.discovery = Discovery(timeout=profile.host_timeout)
        self.port_scanner = PortScanner(timeout=profile.port_timeout)
        self.service_detector = ServiceDetector()
        self.fingerprint = Fingerprint()

        self.host_limiter = asyncio.Semaphore(profile.concurrency)
        self.port_limiter = asyncio.Semaphore(1000)

        self.state = ScanState.IDLE
        self._cancelled = False

        self._event_queue = asyncio.Queue()
        self.arp = ARPScanner()
        self.http = HTTPInspector()
        self.ssl = SSLInspector()


    async def _scan_host(self, ip: str):
        """
        Scan a single host with full enrichment pipeline.
        """

        if self._cancelled:
            return None

        async with self.host_limiter:

            try:
                # --- Discovery ---
                host = await self.discovery.probe_host(ip)

                await self.emit("host_discovered", host)

                if host.status != HostStatus.ALIVE:
                    await self.emit("host_scanned", host)
                    return host

                # --- OS Detection ---
                if self.profile.detect_os and not self._cancelled:
                    host.os = self.fingerprint.detect_os(ip)

                # --- Port Scan ---
                if not self._cancelled:
                    host.ports = await self._scan_ports_with_limit(ip)

                # --- MAC + Vendor ---
                try:
                    host.mac = await self.arp.get_mac(ip)
                    host.vendor = lookup_vendor(host.mac)
                except Exception:
                    pass

                # --- HTTP Title Extraction ---
                for port in host.ports:
                    if port.service == "http" and not self._cancelled:
                        try:
                            host.http_title = await self.http.get_title(ip, port.port)
                        except Exception:
                            pass

                # --- SSL Certificate Inspection ---
                for port in host.ports:
                    if port.service == "https" and not self._cancelled:
                        try:
                            host.ssl_info = self.ssl.get_certificate_info(ip, port.port)
                        except Exception:
                            pass

                await self.emit("host_scanned", host)

                return host

            except Exception:
                # Hard isolation: never crash full scan because of one host
                await self.emit("host_error", ip)
                return None



    async def scan_stream(self, target: str):
        from lanlord.utils.network import expand_target

        self.state = ScanState.RUNNING

        ips = expand_target(target)

        for ip in ips:
            if self._cancelled:
                break

            host = await self._scan_host(ip)
            if host:
                yield host

        self.state = ScanState.COMPLETED


    async def scan(self, target: str):
        from lanlord.utils.network import expand_target
        from lanlord.models.result import ScanResult

        self.state = ScanState.RUNNING

        try:
            ips = expand_target(target)

            tasks = [self._scan_host(ip) for ip in ips]
            hosts = await asyncio.gather(*tasks)

            if self._cancelled:
                self.state = ScanState.CANCELLED
            else:
                self.state = ScanState.COMPLETED

            return ScanResult(
                target=target,
                hosts=[h for h in hosts if h]
            )

        except Exception:
            self.state = ScanState.ERROR
            raise


    
    def cancel(self):
      self._cancelled = True
    
    async def _scan_ports_with_limit(self, ip: str):
        ports = []

        async def scan_single(port):
            if self._cancelled:
                return None

            async with self.port_limiter:
                result = await self.port_scanner.scan_port(ip, port)
                self.service_detector.detect(result)
                return result

        tasks = [scan_single(p) for p in self.profile.ports]
        results = await asyncio.gather(*tasks)

        return [r for r in results if r]

    async def emit(self, event_type: str, payload):
        await self._event_queue.put(ScanEvent(event_type, payload))

    async def events(self):
        while self.state == ScanState.RUNNING:
            event = await self._event_queue.get()
            yield event

    async def shutdown(self):
        self.cancel()
        self.state = ScanState.CANCELLED
    
    async def _scan_ports_with_limit(self, ip: str):
        results = []

        async def scan_single(port):
            if self._cancelled:
                return None

            async with self.port_limiter:
                port_result = await self.port_scanner.scan_port(ip, port)
                self.service_detector.detect(port_result)
                return port_result

        tasks = [scan_single(p) for p in self.profile.ports]
        scanned = await asyncio.gather(*tasks)

        return [p for p in scanned if p]
