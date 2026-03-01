"""TCP port scanner with service name resolution.

Performs asynchronous TCP connect scans on target hosts
with configurable port lists and bounded concurrency.
"""

from __future__ import annotations

import asyncio
import socket
from dataclasses import dataclass, field


# ── Well-known default ports ──────────────────────────────────────────
DEFAULT_PORTS: list[int] = [
    20, 21, 22, 23, 25, 53, 80, 110, 111, 135,
    139, 143, 443, 445, 993, 995, 1433, 1434,
    3306, 3389, 5432, 5900, 6379, 8080, 8443, 8888, 9090, 27017,
]

COMMON_PORTS: list[int] = [22, 80, 443, 3306, 8080]


@dataclass
class PortResult:
    """Result of scanning a single port on a host."""

    port: int
    state: str  # "open" | "closed" | "filtered"
    service: str = ""


@dataclass
class HostScanResult:
    """Aggregated port-scan results for a single host."""

    ip: str
    ports: list[PortResult] = field(default_factory=list)
    open_ports: list[PortResult] = field(default_factory=list)


def get_service_name(port: int) -> str:
    """Resolve a port number to its IANA service name, if known."""
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def parse_ports(port_str: str) -> list[int]:
    """Parse a human-friendly port specification string.

    Supports:
    - Single ports: ``80``
    - Comma-separated: ``22,80,443``
    - Ranges: ``1-1024``
    - Mixed: ``22,80,100-200,443,8080-8090``

    Returns a sorted, deduplicated list of port numbers.
    """
    ports: set[int] = set()
    for part in port_str.replace(" ", "").split(","):
        if not part:
            continue
        if "-" in part:
            bounds = part.split("-", 1)
            try:
                lo, hi = int(bounds[0]), int(bounds[1])
                lo, hi = max(1, lo), min(65535, hi)
                ports.update(range(lo, hi + 1))
            except (ValueError, IndexError):
                continue
        else:
            try:
                p = int(part)
                if 1 <= p <= 65535:
                    ports.add(p)
            except ValueError:
                continue
    return sorted(ports)


async def scan_port(ip: str, port: int, timeout: float = 1.5) -> PortResult:
    """Attempt a TCP connect to *ip*:*port*.

    Returns ``PortResult`` with state ``open``, ``closed``, or ``filtered``.
    """
    try:
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=timeout,
        )
        writer.close()
        await writer.wait_closed()
        service = get_service_name(port)
        return PortResult(port=port, state="open", service=service)
    except asyncio.TimeoutError:
        return PortResult(port=port, state="filtered", service=get_service_name(port))
    except (OSError, ConnectionRefusedError):
        return PortResult(port=port, state="closed", service=get_service_name(port))


async def scan_host(
    ip: str,
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 80,
    progress_callback=None,
) -> HostScanResult:
    """Scan multiple ports on a single host.

    Parameters
    ----------
    ip:
        Target IPv4 address.
    ports:
        List of port numbers to scan. Defaults to ``COMMON_PORTS``.
    timeout:
        Per-port connect timeout in seconds.
    concurrency:
        Maximum simultaneous port probes.
    progress_callback:
        Optional async callable ``(ip, completed, total, result) -> None``.
    """
    if ports is None:
        ports = COMMON_PORTS

    semaphore = asyncio.Semaphore(concurrency)
    result = HostScanResult(ip=ip)
    completed = 0
    total = len(ports)

    async def _probe(port: int):
        nonlocal completed
        async with semaphore:
            pr = await scan_port(ip, port, timeout=timeout)
        result.ports.append(pr)
        if pr.state == "open":
            result.open_ports.append(pr)
        completed += 1
        if progress_callback:
            await progress_callback(ip, completed, total, pr)

    tasks = [asyncio.create_task(_probe(p)) for p in ports]
    await asyncio.gather(*tasks, return_exceptions=True)

    # Sort by port number for clean display
    result.ports.sort(key=lambda r: r.port)
    result.open_ports.sort(key=lambda r: r.port)
    return result


async def scan_hosts(
    ips: list[str],
    ports: list[int] | None = None,
    timeout: float = 1.5,
    concurrency: int = 80,
    host_callback=None,
    port_progress_callback=None,
) -> list[HostScanResult]:
    """Scan ports on multiple hosts sequentially (ports on each host are concurrent).

    Parameters
    ----------
    host_callback:
        Optional async callable ``(completed_hosts, total_hosts, result) -> None``.
    """
    if ports is None:
        ports = COMMON_PORTS

    results: list[HostScanResult] = []
    total_hosts = len(ips)

    for idx, ip in enumerate(ips, 1):
        res = await scan_host(ip, ports=ports, timeout=timeout, concurrency=concurrency, progress_callback=port_progress_callback)
        results.append(res)
        if host_callback:
            await host_callback(idx, total_hosts, res)

    return results
