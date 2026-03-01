"""Host discovery via ICMP ping and TCP fallback.

Works cross-platform without requiring root for basic TCP probes.
Uses ICMP ping (subprocess) as the preferred method and falls back
to a TCP connect probe on port 80/443 when ICMP is unavailable.
"""

from __future__ import annotations

import asyncio
import platform
import time
from dataclasses import dataclass


@dataclass
class PingResult:
    """Result of a single host ping/probe."""

    ip: str
    alive: bool
    response_time_ms: float | None = None  # milliseconds
    method: str = ""  # "icmp" | "tcp"


async def ping_icmp(ip: str, timeout: float = 1.5) -> PingResult:
    """Ping a host using the OS ``ping`` command (no root required).

    Parameters
    ----------
    ip:
        Target IPv4 address.
    timeout:
        Seconds to wait for a reply.
    """
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip]
    else:
        cmd = ["ping", "-c", "1", "-W", str(int(timeout)), ip]

    start = time.monotonic()
    try:
        proc = await asyncio.create_subprocess_exec(
            *cmd,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await asyncio.wait_for(proc.wait(), timeout=timeout + 2)
        elapsed = (time.monotonic() - start) * 1000
        alive = proc.returncode == 0
        return PingResult(ip=ip, alive=alive, response_time_ms=round(elapsed, 2) if alive else None, method="icmp")
    except (asyncio.TimeoutError, OSError):
        return PingResult(ip=ip, alive=False, method="icmp")


async def ping_tcp(ip: str, ports: tuple[int, ...] = (80, 443, 22), timeout: float = 1.5) -> PingResult:
    """Probe a host by attempting a TCP connect to common ports.

    This serves as a fallback when ICMP is blocked.
    """
    start = time.monotonic()
    for port in ports:
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(ip, port),
                timeout=timeout,
            )
            elapsed = (time.monotonic() - start) * 1000
            writer.close()
            await writer.wait_closed()
            return PingResult(ip=ip, alive=True, response_time_ms=round(elapsed, 2), method="tcp")
        except (asyncio.TimeoutError, OSError, ConnectionRefusedError):
            continue
    return PingResult(ip=ip, alive=False, method="tcp")


async def discover_host(ip: str, timeout: float = 1.5, tcp_fallback: bool = True) -> PingResult:
    """Discover whether a host is alive – tries ICMP first, then TCP."""
    result = await ping_icmp(ip, timeout=timeout)
    if result.alive:
        return result
    if tcp_fallback:
        return await ping_tcp(ip, timeout=timeout)
    return result


async def discover_hosts(
    ips: list[str],
    timeout: float = 1.5,
    concurrency: int = 50,
    tcp_fallback: bool = True,
    progress_callback=None,
) -> list[PingResult]:
    """Scan a list of IPs for live hosts with bounded concurrency.

    Parameters
    ----------
    ips:
        List of IPv4 address strings to probe.
    timeout:
        Per-host timeout in seconds.
    concurrency:
        Maximum simultaneous probes.
    tcp_fallback:
        Whether to try TCP if ICMP fails.
    progress_callback:
        Optional *async* callable ``(completed: int, total: int, result: PingResult) -> None``
        invoked after each host completes.
    """
    semaphore = asyncio.Semaphore(concurrency)
    results: list[PingResult] = []
    total = len(ips)
    completed = 0

    async def _probe(ip: str):
        nonlocal completed
        async with semaphore:
            result = await discover_host(ip, timeout=timeout, tcp_fallback=tcp_fallback)
        results.append(result)
        completed += 1
        if progress_callback:
            await progress_callback(completed, total, result)
        return result

    tasks = [asyncio.create_task(_probe(ip)) for ip in ips]
    await asyncio.gather(*tasks, return_exceptions=True)
    return results
