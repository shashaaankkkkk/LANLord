import asyncio
import socket
import aioping
from models import ScanResult

COMMON_PORTS = [22, 80, 443, 3389]

async def scan_ip(ip: str) -> ScanResult:
    alive = False
    hostname = ""
    open_ports = []

    try:
        await aioping.ping(ip, timeout=1)
        alive = True
        try:
            hostname = socket.gethostbyaddr(ip)[0]
        except:
            hostname = ""
    except:
        return ScanResult(ip, False, "", [])

    for port in COMMON_PORTS:
        try:
            r, w = await asyncio.wait_for(
                asyncio.open_connection(ip, port), timeout=0.4
            )
            w.close()
            open_ports.append(port)
        except:
            pass

    return ScanResult(ip, alive, hostname, open_ports)

async def scan_range(ips, limit=200):
    sem = asyncio.Semaphore(limit)

    async def bound(ip):
        async with sem:
            return await scan_ip(ip)

    return await asyncio.gather(*(bound(ip) for ip in ips))
