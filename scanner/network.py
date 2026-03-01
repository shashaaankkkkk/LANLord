"""Network detection utilities.

Detects active network interfaces, local IP, subnet mask, and CIDR range
using psutil and standard library modules.
"""

from __future__ import annotations

import ipaddress
import socket
from dataclasses import dataclass, field

import psutil


@dataclass
class NetworkInfo:
    """Holds information about the detected local network."""

    interface: str = ""
    local_ip: str = ""
    subnet_mask: str = ""
    cidr: str = ""
    network_address: str = ""
    broadcast_address: str = ""
    first_host: str = ""
    last_host: str = ""
    total_hosts: int = 0
    all_interfaces: list[dict[str, str]] = field(default_factory=list)


def _prefix_len_from_mask(mask: str) -> int:
    """Convert dotted subnet mask to prefix length."""
    try:
        return ipaddress.IPv4Network(f"0.0.0.0/{mask}", strict=False).prefixlen
    except (ValueError, TypeError):
        return 24  # sensible default


def detect_network() -> NetworkInfo:
    """Auto-detect the active network interface and derive network range.

    Iterates over network interfaces via *psutil*, picks the first
    non-loopback IPv4 address that looks like a private/local address,
    and computes the CIDR range from the associated subnet mask.
    """
    info = NetworkInfo()
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    candidates: list[tuple[str, str, str]] = []  # (iface, ip, mask)

    for iface, addr_list in addrs.items():
        # Skip interfaces that are down
        if iface in stats and not stats[iface].isup:
            continue
        for addr in addr_list:
            if addr.family != socket.AF_INET:
                continue
            ip = addr.address
            mask = addr.netmask or "255.255.255.0"
            if ip.startswith("127."):
                continue
            info.all_interfaces.append(
                {"interface": iface, "ip": ip, "netmask": mask}
            )
            candidates.append((iface, ip, mask))

    if not candidates:
        # Fallback: resolve hostname
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            if not local_ip.startswith("127."):
                candidates.append(("unknown", local_ip, "255.255.255.0"))
        except socket.error:
            pass

    if not candidates:
        return info  # empty – caller should handle

    # Prefer private addresses, then first candidate
    preferred = None
    for iface, ip, mask in candidates:
        try:
            if ipaddress.IPv4Address(ip).is_private:
                preferred = (iface, ip, mask)
                break
        except ValueError:
            continue
    if preferred is None:
        preferred = candidates[0]

    iface, ip, mask = preferred
    prefix = _prefix_len_from_mask(mask)
    network = ipaddress.IPv4Network(f"{ip}/{prefix}", strict=False)

    hosts = list(network.hosts())
    info.interface = iface
    info.local_ip = ip
    info.subnet_mask = mask
    info.cidr = str(network)
    info.network_address = str(network.network_address)
    info.broadcast_address = str(network.broadcast_address)
    info.first_host = str(hosts[0]) if hosts else ip
    info.last_host = str(hosts[-1]) if hosts else ip
    info.total_hosts = len(hosts)

    return info


def ip_range_from_cidr(cidr: str) -> list[str]:
    """Return a list of host IP strings from a CIDR notation string."""
    try:
        network = ipaddress.IPv4Network(cidr, strict=False)
        return [str(h) for h in network.hosts()]
    except ValueError:
        return []


def ip_range_from_start_end(start: str, end: str) -> list[str]:
    """Return a list of IP strings between *start* and *end* inclusive."""
    try:
        start_ip = ipaddress.IPv4Address(start)
        end_ip = ipaddress.IPv4Address(end)
    except ValueError:
        return []
    if start_ip > end_ip:
        return []
    ips: list[str] = []
    current = start_ip
    while current <= end_ip:
        ips.append(str(current))
        current += 1
    return ips


def validate_ip(ip: str) -> bool:
    """Check whether *ip* is a valid IPv4 address string."""
    try:
        ipaddress.IPv4Address(ip)
        return True
    except ValueError:
        return False


def validate_cidr(cidr: str) -> bool:
    """Check whether *cidr* is a valid IPv4 CIDR notation string."""
    try:
        ipaddress.IPv4Network(cidr, strict=False)
        return True
    except ValueError:
        return False
