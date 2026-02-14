import ipaddress


def expand_target(target: str):
    """
    Expands CIDR or single IP into list of IP strings.
    """
    network = ipaddress.ip_network(target, strict=False)
    return [str(ip) for ip in network.hosts()]


def range_from_start_end(start_ip: str, end_ip: str):
    """
    Generate IP range from start and end.
    """
    start = ipaddress.IPv4Address(start_ip)
    end = ipaddress.IPv4Address(end_ip)

    return [
        str(ipaddress.IPv4Address(ip))
        for ip in range(int(start), int(end) + 1)
    ]
