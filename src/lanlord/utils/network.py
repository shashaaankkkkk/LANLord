

import ipaddress
from typing import List


def expand_target(target: str) -> List[str]:
    """
    Expands CIDR or single IP into list of IP strings.
    """
    network = ipaddress.ip_network(target, strict=False)
    return [str(ip) for ip in network.hosts()]
