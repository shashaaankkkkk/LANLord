import socket
import ipaddress

def get_local_range():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    local_ip = s.getsockname()[0]
    s.close()

    net = ipaddress.IPv4Network(local_ip + "/24", strict=False)
    return str(net.network_address), str(net.broadcast_address)

def generate_ips(start, end):
    s = int(ipaddress.IPv4Address(start))
    e = int(ipaddress.IPv4Address(end))
    return [str(ipaddress.IPv4Address(i)) for i in range(s, e + 1)]
