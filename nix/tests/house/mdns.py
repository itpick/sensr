# One unsolicited mDNS response, the way a device announces its DNS-SD
# services: PTR, SRV and TXT per service plus the A record, sent three times
# to 224.0.0.251:5353 from the given address (house.nix screenshots).
#
#   mdns.py IP HOST INSTANCE TXT SERVICE...
#
# TXT is "key=value|key=value" ("" for none); SERVICE is "_googlecast._tcp".
import socket
import struct
import sys
import time


def name(n):
    out = b""
    for label in n.rstrip(".").split("."):
        b = label.encode()
        out += bytes([len(b)]) + b
    return out + b"\0"


def rr(owner, rtype, rdata, cls=0x8001, ttl=120):
    return name(owner) + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def main():
    ip, host, instance, txt = sys.argv[1:5]
    services = sys.argv[5:]
    strings = [s.encode() for s in txt.split("|") if s]
    txt_rdata = b"".join(bytes([len(s)]) + s for s in strings) or b"\0"
    records = []
    for svc in services:
        fqdn = f"{instance}.{svc}.local"
        records.append(rr(f"{svc}.local", 12, name(fqdn), cls=1))
        records.append(rr(fqdn, 33, struct.pack("!HHH", 0, 0, 8009) + name(f"{host}.local")))
        records.append(rr(fqdn, 16, txt_rdata))
    records.append(rr(f"{host}.local", 1, socket.inet_aton(ip)))
    pkt = struct.pack("!HHHHHH", 0, 0x8400, 0, len(records), 0, 0) + b"".join(records)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((ip, 5353))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(ip))
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    for _ in range(3):
        s.sendto(pkt, ("224.0.0.251", 5353))
        time.sleep(1)


main()
