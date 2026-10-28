"""A plain mDNS service announcement, sent to 224.0.0.251:5353 every INTERVAL seconds:
an IPP printer, the kind of beacon a home LAN has anyway. Standard library only, so it
runs in the python:3-alpine image without an avahi daemon (which did not start in alpine
under podman). The records are PTR, SRV, TXT and A for printer._ipp._tcp.local.

    python3 mdns.py [interval_seconds]        default 2
"""
import socket, struct, sys, time

GROUP, PORT = "224.0.0.251", 5353
NAME, SVC, HOST = "printer", "_ipp._tcp.local", "printer.local"


def qname(name: str) -> bytes:
    return b"".join(bytes([len(l)]) + l.encode() for l in name.split(".")) + b"\x00"


def rr(name: str, rtype: int, rdata: bytes, ttl: int = 120, flush: bool = True) -> bytes:
    cls = 0x0001 | (0x8000 if flush else 0)
    return qname(name) + struct.pack("!HHIH", rtype, cls, ttl, len(rdata)) + rdata


def announcement(ip: str) -> bytes:
    inst = f"{NAME}.{SVC}"
    txt = b"pdl=application/pdf"
    answers = [
        rr(SVC, 12, qname(inst), flush=False),                                    # PTR
        rr(inst, 33, struct.pack("!HHH", 0, 0, 631) + qname(HOST)),               # SRV
        rr(inst, 16, bytes([len(txt)]) + txt),                                    # TXT
        rr(HOST, 1, socket.inet_aton(ip)),                                        # A
    ]
    header = struct.pack("!HHHHHH", 0, 0x8400, 0, len(answers), 0, 0)             # response, AA
    return header + b"".join(answers)


def main() -> None:
    interval = float(sys.argv[1]) if len(sys.argv) > 1 else 2.0
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as probe:
        probe.connect((GROUP, PORT))
        ip = probe.getsockname()[0]
    pkt = announcement(ip)
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 255)
    s.bind(("", PORT))
    print(f"announcing {NAME}.{SVC} at {ip} every {interval} s ({len(pkt)} bytes)", flush=True)
    while True:
        s.sendto(pkt, (GROUP, PORT))
        time.sleep(interval)


if __name__ == "__main__":
    main()
