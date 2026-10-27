"""Minimal pcap reader: standard library only.

Reads classic pcap (what `tcpdump -w` writes) with Ethernet, Linux cooked (SLL v1/v2) or
raw-IP link types, and yields one Packet per IPv4/IPv6 datagram with its TCP/UDP header
fields and payload. Fragments, non-IP frames and other transports are skipped (counted).

    for pkt in read("capture.pcap"): ...

Packet fields: t (float, s), src, dst (str), proto ("tcp"/"udp"/"icmp"/...), sport, dport,
flags (tcp flag bits, 0 for udp), payload (bytes), wire_len (int, on-wire frame length).
"""

from __future__ import annotations

import socket
import struct
from dataclasses import dataclass
from typing import Iterator, Optional

LINKTYPE_ETHERNET, LINKTYPE_RAW_OLD, LINKTYPE_SLL, LINKTYPE_SLL2 = 1, 12, 113, 276
LINKTYPE_RAW, LINKTYPE_IPV4, LINKTYPE_IPV6 = 101, 228, 229

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK = 0x01, 0x02, 0x04, 0x08, 0x10


@dataclass
class Packet:
    t: float
    src: str
    dst: str
    proto: str
    sport: int
    dport: int
    flags: int
    payload: bytes
    wire_len: int
    ip_len: int = 0          # IP total length (v4) or payload length + 40 (v6)
    seq: int = 0             # tcp sequence number, 0 for udp

    @property
    def key(self):
        """Bidirectional flow key: (proto, low endpoint, high endpoint)."""
        a, b = (self.src, self.sport), (self.dst, self.dport)
        return (self.proto,) + ((a, b) if a <= b else (b, a))

    @property
    def forward(self) -> bool:
        """True when this packet goes from the flow key's low endpoint to the high one."""
        return (self.src, self.sport) <= (self.dst, self.dport)


class Stats:
    def __init__(self):
        self.packets = 0
        self.skipped = 0


def _ip4(buf: bytes, t: float, wire_len: int) -> Optional[Packet]:
    if len(buf) < 20:
        return None
    ihl = (buf[0] & 0x0F) * 4
    total = struct.unpack_from("!H", buf, 2)[0]
    frag = struct.unpack_from("!H", buf, 6)[0] & 0x1FFF
    proto = buf[9]
    if frag:
        return None
    src = socket.inet_ntop(socket.AF_INET, buf[12:16])
    dst = socket.inet_ntop(socket.AF_INET, buf[16:20])
    return _l4(buf[ihl:total] if total >= ihl else buf[ihl:], proto, src, dst, t, wire_len, total)


def _ip6(buf: bytes, t: float, wire_len: int) -> Optional[Packet]:
    if len(buf) < 40:
        return None
    plen = struct.unpack_from("!H", buf, 4)[0]
    nxt = buf[6]
    src = socket.inet_ntop(socket.AF_INET6, buf[8:24])
    dst = socket.inet_ntop(socket.AF_INET6, buf[24:40])
    body = buf[40:40 + plen]
    # walk hop-by-hop / routing / destination options; stop at fragments
    while nxt in (0, 43, 60):
        if len(body) < 2:
            return None
        nxt, hl = body[0], (body[1] + 1) * 8
        body = body[hl:]
    if nxt == 44:
        return None
    return _l4(body, nxt, src, dst, t, wire_len, plen + 40)


def _l4(buf: bytes, proto: int, src: str, dst: str, t: float, wire_len: int, ip_len: int) -> Optional[Packet]:
    if proto == 6 and len(buf) >= 20:
        sport, dport = struct.unpack_from("!HH", buf, 0)
        off = (buf[12] >> 4) * 4
        seq = struct.unpack_from("!I", buf, 4)[0]
        return Packet(t, src, dst, "tcp", sport, dport, buf[13], buf[off:], wire_len, ip_len, seq)
    if proto == 17 and len(buf) >= 8:
        sport, dport = struct.unpack_from("!HH", buf, 0)
        return Packet(t, src, dst, "udp", sport, dport, 0, buf[8:], wire_len, ip_len)
    name = {1: "icmp", 58: "icmp6", 2: "igmp"}.get(proto, f"ip{proto}")
    return Packet(t, src, dst, name, 0, 0, 0, buf, wire_len, ip_len)


def _strip_link(linktype: int, buf: bytes) -> Optional[tuple]:
    """Return (ethertype-or-version, ip bytes) for the given link type."""
    if linktype == LINKTYPE_ETHERNET:
        if len(buf) < 14:
            return None
        et = struct.unpack_from("!H", buf, 12)[0]
        off = 14
        while et == 0x8100 or et == 0x88A8:          # VLAN tags
            if len(buf) < off + 4:
                return None
            et = struct.unpack_from("!H", buf, off + 2)[0]
            off += 4
        return et, buf[off:]
    if linktype == LINKTYPE_SLL:
        if len(buf) < 16:
            return None
        return struct.unpack_from("!H", buf, 14)[0], buf[16:]
    if linktype == LINKTYPE_SLL2:
        if len(buf) < 20:
            return None
        return struct.unpack_from("!H", buf, 0)[0], buf[20:]
    if linktype in (LINKTYPE_RAW, LINKTYPE_RAW_OLD, LINKTYPE_IPV4, LINKTYPE_IPV6):
        if not buf:
            return None
        return (0x0800 if buf[0] >> 4 == 4 else 0x86DD), buf
    return None


def read(path: str, stats: Optional[Stats] = None) -> Iterator[Packet]:
    stats = stats or Stats()
    with open(path, "rb") as f:
        gh = f.read(24)
        if len(gh) < 24:
            return
        magic = struct.unpack("<I", gh[:4])[0]
        if magic in (0xA1B2C3D4, 0xA1B23C4D):
            endian, nanos = "<", magic == 0xA1B23C4D
        elif magic in (0xD4C3B2A1, 0x4D3CB2A1):
            endian, nanos = ">", magic == 0x4D3CB2A1
        elif magic == 0x0A0D0D0A:
            raise ValueError("pcapng is not supported; capture with `tcpdump -w` (classic pcap) or convert with `editcap -F pcap`")
        else:
            raise ValueError("not a pcap file")
        linktype = struct.unpack(endian + "I", gh[20:24])[0]
        while True:
            rh = f.read(16)
            if len(rh) < 16:
                return
            ts, tu, incl, orig = struct.unpack(endian + "IIII", rh)
            buf = f.read(incl)
            if len(buf) < incl:
                return
            t = ts + tu / (1e9 if nanos else 1e6)
            stats.packets += 1
            l = _strip_link(linktype, buf)
            pkt = None
            if l is not None:
                et, ip = l
                if et == 0x0800:
                    pkt = _ip4(ip, t, orig)
                elif et == 0x86DD:
                    pkt = _ip6(ip, t, orig)
            if pkt is None:
                stats.skipped += 1
                continue
            yield pkt
