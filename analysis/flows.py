"""Flow table from a pcap: one Flow per bidirectional 5-tuple, keeping the series needed
by the signature and rhythm rules (payload sizes and times per direction, first payload
bytes per direction, TCP flags seen).

    from analysis.flows import build
    flows = build("capture.pcap")      # dict key -> Flow
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from . import pcap

FIRST_BYTES = 64          # payload prefix kept per direction, for static signatures
# byte markers looked for anywhere in a flow's first SCAN_PACKETS payload packets, for the
# signatures that sit past FIRST_BYTES: a libp2p multiaddr in an mDNS TXT record (LocalAI:
# offset 183, in the second packet after a short query) and ggml tensor names in SET_TENSOR
# (offset 528 on LocalAI's loopback, after HELLO and the buffer allocations)
MARKERS = (b"dnsaddr=", b"/p2p/", b"blk.", b"token_embd", b"output_norm")
SCAN_PACKETS = 256


@dataclass
class Flow:
    proto: str
    a: Tuple[str, int]        # low endpoint
    b: Tuple[str, int]        # high endpoint
    t_first: float
    t_last: float
    packets: int = 0
    bytes_ab: int = 0         # wire bytes a->b
    bytes_ba: int = 0
    payload_ab: int = 0       # payload bytes a->b
    payload_ba: int = 0
    # per-direction (t, payload_len) for packets that carry payload
    series_ab: List[Tuple[float, int]] = field(default_factory=list)
    series_ba: List[Tuple[float, int]] = field(default_factory=list)
    first_ab: bytes = b""
    first_ba: bytes = b""
    flags: int = 0            # OR of TCP flags seen
    markers: Set[bytes] = field(default_factory=set)   # MARKERS seen in the first packets
    rst_at: Optional[float] = None
    syn_at: Optional[float] = None
    fin_at: Optional[float] = None
    # tcp sequence tracking per direction: the highest seq+len seen and the bytes
    # accumulated as it advances, so bytes the capture dropped are still counted
    # (expected_ab/expected_ba) and a 32-bit wrap, any number of times, is harmless
    seq_end_ab: Optional[int] = None
    seq_end_ba: Optional[int] = None
    exp_ab: int = 0
    exp_ba: int = 0

    @property
    def key(self):
        return (self.proto, self.a, self.b)

    @property
    def duration(self) -> float:
        return self.t_last - self.t_first

    def endpoints(self) -> str:
        return f"{self.proto} {self.a[0]}:{self.a[1]} <-> {self.b[0]}:{self.b[1]}"

    @property
    def expected_ab(self) -> int:
        """Payload bytes a->b according to TCP sequence numbers (SYN/FIN not counted);
        equals payload_ab when nothing was dropped. 0 for udp."""
        return self.exp_ab

    @property
    def expected_ba(self) -> int:
        return self.exp_ba

    @property
    def dropped(self) -> int:
        """Payload bytes the capture missed, by sequence accounting."""
        return max(0, self.expected_ab - self.payload_ab) + max(0, self.expected_ba - self.payload_ba)

    def add(self, p: pcap.Packet) -> None:
        self.packets += 1
        self.t_last = max(self.t_last, p.t)
        n = len(p.payload)
        if n and len(self.series_ab) + len(self.series_ba) < SCAN_PACKETS:
            self.markers.update(m for m in MARKERS if m in p.payload)
        if p.forward:
            self.bytes_ab += p.wire_len
            self.payload_ab += n
            if n:
                self.series_ab.append((p.t, n))
                if len(self.first_ab) < FIRST_BYTES:
                    self.first_ab += p.payload[:FIRST_BYTES - len(self.first_ab)]
        else:
            self.bytes_ba += p.wire_len
            self.payload_ba += n
            if n:
                self.series_ba.append((p.t, n))
                if len(self.first_ba) < FIRST_BYTES:
                    self.first_ba += p.payload[:FIRST_BYTES - len(self.first_ba)]
        if p.proto == "tcp":
            self.flags |= p.flags
            if p.flags & pcap.TCP_RST and self.rst_at is None:
                self.rst_at = p.t
            if p.flags & pcap.TCP_FIN and self.fin_at is None:
                self.fin_at = p.t
            if p.flags & pcap.TCP_SYN and not p.flags & pcap.TCP_ACK and self.syn_at is None:
                self.syn_at = p.t
            # sequence accounting per direction; a SYN consumes one sequence number
            if n or p.flags & pcap.TCP_SYN:
                start = (p.seq + 1) & 0xFFFFFFFF if p.flags & pcap.TCP_SYN else p.seq
                end = (start + n) & 0xFFFFFFFF
                cur = self.seq_end_ab if p.forward else self.seq_end_ba
                # a SYN starts a new sequence space: libp2p redials a peer from the same
                # port, so one 5-tuple carries several connections, each with a random ISN
                # (counted as up to 2 GB of advance before; 2.7 TB "dropped" on the DHT run)
                if cur is None or p.flags & pcap.TCP_SYN:
                    cur = None
                    adv = n
                else:
                    # how far the highest end advanced (modulo 2^32); a retransmission or
                    # an out-of-order segment behind it advances by nothing
                    adv = (end - cur) & 0xFFFFFFFF
                    if adv >= 0x80000000:
                        adv = 0
                if p.forward:
                    self.exp_ab += adv
                    if cur is None or adv:
                        self.seq_end_ab = end
                else:
                    self.exp_ba += adv
                    if cur is None or adv:
                        self.seq_end_ba = end


def build(path: str, t_end: Optional[float] = None, stats: Optional[pcap.Stats] = None) -> Dict[tuple, Flow]:
    """Flows from the capture, optionally only packets with t <= t_end (seconds, absolute),
    which is how detection latency is measured: rebuild with a growing window."""
    flows: Dict[tuple, Flow] = {}
    for p in pcap.read(path, stats):
        if t_end is not None and p.t > t_end:
            break
        k = p.key
        f = flows.get(k)
        if f is None:
            a, b = k[1], k[2]
            f = flows[k] = Flow(p.proto, a, b, p.t, p.t)
        f.add(p)
    return flows


def hosts(flows: Dict[tuple, Flow]) -> List[str]:
    hs = set()
    for f in flows.values():
        hs.add(f.a[0]); hs.add(f.b[0])
    return sorted(hs)
