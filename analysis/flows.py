"""Flow table from a pcap: one Flow per bidirectional 5-tuple, keeping the series needed
by the signature and rhythm rules (payload sizes and times per direction, first payload
bytes per direction, TCP flags seen).

    from analysis.flows import build
    flows = build("capture.pcap")      # dict key -> Flow
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from . import pcap

FIRST_BYTES = 64          # payload prefix kept per direction, for static signatures


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
    rst_at: Optional[float] = None
    syn_at: Optional[float] = None
    fin_at: Optional[float] = None
    # tcp sequence tracking per direction: (first seq, highest seq+len), so bytes the
    # capture dropped are still counted (expected_ab/expected_ba)
    seq_ab: Optional[Tuple[int, int]] = None
    seq_ba: Optional[Tuple[int, int]] = None

    @property
    def key(self):
        return (self.proto, self.a, self.b)

    @property
    def duration(self) -> float:
        return self.t_last - self.t_first

    def endpoints(self) -> str:
        return f"{self.proto} {self.a[0]}:{self.a[1]} <-> {self.b[0]}:{self.b[1]}"

    @staticmethod
    def _span(sp: Optional[Tuple[int, int]]) -> int:
        if sp is None:
            return 0
        return (sp[1] - sp[0]) & 0xFFFFFFFF

    @property
    def expected_ab(self) -> int:
        """Payload bytes a->b according to TCP sequence numbers (SYN/FIN not counted);
        equals payload_ab when nothing was dropped. 0 for udp."""
        return self._span(self.seq_ab)

    @property
    def expected_ba(self) -> int:
        return self._span(self.seq_ba)

    @property
    def dropped(self) -> int:
        """Payload bytes the capture missed, by sequence accounting."""
        return max(0, self.expected_ab - self.payload_ab) + max(0, self.expected_ba - self.payload_ba)

    def add(self, p: pcap.Packet) -> None:
        self.packets += 1
        self.t_last = max(self.t_last, p.t)
        n = len(p.payload)
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
            # sequence span per direction; a SYN consumes one sequence number
            if n or p.flags & pcap.TCP_SYN:
                start = (p.seq + 1) & 0xFFFFFFFF if p.flags & pcap.TCP_SYN else p.seq
                end = (start + n) & 0xFFFFFFFF
                cur = self.seq_ab if p.forward else self.seq_ba
                if cur is None:
                    cur = (start, end)
                else:
                    # highest end seen, allowing for a wrap; the first start is kept
                    if ((end - cur[1]) & 0xFFFFFFFF) < 0x80000000:
                        cur = (cur[0], end)
                if p.forward:
                    self.seq_ab = cur
                else:
                    self.seq_ba = cur


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
