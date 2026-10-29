"""Static signatures: rules that match bytes, ports and addresses, read from source
(FINDINGS-wire.md). Each rule takes a Flow and returns a Match or None. A rule's `needs`
says what the rule consumed, so a report can say how little capture was enough.

Rules deliberately separate the port part from the byte part (prediction 15): a port
change should defeat only the port part.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from typing import List, Optional

from .flows import Flow

EXO_MAGIC = b"EXO"
EXO_DISCOVERY_GROUP = "ff12::e0a1:de89"
EXO_DISCOVERY_PORT = 52413
EXO_ZENOH_PORT = 52414
EXO_API_PORT = 52415

LLAMA_RPC_PORT = 50052
LLAMA_HELLO_CLIENT = bytes([0x0E]) + struct.pack("<Q", 24) + bytes(24)       # 33 bytes
LLAMA_HELLO_SERVER_PREFIX = struct.pack("<Q", 28) + bytes([8, 0, 1, 0])        # 12 of 36 bytes
LLAMA_CMD_MAX = 0x16

MULTISTREAM = b"/multistream/1.0.0\n"
MDNS_GROUP_V4, MDNS_GROUP_V6, MDNS_PORT = "224.0.0.251", "ff02::fb", 5353


@dataclass
class Match:
    rule: str
    stack: str                # exo | llama.cpp | libp2p | background
    what: str                 # short human description
    needs: str                # what was consumed: "1 packet", "33 bytes", ...
    t: float                  # capture time at which the match became possible
    strength: str             # "byte" (content signature) | "port" (port/address only)


def _ports(f: Flow):
    return {f.a[1], f.b[1]}


def exo_beacon(f: Flow) -> Optional[Match]:
    """20-byte UDP datagram with 'EXO' + kind 0 to the discovery group; 30-byte kind-1 reply."""
    if f.proto != "udp":
        return None
    first = f.first_ab or f.first_ba
    series = f.series_ab or f.series_ba
    if not first or not series:
        return None
    to_group = EXO_DISCOVERY_GROUP in (f.a[0], f.b[0])
    on_port = EXO_DISCOVERY_PORT in _ports(f)
    size = series[0][1]
    if first[:3] == EXO_MAGIC and ((first[3] == 0 and size == 20) or (first[3] == 1 and size == 30)):
        kind = "Hello (multicast)" if first[3] == 0 else "WhatsUp (unicast reply)"
        return Match("exo_beacon", "exo", f"exo discovery {kind}", "1 packet, 4 bytes",
                     series[0][0], "byte")
    if to_group or (on_port and size in (20, 30)):
        return Match("exo_beacon_port", "exo", "UDP to exo's discovery group/port", "1 packet",
                     series[0][0], "port")
    return None


def exo_zenoh(f: Flow) -> Optional[Match]:
    """Plaintext zenoh on 52414: key expressions or JSON field names in the first bytes."""
    if f.proto != "tcp":
        return None
    head = f.first_ab + f.first_ba
    series = f.series_ab or f.series_ba
    t0 = series[0][0] if series else f.t_first
    if b"topics/" in head or b"live/" in head or b'"heartbeat"' in head or b'"token_id"' in head:
        return Match("exo_zenoh", "exo", "zenoh key expression / exo JSON in plaintext", "first bytes",
                     t0, "byte")
    if EXO_ZENOH_PORT in _ports(f) and (f.payload_ab or f.payload_ba):
        return Match("exo_zenoh_port", "exo", "TCP on exo's zenoh port", "1 packet", t0, "port")
    return None


def exo_api(f: Flow) -> Optional[Match]:
    """exo's inter-node GET /node_id probes and client SSE on 52415."""
    if f.proto != "tcp" or EXO_API_PORT not in _ports(f):
        return None
    head = f.first_ab + f.first_ba
    series = f.series_ab or f.series_ba
    t0 = series[0][0] if series else f.t_first
    if b"GET /node_id" in head:
        return Match("exo_node_id", "exo", "GET /node_id probe between exo nodes", "first bytes", t0, "byte")
    if f.payload_ab or f.payload_ba:
        return Match("exo_api_port", "exo", "TCP on exo's API port", "1 packet", t0, "port")
    return None


def llama_hello(f: Flow) -> Optional[Match]:
    """The 33-byte client HELLO and the 36-byte server reply, exact bytes."""
    if f.proto != "tcp":
        return None
    for first, series, dirn in ((f.first_ab, f.series_ab, "ab"), (f.first_ba, f.series_ba, "ba")):
        if first[:33] == LLAMA_HELLO_CLIENT:
            return Match("llama_hello", "llama.cpp", "ggml RPC HELLO (client, 33 bytes)", "33 bytes",
                         series[0][0], "byte")
        if first[:12] == LLAMA_HELLO_SERVER_PREFIX:
            return Match("llama_hello", "llama.cpp", "ggml RPC HELLO reply (server, v8.0.1)", "12 bytes",
                         series[0][0], "byte")
    return None


def llama_frames(f: Flow) -> Optional[Match]:
    """Frame grammar for a capture that missed the HELLO: the client's first observed payload
    starts with cmd byte <= 0x16 and an 8-byte LE length consistent with the bytes that
    follow in the same segment (or larger, for multi-segment frames)."""
    if f.proto != "tcp":
        return None
    for first, series in ((f.first_ab, f.series_ab), (f.first_ba, f.series_ba)):
        if len(first) >= 9 and first[0] <= LLAMA_CMD_MAX:
            n = struct.unpack_from("<Q", first, 1)[0]
            seg = series[0][1] if series else 0
            # fixed small frames from the source: 21 (GRAPH_RECOMPUTE), 321 (GET_TENSOR / SET_TENSOR_HASH),
            # 314+data (SET_TENSOR); anything up to a few hundred MB is a plausible upload
            if n == seg - 9 or (n > seg - 9 and n < 1 << 30):
                if n in (12, 312, 320) or n == seg - 9:
                    return Match("llama_frames", "llama.cpp", f"ggml RPC frame grammar (cmd 0x{first[0]:02x}, len {n})",
                                 "9 bytes", series[0][0], "byte")
    return None


def llama_port(f: Flow) -> Optional[Match]:
    if f.proto == "tcp" and LLAMA_RPC_PORT in _ports(f) and (f.payload_ab or f.payload_ba):
        series = f.series_ab or f.series_ba
        return Match("llama_port", "llama.cpp", "TCP on ggml rpc-server's default port", "1 packet",
                     series[0][0], "port")
    return None


def llama_tensor_names(f: Flow) -> Optional[Match]:
    """Readable ggml tensor names ('blk.N.', 'token_embd', 'output_norm') in the first packets."""
    if f.proto == "tcp" and f.markers & {b"blk.", b"token_embd", b"output_norm"}:
        series = f.series_ab or f.series_ba
        return Match("llama_tensor_names", "llama.cpp", "ggml tensor name in plaintext", "first packets",
                     series[0][0], "byte")
    return None


def libp2p_handshake(f: Flow) -> Optional[Match]:
    """multistream-select in plaintext before Noise/TLS, or a TLS ClientHello with ALPN libp2p."""
    if f.proto != "tcp":
        return None
    head = f.first_ab + f.first_ba
    series = f.series_ab or f.series_ba
    t0 = series[0][0] if series else f.t_first
    if MULTISTREAM in head:
        sec = "/noise" if b"/noise" in head else ("/tls" if b"/tls" in head else "?")
        return Match("libp2p_multistream", "libp2p", f"multistream-select then {sec}", "first bytes", t0, "byte")
    if b"libp2p" in head and head[:1] == b"\x16":
        return Match("libp2p_alpn", "libp2p", "TLS ClientHello with ALPN libp2p", "first bytes", t0, "byte")
    return None


def mdns(f: Flow) -> Optional[Match]:
    """mDNS to the multicast group; libp2p peers advertise /p2p/ in TXT, LocalAI uses a random
    43-char label. Ordinary devices also speak mDNS: on its own this is background."""
    if f.proto != "udp" or MDNS_PORT not in _ports(f):
        return None
    if not ({MDNS_GROUP_V4, MDNS_GROUP_V6} & {f.a[0], f.b[0]}):
        return None
    series = f.series_ab or f.series_ba
    t0 = series[0][0] if series else f.t_first
    if f.markers & {b"dnsaddr=", b"/p2p/"}:
        return Match("mdns_libp2p", "libp2p", "mDNS record advertising a libp2p multiaddr", "1 packet", t0, "byte")
    return Match("mdns", "background", "mDNS (ordinary)", "1 packet", t0, "port")


RULES = [exo_beacon, exo_zenoh, exo_api, llama_hello, llama_tensor_names, llama_frames, llama_port,
         libp2p_handshake, mdns]


def match_all(f: Flow) -> List[Match]:
    out = []
    for r in RULES:
        m = r(f)
        if m:
            out.append(m)
    return out
