"""Client QUIC v1 Initials carrying a ClientHello, for the tests and the synthetic capture.
The ClientHello is shaped like quic-go's: a post-quantum key share large enough that the
handshake message spans two Initials, as in the LocalAI captures (about 1.5 KB)."""

from __future__ import annotations

import struct
from typing import List, Optional

from analysis import quic


def _ext(kind: int, data: bytes) -> bytes:
    return struct.pack("!HH", kind, len(data)) + data


def client_hello(alpn: List[str], sni: Optional[str] = None, key_share: int = 1216) -> bytes:
    exts = b""
    if sni:
        name = sni.encode()
        exts += _ext(0, struct.pack("!HBH", len(name) + 3, 0, len(name)) + name)
    protos = b"".join(bytes([len(p)]) + p.encode() for p in alpn)
    exts += _ext(16, struct.pack("!H", len(protos)) + protos)
    share = struct.pack("!HH", 0x11EC, key_share) + bytes(key_share)
    exts += _ext(51, struct.pack("!H", len(share)) + share)
    body = (b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x06\x13\x01\x13\x02\x13\x03" + b"\x01\x00"
            + struct.pack("!H", len(exts)) + exts)
    return b"\x01" + len(body).to_bytes(3, "big") + body


def initials(hello: bytes, dcid: bytes, scid: bytes = b"\x01" * 8, chunk: int = 1100) -> List[bytes]:
    """The hello split over as many client Initials as it takes, each padded to 1200 bytes."""
    keys = quic.client_initial_keys(dcid)
    out = []
    for pn, off in enumerate(range(0, len(hello), chunk)):
        data = hello[off:off + chunk]
        frame = b"\x06" + quic.encode_varint(off) + quic.encode_varint(len(data)) + data
        prefix = bytes([0xC0]) + struct.pack("!I", 1) + bytes([len(dcid)]) + dcid + bytes([len(scid)]) + scid + b"\x00"
        pn_len = 2
        fixed = len(prefix) + 2 + pn_len + quic.TAG_LEN       # with a 2-byte Length field
        payload = frame + bytes(max(0, quic.MIN_CLIENT_DATAGRAM - fixed - len(frame)))
        header = prefix + quic.encode_varint(pn_len + len(payload) + quic.TAG_LEN).rjust(2, b"\x40")
        out.append(quic.seal_initial(header, pn, pn_len, payload, keys))
    return out
