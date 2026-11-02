"""QUIC v1 Initial packets, read as a passive observer can (RFC 9001 §5.2): the Initial keys
come from the client's first Destination Connection ID and a published salt, so the TLS
ClientHello inside, with its ALPN and SNI, is readable by anyone on the path. libp2p's QUIC
transport (LocalAI's tunnels) offers ALPN `libp2p` there.

    from analysis import quic
    ch = quic.client_hello([datagram, datagram, ...])    # the client's first datagrams
    ch.alpn, ch.sni, ch.datagrams

Standard library only, so AES-128 and GCM are written out below; they run on a few
datagrams per connection, not on the data. QUIC v2 (RFC 9369) is not decoded.
"""

from __future__ import annotations

import hashlib
import hmac
import struct
from dataclasses import dataclass
from typing import Iterator, List, Optional, Tuple

VERSION_1 = 0x00000001
INITIAL_SALT_V1 = bytes.fromhex("38762cf7f55934b34d179ae6a4c80cadccbb7f0a")
TAG_LEN = 16
MIN_CLIENT_DATAGRAM = 1200   # RFC 9000 §14.1: a client pads datagrams carrying an Initial to this
MAX_CID = 20                 # RFC 9000 §17.2: connection ids in v1 are at most 20 bytes

# --- AES-128, encryption only (header protection and GCM need no decryption) ---------------

def _sbox() -> List[int]:
    box = [0] * 256
    p = q = 1
    while True:                       # walk GF(2^8) by 3 and its inverse by 1/3 together
        p ^= ((p << 1) & 0xFF) ^ (0x1B if p & 0x80 else 0)
        q ^= q << 1
        q ^= q << 2
        q ^= q << 4
        q &= 0xFF
        if q & 0x80:
            q ^= 0x09
        box[p] = q ^ 0x63
        for s in range(1, 5):
            box[p] ^= ((q << s) | (q >> (8 - s))) & 0xFF
        if p == 1:
            break
    box[0] = 0x63
    return box


SBOX = _sbox()
SHIFT_ROWS = [(i + 4 * (i % 4)) % 16 for i in range(16)]   # state in column-major order


def _xtime(a: int) -> int:
    return ((a << 1) ^ 0x1B) & 0xFF if a & 0x80 else a << 1


def expand_key(key: bytes) -> List[List[int]]:
    """The 11 round keys of AES-128."""
    w = [list(key[i:i + 4]) for i in range(0, 16, 4)]
    rcon = 1
    for i in range(4, 44):
        t = list(w[i - 1])
        if i % 4 == 0:
            t = [SBOX[b] for b in t[1:] + t[:1]]
            t[0] ^= rcon
            rcon = _xtime(rcon)
        w.append([a ^ b for a, b in zip(w[i - 4], t)])
    return [sum(w[4 * r:4 * r + 4], []) for r in range(11)]


def aes_block(round_keys: List[List[int]], block: bytes) -> bytes:
    s = [a ^ b for a, b in zip(block, round_keys[0])]
    for r in range(1, 11):
        s = [SBOX[s[i]] for i in SHIFT_ROWS]
        if r != 10:
            mixed = []
            for c in range(0, 16, 4):
                a = s[c:c + 4]
                t = a[0] ^ a[1] ^ a[2] ^ a[3]
                mixed += [a[i] ^ t ^ _xtime(a[i] ^ a[(i + 1) % 4]) for i in range(4)]
            s = mixed
        s = [a ^ b for a, b in zip(s, round_keys[r])]
    return bytes(s)


# --- AES-128-GCM ------------------------------------------------------------------------------

_R = 0xE1 << 120


def _gf_mul(x: int, y: int) -> int:
    z = 0
    for i in range(127, -1, -1):
        if (x >> i) & 1:
            z ^= y
        y = (y >> 1) ^ _R if y & 1 else y >> 1
    return z


def _ghash(h: int, aad: bytes, ct: bytes) -> int:
    x = 0
    for data in (aad, ct):
        for i in range(0, len(data), 16):
            x = _gf_mul(x ^ int.from_bytes(data[i:i + 16].ljust(16, b"\0"), "big"), h)
    return _gf_mul(x ^ (len(aad) * 8 << 64 | len(ct) * 8), h)


def _ctr(rk: List[List[int]], iv: bytes, data: bytes) -> bytes:
    out = bytearray()
    for i in range(0, len(data), 16):
        ks = aes_block(rk, iv + struct.pack("!I", 2 + i // 16))
        out += bytes(a ^ b for a, b in zip(data[i:i + 16], ks))
    return bytes(out)


def _tag(rk: List[List[int]], iv: bytes, aad: bytes, ct: bytes) -> bytes:
    h = int.from_bytes(aes_block(rk, bytes(16)), "big")
    s = _ghash(h, aad, ct) ^ int.from_bytes(aes_block(rk, iv + b"\0\0\0\1"), "big")
    return s.to_bytes(16, "big")


def gcm_seal(key: bytes, iv: bytes, plaintext: bytes, aad: bytes) -> bytes:
    rk = expand_key(key)
    ct = _ctr(rk, iv, plaintext)
    return ct + _tag(rk, iv, aad, ct)


def gcm_open(key: bytes, iv: bytes, sealed: bytes, aad: bytes) -> Optional[bytes]:
    """The plaintext, or None when the tag does not verify."""
    if len(sealed) < TAG_LEN:
        return None
    rk = expand_key(key)
    ct, tag = sealed[:-TAG_LEN], sealed[-TAG_LEN:]
    if not hmac.compare_digest(_tag(rk, iv, aad, ct), tag):
        return None
    return _ctr(rk, iv, ct)


# --- Initial keys (RFC 9001 §5.2) -------------------------------------------------------------

def _expand_label(secret: bytes, label: bytes, n: int) -> bytes:
    full = b"tls13 " + label
    info = struct.pack("!HB", n, len(full)) + full + b"\0"
    return hmac.new(secret, info + b"\1", hashlib.sha256).digest()[:n]   # n <= 32: one block


@dataclass(frozen=True)
class Keys:
    key: bytes
    iv: bytes
    hp: bytes


def client_initial_keys(dcid: bytes) -> Keys:
    initial = hmac.new(INITIAL_SALT_V1, dcid, hashlib.sha256).digest()
    secret = _expand_label(initial, b"client in", 32)
    return Keys(_expand_label(secret, b"quic key", 16), _expand_label(secret, b"quic iv", 12),
                _expand_label(secret, b"quic hp", 16))


# --- packets ----------------------------------------------------------------------------------

def _varint(b: bytes, i: int) -> Tuple[int, int]:
    n = 1 << (b[i] >> 6)
    if i + n > len(b):
        raise IndexError("varint past the end")
    v = b[i] & 0x3F
    for j in range(1, n):
        v = v << 8 | b[i + j]
    return v, i + n


def encode_varint(v: int) -> bytes:
    for n, tag in ((1, 0), (2, 0x40), (4, 0x80), (8, 0xC0)):
        if v < 1 << (8 * n - 2):
            return (v | tag << (8 * n - 8)).to_bytes(n, "big")
    raise ValueError(v)


@dataclass(frozen=True)
class LongHeader:
    start: int                 # offset of the packet in the datagram
    pn_offset: int             # offset of the (protected) packet number
    end: int                   # end of the packet in the datagram
    dcid: bytes


def initial_packets(datagram: bytes) -> Iterator[LongHeader]:
    """The v1 Initial packets in a datagram, coalesced ones included; nothing for a short
    header, another version, or bytes that do not parse."""
    i = 0
    try:
        while i < len(datagram) and datagram[i] & 0xC0 == 0xC0:
            first = datagram[i]
            if struct.unpack_from("!I", datagram, i + 1)[0] != VERSION_1:
                return
            j = i + 5
            if datagram[j] > MAX_CID or datagram[j + 1 + datagram[j]] > MAX_CID:
                return
            dcid = datagram[j + 1:j + 1 + datagram[j]]
            j += 1 + datagram[j]
            j += 1 + datagram[j]                       # source connection id
            kind = (first & 0x30) >> 4
            if kind == 3:                              # Retry: no length field, ends the datagram
                return
            if kind == 0:
                token_len, j = _varint(datagram, j)
                j += token_len
            length, j = _varint(datagram, j)
            if j + length > len(datagram) or length < 4 + TAG_LEN:
                return
            if kind == 0:
                yield LongHeader(i, j, j + length, dcid)
            i = j + length
    except (IndexError, struct.error):
        return


def open_initial(datagram: bytes, h: LongHeader, keys: Keys) -> Optional[bytes]:
    """Remove header protection and decrypt; None if the tag does not verify (wrong keys:
    the server's Initials, or not QUIC at all)."""
    sample = datagram[h.pn_offset + 4:h.pn_offset + 20]
    if len(sample) < 16:
        return None
    mask = aes_block(expand_key(keys.hp), sample)
    first = datagram[h.start] ^ (mask[0] & 0x0F)
    pn_len = (first & 3) + 1
    pn_bytes = bytes(a ^ b for a, b in zip(datagram[h.pn_offset:h.pn_offset + pn_len], mask[1:]))
    aad = bytes([first]) + datagram[h.start + 1:h.pn_offset] + pn_bytes
    nonce = (int.from_bytes(keys.iv, "big") ^ int.from_bytes(pn_bytes, "big")).to_bytes(12, "big")
    return gcm_open(keys.key, nonce, datagram[h.pn_offset + pn_len:h.end], aad)


def seal_initial(header: bytes, pn: int, pn_len: int, payload: bytes, keys: Keys) -> bytes:
    """Build a protected Initial from an unprotected header that ends with the Length field
    (which must count pn_len + len(payload) + 16). For tests and the synthetic capture."""
    pn_bytes = pn.to_bytes(pn_len, "big")
    first = (header[0] & ~3) | (pn_len - 1)
    aad = bytes([first]) + header[1:] + pn_bytes
    nonce = (int.from_bytes(keys.iv, "big") ^ pn).to_bytes(12, "big")
    sealed = gcm_seal(keys.key, nonce, payload, aad)
    pn_offset = len(header)
    sample = sealed[4 - pn_len:20 - pn_len]
    mask = aes_block(expand_key(keys.hp), sample)
    out = bytes([first ^ (mask[0] & 0x0F)]) + header[1:]
    return out + bytes(a ^ b for a, b in zip(pn_bytes, mask[1:])) + sealed


def crypto_frames(plain: bytes) -> Iterator[Tuple[int, bytes]]:
    """(offset, data) of each CRYPTO frame; stops at a frame an Initial should not carry."""
    i = 0
    try:
        while i < len(plain):
            t = plain[i]
            if t in (0x00, 0x01):                      # PADDING, PING
                i += 1
            elif t == 0x06:                            # CRYPTO
                off, i = _varint(plain, i + 1)
                n, i = _varint(plain, i)
                if i + n > len(plain):
                    return
                yield off, plain[i:i + n]
                i += n
            elif t in (0x02, 0x03):                    # ACK, ACK with ECN counts
                _, i = _varint(plain, i + 1)
                _, i = _varint(plain, i)
                count, i = _varint(plain, i)
                _, i = _varint(plain, i)
                for _ in range(2 * count + (3 if t == 0x03 else 0)):
                    _, i = _varint(plain, i)
            else:                                      # CONNECTION_CLOSE, or not an Initial
                return
    except IndexError:
        return


# --- the ClientHello ----------------------------------------------------------------------------

@dataclass(frozen=True)
class ClientHello:
    alpn: Tuple[str, ...]
    sni: Optional[str]
    length: int                # handshake message bytes
    datagrams: int             # datagrams it took to complete


def parse_client_hello(buf: bytes) -> Optional[Tuple[Tuple[str, ...], Optional[str], int]]:
    """(alpn, sni, length) of a complete ClientHello at the start of buf, else None."""
    if len(buf) < 4 or buf[0] != 0x01:
        return None
    n = int.from_bytes(buf[1:4], "big")
    if len(buf) < 4 + n:
        return None
    b = buf[4:4 + n]
    try:
        i = 2 + 32                                     # legacy_version, random
        i += 1 + b[i]                                  # session id
        i += 2 + struct.unpack_from("!H", b, i)[0]     # cipher suites
        i += 1 + b[i]                                  # compression methods
        end = i + 2 + struct.unpack_from("!H", b, i)[0]
        if end > len(b):
            return None
        i += 2
        alpn: List[str] = []
        sni = None
        while i + 4 <= end:
            ext, size = struct.unpack_from("!HH", b, i)
            if i + 4 + size > end:
                return None
            data = b[i + 4:i + 4 + size]
            i += 4 + size
            if ext == 16:                              # application_layer_protocol_negotiation
                j, stop = 2, 2 + struct.unpack_from("!H", data, 0)[0]
                while j < stop and j + 1 + data[j] <= len(data):
                    alpn.append(_printable(data[j + 1:j + 1 + data[j]]))
                    j += 1 + data[j]
            elif ext == 0 and len(data) > 5:           # server_name, one host_name
                sni = _printable(data[5:5 + struct.unpack_from("!H", data, 3)[0]])
    except (IndexError, struct.error):
        return None
    return tuple(alpn), sni, n


def _printable(raw: bytes) -> str:
    """Anyone can forge an Initial: keep only printable ASCII before it reaches a report."""
    return "".join(chr(c) if 0x20 <= c < 0x7F else "?" for c in raw)


def _reassemble(chunks: List[Tuple[int, bytes]]) -> bytes:
    """The contiguous CRYPTO stream from offset 0; retransmissions may split it differently."""
    buf = b""
    for off, data in sorted(chunks):
        if off > len(buf):
            break
        if off + len(data) > len(buf):
            buf += data[len(buf) - off:]
    return buf


def client_hello(datagrams: List[bytes]) -> Optional[ClientHello]:
    """The ClientHello carried in a client's first datagrams, or None. Keys come from the
    first Initial's DCID and stay fixed for the client's Initials (RFC 9001 §5.2), even
    after it switches to the server's connection id; after a Retry the client derives them
    again from the new DCID, which the packet carries. A packet that opens with neither is
    skipped (the server's Initials, or another connection on the same 5-tuple)."""
    first_keys = None
    chunks: List[Tuple[int, bytes]] = []
    for k, d in enumerate(datagrams, 1):
        if len(d) < MIN_CLIENT_DATAGRAM:
            continue
        for h in initial_packets(d):
            own = client_initial_keys(h.dcid)
            first_keys = first_keys or own
            plain = open_initial(d, h, first_keys)
            if plain is None and own != first_keys:
                plain = open_initial(d, h, own)
            if plain is not None:
                chunks += crypto_frames(plain)
        parsed = parse_client_hello(_reassemble(chunks))
        if parsed:
            return ClientHello(parsed[0], parsed[1], parsed[2], k)
    return None
