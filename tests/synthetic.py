"""Write a synthetic pcap with the shapes the rules look for, so the analysis can be
checked without a cluster. Not a substitute for a capture: the sizes here are the
source-derived predictions, which the real capture is meant to test.

    python3 -m tests.synthetic out.pcap
    python3 -m analysis.classify out.pcap
"""

from __future__ import annotations

import random
import socket
import struct
import sys

ETH = 1


class Writer:
    def __init__(self, path):
        self.f = open(path, "wb")
        self.f.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, ETH))

    def frame(self, t: float, buf: bytes):
        s, us = int(t), int((t - int(t)) * 1e6)
        self.f.write(struct.pack("<IIII", s, us, len(buf), len(buf)) + buf)

    def close(self):
        self.f.close()


def mac(i: int) -> bytes:
    return bytes([2, 0, 0, 0, 0, i])


def ip4(src, dst, proto, payload):
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), 0, 0, 64, proto, 0,
                      socket.inet_aton(src), socket.inet_aton(dst))
    return hdr + payload


def ip6(src, dst, nxt, payload):
    return struct.pack("!IHBB16s16s", 0x60000000, len(payload), nxt, 64,
                       socket.inet_pton(socket.AF_INET6, src), socket.inet_pton(socket.AF_INET6, dst)) + payload


def tcp(sport, dport, payload, flags=0x18):
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, 5 << 4, flags, 65535, 0, 0) + payload


def udp(sport, dport, payload):
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def eth(src_i, dst_i, ethertype, body):
    return mac(dst_i) + mac(src_i) + struct.pack("!H", ethertype) + body


def main(path: str) -> None:
    w = Writer(path)
    rng = random.Random(0)
    t0 = 1_700_000_000.0
    # exo: three nodes beacon once a second over IPv6 multicast; 1 Hz JSON on 52414; 5 s heartbeat
    nodes6 = ["fd00::1", "fd00::2", "fd00::3"]
    for k in range(120):
        for i, n in enumerate(nodes6):
            t = t0 + k + i * 0.01 + rng.uniform(0, 0.005)
            hello = b"EXO\x00" + rng.randbytes(8) + b"\x11" * 8
            w.frame(t, eth(i + 1, 0x33, 0x86DD, ip6(n, "ff12::e0a1:de89", 17, udp(52413, 52413, hello))))
            if i:
                reply = b"EXO\x01" + hello[4:12] + b"\x22" * 16 + struct.pack("<H", 52414)
                w.frame(t + 0.002, eth(1, i + 1, 0x86DD, ip6(nodes6[0], n, 17, udp(52413, 52413, reply))))
                info = b'{"type":"NodeGatheredInfo","memory":' + str(rng.randint(10**9, 2 * 10**9)).encode() + b"}" * 1
                w.frame(t + 0.05, eth(i + 1, 1, 0x86DD, ip6(n, nodes6[0], 6, tcp(40000 + i, 52414, b"topics/local_events" + info))))
                if k % 5 == 0:
                    w.frame(t + 0.07, eth(1, i + 1, 0x86DD, ip6(nodes6[0], n, 6, tcp(52414, 40000 + i, b'{"heartbeat":true,"clock":' + str(k).encode() + b"}"))))
    # llama.cpp: main host 10.0.0.1 to rpc hosts .2 and .3 on 50052; HELLO then per-token star exchanges
    hello_c = bytes([0x0E]) + struct.pack("<Q", 24) + bytes(24)
    hello_s = struct.pack("<Q", 28) + bytes([8, 0, 1, 0]) + bytes(24)
    for j, host in enumerate(("10.0.0.2", "10.0.0.3")):
        w.frame(t0 + 10 + j * 0.01, eth(10, 11 + j, 0x0800, ip4("10.0.0.1", host, 6, tcp(5000 + j, 50052, hello_c))))
        w.frame(t0 + 10.001 + j * 0.01, eth(11 + j, 10, 0x0800, ip4(host, "10.0.0.1", 6, tcp(50052, 5000 + j, hello_s))))
        # a weight upload: SET_TENSOR frames with readable names
        for n in range(5):
            name = f"blk.{n}.attn_q.weight".encode().ljust(64, b"\0")
            frame = bytes([6]) + struct.pack("<Q", 312 + 1400) + bytes(8) + name + bytes(296 - 72 - 8) + bytes(10) + rng.randbytes(1400)
            w.frame(t0 + 11 + j + n * 0.01, eth(10, 11 + j, 0x0800, ip4("10.0.0.1", host, 6, tcp(5000 + j, 50052, frame[:1400]))))
    for tok in range(60):                      # 60 tokens at 26 ms
        t = t0 + 30 + tok * 0.026
        # host A: 4 KiB in, 4 KiB out; host B: 4 KiB in, 600 KB out (logits), as 1448-byte segments
        for j, host, back in ((0, "10.0.0.2", 4096), (1, "10.0.0.3", 600_000)):
            inp = bytes([6]) + struct.pack("<Q", 312 + 4096) + bytes(312) + bytes(4096)
            off = 0
            while off < len(inp):
                w.frame(t + j * 0.01 + off / 1e9, eth(10, 11 + j, 0x0800, ip4("10.0.0.1", host, 6, tcp(5000 + j, 50052, inp[off:off + 1448]))))
                off += 1448
            w.frame(t + j * 0.01 + 0.001, eth(10, 11 + j, 0x0800, ip4("10.0.0.1", host, 6, tcp(5000 + j, 50052, bytes([16]) + struct.pack("<Q", 12) + bytes(12)))))
            w.frame(t + j * 0.01 + 0.002, eth(10, 11 + j, 0x0800, ip4("10.0.0.1", host, 6, tcp(5000 + j, 50052, bytes([8]) + struct.pack("<Q", 312) + bytes(312)))))
            resp = struct.pack("<Q", back) + bytes(back)
            off = 0
            while off < len(resp):
                w.frame(t + j * 0.01 + 0.004 + off / 1e8, eth(11 + j, 10, 0x0800, ip4(host, "10.0.0.1", 6, tcp(50052, 5000 + j, resp[off:off + 1448]))))
                off += 1448
    # libp2p: multistream handshake then encrypted-looking bytes
    w.frame(t0 + 40, eth(20, 21, 0x0800, ip4("10.0.1.1", "10.0.1.2", 6, tcp(6000, 4001, b"\x13/multistream/1.0.0\n\x07/noise\n"))))
    for k in range(200):
        w.frame(t0 + 41 + k * 0.5, eth(20, 21, 0x0800, ip4("10.0.1.1", "10.0.1.2", 6, tcp(6000, 4001, rng.randbytes(rng.randint(60, 200))))))
    # background: a video-like stream (fixed 1316-byte UDP at 30 ms) and an ordinary mDNS query
    for k in range(1000):
        w.frame(t0 + 50 + k * 0.03, eth(30, 31, 0x0800, ip4("10.0.2.1", "10.0.2.2", 17, udp(5004, 5004, bytes(1316)))))
    q = b"\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x05_http\x04_tcp\x05local\x00\x00\x0c\x00\x01"
    for k in range(10):
        w.frame(t0 + 60 + k * 10, eth(31, 0x33, 0x0800, ip4("10.0.2.2", "224.0.0.251", 17, udp(5353, 5353, q))))
    # LocalAI: a short mDNS query, then answers whose TXT record carries a libp2p multiaddr
    # past the first 64 payload bytes (the real one is at offset 183)
    w.frame(t0 + 70, eth(40, 0x33, 0x0800, ip4("10.0.3.1", "224.0.0.251", 17, udp(5353, 5353, q))))
    for k in range(5):
        ans = (b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x01" + bytes(170)
               + b"Ydnsaddr=/ip4/10.0.3.1/udp/4001/quic-v1/p2p/12D3KooW" + rng.randbytes(40))
        w.frame(t0 + 71 + k * 23.3, eth(40, 0x33, 0x0800, ip4("10.0.3.1", "224.0.0.251", 17, udp(5353, 5353, ans))))
    w.close()


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "synthetic.pcap")
