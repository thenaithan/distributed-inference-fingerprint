"""analysis/quic.py against published vectors, then round trips through tests/quicgen.py.

    python3 -m unittest tests.test_quic
"""

import unittest

from analysis import quic
from tests import quicgen

H = bytes.fromhex


class Vectors(unittest.TestCase):
    def test_aes_fips197_c1(self):
        rk = quic.expand_key(H("000102030405060708090a0b0c0d0e0f"))
        self.assertEqual(quic.aes_block(rk, H("00112233445566778899aabbccddeeff")).hex(),
                         "69c4e0d86a7b0430d8cdb78070b4c55a")

    # McGrew and Viega, "The Galois/Counter Mode of Operation", test cases 3 and 4
    GCM_KEY = H("feffe9928665731c6d6a8f9467308308")
    GCM_IV = H("cafebabefacedbaddecaf888")
    GCM_P = H("d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a72"
              "1c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b391aafd255")
    GCM_C = H("42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e"
              "21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091473f5985")

    def test_gcm_case3(self):
        sealed = quic.gcm_seal(self.GCM_KEY, self.GCM_IV, self.GCM_P, b"")
        self.assertEqual(sealed, self.GCM_C + H("4d5c2af327cd64a62cf35abd2ba6fab4"))
        self.assertEqual(quic.gcm_open(self.GCM_KEY, self.GCM_IV, sealed, b""), self.GCM_P)

    def test_gcm_case4_with_aad(self):
        aad = H("feedfacedeadbeeffeedfacedeadbeefabaddad2")
        sealed = quic.gcm_seal(self.GCM_KEY, self.GCM_IV, self.GCM_P[:60], aad)
        self.assertEqual(sealed, self.GCM_C[:60] + H("5bc94fbc3221a5db94fae95ae7121a47"))
        self.assertIsNone(quic.gcm_open(self.GCM_KEY, self.GCM_IV, sealed, aad[:-1]))

    def test_rfc9001_a1_client_keys(self):
        k = quic.client_initial_keys(H("8394c8f03e515708"))
        self.assertEqual((k.key.hex(), k.iv.hex(), k.hp.hex()),
                         ("1f369613dd76d5467730efcbe3b1a22d", "fa044b2f42a3fd3b46fb255c",
                          "9f50449e04a0e810283a1e9933adedd2"))

    def test_rfc9001_a2_header_protection_mask(self):
        rk = quic.expand_key(H("9f50449e04a0e810283a1e9933adedd2"))
        self.assertEqual(quic.aes_block(rk, H("d1b1c98dd7689fb8ec11d242b123dc9b"))[:5].hex(), "437b9aec36")


class RoundTrip(unittest.TestCase):
    DCID = H("8394c8f03e515708")

    def test_libp2p_hello_over_two_initials(self):
        hello = quicgen.client_hello(["libp2p"])
        dgrams = quicgen.initials(hello, self.DCID)
        self.assertEqual(len(dgrams), 2)
        self.assertTrue(all(len(d) == quic.MIN_CLIENT_DATAGRAM for d in dgrams))
        self.assertIsNone(quic.client_hello(dgrams[:1]))          # incomplete after one
        ch = quic.client_hello(dgrams)
        self.assertEqual((ch.alpn, ch.sni, ch.length, ch.datagrams), (("libp2p",), None, len(hello) - 4, 2))

    def test_sni_and_single_initial(self):
        ch = quic.client_hello(quicgen.initials(quicgen.client_hello(["h3"], "example.com", key_share=32), self.DCID))
        self.assertEqual((ch.alpn, ch.sni, ch.datagrams), (("h3",), "example.com", 1))

    def test_tampered_or_short_or_not_quic(self):
        dgrams = quicgen.initials(quicgen.client_hello(["libp2p"]), self.DCID)
        bad = bytearray(dgrams[0])
        bad[100] ^= 1
        self.assertIsNone(quic.client_hello([bytes(bad), dgrams[1]]))
        self.assertIsNone(quic.client_hello([d[:1199] for d in dgrams]))
        self.assertIsNone(quic.client_hello([bytes(1300), b"\xff" * 1300]))

    def test_retransmit_split_differently(self):
        hello = quicgen.client_hello(["libp2p"])
        first = quicgen.initials(hello, self.DCID, chunk=700)[0]       # offset 0, 700 bytes
        again = quicgen.initials(hello, self.DCID, chunk=1100)          # offsets 0 and 1100
        self.assertEqual(quic.client_hello([first] + again).alpn, ("libp2p",))

    def test_after_retry_new_dcid(self):
        hello = quicgen.client_hello(["libp2p"])
        partial = quicgen.initials(hello, self.DCID)[0]
        retried = quicgen.initials(hello, H("0011223344556677"))
        self.assertEqual(quic.client_hello([partial] + retried).datagrams, 3)

    def test_undecryptable_packet_skipped(self):
        dgrams = quicgen.initials(quicgen.client_hello(["libp2p"]), self.DCID)
        bad = bytearray(dgrams[1])
        bad[100] ^= 1                                  # fails the tag, as a server's Initial would
        self.assertEqual(quic.client_hello([dgrams[0], bytes(bad), dgrams[1]]).alpn, ("libp2p",))

    def test_forged_sni_is_printable(self):
        ch = quic.client_hello(quicgen.initials(quicgen.client_hello(["libp2p"], "a\nb\x1b", key_share=32), self.DCID))
        self.assertEqual(ch.sni, "a?b?")

    def test_other_keys_do_not_open(self):
        d = quicgen.initials(quicgen.client_hello(["libp2p"]), self.DCID)[0]
        h = next(quic.initial_packets(d))
        self.assertIsNotNone(quic.open_initial(d, h, quic.client_initial_keys(self.DCID)))
        self.assertIsNone(quic.open_initial(d, h, quic.client_initial_keys(b"\0" * 8)))

    def test_varint(self):
        for v in (0, 63, 64, 16383, 16384, 2 ** 30 - 1, 2 ** 30):
            enc = quic.encode_varint(v)
            self.assertEqual(quic._varint(enc, 0), (v, len(enc)))


if __name__ == "__main__":
    unittest.main()
