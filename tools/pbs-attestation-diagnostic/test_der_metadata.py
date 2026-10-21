import unittest

from der_metadata import Reader, certificate_metadata, SAN, ISSUER_V1, ISSUER_V2
from policy import IDENTITY, ISSUER


def tlv(tag, raw):
    n = len(raw)
    length = bytes([n]) if n < 128 else bytes([0x80 | ((n.bit_length() + 7) // 8)]) + n.to_bytes((n.bit_length() + 7) // 8, 'big')
    return bytes([tag]) + length + raw


def extension(oid, raw):
    return tlv(0x30, tlv(0x06, oid) + tlv(0x04, raw))


def cert(*, names=None, v1=ISSUER, v2=None, extra=b''):
    san = tlv(0x30, tlv(0x86, IDENTITY.encode()) if names is None else names)
    extensions = extension(SAN, san)
    if v1 is not None: extensions += extension(ISSUER_V1, v1.encode())
    if v2 is not None: extensions += extension(ISSUER_V2, tlv(0x0c, v2.encode()))
    tbs = tlv(0xa0, tlv(0x02, b'\x02')) + tlv(0x02, b'\x01')
    tbs += tlv(0x30, b'') * 5 + tlv(0xa3, tlv(0x30, extensions + extra))
    return tlv(0x30, tlv(0x30, tbs) + tlv(0x30, b'') + tlv(0x03, b'\x00'))


class MetadataOnly(unittest.TestCase):
    def test_v1_v2_and_agreement(self):
        for raw in [cert(), cert(v1=None, v2=ISSUER), cert(v2=ISSUER)]:
            got = certificate_metadata(raw)
            self.assertEqual((got['san'], got['oidc_issuer']), (IDENTITY, ISSUER))
            self.assertFalse(got['authenticated'])
            self.assertFalse(got['sigstore_summary_equivalence'])

    def test_truncations_every_byte(self):
        raw = cert()
        for n in range(len(raw)):
            with self.subTest(n=n), self.assertRaises(ValueError):
                certificate_metadata(raw[:n])

    def test_nonminimal_indefinite_trailing_and_tags(self):
        for raw in [b'\x30\x80\x00\x00', b'\x30\x81\x00', b'\x30\x82\x00\x80' + b'\x00' * 128,
                    cert() + b'\x00', b'\x31' + cert()[1:], b'\x30\xff', b'\x1f\x00']:
            with self.subTest(raw=raw[:6]), self.assertRaises(ValueError):
                certificate_metadata(raw)

    def test_san_issuer_duplicates_conflicts_encodings(self):
        cases = [cert(names=tlv(0x82, b'wrong')), cert(names=tlv(0x86, IDENTITY.encode()) * 2),
                 cert(names=tlv(0x86, b'https://\xff')), cert(v2='https://other.invalid'),
                 cert(extra=extension(SAN, tlv(0x30, tlv(0x86, IDENTITY.encode())))),
                 cert(extra=extension(ISSUER_V1, ISSUER.encode())), cert(v1='not-a-uri'),
                 cert(v1=None), cert(extra=tlv(0x30, tlv(0x06, b'x') + tlv(0x01, b'\x00') + tlv(0x04, b'')))]
        for n, raw in enumerate(cases):
            with self.subTest(n=n), self.assertRaises(ValueError):
                certificate_metadata(raw)

    def test_depth_and_node_limits(self):
        raw = b'\x05\x00'
        for _ in range(34): raw = tlv(0x30, raw)
        for data in [raw, b'\x05\x00' * 4097]:
            with self.assertRaises(ValueError): Reader(data).items(data)


if __name__ == '__main__':
    unittest.main()
