"""Bounded X.509 extension metadata ONLY. Does not authenticate a certificate."""
from policy import CAP, need, sha

SAN = bytes.fromhex('551d11')
ISSUER_V1 = bytes.fromhex('2b0601040183bf300101')
ISSUER_V2 = bytes.fromhex('2b0601040183bf300108')


class Reader:
    def __init__(self, raw):
        need(type(raw) is bytes and 0 < len(raw) <= CAP, 'DER input bound')
        self.nodes = 0

    def items(self, raw, depth=0):
        need(depth <= 32, 'DER depth')
        pos, result = 0, []
        while pos < len(raw):
            self.nodes += 1
            need(self.nodes <= 4096 and pos + 2 <= len(raw), 'DER node/header bound')
            tag, n = raw[pos], raw[pos + 1]
            need(tag & 31 != 31, 'unsupported high tag')
            pos += 2
            if n & 0x80:
                count = n & 0x7f
                need(1 <= count <= 3 and pos + count <= len(raw), 'definite bounded DER length')
                need(raw[pos] != 0, 'minimal DER length')
                n = int.from_bytes(raw[pos:pos + count], 'big')
                need(n >= 128, 'minimal long DER length')
                pos += count
            need(pos + n <= len(raw), 'truncated DER value')
            value = raw[pos:pos + n]
            pos += n
            if tag & 0x20:
                children = self.items(value, depth + 1)
            else:
                children = None
            result.append((tag, value, children))
        return result

    def one(self, raw, tag):
        items = self.items(raw)
        need(len(items) == 1 and items[0][0] == tag, 'single exact DER tag')
        return items[0]


def certificate_metadata(raw):
    r = Reader(raw)
    outer = r.one(raw, 0x30)[2]
    need(len(outer) == 3 and [x[0] for x in outer] == [0x30, 0x30, 0x03], 'Certificate shape')
    tbs = outer[0][2]
    need(len(tbs) == 8 and [x[0] for x in tbs] == [0xa0, 0x02, 0x30, 0x30, 0x30, 0x30, 0x30, 0xa3],
         'fixed v3 TBSCertificate shape')
    need(tbs[0][2] == [(0x02, b'\x02', None)], 'v3 version')
    ext_container = tbs[-1][2]
    need(len(ext_container) == 1 and ext_container[0][0] == 0x30, 'EXPLICIT extensions')
    values = {}
    for ext in ext_container[0][2]:
        need(ext[0] == 0x30, 'Extension sequence')
        fields = ext[2]
        need(len(fields) in (2, 3) and fields[0][0] == 0x06 and fields[-1][0] == 0x04,
             'Extension OID/value')
        if len(fields) == 3:
            need(fields[1][0] == 0x01 and fields[1][1] == b'\xff', 'canonical critical BOOLEAN')
        oid = fields[0][1]
        need(oid not in values, 'duplicate extension OID')
        values[oid] = fields[-1][1]
    need(SAN in values and (ISSUER_V1 in values or ISSUER_V2 in values), 'SAN/OIDC issuer required')
    names = r.one(values[SAN], 0x30)[2]
    need(len(names) == 1 and names[0][0] == 0x86, 'single URI SAN only')
    try:
        san = names[0][1].decode('ascii')
        issuers = []
        if ISSUER_V1 in values:
            issuers.append(values[ISSUER_V1].decode('utf-8'))
        if ISSUER_V2 in values:
            issuers.append(r.one(values[ISSUER_V2], 0x0c)[1].decode('utf-8'))
    except UnicodeError as exc:
        raise ValueError('strict certificate metadata encoding') from exc
    need(san.startswith('https://') and all(x == issuers[0] for x in issuers) and
         issuers[0].startswith('https://') and
         not any(ord(c) < 32 or ord(c) == 127 for c in san + issuers[0]), 'metadata URI/conflict')
    return {'certificate_der_sha256': sha(raw), 'certificate_der_size': len(raw),
            'san': san, 'oidc_issuer': issuers[0], 'authenticated': False,
            'sigstore_summary_equivalence': False}
