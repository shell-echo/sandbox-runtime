"""Fixed PBS statement/capture policy. Parsing is never signature verification."""
import base64
import hashlib
import json
import math
import re

CAP = 1 << 20
CASES = ('bad-digest', 'bad-identity', 'bad-issuer', 'bad-predicate',
         'bad-dsse-signature', 'bad-missing-tlog', 'good-normal', 'good-stripped')
IDENTITY = 'https://github.com/astral-sh/python-build-standalone/.github/workflows/release.yml@refs/heads/main'
ISSUER = 'https://token.actions.githubusercontent.com'
PREDICATE = 'https://slsa.dev/provenance/v1'
DIGESTS = {
    'normal': 'd8975d7df4f08f7b1c7aafcdfacbddcec3d366415f2c1a72b2466b6850815933',
    'stripped': '9e01f63bbb08576cd9c8bc2d0564d098cb30c8453a0cd4bcf6aef458f6d2a147'}
NAMES = {kind: 'cpython-3.13.16-aarch64-apple-darwin-install_only' +
         ('_stripped' if kind == 'stripped' else '') + '-20261002T2049.tar.gz'
         for kind in DIGESTS}
BUNDLE_SHA = '2c2bfa522cc32384344b60330e4c4d16ceb4f087358543890ffbaa17484391f8'
ROOT_SHA = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'
EXPECTED_PREDICATE = {
    'buildDefinition': {
        'buildType': 'https://actions.github.io/buildtypes/workflow/v1',
        'externalParameters': {'workflow': {
            'ref': 'refs/heads/main',
            'repository': 'https://github.com/astral-sh/python-build-standalone',
            'path': '.github/workflows/release.yml'}},
        'internalParameters': {'github': {
            'event_name': 'workflow_dispatch', 'repository_id': '162334160',
            'repository_owner_id': '115962839', 'runner_environment': 'self-hosted'}},
        'resolvedDependencies': [{
            'uri': 'git+https://github.com/astral-sh/python-build-standalone@refs/heads/main',
            'digest': {'gitCommit': '5e46737f6480fc315ebfea83866910cbfcc772f0'}}]},
    'runDetails': {'builder': {'id': IDENTITY}, 'metadata': {
        'invocationId': 'https://github.com/astral-sh/python-build-standalone/actions/runs/37118919715/attempts/1'}}}


class Refused(ValueError):
    pass


def need(ok, why):
    if not ok:
        raise Refused(why)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        need(key not in result, 'duplicate JSON key')
        result[key] = value
    return result


def parse(raw):
    need(type(raw) is bytes and 0 < len(raw) <= CAP, 'JSON byte bound')
    try:
        def constant(_):
            raise Refused('nonfinite JSON')
        value = json.loads(raw.decode('utf-8'), object_pairs_hook=_pairs,
                           parse_constant=constant)
        def visit(v, depth=0):
            need(depth <= 32, 'JSON depth')
            if isinstance(v, dict):
                for k, x in v.items():
                    k.encode('utf-8', errors='strict')
                    visit(x, depth + 1)
            elif isinstance(v, list):
                for x in v:
                    visit(x, depth + 1)
            elif isinstance(v, str):
                v.encode('utf-8', errors='strict')
            elif type(v) is float:
                need(math.isfinite(v), 'nonfinite number')
        visit(value)
        return value
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise Refused('strict JSON: ' + str(exc)) from exc


def canonical(value):
    return json.dumps(value, separators=(',', ':'), sort_keys=True,
                      ensure_ascii=False, allow_nan=False).encode('utf-8')


def keys(value, expected):
    need(type(value) is dict and set(value) == set(expected), 'exact object keys')


def b64(text):
    need(type(text) is str and len(text) <= CAP, 'base64 input bound/type')
    try:
        raw = base64.b64decode(text, validate=True)
    except (ValueError, UnicodeError) as exc:
        raise Refused('base64') from exc
    need(0 < len(raw) <= CAP and base64.b64encode(raw).decode('ascii') == text,
         'canonical base64')
    return raw


def bundle(raw, *, missing_log=False):
    value = parse(raw)
    keys(value, ('mediaType', 'verificationMaterial', 'dsseEnvelope'))
    need(value['mediaType'] == 'application/vnd.dev.sigstore.bundle.v0.3+json', 'bundle format')
    vm = value['verificationMaterial']
    keys(vm, ('certificate', 'tlogEntries', 'timestampVerificationData'))
    keys(vm['certificate'], ('rawBytes',))
    cert = b64(vm['certificate']['rawBytes'])
    need(vm['timestampVerificationData'] == {}, 'fixed timestamp material')
    logs = vm['tlogEntries']
    need(type(logs) is list and len(logs) == (0 if missing_log else 1), 'one retained log')
    if logs:
        keys(logs[0], ('logIndex', 'logId', 'kindVersion', 'integratedTime',
                       'inclusionPromise', 'inclusionProof', 'canonicalizedBody'))
        need(logs[0]['kindVersion'] == {'kind': 'dsse', 'version': '0.0.1'}, 'Rekor v1 kind')
        b64(logs[0]['canonicalizedBody'])
    envelope = value['dsseEnvelope']
    keys(envelope, ('payload', 'payloadType', 'signatures'))
    need(envelope['payloadType'] == 'application/vnd.in-toto+json', 'payload type')
    need(type(envelope['signatures']) is list and len(envelope['signatures']) == 1, 'one DSSE signature')
    keys(envelope['signatures'][0], ('sig',))
    b64(envelope['signatures'][0]['sig'])
    payload = b64(envelope['payload'])
    return value, payload, cert


def statement(payload, kind):
    need(kind in DIGESTS, 'selected archive kind')
    value = parse(payload)
    keys(value, ('_type', 'subject', 'predicateType', 'predicate'))
    need(value['_type'] == 'https://in-toto.io/Statement/v1' and
         value['predicateType'] == PREDICATE, 'statement type')
    need(value['predicate'] == EXPECTED_PREDICATE, 'complete fixed provenance')
    subjects = value['subject']
    need(type(subjects) is list and 1 <= len(subjects) <= 1024, 'subject bound')
    matches = []
    all_digests = []
    for item in subjects:
        keys(item, ('name', 'digest'))
        need(type(item['name']) is str and 0 < len(item['name']) <= 4096, 'subject name')
        ds = item['digest']
        need(type(ds) is dict and 1 <= len(ds) <= 32, 'digest bound')
        for alg, val in ds.items():
            need(re.fullmatch('[a-zA-Z0-9_-]{1,64}', alg) is not None and
                 type(val) is str and re.fullmatch('[a-f0-9]{1,256}', val) is not None,
                 'digest shape')
            if alg == 'sha256':
                need(len(val) == 64, 'sha256 length')
            all_digests.append(val)
            if val == DIGESTS[kind]:
                need(alg == 'sha256', 'selected digest algorithm')
                matches.append(item['name'])
    need(matches == [NAMES[kind]], 'unique named digest subject')
    return {'payload_sha256': sha(payload), 'payload_size': len(payload),
            'subjects': len(subjects), 'digests': all_digests,
            'selected_name': NAMES[kind], 'selected_digest': DIGESTS[kind]}


def original(raw, kind):
    need(len(raw) == 223030 and sha(raw) == BUNDLE_SHA, 'original bundle raw bytes')
    _, payload, _ = bundle(raw)
    result = statement(payload, kind)
    need(result['subjects'] == 896 and result['payload_size'] == 159656, 'complete retained statement')
    return result


def variant(raw, case):
    need(case in CASES, 'case name')
    value, _, _ = bundle(raw)
    if case == 'bad-dsse-signature':
        sig = bytearray(b64(value['dsseEnvelope']['signatures'][0]['sig']))
        sig[-1] ^= 1
        value['dsseEnvelope']['signatures'][0]['sig'] = base64.b64encode(sig).decode('ascii')
        return canonical(value)
    if case == 'bad-missing-tlog':
        value['verificationMaterial']['tlogEntries'] = []
        return canonical(value)
    return raw


def parameters(case):
    need(case in CASES, 'case name')
    kind = 'stripped' if case == 'good-stripped' else 'normal'
    digest, identity, issuer, predicate = DIGESTS[kind], IDENTITY, ISSUER, PREDICATE
    if case == 'bad-digest':
        digest = format(int(digest[0], 16) ^ 1, 'x') + digest[1:]
    elif case == 'bad-identity':
        identity = identity.removesuffix('main') + 'diagnostic-denied'
    elif case == 'bad-issuer':
        issuer = 'https://issuer.invalid'
    elif case == 'bad-predicate':
        predicate = 'urn:diagnostic:wrong-predicate'
    return kind, digest, identity, issuer, predicate


def argv(case, input_dir, cosign, profile):
    _, digest, identity, issuer, predicate = parameters(case)
    return ['/usr/bin/sandbox-exec', '-f', str(profile), str(cosign),
            'verify-blob-attestation', '--bundle', str(input_dir / 'bundle.json'),
            '--trusted-root', str(input_dir / 'trusted_root.json'), '--digest', digest,
            '--digestAlg', 'sha256', '--type', predicate,
            '--certificate-identity', identity, '--certificate-oidc-issuer', issuer,
            '--check-claims=true', '--insecure-ignore-sct=false',
            '--insecure-ignore-tlog=false', '--allow-certificate-chain=false']


def frames(san, issuer):
    # Conditional finite source-derived candidates, NOT authenticated cert metadata.
    need(san == IDENTITY and issuer == ISSUER, 'fixed certificate metadata candidate')
    errors = {
        'bad-digest': 'failed to verify signature: provided artifact digest does not match any digest in statement',
        'bad-identity': 'failed to verify certificate identity: no matching CertificateIdentity found, last error: '
                        f'expected SAN value "{parameters("bad-identity")[2]}", got "{san}"',
        'bad-issuer': 'failed to verify certificate identity: no matching CertificateIdentity found, last error: '
                      f'expected issuer value "https://issuer.invalid", got "{issuer}"',
        'bad-predicate': 'invalid predicate type, expected urn:diagnostic:wrong-predicate got ' + PREDICATE,
        'bad-dsse-signature': 'failed to verify log inclusion: transparency log signature does not match',
        'bad-missing-tlog': 'failed to verify log inclusion: not enough verified log entries from transparency log: 0 < 1'}
    return {case: (('Error: ' + errors[case] + '\nerror during command execution: ' + errors[case] + '\n').encode()
                   if case in errors else b'Verified OK\n') for case in CASES}


def capture(receipt, out, err, expected_argv, case, expected_frames):
    keys(receipt, ('name', 'argv', 'exit_code', 'elapsed_seconds', 'limit_seconds',
                   'per_stream_byte_cap', 'received_bytes', 'stored_bytes', 'failure',
                   'timed_out', 'truncated', 'actively_signalled', 'owned_process_reaped'))
    need(case in CASES and receipt['name'] == case and receipt['argv'] == expected_argv, 'same exact command')
    need(type(receipt['limit_seconds']) is int and receipt['limit_seconds'] == 25 and
         type(receipt['per_stream_byte_cap']) is int and receipt['per_stream_byte_cap'] == CAP,
         'original leaf bounds')
    elapsed = receipt.get('elapsed_seconds')
    need(type(elapsed) in (int, float) and math.isfinite(elapsed) and 0 <= elapsed <= 25,
         'actual natural elapsed')
    for key in ('timed_out', 'truncated', 'actively_signalled'):
        need(receipt.get(key) is False, key)
    need(receipt.get('failure') is None and receipt.get('owned_process_reaped') is True,
         'natural reaped capture')
    code = receipt.get('exit_code')
    need(type(code) is int and code == (0 if case.startswith('good-') else 1), 'case exit')
    need(type(out) is bytes and type(err) is bytes and len(out) <= CAP and len(err) <= CAP,
         'raw capture byte bounds')
    expected_counts = {'stdout': len(out), 'stderr': len(err)}
    for label in ('received_bytes', 'stored_bytes'):
        keys(receipt[label], ('stdout', 'stderr'))
        need(all(type(x) is int for x in receipt[label].values()), 'byte counts are integers')
    need(receipt.get('received_bytes') == expected_counts and
         receipt.get('stored_bytes') == expected_counts, 'complete streams')
    need(out == b'' and err == expected_frames[case], 'exact complete output frame')
    return {'case': case, 'provisional_only': True, 'cryptographic_acceptance': False}
