import base64
import copy
import json
from pathlib import Path
import unittest
from unittest.mock import patch

import policy as p


def fixture():
    subjects = [{'name': p.NAMES[k], 'digest': {'sha256': v}} for k, v in p.DIGESTS.items()]
    subjects += [{'name': 'other-' + str(n), 'digest': {'sha256': format(n, '064x')}} for n in range(894)]
    statement = {'_type': 'https://in-toto.io/Statement/v1', 'subject': subjects,
                 'predicateType': p.PREDICATE, 'predicate': copy.deepcopy(p.EXPECTED_PREDICATE)}
    value = {'mediaType': 'application/vnd.dev.sigstore.bundle.v0.3+json',
             'verificationMaterial': {'certificate': {'rawBytes': 'Y2VydA=='},
                'timestampVerificationData': {}, 'tlogEntries': [{
                    'logIndex': '1', 'logId': {}, 'kindVersion': {'kind': 'dsse', 'version': '0.0.1'},
                    'integratedTime': '1', 'inclusionPromise': {}, 'inclusionProof': {},
                    'canonicalizedBody': 'bG9n'}]},
             'dsseEnvelope': {'payload': base64.b64encode(p.canonical(statement)).decode(),
                              'payloadType': 'application/vnd.in-toto+json', 'signatures': [{'sig': 'c2ln'}]}}
    return statement, value


def receipt(case, args, err):
    return {'name': case, 'argv': args, 'exit_code': 0 if case.startswith('good-') else 1,
            'elapsed_seconds': .1, 'limit_seconds': 25, 'per_stream_byte_cap': p.CAP,
            'received_bytes': {'stdout': 0, 'stderr': len(err)},
            'stored_bytes': {'stdout': 0, 'stderr': len(err)}, 'failure': None,
            'timed_out': False, 'truncated': False, 'actively_signalled': False,
            'owned_process_reaped': True}


class StrictJSON(unittest.TestCase):
    def test_canonical_positive(self):
        self.assertEqual(p.parse(b'{"x":[1,true,"ok"]}'), {'x': [1, True, 'ok']})

    def test_refusals(self):
        for raw in [b'{"a":1,"a":2}', b'NaN', b'Infinity', b'1e999', b'"\xff"',
                    b'"\\ud800"', b'{} trailing', b'[' * 34 + b'0' + b']' * 34,
                    b' ' * (p.CAP + 1), b'', b'0' * 5000]:
            with self.subTest(raw=raw[:24]), self.assertRaises(p.Refused):
                p.parse(raw)

    def test_base64_refusals(self):
        for value in ['', 'YQ', 'YR==', 'YQ===', 'YQ==\n', '\u0100', 1, True]:
            with self.subTest(value=value), self.assertRaises(p.Refused):
                p.b64(value)


class Provenance(unittest.TestCase):
    def setUp(self):
        self.statement, self.bundle = fixture()

    def test_full_subject_list_both_named_digests(self):
        for kind in p.DIGESTS:
            actual = p.statement(p.canonical(self.statement), kind)
            self.assertEqual(actual['subjects'], 896)
            self.assertEqual(len(actual['digests']), 896)
            self.assertEqual(actual['selected_name'], p.NAMES[kind])

    def test_every_provenance_edge_refuses(self):
        paths = [
            ['buildDefinition', 'buildType'],
            ['buildDefinition', 'externalParameters', 'workflow', 'ref'],
            ['buildDefinition', 'externalParameters', 'workflow', 'repository'],
            ['buildDefinition', 'externalParameters', 'workflow', 'path'],
            ['buildDefinition', 'internalParameters', 'github', 'repository_id'],
            ['buildDefinition', 'internalParameters', 'github', 'repository_owner_id'],
            ['buildDefinition', 'internalParameters', 'github', 'event_name'],
            ['buildDefinition', 'internalParameters', 'github', 'runner_environment'],
            ['buildDefinition', 'resolvedDependencies', 0, 'uri'],
            ['buildDefinition', 'resolvedDependencies', 0, 'digest', 'gitCommit'],
            ['runDetails', 'builder', 'id'], ['runDetails', 'metadata', 'invocationId']]
        for path in paths:
            value = copy.deepcopy(self.statement)
            obj = value['predicate']
            for key in path[:-1]:
                obj = obj[key]
            obj[path[-1]] = 'wrong'
            with self.subTest(path=path), self.assertRaises(p.Refused):
                p.statement(p.canonical(value), 'normal')

    def test_wrong_absent_duplicate_named_subject(self):
        variants = []
        v = copy.deepcopy(self.statement); v['subject'][0]['name'] = 'wrong'; variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'].pop(0); variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'].append(v['subject'][0]); variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'][0]['digest'] = {'sha512': p.DIGESTS['normal']}; variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'][-1]['digest'] = {'sha256': True}; variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'][-1]['extra'] = 1; variants.append(v)
        v = copy.deepcopy(self.statement); v['subject'] = v['subject'] * 2; variants.append(v)
        v = copy.deepcopy(self.statement); v['predicateType'] = 'wrong'; variants.append(v)
        for n, value in enumerate(variants):
            with self.subTest(n=n), self.assertRaises(p.Refused):
                p.statement(p.canonical(value), 'normal')

    def test_raw_original_hash_not_semantics(self):
        raw = p.canonical(self.bundle)
        with self.assertRaises(p.Refused):
            p.original(raw, 'normal')

    def test_bundle_shape_refusals(self):
        for change in ['extra', 'format', 'payload', 'signatures', 'logs', 'timestamp']:
            value = copy.deepcopy(self.bundle)
            if change == 'extra': value['extra'] = 1
            if change == 'format': value['mediaType'] = 'application/vnd.dev.sigstore.bundle.v0.2+json'
            if change == 'payload': value['dsseEnvelope']['payload'] += '\n'
            if change == 'signatures': value['dsseEnvelope']['signatures'] *= 2
            if change == 'logs': value['verificationMaterial']['tlogEntries'] = []
            if change == 'timestamp': value['verificationMaterial']['timestampVerificationData'] = {'x': []}
            with self.subTest(change=change), self.assertRaises(p.Refused):
                p.bundle(p.canonical(value))

    def test_exact_mutations(self):
        raw = json.dumps(self.bundle, indent=2).encode()
        for case in p.CASES:
            actual = p.variant(raw, case)
            expected = copy.deepcopy(self.bundle)
            if case == 'bad-missing-tlog':
                expected['verificationMaterial']['tlogEntries'] = []
            elif case == 'bad-dsse-signature':
                expected['dsseEnvelope']['signatures'][0]['sig'] = 'c2lm'
            else:
                self.assertEqual(actual, raw)
            self.assertEqual(p.parse(actual), expected)
        self.assertEqual(p.parameters('bad-identity')[2], p.IDENTITY.removesuffix('main') + 'diagnostic-denied')
        self.assertNotEqual(p.parameters('bad-digest')[1], p.DIGESTS['normal'])


class CaptureFrames(unittest.TestCase):
    def test_all_eight_exact_candidate_frames(self):
        frames = p.frames(p.IDENTITY, p.ISSUER)
        for case in p.CASES:
            args = p.argv(case, Path('/private/input'), '/cosign', '/deny.sb')
            result = p.capture(receipt(case, args, frames[case]), b'', frames[case], args, case, frames)
            self.assertFalse(result['cryptographic_acceptance'])
            self.assertTrue(result['provisional_only'])

    def test_complete_literal_digest_and_predicate(self):
        frames = p.frames(p.IDENTITY, p.ISSUER)
        payload = b'failed to verify signature: provided artifact digest does not match any digest in statement'
        self.assertEqual(frames['bad-digest'], b'Error: ' + payload + b'\nerror during command execution: ' + payload + b'\n')
        self.assertEqual(frames['good-normal'], b'Verified OK\n')

    def test_every_receipt_missing_field(self):
        err = p.frames(p.IDENTITY, p.ISSUER)['bad-digest']
        for key in receipt('bad-digest', ['fixed'], err):
            value = receipt('bad-digest', ['fixed'], err); value.pop(key)
            with self.subTest(key=key), self.assertRaises(p.Refused):
                p.capture(value, b'', err, ['fixed'], 'bad-digest', p.frames(p.IDENTITY, p.ISSUER))

    def test_flags_bounds_argv_and_exit(self):
        frames = p.frames(p.IDENTITY, p.ISSUER); err = frames['bad-digest']
        changes = {'timed_out': True, 'actively_signalled': True, 'truncated': True,
                   'owned_process_reaped': False, 'failure': 'network failed', 'exit_code': 0,
                   'limit_seconds': 26, 'per_stream_byte_cap': p.CAP + 1,
                   'elapsed_seconds': float('nan'), 'argv': ['other'], 'name': 'other',
                   'received_bytes': {'stdout': 0, 'stderr': 0}}
        for key, bad in changes.items():
            value = receipt('bad-digest', ['fixed'], err); value[key] = bad
            with self.subTest(key=key), self.assertRaises(p.Refused):
                p.capture(value, b'', err, ['fixed'], 'bad-digest', frames)

    def test_unknown_warning_timestamp_wrong_stream_and_partial(self):
        frames = p.frames(p.IDENTITY, p.ISSUER)
        for case in p.CASES:
            err = frames[case]
            for out, wrong in [(b'', err + b'\n'), (b'', b'warning\n' + err),
                               (b'', err[:-1]), (err, b''), (b'', b'network failure\n'),
                               (b'', b'2026/10/21 ' + err), (b'', err.replace(b'Error:', b'ERROR:'))]:
                if out == b'' and wrong == err:
                    continue
                value = receipt(case, ['fixed'], wrong)
                value['received_bytes']['stdout'] = len(out)
                value['stored_bytes']['stdout'] = len(out)
                with self.subTest(case=case, wrong=wrong[:20]), self.assertRaises(p.Refused):
                    p.capture(value, out, wrong, ['fixed'], case, frames)


if __name__ == '__main__':
    unittest.main()
