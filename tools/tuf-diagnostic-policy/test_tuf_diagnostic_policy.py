"""Independent synthetic literals and refusal cases; never invokes any tool."""
import unittest

import tuf_diagnostic_policy as p

MIRROR = 'file:///synthetic-run/case/mirror'
ARGV = ['/usr/bin/sandbox-exec', '-f', '/synthetic/profile.sb',
        '/synthetic/cosign', 'initialize', '--mirror', MIRROR]
# Gold strings are intentionally independent of the module's constructors/constants.
WARNINGS = (
    'WARNING: Could not fetch signing_config.json from the TUF mirror (encountered error: '
    'failed to load metadata: tuf refresh failed: Get "file:///synthetic-run/case/mirror/15.root.json": '
    'unsupported protocol scheme "file"). It is recommended to use a signing config file rather than provide service URLs when signing.\n'
    'WARNING: Could not fetch trusted_root.json from the TUF mirror (encountered error: '
    'failed to create TUF client failed to load metadata: tuf refresh failed: Get "file:///synthetic-run/case/mirror/15.root.json": '
    'unsupported protocol scheme "file"), falling back to individual targets. It is recommended to update your TUF metadata repository to include trusted_root.json.\n'
)
PAYLOADS = {
    'bad-root13': 'updating local metadata and targets: error updating to TUF remote mirror: tuf: valid signatures did not meet threshold',
    'bad-timestamp': 'updating local metadata and targets: error updating to TUF remote mirror: tuf: failed to decode timestamp.json: tuf: valid signatures did not meet threshold',
    'bad-target': 'updating local metadata and targets: downloading target: tuf: failed to download trusted_root.json: wrong sha256 hash, expected '
                  '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66 got '
                  '89798404182843a00037e10a50ba95597b4d66c78b921f90909d2ce1a620fab0',
}
EXPECTED = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'
ACTUAL = '89798404182843a00037e10a50ba95597b4d66c78b921f90909d2ce1a620fab0'


def frame(case):
    text = WARNINGS
    if case != 'good':
        message = PAYLOADS[case]
        text += 'Error: ' + message + '\nerror during command execution: ' + message + '\n'
    return text.encode()


def receipt(case='bad-root13', out=b'', err=None):
    if err is None:
        err = frame(case)
    return {'name': 'chain-' + case, 'argv': list(ARGV), 'exit_code': 0 if case == 'good' else 1,
            'elapsed_seconds': 0.5, 'limit_seconds': 25, 'per_stream_byte_cap': 1048576,
            'received_bytes': {'stdout': len(out), 'stderr': len(err)},
            'stored_bytes': {'stdout': len(out), 'stderr': len(err)}, 'failure': None,
            'timed_out': False, 'truncated': False, 'actively_signalled': False,
            'owned_process_reaped': True}


class CapturePolicyTests(unittest.TestCase):
    def test_no_import_side_effect_or_authentication_verdict(self):
        self.assertEqual(p.CASES, ('bad-root13', 'bad-timestamp', 'bad-target', 'good'))
        self.assertEqual((p.CHILD_SECONDS, p.STREAM_CAP), (25, 1048576))
        self.assertEqual(dict(p.ERROR_PAYLOADS), PAYLOADS)
        with self.assertRaises(TypeError):
            p.ERROR_PAYLOADS['bad-root13'] = 'changed'


def add_test(name, action):
    def method(self):
        action(self)
    method.__name__ = 'test_' + name
    setattr(CapturePolicyTests, method.__name__, method)


for case in ('bad-root13', 'bad-timestamp', 'bad-target', 'good'):
    def positive(self, case=case):
        value = p.validate_capture(receipt(case), b'', frame(case), MIRROR, case, list(ARGV))
        self.assertEqual(value, {'expected_modern_file_warnings': 2, 'legacy_case': case,
                                'format_match_only': True, 'authentication_checked': False,
                                'negative_provisional': case != 'good', 'natural_bounded_capture': True})
    add_test('fixed_frame_' + case.replace('-', '_'), positive)


BAD_FRAMES = {
    'missing_cobra_line': lambda b: b.replace(('Error: ' + PAYLOADS['bad-target'] + '\n').encode(), b''),
    'missing_final_line': lambda b: b[:b.rfind(b'error during command execution:')],
    'extra_line': lambda b: b + b'ignored\n',
    'extra_blank': lambda b: b + b'\n',
    'no_final_LF': lambda b: b[:-1],
    'CRLF': lambda b: b.replace(b'\n', b'\r\n'),
    'NUL': lambda b: b.replace(b'Error: ', b'Error: \0'),
    'invalid_UTF8': lambda b: b'\xff' + b[1:],
    'unicode_line_separator': lambda b: b.replace(b'\n', '\u2028'.encode(), 1),
    'swapped_warnings': lambda b: b'\n'.join([b.split(b'\n')[1], b.split(b'\n')[0], *b.split(b'\n')[2:]]),
    'duplicated_warning': lambda b: b.split(b'\n')[0] + b'\n' + b.split(b'\n')[0] + b'\n' + b.split(b'\n', 2)[2],
    'warning1_wrong_role': lambda b: b.replace(b'fetch signing_config.json', b'fetch root.json', 1),
    'warning2_wrong_role': lambda b: b.replace(b'fetch trusted_root.json', b'fetch root.json', 1),
    'warning1_uses_warning2_wrapper': lambda b: b.replace(b'failed to load metadata:', b'failed to create TUF client failed to load metadata:', 1),
    'warning2_loses_own_wrapper': lambda b: b.replace(b'failed to create TUF client ', b''),
    'wrong_fetch_wrapper': lambda b: b.replace(b'failed to load metadata:', b'failed to download metadata:'),
    'different_file_mirror': lambda b: b.replace(MIRROR.encode(), b'file:///unreviewed/mirror'),
    'mirror_prefix_child': lambda b: b.replace(b'/mirror/15.root.json', b'/mirror/child/15.root.json'),
    'wrong_root_version': lambda b: b.replace(b'/15.root.json', b'/13.root.json'),
    'HTTP_warning': lambda b: b.replace(MIRROR.encode(), b'https://unreviewed.invalid'),
    'extra_warning_URL': lambda b: b.replace(b'unsupported protocol', b'https://unreviewed.invalid unsupported protocol'),
    'wrong_warning_reason': lambda b: b.replace(b'unsupported protocol scheme "file"', b'TLS timeout'),
    'timestamp_prefix': lambda b: b.replace(b'\nerror during command execution:', b'\n2026/10/20 00:00:00 error during command execution:'),
    'unequal_payloads': lambda b: b.replace(b'\nerror during command execution: updating', b'\nerror during command execution: EXTRA updating'),
    'wrong_case_both_payloads': lambda b: b.replace(PAYLOADS['bad-target'].encode(), PAYLOADS['bad-root13'].encode()),
    'wrong_target_wrapper': lambda b: b.replace(b'downloading target:', b'error updating to TUF remote mirror:'),
    'short_old_hash_leaf': lambda b: b.replace((', expected ' + EXPECTED + ' got ' + ACTUAL).encode(), b''),
    'expected_hash_omitted': lambda b: b.replace(('expected ' + EXPECTED + ' ').encode(), b''),
    'actual_hash_omitted': lambda b: b.replace((' got ' + ACTUAL).encode(), b''),
    'expected_hash_short': lambda b: b.replace(EXPECTED.encode(), EXPECTED[:-1].encode()),
    'actual_hash_short': lambda b: b.replace(ACTUAL.encode(), ACTUAL[:-1].encode()),
    'expected_hash_wrong': lambda b: b.replace(EXPECTED.encode(), ('0' + EXPECTED[1:]).encode()),
    'actual_hash_wrong': lambda b: b.replace(ACTUAL.encode(), ('0' + ACTUAL[1:]).encode()),
    'uppercase_expected': lambda b: b.replace(EXPECTED.encode(), EXPECTED.upper().encode()),
    'uppercase_actual': lambda b: b.replace(ACTUAL.encode(), ACTUAL.upper().encode()),
    'swapped_hash_values': lambda b: b.replace(EXPECTED.encode(), b'PLACEHOLDER').replace(ACTUAL.encode(), EXPECTED.encode()).replace(b'PLACEHOLDER', ACTUAL.encode()),
    'hash_suffix': lambda b: b.replace(ACTUAL.encode(), (ACTUAL + '0').encode()),
    'error_substring_prefix': lambda b: b.replace(PAYLOADS['bad-target'].encode(), ('unrelated ' + PAYLOADS['bad-target']).encode()),
    'error_substring_suffix': lambda b: b.replace(PAYLOADS['bad-target'].encode(), (PAYLOADS['bad-target'] + ' unrelated').encode()),
    'swapped_error_lines': lambda b: b'\n'.join([*b.split(b'\n')[:2], b.split(b'\n')[3], b.split(b'\n')[2], b'']),
}
for label, mutate in BAD_FRAMES.items():
    def refuse(self, mutate=mutate, label=label):
        raw = mutate(frame('bad-target'))
        self.assertNotEqual(raw, frame('bad-target'), label)
        reason = 'strict stderr UTF8' if label == 'invalid_UTF8' else 'exact fixed stderr frame'
        with self.assertRaisesRegex(p.PolicyError, reason):
            p.warnings_and_error(raw, MIRROR, 'bad-target')
    add_test('refuse_frame_' + label, refuse)


for case in PAYLOADS:
    def refuse_three(self, case=case):
        raw = (WARNINGS + '2026/10/20 00:00:00 error during command execution: ' + PAYLOADS[case] + '\n').encode()
        with self.assertRaisesRegex(p.PolicyError, 'exact fixed stderr frame'):
            p.warnings_and_error(raw, MIRROR, case)
    add_test('refuse_old_three_lines_' + case.replace('-', '_'), refuse_three)


for label, mirror in {
    'http': 'http://host/mirror', 'authority': 'file://host/mirror',
    'credentials': 'file://user@host/mirror', 'query': MIRROR + '?x=1',
    'fragment': MIRROR + '#x', 'percent': MIRROR + '/%2e%2e',
    'traversal': MIRROR + '/../x', 'dot': MIRROR + '/./x',
    'empty_component': MIRROR + '//x', 'trailing_slash': MIRROR + '/',
    'control': MIRROR + '\n', 'nonascii': MIRROR + '/\u00e9',
    'empty_root': 'file:///', 'relative': 'file:relative', 'huge': 'file:///' + 'a' * 4096,
}.items():
    def refuse(self, mirror=mirror):
        with self.assertRaisesRegex(p.PolicyError, 'canonical file mirror'):
            p.warnings_and_error(frame('good'), mirror, 'good')
    add_test('refuse_mirror_' + label, refuse)


RECEIPT_MUTATIONS = {
    'exit_zero': ('exit_code', 0, 'natural expected outcome'),
    'exit_bool': ('exit_code', True, 'natural expected outcome'),
    'exit_signal': ('exit_code', -15, 'natural expected outcome'),
    'active_signal': ('actively_signalled', True, 'natural expected outcome'),
    'signal_false_integer': ('actively_signalled', 0, 'natural expected outcome'),
    'timeout': ('timed_out', True, 'natural expected outcome'),
    'truncated': ('truncated', True, 'natural expected outcome'),
    'failure': ('failure', 'failure', 'natural expected outcome'),
    'not_reaped': ('owned_process_reaped', False, 'natural expected outcome'),
    'reaped_integer': ('owned_process_reaped', 1, 'natural expected outcome'),
    'longer_limit': ('limit_seconds', 26, 'original capture limits'),
    'float_limit': ('limit_seconds', 25.0, 'original capture limits'),
    'larger_cap': ('per_stream_byte_cap', 1048577, 'original capture limits'),
    'float_cap': ('per_stream_byte_cap', 1048576.0, 'original capture limits'),
    'late': ('elapsed_seconds', 25.000001, 'bounded elapsed'),
    'elapsed_bool': ('elapsed_seconds', True, 'bounded elapsed'),
    'elapsed_negative': ('elapsed_seconds', -0.1, 'bounded elapsed'),
    'elapsed_nan': ('elapsed_seconds', float('nan'), 'bounded elapsed'),
    'elapsed_inf': ('elapsed_seconds', float('inf'), 'bounded elapsed'),
    'elapsed_huge_int': ('elapsed_seconds', 10 ** 400, 'bounded elapsed'),
    'name': ('name', 'chain-good', 'capture source binding'),
    'argv': ('argv', ARGV + ['--root', '/unreviewed'], 'capture source binding'),
}
for label, (key, value, reason) in RECEIPT_MUTATIONS.items():
    def refuse(self, key=key, value=value, reason=reason):
        r = receipt(); r[key] = value
        with self.assertRaisesRegex(p.PolicyError, reason):
            p.validate_capture(r, b'', frame('bad-root13'), MIRROR, 'bad-root13', list(ARGV))
    add_test('refuse_receipt_' + label, refuse)


for stream_kind in ('received_bytes', 'stored_bytes'):
    for label, value in {'bool': False, 'negative': -1, 'wrong': 1, 'float': 0.0, 'over_cap': 1048577}.items():
        def refuse(self, stream_kind=stream_kind, value=value):
            r = receipt(); r[stream_kind]['stdout'] = value
            with self.assertRaisesRegex(p.PolicyError, 'exact captured byte counts'):
                p.validate_capture(r, b'', frame('bad-root13'), MIRROR, 'bad-root13', list(ARGV))
        add_test('refuse_counts_' + stream_kind + '_' + label, refuse)


def miscellaneous(self):
    for case in ('unknown', '', False, None):
        with self.subTest(case=case), self.assertRaisesRegex(p.PolicyError, 'unknown case'):
            p.warnings_and_error(frame('good'), MIRROR, case)
    for out in (b'Root status: \n {}', b'unrelated stdout\n'):
        with self.subTest(stdout=out), self.assertRaisesRegex(p.PolicyError, 'empty negative stdout'):
            p.validate_capture(receipt(out=out), out, frame('bad-root13'), MIRROR, 'bad-root13', list(ARGV))
    for raw in (bytearray(frame('good')), b'x' * 1048577):
        with self.subTest(type=type(raw)), self.assertRaisesRegex(p.PolicyError, 'bounded stderr bytes'):
            p.warnings_and_error(raw, MIRROR, 'good')
    with self.assertRaisesRegex(p.PolicyError, 'exact fixed stderr frame'):
        p.warnings_and_error(frame('bad-root13'), MIRROR, 'good')
    for change in ('missing', 'unknown'):
        r = receipt()
        if change == 'missing':
            del r['failure']
        else:
            r['extra'] = True
        with self.subTest(change=change), self.assertRaisesRegex(p.PolicyError, 'closed receipt'):
            p.validate_capture(r, b'', frame('bad-root13'), MIRROR, 'bad-root13', list(ARGV))
    for extra in (['--root', '/unreviewed'], ['--verbose']):
        args = ARGV + extra; r = receipt(); r['argv'] = args
        with self.subTest(args=args), self.assertRaisesRegex(p.PolicyError, 'fixed reviewed argv shape'):
            p.validate_capture(r, b'', frame('bad-root13'), MIRROR, 'bad-root13', args)
    # Root status authentication remains outside this syntax-only result.
    out = b'synthetic unauthenticated output'
    result = p.validate_capture(receipt('good', out), out, frame('good'), MIRROR, 'good', list(ARGV))
    self.assertFalse(result['authentication_checked'])
    self.assertNotIn('passed', result)


add_test('additional_type_output_source_refusals', miscellaneous)


if __name__ == '__main__':
    unittest.main(verbosity=2)
