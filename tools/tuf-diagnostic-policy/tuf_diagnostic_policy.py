"""Fixed Cosign 3.1.3 capture syntax; no TUF authentication or execution.

The caller must independently bind the binary, input tree, argv, state and
original host/supply/isolation gates. A matching negative remains provisional
until the same frozen-base good case authenticates and the batch is reviewed.
"""
import math
import re
from types import MappingProxyType

CASES = ('bad-root13', 'bad-timestamp', 'bad-target', 'good')
CHILD_SECONDS = 25
STREAM_CAP = 1048576
TARGET = 'trusted_root.json'
TARGET_SHA = '6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66'
BAD_TARGET_SHA = '89798404182843a00037e10a50ba95597b4d66c78b921f90909d2ce1a620fab0'
ERROR_PAYLOADS = MappingProxyType({
    'bad-root13': 'updating local metadata and targets: error updating to TUF remote mirror: '
                  'tuf: valid signatures did not meet threshold',
    'bad-timestamp': 'updating local metadata and targets: error updating to TUF remote mirror: '
                     'tuf: failed to decode timestamp.json: tuf: valid signatures did not meet threshold',
    'bad-target': 'updating local metadata and targets: downloading target: '
                  'tuf: failed to download trusted_root.json: wrong sha256 hash, expected '
                  + TARGET_SHA + ' got ' + BAD_TARGET_SHA,
})
_RECEIPT_KEYS = frozenset(('name', 'argv', 'exit_code', 'elapsed_seconds',
                         'limit_seconds', 'per_stream_byte_cap', 'received_bytes',
                         'stored_bytes', 'failure', 'timed_out', 'truncated',
                         'actively_signalled', 'owned_process_reaped'))


class PolicyError(RuntimeError):
    pass


def _need(condition, reason):
    if not condition:
        raise PolicyError(reason)


def _inputs(mirror, case):
    _need(type(case) is str and case in CASES, 'unknown case')
    _need(type(mirror) is str and 0 < len(mirror) <= 4096 and
          mirror.startswith('file:///'), 'canonical file mirror')
    parts = mirror[len('file:///'):].split('/')
    _need(all(p not in ('', '.', '..') and
              re.fullmatch(r'[A-Za-z0-9_.-]+', p) is not None for p in parts),
          'canonical file mirror')


def warnings_and_error(raw, mirror, case):
    """Match only the fixed LF frame; never return an authentication verdict."""
    _inputs(mirror, case)
    _need(type(raw) is bytes and len(raw) <= STREAM_CAP, 'bounded stderr bytes')
    try:
        raw.decode('utf-8', errors='strict')
    except UnicodeDecodeError as exc:
        raise PolicyError('strict stderr UTF8') from exc
    fetch = 'Get "' + mirror + '/15.root.json": unsupported protocol scheme "file"'
    lines = [
        'WARNING: Could not fetch signing_config.json from the TUF mirror (encountered error: '
        'failed to load metadata: tuf refresh failed: ' + fetch +
        '). It is recommended to use a signing config file rather than provide service URLs when signing.',
        'WARNING: Could not fetch trusted_root.json from the TUF mirror (encountered error: '
        'failed to create TUF client failed to load metadata: tuf refresh failed: ' + fetch +
        '), falling back to individual targets. It is recommended to update your TUF metadata repository to include trusted_root.json.',
    ]
    if case != 'good':
        payload = ERROR_PAYLOADS[case]
        lines += ['Error: ' + payload, 'error during command execution: ' + payload]
    expected = ('\n'.join(lines) + '\n').encode('ascii')
    _need(raw == expected, 'exact fixed stderr frame')
    return {'expected_modern_file_warnings': 2, 'legacy_case': case,
            'format_match_only': True, 'authentication_checked': False,
            'negative_provisional': case != 'good'}


def validate_capture(receipt, stdout, stderr, mirror, case, expected_argv):
    """Natural bounded capture + syntax only; state/cryptography stay with caller.

    expected_argv must come from the separately reviewed source/input lock.
    This function cannot authenticate a receipt or its producer by itself.
    """
    _inputs(mirror, case)
    _need(type(stdout) is bytes and type(stderr) is bytes and
          len(stdout) <= STREAM_CAP and len(stderr) <= STREAM_CAP, 'bounded stream bytes')
    _need(type(receipt) is dict and set(receipt) == _RECEIPT_KEYS, 'closed receipt')
    _need(type(expected_argv) is list and len(expected_argv) == 7 and
          all(type(v) is str and 0 < len(v) <= 4096 and
              not any(ord(c) < 32 or ord(c) == 127 for c in v) for v in expected_argv) and
          expected_argv[0:2] == ['/usr/bin/sandbox-exec', '-f'] and
          expected_argv[2].startswith('/') and expected_argv[3].startswith('/') and
          expected_argv[4:] == ['initialize', '--mirror', mirror], 'fixed reviewed argv shape')
    _need(type(receipt['argv']) is list and receipt['argv'] == expected_argv and
          receipt['name'] == 'chain-' + case, 'capture source binding')
    _need(type(receipt['exit_code']) is int and
          receipt['exit_code'] == (0 if case == 'good' else 1) and
          receipt['failure'] is None and receipt['owned_process_reaped'] is True and
          all(receipt[k] is False for k in ('timed_out', 'truncated', 'actively_signalled')),
          'natural expected outcome')
    _need(type(receipt['limit_seconds']) is int and receipt['limit_seconds'] == CHILD_SECONDS and
          type(receipt['per_stream_byte_cap']) is int and receipt['per_stream_byte_cap'] == STREAM_CAP,
          'original capture limits')
    elapsed = receipt['elapsed_seconds']
    _need(type(elapsed) in (int, float) and 0 <= elapsed <= CHILD_SECONDS and math.isfinite(elapsed),
          'bounded elapsed')
    sizes = {'stdout': len(stdout), 'stderr': len(stderr)}
    for kind in ('received_bytes', 'stored_bytes'):
        counts = receipt[kind]
        _need(type(counts) is dict and set(counts) == set(sizes) and
              all(type(v) is int and 0 <= v <= STREAM_CAP for v in counts.values()) and
              counts == sizes, 'exact captured byte counts')
    if case != 'good':
        _need(stdout == b'', 'empty negative stdout')
    result = warnings_and_error(stderr, mirror, case)
    result['natural_bounded_capture'] = True
    return result
