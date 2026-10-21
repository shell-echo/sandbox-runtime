"""Eight-case controller library; requires separately reviewed private guards.

No CLI/admission fallback. A reviewed outer wrapper owns a new process group and
enforces 90s over *all* full validation/cases/postchecks, including blocked I/O.
The private guard implementation and new complete input graph must be reviewed
by value before this library is callable for a real run.
"""
from pathlib import Path
import os
import re
import signal
import time

import capture as bounded
import files
import policy as p
from der_metadata import certificate_metadata

COSIGN = '/Users/echo/.local/share/mise/installs/aqua-sigstore-cosign/3.1.3/cosign'
COSIGN_SHA = '5cf948c2f4dfe59687bdd0b8523709067383e03982cc543475c8a7dc70e92a76'
SANDBOX_SHA = '58839ef01b4eef8aac0d2aa8f9d1c074ae45aafe3533965b030672450064acc8'
PROFILE = b'(version 1)\n(allow default)\n(deny network*)\n'
ALIASES = {
    '/usr/bin/uptime': '/usr/bin/uptime', '/usr/bin/top': '/usr/bin/top',
    '/usr/bin/vm_stat': '/usr/bin/vm_stat', '/usr/bin/memory_pressure': '/usr/bin/memory_pressure',
    '/Users/echo/.docker/bin/docker': '/Applications/Docker.app/Contents/Resources/bin/docker',
    '/usr/bin/curl': '/usr/bin/curl',
    '/Users/echo/.local/share/mise/installs/python/3.13.16/bin/python3':
        '/Users/echo/.local/share/mise/installs/python/3.13.16/bin/python3.13',
    '/usr/bin/git': '/usr/bin/git', '/bin/ps': '/bin/ps'}
GUARD_KEYS = {'host_binding_sha256', 'boot_binding_sha256', 'network_binding_sha256',
              'supply_binding_sha256', 'tuf_acceptance_sha256', 'role_expiry_checked',
              'host_age_seconds', 'same_daemon', 'same_boot'}


def environment(state):
    return {'PATH': '/usr/bin:/bin', 'LC_ALL': 'C', 'LANG': 'C',
            'HOME': str(state / 'home'), 'XDG_CACHE_HOME': str(state / 'cache'),
            'TUF_ROOT': str(state / 'tuf'), 'TMPDIR': str(state / 'tmp'), 'GOMAXPROCS': '2'}


def abort_owned_group():
    # Only the batch owns this group. A failed leaf's descendants inherit it.
    # Preserve the report first, then terminate the *entire* group including this
    # controller. The independent outer capture retains/reaps the signalled batch.
    p.need(os.getpgrp() == os.getpid(), 'refuse to signal any non-owned group')
    os.killpg(os.getpgrp(), signal.SIGKILL)


def verify_inputs(plan):
    p.keys(plan, ('run_dir', 'files', 'case_inputs', 'case_order', 'profile', 'originals',
                  'guard_bindings', 'source_frames', 'tool_aliases', 'metadata_record', 'group_census_source_sha256',
                  'execution_review_sha256', 'execution_review_path'))
    p.need(plan['case_order'] == list(p.CASES) and set(plan['case_inputs']) == set(p.CASES), 'exact eight cases')
    p.need(type(plan['execution_review_sha256']) is str and
           re.fullmatch('[a-f0-9]{64}', plan['execution_review_sha256']) is not None,
           'separate concrete execution review required')
    review_raw, review_row = files.read(plan['execution_review_path'])
    p.need(review_row['mode'] == '0o600' and review_row['sha256'] == plan['execution_review_sha256'],
           'exact external independently reviewed execution record')
    review = p.parse(review_raw)
    # Avoid a self-referential manifest: review binds the complete plan with its
    # two review fields omitted; the outer caller pins this review by value.
    body = {k: v for k, v in plan.items() if not k.startswith('execution_review_')}
    p.keys(review, ('plan_body_sha256', 'run_dir', 'decision', 'error_frames_source_closed',
                    'implementation_and_full_inputs_reviewed', 'actual_run_accepted'))
    p.need(review['error_frames_source_closed'] is True and
           review['implementation_and_full_inputs_reviewed'] is True and
           review['actual_run_accepted'] is False, 'review flags are exact booleans')
    p.need(review == {'plan_body_sha256': p.sha(p.canonical(body)), 'run_dir': plan['run_dir'],
                     'decision': 'APPROVED-TO-ATTEMPT', 'error_frames_source_closed': True,
                     'implementation_and_full_inputs_reviewed': True, 'actual_run_accepted': False},
           'review cannot be design-only, stale, or an actual acceptance claim')
    for path, expected in plan['files'].items():
        files.checked(path, expected, max(p.CAP, expected['size']))
    p.need(any(row['sha256'] == plan['group_census_source_sha256'] for row in plan['files'].values()),
           'concrete group census source present in full input lock')
    p.need(plan['tool_aliases'] == ALIASES,
           'all nine inherited tool aliases')
    for selected, target in plan['tool_aliases'].items():
        p.need(target in plan['files'] and str(Path(selected).resolve(strict=True)) == target,
               'exact reviewed tool alias')
    for path, digest, mode in [(COSIGN, COSIGN_SHA, '0o755'),
                               ('/usr/bin/sandbox-exec', SANDBOX_SHA, '0o755')]:
        p.need(path in plan['files'] and plan['files'][path]['sha256'] == digest and
               plan['files'][path]['mode'] == mode, 'fixed tool identity')
    profile = Path(plan['profile'])
    p.need(str(profile) in plan['files'] and files.checked(profile, plan['files'][str(profile)]) == PROFILE,
           'unchanged deny network profile')
    originals = {}
    metadata_expected = []
    for kind in p.DIGESTS:
        source = plan['originals'][kind]
        p.need(source in plan['files'], 'locked original bundle')
        raw = files.checked(source, plan['files'][source])
        originals[kind] = raw
        facts = p.original(raw, kind)
        _, payload, cert = p.bundle(raw)
        meta = certificate_metadata(cert)
        p.need(meta['san'] == p.IDENTITY and meta['oidc_issuer'] == p.ISSUER, 'actual fixed certificate metadata')
        metadata_expected.append({'source': source, 'source_sha256': p.sha(raw),
                                  'payload_sha256': p.sha(payload), 'metadata': meta})
        if kind == 'normal':
            p.need(p.parameters('bad-digest')[1] not in facts['digests'], 'negative digest absent everywhere')
    record_path = plan['metadata_record']
    p.need(record_path in plan['files'], 'complete metadata-only observation in input graph')
    record = p.parse(files.checked(record_path, plan['files'][record_path]))
    p.need(type(record.get('actual_P2_started')) is int and
           record.get('cryptographic_acceptance') is False and
           record.get('source_summary_equivalence_closed') is False, 'exact metadata observation flags')
    p.need(type(record.get('results')) is list and len(record['results']) == 2,
           'two complete original metadata observations')
    for result in record['results']:
        p.need(type(result) is dict and type(result.get('metadata')) is dict, 'metadata result object')
        m = result['metadata']
        p.need(m.get('authenticated') is False and m.get('sigstore_summary_equivalence') is False and
               type(m.get('certificate_der_size')) is int, 'strict nested metadata flags/types')
    p.need(record == {'results': metadata_expected, 'frames': plan['source_frames'],
                     'cryptographic_acceptance': False, 'source_summary_equivalence_closed': False,
                     'actual_P2_started': 0}, 'same original bundle/DER metadata observation')
    run = Path(plan['run_dir'])
    files.directories(run)
    p.need(run.lstat().st_uid == os.getuid() and run.lstat().st_mode & 0o777 == 0o700,
           'private exclusive run')
    all_inputs = run / 'inputs'
    snap = files.snapshot(all_inputs)
    expected_files = {}
    expected_dirs = {'.'} | set(p.CASES)
    for case in p.CASES:
        spec = plan['case_inputs'][case]
        p.keys(spec, ('directory', 'bundle', 'root'))
        own = all_inputs / case
        p.need(spec['directory'] == str(own), 'exact case input directory')
        kind = p.parameters(case)[0]
        for name, row in [('bundle.json', spec['bundle']), ('trusted_root.json', spec['root'])]:
            p.need(plan['files'].get(str(own / name)) == row, 'case included in full lock')
            expected_files[case + '/' + name] = row
        raw = files.checked(own / 'bundle.json', spec['bundle'])
        p.need(raw == p.variant(originals[kind], case), 'exact one-field variant')
        root = files.checked(own / 'trusted_root.json', spec['root'])
        p.need(len(root) == 6787 and p.sha(root) == p.ROOT_SHA, 'authenticated frozen root bytes')
    p.need(snap['files'] == expected_files and set(snap['directories']) == expected_dirs,
           'exact complete case input tree')
    p.need(plan['source_frames'] == {k: v.decode() for k, v in p.frames(p.IDENTITY, p.ISSUER).items()},
           'finite source-derived candidate frames')
    return snap


def guard_check(guards, plan):
    # No mock/default/true predicate in the production library. Implementations
    # must bind original dual-host evidence, same boot/network proof, full TUF
    # chain/expiry and supply provenance; this shape check does not replace them.
    result = guards.check()
    p.keys(result, GUARD_KEYS)
    p.need(result['role_expiry_checked'] is True and result['same_daemon'] is True and
           result['same_boot'] is True, 'current original guards')
    age = result['host_age_seconds']
    p.need(type(age) in (int, float) and 0 <= age <= 120, 'fresh original host evidence')
    names = GUARD_KEYS - {'role_expiry_checked', 'host_age_seconds', 'same_daemon', 'same_boot'}
    p.need(set(plan['guard_bindings']) == names, 'all concrete guard bindings')
    for name in names:
        value = result[name]
        p.need(type(value) is str and len(value) == 64 and value == plan['guard_bindings'][name],
               'same reviewed guard ' + name)
    return {k: result[k] for k in names}


def group_check(guards, plan):
    census = guards.require_only_batch_member()
    p.keys(census, ('group_id', 'members', 'observed_current', 'source_binding_sha256'))
    p.need(type(census['group_id']) is int and census['group_id'] == os.getpid() == os.getpgrp() and
           census['members'] == [os.getpid()] and
           all(type(x) is int for x in census['members']) and census['observed_current'] is True and
           type(census['source_binding_sha256']) is str and
           re.fullmatch('[a-f0-9]{64}', census['source_binding_sha256']) is not None and
           census['source_binding_sha256'] == plan['group_census_source_sha256'],
           'concrete current owned-group census; unknown or residual member refuses')
    return census


def run_batch(plan, guards):
    start = time.monotonic()
    p.need(os.getpgrp() == os.getpid() and guards.outer_deadline_seconds == 90 and
           guards.outer_owns_this_group is True, 'reviewed 90s outer owned group')
    run = Path(plan['run_dir'])
    files.write_new(run / 'execution-claim.json', p.canonical({
        'pid': os.getpid(), 'review_sha256': plan['execution_review_sha256']}))
    results, error = [], None
    bindings = None
    initial_inputs = None
    try:
        initial_inputs = verify_inputs(plan)
        bindings = guard_check(guards, plan)
        states = run / 'states'
        states.mkdir(mode=0o700)
        state_root = files.directories(states)
        for case in p.CASES:
            p.need(time.monotonic() - start < 90, 'whole batch deadline')
            p.need(verify_inputs(plan) == initial_inputs and guard_check(guards, plan) == bindings,
                   'same complete inputs/guards before case')
            state = states / case
            state.mkdir(mode=0o700)
            for name in ('home', 'cache', 'tuf', 'tmp'):
                (state / name).mkdir(mode=0o700)
            empty = files.snapshot(state)
            p.need(empty['files'] == {}, 'empty fresh state')
            args = p.argv(case, Path(plan['case_inputs'][case]['directory']), COSIGN, Path(plan['profile']))
            post_errors = []
            try:
                receipt = bounded.run(args, run, case, environment(state), seconds=25, cap=p.CAP)
                files.write_new(run / (case + '.receipt.json'), p.canonical(receipt))
                out, _ = files.read(run / (case + '.stdout'))
                err, _ = files.read(run / (case + '.stderr'))
            finally:
                # Capture state even when an unrelated full-input check fails;
                # neither failure may erase the other one's evidence.
                for name, check in [
                    ('inputs', lambda: p.need(verify_inputs(plan) == initial_inputs, 'same full inputs')),
                    ('guards', lambda: p.need(guard_check(guards, plan) == bindings, 'same guards')),
                    ('group', lambda: files.write_new(run / (case + '.group.json'), p.canonical(group_check(guards, plan))))]:
                    try:
                        check()
                    except Exception as exc:
                        post_errors.append(name + ': ' + type(exc).__name__ + ': ' + str(exc))
                try:
                    post = files.snapshot(state)
                    files.write_new(run / (case + '.state.json'), p.canonical(post))
                    p.need(post == empty and files.directories(states) == state_root,
                           'no unexpected cache/trust/state changes')
                except Exception as exc:
                    post_errors.append('state: ' + type(exc).__name__ + ': ' + str(exc))
                files.write_new(run / (case + '.postchecks.json'), p.canonical({'errors': post_errors}))
            p.need(post_errors == [], 'case postchecks failed')
            result = p.capture(receipt, out, err, args, case, p.frames(p.IDENTITY, p.ISSUER))
            if case.startswith('good-'):
                kind = p.parameters(case)[0]
                source = plan['originals'][kind]
                raw = files.checked(source, plan['files'][source])
                case_raw = files.checked(Path(plan['case_inputs'][case]['directory']) / 'bundle.json',
                                         plan['case_inputs'][case]['bundle'])
                p.need(case_raw == raw, 'postpolicy parses same command original bytes')
                result['original_bundle_postpolicy'] = p.original(case_raw, kind)
            results.append(result)
        p.need(verify_inputs(plan) == initial_inputs and guard_check(guards, plan) == bindings,
               'final whole input/guard check')
        files.write_new(run / 'final-group.json', p.canonical(group_check(guards, plan)))
        p.need(time.monotonic() - start <= 90, 'actual whole batch elapsed')
    except Exception as exc:
        error = type(exc).__name__ + ': ' + str(exc)
    finally:
        # Preserve a failing postcheck independently of its earlier failure.
        try:
            final = verify_inputs(plan)
            p.need(initial_inputs is not None and final == initial_inputs, 'final original input binding')
            p.need(bindings is not None and guard_check(guards, plan) == bindings, 'final guard binding')
        except Exception as exc:
            error = (error or '') + '; final: ' + type(exc).__name__ + ': ' + str(exc)
        report = {'results': results, 'error': error, 'elapsed_seconds': time.monotonic() - start,
                  'all_eight_captured': error is None and len(results) == 8,
                  'independent_actual_review_required': True, 'cryptographic_acceptance': False}
        try:
            files.write_new(run / 'batch-result.json', p.canonical(report))
        finally:
            if not report['all_eight_captured'] or report['elapsed_seconds'] > 90:
                abort_owned_group()
    p.need(report['all_eight_captured'] and report['elapsed_seconds'] <= 90, 'failed batch; preserve identity')
    return report
