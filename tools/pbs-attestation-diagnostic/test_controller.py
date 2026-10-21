import copy
import os
from pathlib import Path
import signal
import sys
import tempfile
import unittest
from unittest.mock import patch

import capture
import controller as c
import files
import policy as p
from test_policy import receipt, fixture
import base64


class PrivateFixture(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=Path(tempfile.gettempdir()).resolve())
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.root.chmod(0o700)


class FullFileGuards(PrivateFixture):
    def test_full_read_empty_eof_and_pin(self):
        path = self.root / 'input'
        for raw in [b'', b'abcd']:
            if path.exists(): path.unlink()
            files.write_new(path, raw)
            self.assertEqual(files.read(path)[0], raw)
            self.assertEqual(files.checked(path, files.read(path)[1]), raw)

    def test_replaced_same_bytes_inode_and_mode(self):
        path = self.root / 'input'; files.write_new(path, b'abcd')
        old = files.read(path)[1]
        alternate = self.root / 'other'; files.write_new(alternate, b'abcd'); alternate.replace(path)
        with self.assertRaises(p.Refused): files.checked(path, old)
        pin = files.read(path)[1]; path.chmod(0o644)
        with self.assertRaises(p.Refused): files.checked(path, pin)

    def test_symlink_brokenlink_fifo_and_parent_symlink(self):
        target = self.root / 'target'; files.write_new(target, b'a')
        (self.root / 'link').symlink_to(target)
        (self.root / 'broken').symlink_to(self.root / 'absent')
        os.mkfifo(self.root / 'fifo', 0o600)
        for name in ['link', 'broken', 'fifo']:
            with self.subTest(name=name), self.assertRaises((p.Refused, OSError)):
                files.read(self.root / name)
        (self.root / 'dir').mkdir(mode=0o700)
        (self.root / 'alias').symlink_to(self.root / 'dir')
        files.write_new(self.root / 'dir/inside', b'a')
        with self.assertRaises(p.Refused): files.read(self.root / 'alias/inside')

    def test_bound_and_observed_file_drift(self):
        path = self.root / 'input'; files.write_new(path, b'abcd')
        with self.assertRaises(p.Refused): files.read(path, 3)
        real_read = os.read
        def drift(fd, size):
            raw = real_read(fd, size)
            if raw: path.write_bytes(b'xxxx')
            return raw
        with patch.object(files.os, 'read', side_effect=drift), self.assertRaises(p.Refused): files.read(path)

    def test_state_exact_capture_and_refusals(self):
        sub = self.root / 'home'; sub.mkdir(mode=0o700)
        first = files.snapshot(self.root)
        self.assertEqual(first['files'], {})
        files.write_new(sub / 'cache', b'x')
        second = files.snapshot(self.root)
        self.assertNotEqual(first, second)
        with self.assertRaises(p.Refused): files.snapshot(self.root, max_files=0)
        with self.assertRaises(p.Refused): files.snapshot(self.root, max_bytes=0)
        (sub / 'cache').chmod(0o644)
        with self.assertRaises(p.Refused): files.snapshot(self.root)

    def test_exclusive_creation(self):
        path = self.root / 'claim'; files.write_new(path, b'a')
        with self.assertRaises(FileExistsError): files.write_new(path, b'b')
        self.assertEqual(path.read_bytes(), b'a')


class BoundedCapture(PrivateFixture):
    def run_code(self, code, name, seconds=.5, cap=100):
        return capture.run([sys.executable, '-B', '-c', code], self.root, name,
                           {'PATH': '/usr/bin:/bin', 'LANG': 'C'}, seconds=seconds,
                           cap=cap, owned_group=True)

    def test_natural_stdout_stderr_and_exit(self):
        got = self.run_code('import os;os.write(1,b"abc");os.write(2,b"err")', 'natural')
        self.assertEqual(got['exit_code'], 0)
        self.assertEqual(got['stored_bytes'], {'stdout': 3, 'stderr': 3})
        self.assertTrue(got['owned_process_reaped'])
        self.assertFalse(got['actively_signalled'])
        self.assertIsNone(got['failure'])

    def test_timeout_and_reap(self):
        got = self.run_code('import time;time.sleep(3)', 'timeout', seconds=.15)
        self.assertTrue(got['timed_out'])
        self.assertTrue(got['actively_signalled'])
        self.assertTrue(got['owned_process_reaped'])
        self.assertEqual(got['exit_code'], -signal.SIGKILL)

    def test_byte_cap_preserves_prefix_and_fails(self):
        got = self.run_code('import os;os.write(2,b"x"*1000)', 'cap', cap=17)
        self.assertTrue(got['truncated'])
        self.assertEqual((self.root / 'cap.stderr').read_bytes(), b'x' * 17)
        self.assertEqual(got['stored_bytes']['stderr'], 17)
        self.assertGreater(got['received_bytes']['stderr'], 17)

    def test_group_leader_exit_with_inherited_pipe_still_stops(self):
        # A synthetic process-tree fixture, not another verification executor.
        code = ('import os,time;pid=os.fork();'
                'os._exit(0) if pid else None;time.sleep(3)')
        got = self.run_code(code, 'group', seconds=.15)
        self.assertTrue(got['timed_out'])
        self.assertTrue(got['actively_signalled'])
        self.assertTrue(got['owned_process_reaped'])
        self.assertLess(got['elapsed_seconds'], 1)

    def test_no_overwrite_capture(self):
        self.run_code('pass', 'once')
        old = (self.root / 'once.stdout').read_bytes()
        got = self.run_code('print("wrong")', 'once')
        self.assertIsNotNone(got['failure'])
        self.assertEqual((self.root / 'once.stdout').read_bytes(), old)


class Guards(PrivateFixture):
    def setUp(self):
        super().setUp()
        self.bindings = {k: 'a' * 64 for k in c.GUARD_KEYS if k.endswith('sha256')}
        self.value = dict(self.bindings, host_age_seconds=0, same_daemon=True,
                          same_boot=True, role_expiry_checked=True)
        self.guard = type('FakeGuard', (), {'check': lambda _: copy.deepcopy(self.value),
                     'outer_deadline_seconds': 90, 'outer_owns_this_group': True,
                     'group_census_source_sha256': 'b' * 64,
                     'require_only_batch_member': lambda _: {
                         'group_id': os.getpid(), 'members': [os.getpid()],
                         'observed_current': True, 'source_binding_sha256': 'b' * 64}})()
        self.plan = {'guard_bindings': self.bindings, 'group_census_source_sha256': 'b' * 64}

    def test_all_current_bound_guard_fields(self):
        self.assertEqual(c.guard_check(self.guard, self.plan), self.bindings)

    def test_stale_missing_or_unknown_guard(self):
        for key, value in [('host_age_seconds', 121), ('host_age_seconds', -1),
                           ('host_age_seconds', float('nan')), ('same_boot', False),
                           ('same_daemon', False), ('role_expiry_checked', False),
                           ('network_binding_sha256', 'b' * 64)]:
            old = copy.deepcopy(self.value); self.value[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(p.Refused):
                c.guard_check(self.guard, self.plan)
            self.value = old
        self.value.pop('same_boot')
        with self.assertRaises(p.Refused): c.guard_check(self.guard, self.plan)

    def test_minimal_child_environment(self):
        env = c.environment(self.root)
        self.assertEqual(set(env), {'PATH', 'LC_ALL', 'LANG', 'HOME', 'XDG_CACHE_HOME',
                                    'TUF_ROOT', 'TMPDIR', 'GOMAXPROCS'})
        self.assertEqual(env['GOMAXPROCS'], '2')
        self.assertNotIn('AWS_PROFILE', env)

    def test_group_census_missing_or_leftover_refused(self):
        for wrong in [True, {'group_id': os.getpid(), 'members': [os.getpid(), 123],
                      'observed_current': True, 'source_binding_sha256': 'b' * 64}]:
            with patch.object(self.guard, 'require_only_batch_member', return_value=wrong), \
                 patch.object(c.os, 'getpgrp', return_value=os.getpid()), self.assertRaises(p.Refused):
                c.group_check(self.guard, self.plan)

    def orchestration_plan(self):
        # No real policy/tool admission is replaced globally. These mocks test
        # sequencing independently; provenance/file/capture rejection tests above
        # exercise actual implementations. No Cosign/host process is launched.
        original = self.root / 'original'; files.write_new(original, b'synthetic')
        self.plan.update(run_dir=str(self.root), execution_review_sha256='a' * 64,
                         files={str(original): files.read(original)[1]},
                         originals={'normal': str(original), 'stripped': str(original)},
                         case_inputs={})
        for case in p.CASES:
            d = self.root / 'inputs' / case; d.mkdir(mode=0o700, parents=True)
            files.write_new(d / 'bundle.json', b'synthetic')
            self.plan['case_inputs'][case] = {'directory': str(d), 'bundle': files.read(d / 'bundle.json')[1]}
        return self.plan

    def fake_capture(self, args, root, case, env, **kw):
        err = p.frames(p.IDENTITY, p.ISSUER)[case]
        files.write_new(root / (case + '.stdout'), b'')
        files.write_new(root / (case + '.stderr'), err)
        return receipt(case, args, err)

    def test_orchestration_eight_cases_postpolicy_and_no_acceptance(self):
        plan = self.orchestration_plan(); plan['profile'] = '/synthetic/deny.sb'
        with patch.object(c.os, 'getpgrp', return_value=os.getpid()), \
             patch.object(c, 'verify_inputs', return_value={'bound': True}) as verify, \
             patch.object(c.bounded, 'run', side_effect=self.fake_capture), \
             patch.object(p, 'original', return_value={'synthetic': True}) as post:
            report = c.run_batch(plan, self.guard)
        self.assertEqual([x['case'] for x in report['results']], list(p.CASES))
        self.assertEqual(post.call_count, 2)
        self.assertGreaterEqual(verify.call_count, 18)
        self.assertTrue(report['all_eight_captured'])
        self.assertFalse(report['cryptographic_acceptance'])
        with self.assertRaises(FileExistsError): c.run_batch(plan, self.guard)

    def test_unknown_error_stops_before_next_case_and_keeps_failure(self):
        plan = self.orchestration_plan(); plan['profile'] = '/synthetic/deny.sb'
        def bad_capture(args, root, case, env, **kw):
            files.write_new(root / (case + '.stdout'), b'')
            err = b'network error\n'; files.write_new(root / (case + '.stderr'), err)
            return receipt(case, args, err)
        with patch.object(c.os, 'getpgrp', return_value=os.getpid()), \
             patch.object(c, 'verify_inputs', return_value={'bound': True}), \
             patch.object(c.bounded, 'run', side_effect=bad_capture) as leaf, \
             patch.object(c, 'abort_owned_group') as abort, self.assertRaises(p.Refused):
            c.run_batch(plan, self.guard)
        self.assertEqual(leaf.call_count, 1)
        abort.assert_called_once()
        result = p.parse((self.root / 'batch-result.json').read_bytes())
        self.assertFalse(result['all_eight_captured'])
        self.assertIn('exact complete output frame', result['error'])

    def test_requires_outer_owned_group(self):
        self.guard.outer_deadline_seconds = 91
        with self.assertRaises(p.Refused): c.run_batch({}, self.guard)

    def test_failed_post_input_check_still_preserves_full_state(self):
        plan = self.orchestration_plan(); plan['profile'] = '/synthetic/deny.sb'
        count = 0
        def drift(_):
            nonlocal count
            count += 1
            if count >= 3:
                raise p.Refused('changed complete input')
            return {'bound': True}
        with patch.object(c.os, 'getpgrp', return_value=os.getpid()), \
             patch.object(c, 'verify_inputs', side_effect=drift), \
             patch.object(c.bounded, 'run', side_effect=self.fake_capture), \
             patch.object(c, 'abort_owned_group') as abort, self.assertRaises(p.Refused):
            c.run_batch(plan, self.guard)
        self.assertTrue((self.root / (p.CASES[0] + '.state.json')).exists())
        checks = p.parse((self.root / (p.CASES[0] + '.postchecks.json')).read_bytes())
        self.assertIn('changed complete input', checks['errors'][0])
        abort.assert_called_once()

    def test_unexpected_cache_rejects_and_preserves_bytes(self):
        plan = self.orchestration_plan(); plan['profile'] = '/synthetic/deny.sb'
        def writing_capture(args, root, case, env, **kw):
            files.write_new(Path(env['XDG_CACHE_HOME']) / 'unexpected', b'preserve-me')
            return self.fake_capture(args, root, case, env, **kw)
        with patch.object(c.os, 'getpgrp', return_value=os.getpid()), \
             patch.object(c, 'verify_inputs', return_value={'bound': True}), \
             patch.object(c.bounded, 'run', side_effect=writing_capture), \
             patch.object(c, 'abort_owned_group') as abort, self.assertRaises(p.Refused):
            c.run_batch(plan, self.guard)
        self.assertEqual((self.root / 'states' / p.CASES[0] / 'cache/unexpected').read_bytes(), b'preserve-me')
        post = p.parse((self.root / (p.CASES[0] + '.state.json')).read_bytes())
        self.assertIn('cache/unexpected', post['files'])
        abort.assert_called_once()

    def test_will_not_signal_unowned_process_group(self):
        with patch.object(c.os, 'getpgrp', return_value=-1), \
             patch.object(c.os, 'killpg') as kill, self.assertRaises(p.Refused):
            c.abort_owned_group()
        kill.assert_not_called()


class InheritedLeafLifecycle(PrivateFixture):
    def test_real_inherited_leaf_failure_aborts_entire_owned_batch(self):
        # The helper batch is the sole group leader; its fork fixture simulates
        # the exited-leader/held-pipe failure in the same owned_group=False mode
        # used by production leaves. No user's processes are addressed.
        module_dir = str(Path(c.__file__).parent)
        code = ('import sys,os;from pathlib import Path;'
                'sys.path.insert(0,' + repr(module_dir) + ');'
                'import capture,controller,files,policy;'
                'root=Path(' + repr(str(self.root)) + ');'
                'r=capture.run([sys.executable,"-B","-c",'
                + repr('import os,time;pid=os.fork();os._exit(0) if pid else None;time.sleep(3)') +
                '],root,"leaf",{},seconds=.15,cap=100,owned_group=False);'
                'files.write_new(root/"leaf.receipt.json",policy.canonical(r));'
                'controller.abort_owned_group()')
        outer = capture.run([sys.executable, '-B', '-c', code], self.root, 'outer',
                            {'PATH': '/usr/bin:/bin'}, seconds=2, cap=1000, owned_group=True)
        inner = p.parse((self.root / 'leaf.receipt.json').read_bytes())
        self.assertTrue(inner['timed_out'])
        self.assertTrue(inner['owned_process_reaped'])
        self.assertEqual(outer['exit_code'], -signal.SIGKILL)
        self.assertTrue(outer['owned_process_reaped'])
        self.assertFalse(outer['timed_out'])
        self.assertLess(outer['elapsed_seconds'], 1)


class CompleteInputs(PrivateFixture):
    def setUp(self):
        super().setUp()
        statement, bundle = fixture()
        from test_der_metadata import cert
        bundle['verificationMaterial']['certificate']['rawBytes'] = base64.b64encode(cert()).decode()
        payload = p.canonical(statement)
        payload += b' ' * (159656 - len(payload))
        bundle['dsseEnvelope']['payload'] = base64.b64encode(payload).decode()
        raw = p.canonical(bundle)
        self.assertLessEqual(len(raw), 223030)
        self.raw = raw + b' ' * (223030 - len(raw))
        self.root_bytes = b'synthetic-root' + b' ' * (6787 - len(b'synthetic-root'))
        self.inputs = self.root / 'inputs'; self.inputs.mkdir(mode=0o700)
        self.original_path = self.root / 'original.json'; files.write_new(self.original_path, self.raw)
        self.profile = self.root / 'deny.sb'; files.write_new(self.profile, c.PROFILE)
        self.tool = self.root / 'cosign'; files.write_new(self.tool, b'synthetic-tool'); self.tool.chmod(0o755)
        self.aliases = {}
        for n in range(9):
            file = self.root / ('alias-' + str(n)); files.write_new(file, b'synthetic-alias')
            self.aliases[str(file)] = str(file)
        self.plan = {'run_dir': str(self.root), 'files': {}, 'case_inputs': {},
                     'case_order': list(p.CASES), 'profile': str(self.profile),
                     'originals': {k: str(self.original_path) for k in p.DIGESTS},
                     'guard_bindings': {}, 'tool_aliases': self.aliases,
                     'group_census_source_sha256': p.sha(b'synthetic-tool'),
                     'source_frames': {k: v.decode() for k, v in p.frames(p.IDENTITY, p.ISSUER).items()}}
        for case in p.CASES:
            own = self.inputs / case; own.mkdir(mode=0o700)
            files.write_new(own / 'bundle.json', p.variant(self.raw, case))
            files.write_new(own / 'trusted_root.json', self.root_bytes)
            self.plan['case_inputs'][case] = {'directory': str(own),
                'bundle': files.read(own / 'bundle.json')[1], 'root': files.read(own / 'trusted_root.json')[1]}
        from der_metadata import certificate_metadata
        _, payload, cert_raw = p.bundle(self.raw)
        metadata = {'results': [{'source': str(self.original_path), 'source_sha256': p.sha(self.raw),
                    'payload_sha256': p.sha(payload), 'metadata': certificate_metadata(cert_raw)}] * 2,
                    'frames': self.plan['source_frames'], 'cryptographic_acceptance': False,
                    'source_summary_equivalence_closed': False, 'actual_P2_started': 0}
        meta_path = self.root / 'metadata.json'; files.write_new(meta_path, p.canonical(metadata))
        self.plan['metadata_record'] = str(meta_path)
        self.plan['files'] = {str(f): files.read(f)[1] for f in self.root.rglob('*') if f.is_file()}
        # Only the unavailable sandbox binary is mocked. Real no-follow/EOF and
        # inode checks cover every fixture file; this is not supplier evidence.
        self.sandbox_row = {'sha256': c.SANDBOX_SHA, 'size': 4, 'mode': '0o755', 'identity': []}
        self.plan['files']['/usr/bin/sandbox-exec'] = self.sandbox_row
        self.patches = [patch.object(c, 'COSIGN', str(self.tool)),
                        patch.object(c, 'COSIGN_SHA', p.sha(b'synthetic-tool')),
                        patch.object(c, 'ALIASES', self.aliases),
                        patch.object(p, 'BUNDLE_SHA', p.sha(self.raw)),
                        patch.object(p, 'ROOT_SHA', p.sha(self.root_bytes))]
        for obj in self.patches:
            obj.start(); self.addCleanup(obj.stop)
        checked = files.checked
        def sandbox_only(path, expected, cap=p.CAP):
            if str(path) == '/usr/bin/sandbox-exec':
                self.assertEqual(expected, self.sandbox_row)
                return b'tool'
            return checked(path, expected, cap)
        obj = patch.object(files, 'checked', side_effect=sandbox_only); obj.start(); self.addCleanup(obj.stop)
        self.write_review()

    def write_review(self, **changes):
        self.plan.pop('execution_review_path', None); self.plan.pop('execution_review_sha256', None)
        body = copy.deepcopy(self.plan)
        value = {'plan_body_sha256': p.sha(p.canonical(body)), 'run_dir': str(self.root),
                 'decision': 'APPROVED-TO-ATTEMPT', 'error_frames_source_closed': True,
                 'implementation_and_full_inputs_reviewed': True, 'actual_run_accepted': False}
        value.update(changes)
        path = self.root / ('review-' + str(len(list(self.root.glob('review-*')))) + '.json')
        files.write_new(path, p.canonical(value))
        self.plan.update(execution_review_path=str(path), execution_review_sha256=p.sha(path.read_bytes()))

    def test_complete_synthetic_closed_graph(self):
        self.assertEqual(len(c.verify_inputs(self.plan)['files']), 16)

    def test_design_only_review_refused(self):
        for changes in [{'decision': 'DESIGN-PASS'}, {'error_frames_source_closed': False},
                        {'implementation_and_full_inputs_reviewed': False},
                        {'error_frames_source_closed': 1}, {'actual_run_accepted': 0},
                        {'actual_run_accepted': True}, {'plan_body_sha256': '0' * 64}]:
            self.write_review(**changes)
            with self.subTest(changes=changes), self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_input_content_drift_after_review(self):
        self.original_path.write_bytes(self.raw[:-1] + b'x')
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_extra_unlocked_case_file_and_symlink_refused(self):
        extra = self.inputs / p.CASES[0] / 'unexpected'; files.write_new(extra, b'x')
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)
        extra.unlink(); extra.symlink_to(self.original_path)
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_variant_wrong_field_even_under_new_review_refused(self):
        case = 'bad-missing-tlog'; spec = self.plan['case_inputs'][case]
        path = Path(spec['directory']) / 'bundle.json'
        value = p.parse(path.read_bytes()); value['dsseEnvelope']['payloadType'] = 'wrong'
        path.write_bytes(p.canonical(value))
        row = files.read(path)[1]; spec['bundle'] = row; self.plan['files'][str(path)] = row
        self.write_review()
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_alias_or_missing_case_refused(self):
        del self.plan['case_inputs'][p.CASES[-1]]
        self.write_review()
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_wrong_metadata_even_under_new_review_refused(self):
        path = Path(self.plan['metadata_record']); value = p.parse(path.read_bytes())
        value['results'][0]['metadata']['san'] = 'https://wrong.invalid'
        path.write_bytes(p.canonical(value)); self.plan['files'][str(path)] = files.read(path)[1]
        self.write_review()
        with self.assertRaises(p.Refused): c.verify_inputs(self.plan)

    def test_metadata_boolean_number_confusion_refused(self):
        path = Path(self.plan['metadata_record']); original = p.parse(path.read_bytes())
        for key in ['actual_P2_started', 'cryptographic_acceptance', 'source_summary_equivalence_closed',
                    'authenticated', 'sigstore_summary_equivalence']:
            value = copy.deepcopy(original)
            if key in ['authenticated', 'sigstore_summary_equivalence']:
                value['results'][0]['metadata'][key] = 0
            else:
                value[key] = False if key == 'actual_P2_started' else 0
            path.write_bytes(p.canonical(value)); self.plan['files'][str(path)] = files.read(path)[1]
            self.write_review()
            with self.subTest(key=key), self.assertRaises(p.Refused): c.verify_inputs(self.plan)


if __name__ == '__main__':
    unittest.main()
