"""Bounded captures. The outer reviewed wrapper must own the batch process group."""
import os
from pathlib import Path
import selectors
import signal
import subprocess
import time

from policy import CAP, need


def run(args, directory, name, env, *, seconds, cap, owned_group=False):
    need(type(seconds) in (int, float) and 0 < seconds <= 90 and
         type(cap) is int and 0 < cap <= CAP, 'capture bounds')
    directory = Path(directory)
    start = time.monotonic()
    counts = {'stdout': 0, 'stderr': 0}
    stored = dict(counts)
    failure = None
    timed_out = truncated = signalled = False
    child = None
    selector = selectors.DefaultSelector()
    streams = {}
    try:
        for key in counts:
            fd = os.open(directory / (name + '.' + key), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            streams[key] = os.fdopen(fd, 'wb')
        child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=env, close_fds=True,
                                 start_new_session=owned_group)
        for label, pipe in [('stdout', child.stdout), ('stderr', child.stderr)]:
            os.set_blocking(pipe.fileno(), False)
            selector.register(pipe, selectors.EVENT_READ, label)
        while selector.get_map():
            remaining = seconds - (time.monotonic() - start)
            if remaining <= 0:
                timed_out, failure = True, 'wall time limit'
                break
            for key, _ in selector.select(min(.02, remaining)):
                raw = os.read(key.fd, 65536)
                if not raw:
                    selector.unregister(key.fileobj)
                    continue
                label = key.data
                counts[label] += len(raw)
                take = min(len(raw), cap - stored[label])
                streams[label].write(raw[:take])
                stored[label] += take
                if counts[label] > cap:
                    truncated, failure = True, label + ' byte limit'
                    break
            if failure:
                break
        if not failure:
            remaining = seconds - (time.monotonic() - start)
            if remaining <= 0:
                timed_out, failure = True, 'wall time before reap'
            else:
                try:
                    child.wait(timeout=remaining)
                except subprocess.TimeoutExpired:
                    timed_out, failure = True, 'wall time on reap'
    except Exception as exc:
        failure = type(exc).__name__ + ': ' + str(exc)
    finally:
        # Do not poll/reap an exited group leader before killpg: descendants may
        # still hold the pipes. Its unreaped PID prevents process-group ID reuse.
        if child is not None and failure:
            try:
                if owned_group:
                    os.killpg(child.pid, signal.SIGKILL)
                elif child.returncode is None:
                    child.kill()
                signalled = True
            except ProcessLookupError:
                pass
            try:
                child.wait(timeout=2)
            except subprocess.TimeoutExpired:
                failure += '; owned child not reaped in cleanup bound'
        selector.close()
        if child is not None:
            child.stdout.close()
            child.stderr.close()
        for stream in streams.values():
            stream.close()
    elapsed = time.monotonic() - start
    if elapsed > seconds:
        timed_out, failure = True, failure or 'actual elapsed exceeded wall time'
    return {'name': name, 'argv': args, 'exit_code': None if child is None else child.returncode,
            'elapsed_seconds': elapsed, 'limit_seconds': seconds, 'per_stream_byte_cap': cap,
            'received_bytes': counts, 'stored_bytes': stored, 'failure': failure,
            'timed_out': timed_out, 'truncated': truncated, 'actively_signalled': signalled,
            'owned_process_reaped': child is not None and child.returncode is not None}
