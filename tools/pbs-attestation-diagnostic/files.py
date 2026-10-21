"""No-follow full reads with inode/EOF guards; no hash cache."""
import os
from pathlib import Path
import stat

from policy import CAP, need, sha


def identity(s):
    return [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid,
            s.st_size, s.st_mtime_ns, s.st_ctime_ns]


def directories(path):
    path = Path(path)
    need(path.is_absolute() and '..' not in path.parts, 'absolute normalized path')
    result = {}
    for part in reversed([path, *path.parents]):
        s = part.lstat()
        need(stat.S_ISDIR(s.st_mode), 'real directory, no parent symlink')
        # Contents can be created in these ancestors; bind their stable identities.
        result[str(part)] = [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid]
    return result


def read(path, cap=CAP):
    path = Path(path)
    parents = directories(path.parent)
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        from policy import Refused
        raise Refused('no-follow regular file open refused: ' + str(path)) from exc
    try:
        before = os.fstat(fd)
        need(stat.S_ISREG(before.st_mode) and 0 <= before.st_size <= cap, 'bounded regular file')
        parts, total = [], 0
        while True:
            block = os.read(fd, min(1 << 20, cap - total + 1))
            if not block:
                break
            parts.append(block)
            total += len(block)
            need(total <= cap, 'read/EOF cap')
        after = os.fstat(fd)
        need(identity(before) == identity(after) == identity(path.lstat()) and
             total == before.st_size and directories(path.parent) == parents, 'file/path drift')
        raw = b''.join(parts)
        return raw, {'sha256': sha(raw), 'size': total,
                     'mode': oct(stat.S_IMODE(before.st_mode)), 'identity': identity(before)}
    finally:
        os.close(fd)


def checked(path, expected, cap=CAP):
    raw, actual = read(path, cap)
    need(actual == expected, 'exact pinned bytes/mode/inode ' + str(path))
    return raw


def snapshot(root, max_files=256, max_bytes=32 << 20):
    root = Path(root)
    before = directories(root)
    need(stat.S_IMODE(root.lstat().st_mode) == 0o700 and root.lstat().st_uid == os.getuid(),
         'private owned root')
    files, dirs, total = {}, {}, 0
    for base, children, names in os.walk(root, followlinks=False):
        p = Path(base)
        s = p.lstat()
        need(stat.S_ISDIR(s.st_mode) and stat.S_IMODE(s.st_mode) == 0o700 and
             s.st_uid == os.getuid(), 'private real state directory')
        dirs[str(p.relative_to(root))] = [s.st_dev, s.st_ino, s.st_mode, s.st_uid, s.st_gid]
        need(len(dirs) <= 256, 'directory bound')
        for name in children:
            need(stat.S_ISDIR((p / name).lstat().st_mode), 'no state symlink')
        for name in names:
            need(len(files) < max_files, 'state file count')
            _, row = read(p / name, max_bytes - total)
            need(row['mode'] == '0o600' and row['identity'][3] == os.getuid(), 'private state file')
            total += row['size']
            files[str((p / name).relative_to(root))] = row
    need(directories(root) == before, 'state root drift')
    return {'files': files, 'directories': dirs}


def write_new(path, raw):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(raw)
