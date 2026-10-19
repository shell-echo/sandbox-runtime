//go:build linux

package phase6process

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// ObservePID1 hashes an opened /proc/1/exe descriptor and brackets it with
// start ticks, path, descriptor identity, argv and credential snapshots. It
// deliberately accepts no caller-selected PID, path, command or shell.
func ObservePID1(ctx context.Context) (Observation, error) {
	if ctx == nil || ctx.Err() != nil {
		return Observation{}, ErrIdentity
	}
	before, e := snapshot()
	if e != nil {
		return Observation{}, ErrIdentity
	}
	f, e := os.Open("/proc/1/exe")
	if e != nil {
		return Observation{}, ErrIdentity
	}
	defer f.Close()
	st, e := f.Stat()
	if e != nil || !st.Mode().IsRegular() || st.Size() < 1 || st.Size() > 128<<20 {
		return Observation{}, ErrIdentity
	}
	h := sha256.New()
	buf := make([]byte, 64<<10)
	var total int64
	for {
		if ctx.Err() != nil {
			return Observation{}, ErrIdentity
		}
		n, err := f.Read(buf)
		if n > 0 {
			total += int64(n)
			if total > 128<<20 {
				return Observation{}, ErrIdentity
			}
			_, _ = h.Write(buf[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return Observation{}, ErrIdentity
		}
	}
	after, e := snapshot()
	now, ne := os.Stat("/proc/1/exe")
	end, ee := f.Stat()
	if e != nil || ne != nil || ee != nil || ctx.Err() != nil || total != st.Size() || !os.SameFile(st, now) || !os.SameFile(st, end) || end.Size() != st.Size() || !equalSnapshot(before, after) {
		return Observation{}, ErrIdentity
	}
	sys, ok := st.Sys().(*syscall.Stat_t)
	if !ok {
		return Observation{}, ErrIdentity
	}
	before.Digest = "sha256:" + hex.EncodeToString(h.Sum(nil))
	before.Device = uint64(sys.Dev)
	before.Inode = sys.Ino
	return before, nil
}
func readProc(path string) ([]byte, error) {
	f, e := os.Open(path)
	if e != nil {
		return nil, e
	}
	defer f.Close()
	b, e := io.ReadAll(io.LimitReader(f, 64<<10+1))
	if e != nil || len(b) == 0 || len(b) > 64<<10 {
		return nil, ErrIdentity
	}
	return b, nil
}
func snapshot() (Observation, error) {
	var o Observation
	stat, e := readProc("/proc/1/stat")
	if e != nil {
		return o, ErrIdentity
	}
	o.StartTicks, e = parseStart(stat)
	if e != nil {
		return o, ErrIdentity
	}
	o.Executable, e = os.Readlink("/proc/1/exe")
	if e != nil {
		return o, ErrIdentity
	}
	cmd, e := readProc("/proc/1/cmdline")
	if e != nil || cmd[len(cmd)-1] != 0 {
		return o, ErrIdentity
	}
	o.Args = strings.Split(string(cmd[:len(cmd)-1]), "\x00")
	status, e := readProc("/proc/1/status")
	if e != nil || parseStatus(status, &o) != nil {
		return o, ErrIdentity
	}
	return o, nil
}
func parseStart(b []byte) (uint64, error) {
	i := bytes.LastIndexByte(b, ')')
	if i < 0 || !bytes.HasPrefix(b, []byte("1 (")) {
		return 0, ErrIdentity
	}
	f := strings.Fields(string(b[i+1:]))
	if len(f) < 20 {
		return 0, ErrIdentity
	}
	n, e := strconv.ParseUint(f[19], 10, 64)
	if e != nil || n == 0 {
		return 0, ErrIdentity
	}
	return n, nil
}
func parseStatus(b []byte, o *Observation) error {
	fields := map[string]string{}
	for _, line := range strings.Split(string(b), "\n") {
		k, v, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		if _, exists := fields[k]; exists {
			return ErrIdentity
		}
		fields[k] = strings.TrimSpace(v)
	}
	numbers := func(k string) ([]uint32, error) {
		var out []uint32
		for _, v := range strings.Fields(fields[k]) {
			n, e := strconv.ParseUint(v, 10, 32)
			if e != nil {
				return nil, ErrIdentity
			}
			out = append(out, uint32(n))
		}
		if len(out) == 0 {
			return nil, ErrIdentity
		}
		return out, nil
	}
	var e error
	if o.UIDs, e = numbers("Uid"); e != nil || len(o.UIDs) != 4 {
		return ErrIdentity
	}
	if o.GIDs, e = numbers("Gid"); e != nil || len(o.GIDs) != 4 {
		return ErrIdentity
	}
	if o.Groups, e = numbers("Groups"); e != nil {
		return ErrIdentity
	}
	slices.Sort(o.Groups)
	if o.NamespacePIDs, e = numbers("NSpid"); e != nil {
		return ErrIdentity
	}
	for _, k := range []string{"CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb"} {
		v, e := strconv.ParseUint(fields[k], 16, 64)
		if e != nil {
			return ErrIdentity
		}
		o.Capabilities = append(o.Capabilities, v)
	}
	v, e := numbers("NoNewPrivs")
	if e != nil || len(v) != 1 {
		return ErrIdentity
	}
	o.NoNewPrivileges = v[0]
	v, e = numbers("Seccomp")
	if e != nil || len(v) != 1 {
		return ErrIdentity
	}
	o.Seccomp = v[0]
	return nil
}
func equalSnapshot(a, b Observation) bool {
	return a.Executable == b.Executable && a.StartTicks == b.StartTicks && a.NoNewPrivileges == b.NoNewPrivileges && a.Seccomp == b.Seccomp && slices.Equal(a.Args, b.Args) && slices.Equal(a.UIDs, b.UIDs) && slices.Equal(a.GIDs, b.GIDs) && slices.Equal(a.Groups, b.Groups) && slices.Equal(a.NamespacePIDs, b.NamespacePIDs) && slices.Equal(a.Capabilities, b.Capabilities)
}
