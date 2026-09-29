package phase6capacity

import "testing"

func TestParseCgroupV2Sample(t *testing.T) {
	memory := []byte("124551168\n")
	pids := []byte("72\n")
	cpu := []byte("usage_usec 601300\nuser_usec 294617\nsystem_usec 306683\nnr_periods 9\nnr_throttled 3\nthrottled_usec 77183\n")
	events := []byte("low 0\nhigh 0\nmax 0\noom 0\noom_kill 0\n")
	sample, err := ParseCgroupV2Sample(memory, pids, cpu, events)
	if err != nil || sample.MemoryPeakBytes != 124551168 || sample.PIDsPeak != 72 ||
		sample.CPUPeriods != 9 || sample.CPUThrottledPeriods != 3 || sample.CPUThrottledUsec != 77183 ||
		sample.MemoryOOMEvents != 0 || sample.MemoryOOMKillEvents != 0 {
		t.Fatalf("real cgroup v2 shape rejected: %+v, %v", sample, err)
	}
	for _, item := range []struct {
		name                     string
		memory, pids, cpu, event []byte
	}{
		{"missing memory peak", nil, pids, cpu, events},
		{"noncanonical peak", []byte("+72\n"), pids, cpu, events},
		{"overflow", []byte("9223372036854775808\n"), pids, cpu, events},
		{"duplicate cpu field", memory, pids, append(append([]byte(nil), cpu...), []byte("nr_periods 9\n")...), events},
		{"missing cpu field", memory, pids, []byte("usage_usec 1\nnr_periods 1\nnr_throttled 0\n"), events},
		{"impossible throttling", memory, pids, []byte("usage_usec 1\nnr_periods 1\nnr_throttled 2\nthrottled_usec 1\n"), events},
		{"missing OOM field", memory, pids, cpu, []byte("oom 0\n")},
		{"malformed line", memory, pids, cpu, []byte("oom 0\noom_kill\n")},
	} {
		t.Run(item.name, func(t *testing.T) {
			if _, err := ParseCgroupV2Sample(item.memory, item.pids, item.cpu, item.event); err == nil {
				t.Fatal("invalid cgroup v2 sample admitted")
			}
		})
	}
}
