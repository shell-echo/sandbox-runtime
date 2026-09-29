// Package phase6capacity parses bounded raw cgroup v2 observations. A parsed
// sample is component telemetry, not authority for a Slice 6 resource tier.
package phase6capacity

import (
	"errors"
	"strconv"
	"strings"
)

var ErrInvalidCgroupV2Sample = errors.New("invalid Phase 6 cgroup v2 sample")

type CgroupV2Sample struct {
	MemoryPeakBytes     int64
	PIDsPeak            int64
	CPUUsageUsec        int64
	CPUPeriods          int64
	CPUThrottledPeriods int64
	CPUThrottledUsec    int64
	MemoryOOMEvents     int64
	MemoryOOMKillEvents int64
}

// ParseCgroupV2Sample accepts exact raw memory.peak, pids.peak, cpu.stat and
// memory.events file bytes. Unknown kernel counters are tolerated but every
// line must be well formed and no counter may repeat. Missing required
// counters, overflow and internally inconsistent CPU periods fail closed.
func ParseCgroupV2Sample(memoryPeak, pidsPeak, cpuStat, memoryEvents []byte) (CgroupV2Sample, error) {
	memory, err := parseSingleCgroupCounter(memoryPeak)
	if err != nil || memory == 0 {
		return CgroupV2Sample{}, ErrInvalidCgroupV2Sample
	}
	pids, err := parseSingleCgroupCounter(pidsPeak)
	if err != nil || pids == 0 {
		return CgroupV2Sample{}, ErrInvalidCgroupV2Sample
	}
	cpu, err := parseCgroupCounters(cpuStat)
	if err != nil {
		return CgroupV2Sample{}, err
	}
	events, err := parseCgroupCounters(memoryEvents)
	if err != nil {
		return CgroupV2Sample{}, err
	}
	usage, usageOK := cpu["usage_usec"]
	periods, periodsOK := cpu["nr_periods"]
	throttledPeriods, throttledPeriodsOK := cpu["nr_throttled"]
	throttledUsec, throttledUsecOK := cpu["throttled_usec"]
	oom, oomOK := events["oom"]
	oomKill, oomKillOK := events["oom_kill"]
	if !usageOK || !periodsOK || !throttledPeriodsOK || !throttledUsecOK ||
		!oomOK || !oomKillOK || throttledPeriods > periods {
		return CgroupV2Sample{}, ErrInvalidCgroupV2Sample
	}
	return CgroupV2Sample{MemoryPeakBytes: memory, PIDsPeak: pids,
		CPUUsageUsec: usage, CPUPeriods: periods, CPUThrottledPeriods: throttledPeriods,
		CPUThrottledUsec: throttledUsec, MemoryOOMEvents: oom,
		MemoryOOMKillEvents: oomKill}, nil
}

func parseSingleCgroupCounter(document []byte) (int64, error) {
	if len(document) == 0 || len(document) > 64 {
		return 0, ErrInvalidCgroupV2Sample
	}
	value := strings.TrimSuffix(string(document), "\n")
	if value == "" || strings.ContainsAny(value, " \t\r\n+-") {
		return 0, ErrInvalidCgroupV2Sample
	}
	for _, digit := range value {
		if digit < '0' || digit > '9' {
			return 0, ErrInvalidCgroupV2Sample
		}
	}
	count, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return 0, ErrInvalidCgroupV2Sample
	}
	return count, nil
}

func parseCgroupCounters(document []byte) (map[string]int64, error) {
	if len(document) == 0 || len(document) > 4096 || document[len(document)-1] != '\n' {
		return nil, ErrInvalidCgroupV2Sample
	}
	lines := strings.Split(strings.TrimSuffix(string(document), "\n"), "\n")
	if len(lines) == 0 || len(lines) > 32 {
		return nil, ErrInvalidCgroupV2Sample
	}
	result := make(map[string]int64, len(lines))
	for _, line := range lines {
		parts := strings.Split(line, " ")
		if len(parts) != 2 || len(parts[0]) == 0 || len(parts[0]) > 64 ||
			!validCgroupCounterName(parts[0]) {
			return nil, ErrInvalidCgroupV2Sample
		}
		if _, duplicate := result[parts[0]]; duplicate {
			return nil, ErrInvalidCgroupV2Sample
		}
		value, err := parseSingleCgroupCounter([]byte(parts[1]))
		if err != nil {
			return nil, ErrInvalidCgroupV2Sample
		}
		result[parts[0]] = value
	}
	return result, nil
}

func validCgroupCounterName(value string) bool {
	for _, character := range value {
		if (character < 'a' || character > 'z') && character != '_' {
			return false
		}
	}
	return true
}
