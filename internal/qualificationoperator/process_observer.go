package qualificationoperator

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

var ErrProcessObservation = errors.New("qualification process observation failed")

type executableIdentity struct {
	device uint64
	inode  uint64
	path   string
}

// ProcessObserver continuously witnesses executions from outside the candidate
// process tree. It retains only component occurrence counts; OS PIDs and procfs
// paths never cross into sanitized evidence.
type ProcessObserver struct {
	targets map[string]executableIdentity

	mu       sync.Mutex
	seen     map[string]map[string]struct{}
	counts   map[string]int
	running  map[string]int
	done     chan struct{}
	cancel   context.CancelFunc
	failed   bool
	emulated bool
}

func StartProcessObserver(parent context.Context, executablePaths map[string]string) (*ProcessObserver, error) {
	if runtime.GOOS != "linux" || parent == nil || len(executablePaths) != 4 {
		return nil, ErrProcessObservation
	}
	targets := make(map[string]executableIdentity, len(executablePaths))
	for component, path := range executablePaths {
		identity, err := statExecutable(path)
		if err != nil || component == "" {
			return nil, ErrProcessObservation
		}
		identity.path = path
		targets[component] = identity
	}
	ctx, cancel := context.WithCancel(parent)
	observer := &ProcessObserver{
		targets: targets, seen: make(map[string]map[string]struct{}, len(targets)), counts: make(map[string]int, len(targets)), running: make(map[string]int, len(targets)),
		done: make(chan struct{}), cancel: cancel,
	}
	for component := range targets {
		observer.seen[component] = make(map[string]struct{})
	}
	go observer.run(ctx)
	return observer, nil
}

func (o *ProcessObserver) Close() error {
	if o == nil {
		return nil
	}
	o.cancel()
	<-o.done
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.failed {
		return ErrProcessObservation
	}
	return nil
}

func (o *ProcessObserver) WaitOccurrence(ctx context.Context, component string, occurrence int) error {
	if o == nil || occurrence < 1 {
		return ErrProcessObservation
	}
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		o.mu.Lock()
		count, exists, failed := o.counts[component], o.targets[component].inode != 0, o.failed
		o.mu.Unlock()
		if !exists || failed {
			return ErrProcessObservation
		}
		if count >= occurrence {
			return nil
		}
		select {
		case <-ctx.Done():
			return errors.Join(ErrProcessObservation, context.Cause(ctx))
		case <-ticker.C:
		}
	}
}

func (o *ProcessObserver) Counts() map[string]int {
	o.mu.Lock()
	defer o.mu.Unlock()
	result := make(map[string]int, len(o.counts))
	for component, count := range o.counts {
		result[component] = count
	}
	return result
}

func (o *ProcessObserver) Running(component string) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.running[component]
}

func (o *ProcessObserver) Emulated() bool {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.emulated
}

func (o *ProcessObserver) run(ctx context.Context) {
	defer close(o.done)
	ticker := time.NewTicker(5 * time.Millisecond)
	defer ticker.Stop()
	for {
		if err := o.scan(); err != nil {
			o.mu.Lock()
			o.failed = true
			o.mu.Unlock()
			return
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (o *ProcessObserver) scan() error {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return err
	}
	running := make(map[string]int, len(o.targets))
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		if _, err := strconv.Atoi(entry.Name()); err != nil {
			continue
		}
		exe := filepath.Join("/proc", entry.Name(), "exe")
		identity, err := statExecutable(exe)
		if err != nil {
			continue
		}
		resolved, _ := os.Readlink(exe)
		commandPath := ""
		if resolved == "/run/rosetta/rosetta" {
			command, readErr := os.ReadFile(filepath.Join("/proc", entry.Name(), "cmdline"))
			if readErr == nil {
				if end := bytes.IndexByte(command, 0); end > 0 {
					commandPath = string(command[:end])
				}
			}
		}
		stat, err := os.ReadFile(filepath.Join("/proc", entry.Name(), "stat"))
		if err != nil || len(stat) > 16<<10 {
			continue
		}
		startTime, ok := procStartTime(stat)
		if !ok {
			continue
		}
		key := entry.Name() + ":" + startTime
		for component, target := range o.targets {
			emulated := resolved == "/run/rosetta/rosetta" && commandPath == target.path
			if (identity.device != target.device || identity.inode != target.inode) && resolved != target.path && !emulated {
				continue
			}
			o.mu.Lock()
			if emulated {
				o.emulated = true
			}
			running[component]++
			if _, exists := o.seen[component][key]; !exists {
				o.seen[component][key] = struct{}{}
				o.counts[component]++
			}
			o.mu.Unlock()
		}
	}
	o.mu.Lock()
	for component := range o.targets {
		o.running[component] = running[component]
	}
	o.mu.Unlock()
	return nil
}

// procStartTime returns Linux procfs stat field 22. PID plus starttime is
// stable for one process lifetime and distinguishes a reused PID; mutable CPU
// accounting fields in the same record must never participate in identity.
func procStartTime(stat []byte) (string, bool) {
	closing := bytes.LastIndex(stat, []byte(") "))
	if closing < 0 {
		return "", false
	}
	fields := strings.Fields(string(stat[closing+2:]))
	// The suffix begins at field 3 (state), so field 22 is index 19.
	if len(fields) <= 19 {
		return "", false
	}
	if _, err := strconv.ParseUint(fields[19], 10, 64); err != nil {
		return "", false
	}
	return fields[19], true
}

func statExecutable(path string) (executableIdentity, error) {
	info, err := os.Stat(path)
	if err != nil || !info.Mode().IsRegular() {
		return executableIdentity{}, ErrProcessObservation
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return executableIdentity{}, ErrProcessObservation
	}
	return executableIdentity{device: uint64(stat.Dev), inode: stat.Ino}, nil
}

// GatewayRouting switches the candidate's stable DNS name from its private
// bind loopback to the public observation proxy only after the private listener
// for the selected phase is independently reachable.
type GatewayRouting struct {
	dns            *RotatingDNS
	processes      *ProcessObserver
	privateAddress string
	mu             sync.Mutex
	cancel         context.CancelFunc
	generation     uint64
}

func NewGatewayRouting(dns *RotatingDNS, processes *ProcessObserver, privateAddress string) (*GatewayRouting, error) {
	if dns == nil || processes == nil || privateAddress == "" {
		return nil, ErrProcessObservation
	}
	return &GatewayRouting{dns: dns, processes: processes, privateAddress: privateAddress}, nil
}

func (r *GatewayRouting) Arm(ctx context.Context) error {
	if ctx == nil || ctx.Err() != nil {
		return ErrProcessObservation
	}
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
	}
	r.generation++
	generation := r.generation
	routeContext, cancel := context.WithCancel(ctx)
	r.cancel = cancel
	occurrence := r.processes.Counts()["caller_gateway"] + 1
	r.dns.UsePrivate()
	r.mu.Unlock()
	go func() {
		defer func() {
			r.mu.Lock()
			if r.generation == generation {
				r.cancel = nil
			}
			r.mu.Unlock()
		}()
		for {
			wait, cancel := context.WithTimeout(routeContext, 30*time.Second)
			if r.processes.WaitOccurrence(wait, "caller_gateway", occurrence) != nil {
				cancel()
				return
			}
			// A newly observed Gateway must resolve its advertised name to the
			// private bind address. This is also a fallback for a prior service
			// that terminated without completing an observed connection.
			r.dns.UsePrivate()
			for {
				connection, err := net.DialTimeout("tcp", r.privateAddress, 100*time.Millisecond)
				if err == nil {
					_ = connection.Close()
					r.dns.UseObserver()
					break
				}
				select {
				case <-wait.Done():
					cancel()
					return
				case <-time.After(5 * time.Millisecond):
				}
			}
			cancel()
			occurrence++
		}
	}()
	return nil
}
