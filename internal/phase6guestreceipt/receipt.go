// Package phase6guestreceipt carries bounded, private Guest-edge observations
// for the Slice 6 local-candidate gate. It is not a production logging API.
package phase6guestreceipt

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/shell-echo/sandbox-runtime/guestagent"
	"golang.org/x/sys/unix"
)

const (
	Protocol       = "sandbox-runtime.phase6-guest-receipt.v1"
	MaxEvents      = 256
	MaxQueued      = 64
	MaxRecordBytes = 512
	MaxTotalBytes  = 128 << 10
	writeBudget    = 250 * time.Millisecond
)

var ErrUnavailable = errors.New("private Guest receipt unavailable")

type Record struct {
	Protocol          string `json:"protocol"`
	Role              string `json:"role"`
	Event             string `json:"event"`
	Sequence          uint64 `json:"sequence"`
	ElapsedNanos      int64  `json:"elapsed_nanos"`
	UnixMillis        int64  `json:"unix_millis"`
	ProfileDigest     string `json:"profile_digest,omitempty"`
	ConfigDigest      string `json:"config_digest,omitempty"`
	AttemptDigest     string `json:"attempt_digest,omitempty"`
	BindingGeneration int64  `json:"binding_generation,omitempty"`
	Reason            string `json:"reason,omitempty"`
	EventCount        uint64 `json:"event_count"`
	Dropped           uint64 `json:"dropped"`
}

type Recorder struct {
	mu       sync.Mutex
	outputFD int
	role     string
	start    time.Time
	queue    chan Record
	done     chan struct{}
	stop     chan struct{}
	stopOnce sync.Once
	seq      uint64
	count    uint64
	dropped  uint64
	sealed   bool
	aborted  bool
	writeErr error
}

func New(output *os.File, role, profileDigest, configDigest string) (*Recorder, error) {
	if output == nil || (role != "product" && role != "guest") ||
		!validDigest(profileDigest) || !validDigest(configDigest) {
		return nil, ErrUnavailable
	}
	info, err := output.Stat()
	if err != nil || info.Mode()&os.ModeNamedPipe == 0 || info.Mode()&os.ModeCharDevice != 0 {
		return nil, ErrUnavailable
	}
	fd, err := openIndependentNonblockingPipe(output)
	if err != nil {
		return nil, ErrUnavailable
	}
	r := &Recorder{outputFD: fd, role: role, start: time.Now(), queue: make(chan Record, MaxQueued),
		done: make(chan struct{}), stop: make(chan struct{}), seq: 1}
	begin := r.record("begin")
	begin.ProfileDigest = profileDigest
	begin.ConfigDigest = configDigest
	r.queue <- begin
	go r.writeLoop()
	return r, nil
}

func (r *Recorder) Sink(value guestagent.Observation) {
	if r == nil {
		return
	}
	r.Emit(value.Event, value.AttemptDigest, value.BindingGeneration, value.Reason)
}

// Emit only validates and enqueues bounded local data. It never writes to
// stdout, waits for a reader, or changes the caller's authorization result.
func (r *Recorder) Emit(event, digest string, generation int64, reason string) {
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.sealed || r.count >= MaxEvents || !validEvent(r.role, event, reason) ||
		!validDigest(digest) || generation < 1 {
		r.dropped++
		return
	}
	r.seq++
	record := r.record(event)
	record.AttemptDigest = digest
	record.BindingGeneration = generation
	record.Reason = reason
	select {
	case r.queue <- record:
		r.count++
	default:
		r.dropped++
	}
}

// Seal joins the sole writer; a missing or nonzero-drop seal is never valid
// evidence. The caller supplies its existing shutdown context/budget.
func (r *Recorder) Seal(ctx context.Context) error {
	if r == nil {
		return ErrUnavailable
	}
	if ctx == nil || ctx.Err() != nil {
		r.Abort()
		return ErrUnavailable
	}
	r.mu.Lock()
	if r.aborted {
		r.mu.Unlock()
		return ErrUnavailable
	}
	if !r.sealed {
		r.sealed = true
		r.seq++
		terminal := r.record("seal")
		terminal.EventCount = r.count
		terminal.Dropped = r.dropped
		select {
		case r.queue <- terminal:
		default:
			r.dropped++
		}
		close(r.queue)
	}
	r.mu.Unlock()
	select {
	case <-r.done:
	case <-ctx.Done():
		r.Abort()
		return ErrUnavailable
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.writeErr != nil || r.dropped != 0 || r.aborted {
		return ErrUnavailable
	}
	return nil
}

// Abort joins the writer without emitting a complete seal. It is used when
// source quiescence or the inherited shutdown deadline cannot be proved.
func (r *Recorder) Abort() {
	if r == nil {
		return
	}
	r.mu.Lock()
	if !r.sealed {
		r.sealed = true
		close(r.queue)
	}
	r.aborted = true
	r.stopOnce.Do(func() { close(r.stop) })
	r.mu.Unlock()
	<-r.done
}

func (r *Recorder) record(event string) Record {
	return Record{Protocol: Protocol, Role: r.role, Event: event, Sequence: r.seq,
		ElapsedNanos: time.Since(r.start).Nanoseconds(), UnixMillis: time.Now().UnixMilli()}
}

func (r *Recorder) writeLoop() {
	defer close(r.done)
	defer unix.Close(r.outputFD)
	total := 0
	for record := range r.queue {
		select {
		case <-r.stop:
			r.setWriteError()
			return
		default:
		}
		line, err := json.Marshal(record)
		if err != nil || len(line)+1 > MaxRecordBytes || total+len(line)+1 > MaxTotalBytes {
			r.setWriteError()
			return
		}
		line = append(line, '\n')
		if err := r.writeBounded(line); err != nil {
			r.setWriteError()
			return
		}
		total += len(line)
	}
}

func (r *Recorder) writeBounded(line []byte) error {
	deadline := time.Now().Add(writeBudget)
	for len(line) > 0 {
		select {
		case <-r.stop:
			return ErrUnavailable
		default:
		}
		count, err := unix.Write(r.outputFD, line)
		if count > 0 {
			line = line[count:]
		}
		wait := errors.Is(err, unix.EINTR) || errors.Is(err, unix.EAGAIN) || errors.Is(err, unix.EWOULDBLOCK)
		if err != nil && !wait {
			return ErrUnavailable
		}
		if time.Now().After(deadline) {
			return ErrUnavailable
		}
		if count == 0 || wait {
			select {
			case <-r.stop:
				return ErrUnavailable
			case <-time.After(time.Millisecond):
			}
		}
	}
	return nil
}

func (r *Recorder) setWriteError() {
	r.mu.Lock()
	r.writeErr = ErrUnavailable
	r.mu.Unlock()
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, character := range value[len("sha256:"):] {
		if character < '0' || character > '9' && character < 'a' || character > 'f' {
			return false
		}
	}
	return true
}

func validEvent(role, event, reason string) bool {
	if role == "guest" {
		return reason == "" && (event == guestagent.ObservationGuestHelloWritten ||
			event == guestagent.ObservationGuestWelcomeAccepted ||
			event == guestagent.ObservationGuestReadTerminated)
	}
	if role != "product" {
		return false
	}
	switch event {
	case guestagent.ObservationProductAuthAccepted, guestagent.ObservationProductWelcomeWritten,
		guestagent.ObservationProductPeerInstalled, guestagent.ObservationProductAuthorityStale,
		"product_validated_revoked":
		return reason == ""
	case guestagent.ObservationProductCloseCompleted:
		return reason == "authority_stale" || reason == "operator_disconnect" ||
			reason == "transport_terminated" || reason == "invalid_frame" || reason == "handler_shutdown"
	default:
		return false
	}
}
