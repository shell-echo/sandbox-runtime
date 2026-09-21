package sessiontermination

import (
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
)

func TestFirstCauseCannotBeOverwrittenByCancellation(t *testing.T) {
	var first First
	if !first.Observe(StageMediaReader, CauseBackpressure) {
		t.Fatal("first terminal cause was not accepted")
	}
	if first.Observe(StageCloseOrdering, CauseCallerCancel) {
		t.Fatal("later cancellation replaced the first terminal cause")
	}
	record, ok := first.Load()
	if !ok || record != (Record{Stage: StageMediaReader, Cause: CauseBackpressure}) {
		t.Fatalf("first terminal record = %#v, %v", record, ok)
	}
}

func TestFirstCauseHasExactlyOneConcurrentOwner(t *testing.T) {
	var first First
	var owners int
	var lock sync.Mutex
	var group sync.WaitGroup
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func() {
			defer group.Done()
			if first.Observe(StageExecutorTransport, CauseTransportClosed) {
				lock.Lock()
				owners++
				lock.Unlock()
			}
		}()
	}
	group.Wait()
	if owners != 1 {
		t.Fatalf("first terminal owners = %d", owners)
	}
}

func TestTerminationRecordsStayClosedAndSanitized(t *testing.T) {
	records := []Record{
		FromError(context.Canceled, StageInputWriter, CauseRuntimeFailure),
		FromError(context.DeadlineExceeded, StageAuthorityWatcher, CauseRuntimeFailure),
		FromError(io.EOF, StageExecutorTransport, CauseRuntimeFailure),
		FromError(errors.New("/private/socket secret=credential"), StageBrokerRuntime, CauseRuntimeFailure),
	}
	want := []Cause{CauseCallerCancel, CauseExpiry, CauseTransportClosed, CauseRuntimeFailure}
	for index, record := range records {
		if !record.Valid() || record.Cause != want[index] {
			t.Fatalf("record %d = %#v", index, record)
		}
		text := record.String()
		if strings.Contains(text, "private") || strings.Contains(text, "credential") || strings.Contains(text, "secret") {
			t.Fatalf("record leaked implementation detail: %q", text)
		}
	}
}

func TestParseAcceptsOnlyCanonicalClosedRecord(t *testing.T) {
	want := Record{Stage: StageMediaReader, Cause: CauseBackpressure}
	got, ok := Parse(want.String())
	if !ok || got != want {
		t.Fatalf("parsed record = %#v, %v", got, ok)
	}
	for _, value := range []string{
		"stage=media_reader cause=backpressure_limit extra=secret",
		"stage=/tmp/socket cause=runtime_failure",
		"stage=media_reader cause=raw_error",
	} {
		if _, accepted := Parse(value); accepted {
			t.Fatalf("unsafe record accepted: %q", value)
		}
	}
}
