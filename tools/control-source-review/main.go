// control-source-review is an operator planning tool. Candidate mode builds in
// owned temporary storage and uses the selected Go caches; it never connects
// to Docker, provisions credentials or grants runtime admission. Its operator
// supervisor must enforce a hard wall limit around non-cancellable file I/O.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6fdloader"
	"github.com/shell-echo/sandbox-runtime/internal/phase6rolecandidate"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"io"
	"os"
	"time"
)

var errUsage = errors.New("read canonical Profile, -intent or -candidate input from stdin; output is held, not a permit")

func run(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	if len(args) > 1 || len(args) == 1 && args[0] != "-intent" && args[0] != "-candidate" {
		return errUsage
	}
	if ctx == nil || ctx.Err() != nil {
		return errors.New("invalid input")
	}
	maximum := 4 << 20
	if len(args) == 1 && args[0] == "-candidate" {
		maximum = 64 << 10
	}
	data, e := io.ReadAll(io.LimitReader(input, int64(maximum)+1))
	if e != nil || len(data) > maximum || ctx.Err() != nil {
		return errors.New("invalid input")
	}
	if len(args) == 1 && args[0] == "-candidate" {
		var request phase6rolecandidate.ControlCandidateInput
		if phase6fdloader.DecodeCanonical(data, &request) != nil {
			return errors.New("invalid held source candidate input")
		}
		review, err := phase6rolecandidate.ReviewControlSourceCandidate(ctx, request)
		if err != nil || ctx.Err() != nil {
			return errors.New("held source candidate unavailable")
		}
		return json.NewEncoder(output).Encode(review)
	}
	if len(args) == 1 {
		intent, d, e := phase6security.ReviewControlSourceIntent(data)
		if e != nil {
			return errors.New("invalid standalone source intent")
		}
		return json.NewEncoder(output).Encode(struct {
			Admission string                               `json:"admission"`
			Digest    string                               `json:"intent_digest"`
			Intent    phase6security.ControlSourceIntentV1 `json:"intent"`
		}{"held-not-a-permit", d, intent})
	}
	review, e := phase6security.ReviewControlSourceProfile(data)
	if e != nil {
		return errors.New("invalid complete source Profile")
	}
	return json.NewEncoder(output).Encode(review)
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		if errors.Is(err, errUsage) {
			os.Exit(2)
		}
		os.Exit(1)
	}
}
