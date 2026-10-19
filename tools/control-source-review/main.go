// control-source-review is a bounded, read-only operator planning tool. It has
// no Docker connection, provisioning, credential, or runtime admission path.
package main

import (
	"encoding/json"
	"fmt"
	"github.com/shell-echo/sandbox-runtime/internal/phase6security"
	"io"
	"os"
)

func main() {
	if len(os.Args) > 2 || len(os.Args) == 2 && os.Args[1] != "-intent" {
		fmt.Fprintln(os.Stderr, "read canonical Profile from stdin; output is held, not a permit")
		os.Exit(2)
	}
	data, e := io.ReadAll(io.LimitReader(os.Stdin, (4<<20)+1))
	if e != nil || len(data) > 4<<20 {
		fmt.Fprintln(os.Stderr, "invalid input")
		os.Exit(1)
	}
	if len(os.Args) == 2 {
		intent, d, e := phase6security.ReviewControlSourceIntent(data)
		if e != nil {
			fmt.Fprintln(os.Stderr, "invalid standalone source intent")
			os.Exit(1)
		}
		if json.NewEncoder(os.Stdout).Encode(struct {
			Admission string                               `json:"admission"`
			Digest    string                               `json:"intent_digest"`
			Intent    phase6security.ControlSourceIntentV1 `json:"intent"`
		}{"held-not-a-permit", d, intent}) != nil {
			os.Exit(1)
		}
		return
	}
	review, e := phase6security.ReviewControlSourceProfile(data)
	if e != nil {
		fmt.Fprintln(os.Stderr, "invalid complete source Profile")
		os.Exit(1)
	}
	if json.NewEncoder(os.Stdout).Encode(review) != nil {
		os.Exit(1)
	}
}
