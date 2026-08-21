package exec

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

var execTestNow = time.Date(2026, 8, 21, 12, 0, 0, 0, time.UTC)

func validRequest() Request {
	return Request{
		SandboxID:          "sandbox-1",
		OperationID:        "operation-1",
		AttemptID:          "attempt-1",
		FencingToken:       1,
		ExpectedGeneration: 1,
		IdempotencyKey:     "exec-request-1",
		RequestDigest:      "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		Deadline:           execTestNow.Add(time.Minute),
		Command:            []string{"printf", "hello"},
		WorkingDirectory:   "/workspace/src",
		ResultRetention:    time.Hour,
		Environment:        map[string]string{"HOME": "envref:grant/exec-home"},
		SecretReferenceIDs: []string{"secret-ref-1"},
		SecretGrantID:      "grant:exec-1",
		SecretGrantDigest:  "sha256:1111111111111111111111111111111111111111111111111111111111111111",
		StdinReference:     "ref:stdin-1",
		CaptureStdout:      true,
		CaptureStderr:      true,
		CaptureMaxBytes:    65536,
	}
}

func TestRequestValidateAcceptsContractBounds(t *testing.T) {
	request := validRequest()
	request.IdempotencyKey = strings.Repeat("界", MaxIdempotencyKeyRunes)
	request.Command = []string{strings.Repeat("界", MaxCommandItemRunes)}
	request.WorkingDirectory = "/workspace/" + strings.Repeat("a", MaxWorkingDirectoryRunes-len("/workspace/"))
	request.ResultRetention = MinRetention
	request.CaptureMaxBytes = MaxCaptureBytes
	request.Environment = environmentReferences(MaxEnvironmentValues)
	request.SecretReferenceIDs = secretReferences(MaxSecretReferences)
	if err := request.Validate(execTestNow); err != nil {
		t.Fatalf("Validate() error = %v", err)
	}

	request.Command = make([]string, MaxCommandItems)
	for index := range request.Command {
		request.Command[index] = "x"
	}
	request.ResultRetention = MaxRetention
	if err := request.Validate(execTestNow); err != nil {
		t.Fatalf("Validate() at item and retention limits error = %v", err)
	}

	request.CaptureStdout = false
	request.CaptureStderr = false
	request.CaptureMaxBytes = 0
	if err := request.Validate(execTestNow); err != nil {
		t.Fatalf("Validate() with omitted capture projection error = %v", err)
	}
}

func TestRequestValidateRejectsInvalidBoundaries(t *testing.T) {
	tests := map[string]func(*Request){
		"empty sandbox ID":              func(r *Request) { r.SandboxID = "" },
		"invalid operation ID":          func(r *Request) { r.OperationID = "operation value" },
		"invalid attempt ID":            func(r *Request) { r.AttemptID = "attempt/value" },
		"empty idempotency key":         func(r *Request) { r.IdempotencyKey = "" },
		"oversized idempotency key":     func(r *Request) { r.IdempotencyKey = strings.Repeat("x", MaxIdempotencyKeyRunes+1) },
		"invalid UTF-8 idempotency key": func(r *Request) { r.IdempotencyKey = string([]byte{0xff}) },
		"zero fencing token":            func(r *Request) { r.FencingToken = 0 },
		"zero expected generation":      func(r *Request) { r.ExpectedGeneration = 0 },
		"invalid digest":                func(r *Request) { r.RequestDigest = "sha256:ABC" },
		"missing deadline":              func(r *Request) { r.Deadline = time.Time{} },
		"empty command":                 func(r *Request) { r.Command = nil },
		"too many command items": func(r *Request) {
			r.Command = make([]string, MaxCommandItems+1)
			for index := range r.Command {
				r.Command[index] = "x"
			}
		},
		"empty command item":         func(r *Request) { r.Command = []string{""} },
		"oversized command item":     func(r *Request) { r.Command = []string{strings.Repeat("x", MaxCommandItemRunes+1)} },
		"invalid UTF-8 command item": func(r *Request) { r.Command = []string{string([]byte{0xff})} },
		"NUL command item":           func(r *Request) { r.Command = []string{"printf\x00"} },
		"new line command item":      func(r *Request) { r.Command = []string{"printf\n"} },
		"wrong working mount":        func(r *Request) { r.WorkingDirectory = "/outputs" },
		"path traversal":             func(r *Request) { r.WorkingDirectory = "/workspace/../etc" },
		"oversized working directory": func(r *Request) {
			r.WorkingDirectory = "/workspace/" + strings.Repeat("a", MaxWorkingDirectoryRunes-len("/workspace/")+1)
		},
		"non-positive retention": func(r *Request) { r.ResultRetention = 0 },
		"too long retention":     func(r *Request) { r.ResultRetention = MaxRetention + time.Second },
		"too many environment values": func(r *Request) {
			r.Environment = environmentReferences(MaxEnvironmentValues + 1)
		},
		"invalid environment name":    func(r *Request) { r.Environment = map[string]string{"invalid-name": "envref:value"} },
		"plaintext environment value": func(r *Request) { r.Environment = map[string]string{"TOKEN": "plaintext-secret"} },
		"too many secret references": func(r *Request) {
			r.SecretReferenceIDs = secretReferences(MaxSecretReferences + 1)
		},
		"invalid secret reference": func(r *Request) { r.SecretReferenceIDs = []string{"secret/ref"} },
		"grant ID without digest":  func(r *Request) { r.SecretGrantDigest = "" },
		"grant digest without ID":  func(r *Request) { r.SecretGrantID = "" },
		"invalid grant ID":         func(r *Request) { r.SecretGrantID = "grant:bad value" },
		"invalid grant digest":     func(r *Request) { r.SecretGrantDigest = "sha256:ABC" },
		"invalid stdin reference":  func(r *Request) { r.StdinReference = "plaintext-input" },
		"negative capture bound":   func(r *Request) { r.CaptureMaxBytes = -1 },
		"too large capture bound":  func(r *Request) { r.CaptureMaxBytes = MaxCaptureBytes + 1 },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			request := validRequest()
			mutate(&request)
			if err := request.Validate(execTestNow); !errors.Is(err, ErrInvalidRequest) {
				t.Fatalf("Validate() error = %v, want ErrInvalidRequest", err)
			}
		})
	}
}

func environmentReferences(count int) map[string]string {
	references := make(map[string]string, count)
	for index := 0; index < count; index++ {
		references[fmt.Sprintf("VALUE_%d", index)] = "envref:value"
	}
	return references
}

func secretReferences(count int) []string {
	references := make([]string, count)
	for index := range references {
		references[index] = fmt.Sprintf("secret-ref-%d", index)
	}
	return references
}

func TestRequestValidateRejectsExpiredDeadline(t *testing.T) {
	request := validRequest()
	request.Deadline = execTestNow
	if err := request.Validate(execTestNow); !errors.Is(err, ErrDeadlineExpired) {
		t.Fatalf("Validate() error = %v, want ErrDeadlineExpired", err)
	}
}

func TestRequestCloneIsDeep(t *testing.T) {
	request := validRequest()
	clone := request.Clone()
	request.Command[0] = "changed-command"
	request.SecretReferenceIDs[0] = "changed-reference"
	request.Environment["HOME"] = "envref:changed"
	if clone.Command[0] != "printf" || clone.SecretReferenceIDs[0] != "secret-ref-1" || clone.Environment["HOME"] != "envref:grant/exec-home" {
		t.Fatalf("Clone() shares mutable input: %#v", clone)
	}
}

func TestDispatchValidateRejectsNonOpaqueReference(t *testing.T) {
	valid := Dispatch{ExecutionReference: "ref:exec/receipt-1", AcceptedAt: execTestNow}
	if err := valid.Validate(); err != nil {
		t.Fatalf("valid Dispatch.Validate() error = %v", err)
	}
	for _, reference := range []ExecutionReference{"", "/var/lib/docker/containers/abc", "container-abc"} {
		dispatch := valid
		dispatch.ExecutionReference = reference
		if err := dispatch.Validate(); !errors.Is(err, ErrInvalidDispatch) {
			t.Fatalf("Dispatch(%q).Validate() error = %v, want ErrInvalidDispatch", reference, err)
		}
	}
}
