package v1

import (
	"errors"
	"strings"
	"testing"
)

func TestDecodeStrictRejectsUnknownField(t *testing.T) {
	var request LeaseRequest
	err := DecodeStrict(strings.NewReader(`{"unknown":true}`), 1024, &request)
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("DecodeStrict() error = %v, want unknown field", err)
	}
}

func TestDecodeStrictRejectsMultipleValues(t *testing.T) {
	var request LeaseRequest
	err := DecodeStrict(strings.NewReader(`{} {}`), 1024, &request)
	if err == nil || !strings.Contains(err.Error(), "multiple JSON values") {
		t.Fatalf("DecodeStrict() error = %v, want multiple JSON values", err)
	}
}

func TestDecodeStrictRejectsOversizedBody(t *testing.T) {
	var request LeaseRequest
	body := strings.Repeat(" ", int(MaxLeaseRequestBytes)+1)
	err := DecodeStrict(strings.NewReader(body), MaxLeaseRequestBytes, &request)
	if !errors.Is(err, ErrBodyTooLarge) {
		t.Fatalf("DecodeStrict() error = %v, want %v", err, ErrBodyTooLarge)
	}
}

func TestDecodeStrictRejectsClosedEnumAndIdentifierValues(t *testing.T) {
	tests := []struct {
		name        string
		document    string
		destination any
	}{
		{name: "desired state", document: `{"desired_state":"terminated"}`, destination: &DesiredStateRequest{}},
		{name: "digest", document: `{"request_digest":"sha256:not-a-digest"}`, destination: &MutationEnvelope{}},
		{name: "slot key", document: `{"sandbox_slot_key":"Primary Code"}`, destination: &Status{}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := DecodeStrict(strings.NewReader(test.document), 1024, test.destination); err == nil {
				t.Fatal("DecodeStrict() error = nil, want rejection")
			}
		})
	}
}
