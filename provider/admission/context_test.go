package admission

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeAdmissionContextCarrierBindsDigestAndTarget(t *testing.T) {
	context := validAdmissionContextForTest()
	digest, err := DigestForAdmissionContext(context)
	if err != nil {
		t.Fatal(err)
	}
	context.ContextDigest = digest
	carrier := encodeAdmissionContextForTest(t, context)
	decoded, err := DecodeAdmissionContextCarrier(carrier)
	if err != nil {
		t.Fatalf("DecodeAdmissionContextCarrier() error = %v", err)
	}
	if decoded.ContextDigest != digest || decoded.Operation != OperationExec {
		t.Fatalf("decoded context = %#v", decoded)
	}
	request, err := http.NewRequest(http.MethodPost, "https://provider.test/v1/sandboxes/sandbox-1/exec", nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := decoded.ValidateTarget(request); err != nil {
		t.Fatalf("ValidateTarget() error = %v", err)
	}
	request.URL.RawQuery = "%zz"
	if err := decoded.ValidateTarget(request); !errors.Is(err, ErrAdmissionContextTargetMismatch) {
		t.Fatalf("malformed query error = %v", err)
	}
}

func TestDecodeAdmissionContextCarrierRejectsCarrierAndDocumentConfusion(t *testing.T) {
	context := validAdmissionContextForTest()
	digest, err := DigestForAdmissionContext(context)
	if err != nil {
		t.Fatal(err)
	}
	context.ContextDigest = digest
	carrier := encodeAdmissionContextForTest(t, context)
	tests := map[string]string{
		"padding":    carrier + "=",
		"whitespace": carrier + " ",
		"tampered": encodeAdmissionContextForTest(t, func() AdmissionContext {
			copy := context
			copy.TenantID = "tenant-other"
			return copy
		}()),
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeAdmissionContextCarrier(value); !errors.Is(err, ErrInvalidAdmissionContext) {
				t.Fatalf("DecodeAdmissionContextCarrier() error = %v", err)
			}
		})
	}
	raw, err := base64.RawURLEncoding.DecodeString(carrier)
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(raw, &document); err != nil {
		t.Fatal(err)
	}
	document["unknown"] = true
	encoded, _ := json.Marshal(document)
	unknown := base64.RawURLEncoding.EncodeToString(encoded)
	if _, err := DecodeAdmissionContextCarrier(unknown); !errors.Is(err, ErrInvalidAdmissionContext) {
		t.Fatalf("unknown member error = %v", err)
	}
	duplicate := strings.Replace(string(raw), `"tenant_id":"tenant-1"`, `"tenant_id":"tenant-1","tenant_id":"tenant-1"`, 1)
	if _, err := DecodeAdmissionContextCarrier(base64.RawURLEncoding.EncodeToString([]byte(duplicate))); !errors.Is(err, ErrInvalidAdmissionContext) {
		t.Fatalf("duplicate member error = %v", err)
	}
}

func TestDecodeAdmissionContextCarrierEnforcesSchemaBounds(t *testing.T) {
	base := validAdmissionContextForTest()
	cases := map[string]func(*AdmissionContext){
		"controller subject too long": func(value *AdmissionContext) { value.ControllerSubject = strings.Repeat("x", 201) },
		"sandbox id too long":         func(value *AdmissionContext) { value.SandboxID = strings.Repeat("x", 201) },
		"fencing token too large":     func(value *AdmissionContext) { value.FencingToken = maxSafeJSONInteger + 1 },
		"path too short":              func(value *AdmissionContext) { value.HTTPTarget.Path = "/v1" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			value := base
			mutate(&value)
			digest, err := DigestForAdmissionContext(value)
			if err != nil {
				t.Fatal(err)
			}
			value.ContextDigest = digest
			if _, err := DecodeAdmissionContextCarrier(encodeAdmissionContextForTest(t, value)); !errors.Is(err, ErrInvalidAdmissionContext) {
				t.Fatalf("DecodeAdmissionContextCarrier() error = %v, want %v", err, ErrInvalidAdmissionContext)
			}
		})
	}
}

func TestDecodeAdmissionContextCarrierClosesQueryByOperation(t *testing.T) {
	base := validAdmissionContextForTest()
	event := base
	event.Operation = OperationReadEvents
	event.RequestContractID = "urn:shell-echo:sandbox-runtime:descriptor:events:v1"
	event.RequestDigestProfile = DigestProfileFullDocument
	event.HTTPTarget = AdmissionTarget{Method: http.MethodGet, Path: "/v1/sandboxes/sandbox-1/events", NormalizedQuery: []AdmissionQuery{}}

	tests := []struct {
		name    string
		context AdmissionContext
		valid   bool
	}{
		{
			name: "query forbidden for mutation",
			context: func() AdmissionContext {
				value := base
				value.HTTPTarget.NormalizedQuery = []AdmissionQuery{{Name: "unexpected", Value: "value"}}
				return value
			}(),
		},
		{
			name: "unknown event query",
			context: func() AdmissionContext {
				value := event
				value.HTTPTarget.NormalizedQuery = []AdmissionQuery{{Name: "unexpected", Value: "value"}}
				return value
			}(),
		},
		{
			name: "noncanonical event sequence",
			context: func() AdmissionContext {
				value := event
				value.HTTPTarget.NormalizedQuery = []AdmissionQuery{{Name: "after_sequence", Value: "01"}}
				return value
			}(),
		},
		{
			name: "canonical event sequence",
			context: func() AdmissionContext {
				value := event
				value.HTTPTarget.NormalizedQuery = []AdmissionQuery{{Name: "after_sequence", Value: "1"}}
				return value
			}(),
			valid: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			value := test.context
			digest, err := DigestForAdmissionContext(value)
			if err != nil {
				t.Fatal(err)
			}
			value.ContextDigest = digest
			_, err = DecodeAdmissionContextCarrier(encodeAdmissionContextForTest(t, value))
			if test.valid && err != nil {
				t.Fatalf("DecodeAdmissionContextCarrier() error = %v", err)
			}
			if !test.valid && !errors.Is(err, ErrInvalidAdmissionContext) {
				t.Fatalf("DecodeAdmissionContextCarrier() error = %v, want %v", err, ErrInvalidAdmissionContext)
			}
		})
	}
}

func validAdmissionContextForTest() AdmissionContext {
	return AdmissionContext{
		ContextContractID:        AdmissionContextContractID,
		ContextDigestProfile:     AdmissionContextDigestProfile,
		ControllerSubject:        "spiffe://provider/controller",
		ProviderRevisionID:       "provider-revision-1",
		ProviderInstanceAudience: "urn:shell-echo:sandbox-runtime:provider-instance:provider-1",
		TenantID:                 "tenant-1", WorkOrderID: "work-order-1",
		PolicyDigest: validDigest('a'), PolicyDecidedAt: "2026-08-20T00:00:00Z",
		Operation: OperationExec, SandboxID: "sandbox-1", OperationID: "operation-1",
		AttemptID: "attempt-1", FencingToken: 1, DeadlineAt: "2026-08-20T00:05:00Z",
		RequestContractID:    "urn:shell-echo:sandbox-runtime:request:exec:v1",
		RequestDigestProfile: DigestProfileRequestExcludingDigest, RequestDigest: validDigest('b'),
		HTTPTarget: AdmissionTarget{Method: http.MethodPost, Path: "/v1/sandboxes/sandbox-1/exec", NormalizedQuery: []AdmissionQuery{}},
	}
}

func encodeAdmissionContextForTest(t *testing.T, context AdmissionContext) string {
	t.Helper()
	encoded, err := json.Marshal(context)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}
