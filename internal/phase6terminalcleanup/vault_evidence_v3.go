package phase6terminalcleanup

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"
	"sync"
	"time"
)

const maxEvidenceV3ProjectionBytes = 64 << 10

type vaultEvidenceV3Collector struct {
	mu          sync.Mutex
	plan        Plan
	now         func() time.Time
	events      []EvidenceV3Event
	issuerDER   []byte
	crlDER      []byte
	crlAt       string
	issuerReads int
	bytes       int
	failed      bool
}

type vaultEvidenceV3Transport struct {
	next      http.RoundTripper
	collector *vaultEvidenceV3Collector
}

type replayReadCloser struct {
	io.Reader
	original io.Closer
	prefix   []byte
}

func (r *replayReadCloser) Close() error {
	clear(r.prefix)
	return r.original.Close()
}

func newVaultEvidenceV3Collector(plan Plan, now func() time.Time) *vaultEvidenceV3Collector {
	return &vaultEvidenceV3Collector{plan: plan, now: now}
}

// Capture the existing authenticated HTTP exchange without requesting any
// extra Vault operation. The original response is replayed byte-for-byte to
// the old client; evidence projection failure never skips remote cleanup.
func (t *vaultEvidenceV3Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if t == nil || t.next == nil || t.collector == nil || request == nil {
		return nil, ErrInvalid
	}
	var requestRaw []byte
	if request.Body != nil {
		original := request.Body
		prefix, err := io.ReadAll(io.LimitReader(original, 8<<10+1))
		requestRaw = prefix
		replay := bytes.Clone(prefix)
		request.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(replay), original),
			original: original, prefix: replay}
		if err != nil || len(prefix) > 8<<10 {
			t.collector.fail()
		}
	}
	defer clear(requestRaw)
	response, err := t.next.RoundTrip(request)
	if err != nil {
		t.collector.fail()
		return response, err
	}
	if response == nil || response.Body == nil {
		t.collector.fail()
		return response, nil
	}
	original := response.Body
	prefix, readErr := io.ReadAll(io.LimitReader(original, maxVaultReply+1))
	replay := bytes.Clone(prefix)
	response.Body = &replayReadCloser{Reader: io.MultiReader(bytes.NewReader(replay), original),
		original: original, prefix: replay}
	if readErr != nil || len(prefix) > maxVaultReply {
		t.collector.fail()
		clear(prefix)
		return response, nil
	}
	t.collector.observe(request.Context(), request.Method, request.URL.Path, requestRaw,
		response.StatusCode, response.Header.Get("Content-Type"), prefix)
	clear(prefix)
	return response, nil
}

func (c *vaultEvidenceV3Collector) fail() {
	c.mu.Lock()
	c.failed = true
	c.mu.Unlock()
}

func (c *vaultEvidenceV3Collector) observe(ctx context.Context, method, path string,
	requestRaw []byte, status int, rawMedia string, response []byte) {
	if ctx == nil || ctx.Err() != nil || c == nil {
		if c != nil {
			c.fail()
		}
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed {
		return
	}
	media := ""
	if status != http.StatusNoContent {
		var err error
		media, _, err = mime.ParseMediaType(rawMedia)
		if err != nil {
			c.failed = true
			return
		}
		media = strings.ToLower(media)
	}
	event := EvidenceV3Event{Status: status, MediaType: media}
	issuerPath := "/v1/pki/issuer/" + c.plan.GeneralIssuerID
	switch {
	case method == http.MethodPost && path == "/v1/auth/token/lookup-accessor":
		accessor, ok := evidenceV3RequestField(requestRaw, "accessor")
		if !ok {
			c.failed = true
			return
		}
		event.TargetDigest = targetDigest("token", accessor)
		preflight := len(c.events) < len(c.plan.Tokens)
		if preflight {
			event.Kind = "lookup-preflight"
		} else {
			event.Kind = "lookup-post-revoke"
		}
		if status == http.StatusBadRequest && exactInvalidAccessor(response) {
			var value struct {
				Errors []string `json:"errors"`
			}
			if json.Unmarshal(response, &value) != nil || len(value.Errors) != 1 {
				c.failed = true
				return
			}
			event.InvalidAccessorError = value.Errors[0]
		} else if status == http.StatusOK && rejectDuplicateJSON(response) == nil {
			var value struct {
				Data struct {
					Accessor  string            `json:"accessor"`
					Policies  []string          `json:"policies"`
					Meta      map[string]string `json:"meta"`
					Role      string            `json:"role"`
					Type      string            `json:"type"`
					Orphan    bool              `json:"orphan"`
					Renewable bool              `json:"renewable"`
					TTL       int64             `json:"ttl"`
				} `json:"data"`
			}
			if json.Unmarshal(response, &value) != nil || value.Data.Accessor != accessor ||
				len(value.Data.Meta) > 7 || len(value.Data.Policies) > 1 {
				c.failed = true
				return
			}
			event.ObservedDigest = targetDigest("token", value.Data.Accessor)
			event.Token = &EvidenceV3Token{Policies: append([]string(nil), value.Data.Policies...),
				Metadata: value.Data.Meta, Role: value.Data.Role, Type: value.Data.Type,
				Orphan: value.Data.Orphan, Renewable: value.Data.Renewable, TTLSeconds: value.Data.TTL}
		} else {
			c.failed = true
			return
		}
	case method == http.MethodPost && path == "/v1/auth/token/revoke-accessor":
		accessor, ok := evidenceV3RequestField(requestRaw, "accessor")
		if !ok || status != http.StatusNoContent || len(response) != 0 {
			c.failed = true
			return
		}
		event.Kind, event.TargetDigest = "accessor-revoke", targetDigest("token", accessor)
	case method == http.MethodPost && path == "/v1/auth/token/revoke-self":
		if status != http.StatusNoContent || len(response) != 0 || !bytes.Equal(requestRaw, []byte("{}")) {
			c.failed = true
			return
		}
		event.Kind, event.TargetDigest = "self-revoke", c.plan.Digest
	case method == http.MethodPost && path == "/v1/pki/revoke":
		serial, ok := evidenceV3RequestField(requestRaw, "serial_number")
		if !ok || status != http.StatusOK || media != "application/json" {
			c.failed = true
			return
		}
		kind := ""
		for _, target := range c.plan.Certificates {
			if target.Serial == serial {
				kind = "certificate"
				if target.Kind == externalPostgresKind {
					kind = externalPostgresKind
				}
			}
		}
		if kind == "" {
			c.failed = true
			return
		}
		var value struct {
			RevocationTime    int64  `json:"revocation_time"`
			RevocationTimeRFC string `json:"revocation_time_rfc3339"`
			State             string `json:"state"`
		}
		if evidenceV3DecodeVaultData(response, &value) != nil {
			c.failed = true
			return
		}
		event.Kind, event.TargetDigest = "certificate-revoke", targetDigest(kind, serial)
		event.RevocationState, event.RevocationUnix, event.RevocationRFC3339 =
			value.State, value.RevocationTime, value.RevocationTimeRFC
	case method == http.MethodGet && path == issuerPath+"/der":
		if status != http.StatusOK || (media != "application/pkix-cert" && media != "application/octet-stream") ||
			len(response) < 1 || len(response) > 64<<10 {
			c.failed = true
			return
		}
		sha := sha256.Sum256(response)
		event.TargetDigest = c.plan.GeneralIssuerDigest
		event.ObservedDigest = "sha256:" + hex.EncodeToString(sha[:])
		if c.issuerReads == 0 {
			event.Kind = "issuer-read"
			c.issuerDER = bytes.Clone(response)
		} else {
			event.Kind = "issuer-reread"
		}
		c.issuerReads++
	case method == http.MethodGet && path == "/v1/pki/config/crl":
		if status != http.StatusOK || media != "application/json" {
			c.failed = true
			return
		}
		var fields map[string]json.RawMessage
		if evidenceV3DecodeVaultData(response, &fields) != nil ||
			!bytes.Equal(fields["disable"], []byte("false")) ||
			!bytes.Equal(fields["auto_rebuild"], []byte("false")) ||
			!bytes.Equal(fields["enable_delta"], []byte("false")) {
			c.failed = true
			return
		}
		event.Kind, event.TargetDigest = "crl-config", c.plan.GeneralIssuerDigest
		event.CRLConfig = &EvidenceV3CRLConfig{}
	case method == http.MethodGet && path == issuerPath+"/crl/der":
		if status != http.StatusOK || (media != "application/pkix-crl" &&
			media != "application/x-pkcs7-crl" && media != "application/octet-stream") ||
			len(response) < 1 || len(response) > 512<<10 {
			c.failed = true
			return
		}
		sha := sha256.Sum256(response)
		event.Kind, event.TargetDigest = "crl-read", c.plan.GeneralIssuerDigest
		event.ObservedDigest = "sha256:" + hex.EncodeToString(sha[:])
		c.crlDER = bytes.Clone(response)
		c.crlAt = c.now().UTC().Format(time.RFC3339Nano)
	default:
		c.failed = true
		return
	}
	encoded, err := json.Marshal(event)
	if err != nil || len(c.events) >= 32 || c.bytes+len(encoded) > maxEvidenceV3ProjectionBytes {
		c.failed = true
		return
	}
	c.bytes += len(encoded)
	c.events = append(c.events, event)
}

func evidenceV3RequestField(document []byte, field string) (string, bool) {
	if len(document) < 2 || len(document) > 8<<10 || rejectDuplicateJSON(document) != nil {
		return "", false
	}
	var value map[string]string
	if json.Unmarshal(document, &value) != nil || len(value) != 1 || value[field] == "" {
		return "", false
	}
	return value[field], true
}

func evidenceV3DecodeVaultData(document []byte, target any) error {
	if len(document) < 2 || len(document) > maxVaultReply || rejectDuplicateJSON(document) != nil {
		return ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var envelope struct {
		RequestID     string          `json:"request_id"`
		LeaseID       string          `json:"lease_id"`
		Renewable     bool            `json:"renewable"`
		LeaseDuration int64           `json:"lease_duration"`
		Data          json.RawMessage `json:"data"`
		WrapInfo      json.RawMessage `json:"wrap_info"`
		Warnings      json.RawMessage `json:"warnings"`
		Auth          json.RawMessage `json:"auth"`
		MountType     string          `json:"mount_type"`
	}
	if decoder.Decode(&envelope) != nil || len(envelope.Data) < 2 {
		return ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		return ErrInvalid
	}
	data := json.NewDecoder(bytes.NewReader(envelope.Data))
	data.DisallowUnknownFields()
	if data.Decode(target) != nil || !errors.Is(data.Decode(&trailing), io.EOF) {
		return ErrInvalid
	}
	return nil
}

func (v *VaultRemote) PrivateEvidenceV3(receipt Receipt) (EvidenceV3, error) {
	if v == nil || v.evidence == nil {
		return EvidenceV3{}, ErrInvalid
	}
	c := v.evidence
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failed || len(c.events) < 1 || c.crlAt == "" {
		return EvidenceV3{}, ErrInvalid
	}
	evidence := EvidenceV3{Protocol: EvidenceV3Protocol, RunID: c.plan.RunID,
		ProfileDigest: c.plan.ProfileDigest, PlanDigest: c.plan.Digest,
		CRLVerifiedUTC: c.crlAt, IssuerDER: bytes.Clone(c.issuerDER),
		CRLDER: bytes.Clone(c.crlDER), Events: append([]EvidenceV3Event(nil), c.events...),
		Receipt: receipt}
	if VerifyEvidenceV3(c.plan, evidence) != nil {
		clear(evidence.IssuerDER)
		clear(evidence.CRLDER)
		return EvidenceV3{}, ErrInvalid
	}
	return evidence, nil
}

func (c *vaultEvidenceV3Collector) clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	clear(c.issuerDER)
	clear(c.crlDER)
	c.issuerDER, c.crlDER, c.events = nil, nil, nil
	c.failed = true
}
