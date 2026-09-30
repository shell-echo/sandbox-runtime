// Package phase6fdloader defines the closed, same-host Docker startup input
// for Phase 6 roles that already consume private regular-file descriptors.
// Docker/operator identity is the trusted boundary; this is not a remotely
// authenticated or persistent replay-ledger protocol.
package phase6fdloader

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strings"
)

const (
	ProtocolID             = "sandbox-runtime.phase6-fd-startup.v1"
	MaxEnvelopeBytes       = 4 << 20
	RolePath               = "/usr/local/bin/phase6-role"
	LoaderPath             = "/usr/local/bin/phase6-fd-loader"
	FixedEntrypointCommand = "exec 3</dev/null 4</dev/null 5</dev/null 6</dev/null; exec /usr/local/bin/phase6-fd-loader"
)

var ErrInvalid = errors.New("invalid Phase 6 private-FD startup input")

type Descriptor struct {
	FD       int
	Purpose  string
	MaxBytes int
	Exact    bool
}

type Specification struct {
	Target         string
	MaxConfigBytes int
	Descriptors    []Descriptor
}

// SpecificationFor intentionally has no user-extensible target, path or FD.
func SpecificationFor(target string) (Specification, bool) {
	switch target {
	case "certificate-controller":
		return Specification{target, 2 << 20, []Descriptor{
			{3, "credential-agent-signing-key", 64, true},
			{4, "certificate-controller-signing-key", 64, true},
			{5, "vault-client-tls-private-key", 64 << 10, false},
			{6, "vault-tls-certificate-request-key", 64, true},
		}}, true
	case "workload-credential-controller-v2":
		return Specification{target, 2 << 20, []Descriptor{
			{3, "vault-operator-bootstrap-token", 8 << 10, false},
			{4, "vault-bootstrap-tls-private-key", 64 << 10, false},
			{5, "vault-tls-certificate-request-key", 64, true},
		}}, true
	case "workload-material-agent":
		return Specification{target, 2 << 20, []Descriptor{{3, "workload-agent-identity", 64, true}}}, true
	case "workload-tls-agent":
		return Specification{target, 256 << 10, []Descriptor{{3, "certificate-request-signing-key", 64, true}}}, true
	case "break-glass-controller":
		return Specification{target, 1 << 20, []Descriptor{{3, "break-glass-signing-key", 64, true}}}, true
	case "egress-policy-state-authority":
		return Specification{target, 16 << 10, []Descriptor{{3, "policy-state-signing-key", 64, true}}}, true
	default:
		return Specification{}, false
	}
}

type PrivateFile struct {
	FD   int    `json:"fd"`
	Data []byte `json:"data"`
}

// Envelope is delivered once through Docker's non-TTY attached stdin and
// closed. Its container ID comes from Docker create, not self-declared state.
type Envelope struct {
	Protocol    string        `json:"protocol"`
	RunID       string        `json:"run_id"`
	Target      string        `json:"target"`
	ContainerID string        `json:"container_id"`
	Nonce       string        `json:"nonce"`
	Config      []byte        `json:"config"`
	Files       []PrivateFile `json:"files"`
}

// Expected is fixed by Docker create metadata and the Docker-assigned
// hostname. The operator separately verifies the full create ID and image.
type Expected struct {
	RunID             string
	Target            string
	Nonce             string
	ContainerHostname string
}

func Decode(reader io.Reader, expected Expected) (Envelope, error) {
	if reader == nil {
		return Envelope{}, ErrInvalid
	}
	raw, err := io.ReadAll(io.LimitReader(reader, MaxEnvelopeBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > MaxEnvelopeBytes {
		clear(raw)
		return Envelope{}, ErrInvalid
	}
	defer clear(raw)
	var value Envelope
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&value) != nil {
		value.Destroy()
		return Envelope{}, ErrInvalid
	}
	var trailing any
	if !errors.Is(decoder.Decode(&trailing), io.EOF) {
		value.Destroy()
		return Envelope{}, ErrInvalid
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(raw, canonical) || value.Validate(expected) != nil {
		value.Destroy()
		return Envelope{}, ErrInvalid
	}
	return value, nil
}

func (value Envelope) Validate(expected Expected) error {
	spec, ok := SpecificationFor(expected.Target)
	if !ok || value.Protocol != ProtocolID || value.Target != expected.Target ||
		value.RunID != expected.RunID || value.Nonce != expected.Nonce ||
		!lowerHex(value.RunID, 32) || !lowerHex(value.Nonce, 32) ||
		!lowerHex(value.ContainerID, 64) ||
		!lowerHex(expected.ContainerHostname, 12) ||
		!strings.HasPrefix(value.ContainerID, expected.ContainerHostname) ||
		len(value.Config) < 1 || len(value.Config) > spec.MaxConfigBytes ||
		len(value.Files) != len(spec.Descriptors) {
		return ErrInvalid
	}
	for index, file := range value.Files {
		descriptor := spec.Descriptors[index]
		if file.FD != descriptor.FD || len(file.Data) < 1 || len(file.Data) > descriptor.MaxBytes ||
			(descriptor.Exact && len(file.Data) != descriptor.MaxBytes) {
			return ErrInvalid
		}
	}
	return nil
}

func (value *Envelope) Destroy() {
	if value == nil {
		return
	}
	clear(value.Config)
	for i := range value.Files {
		clear(value.Files[i].Data)
	}
	*value = Envelope{}
}

func lowerHex(value string, length int) bool {
	if len(value) != length {
		return false
	}
	for _, c := range value {
		if c < '0' || c > '9' {
			if c < 'a' || c > 'f' {
				return false
			}
		}
	}
	return true
}
