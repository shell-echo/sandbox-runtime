package vaultkv

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

const materialSchema = "sandbox-runtime.vault-kv-material.v1"

type vaultResponse struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int             `json:"lease_duration"`
	Data          kvResponseData  `json:"data"`
	WrapInfo      json.RawMessage `json:"wrap_info"`
	Warnings      json.RawMessage `json:"warnings"`
	Auth          json.RawMessage `json:"auth"`
	MountType     string          `json:"mount_type"`
}

type kvResponseData struct {
	Data     materialDocument `json:"data"`
	Metadata kvMetadata       `json:"metadata"`
}

type kvMetadata struct {
	CreatedTime    string          `json:"created_time"`
	CustomMetadata json.RawMessage `json:"custom_metadata"`
	DeletionTime   string          `json:"deletion_time"`
	Destroyed      bool            `json:"destroyed"`
	Version        int             `json:"version"`
}

type materialDocument struct {
	Schema        string `json:"schema"`
	BindingDigest string `json:"binding_digest"`
	Version       string `json:"version"`
	Revision      string `json:"revision"`
	Digest        string `json:"digest"`
	State         string `json:"state"`
	NotBefore     string `json:"not_before"`
	NotAfter      string `json:"not_after"`
	Material      []byte `json:"material"`
}

func decodeMaterial(document []byte, binding secretref.Binding, requestedVersion int, now time.Time) (secretref.SecretMaterial, error) {
	if len(document) < 1 || len(document) > maxResponseBytes || rejectDuplicateJSON(document) != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var response vaultResponse
	if err := decoder.Decode(&response); err != nil {
		clear(response.Data.Data.Material)
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		clear(response.Data.Data.Material)
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	data := response.Data.Data
	defer clear(data.Material)
	if response.Data.Metadata.Version != requestedVersion || response.Data.Metadata.Destroyed || response.Data.Metadata.DeletionTime != "" ||
		data.Schema != materialSchema || data.BindingDigest != binding.Digest() || data.Version != binding.Version ||
		!validRevision(data.Revision) || !validDigest(data.Digest) || len(data.Material) < 1 || len(data.Material) > secretref.MaxSecretBytes {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	notBefore, errBefore := parseCanonicalTime(data.NotBefore)
	notAfter, errAfter := parseCanonicalTime(data.NotAfter)
	window := secretref.RotationWindow{NotBefore: notBefore, NotAfter: notAfter, State: secretref.KeyState(data.State)}
	if errBefore != nil || errAfter != nil || window.Validate(now) != nil {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	if window.State == secretref.KeyRevoked {
		return secretref.SecretMaterial{}, secretref.ErrRevoked
	}
	if window.State != secretref.KeyActive || now.Before(window.NotBefore) || !now.Before(window.NotAfter) {
		return secretref.SecretMaterial{}, secretref.ErrExpired
	}
	digest := sha256.Sum256(data.Material)
	if data.Digest != "sha256:"+hex.EncodeToString(digest[:]) {
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	material := secretref.SecretMaterial{
		Binding: binding, Bytes: append([]byte(nil), data.Material...), Digest: data.Digest,
		Window: window, Revision: data.Revision,
	}
	if material.Validate(now) != nil {
		material.Destroy()
		return secretref.SecretMaterial{}, secretref.ErrUnavailable
	}
	return material, nil
}

func validRevision(value string) bool {
	if len(value) < 1 || len(value) > 64 {
		return false
	}
	for _, character := range value {
		if !(character >= 'a' && character <= 'z') && !(character >= '0' && character <= '9') && !strings.ContainsRune("._-", character) {
			return false
		}
	}
	return true
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == sha256.Size
}

func parseCanonicalTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339Nano, value)
	if err != nil || value != parsed.UTC().Format(time.RFC3339Nano) {
		return time.Time{}, secretref.ErrUnavailable
	}
	return parsed, nil
}

func rejectDuplicateJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	if err := scanJSONValue(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return secretref.ErrUnavailable
			}
			if _, duplicate := seen[key]; duplicate {
				return secretref.ErrUnavailable
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim('}') {
			return secretref.ErrUnavailable
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || closing != json.Delim(']') {
			return secretref.ErrUnavailable
		}
	default:
		return secretref.ErrUnavailable
	}
	return nil
}
