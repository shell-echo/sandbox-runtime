package vaulttransit

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

type encryptRequest struct {
	Plaintext      []byte `json:"plaintext"`
	AssociatedData []byte `json:"associated_data"`
	KeyVersion     int    `json:"key_version"`
}

type decryptRequest struct {
	Ciphertext     string `json:"ciphertext"`
	AssociatedData []byte `json:"associated_data"`
}

type vaultResponse struct {
	RequestID     string          `json:"request_id"`
	LeaseID       string          `json:"lease_id"`
	Renewable     bool            `json:"renewable"`
	LeaseDuration int             `json:"lease_duration"`
	Data          json.RawMessage `json:"data"`
	WrapInfo      json.RawMessage `json:"wrap_info"`
	Warnings      json.RawMessage `json:"warnings"`
	Auth          json.RawMessage `json:"auth"`
	MountType     string          `json:"mount_type"`
}

type encryptResponse struct {
	Ciphertext string `json:"ciphertext"`
	KeyVersion int    `json:"key_version,omitempty"`
}

type decryptResponse struct {
	Plaintext []byte `json:"plaintext"`
}

func decodeVaultData(document []byte, target any) error {
	if len(document) < 1 || len(document) > maxResponseBytes || rejectDuplicateJSON(document) != nil {
		return secretref.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var response vaultResponse
	if err := decoder.Decode(&response); err != nil || len(response.Data) < 2 {
		return secretref.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	dataDecoder := json.NewDecoder(bytes.NewReader(response.Data))
	dataDecoder.DisallowUnknownFields()
	if err := dataDecoder.Decode(target); err != nil {
		return secretref.ErrUnavailable
	}
	if err := dataDecoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	return nil
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
