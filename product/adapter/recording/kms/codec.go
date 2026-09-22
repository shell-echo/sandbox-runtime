package kms

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strings"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
	"github.com/shell-echo/sandbox-runtime/product"
)

const (
	keyHandlePrefix         = "rkms1:"
	keyHandleSchema         = "sandbox-runtime.recording-key-handle.v1"
	segmentSchema           = "sandbox-runtime.recording-segment.v1"
	wrapAADSchema           = "sandbox-runtime.recording-wrapped-key-aad.v1"
	segmentAADSchema        = "sandbox-runtime.recording-segment-aad.v1"
	directoryIdentitySchema = "sandbox-runtime.recording-directory-identity.v1"
	maxKeyHandleDocument    = 96 << 10
)

type keyHandle struct {
	Schema           string `json:"schema"`
	FormatVersion    int    `json:"format_version"`
	BindingDigest    string `json:"binding_digest"`
	KMSKeyVersion    string `json:"kms_key_version"`
	ProviderKeyID    string `json:"provider_key_id"`
	WrapAlgorithm    string `json:"wrap_algorithm"`
	ContentAlgorithm string `json:"content_algorithm"`
	WrappedDataKey   []byte `json:"wrapped_data_key"`
}

func keyHandleFromEnvelope(envelope secretref.OpaqueEnvelope) keyHandle {
	return keyHandle{
		Schema:           keyHandleSchema,
		FormatVersion:    1,
		BindingDigest:    envelope.BindingDigest,
		KMSKeyVersion:    envelope.KeyVersion,
		ProviderKeyID:    envelope.KeyID,
		WrapAlgorithm:    envelope.Algorithm,
		ContentAlgorithm: contentAlgorithm,
		WrappedDataKey:   append([]byte(nil), envelope.Ciphertext...),
	}
}

func (h keyHandle) envelope() secretref.OpaqueEnvelope {
	return secretref.OpaqueEnvelope{
		BindingDigest: h.BindingDigest,
		KeyID:         h.ProviderKeyID,
		KeyVersion:    h.KMSKeyVersion,
		Algorithm:     h.WrapAlgorithm,
		Ciphertext:    append([]byte(nil), h.WrappedDataKey...),
	}
}

func (h keyHandle) validateShape() error {
	if h.Schema != keyHandleSchema || h.FormatVersion != 1 || !validDigest(h.BindingDigest) ||
		h.KMSKeyVersion == "" || len(h.KMSKeyVersion) > 64 || h.ProviderKeyID == "" || len(h.ProviderKeyID) > 128 ||
		h.WrapAlgorithm != secretref.EnvelopeAlgorithmV1 || h.ContentAlgorithm != contentAlgorithm ||
		len(h.WrappedDataKey) < 1 || len(h.WrappedDataKey) > maxWrappedDataKeyBytes {
		return product.ErrStoreUnavailable
	}
	return nil
}

func encodeKeyHandle(handle keyHandle) (string, error) {
	if err := handle.validateShape(); err != nil {
		return "", err
	}
	document, err := canonicalJSON(handle)
	if err != nil || len(document) > maxKeyHandleDocument {
		return "", product.ErrStoreUnavailable
	}
	return keyHandlePrefix + base64.RawURLEncoding.EncodeToString(document), nil
}

func decodeKeyHandle(value string) (keyHandle, error) {
	var handle keyHandle
	maximumEncoded := base64.RawURLEncoding.EncodedLen(maxKeyHandleDocument)
	if !strings.HasPrefix(value, keyHandlePrefix) || len(value) <= len(keyHandlePrefix) || len(value) > len(keyHandlePrefix)+maximumEncoded {
		return handle, product.ErrStoreUnavailable
	}
	encoded := strings.TrimPrefix(value, keyHandlePrefix)
	document, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil || base64.RawURLEncoding.EncodeToString(document) != encoded {
		clear(document)
		return handle, product.ErrStoreUnavailable
	}
	defer clear(document)
	if err := decodeCanonicalJSON(document, maxKeyHandleDocument, &handle); err != nil || handle.validateShape() != nil {
		return keyHandle{}, product.ErrStoreUnavailable
	}
	return handle, nil
}

type segmentDocument struct {
	Schema           string `json:"schema"`
	FormatVersion    int    `json:"format_version"`
	BindingDigest    string `json:"binding_digest"`
	KMSKeyVersion    string `json:"kms_key_version"`
	ProviderKeyID    string `json:"provider_key_id"`
	WrapAlgorithm    string `json:"wrap_algorithm"`
	ContentAlgorithm string `json:"content_algorithm"`
	Nonce            []byte `json:"nonce"`
	Ciphertext       []byte `json:"ciphertext"`
}

func (d segmentDocument) matches(binding secretref.Binding) bool {
	return d.Schema == segmentSchema && d.FormatVersion == 1 && d.BindingDigest == binding.Digest() &&
		d.KMSKeyVersion == binding.Version && d.ProviderKeyID == binding.KeyID &&
		d.WrapAlgorithm == secretref.EnvelopeAlgorithmV1 && d.ContentAlgorithm == contentAlgorithm &&
		len(d.Nonce) > 0 && len(d.Nonce) <= 64 && len(d.Ciphertext) > 0 && len(d.Ciphertext) <= product.MaxRecordingSegmentBytes+128
}

func encodeSegmentDocument(document segmentDocument) ([]byte, error) {
	if document.Schema != segmentSchema || document.FormatVersion != 1 || !validDigest(document.BindingDigest) ||
		document.KMSKeyVersion == "" || len(document.KMSKeyVersion) > 64 || document.ProviderKeyID == "" || len(document.ProviderKeyID) > 128 ||
		document.WrapAlgorithm != secretref.EnvelopeAlgorithmV1 || document.ContentAlgorithm != contentAlgorithm ||
		len(document.Nonce) < 1 || len(document.Nonce) > 64 || len(document.Ciphertext) < 1 || len(document.Ciphertext) > product.MaxRecordingSegmentBytes+128 {
		return nil, product.ErrStoreUnavailable
	}
	encoded, err := canonicalJSON(document)
	if err != nil || len(encoded) > maxSegmentDocumentSize {
		clear(encoded)
		return nil, product.ErrStoreUnavailable
	}
	return encoded, nil
}

func decodeSegmentDocument(document []byte) (segmentDocument, error) {
	var decoded segmentDocument
	if err := decodeCanonicalJSON(document, maxSegmentDocumentSize, &decoded); err != nil {
		return segmentDocument{}, product.ErrStoreUnavailable
	}
	if decoded.Schema != segmentSchema || decoded.FormatVersion != 1 || !validDigest(decoded.BindingDigest) ||
		decoded.KMSKeyVersion == "" || len(decoded.KMSKeyVersion) > 64 || decoded.ProviderKeyID == "" || len(decoded.ProviderKeyID) > 128 ||
		decoded.WrapAlgorithm != secretref.EnvelopeAlgorithmV1 || decoded.ContentAlgorithm != contentAlgorithm ||
		len(decoded.Nonce) < 1 || len(decoded.Nonce) > 64 || len(decoded.Ciphertext) < 1 || len(decoded.Ciphertext) > product.MaxRecordingSegmentBytes+128 {
		return segmentDocument{}, product.ErrStoreUnavailable
	}
	return decoded, nil
}

type wrappedKeyAAD struct {
	Schema        string `json:"schema"`
	TenantID      string `json:"tenant_id"`
	RecordingID   string `json:"recording_id"`
	BindingDigest string `json:"binding_digest"`
	KMSKeyVersion string `json:"kms_key_version"`
	ProviderKeyID string `json:"provider_key_id"`
	Algorithm     string `json:"algorithm"`
}

func wrapAAD(tenantID, recordingID string, binding secretref.Binding) []byte {
	document, _ := canonicalJSON(wrappedKeyAAD{
		Schema: wrapAADSchema, TenantID: tenantID, RecordingID: recordingID,
		BindingDigest: binding.Digest(), KMSKeyVersion: binding.Version,
		ProviderKeyID: binding.KeyID, Algorithm: secretref.EnvelopeAlgorithmV1,
	})
	return document
}

type recordingSegmentAAD struct {
	Schema           string `json:"schema"`
	TenantID         string `json:"tenant_id"`
	RecordingID      string `json:"recording_id"`
	ObjectReference  string `json:"object_reference"`
	Sequence         int64  `json:"sequence"`
	BindingDigest    string `json:"binding_digest"`
	KMSKeyVersion    string `json:"kms_key_version"`
	ProviderKeyID    string `json:"provider_key_id"`
	WrapAlgorithm    string `json:"wrap_algorithm"`
	ContentAlgorithm string `json:"content_algorithm"`
}

func segmentAAD(tenantID, recordingID, reference string, sequence int64, binding secretref.Binding) []byte {
	document, _ := canonicalJSON(recordingSegmentAAD{
		Schema: segmentAADSchema, TenantID: tenantID, RecordingID: recordingID,
		ObjectReference: reference, Sequence: sequence, BindingDigest: binding.Digest(),
		KMSKeyVersion: binding.Version, ProviderKeyID: binding.KeyID,
		WrapAlgorithm: secretref.EnvelopeAlgorithmV1, ContentAlgorithm: contentAlgorithm,
	})
	return document
}

type recordingDirectoryIdentity struct {
	Schema      string `json:"schema"`
	TenantID    string `json:"tenant_id"`
	RecordingID string `json:"recording_id"`
}

func canonicalJSON(value any) ([]byte, error) {
	return json.Marshal(value)
}

func decodeCanonicalJSON(document []byte, maximum int, target any) error {
	if len(document) < 1 || len(document) > maximum || scanUniqueJSONObject(json.NewDecoder(bytes.NewReader(document))) != nil {
		return product.ErrStoreUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return product.ErrStoreUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return product.ErrStoreUnavailable
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
		return product.ErrStoreUnavailable
	}
	return nil
}

func scanUniqueJSONObject(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok || delimiter != '{' {
		return product.ErrStoreUnavailable
	}
	seen := make(map[string]struct{})
	for decoder.More() {
		keyToken, err := decoder.Token()
		if err != nil {
			return err
		}
		key, ok := keyToken.(string)
		if !ok {
			return product.ErrStoreUnavailable
		}
		if _, duplicate := seen[key]; duplicate {
			return product.ErrStoreUnavailable
		}
		seen[key] = struct{}{}
		var value any
		if err := decoder.Decode(&value); err != nil {
			return err
		}
	}
	if _, err := decoder.Token(); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return product.ErrStoreUnavailable
	}
	return nil
}

func validDigest(value string) bool {
	if len(value) != len("sha256:")+64 || !strings.HasPrefix(value, "sha256:") || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil && len(decoded) == 32
}
