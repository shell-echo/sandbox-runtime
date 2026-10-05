package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"

	"github.com/shell-echo/sandbox-runtime/internal/secretfile"
)

// The wire identifiers and digest domains remain the existing CRL versions.
// These entry points admit only a fully validated ProfileV2 and an
// independently supplied expected digest; they never fall back to v1.
func DecodePeerCRLSourcesV2(document []byte, profile ProfileV2,
	expectedMappingDigest string) (PeerCRLSources, error) {
	if profile.Validate() != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	return decodePeerCRLSourcesV2Fields(document, profile, expectedMappingDigest)
}

func decodePeerCRLSourcesV2Fields(document []byte, profile ProfileV2,
	expectedMappingDigest string) (PeerCRLSources, error) {
	if len(document) < 1 || len(document) > 128<<10 ||
		!digestPattern.MatchString(expectedMappingDigest) || rejectDuplicateMembers(document) != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value PeerCRLSources
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) ||
		value.Digest() != expectedMappingDigest || value.validateV2Fields(profile) != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	return value, nil
}

func VerifyPeerCRLSourcesFileV2(path string, profile ProfileV2,
	expectedMappingDigest string) (PeerCRLSources, error) {
	if profile.Validate() != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	document, err := secretfile.Read(path, 128<<10)
	if err != nil {
		return PeerCRLSources{}, ErrInvalidProfile
	}
	defer clear(document)
	return decodePeerCRLSourcesV2Fields(document, profile, expectedMappingDigest)
}

func DecodePeerCRLRoleDocumentV2(document []byte, profile ProfileV2,
	expectedMappingDigest, expectedRoleDigest, expectedLocalPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if profile.Validate() != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return decodePeerCRLRoleDocumentV2Fields(document, profile, expectedMappingDigest,
		expectedRoleDigest, expectedLocalPrincipalDigest)
}

func decodePeerCRLRoleDocumentV2Fields(document []byte, profile ProfileV2,
	expectedMappingDigest, expectedRoleDigest, expectedLocalPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if len(document) < 1 || len(document) > 128<<10 ||
		!digestPattern.MatchString(expectedRoleDigest) ||
		!digestPattern.MatchString(expectedLocalPrincipalDigest) || rejectDuplicateMembers(document) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value PeerCRLRoleDocument
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) || value.Digest() != expectedRoleDigest ||
		value.LocalPrincipalDigest != expectedLocalPrincipalDigest ||
		value.validateV2Fields(profile, expectedMappingDigest) != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	return value, nil
}

func VerifyPeerCRLRoleFileV2(path string, profile ProfileV2,
	expectedMappingDigest, expectedRoleDigest, expectedLocalPrincipalDigest string) (PeerCRLRoleDocument, error) {
	if profile.Validate() != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	document, err := secretfile.Read(path, 128<<10)
	if err != nil {
		return PeerCRLRoleDocument{}, ErrInvalidProfile
	}
	defer clear(document)
	return decodePeerCRLRoleDocumentV2Fields(document, profile, expectedMappingDigest,
		expectedRoleDigest, expectedLocalPrincipalDigest)
}
