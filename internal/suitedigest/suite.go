// Package suitedigest validates and verifies content-derived Provider Suite
// identities.
package suitedigest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	// DigestProfile identifies the only Suite digest algorithm supported by this
	// implementation.
	DigestProfile = "rfc8785-full-document-excluding-suite-digest-v1"
	// ExecutionModeRepositoryGoTest identifies a repository-owned Go test
	// profile.
	ExecutionModeRepositoryGoTest = "repository-go-test"
	// ExecutionModeRemoteHTTPBlackBox identifies a remote HTTP black-box
	// profile.
	ExecutionModeRemoteHTTPBlackBox = "remote-http-black-box"

	MaxDocumentBytes   = 1 << 20
	maxProfiles        = 64
	maxTests           = 4096
	maxIdentifierRunes = 200
)

var (
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	versionPattern = regexp.MustCompile(`^[0-9]+\.[0-9]+\.[0-9]+$`)
)

// Document is the closed Provider Suite document shape.
type Document struct {
	SuiteID            string    `json:"suite_id"`
	SuiteVersion       string    `json:"suite_version"`
	SuiteDigestProfile string    `json:"suite_digest_profile"`
	Profiles           []Profile `json:"profiles"`
	SuiteDigest        string    `json:"suite_digest"`
}

// Profile is one ordered Suite case inventory.
type Profile struct {
	ProfileID          string   `json:"profile_id"`
	ExecutionMode      string   `json:"execution_mode"`
	MutationsPerformed *bool    `json:"mutations_performed,omitempty"`
	Tests              []string `json:"tests"`
}

// Verified is an immutable-by-convention copy of one verified Suite document.
type Verified struct {
	SuiteID            string
	SuiteVersion       string
	SuiteDigestProfile string
	SuiteDigest        string
	Profiles           []Profile
}

// Compute returns the content digest for a strict Suite document. The declared
// top-level suite_digest is validated for shape but excluded from the digest.
func Compute(document []byte, digestProfile string) (string, error) {
	_, computed, err := parse(document, digestProfile)
	if err != nil {
		return "", err
	}
	return computed, nil
}

// Verify validates a strict Suite and requires its declared digest to match its
// RFC 8785 canonical content excluding the top-level suite_digest member.
func Verify(document []byte, digestProfile string) (Verified, error) {
	parsed, computed, err := parse(document, digestProfile)
	if err != nil {
		return Verified{}, err
	}
	if parsed.SuiteDigest != computed {
		return Verified{}, fmt.Errorf("Suite digest %s does not match computed digest %s", parsed.SuiteDigest, computed)
	}
	return Verified{
		SuiteID:            parsed.SuiteID,
		SuiteVersion:       parsed.SuiteVersion,
		SuiteDigestProfile: parsed.SuiteDigestProfile,
		SuiteDigest:        parsed.SuiteDigest,
		Profiles:           cloneProfiles(parsed.Profiles),
	}, nil
}

// Load reads and verifies one bounded regular Suite file. Symlinks and other
// non-regular inputs are rejected.
func Load(path, digestProfile string) (Verified, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return Verified{}, fmt.Errorf("inspect Suite: %w", err)
	}
	if !info.Mode().IsRegular() {
		return Verified{}, errors.New("Suite must be a regular file")
	}
	if info.Size() == 0 || info.Size() > MaxDocumentBytes {
		return Verified{}, fmt.Errorf("Suite size must be between 1 and %d bytes", MaxDocumentBytes)
	}
	file, err := os.Open(path)
	if err != nil {
		return Verified{}, fmt.Errorf("open Suite: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return Verified{}, fmt.Errorf("inspect opened Suite: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return Verified{}, errors.New("Suite file changed while opening")
	}
	document, err := io.ReadAll(io.LimitReader(file, MaxDocumentBytes+1))
	if err != nil {
		return Verified{}, fmt.Errorf("read Suite: %w", err)
	}
	if len(document) > MaxDocumentBytes {
		return Verified{}, fmt.Errorf("Suite exceeds %d bytes", MaxDocumentBytes)
	}
	return Verify(document, digestProfile)
}

// RequiredProfile returns a defensive copy of the uniquely identified profile.
func (v Verified) RequiredProfile(profileID string) (Profile, error) {
	for _, profile := range v.Profiles {
		if profile.ProfileID == profileID {
			return cloneProfile(profile), nil
		}
	}
	return Profile{}, fmt.Errorf("Suite is missing required profile %q", profileID)
}

func parse(document []byte, digestProfile string) (Document, string, error) {
	if digestProfile != DigestProfile {
		return Document{}, "", fmt.Errorf("unsupported Suite digest profile %q", digestProfile)
	}
	if len(document) == 0 || len(document) > MaxDocumentBytes {
		return Document{}, "", fmt.Errorf("Suite size must be between 1 and %d bytes", MaxDocumentBytes)
	}
	if !utf8.Valid(document) {
		return Document{}, "", errors.New("Suite must be valid UTF-8")
	}
	if err := validateUnicodeEscapes(document); err != nil {
		return Document{}, "", err
	}
	canonical, err := jcs.Transform(document)
	if err != nil {
		return Document{}, "", fmt.Errorf("canonicalize Suite: %w", err)
	}
	if len(canonical) < 2 || canonical[0] != '{' || canonical[len(canonical)-1] != '}' {
		return Document{}, "", errors.New("Suite must be a JSON object")
	}

	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.DisallowUnknownFields()
	var wire struct {
		SuiteID            string `json:"suite_id"`
		SuiteVersion       string `json:"suite_version"`
		SuiteDigestProfile string `json:"suite_digest_profile"`
		Profiles           []struct {
			ProfileID          string          `json:"profile_id"`
			ExecutionMode      string          `json:"execution_mode"`
			MutationsPerformed json.RawMessage `json:"mutations_performed"`
			Tests              []string        `json:"tests"`
		} `json:"profiles"`
		SuiteDigest string `json:"suite_digest"`
	}
	if err := decoder.Decode(&wire); err != nil {
		return Document{}, "", fmt.Errorf("decode Suite: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Document{}, "", errors.New("Suite contains multiple JSON values")
		}
		return Document{}, "", fmt.Errorf("decode Suite trailer: %w", err)
	}
	parsed := Document{
		SuiteID:            wire.SuiteID,
		SuiteVersion:       wire.SuiteVersion,
		SuiteDigestProfile: wire.SuiteDigestProfile,
		SuiteDigest:        wire.SuiteDigest,
		Profiles:           make([]Profile, len(wire.Profiles)),
	}
	for index, wireProfile := range wire.Profiles {
		profile := Profile{
			ProfileID:     wireProfile.ProfileID,
			ExecutionMode: wireProfile.ExecutionMode,
			Tests:         wireProfile.Tests,
		}
		if wireProfile.MutationsPerformed != nil {
			if bytes.Equal(wireProfile.MutationsPerformed, []byte("null")) {
				return Document{}, "", fmt.Errorf("Suite profile %q mutations_performed must be a boolean", profile.ProfileID)
			}
			var mutationsPerformed bool
			if err := json.Unmarshal(wireProfile.MutationsPerformed, &mutationsPerformed); err != nil {
				return Document{}, "", fmt.Errorf("Suite profile %q mutations_performed must be a boolean", profile.ProfileID)
			}
			profile.MutationsPerformed = &mutationsPerformed
		}
		parsed.Profiles[index] = profile
	}
	if err := validate(parsed, digestProfile); err != nil {
		return Document{}, "", err
	}
	computed, err := computeCanonicalDigest(canonical)
	if err != nil {
		return Document{}, "", err
	}
	return parsed, computed, nil
}

func validate(document Document, digestProfile string) error {
	if !validIdentifier(document.SuiteID) {
		return errors.New("Suite ID must be valid, non-blank, and at most 200 characters")
	}
	if !versionPattern.MatchString(document.SuiteVersion) {
		return errors.New("Suite version must be a semantic version")
	}
	if document.SuiteDigestProfile == "" {
		return errors.New("Suite digest profile is required")
	}
	if document.SuiteDigestProfile != digestProfile {
		return fmt.Errorf("Suite digest profile %q does not match requested profile %q", document.SuiteDigestProfile, digestProfile)
	}
	if !digestPattern.MatchString(document.SuiteDigest) {
		return errors.New("Suite digest must be a lowercase SHA-256 digest")
	}
	if len(document.Profiles) == 0 || len(document.Profiles) > maxProfiles {
		return fmt.Errorf("Suite profiles count must be between 1 and %d", maxProfiles)
	}
	profileIDs := make(map[string]struct{}, len(document.Profiles))
	for profileIndex, profile := range document.Profiles {
		if !validIdentifier(profile.ProfileID) {
			return fmt.Errorf("Suite profile %d ID must be valid, non-blank, and at most 200 characters", profileIndex)
		}
		if _, duplicate := profileIDs[profile.ProfileID]; duplicate {
			return fmt.Errorf("Suite contains duplicate profile %q", profile.ProfileID)
		}
		profileIDs[profile.ProfileID] = struct{}{}
		switch profile.ExecutionMode {
		case ExecutionModeRepositoryGoTest:
			if profile.MutationsPerformed != nil && *profile.MutationsPerformed {
				return fmt.Errorf("Suite profile %q repository-go-test mode cannot perform mutations", profile.ProfileID)
			}
		case ExecutionModeRemoteHTTPBlackBox:
			if profile.MutationsPerformed == nil {
				return fmt.Errorf("Suite profile %q remote-http-black-box mode requires mutations_performed", profile.ProfileID)
			}
			if *profile.MutationsPerformed {
				return fmt.Errorf("Suite profile %q remote-http-black-box mode must set mutations_performed to false", profile.ProfileID)
			}
		default:
			return fmt.Errorf("Suite profile %q has unsupported execution mode %q", profile.ProfileID, profile.ExecutionMode)
		}
		if len(profile.Tests) == 0 || len(profile.Tests) > maxTests {
			return fmt.Errorf("Suite profile %q tests count must be between 1 and %d", profile.ProfileID, maxTests)
		}
		caseIDs := make(map[string]struct{}, len(profile.Tests))
		for testIndex, caseID := range profile.Tests {
			if !validIdentifier(caseID) {
				return fmt.Errorf("Suite profile %q test %d ID must be valid, non-blank, and at most 200 characters", profile.ProfileID, testIndex)
			}
			if _, duplicate := caseIDs[caseID]; duplicate {
				return fmt.Errorf("Suite profile %q contains duplicate case %q", profile.ProfileID, caseID)
			}
			caseIDs[caseID] = struct{}{}
		}
	}
	return nil
}

func computeCanonicalDigest(canonical []byte) (string, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(canonical, &members); err != nil {
		return "", fmt.Errorf("decode canonical Suite members: %w", err)
	}
	if _, exists := members["suite_digest"]; !exists {
		return "", errors.New("Suite digest member is required")
	}
	delete(members, "suite_digest")
	withoutDigest, err := json.Marshal(members)
	if err != nil {
		return "", fmt.Errorf("encode Suite without digest: %w", err)
	}
	canonicalWithoutDigest, err := jcs.Transform(withoutDigest)
	if err != nil {
		return "", fmt.Errorf("canonicalize Suite without digest: %w", err)
	}
	digest := sha256.Sum256(canonicalWithoutDigest)
	return "sha256:" + hex.EncodeToString(digest[:]), nil
}

func validateUnicodeEscapes(document []byte) error {
	inString := false
	for index := 0; index < len(document); index++ {
		switch document[index] {
		case '"':
			inString = !inString
		case '\\':
			if !inString || index+1 >= len(document) {
				continue
			}
			if document[index+1] != 'u' {
				index++
				continue
			}
			codePoint, ok := decodeHexQuad(document, index+2)
			if !ok {
				continue
			}
			switch {
			case codePoint >= 0xd800 && codePoint <= 0xdbff:
				if index+11 >= len(document) || document[index+6] != '\\' || document[index+7] != 'u' {
					return errors.New("Suite contains an invalid Unicode surrogate escape")
				}
				low, ok := decodeHexQuad(document, index+8)
				if !ok || low < 0xdc00 || low > 0xdfff {
					return errors.New("Suite contains an invalid Unicode surrogate escape")
				}
				index += 11
			case codePoint >= 0xdc00 && codePoint <= 0xdfff:
				return errors.New("Suite contains an invalid Unicode surrogate escape")
			default:
				index += 5
			}
		}
	}
	return nil
}

func decodeHexQuad(document []byte, start int) (uint16, bool) {
	if start+4 > len(document) {
		return 0, false
	}
	var value uint16
	for _, digit := range document[start : start+4] {
		value <<= 4
		switch {
		case digit >= '0' && digit <= '9':
			value += uint16(digit - '0')
		case digit >= 'a' && digit <= 'f':
			value += uint16(digit-'a') + 10
		case digit >= 'A' && digit <= 'F':
			value += uint16(digit-'A') + 10
		default:
			return 0, false
		}
	}
	return value, true
}

func validIdentifier(value string) bool {
	return utf8.ValidString(value) && strings.TrimSpace(value) != "" && utf8.RuneCountInString(value) <= maxIdentifierRunes
}

func cloneProfiles(profiles []Profile) []Profile {
	cloned := make([]Profile, len(profiles))
	for index, profile := range profiles {
		cloned[index] = cloneProfile(profile)
	}
	return cloned
}

func cloneProfile(profile Profile) Profile {
	cloned := Profile{
		ProfileID:     profile.ProfileID,
		ExecutionMode: profile.ExecutionMode,
		Tests:         append([]string(nil), profile.Tests...),
	}
	if profile.MutationsPerformed != nil {
		mutationsPerformed := *profile.MutationsPerformed
		cloned.MutationsPerformed = &mutationsPerformed
	}
	return cloned
}
