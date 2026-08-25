package admission

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/gowebpki/jcs"
)

const (
	maxAdmissionDocumentBytes = 1 << 20
	maxAdmissionJSONDepth     = 64
	maxAdmissionNumberBytes   = 128
	maxSafeJSONInteger        = 9007199254740991
)

var (
	ErrInvalidRequestDocument = errors.New("provider admission request document is invalid")
	ErrRequestDigestMismatch  = errors.New("provider admission request digest does not match")
)

// VerifyRequestDigest verifies a token request digest against one bounded,
// strict-I-JSON document. Request-excluding profiles additionally require the
// document's top-level request_digest to equal the verified token digest.
func VerifyRequestDigest(profile DigestProfile, expectedDigest string, document []byte) error {
	if !profile.Supported() || !digestPattern.MatchString(expectedDigest) {
		return ErrInvalidRequestDocument
	}
	canonical, err := canonicalAdmissionDocument(document)
	if err != nil {
		return ErrInvalidRequestDocument
	}
	if profile == DigestProfileRequestExcludingDigest {
		canonical, err = canonicalWithoutRequestDigest(canonical, expectedDigest)
		if err != nil {
			if errors.Is(err, ErrRequestDigestMismatch) {
				return ErrRequestDigestMismatch
			}
			return ErrInvalidRequestDocument
		}
	}
	if canonicalSHA256(canonical) != expectedDigest {
		return ErrRequestDigestMismatch
	}
	return nil
}

func canonicalAdmissionDocument(document []byte) ([]byte, error) {
	if len(document) == 0 || len(document) > maxAdmissionDocumentBytes || !utf8.Valid(document) {
		return nil, ErrInvalidRequestDocument
	}
	if err := validateStrictJSON(document); err != nil {
		return nil, err
	}
	canonical, err := jcs.Transform(document)
	if err != nil || len(canonical) < 2 || canonical[0] != '{' || canonical[len(canonical)-1] != '}' {
		return nil, ErrInvalidRequestDocument
	}
	return canonical, nil
}

func canonicalWithoutRequestDigest(canonical []byte, expectedDigest string) ([]byte, error) {
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var document map[string]json.RawMessage
	if err := decoder.Decode(&document); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, ErrInvalidRequestDocument
	}
	encodedDigest, ok := document["request_digest"]
	if !ok {
		return nil, ErrInvalidRequestDocument
	}
	var requestDigest string
	if err := json.Unmarshal(encodedDigest, &requestDigest); err != nil || !digestPattern.MatchString(requestDigest) {
		return nil, ErrInvalidRequestDocument
	}
	if requestDigest != expectedDigest {
		return nil, ErrRequestDigestMismatch
	}
	delete(document, "request_digest")
	withoutDigest, err := json.Marshal(document)
	if err != nil {
		return nil, err
	}
	return jcs.Transform(withoutDigest)
}

func canonicalSHA256(canonical []byte) string {
	digest := sha256.Sum256(canonical)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func validateStrictJSON(document []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.UseNumber()

	depth := 0
	started := false
	complete := false
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return err
		}
		if complete {
			return ErrInvalidRequestDocument
		}
		switch value := token.(type) {
		case json.Delim:
			switch value {
			case '{', '[':
				if depth == 0 && started {
					return ErrInvalidRequestDocument
				}
				started = true
				depth++
				if depth > maxAdmissionJSONDepth {
					return ErrInvalidRequestDocument
				}
			case '}', ']':
				if depth == 0 {
					return ErrInvalidRequestDocument
				}
				depth--
				if depth == 0 {
					complete = true
				}
			}
		case json.Number:
			if err := validateStrictJSONNumber(value); err != nil {
				return err
			}
			if depth == 0 {
				if started {
					return ErrInvalidRequestDocument
				}
				started = true
				complete = true
			}
		default:
			if depth == 0 {
				if started {
					return ErrInvalidRequestDocument
				}
				started = true
				complete = true
			}
		}
	}
	if !started || !complete || depth != 0 {
		return ErrInvalidRequestDocument
	}
	return nil
}

func validateStrictJSONNumber(number json.Number) error {
	encoded := number.String()
	if len(encoded) == 0 || len(encoded) > maxAdmissionNumberBytes {
		return ErrInvalidRequestDocument
	}
	if exponent := strings.IndexAny(encoded, "eE"); exponent >= 0 {
		exponentDigits := strings.TrimPrefix(strings.TrimPrefix(encoded[exponent+1:], "+"), "-")
		if len(exponentDigits) == 0 || len(exponentDigits) > 4 {
			return ErrInvalidRequestDocument
		}
	}
	value, err := strconv.ParseFloat(encoded, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return ErrInvalidRequestDocument
	}
	if _, err := jcs.NumberToJSON(value); err != nil {
		return ErrInvalidRequestDocument
	}
	if math.Trunc(value) == value && math.Abs(value) > maxSafeJSONInteger {
		return ErrInvalidRequestDocument
	}
	return nil
}
