package phase6security

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
)

const Slice6DescriptorPayloadProtocol = "sandbox-runtime.phase6-slice6-descriptor-payload.v1"

var slice6DescriptorSubjectPattern = regexp.MustCompile(`^[a-z][a-z0-9-]{0,79}$`)

// Slice6DescriptorPayload retains the exact OCI document bytes. JSON's
// canonical base64 representation of []byte does not reinterpret OCI JSON.
// The run envelope separately binds this raw payload to the run identity.
type Slice6DescriptorPayload struct {
	Protocol string `json:"protocol"`
	Kind     string `json:"kind"`
	Subject  string `json:"subject"`
	Index    []byte `json:"index,omitempty"`
	Manifest []byte `json:"manifest"`
	Config   []byte `json:"config"`
}

func NewSlice6DescriptorPayload(kind, subject string, documents ImageDescriptorDocuments) (Slice6DescriptorPayload, error) {
	value := Slice6DescriptorPayload{Protocol: Slice6DescriptorPayloadProtocol,
		Kind: kind, Subject: subject, Index: documents.Index,
		Manifest: documents.Manifest, Config: documents.Config}
	if !validSlice6DescriptorPayload(value) {
		return Slice6DescriptorPayload{}, ErrInvalidSlice6Evidence
	}
	return value, nil
}

func (p Slice6DescriptorPayload) Documents() ImageDescriptorDocuments {
	return ImageDescriptorDocuments{Index: p.Index, Manifest: p.Manifest, Config: p.Config}
}

func (p Slice6DescriptorPayload) Encode() ([]byte, error) {
	if !validSlice6DescriptorPayload(p) {
		return nil, ErrInvalidSlice6Evidence
	}
	document, err := json.Marshal(p)
	if err != nil || len(document) > maxSlice6ReceiptSize {
		return nil, ErrInvalidSlice6Evidence
	}
	return document, nil
}

func DecodeSlice6DescriptorPayload(document []byte) (Slice6DescriptorPayload, error) {
	if len(document) < 1 || len(document) > maxSlice6ReceiptSize || rejectDuplicateMembers(document) != nil {
		return Slice6DescriptorPayload{}, ErrInvalidSlice6Evidence
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var value Slice6DescriptorPayload
	if decoder.Decode(&value) != nil || !errors.Is(decoder.Decode(new(any)), io.EOF) ||
		!validSlice6DescriptorPayload(value) {
		return Slice6DescriptorPayload{}, ErrInvalidSlice6Evidence
	}
	canonical, err := json.Marshal(value)
	if err != nil || !bytes.Equal(canonical, document) {
		return Slice6DescriptorPayload{}, ErrInvalidSlice6Evidence
	}
	return value, nil
}

func validSlice6DescriptorPayload(value Slice6DescriptorPayload) bool {
	return value.Protocol == Slice6DescriptorPayloadProtocol &&
		(value.Kind == "container" || value.Kind == "external") &&
		slice6DescriptorSubjectPattern.MatchString(value.Subject) &&
		len(value.Index) <= 4<<20 && len(value.Manifest) > 0 && len(value.Manifest) <= 4<<20 &&
		len(value.Config) > 0 && len(value.Config) <= 4<<20
}
