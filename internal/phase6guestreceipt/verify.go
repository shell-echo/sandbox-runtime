package phase6guestreceipt

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// Verify accepts only a complete, canonical, closed receipt stream from one
// actual role stdout capture. It does not by itself prove process identity or
// image provenance; the outer gate must bind those independently.
func Verify(document []byte, role, profileDigest, configDigest string) ([]Record, error) {
	if (role != "product" && role != "guest") || !validDigest(profileDigest) || !validDigest(configDigest) ||
		len(document) == 0 || len(document) > MaxTotalBytes || document[len(document)-1] != '\n' {
		return nil, ErrUnavailable
	}
	lines := bytes.Split(document[:len(document)-1], []byte{'\n'})
	if len(lines) < 2 || len(lines) > MaxEvents+2 {
		return nil, ErrUnavailable
	}
	records := make([]Record, 0, len(lines))
	previousElapsed := int64(-1)
	attempts := make(map[string]*attemptState)
	for index, line := range lines {
		if len(line) == 0 || len(line) > MaxRecordBytes {
			return nil, ErrUnavailable
		}
		record, err := decodeCanonical(line)
		if err != nil || record.Protocol != Protocol || record.Role != role ||
			record.Sequence != uint64(index+1) || record.ElapsedNanos < previousElapsed ||
			record.UnixMillis < 1_577_836_800_000 || record.UnixMillis > 4_102_444_800_000 {
			return nil, ErrUnavailable
		}
		previousElapsed = record.ElapsedNanos
		switch {
		case index == 0:
			if record.Event != "begin" || record.ProfileDigest != profileDigest || record.ConfigDigest != configDigest ||
				record.AttemptDigest != "" || record.BindingGeneration != 0 || record.Reason != "" ||
				record.EventCount != 0 || record.Dropped != 0 {
				return nil, ErrUnavailable
			}
		case index == len(lines)-1:
			if record.Event != "seal" || record.EventCount != uint64(len(lines)-2) || record.Dropped != 0 ||
				record.ProfileDigest != "" || record.ConfigDigest != "" || record.AttemptDigest != "" ||
				record.BindingGeneration != 0 || record.Reason != "" {
				return nil, ErrUnavailable
			}
		default:
			if record.ProfileDigest != "" || record.ConfigDigest != "" || record.EventCount != 0 ||
				record.Dropped != 0 || !validDigest(record.AttemptDigest) || record.BindingGeneration < 1 ||
				!validEvent(role, record.Event, record.Reason) ||
				!validAttemptTransition(attempts, role, record) {
				return nil, ErrUnavailable
			}
		}
		records = append(records, record)
	}
	return records, nil
}

func decodeCanonical(line []byte) (Record, error) {
	decoder := json.NewDecoder(bytes.NewReader(line))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return Record{}, ErrUnavailable
	}
	seen := make(map[string]bool)
	for decoder.More() {
		key, err := decoder.Token()
		name, ok := key.(string)
		if err != nil || !ok || seen[name] {
			return Record{}, ErrUnavailable
		}
		seen[name] = true
		var value json.RawMessage
		if decoder.Decode(&value) != nil {
			return Record{}, ErrUnavailable
		}
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return Record{}, ErrUnavailable
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return Record{}, ErrUnavailable
	}
	decoder = json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	var record Record
	if decoder.Decode(&record) != nil {
		return Record{}, ErrUnavailable
	}
	canonical, err := json.Marshal(record)
	if err != nil || !bytes.Equal(canonical, line) {
		return Record{}, ErrUnavailable
	}
	return record, nil
}

type attemptState struct {
	generation int64
	events     map[string]bool
}

func validAttemptTransition(attempts map[string]*attemptState, role string, record Record) bool {
	state := attempts[record.AttemptDigest]
	if state == nil {
		state = &attemptState{generation: record.BindingGeneration, events: make(map[string]bool)}
		attempts[record.AttemptDigest] = state
	}
	if state.generation != record.BindingGeneration || state.events[record.Event] {
		return false
	}
	switch role {
	case "guest":
		switch record.Event {
		case "guest_hello_written":
			if len(state.events) != 0 {
				return false
			}
		case "guest_welcome_accepted":
			if !state.events["guest_hello_written"] {
				return false
			}
		case "guest_read_terminated":
			if !state.events["guest_welcome_accepted"] {
				return false
			}
		}
	case "product":
		switch record.Event {
		case "product_validated_revoked":
			if len(state.events) != 0 {
				return false
			}
		case "product_auth_accepted":
			if len(state.events) != 0 {
				return false
			}
		case "product_welcome_written":
			if !state.events["product_auth_accepted"] {
				return false
			}
		case "product_peer_installed":
			if !state.events["product_welcome_written"] {
				return false
			}
		case "product_authority_stale", "product_close_completed":
			if !state.events["product_peer_installed"] {
				return false
			}
		}
	}
	state.events[record.Event] = true
	return true
}
