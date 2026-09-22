package workloadagent

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/secretref"
)

func EncodeRequest(request Request, now time.Time) ([]byte, error) {
	if request.Validate(now) != nil {
		return nil, secretref.ErrUnavailable
	}
	return encodeCanonical(request, maxRequestBytes)
}

func DecodeRequest(document []byte, now time.Time) (Request, error) {
	var request Request
	if decodeCanonical(document, maxRequestBytes, &request) != nil || request.Validate(now) != nil {
		return Request{}, secretref.ErrUnavailable
	}
	return request, nil
}

func EncodeResponse(response Response, request Request, now time.Time) ([]byte, error) {
	if response.Validate(request, now) != nil {
		return nil, secretref.ErrUnavailable
	}
	return encodeCanonical(response, maxResponseBytes)
}

func DecodeResponse(document []byte, request Request, now time.Time) (Response, error) {
	var response Response
	if decodeCanonical(document, maxResponseBytes, &response) != nil || response.Validate(request, now) != nil {
		clear(response.Material)
		return Response{}, secretref.ErrUnavailable
	}
	return response, nil
}

func WriteFrame(writer io.Writer, document []byte, maximum int) error {
	if writer == nil || len(document) < 1 || len(document) > maximum || maximum < 1 || maximum > maxResponseBytes {
		return secretref.ErrUnavailable
	}
	header := make([]byte, 4)
	binary.BigEndian.PutUint32(header, uint32(len(document)))
	if err := writeAll(writer, header); err != nil {
		return err
	}
	return writeAll(writer, document)
}

func ReadFrame(reader io.Reader, maximum int) ([]byte, error) {
	if reader == nil || maximum < 1 || maximum > maxResponseBytes {
		return nil, secretref.ErrUnavailable
	}
	header := make([]byte, 4)
	if _, err := io.ReadFull(reader, header); err != nil {
		return nil, secretref.ErrUnavailable
	}
	length := int(binary.BigEndian.Uint32(header))
	if length < 1 || length > maximum {
		return nil, secretref.ErrUnavailable
	}
	document := make([]byte, length)
	if _, err := io.ReadFull(reader, document); err != nil {
		clear(document)
		return nil, secretref.ErrUnavailable
	}
	return document, nil
}

func writeAll(writer io.Writer, document []byte) error {
	for written := 0; written < len(document); {
		count, err := writer.Write(document[written:])
		written += count
		if err != nil || count == 0 {
			return secretref.ErrUnavailable
		}
	}
	return nil
}

func encodeCanonical(value any, maximum int) ([]byte, error) {
	document, err := json.Marshal(value)
	if err != nil || len(document) < 1 || len(document) > maximum {
		clear(document)
		return nil, secretref.ErrUnavailable
	}
	return document, nil
}

func decodeCanonical(document []byte, maximum int, target any) error {
	if len(document) < 1 || len(document) > maximum || rejectDuplicateJSON(document) != nil {
		return secretref.ErrUnavailable
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return secretref.ErrUnavailable
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return secretref.ErrUnavailable
	}
	canonical, err := json.Marshal(target)
	if err != nil || !bytes.Equal(canonical, document) {
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
	delimiter, ok := token.(json.Delim)
	if !ok {
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
