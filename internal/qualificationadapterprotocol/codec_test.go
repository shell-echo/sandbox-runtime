package qualificationadapterprotocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"strings"
	"testing"
)

func TestCodecDecodesExactBoundedInvocation(t *testing.T) {
	codec := loadCodecForTest(t)
	document := marshalProtocolValue(t, invocationExampleForSchemaTest())
	document = padJSONDocument(t, document, int(MaxInvocationBytes))

	message, err := codec.DecodeInvocation(bytes.NewReader(document))
	if err != nil {
		t.Fatalf("DecodeInvocation(exact limit) error = %v", err)
	}
	if message.MessageType != "invocation" || message.Sequence != nil || message.InvocationID == nil ||
		*message.InvocationID != "invocation-initial" || message.Phase == nil || *message.Phase != "initial" ||
		message.DocumentBytes != MaxInvocationBytes || message.WireBytes != MaxInvocationBytes || !bytes.Equal(message.Document, document) {
		t.Fatalf("unexpected decoded invocation: %+v", message)
	}

	overLimit := append(append([]byte(nil), document...), ' ')
	_, err = codec.DecodeInvocation(bytes.NewReader(overLimit))
	assertDecodeFailureValue(t, err, DecodeFailureInvocationLimit)
}

func TestCodecRejectsInvalidInvocationDocuments(t *testing.T) {
	codec := loadCodecForTest(t)
	valid := marshalProtocolValue(t, invocationExampleForSchemaTest())
	duplicate := bytes.Replace(valid, []byte(`"invocation_id":"invocation-initial"`), []byte(`"invocation_id":"duplicate","invocation_id":"invocation-initial"`), 1)
	if bytes.Equal(duplicate, valid) {
		t.Fatal("duplicate-member fixture did not change the invocation")
	}
	unknownValue := cloneMap(invocationExampleForSchemaTest())
	unknownValue["private_path"] = "/must-not-appear-in-error"
	wrongDirection := marshalProtocolValue(t, startupIdentityForCodecTest())
	wrongDirectionAndAuthority := startupIdentityForCodecTest()
	wrongDirectionAndAuthority["protocol_semantics_digest"] = "sha256:" + strings.Repeat("f", 64)

	tests := []struct {
		name    string
		content []byte
		want    DecodeFailure
	}{
		{name: "empty", content: nil, want: DecodeFailureInvalidJSON},
		{name: "invalid utf8", content: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}, want: DecodeFailureInvalidEncoding},
		{name: "duplicate member", content: duplicate, want: DecodeFailureInvalidJSON},
		{name: "unpaired surrogate", content: []byte(`{"message_type":"invocation","value":"\ud800"}`), want: DecodeFailureInvalidJSON},
		{name: "multiple values", content: append(append([]byte(nil), valid...), []byte(` {}`)...), want: DecodeFailureInvalidJSON},
		{name: "unknown field", content: marshalProtocolValue(t, unknownValue), want: DecodeFailureSchema},
		{name: "wrong direction", content: wrongDirection, want: DecodeFailureDirection},
		{name: "direction precedes authority", content: marshalProtocolValue(t, wrongDirectionAndAuthority), want: DecodeFailureDirection},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := codec.DecodeInvocation(bytes.NewReader(test.content))
			assertDecodeFailureValue(t, err, test.want)
			if strings.Contains(err.Error(), "/must-not-appear-in-error") {
				t.Fatal("decode error leaked an invocation field value")
			}
		})
	}
}

func TestOutputDecoderAcceptsSchemaValidRecordsAndExactRecordLimit(t *testing.T) {
	codec := loadCodecForTest(t)
	startup := append(marshalProtocolValue(t, startupIdentityForCodecTest()), '\n')
	acceptedDocument := marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil))
	acceptedDocument = padJSONDocument(t, acceptedDocument, int(MaxAdapterOutputRecordBytes))
	accepted := append(append([]byte(nil), acceptedDocument...), '\n')
	stream := append(append([]byte(nil), startup...), accepted...)
	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))

	first, err := decoder.Next()
	if err != nil || first.MessageType != "startup_identity" || first.Sequence == nil || *first.Sequence != 0 {
		t.Fatalf("decode startup = %+v, %v", first, err)
	}
	second, err := decoder.Next()
	if err != nil {
		t.Fatalf("decode exact-limit record: %v", err)
	}
	if second.MessageType != "invocation_accepted" || second.DocumentBytes != MaxAdapterOutputRecordBytes || second.WireBytes != MaxAdapterOutputRecordBytes+1 {
		t.Fatalf("unexpected exact-limit record: %+v", second)
	}
	if _, err := decoder.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next after complete stream = %v, want EOF", err)
	}
	if decoder.Records() != 2 || decoder.TotalWireBytes() != int64(len(stream)) {
		t.Fatalf("unexpected counters: records=%d bytes=%d", decoder.Records(), decoder.TotalWireBytes())
	}

	overLimitDocument := padJSONDocument(t, marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil)), int(MaxAdapterOutputRecordBytes+1))
	overLimit := append(overLimitDocument, '\n')
	overLimitDecoder := codec.NewOutputDecoder(bytes.NewReader(overLimit))
	_, err = overLimitDecoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureOutputRecord)
}

func TestOutputDecoderEnforcesExactStdoutTotal(t *testing.T) {
	codec := loadCodecForTest(t)
	base := marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil))
	fullDocument := padJSONDocument(t, base, int(MaxAdapterOutputRecordBytes))
	fullRecord := append(append([]byte(nil), fullDocument...), '\n')
	const fullRecordCount = 31
	remaining := int(MaxAdapterStdoutBytes) - fullRecordCount*len(fullRecord)
	lastDocument := padJSONDocument(t, base, remaining-1)
	lastRecord := append(append([]byte(nil), lastDocument...), '\n')
	stream := make([]byte, 0, MaxAdapterStdoutBytes)
	for range fullRecordCount {
		stream = append(stream, fullRecord...)
	}
	stream = append(stream, lastRecord...)
	if int64(len(stream)) != MaxAdapterStdoutBytes {
		t.Fatalf("test stream bytes = %d", len(stream))
	}

	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))
	for index := 0; index < fullRecordCount+1; index++ {
		if _, err := decoder.Next(); err != nil {
			t.Fatalf("Next(%d) at exact total limit: %v", index, err)
		}
	}
	if _, err := decoder.Next(); !errors.Is(err, io.EOF) {
		t.Fatalf("Next after exact total limit = %v, want EOF", err)
	}

	overLimitDecoder := codec.NewOutputDecoder(bytes.NewReader(append(append([]byte(nil), stream...), 'x')))
	for index := 0; index < fullRecordCount+1; index++ {
		if _, err := overLimitDecoder.Next(); err != nil {
			t.Fatalf("Next(%d) before total overflow: %v", index, err)
		}
	}
	_, err := overLimitDecoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureOutputTotal)
	if overLimitDecoder.TotalWireBytes() != MaxAdapterStdoutBytes+1 {
		t.Fatalf("overflow byte count = %d", overLimitDecoder.TotalWireBytes())
	}
}

func TestOutputDecoderEnforcesRecordCountBeforeRecordShape(t *testing.T) {
	codec := loadCodecForTest(t)
	record := append(marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil)), '\n')
	stream := bytes.Repeat(record, MaxAdapterOutputRecords)
	stream = append(stream, 'x')
	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))
	for index := 0; index < MaxAdapterOutputRecords; index++ {
		if _, err := decoder.Next(); err != nil {
			t.Fatalf("Next(%d) before record-count limit: %v", index, err)
		}
	}
	_, err := decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureOutputRecordCount)
	if decoder.Records() != MaxAdapterOutputRecords {
		t.Fatalf("record count = %d", decoder.Records())
	}
}

func TestOutputDecoderRejectsInvalidFramingJSONSchemaDirectionAndAuthority(t *testing.T) {
	codec := loadCodecForTest(t)
	valid := marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil))
	unknown := outputExample("invocation_accepted", 1, map[string]any{"private_path": "/must-not-appear-in-error"})
	wrongAuthority := startupIdentityForCodecTest()
	wrongAuthority["protocol_semantics_digest"] = "sha256:" + strings.Repeat("f", 64)

	tests := []struct {
		name   string
		stream []byte
		want   DecodeFailure
	}{
		{name: "missing lf", stream: valid, want: DecodeFailureInvalidFraming},
		{name: "empty record", stream: []byte{'\n'}, want: DecodeFailureInvalidFraming},
		{name: "crlf", stream: append(append([]byte(nil), valid...), '\r', '\n'), want: DecodeFailureInvalidFraming},
		{name: "invalid utf8", stream: []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}', '\n'}, want: DecodeFailureInvalidEncoding},
		{name: "unpaired surrogate", stream: []byte("{\"message_type\":\"invocation_accepted\",\"value\":\"\\udfff\"}\n"), want: DecodeFailureInvalidJSON},
		{name: "schema", stream: append(marshalProtocolValue(t, unknown), '\n'), want: DecodeFailureSchema},
		{name: "wrong direction", stream: append(marshalProtocolValue(t, invocationExampleForSchemaTest()), '\n'), want: DecodeFailureDirection},
		{name: "authority", stream: append(marshalProtocolValue(t, wrongAuthority), '\n'), want: DecodeFailureAuthority},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			decoder := codec.NewOutputDecoder(bytes.NewReader(test.stream))
			_, err := decoder.Next()
			assertDecodeFailureValue(t, err, test.want)
			_, repeated := decoder.Next()
			if repeated != err {
				t.Fatalf("decoder did not retain first failure: first=%v repeated=%v", err, repeated)
			}
			if strings.Contains(err.Error(), "/must-not-appear-in-error") {
				t.Fatal("decode error leaked an adapter output field value")
			}
		})
	}
}

func TestOutputDecoderRejectsCarriageReturnAwayFromDelimiter(t *testing.T) {
	codec := loadCodecForTest(t)
	document := marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil))
	document = append([]byte{'{', '\r'}, document[1:]...)
	decoder := codec.NewOutputDecoder(bytes.NewReader(append(document, '\n')))
	_, err := decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureInvalidFraming)
}

func TestCodecRejectsUnavailableReaders(t *testing.T) {
	codec := loadCodecForTest(t)
	_, err := codec.DecodeInvocation(nil)
	assertDecodeFailureValue(t, err, DecodeFailureIO)

	decoder := codec.NewOutputDecoder(nil)
	_, err = decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureIO)
}

func TestNewCodecHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := NewCodec(ctx, "../.."); !errors.Is(err, context.Canceled) {
		t.Fatalf("NewCodec(canceled context) = %v", err)
	}
}

func TestCodecAppliesByteLimitsBeforeStreamErrors(t *testing.T) {
	codec := loadCodecForTest(t)
	readFailure := errors.New("private reader failure")

	_, err := codec.DecodeInvocation(&terminalErrorReader{
		data: bytes.Repeat([]byte{'x'}, int(MaxInvocationBytes+1)),
		err:  readFailure,
	})
	assertDecodeFailureValue(t, err, DecodeFailureInvocationLimit)

	partial := bytes.Repeat([]byte{'x'}, int(MaxAdapterOutputRecordBytes+1))
	decoder := codec.NewOutputDecoder(&terminalErrorReader{data: partial, err: readFailure})
	_, err = decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureOutputRecord)
	if decoder.TotalWireBytes() != int64(len(partial)) {
		t.Fatalf("partial record byte count = %d, want %d", decoder.TotalWireBytes(), len(partial))
	}
}

func TestCodecSanitizesStreamErrorsAfterObservedBytes(t *testing.T) {
	codec := loadCodecForTest(t)
	readFailure := errors.New("/private/reader/diagnostic")
	partial := []byte(`{"message_type":`)

	_, err := codec.DecodeInvocation(&terminalErrorReader{data: partial, err: readFailure})
	assertDecodeFailureValue(t, err, DecodeFailureIO)
	if strings.Contains(err.Error(), readFailure.Error()) {
		t.Fatal("invocation decode error leaked reader diagnostics")
	}

	decoder := codec.NewOutputDecoder(&terminalErrorReader{data: partial, err: readFailure})
	_, err = decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureIO)
	if strings.Contains(err.Error(), readFailure.Error()) {
		t.Fatal("output decode error leaked reader diagnostics")
	}
}

func TestOutputDecoderCountsCompleteRejectedRecord(t *testing.T) {
	codec := loadCodecForTest(t)
	decoder := codec.NewOutputDecoder(bytes.NewReader([]byte("{}\n")))
	_, err := decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureSchema)
	if decoder.Records() != 1 || decoder.TotalWireBytes() != 3 {
		t.Fatalf("rejected record counters: records=%d bytes=%d", decoder.Records(), decoder.TotalWireBytes())
	}
}

func TestOutputDecoderCountsTruncatedBytes(t *testing.T) {
	codec := loadCodecForTest(t)
	record := append(marshalProtocolValue(t, outputExample("invocation_accepted", 1, nil)), '\n')
	stream := append(append([]byte(nil), record...), []byte("truncated")...)
	decoder := codec.NewOutputDecoder(bytes.NewReader(stream))
	if _, err := decoder.Next(); err != nil {
		t.Fatal(err)
	}
	_, err := decoder.Next()
	assertDecodeFailureValue(t, err, DecodeFailureInvalidFraming)
	if decoder.TotalWireBytes() != int64(len(stream)) {
		t.Fatalf("truncated byte count = %d, want %d", decoder.TotalWireBytes(), len(stream))
	}
}

func TestDecodeStrictValueAcceptsPairedUnicodeSurrogateEscape(t *testing.T) {
	if _, err := decodeStrictValue([]byte(`{"value":"\ud83d\ude00"}`)); err != nil {
		t.Fatalf("decodeStrictValue(valid surrogate pair) error = %v", err)
	}
}

func loadCodecForTest(t *testing.T) *Codec {
	t.Helper()
	codec, err := NewCodec(context.Background(), "../..")
	if err != nil {
		t.Fatal(err)
	}
	return codec
}

func marshalProtocolValue(t *testing.T, value map[string]any) []byte {
	t.Helper()
	document, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return document
}

func padJSONDocument(t *testing.T, document []byte, size int) []byte {
	t.Helper()
	if len(document) > size {
		t.Fatalf("document length %d exceeds requested size %d", len(document), size)
	}
	result := make([]byte, 0, size)
	result = append(result, document...)
	result = append(result, bytes.Repeat([]byte{' '}, size-len(document))...)
	return result
}

func startupIdentityForCodecTest() map[string]any {
	release := map[string]any{"kind": "source-revision", "value": strings.Repeat("a", 40), "immutable": true}
	return map[string]any{
		"format_version":                      float64(1),
		"protocol_id":                         ProtocolID,
		"protocol_version":                    ProtocolVersion,
		"message_type":                        "startup_identity",
		"sequence":                            float64(0),
		"protocol_schema_digest":              ExpectedProtocolSchemaDigest,
		"protocol_semantics_digest":           ExpectedProtocolSemanticsDigest,
		"caller_release_identity":             release,
		"adapter_release_identity":            release,
		"contract_revision":                   "9206e601f75a54db0b66969239d7e8cc5bcc8af9",
		"contract_tree":                       "c5e4221f2ceaaaad53c8038e1ebaacfe0c5a4daf",
		"profile_id":                          "sandbox-runtime-external-caller-coding-shell-v1",
		"profile_version":                     "1.0.0",
		"profile_digest":                      "sha256:baee769c0acc395448af61faef99cd97fbb63ccb83c70eb51915952be519991a",
		"expected_values_injected_by_harness": false,
		"credential_channel_requirements": []any{map[string]any{
			"channel_id": "controller-a-provider", "role": "provider_credentials", "actor": "controller_a",
			"media_type": "application/vnd.example.credentials+json", "max_bytes": float64(4096),
		}},
	}
}

func assertDecodeFailureValue(t *testing.T, err error, want DecodeFailure) {
	t.Helper()
	if got, ok := DecodeFailureOf(err); !ok || got != want {
		t.Fatalf("DecodeFailureOf(%v) = %q, %v; want %q", err, got, ok, want)
	}
}

type terminalErrorReader struct {
	data []byte
	err  error
}

func (r *terminalErrorReader) Read(buffer []byte) (int, error) {
	if len(r.data) == 0 {
		return 0, r.err
	}
	count := copy(buffer, r.data)
	r.data = r.data[count:]
	if len(r.data) == 0 {
		return count, r.err
	}
	return count, nil
}
