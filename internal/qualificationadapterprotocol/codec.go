package qualificationadapterprotocol

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"unicode/utf8"

	"github.com/santhosh-tekuri/jsonschema/v6"
	"github.com/shell-echo/sandbox-runtime/internal/qualificationreport"
)

const (
	MaxInvocationBytes           int64 = 32768
	MaxAdapterOutputRecordBytes  int64 = 65536
	MaxAdapterOutputRecords      int   = 33
	MaxAdapterStdoutBytes        int64 = 2097152
	MaxAdapterStderrBytes        int64 = 262144
	MaxCredentialChannels        int   = 8
	MaxCredentialChannelBytes    int64 = 1048576
	MaxCredentialTotalBytes      int64 = 4194304
	outputDecoderReadBufferBytes       = MaxAdapterOutputRecordBytes + 2
)

// DecodeFailure is a stable, sanitized codec failure classification. It never
// includes raw protocol data, paths, endpoints, or adapter diagnostics.
type DecodeFailure string

const (
	DecodeFailureInvalidEncoding   DecodeFailure = "invalid-encoding"
	DecodeFailureInvalidJSON       DecodeFailure = "invalid-json"
	DecodeFailureInvalidFraming    DecodeFailure = "invalid-framing"
	DecodeFailureInvocationLimit   DecodeFailure = "invocation-byte-limit-exceeded"
	DecodeFailureOutputRecord      DecodeFailure = "output-record-byte-limit-exceeded"
	DecodeFailureOutputRecordCount DecodeFailure = "output-record-count-limit-exceeded"
	DecodeFailureOutputTotal       DecodeFailure = "output-total-byte-limit-exceeded"
	DecodeFailureSchema            DecodeFailure = "schema-violation"
	DecodeFailureDirection         DecodeFailure = "message-direction-violation"
	DecodeFailureAuthority         DecodeFailure = "protocol-authority-mismatch"
	DecodeFailureIO                DecodeFailure = "io-failure"
)

// DecodeError deliberately exposes only a bounded classification. The
// underlying JSON Schema error can contain invocation values and is therefore
// not retained.
type DecodeError struct {
	Failure DecodeFailure
}

func (e *DecodeError) Error() string {
	return "adapter protocol decode failed: " + string(e.Failure)
}

// DecodeFailureOf returns the stable failure classification for a codec error.
func DecodeFailureOf(err error) (DecodeFailure, bool) {
	var decodeErr *DecodeError
	if !errors.As(err, &decodeErr) {
		return "", false
	}
	return decodeErr.Failure, true
}

func decodeFailure(failure DecodeFailure) error {
	return &DecodeError{Failure: failure}
}

// DecodedMessage is the schema-validated protocol envelope plus the exact JSON
// document bytes. Document can contain untrusted paths, endpoints, and other
// private protocol data and must not be logged or copied into evidence.
// DocumentBytes excludes an adapter-output LF delimiter; WireBytes includes
// every byte consumed for this invocation or output record.
type DecodedMessage struct {
	MessageType             string
	Sequence                *int
	InvocationID            *string
	Phase                   *string
	CaseID                  *string
	Document                json.RawMessage
	DocumentBytes           int64
	WireBytes               int64
	protocolSchemaDigest    *string
	protocolSemanticsDigest *string
	disposition             *string
	completion              *string
	errorCode               *string
	terminal                *bool
	validatedBy             *Codec
	outputDecoder           *OutputDecoder
	direction               decodedMessageDirection
	documentDigest          [sha256.Size]byte
}

type decodedMessageDirection uint8

const (
	decodedHarnessToAdapter decodedMessageDirection = iota + 1
	decodedAdapterToHarness
)

// Codec validates the locked protocol schema and direction-specific message
// boundaries. It does not validate message order or launch a process.
type Codec struct {
	schema           *jsonschema.Schema
	transcriptSchema *jsonschema.Schema
	caseOrder        map[string][]string
}

// NewCodec verifies all P2.7c.1 authorities before compiling the schema used by
// the runtime-independent P2.7c.2 codec.
func NewCodec(ctx context.Context, sourceRoot string) (*Codec, error) {
	definition, err := VerifyDefinition(ctx, sourceRoot)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	protocolDocument, err := readRepositoryFile(sourceRoot, ProtocolSchemaPath, maxDefinitionBytes)
	if err != nil || rawDigest(protocolDocument) != ExpectedProtocolSchemaDigest {
		return nil, errors.New("load locked adapter protocol schema")
	}
	semanticsDocument, err := readRepositoryFile(sourceRoot, ProtocolSemanticsPath, maxDefinitionBytes)
	if err != nil || rawDigest(semanticsDocument) != ExpectedProtocolSemanticsDigest {
		return nil, errors.New("load locked adapter protocol semantics")
	}
	reportDocument, err := readRepositoryFile(sourceRoot, qualificationreport.ReportSchemaPath, maxDefinitionBytes)
	if err != nil || rawDigest(reportDocument) != qualificationreport.ExpectedReportSchemaDigest {
		return nil, errors.New("load locked qualification report schema")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	schema, err := compileProtocolSchema(protocolDocument, reportDocument)
	if err != nil {
		return nil, err
	}
	transcriptDocument, err := readRepositoryFile(sourceRoot, TranscriptSchemaPath, maxDefinitionBytes)
	if err != nil || rawDigest(transcriptDocument) != ExpectedTranscriptSchemaDigest {
		return nil, errors.New("load locked adapter transcript schema")
	}
	transcriptSchema, err := compileTranscriptSchema(transcriptDocument)
	if err != nil {
		return nil, err
	}
	return &Codec{schema: schema, transcriptSchema: transcriptSchema, caseOrder: cloneCaseOrder(definition.caseOrder)}, nil
}

func (c *Codec) orderedCaseIDs(phaseID string) ([]string, bool) {
	if c == nil {
		return nil, false
	}
	cases, ok := c.caseOrder[phaseID]
	if !ok || len(cases) == 0 {
		return nil, false
	}
	return append([]string(nil), cases...), true
}

func cloneCaseOrder(value map[string][]string) map[string][]string {
	cloned := make(map[string][]string, len(value))
	for phaseID, cases := range value {
		cloned[phaseID] = append([]string(nil), cases...)
	}
	return cloned
}

// DecodeInvocation reads exactly one EOF-framed harness-to-adapter invocation.
// All bytes, including legal JSON whitespace, count toward MaxInvocationBytes.
func (c *Codec) DecodeInvocation(reader io.Reader) (DecodedMessage, error) {
	if c == nil || c.schema == nil || reader == nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureIO)
	}
	document, err := io.ReadAll(io.LimitReader(reader, MaxInvocationBytes+1))
	if int64(len(document)) > MaxInvocationBytes {
		return DecodedMessage{}, decodeFailure(DecodeFailureInvocationLimit)
	}
	if err != nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureIO)
	}
	message, err := c.decodeDocument(document, int64(len(document)))
	if err != nil {
		return DecodedMessage{}, err
	}
	if !messageTypeAllowed(message.MessageType, harnessToAdapterMessageTypes) {
		return DecodedMessage{}, decodeFailure(DecodeFailureDirection)
	}
	message.validatedBy = c
	message.direction = decodedHarnessToAdapter
	return message, nil
}

// OutputDecoder reads LF-delimited adapter-to-harness records. A clean EOF is
// returned as io.EOF; a non-empty final fragment without LF is invalid framing.
type OutputDecoder struct {
	codec          *Codec
	reader         *bufio.Reader
	records        int
	totalWireBytes int64
	failure        error
	eof            bool
}

// NewOutputDecoder creates one decoder for one adapter process stdout stream.
func (c *Codec) NewOutputDecoder(reader io.Reader) *OutputDecoder {
	decoder := &OutputDecoder{codec: c}
	if c == nil || c.schema == nil || reader == nil {
		decoder.failure = decodeFailure(DecodeFailureIO)
		return decoder
	}
	limited := &io.LimitedReader{R: reader, N: MaxAdapterStdoutBytes + 1}
	decoder.reader = bufio.NewReaderSize(limited, int(outputDecoderReadBufferBytes))
	return decoder
}

// Records returns the number of complete LF-terminated records observed,
// including a complete record that was subsequently rejected.
func (d *OutputDecoder) Records() int {
	if d == nil {
		return 0
	}
	return d.records
}

// TotalWireBytes returns bytes consumed from complete or partial records,
// including LF delimiters and invalid or truncated bytes.
func (d *OutputDecoder) TotalWireBytes() int64 {
	if d == nil {
		return 0
	}
	return d.totalWireBytes
}

// Next returns the next independently schema-valid adapter output record.
// PhaseStateMachine separately enforces the implemented startup, invocation,
// sequence, binding, case-order, terminal, and EOF state.
func (d *OutputDecoder) Next() (DecodedMessage, error) {
	if d == nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureIO)
	}
	if d.failure != nil {
		return DecodedMessage{}, d.failure
	}
	if d.eof {
		return DecodedMessage{}, io.EOF
	}
	if d.records >= MaxAdapterOutputRecords {
		return d.readBeyondRecordLimit()
	}

	record, err := d.reader.ReadSlice('\n')
	d.totalWireBytes += int64(len(record))
	if d.totalWireBytes > MaxAdapterStdoutBytes {
		return DecodedMessage{}, d.fail(DecodeFailureOutputTotal)
	}
	if errors.Is(err, bufio.ErrBufferFull) {
		return DecodedMessage{}, d.fail(DecodeFailureOutputRecord)
	}
	if err != nil && int64(len(record)) > MaxAdapterOutputRecordBytes {
		return DecodedMessage{}, d.fail(DecodeFailureOutputRecord)
	}
	if errors.Is(err, io.EOF) {
		if len(record) == 0 {
			d.eof = true
			return DecodedMessage{}, io.EOF
		}
		return DecodedMessage{}, d.fail(DecodeFailureInvalidFraming)
	}
	if err != nil {
		return DecodedMessage{}, d.fail(DecodeFailureIO)
	}

	d.records++
	document := record[:len(record)-1]
	if int64(len(document)) > MaxAdapterOutputRecordBytes {
		return DecodedMessage{}, d.fail(DecodeFailureOutputRecord)
	}
	if len(document) == 0 || bytes.IndexByte(document, '\r') >= 0 {
		return DecodedMessage{}, d.fail(DecodeFailureInvalidFraming)
	}
	message, err := d.codec.decodeDocument(document, int64(len(record)))
	if err != nil {
		d.failure = err
		return DecodedMessage{}, err
	}
	if !messageTypeAllowed(message.MessageType, adapterToHarnessMessageTypes) {
		return DecodedMessage{}, d.fail(DecodeFailureDirection)
	}
	if message.MessageType == "startup_identity" &&
		(message.protocolSchemaDigest == nil || *message.protocolSchemaDigest != ExpectedProtocolSchemaDigest ||
			message.protocolSemanticsDigest == nil || *message.protocolSemanticsDigest != ExpectedProtocolSemanticsDigest) {
		return DecodedMessage{}, d.fail(DecodeFailureAuthority)
	}
	message.validatedBy = d.codec
	message.outputDecoder = d
	message.direction = decodedAdapterToHarness
	return message, nil
}

func (d *OutputDecoder) readBeyondRecordLimit() (DecodedMessage, error) {
	value, err := d.reader.ReadByte()
	if err != nil {
		if errors.Is(err, io.EOF) {
			d.eof = true
			return DecodedMessage{}, io.EOF
		}
		return DecodedMessage{}, d.fail(DecodeFailureIO)
	}
	_ = value
	d.totalWireBytes++
	if d.totalWireBytes > MaxAdapterStdoutBytes {
		return DecodedMessage{}, d.fail(DecodeFailureOutputTotal)
	}
	return DecodedMessage{}, d.fail(DecodeFailureOutputRecordCount)
}

func (d *OutputDecoder) fail(failure DecodeFailure) error {
	d.failure = decodeFailure(failure)
	return d.failure
}

func (c *Codec) decodeDocument(document []byte, wireBytes int64) (DecodedMessage, error) {
	if len(document) == 0 {
		return DecodedMessage{}, decodeFailure(DecodeFailureInvalidJSON)
	}
	if !utf8.Valid(document) {
		return DecodedMessage{}, decodeFailure(DecodeFailureInvalidEncoding)
	}
	value, err := decodeStrictValue(document)
	if err != nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureInvalidJSON)
	}
	object, ok := value.(map[string]any)
	if !ok || object == nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureSchema)
	}
	if err := c.schema.Validate(object); err != nil {
		return DecodedMessage{}, decodeFailure(DecodeFailureSchema)
	}
	messageType, ok := object["message_type"].(string)
	if !ok {
		return DecodedMessage{}, decodeFailure(DecodeFailureSchema)
	}
	message := DecodedMessage{
		MessageType:             messageType,
		InvocationID:            optionalString(object["invocation_id"]),
		Phase:                   optionalString(object["phase"]),
		CaseID:                  optionalString(object["case_id"]),
		Document:                append(json.RawMessage(nil), document...),
		DocumentBytes:           int64(len(document)),
		WireBytes:               wireBytes,
		protocolSchemaDigest:    optionalString(object["protocol_schema_digest"]),
		protocolSemanticsDigest: optionalString(object["protocol_semantics_digest"]),
		disposition:             optionalString(object["disposition"]),
		completion:              optionalString(object["completion"]),
		errorCode:               optionalString(object["error_code"]),
		terminal:                optionalBool(object["terminal"]),
		documentDigest:          sha256.Sum256(document),
	}
	if sequence, present := object["sequence"].(float64); present {
		converted := int(sequence)
		message.Sequence = &converted
	}
	return message, nil
}

func optionalString(value any) *string {
	text, ok := value.(string)
	if !ok {
		return nil
	}
	return &text
}

func optionalBool(value any) *bool {
	flag, ok := value.(bool)
	if !ok {
		return nil
	}
	return &flag
}

func messageTypeAllowed(messageType string, allowed []string) bool {
	for _, candidate := range allowed {
		if messageType == candidate {
			return true
		}
	}
	return false
}
