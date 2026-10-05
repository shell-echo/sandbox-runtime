package staging

import (
	"context"
	"encoding/json"
	"errors"
	"unicode/utf8"

	"github.com/shell-echo/sandbox-runtime/provider/artifact"
)

// passive-json-v1 accepts data, not executable or renderable document formats.
// The total document bound remains the Provider Contract's 64 MiB maximum.
// Encoded strings can be six times their decoded size through JSON escapes;
// the preallocation bound below preserves a 1 MiB decoded string allowance.
const (
	PassiveJSONMaxDepth              = 64
	PassiveJSONMaxTokens             = 250_000
	PassiveJSONMaxStringBytes        = 1 << 20
	PassiveJSONMaxEncodedStringBytes = 6 * PassiveJSONMaxStringBytes
	passiveJSONContextStride         = 4096
)

var errInvalidPassiveJSON = errors.New("invalid passive JSON content")

type PassiveJSONChecker struct{}

func NewPassiveJSONChecker() *PassiveJSONChecker { return &PassiveJSONChecker{} }

func (*PassiveJSONChecker) CheckSupport(ctx context.Context, _ artifact.Request) error {
	if ctx == nil {
		return context.Canceled
	}
	return ctx.Err()
}

func (*PassiveJSONChecker) CheckContent(ctx context.Context, request artifact.Request, content []byte) (artifact.CheckStatus, error) {
	if ctx == nil {
		return artifact.CheckNotRun, context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return artifact.CheckNotRun, err
	}
	if request.ExpectedMediaType != "application/json" {
		return artifact.CheckFailed, nil
	}
	if err := parsePassiveJSON(ctx, content); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return artifact.CheckNotRun, ctxErr
		}
		return artifact.CheckFailed, nil
	}
	return artifact.CheckPassed, nil
}

// The closed policy scanner validates JSON grammar and complexity in one
// forward pass. It never asks encoding/json to buffer an unbounded token or
// whitespace span. Only an already-bounded object key is decoded for duplicate
// detection; strings and numbers are otherwise checked without allocation.
type passiveJSONParser struct {
	ctx       context.Context
	content   []byte
	position  int
	nextCheck int
	tokens    int
}

func parsePassiveJSON(ctx context.Context, content []byte) error {
	if ctx == nil {
		return context.Canceled
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(content) == 0 || len(content) > artifact.MaxArtifactBytes {
		return errInvalidPassiveJSON
	}
	p := passiveJSONParser{ctx: ctx, content: content}
	if err := p.value(0); err != nil {
		return err
	}
	if err := p.space(); err != nil {
		return err
	}
	if p.position != len(content) {
		return errInvalidPassiveJSON
	}
	return ctx.Err()
}

func (p *passiveJSONParser) check() error {
	if p.position < p.nextCheck {
		return nil
	}
	p.nextCheck = p.position + passiveJSONContextStride
	return p.ctx.Err()
}

func (p *passiveJSONParser) space() error {
	for p.position < len(p.content) {
		switch p.content[p.position] {
		case ' ', '\t', '\r', '\n':
			p.position++
			if err := p.check(); err != nil {
				return err
			}
		default:
			return p.check()
		}
	}
	return p.check()
}

func (p *passiveJSONParser) value(depth int) error {
	if err := p.space(); err != nil {
		return err
	}
	p.tokens++
	if p.tokens > PassiveJSONMaxTokens || p.position >= len(p.content) {
		return errInvalidPassiveJSON
	}
	switch p.content[p.position] {
	case '{':
		if depth >= PassiveJSONMaxDepth {
			return errInvalidPassiveJSON
		}
		return p.object(depth + 1)
	case '[':
		if depth >= PassiveJSONMaxDepth {
			return errInvalidPassiveJSON
		}
		return p.array(depth + 1)
	case '"':
		_, err := p.string()
		return err
	case 't':
		return p.literal("true")
	case 'f':
		return p.literal("false")
	case 'n':
		return p.literal("null")
	default:
		return p.number()
	}
}

func (p *passiveJSONParser) object(depth int) error {
	p.position++ // {
	if err := p.space(); err != nil {
		return err
	}
	if p.take('}') {
		return nil
	}
	seen := make(map[string]struct{})
	for {
		p.tokens++ // key
		if p.tokens > PassiveJSONMaxTokens || p.position >= len(p.content) || p.content[p.position] != '"' {
			return errInvalidPassiveJSON
		}
		raw, err := p.string()
		if err != nil {
			return err
		}
		if err := p.ctx.Err(); err != nil {
			return err
		}
		var key string
		if json.Unmarshal(raw, &key) != nil || len(key) > PassiveJSONMaxStringBytes {
			return errInvalidPassiveJSON
		}
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if _, duplicate := seen[key]; duplicate {
			return errInvalidPassiveJSON
		}
		seen[key] = struct{}{}
		if err := p.ctx.Err(); err != nil {
			return err
		}
		if err := p.space(); err != nil {
			return err
		}
		if !p.take(':') {
			return errInvalidPassiveJSON
		}
		if err := p.value(depth); err != nil {
			return err
		}
		if err := p.space(); err != nil {
			return err
		}
		if p.take('}') {
			return nil
		}
		if !p.take(',') {
			return errInvalidPassiveJSON
		}
		if err := p.space(); err != nil {
			return err
		}
	}
}

func (p *passiveJSONParser) array(depth int) error {
	p.position++ // [
	if err := p.space(); err != nil {
		return err
	}
	if p.take(']') {
		return nil
	}
	for {
		if err := p.value(depth); err != nil {
			return err
		}
		if err := p.space(); err != nil {
			return err
		}
		if p.take(']') {
			return nil
		}
		if !p.take(',') {
			return errInvalidPassiveJSON
		}
	}
}

func (p *passiveJSONParser) take(value byte) bool {
	if p.position >= len(p.content) || p.content[p.position] != value {
		return false
	}
	p.position++
	return true
}

func (p *passiveJSONParser) literal(value string) error {
	if len(p.content)-p.position < len(value) || string(p.content[p.position:p.position+len(value)]) != value {
		return errInvalidPassiveJSON
	}
	p.position += len(value)
	return p.check()
}

func (p *passiveJSONParser) number() error {
	start := p.position
	p.take('-')
	if p.take('0') {
		// A following digit is rejected by the enclosing grammar.
	} else {
		if p.position >= len(p.content) || p.content[p.position] < '1' || p.content[p.position] > '9' {
			return errInvalidPassiveJSON
		}
		if err := p.digits(start); err != nil {
			return err
		}
	}
	if p.take('.') {
		if !p.digit() {
			return errInvalidPassiveJSON
		}
		if err := p.digits(start); err != nil {
			return err
		}
	}
	if p.take('e') || p.take('E') {
		if !p.take('+') {
			p.take('-')
		}
		if !p.digit() {
			return errInvalidPassiveJSON
		}
		if err := p.digits(start); err != nil {
			return err
		}
	}
	if p.position-start > PassiveJSONMaxStringBytes {
		return errInvalidPassiveJSON
	}
	return p.check()
}

func (p *passiveJSONParser) digit() bool {
	if p.position >= len(p.content) || p.content[p.position] < '0' || p.content[p.position] > '9' {
		return false
	}
	p.position++
	return true
}

func (p *passiveJSONParser) digits(start int) error {
	for p.digit() {
		if p.position-start > PassiveJSONMaxStringBytes {
			return errInvalidPassiveJSON
		}
		if err := p.check(); err != nil {
			return err
		}
	}
	return nil
}

func (p *passiveJSONParser) string() ([]byte, error) {
	start := p.position
	p.position++ // opening quote
	decoded := 0
	for p.position < len(p.content) {
		if err := p.check(); err != nil {
			return nil, err
		}
		if p.position-start-1 > PassiveJSONMaxEncodedStringBytes || decoded > PassiveJSONMaxStringBytes {
			return nil, errInvalidPassiveJSON
		}
		switch value := p.content[p.position]; {
		case value == '"':
			p.position++
			return p.content[start:p.position], nil
		case value == '\\':
			p.position++
			if p.position >= len(p.content) {
				return nil, errInvalidPassiveJSON
			}
			switch p.content[p.position] {
			case '"', '\\', '/', 'b', 'f', 'n', 'r', 't':
				p.position++
				decoded++
			case 'u':
				code, ok := jsonHex4(p.content, p.position+1)
				if !ok || code >= 0xdc00 && code <= 0xdfff {
					return nil, errInvalidPassiveJSON
				}
				if code >= 0xd800 && code <= 0xdbff {
					if p.position+10 >= len(p.content) || p.content[p.position+5] != '\\' || p.content[p.position+6] != 'u' {
						return nil, errInvalidPassiveJSON
					}
					low, ok := jsonHex4(p.content, p.position+7)
					if !ok || low < 0xdc00 || low > 0xdfff {
						return nil, errInvalidPassiveJSON
					}
					p.position += 11
					decoded += 4
				} else {
					p.position += 5
					decoded += utf8.RuneLen(rune(code))
				}
			default:
				return nil, errInvalidPassiveJSON
			}
		case value < 0x20:
			return nil, errInvalidPassiveJSON
		case value < utf8.RuneSelf:
			p.position++
			decoded++
		default:
			r, size := utf8.DecodeRune(p.content[p.position:])
			if r == utf8.RuneError && size == 1 {
				return nil, errInvalidPassiveJSON
			}
			p.position += size
			decoded += size
		}
	}
	return nil, errInvalidPassiveJSON
}

func jsonHex4(content []byte, start int) (uint16, bool) {
	if start+4 > len(content) {
		return 0, false
	}
	var result uint16
	for _, value := range content[start : start+4] {
		result <<= 4
		switch {
		case value >= '0' && value <= '9':
			result |= uint16(value - '0')
		case value >= 'a' && value <= 'f':
			result |= uint16(value-'a') + 10
		case value >= 'A' && value <= 'F':
			result |= uint16(value-'A') + 10
		default:
			return 0, false
		}
	}
	return result, true
}

var _ artifact.ContentChecker = (*PassiveJSONChecker)(nil)
var _ artifact.SupportChecker = (*PassiveJSONChecker)(nil)
