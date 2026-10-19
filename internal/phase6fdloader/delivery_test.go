package phase6fdloader

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"io"
	"strings"
	"testing"
)

func TestDeliveryFramingAndVersionSeparation(t *testing.T) {
	expected := Expected{strings.Repeat("a", 32), ControlDeliveryTarget, strings.Repeat("b", 32), strings.Repeat("c", 12)}
	ev := Envelope{DeliveryStartupProtocol, expected.RunID, expected.Target, strings.Repeat("c", 64), expected.Nonce, []byte(`{}`), []PrivateFile{{3, make([]byte, 32)}}}
	raw, _ := json.Marshal(ev)
	var wire bytes.Buffer
	if WriteFrame(&wire, raw, MaxEnvelopeBytes) != nil {
		t.Fatal("frame")
	}
	wire.WriteString("reply remains")
	got, e := ReadFrame(&wire, MaxEnvelopeBytes)
	if e != nil || !bytes.Equal(got, raw) || wire.String() != "reply remains" {
		t.Fatal("frame overread")
	}
	if _, e := Decode(bytes.NewReader(got), expected); e != nil {
		t.Fatal(e)
	}
	ev.Protocol = ProtocolID
	bad, _ := json.Marshal(ev)
	if _, e := Decode(bytes.NewReader(bad), expected); e == nil {
		t.Fatal("old protocol accepted")
	}
	ev.Protocol = DeliveryStartupProtocol
	ev.Files = append(ev.Files, PrivateFile{5, []byte(`{}`)})
	bad, _ = json.Marshal(ev)
	if _, e := Decode(bytes.NewReader(bad), expected); e == nil {
		t.Fatal("operator can supply loader binding")
	}
	tls, _ := SpecificationFor("workload-tls-agent")
	if tls.Descriptors[0].MaxBytes != 64 {
		t.Fatal("TLS changed")
	}
	for name, input := range map[string][]byte{"empty": nil, "short header": {0, 0}, "empty frame": {0, 0, 0, 0}, "short payload": {0, 0, 0, 3, 1}, "huge": {255, 255, 255, 255}} {
		t.Run(name, func(t *testing.T) {
			if _, e := ReadFrame(bytes.NewReader(input), 20); e == nil {
				t.Fatal("bad frame")
			}
		})
	}
	var out bytes.Buffer
	WriteFrame(&out, []byte("abc"), 3)
	h := out.Bytes()[:4]
	if binary.BigEndian.Uint32(h) != 3 {
		t.Fatal("length")
	}
	if _, e := ReadFrame(io.LimitReader(&out, 6), 3); e == nil {
		t.Fatal("truncation")
	}
}
func TestStartupBindingCanonicalIdentity(t *testing.T) {
	b := StartupBinding{DeliveryStartupProtocol, strings.Repeat("a", 32), strings.Repeat("b", 32), strings.Repeat("c", 64), ControlDeliveryTarget}
	if b.Validate(strings.Repeat("c", 12)) != nil {
		t.Fatal("binding")
	}
	if b.Validate(strings.Repeat("d", 12)) == nil {
		t.Fatal("hostname")
	}
	raw, _ := json.Marshal(b)
	for _, bad := range [][]byte{append(append([]byte(nil), raw...), 10), append([]byte(`{"unknown":0,`), raw[1:]...), append([]byte(`{"protocol":"bad",`), raw[1:]...)} {
		var v StartupBinding
		if DecodeCanonical(bad, &v) == nil {
			t.Fatal("noncanonical")
		}
	}
}

func TestSourceStartupRequiresDistinctTargetAndVersion(t *testing.T) {
	x := Expected{strings.Repeat("a", 32), ControlSourceTarget, strings.Repeat("b", 32), strings.Repeat("c", 12)}
	ev := Envelope{SourceStartupProtocol, x.RunID, x.Target, strings.Repeat("c", 64), x.Nonce, []byte(`{}`), []PrivateFile{{3, make([]byte, 32)}}}
	if ev.Validate(x) != nil {
		t.Fatal("source startup")
	}
	for _, protocol := range []string{ProtocolID, DeliveryStartupProtocol} {
		q := ev
		q.Protocol = protocol
		if q.Validate(x) == nil {
			t.Fatal("cross-version", protocol)
		}
	}
	b := StartupBinding{SourceStartupProtocol, x.RunID, x.Nonce, ev.ContainerID, x.Target}
	if b.Validate(x.ContainerHostname) != nil {
		t.Fatal("source binding")
	}
	b.Target = ControlDeliveryTarget
	if b.Validate(x.ContainerHostname) == nil {
		t.Fatal("old binding")
	}
}

func TestTrustStartupCannotReusePreviousEnvelope(t *testing.T) {
	x := Expected{strings.Repeat("a", 32), ControlTrustTarget, strings.Repeat("b", 32), strings.Repeat("c", 12)}
	ev := Envelope{TrustStartupProtocol, x.RunID, x.Target, strings.Repeat("c", 64), x.Nonce, []byte(`{}`), []PrivateFile{{3, make([]byte, 32)}}}
	if ev.Validate(x) != nil {
		t.Fatal("trust startup")
	}
	for _, protocol := range []string{ProtocolID, DeliveryStartupProtocol, SourceStartupProtocol} {
		q := ev
		q.Protocol = protocol
		if q.Validate(x) == nil {
			t.Fatal("cross-version", protocol)
		}
	}
	b := StartupBinding{TrustStartupProtocol, x.RunID, x.Nonce, ev.ContainerID, x.Target}
	if b.Validate(x.ContainerHostname) != nil {
		t.Fatal("trust binding")
	}
	b.Target = ControlSourceTarget
	if b.Validate(x.ContainerHostname) == nil {
		t.Fatal("old source binding")
	}
}
