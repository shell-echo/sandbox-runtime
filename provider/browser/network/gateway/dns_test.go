package gateway

import (
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestDNSResponseAllowsOnlyPolicyARecords(t *testing.T) {
	server := testServer(t, nil, nil)
	for _, test := range []struct {
		name    string
		host    string
		typeID  dnsmessage.Type
		rcode   dnsmessage.RCode
		answers int
	}{
		{name: "allowed A", host: "allowed.example.", typeID: dnsmessage.TypeA, rcode: dnsmessage.RCodeSuccess, answers: 1},
		{name: "allowed AAAA has no bypass", host: "allowed.example.", typeID: dnsmessage.TypeAAAA, rcode: dnsmessage.RCodeSuccess},
		{name: "denied host", host: "denied.example.", typeID: dnsmessage.TypeA, rcode: dnsmessage.RCodeRefused},
		{name: "denied type", host: "allowed.example.", typeID: dnsmessage.TypeMX, rcode: dnsmessage.RCodeRefused},
	} {
		t.Run(test.name, func(t *testing.T) {
			response, ok := server.dnsResponse(dnsQuery(t, test.host, test.typeID))
			if !ok {
				t.Fatal("no DNS response")
			}
			var message dnsmessage.Message
			if err := message.Unpack(response); err != nil {
				t.Fatal(err)
			}
			if !message.Header.Response || message.Header.RCode != test.rcode || len(message.Questions) != 1 || len(message.Answers) != test.answers {
				t.Fatalf("response = %#v", message)
			}
			if test.answers == 1 {
				body, ok := message.Answers[0].Body.(*dnsmessage.AResource)
				if !ok || body.A != [4]byte{10, 88, 0, 2} || message.Answers[0].Header.TTL != dnsResponseTTL {
					t.Fatalf("answer = %#v", message.Answers[0])
				}
			}
		})
	}
}

func TestDNSResponseRejectsMalformedAndMultipleQuestions(t *testing.T) {
	server := testServer(t, nil, nil)
	if _, ok := server.dnsResponse([]byte{1, 2, 3}); ok {
		t.Fatal("truncated header produced a response")
	}
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 7})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	for _, host := range []string{"allowed.example.", "other.example."} {
		if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(host), Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}); err != nil {
			t.Fatal(err)
		}
	}
	request, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	response, ok := server.dnsResponse(request)
	if !ok {
		t.Fatal("multiple-question request produced no error response")
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil || message.Header.RCode != dnsmessage.RCodeFormatError {
		t.Fatalf("response = %#v, %v", message, err)
	}
}

func TestDNSTCPFramingAndBounds(t *testing.T) {
	server := testServer(t, nil, nil)
	client, gateway := net.Pipe()
	done := make(chan struct{})
	go func() {
		server.handleDNSTCP(t.Context(), gateway)
		close(done)
	}()
	query := dnsQuery(t, "allowed.example.", dnsmessage.TypeA)
	header := []byte{0, 0}
	binary.BigEndian.PutUint16(header, uint16(len(query)))
	if _, err := client.Write(append(header, query...)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.ReadFull(client, header); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint16(header))
	if _, err := io.ReadFull(client, response); err != nil {
		t.Fatal(err)
	}
	_ = client.Close()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("DNS TCP handler did not exit")
	}
	var message dnsmessage.Message
	if err := message.Unpack(response); err != nil || len(message.Answers) != 1 {
		t.Fatalf("response = %#v, %v", message, err)
	}
}

func dnsQuery(t *testing.T, host string, typeID dnsmessage.Type) []byte {
	t.Helper()
	builder := dnsmessage.NewBuilder(nil, dnsmessage.Header{ID: 42, RecursionDesired: true})
	if err := builder.StartQuestions(); err != nil {
		t.Fatal(err)
	}
	if err := builder.Question(dnsmessage.Question{Name: dnsmessage.MustNewName(host), Type: typeID, Class: dnsmessage.ClassINET}); err != nil {
		t.Fatal(err)
	}
	message, err := builder.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return message
}
