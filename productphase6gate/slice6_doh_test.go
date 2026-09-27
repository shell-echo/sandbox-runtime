//go:build phase6slice6gate

package productphase6gate

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"slices"
	"testing"
	"time"

	"github.com/shell-echo/sandbox-runtime/internal/netpolicy"
	"golang.org/x/net/dns/dnsmessage"
)

const (
	slice6RegistryProbeHost = "registry-1.docker.io"
	slice6DoHURL            = "https://cloudflare-dns.com/dns-query"
	slice6DoHAddress        = "1.1.1.1:443"
	slice6DoHPreflightEnv   = "SANDBOX_RUNTIME_PHASE6_SLICE6_DOH_PREFLIGHT"
	slice6MaxDNSWireBytes   = 4096
)

type slice6PublicDNSAnswer struct {
	addresses  []net.IP
	minimumTTL uint32
	rawDigests [2]string
	observedAt time.Time
}

// This is a bounded pre-freeze bootstrap lookup, not a Product, broker or
// application DNS resolver. The full gate must independently exercise its
// actual isolated DNS fixture and broker's checked numeric dial.
func lookupSlice6PublicRegistryDNS(ctx context.Context) (slice6PublicDNSAnswer, error) {
	if ctx == nil || ctx.Err() != nil {
		return slice6PublicDNSAnswer{}, errors.New("Slice 6 DNS context unavailable")
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	transport := &http.Transport{
		Proxy: nil, DisableKeepAlives: true, DisableCompression: true,
		TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS13, ServerName: "cloudflare-dns.com"},
		TLSHandshakeTimeout: 5 * time.Second, ResponseHeaderTimeout: 5 * time.Second,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != "cloudflare-dns.com:443" {
				return nil, errors.New("unreviewed Slice 6 DoH destination")
			}
			dialer := &net.Dialer{Timeout: 5 * time.Second}
			return dialer.DialContext(ctx, "tcp", slice6DoHAddress)
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 12 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	result := slice6PublicDNSAnswer{observedAt: time.Now().UTC()}
	for index, kind := range []dnsmessage.Type{dnsmessage.TypeA, dnsmessage.TypeAAAA} {
		query, id, err := slice6DNSQuestion(kind)
		if err != nil {
			return slice6PublicDNSAnswer{}, err
		}
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, slice6DoHURL, bytes.NewReader(query))
		if err != nil {
			return slice6PublicDNSAnswer{}, err
		}
		request.Header.Set("Accept", "application/dns-message")
		request.Header.Set("Content-Type", "application/dns-message")
		response, err := client.Do(request)
		if err != nil {
			return slice6PublicDNSAnswer{}, err
		}
		wire, readErr := io.ReadAll(io.LimitReader(response.Body, slice6MaxDNSWireBytes+1))
		closeErr := response.Body.Close()
		mediaType, _, typeErr := mime.ParseMediaType(response.Header.Get("Content-Type"))
		if readErr != nil || closeErr != nil || response.StatusCode != http.StatusOK ||
			typeErr != nil || mediaType != "application/dns-message" || len(wire) == 0 || len(wire) > slice6MaxDNSWireBytes {
			return slice6PublicDNSAnswer{}, errors.New("bounded Slice 6 DoH response unavailable")
		}
		addresses, ttl, err := parseSlice6DNSAnswer(wire, id, kind)
		if err != nil {
			return slice6PublicDNSAnswer{}, err
		}
		result.addresses = append(result.addresses, addresses...)
		if ttl != 0 && (result.minimumTTL == 0 || ttl < result.minimumTTL) {
			result.minimumTTL = ttl
		}
		digest := sha256.Sum256(wire)
		result.rawDigests[index] = "sha256:" + hex.EncodeToString(digest[:])
	}
	if len(result.addresses) == 0 || len(result.addresses) > 16 || result.minimumTTL == 0 || result.minimumTTL > 3600 {
		return slice6PublicDNSAnswer{}, fmt.Errorf("Slice 6 public DNS answer count or freshness invalid: count=%d minimum_ttl=%d", len(result.addresses), result.minimumTTL)
	}
	policy, err := netpolicy.NewBounded([]string{slice6RegistryProbeHost}, []int{443}, 16)
	if err != nil || policy.Check(slice6RegistryProbeHost, 443, result.addresses) != nil {
		return slice6PublicDNSAnswer{}, errors.New("Slice 6 DoH answers are not approved public destinations")
	}
	slices.SortFunc(result.addresses, func(a, b net.IP) int { return bytes.Compare(a.To16(), b.To16()) })
	for index := 1; index < len(result.addresses); index++ {
		if result.addresses[index].Equal(result.addresses[index-1]) {
			return slice6PublicDNSAnswer{}, errors.New("duplicate Slice 6 public DNS address")
		}
	}
	return result, nil
}

func slice6DNSQuestion(kind dnsmessage.Type) ([]byte, uint16, error) {
	var idBytes [2]byte
	if _, err := rand.Read(idBytes[:]); err != nil {
		return nil, 0, err
	}
	id := binary.BigEndian.Uint16(idBytes[:])
	name, err := dnsmessage.NewName(slice6RegistryProbeHost + ".")
	if err != nil {
		return nil, 0, err
	}
	query := dnsmessage.Message{Header: dnsmessage.Header{ID: id, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: name, Type: kind, Class: dnsmessage.ClassINET}}}
	wire, err := query.Pack()
	return wire, id, err
}

func parseSlice6DNSAnswer(wire []byte, id uint16, kind dnsmessage.Type) ([]net.IP, uint32, error) {
	var message dnsmessage.Message
	if len(wire) == 0 || len(wire) > slice6MaxDNSWireBytes || message.Unpack(wire) != nil ||
		!message.Header.Response || message.Header.ID != id || message.Header.Truncated ||
		message.Header.RCode != dnsmessage.RCodeSuccess || len(message.Questions) != 1 ||
		message.Questions[0].Name.String() != slice6RegistryProbeHost+"." ||
		message.Questions[0].Type != kind || message.Questions[0].Class != dnsmessage.ClassINET || len(message.Answers) > 16 {
		return nil, 0, errors.New("invalid Slice 6 DNS wire answer")
	}
	var addresses []net.IP
	var minTTL uint32
	for _, answer := range message.Answers {
		if answer.Header.Name.String() != slice6RegistryProbeHost+"." ||
			answer.Header.Class != dnsmessage.ClassINET || answer.Header.Type != kind ||
			answer.Header.TTL < 1 || answer.Header.TTL > 3600 {
			return nil, 0, errors.New("unreviewed Slice 6 DNS answer")
		}
		if minTTL == 0 || answer.Header.TTL < minTTL {
			minTTL = answer.Header.TTL
		}
		switch body := answer.Body.(type) {
		case *dnsmessage.AResource:
			if kind != dnsmessage.TypeA {
				return nil, 0, errors.New("wrong Slice 6 DNS address family")
			}
			addresses = append(addresses, net.IP(body.A[:]))
		case *dnsmessage.AAAAResource:
			if kind != dnsmessage.TypeAAAA {
				return nil, 0, errors.New("wrong Slice 6 DNS address family")
			}
			addresses = append(addresses, net.IP(body.AAAA[:]))
		default:
			return nil, 0, errors.New("unreviewed Slice 6 DNS record")
		}
	}
	return addresses, minTTL, nil
}

func TestSlice6DoHWireParserRejectsPrivateAndMismatchedAnswers(t *testing.T) {
	name := dnsmessage.MustNewName(slice6RegistryProbeHost + ".")
	build := func(id uint16, address [4]byte) []byte {
		t.Helper()
		message := dnsmessage.Message{Header: dnsmessage.Header{ID: id, Response: true, RCode: dnsmessage.RCodeSuccess},
			Questions: []dnsmessage.Question{{Name: name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}},
			Answers: []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{Name: name, Type: dnsmessage.TypeA,
				Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{A: address}}}}
		wire, err := message.Pack()
		if err != nil {
			t.Fatal(err)
		}
		return wire
	}
	addresses, ttl, err := parseSlice6DNSAnswer(build(17, [4]byte{34, 238, 55, 159}), 17, dnsmessage.TypeA)
	if err != nil || ttl != 60 || len(addresses) != 1 {
		t.Fatalf("valid bounded DNS answer rejected: %v", err)
	}
	if _, _, err := parseSlice6DNSAnswer(build(17, [4]byte{34, 238, 55, 159}), 18, dnsmessage.TypeA); err == nil {
		t.Fatal("mismatched DNS transaction ID admitted")
	}
	policy, err := netpolicy.NewBounded([]string{slice6RegistryProbeHost}, []int{443}, 16)
	if err != nil || policy.Check(slice6RegistryProbeHost, 443, []net.IP{{198, 18, 0, 32}}) == nil {
		t.Fatal("FakeDNS address was admitted as public")
	}
}

// This opt-in check only proves that the controlled pre-freeze public-address
// input can currently be obtained. It is not a Product->broker scenario.
func TestSlice6AuthenticatedPublicDNSBootstrap(t *testing.T) {
	if os.Getenv(slice6DoHPreflightEnv) != "1" {
		t.Skip("set " + slice6DoHPreflightEnv + "=1 for authenticated public DNS bootstrap diagnostic")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 12*time.Second)
	defer cancel()
	answer, err := lookupSlice6PublicRegistryDNS(ctx)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("verified DoH produced %d public addresses, minimum TTL %d seconds, raw digests %s/%s; broker path remains unproved",
		len(answer.addresses), answer.minimumTTL, answer.rawDigests[0], answer.rawDigests[1])
}
