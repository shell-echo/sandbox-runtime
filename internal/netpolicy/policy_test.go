package netpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPolicyRejectsMetadataPrivateAndRebindingAddresses(t *testing.T) {
	policy, err := New([]string{"packages.example.test"}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	public := net.ParseIP("93.184.216.34")
	if err := policy.Check("packages.example.test", 443, []net.IP{public}); err != nil {
		t.Fatal(err)
	}
	for _, address := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.4", "192.88.99.1", "240.0.0.1", "::1", "100::1", "2001:db8::1", "3fff::1", "5f00::1"} {
		if err := policy.Check("packages.example.test", 443, []net.IP{public, net.ParseIP(address)}); !errors.Is(err, ErrDenied) {
			t.Fatalf("address %s was accepted: %v", address, err)
		}
	}
	if err := policy.Check("other.example.test", 443, []net.IP{public}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unlisted host = %v", err)
	}
	for _, host := range []string{"Packages.example.test", "packages.example.test ", "93.184.216.34"} {
		if err := policy.Check(host, 443, []net.IP{public}); !errors.Is(err, ErrDenied) {
			t.Fatalf("noncanonical host %q = %v", host, err)
		}
	}
	bounded, err := NewBounded([]string{"packages.example.test"}, []int{443}, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := bounded.Check("packages.example.test", 443, []net.IP{public, public}); !errors.Is(err, ErrDenied) {
		t.Fatalf("oversized DNS answer set = %v", err)
	}
}

func TestPolicyRejectsDuplicatePortsAndInvalidAnswerBounds(t *testing.T) {
	if _, err := New([]string{"packages.example.test"}, []int{443, 443}); !errors.Is(err, ErrInvalid) {
		t.Fatalf("duplicate port error = %v", err)
	}
	for _, maximum := range []int{0, 33} {
		if _, err := NewBounded([]string{"packages.example.test"}, []int{443}, maximum); !errors.Is(err, ErrInvalid) {
			t.Fatalf("maximum %d error = %v", maximum, err)
		}
	}
}

type staticResolver []net.IPAddr

func (r staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) { return r, nil }

type recordingDialer struct {
	addresses []string
	err       error
}

func (d *recordingDialer) DialContext(_ context.Context, _, address string) (net.Conn, error) {
	d.addresses = append(d.addresses, address)
	return nil, d.err
}

func TestDialContextChecksAllDNSAnswersBeforeOpeningSocket(t *testing.T) {
	policy, err := New([]string{"packages.example.test"}, []int{443})
	if err != nil {
		t.Fatal(err)
	}
	dialer := &recordingDialer{err: errors.New("refused")}
	_, err = policy.DialContext(context.Background(), staticResolver{{IP: net.ParseIP("93.184.216.34")}}, dialer, "packages.example.test", 443)
	if !errors.Is(err, ErrDial) || len(dialer.addresses) != 1 || dialer.addresses[0] != "93.184.216.34:443" {
		t.Fatalf("dial result = %v, calls = %v", err, dialer.addresses)
	}

	dialer = &recordingDialer{}
	_, err = policy.DialContext(context.Background(), staticResolver{{IP: net.ParseIP("93.184.216.34")}, {IP: net.ParseIP("169.254.169.254")}}, dialer, "packages.example.test", 443)
	if !errors.Is(err, ErrDenied) || len(dialer.addresses) != 0 {
		t.Fatalf("rebinding result = %v, calls = %v", err, dialer.addresses)
	}
}

func TestSixteenAnswerPolicyRejectsSeventeenthOrPoisonedLastBeforeDial(t *testing.T) {
	const host = "registry-1.docker.io"
	policy, err := NewBounded([]string{host}, []int{443}, 16)
	if err != nil {
		t.Fatal(err)
	}
	addresses := make([]net.IP, 0, 17)
	for index := byte(1); index <= 16; index++ {
		addresses = append(addresses, net.IPv4(34, 238, 55, index))
	}
	if err := policy.Check(host, 443, addresses); err != nil {
		t.Fatalf("16 public addresses were rejected: %v", err)
	}
	resolver := func(values []net.IP) staticResolver {
		answers := make(staticResolver, 0, len(values))
		for _, address := range values {
			answers = append(answers, net.IPAddr{IP: address})
		}
		return answers
	}
	dialer := &recordingDialer{err: errors.New("refused")}
	_, err = policy.DialContext(context.Background(), resolver(addresses), dialer, host, 443)
	if !errors.Is(err, ErrDial) || len(dialer.addresses) != 16 {
		t.Fatalf("16 public addresses did not enter bounded sequential dial: %v, calls=%d", err, len(dialer.addresses))
	}
	tooMany := append(append([]net.IP(nil), addresses...), net.IPv4(34, 238, 55, 17))
	dialer = &recordingDialer{}
	_, err = policy.DialContext(context.Background(), resolver(tooMany), dialer, host, 443)
	if !errors.Is(err, ErrDenied) || len(dialer.addresses) != 0 {
		t.Fatalf("17th answer reached numeric dial: %v, calls=%d", err, len(dialer.addresses))
	}
	for _, bad := range []string{"198.18.0.32", "10.0.0.1", "169.254.169.254", "127.0.0.1", "::1", "fc00::1"} {
		mixed := append(append([]net.IP(nil), addresses[:15]...), net.ParseIP(bad))
		dialer = &recordingDialer{}
		_, err = policy.DialContext(context.Background(), resolver(mixed), dialer, host, 443)
		if !errors.Is(err, ErrDenied) || len(dialer.addresses) != 0 {
			t.Fatalf("poisoned last address %s reached numeric dial: %v, calls=%d", bad, err, len(dialer.addresses))
		}
	}
}

type contextWaitingDialer struct{ calls int }

func (d *contextWaitingDialer) DialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	d.calls++
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestSixteenAnswerDialSharesOneDeadline(t *testing.T) {
	policy, err := NewBounded([]string{"registry-1.docker.io"}, []int{443}, 16)
	if err != nil {
		t.Fatal(err)
	}
	answers := make(staticResolver, 16)
	for index := range answers {
		answers[index] = net.IPAddr{IP: net.IPv4(34, 238, 55, byte(index+1))}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer cancel()
	dialer := &contextWaitingDialer{}
	_, err = policy.DialContext(ctx, answers, dialer, "registry-1.docker.io", 443)
	if !errors.Is(err, context.DeadlineExceeded) || dialer.calls != 1 {
		t.Fatalf("DNS candidates renewed deadline or continued after cancellation: %v, calls=%d", err, dialer.calls)
	}
}
