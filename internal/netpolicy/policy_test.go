package netpolicy

import (
	"context"
	"errors"
	"net"
	"testing"
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
	for _, address := range []string{"169.254.169.254", "127.0.0.1", "10.0.0.4", "::1"} {
		if err := policy.Check("packages.example.test", 443, []net.IP{public, net.ParseIP(address)}); !errors.Is(err, ErrDenied) {
			t.Fatalf("address %s was accepted: %v", address, err)
		}
	}
	if err := policy.Check("other.example.test", 443, []net.IP{public}); !errors.Is(err, ErrDenied) {
		t.Fatalf("unlisted host = %v", err)
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
