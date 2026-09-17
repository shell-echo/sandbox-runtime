package qualificationoperator

import (
	"net"
	"testing"
	"time"
)

func TestRotatingDNSReservesFirstLookupForGatewayBinding(t *testing.T) {
	dns := &RotatingDNS{
		private: true, observerReady: make(chan struct{}), stopping: make(chan struct{}),
	}
	address, ok := dns.aRecordAddress()
	if !ok || !address.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("first address = %v, %t", address, ok)
	}

	result := make(chan net.IP, 1)
	go func() {
		address, _ := dns.aRecordAddress()
		result <- address
	}()
	select {
	case address := <-result:
		t.Fatalf("client lookup bypassed observer readiness: %v", address)
	case <-time.After(20 * time.Millisecond):
	}
	dns.UseObserver()
	select {
	case address := <-result:
		if !address.Equal(net.IPv4(127, 0, 0, 1)) {
			t.Fatalf("observer address = %v", address)
		}
	case <-time.After(time.Second):
		t.Fatal("client lookup was not released")
	}

	dns.UsePrivate()
	address, ok = dns.aRecordAddress()
	if !ok || !address.Equal(net.IPv4(127, 0, 0, 2)) {
		t.Fatalf("next-generation first address = %v, %t", address, ok)
	}
}

func TestRotatingDNSStopsBlockedLookup(t *testing.T) {
	dns := &RotatingDNS{
		private: true, privateAnswerIssued: true, observerReady: make(chan struct{}), stopping: make(chan struct{}),
	}
	result := make(chan bool, 1)
	go func() {
		_, ok := dns.aRecordAddress()
		result <- ok
	}()
	close(dns.stopping)
	select {
	case ok := <-result:
		if ok {
			t.Fatal("stopping DNS returned an address")
		}
	case <-time.After(time.Second):
		t.Fatal("blocked lookup did not stop")
	}
}
