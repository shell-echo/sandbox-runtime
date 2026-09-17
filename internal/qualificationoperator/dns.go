package qualificationoperator

import (
	"encoding/binary"
	"net"
	"sync"
	"time"
)

type RotatingDNS struct {
	connection          *net.UDPConn
	name                []byte
	mu                  sync.Mutex
	private             bool
	privateAnswerIssued bool
	observerReady       chan struct{}
	observerSignaled    bool
	done, stopping      chan struct{}
	stopOnce            sync.Once
}

func StartRotatingDNS(listenAddress, hostname string) (*RotatingDNS, error) {
	address, err := net.ResolveUDPAddr("udp", listenAddress)
	if err != nil {
		return nil, ErrObservationProxy
	}
	connection, err := net.ListenUDP("udp", address)
	if err != nil {
		return nil, ErrObservationProxy
	}
	d := &RotatingDNS{
		connection: connection, name: encodeDNSName(hostname), private: true,
		observerReady: make(chan struct{}), done: make(chan struct{}), stopping: make(chan struct{}),
	}
	if len(d.name) == 0 {
		_ = connection.Close()
		return nil, ErrObservationProxy
	}
	go d.serve()
	return d, nil
}

// UsePrivate starts one Gateway generation. Its first A answer is the private
// bind address. Later A lookups wait until UseObserver confirms that listener,
// preventing the client from racing past the out-of-band observer.
func (d *RotatingDNS) UsePrivate() {
	d.mu.Lock()
	if !d.observerSignaled {
		close(d.observerReady)
	}
	d.private = true
	d.privateAnswerIssued = false
	d.observerReady = make(chan struct{})
	d.observerSignaled = false
	d.mu.Unlock()
}

// UseObserver makes every A lookup resolve to the operator-owned observer.
// The operator switches only after it has independently observed the private
// Gateway listener for the current phase.
func (d *RotatingDNS) UseObserver() {
	d.mu.Lock()
	d.private = false
	if !d.observerSignaled {
		close(d.observerReady)
		d.observerSignaled = true
	}
	d.mu.Unlock()
}

func (d *RotatingDNS) Close() error {
	if d == nil || d.connection == nil {
		return nil
	}
	d.stopOnce.Do(func() { close(d.stopping) })
	d.UseObserver()
	err := d.connection.Close()
	<-d.done
	return err
}

func (d *RotatingDNS) serve() {
	defer close(d.done)
	buffer := make([]byte, 512)
	for {
		n, peer, err := d.connection.ReadFromUDP(buffer)
		if err != nil {
			return
		}
		response, ok := d.answer(buffer[:n])
		if ok {
			_, _ = d.connection.WriteToUDP(response, peer)
		}
	}
}

func (d *RotatingDNS) answer(request []byte) ([]byte, bool) {
	if len(request) < 12 || binary.BigEndian.Uint16(request[4:6]) != 1 {
		return nil, false
	}
	offset := 12
	for offset < len(request) && request[offset] != 0 {
		offset += int(request[offset]) + 1
	}
	if offset+5 > len(request) || !equalBytes(request[12:offset+1], d.name) {
		return nil, false
	}
	questionEnd := offset + 5
	qtype := binary.BigEndian.Uint16(request[offset+1 : offset+3])
	response := append([]byte(nil), request[:questionEnd]...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], 0)
	if qtype != 1 {
		return response, true
	}
	ip, ok := d.aRecordAddress()
	if !ok {
		return nil, false
	}
	binary.BigEndian.PutUint16(response[6:8], 1)
	answer := make([]byte, 16)
	binary.BigEndian.PutUint16(answer[0:2], 0xc00c)
	binary.BigEndian.PutUint16(answer[2:4], 1)
	binary.BigEndian.PutUint16(answer[4:6], 1)
	binary.BigEndian.PutUint32(answer[6:10], 0)
	binary.BigEndian.PutUint16(answer[10:12], 4)
	copy(answer[12:16], ip.To4())
	return append(response, answer...), true
}

func (d *RotatingDNS) aRecordAddress() (net.IP, bool) {
	d.mu.Lock()
	if !d.private {
		d.mu.Unlock()
		return net.IPv4(127, 0, 0, 1), true
	}
	if !d.privateAnswerIssued {
		d.privateAnswerIssued = true
		d.mu.Unlock()
		return net.IPv4(127, 0, 0, 2), true
	}
	ready := d.observerReady
	d.mu.Unlock()

	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-ready:
		return net.IPv4(127, 0, 0, 1), true
	case <-d.stopping:
		return nil, false
	case <-timer.C:
		return nil, false
	}
}

func encodeDNSName(hostname string) []byte {
	var result []byte
	for _, label := range splitDNSName(hostname) {
		if len(label) == 0 || len(label) > 63 {
			return nil
		}
		result = append(result, byte(len(label)))
		result = append(result, label...)
	}
	return append(result, 0)
}

func splitDNSName(value string) []string {
	var result []string
	start := 0
	for index := 0; index <= len(value); index++ {
		if index == len(value) || value[index] == '.' {
			result = append(result, value[start:index])
			start = index + 1
		}
	}
	return result
}

func equalBytes(left, right []byte) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
