package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"net"
	"net/netip"
	"os"
	"sync"
	"testing"
	"time"

	vpncrypto "github.com/AzriVz/Aku-Cinta-VPN/internal/crypto"
)

func ipv4Packet(size int) []byte {
	packet := make([]byte, size)
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(size))
	return packet
}

func TestValidateIPv4Packet(t *testing.T) {
	if err := validateIPv4Packet(ipv4Packet(84), 1300); err != nil {
		t.Fatalf("valid packet rejected: %v", err)
	}

	tests := map[string][]byte{
		"short":           make([]byte, 19),
		"IPv6":            append([]byte{0x60}, make([]byte, 39)...),
		"short header":    append([]byte{0x44}, make([]byte, 39)...),
		"length mismatch": ipv4Packet(40),
		"oversized":       ipv4Packet(1400),
	}
	// Make only the mismatch case disagree with its actual slice length.
	binary.BigEndian.PutUint16(tests["length mismatch"][2:4], 39)

	for name, packet := range tests {
		t.Run(name, func(t *testing.T) {
			if err := validateIPv4Packet(packet, 1300); err == nil {
				t.Fatal("invalid packet accepted")
			}
		})
	}
}

type memoryTUN struct {
	reads     chan []byte
	writes    chan []byte
	closed    chan struct{}
	closeOnce sync.Once
}

func newMemoryTUN() *memoryTUN {
	return &memoryTUN{
		reads:  make(chan []byte, 4),
		writes: make(chan []byte, 4),
		closed: make(chan struct{}),
	}
}

func (m *memoryTUN) Read(buffer []byte) (int, error) {
	select {
	case packet := <-m.reads:
		return copy(buffer, packet), nil
	case <-m.closed:
		return 0, os.ErrClosed
	}
}

func (m *memoryTUN) Write(packet []byte) (int, error) {
	copyOfPacket := append([]byte(nil), packet...)
	select {
	case m.writes <- copyOfPacket:
		return len(packet), nil
	case <-m.closed:
		return 0, os.ErrClosed
	}
}

func (m *memoryTUN) Close() error {
	m.closeOnce.Do(func() { close(m.closed) })
	return nil
}

func localAddrPort(connection *net.UDPConn) netip.AddrPort {
	address := connection.LocalAddr().(*net.UDPAddr).AddrPort()
	return netip.AddrPortFrom(address.Addr().Unmap(), address.Port())
}

func waitForPacket(t *testing.T, packets <-chan []byte) []byte {
	t.Helper()
	select {
	case packet := <-packets:
		return packet
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for forwarded packet")
		return nil
	}
}

func TestBidirectionalEncryptedForwarding(t *testing.T) {
	listen := func() *net.UDPConn {
		connection, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		return connection
	}
	udpA := listen()
	udpB := listen()
	tunA := newMemoryTUN()
	tunB := newMemoryTUN()
	boxA, err := vpncrypto.New(bytes.Repeat([]byte{0x7a}, vpncrypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	boxB, err := vpncrypto.New(bytes.Repeat([]byte{0x7a}, vpncrypto.KeySize))
	if err != nil {
		t.Fatal(err)
	}
	tunnelA, err := New(tunA, udpA, localAddrPort(udpB), boxA, 100, 1300, nil)
	if err != nil {
		t.Fatal(err)
	}
	tunnelB, err := New(tunB, udpB, localAddrPort(udpA), boxB, 200, 1300, nil)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	errCh := make(chan error, 2)
	go func() { errCh <- tunnelA.Run(ctx) }()
	go func() { errCh <- tunnelB.Run(ctx) }()

	// A malformed datagram from the configured peer must be dropped without
	// stopping the receiver or writing unauthenticated bytes to its TUN.
	if _, err := udpB.WriteToUDPAddrPort([]byte("not an authenticated VPN packet"), localAddrPort(udpA)); err != nil {
		t.Fatal(err)
	}

	packetA := ipv4Packet(1200)
	copy(packetA[20:], bytes.Repeat([]byte{0xa5}, len(packetA)-20))
	tunA.reads <- packetA
	if got := waitForPacket(t, tunB.writes); !bytes.Equal(got, packetA) {
		t.Fatal("A -> B packet changed during forwarding")
	}

	packetB := ipv4Packet(84)
	copy(packetB[20:], bytes.Repeat([]byte{0x5a}, len(packetB)-20))
	tunB.reads <- packetB
	if got := waitForPacket(t, tunA.writes); !bytes.Equal(got, packetB) {
		t.Fatal("B -> A packet changed during forwarding")
	}

	select {
	case unexpected := <-tunA.writes:
		t.Fatalf("unexpected unauthenticated packet reached TUN A: %x", unexpected)
	default:
	}

	cancel()
	for range 2 {
		select {
		case err := <-errCh:
			if err != nil {
				t.Fatalf("Run() shutdown error = %v", err)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("timed out waiting for tunnel shutdown")
		}
	}
}
