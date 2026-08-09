// Package tunnel forwards complete IPv4 packets between a Linux TUN device and
// one authenticated UDP peer.
package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"net/netip"
	"os"
	"sync"

	vpncrypto "github.com/AzriVz/Aku-Cinta-VPN/internal/crypto"
	"github.com/AzriVz/Aku-Cinta-VPN/internal/protocol"
)

const maxIPv4PacketSize = 65535

var ErrSequenceExhausted = errors.New("transmit sequence number exhausted")

type debugLogger interface {
	Debugf(format string, args ...any)
}

type discardLogger struct{}

func (discardLogger) Debugf(string, ...any) {}

// Tunnel owns its TUN device and UDP socket. Run closes both when its context
// is cancelled or either forwarding loop fails.
type Tunnel struct {
	tun       io.ReadWriteCloser
	udp       *net.UDPConn
	peer      netip.AddrPort
	box       *vpncrypto.Box
	prefix    uint32
	mtu       int
	replay    *protocol.ReplayProtector
	logger    debugLogger
	closeOnce sync.Once
	closeErr  error
}

func New(tunDevice io.ReadWriteCloser, udp *net.UDPConn, peer netip.AddrPort, box *vpncrypto.Box, prefix uint32, mtu int, logger debugLogger) (*Tunnel, error) {
	if tunDevice == nil {
		return nil, errors.New("TUN device is nil")
	}
	if udp == nil {
		return nil, errors.New("UDP socket is nil")
	}
	if !peer.IsValid() || !peer.Addr().Is4() || peer.Port() == 0 {
		return nil, fmt.Errorf("invalid UDP peer %q", peer)
	}
	if box == nil {
		return nil, errors.New("crypto box is nil")
	}
	if mtu < 576 || mtu > maxIPv4PacketSize-protocol.Overhead {
		return nil, fmt.Errorf("invalid tunnel MTU %d", mtu)
	}
	if logger == nil {
		logger = discardLogger{}
	}
	return &Tunnel{
		tun:    tunDevice,
		udp:    udp,
		peer:   peer,
		box:    box,
		prefix: prefix,
		mtu:    mtu,
		replay: protocol.NewReplayProtector(),
		logger: logger,
	}, nil
}

// Run starts both forwarding directions and blocks until shutdown. Cancelling
// ctx closes the descriptors, which safely unblocks kernel reads.
func (t *Tunnel) Run(ctx context.Context) error {
	errCh := make(chan error, 2)
	go func() { errCh <- t.forwardTUNToUDP() }()
	go func() { errCh <- t.forwardUDPToTUN() }()

	var firstErr error
	received := 0
	select {
	case <-ctx.Done():
		firstErr = ctx.Err()
	case firstErr = <-errCh:
		received = 1
	}

	_ = t.Close()
	for received < 2 {
		err := <-errCh
		received++
		if firstErr == nil || isExpectedClose(firstErr) {
			firstErr = err
		}
	}

	if errors.Is(firstErr, context.Canceled) || errors.Is(firstErr, context.DeadlineExceeded) || isExpectedClose(firstErr) {
		return nil
	}
	return firstErr
}

// Close closes both owned descriptors exactly once.
func (t *Tunnel) Close() error {
	t.closeOnce.Do(func() {
		tunErr := t.tun.Close()
		udpErr := t.udp.Close()
		t.closeErr = errors.Join(tunErr, udpErr)
	})
	return t.closeErr
}

func (t *Tunnel) forwardTUNToUDP() error {
	buffer := make([]byte, maxIPv4PacketSize)
	sequence := uint64(1)
	for {
		n, err := t.tun.Read(buffer)
		if err != nil {
			return fmt.Errorf("read TUN packet: %w", err)
		}
		if err := validateIPv4Packet(buffer[:n], t.mtu); err != nil {
			t.logger.Debugf("drop invalid TUN packet: %v", err)
			continue
		}
		if sequence == 0 {
			return ErrSequenceExhausted
		}

		header := protocol.NewDataHeader(sequence, t.prefix)
		ciphertext, err := t.box.Seal(header, buffer[:n])
		if err != nil {
			return fmt.Errorf("encrypt TUN packet: %w", err)
		}
		datagram, err := protocol.Encode(header, ciphertext)
		if err != nil {
			return fmt.Errorf("encode encrypted packet: %w", err)
		}
		written, err := t.udp.WriteToUDPAddrPort(datagram, t.peer)
		if err != nil {
			return fmt.Errorf("send UDP packet to %s: %w", t.peer, err)
		}
		if written != len(datagram) {
			return fmt.Errorf("send UDP packet: %w", io.ErrShortWrite)
		}
		t.logger.Debugf("tun -> udp seq=%d plaintext=%d encrypted=%d", sequence, n, len(datagram))
		if sequence == math.MaxUint64 {
			sequence = 0
		} else {
			sequence++
		}
	}
}

func (t *Tunnel) forwardUDPToTUN() error {
	buffer := make([]byte, maxIPv4PacketSize)
	for {
		n, sender, err := t.udp.ReadFromUDPAddrPort(buffer)
		if err != nil {
			return fmt.Errorf("read UDP packet: %w", err)
		}
		sender = netip.AddrPortFrom(sender.Addr().Unmap(), sender.Port())
		if sender != t.peer {
			t.logger.Debugf("drop UDP packet from unexpected peer %s", sender)
			continue
		}
		if n > t.mtu+protocol.Overhead {
			t.logger.Debugf("drop oversized UDP packet: got=%d maximum=%d", n, t.mtu+protocol.Overhead)
			continue
		}

		header, ciphertext, err := protocol.Parse(buffer[:n])
		if err != nil {
			t.logger.Debugf("drop malformed UDP packet: %v", err)
			continue
		}
		plaintext, err := t.box.Open(header, ciphertext)
		if err != nil {
			t.logger.Debugf("drop unauthenticated UDP packet: %v", err)
			continue
		}
		// Replay state is deliberately advanced only after AEAD authentication.
		if !t.replay.Accept(header.Prefix, header.Sequence) {
			t.logger.Debugf("drop replayed UDP packet seq=%d", header.Sequence)
			continue
		}
		if err := validateIPv4Packet(plaintext, t.mtu); err != nil {
			t.logger.Debugf("drop invalid decrypted packet seq=%d: %v", header.Sequence, err)
			continue
		}
		written, err := t.tun.Write(plaintext)
		if err != nil {
			return fmt.Errorf("write TUN packet: %w", err)
		}
		if written != len(plaintext) {
			return fmt.Errorf("write TUN packet: %w", io.ErrShortWrite)
		}
		t.logger.Debugf("udp -> tun seq=%d plaintext=%d", header.Sequence, len(plaintext))
	}
}

func validateIPv4Packet(packet []byte, mtu int) error {
	if len(packet) < 20 {
		return fmt.Errorf("IPv4 packet is too short: %d bytes", len(packet))
	}
	if len(packet) > mtu {
		return fmt.Errorf("IPv4 packet exceeds MTU: %d > %d", len(packet), mtu)
	}
	if packet[0]>>4 != 4 {
		return fmt.Errorf("unsupported IP version %d", packet[0]>>4)
	}
	headerLength := int(packet[0]&0x0f) * 4
	if headerLength < 20 || headerLength > len(packet) {
		return fmt.Errorf("invalid IPv4 header length %d", headerLength)
	}
	totalLength := int(binary.BigEndian.Uint16(packet[2:4]))
	if totalLength != len(packet) {
		return fmt.Errorf("IPv4 total length %d does not match packet length %d", totalLength, len(packet))
	}
	return nil
}

func isExpectedClose(err error) bool {
	return errors.Is(err, net.ErrClosed) || errors.Is(err, os.ErrClosed)
}
