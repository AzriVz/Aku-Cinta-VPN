// Package protocol defines the small authenticated framing protocol carried in
// each UDP datagram.
package protocol

import (
	"encoding/binary"
	"errors"
	"fmt"
)

const (
	// Version is the only wire-format version supported by this implementation.
	Version uint8 = 1
	// TypeData identifies a datagram containing one complete Layer 3 packet.
	TypeData uint8 = 0

	HeaderSize = 16
	TagSize    = 16
	Overhead   = HeaderSize + TagSize
)

var (
	ErrPacketTooShort     = errors.New("VPN packet is too short")
	ErrUnsupportedVersion = errors.New("unsupported VPN packet version")
	ErrUnsupportedType    = errors.New("unsupported VPN packet type")
	ErrInvalidReserved    = errors.New("reserved header bits are non-zero")
)

// Header is transmitted in cleartext but authenticated as AEAD additional
// data. Prefix and Sequence together form the 12-byte ChaCha20-Poly1305 nonce.
type Header struct {
	Version  uint8
	Type     uint8
	Sequence uint64
	Prefix   uint32
}

// NewDataHeader constructs a header for an encrypted IP packet.
func NewDataHeader(sequence uint64, prefix uint32) Header {
	return Header{
		Version:  Version,
		Type:     TypeData,
		Sequence: sequence,
		Prefix:   prefix,
	}
}

// MarshalBinary returns the fixed-size network-byte-order wire header.
func (h Header) MarshalBinary() ([]byte, error) {
	if err := h.Validate(); err != nil {
		return nil, err
	}

	b := make([]byte, HeaderSize)
	b[0] = h.Version
	b[1] = h.Type
	// bytes 2 and 3 are reserved and remain zero.
	binary.BigEndian.PutUint64(b[4:12], h.Sequence)
	binary.BigEndian.PutUint32(b[12:16], h.Prefix)
	return b, nil
}

// Validate checks all currently defined header fields.
func (h Header) Validate() error {
	if h.Version != Version {
		return fmt.Errorf("%w: %d", ErrUnsupportedVersion, h.Version)
	}
	if h.Type != TypeData {
		return fmt.Errorf("%w: %d", ErrUnsupportedType, h.Type)
	}
	return nil
}

// Parse splits a UDP datagram into its authenticated header and ciphertext.
func Parse(datagram []byte) (Header, []byte, error) {
	if len(datagram) < HeaderSize+TagSize {
		return Header{}, nil, ErrPacketTooShort
	}
	if datagram[0] != Version {
		return Header{}, nil, fmt.Errorf("%w: %d", ErrUnsupportedVersion, datagram[0])
	}
	if datagram[1] != TypeData {
		return Header{}, nil, fmt.Errorf("%w: %d", ErrUnsupportedType, datagram[1])
	}
	if datagram[2] != 0 || datagram[3] != 0 {
		return Header{}, nil, ErrInvalidReserved
	}

	h := Header{
		Version:  datagram[0],
		Type:     datagram[1],
		Sequence: binary.BigEndian.Uint64(datagram[4:12]),
		Prefix:   binary.BigEndian.Uint32(datagram[12:16]),
	}
	return h, datagram[HeaderSize:], nil
}

// Encode combines a validated header and an AEAD ciphertext/tag.
func Encode(h Header, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < TagSize {
		return nil, ErrPacketTooShort
	}
	header, err := h.MarshalBinary()
	if err != nil {
		return nil, err
	}
	packet := make([]byte, 0, len(header)+len(ciphertext))
	packet = append(packet, header...)
	packet = append(packet, ciphertext...)
	return packet, nil
}
