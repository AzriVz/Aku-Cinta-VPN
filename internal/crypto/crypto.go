// Package crypto wraps ChaCha20-Poly1305 for the VPN wire protocol.
package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"

	"github.com/AzriVz/Aku-Cinta-VPN/internal/protocol"
	"golang.org/x/crypto/chacha20poly1305"
)

const KeySize = chacha20poly1305.KeySize

// Box authenticates and encrypts complete Layer 3 packets.
type Box struct {
	aead cipher.AEAD
}

func New(key []byte) (*Box, error) {
	if len(key) != KeySize {
		return nil, fmt.Errorf("invalid PSK length: got %d bytes, want %d", len(key), KeySize)
	}
	aead, err := chacha20poly1305.New(key)
	if err != nil {
		return nil, fmt.Errorf("initialize ChaCha20-Poly1305: %w", err)
	}
	return &Box{aead: aead}, nil
}

// RandomPrefix creates the random four-byte portion of a sender session nonce.
func RandomPrefix() (uint32, error) {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return 0, fmt.Errorf("generate nonce prefix: %w", err)
	}
	return binary.BigEndian.Uint32(b[:]), nil
}

func nonce(header protocol.Header) ([chacha20poly1305.NonceSize]byte, error) {
	if err := header.Validate(); err != nil {
		return [chacha20poly1305.NonceSize]byte{}, err
	}
	var value [chacha20poly1305.NonceSize]byte
	binary.BigEndian.PutUint32(value[0:4], header.Prefix)
	binary.BigEndian.PutUint64(value[4:12], header.Sequence)
	return value, nil
}

// Seal returns ciphertext with the Poly1305 authentication tag appended. The
// cleartext header is authenticated as additional data.
func (b *Box) Seal(header protocol.Header, plaintext []byte) ([]byte, error) {
	nonceValue, err := nonce(header)
	if err != nil {
		return nil, err
	}
	aad, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	return b.aead.Seal(nil, nonceValue[:], plaintext, aad), nil
}

// Open authenticates and decrypts ciphertext using the received header.
func (b *Box) Open(header protocol.Header, ciphertext []byte) ([]byte, error) {
	nonceValue, err := nonce(header)
	if err != nil {
		return nil, err
	}
	aad, err := header.MarshalBinary()
	if err != nil {
		return nil, err
	}
	plaintext, err := b.aead.Open(nil, nonceValue[:], ciphertext, aad)
	if err != nil {
		return nil, fmt.Errorf("authenticate encrypted packet: %w", err)
	}
	return plaintext, nil
}
