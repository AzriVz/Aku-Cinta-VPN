package crypto

import (
	"bytes"
	"testing"

	"github.com/AzriVz/Aku-Cinta-VPN/internal/protocol"
)

func TestSealOpenRoundTrip(t *testing.T) {
	box, err := New(bytes.Repeat([]byte{0x42}, KeySize))
	if err != nil {
		t.Fatal(err)
	}
	header := protocol.NewDataHeader(123, 456)
	plaintext := []byte("complete layer three packet")
	ciphertext, err := box.Seal(header, plaintext)
	if err != nil {
		t.Fatalf("Seal() error = %v", err)
	}
	if bytes.Contains(ciphertext, plaintext) {
		t.Fatal("ciphertext contains plaintext")
	}
	got, err := box.Open(header, ciphertext)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if !bytes.Equal(got, plaintext) {
		t.Fatalf("Open() = %q, want %q", got, plaintext)
	}
}

func TestNewRejectsInvalidKeyLength(t *testing.T) {
	for _, size := range []int{0, KeySize - 1, KeySize + 1} {
		if _, err := New(make([]byte, size)); err == nil {
			t.Fatalf("New() accepted %d-byte key", size)
		}
	}
}

func TestOpenRejectsTamperingWrongKeyAndChangedHeader(t *testing.T) {
	key := bytes.Repeat([]byte{0x11}, KeySize)
	box, _ := New(key)
	header := protocol.NewDataHeader(5, 6)
	ciphertext, err := box.Seal(header, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}

	tampered := append([]byte(nil), ciphertext...)
	tampered[0] ^= 0x80
	if _, err := box.Open(header, tampered); err == nil {
		t.Fatal("Open() accepted tampered ciphertext")
	}

	wrongBox, _ := New(bytes.Repeat([]byte{0x22}, KeySize))
	if _, err := wrongBox.Open(header, ciphertext); err == nil {
		t.Fatal("Open() accepted ciphertext encrypted with a different key")
	}

	changedHeader := header
	changedHeader.Sequence++
	if _, err := box.Open(changedHeader, ciphertext); err == nil {
		t.Fatal("Open() accepted changed authenticated header")
	}
}
