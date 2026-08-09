package protocol

import (
	"encoding/binary"
	"errors"
	"testing"
)

func TestEncodeParseRoundTrip(t *testing.T) {
	want := NewDataHeader(0x0102030405060708, 0xaabbccdd)
	ciphertext := make([]byte, TagSize+4)
	packet, err := Encode(want, ciphertext)
	if err != nil {
		t.Fatalf("Encode() error = %v", err)
	}

	got, gotCiphertext, err := Parse(packet)
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if got != want {
		t.Fatalf("Parse() header = %#v, want %#v", got, want)
	}
	if len(gotCiphertext) != len(ciphertext) {
		t.Fatalf("ciphertext length = %d, want %d", len(gotCiphertext), len(ciphertext))
	}
	if got.Sequence != binary.BigEndian.Uint64(packet[4:12]) {
		t.Fatal("sequence number was not encoded in network byte order")
	}
}

func TestParseRejectsMalformedPackets(t *testing.T) {
	valid, err := Encode(NewDataHeader(7, 9), make([]byte, TagSize))
	if err != nil {
		t.Fatal(err)
	}

	tests := []struct {
		name string
		edit func([]byte) []byte
		want error
	}{
		{"truncated", func(p []byte) []byte { return p[:HeaderSize+TagSize-1] }, ErrPacketTooShort},
		{"bad version", func(p []byte) []byte { p[0]++; return p }, ErrUnsupportedVersion},
		{"bad type", func(p []byte) []byte { p[1] = 99; return p }, ErrUnsupportedType},
		{"reserved", func(p []byte) []byte { p[3] = 1; return p }, ErrInvalidReserved},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			packet := append([]byte(nil), valid...)
			_, _, gotErr := Parse(tt.edit(packet))
			if !errors.Is(gotErr, tt.want) {
				t.Fatalf("Parse() error = %v, want %v", gotErr, tt.want)
			}
		})
	}
}

func TestEncodeRejectsInvalidInput(t *testing.T) {
	badHeader := NewDataHeader(1, 2)
	badHeader.Version = 42
	if _, err := Encode(badHeader, make([]byte, TagSize)); !errors.Is(err, ErrUnsupportedVersion) {
		t.Fatalf("Encode() error = %v, want unsupported version", err)
	}
	if _, err := Encode(NewDataHeader(1, 2), make([]byte, TagSize-1)); !errors.Is(err, ErrPacketTooShort) {
		t.Fatalf("Encode() error = %v, want packet too short", err)
	}
}
