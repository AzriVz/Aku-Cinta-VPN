package protocol

import "testing"

func TestReplayWindow(t *testing.T) {
	var window ReplayWindow
	for _, sequence := range []uint64{1, 3, 2, 65, 4, 64} {
		if !window.Accept(sequence) {
			t.Fatalf("first occurrence of sequence %d was rejected", sequence)
		}
	}
	for _, sequence := range []uint64{0, 1, 2, 3, 4, 64, 65} {
		if window.Accept(sequence) {
			t.Fatalf("duplicate or invalid sequence %d was accepted", sequence)
		}
	}
	if !window.Accept(130) {
		t.Fatal("new sequence after a large jump was rejected")
	}
	if window.Accept(65) {
		t.Fatal("sequence outside the 64-packet window was accepted")
	}
}

func TestReplayProtectorSeparatesPrefixes(t *testing.T) {
	p := NewReplayProtector()
	if !p.Accept(10, 1) || !p.Accept(20, 1) {
		t.Fatal("same sequence should be valid in different sessions")
	}
	if p.Accept(10, 1) || p.Accept(20, 1) {
		t.Fatal("duplicate sequence was accepted")
	}
}
