package protocol

import "sync"

const replayWindowSize = 64

// ReplayWindow accepts limited packet reordering while rejecting duplicate and
// stale sequence numbers. A window is scoped to one random sender prefix.
type ReplayWindow struct {
	highest uint64
	bitmap  uint64
}

// Accept records sequence and reports whether it has not been seen before.
// Sequence zero is invalid because transmitters start at one.
func (w *ReplayWindow) Accept(sequence uint64) bool {
	if sequence == 0 {
		return false
	}
	if w.highest == 0 {
		w.highest = sequence
		w.bitmap = 1
		return true
	}
	if sequence > w.highest {
		shift := sequence - w.highest
		if shift >= replayWindowSize {
			w.bitmap = 1
		} else {
			w.bitmap = (w.bitmap << shift) | 1
		}
		w.highest = sequence
		return true
	}

	delta := w.highest - sequence
	if delta >= replayWindowSize {
		return false
	}
	mask := uint64(1) << delta
	if w.bitmap&mask != 0 {
		return false
	}
	w.bitmap |= mask
	return true
}

// ReplayProtector keeps an independent replay window for every authenticated
// sender session prefix. This lets a peer restart with a new random prefix.
type ReplayProtector struct {
	mu       sync.Mutex
	sessions map[uint32]*ReplayWindow
}

func NewReplayProtector() *ReplayProtector {
	return &ReplayProtector{sessions: make(map[uint32]*ReplayWindow)}
}

// Accept must only be called after successful AEAD authentication. This keeps
// unauthenticated traffic from creating session state or advancing a window.
func (p *ReplayProtector) Accept(prefix uint32, sequence uint64) bool {
	p.mu.Lock()
	defer p.mu.Unlock()

	window := p.sessions[prefix]
	if window == nil {
		window = &ReplayWindow{}
		p.sessions[prefix] = window
	}
	return window.Accept(sequence)
}
