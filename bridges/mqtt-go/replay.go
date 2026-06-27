package main

import "sync"

// replayGuard is the receiver-side replay rejection for encrypted mpubsub
// traffic: a freshness window plus a bounded nonce de-dup cache. It mirrors
// the Python reference ReplayGuard (tests/unit/reference.py) and the C++
// replay_guard.h so all three make the same accept/reject decision.
//
// See docs/PROTOCOL.md for the rationale. In short: a captured ciphertext is
// byte-identical however long after it was recorded, so the receiver drops
// anything stamped more than `window` seconds from its own clock (the
// timestamp lives inside the ciphertext, so an attacker without the key can't
// move it) and remembers recently-seen nonces to reject verbatim replays
// within the window. The clock is the freshness reference, so nothing needs
// to persist across a restart.
type replayGuard struct {
	window     uint32 // seconds; 0 disables protection
	maxEntries int

	mu    sync.Mutex
	order []replayEntry
	seen  map[uint32]struct{}
}

type replayEntry struct {
	nonce uint32
	ts    uint32
}

func newReplayGuard(window uint32, maxEntries int) *replayGuard {
	return &replayGuard{
		window:     window,
		maxEntries: maxEntries,
		seen:       make(map[uint32]struct{}),
	}
}

func (g *replayGuard) enabled() bool { return g.window != 0 }

// accept reports whether a packet stamped (timestamp, nonce) is fresh and
// previously unseen, recording it as a side effect. nowValid==false (clock
// not synced) or timestamp==0 (sender had no clock) fail closed; window==0
// always accepts. The bridge always has a real clock, so it passes
// nowValid=true.
func (g *replayGuard) accept(now uint32, nowValid bool, timestamp, nonce uint32) bool {
	if g.window == 0 {
		return true
	}
	if !nowValid {
		return false
	}
	if timestamp == 0 {
		return false
	}
	var skew uint32
	if now >= timestamp {
		skew = now - timestamp
	} else {
		skew = timestamp - now
	}
	if skew > g.window {
		return false
	}

	g.mu.Lock()
	defer g.mu.Unlock()
	g.prune(now)
	if _, dup := g.seen[nonce]; dup {
		return false
	}
	g.seen[nonce] = struct{}{}
	g.order = append(g.order, replayEntry{nonce: nonce, ts: timestamp})
	if len(g.order) > g.maxEntries {
		delete(g.seen, g.order[0].nonce)
		g.order = g.order[1:]
	}
	return true
}

// prune drops entries older than the window from the front of the order
// slice. Insertion order tracks timestamp order (the clock advances), so the
// oldest live entry is always at the front. Caller holds g.mu.
func (g *replayGuard) prune(now uint32) {
	cutoff := now - g.window
	i := 0
	for i < len(g.order) && g.order[i].ts < cutoff {
		delete(g.seen, g.order[i].nonce)
		i++
	}
	if i > 0 {
		// Compact in place so the backing array stays bounded.
		g.order = append(g.order[:0], g.order[i:]...)
	}
}
