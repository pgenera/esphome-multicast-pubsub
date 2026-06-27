package main

import "testing"

const replayNow uint32 = 1_700_000_000

func TestReplayFreshAccepted(t *testing.T) {
	g := newReplayGuard(30, 128)
	if !g.accept(replayNow, true, replayNow, 1) {
		t.Error("fresh packet should be accepted")
	}
}

func TestReplayExactReplayRejected(t *testing.T) {
	g := newReplayGuard(30, 128)
	g.accept(replayNow, true, replayNow, 1)
	if g.accept(replayNow, true, replayNow, 1) {
		t.Error("verbatim replay should be rejected")
	}
}

func TestReplayDistinctNoncesAccepted(t *testing.T) {
	g := newReplayGuard(30, 128)
	if !g.accept(replayNow, true, replayNow, 1) || !g.accept(replayNow, true, replayNow, 2) {
		t.Error("distinct nonces at the same timestamp should both be accepted")
	}
}

func TestReplayStaleRejected(t *testing.T) {
	g := newReplayGuard(30, 128)
	if g.accept(replayNow, true, replayNow-31, 1) {
		t.Error("stale packet should be rejected")
	}
}

func TestReplayFutureRejected(t *testing.T) {
	g := newReplayGuard(30, 128)
	if g.accept(replayNow, true, replayNow+31, 1) {
		t.Error("too-future packet should be rejected")
	}
}

func TestReplayWindowEdgeAccepted(t *testing.T) {
	g := newReplayGuard(30, 128)
	if !g.accept(replayNow, true, replayNow-30, 1) || !g.accept(replayNow, true, replayNow+30, 2) {
		t.Error("packets exactly at the window edge should be accepted")
	}
}

func TestReplayWindowZeroDisables(t *testing.T) {
	g := newReplayGuard(0, 128)
	if !g.accept(replayNow, true, replayNow-10000, 1) || !g.accept(replayNow, true, replayNow-10000, 1) {
		t.Error("window 0 should accept everything, including a stale replay")
	}
}

func TestReplayInvalidClockFailsClosed(t *testing.T) {
	g := newReplayGuard(30, 128)
	if g.accept(replayNow, false, replayNow, 1) {
		t.Error("unsynced local clock should fail closed")
	}
}

func TestReplayZeroTimestampFailsClosed(t *testing.T) {
	g := newReplayGuard(30, 128)
	if g.accept(replayNow, true, 0, 1) {
		t.Error("timestamp 0 (sender had no clock) should fail closed")
	}
}

func TestReplayNonceFreshAfterWindow(t *testing.T) {
	g := newReplayGuard(30, 128)
	g.accept(replayNow, true, replayNow, 1)
	later := replayNow + 100 // window has fully slid past the first packet
	if !g.accept(later, true, later, 1) {
		t.Error("a nonce reused after the window slid past should be accepted")
	}
}

func TestReplayCacheBounded(t *testing.T) {
	g := newReplayGuard(3600, 4)
	for n := uint32(0); n < 10; n++ {
		if !g.accept(replayNow, true, replayNow, n) {
			t.Fatalf("nonce %d should be accepted", n)
		}
	}
	if g.accept(replayNow, true, replayNow, 9) {
		t.Error("recent nonce 9 should still be remembered (rejected)")
	}
	if !g.accept(replayNow, true, replayNow, 0) {
		t.Error("oldest nonce 0 should have been evicted (accepted again)")
	}
}
