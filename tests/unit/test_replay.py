"""ReplayGuard tests against the Python reference.

The guard is the receiver-side policy that turns the in-ciphertext
timestamp + nonce (see test_encryption.py) into actual replay rejection.
The same accept/reject decisions are mirrored by the C++ replay_guard.h
host harness and the Go bridge's replayGuard.
"""

from __future__ import annotations

from reference import ReplayGuard

NOW = 1_700_000_000  # arbitrary fixed "current" unix time


def test_fresh_packet_accepted() -> None:
    g = ReplayGuard(window_seconds=30)
    assert g.accept(NOW, True, NOW, nonce=1)


def test_exact_replay_rejected() -> None:
    g = ReplayGuard(window_seconds=30)
    assert g.accept(NOW, True, NOW, nonce=1)
    # Same nonce again within the window: a verbatim resend -> drop.
    assert not g.accept(NOW, True, NOW, nonce=1)


def test_distinct_nonces_same_timestamp_both_accepted() -> None:
    g = ReplayGuard(window_seconds=30)
    assert g.accept(NOW, True, NOW, nonce=1)
    assert g.accept(NOW, True, NOW, nonce=2)


def test_stale_packet_rejected() -> None:
    g = ReplayGuard(window_seconds=30)
    assert not g.accept(NOW, True, NOW - 31, nonce=1)


def test_future_packet_rejected() -> None:
    """A timestamp too far ahead of us (skewed/fast clock or replay seeded
    from one) is rejected symmetrically with the stale case."""
    g = ReplayGuard(window_seconds=30)
    assert not g.accept(NOW, True, NOW + 31, nonce=1)


def test_edge_of_window_accepted() -> None:
    g = ReplayGuard(window_seconds=30)
    assert g.accept(NOW, True, NOW - 30, nonce=1)
    assert g.accept(NOW, True, NOW + 30, nonce=2)


def test_window_zero_disables_protection() -> None:
    g = ReplayGuard(window_seconds=0)
    # Always accept, even a stale exact replay.
    assert g.accept(NOW, True, NOW - 10_000, nonce=1)
    assert g.accept(NOW, True, NOW - 10_000, nonce=1)


def test_invalid_local_clock_fails_closed() -> None:
    g = ReplayGuard(window_seconds=30)
    assert not g.accept(NOW, False, NOW, nonce=1)


def test_zero_timestamp_fails_closed() -> None:
    """timestamp==0 means the sender had no synced clock; a replay-checking
    receiver can't verify freshness, so it drops."""
    g = ReplayGuard(window_seconds=30)
    assert not g.accept(NOW, True, 0, nonce=1)


def test_nonce_evicted_after_window_is_not_a_replay() -> None:
    """Once the window slides past a nonce's timestamp it leaves the cache;
    a later packet reusing that nonce is fresh on its own merits (and an
    attacker can't actually do this without also forging a fresh timestamp,
    which the freshness check independently rejects)."""
    g = ReplayGuard(window_seconds=30)
    assert g.accept(NOW, True, NOW, nonce=1)
    later = NOW + 100  # window has fully slid past the first packet
    assert g.accept(later, True, later, nonce=1)


def test_dedup_cache_is_bounded() -> None:
    """The cache holds at most max_entries; overflow drops the oldest. This
    keeps RAM bounded on ESP8266-class devices at the cost of admitting a
    replay of a very old (but still in-window) nonce under heavy traffic."""
    g = ReplayGuard(window_seconds=3600, max_entries=4)
    for n in range(10):
        assert g.accept(NOW, True, NOW, nonce=n)
    # Recent nonces are still remembered (rejected as replays)...
    assert not g.accept(NOW, True, NOW, nonce=9)
    # ...but the oldest have been evicted to stay within the cap.
    assert g.accept(NOW, True, NOW, nonce=0)
