"""Cross-implementation check: ``replay_guard_test`` (the C++ ReplayGuard used
by the ESPHome component) must make the same accept/reject decision as the
Python reference :class:`ReplayGuard` for every command stream.

Run ``make replay_guard_test`` first.
"""

from __future__ import annotations

import random
import subprocess
from pathlib import Path

import pytest

from reference import ReplayGuard

HERE = Path(__file__).parent
BINARY = HERE / "replay_guard_test"

# Must match the capacity compiled into replay_guard_main.cpp (ReplayGuardT<64>).
CAPACITY = 64


def _run_cpp(commands: list[str]) -> list[str]:
    if not BINARY.exists():
        pytest.skip(f"{BINARY} not built; run `make replay_guard_test` first")
    proc = subprocess.run(
        [str(BINARY)],
        input="\n".join(commands) + "\n",
        capture_output=True,
        text=True,
        check=True,
        timeout=10,
    )
    return proc.stdout.strip().splitlines()


def _run_python(commands: list[str]) -> list[str]:
    """Replay the same command stream through the Python ReplayGuard."""
    out: list[str] = []
    guard = ReplayGuard(0, max_entries=CAPACITY)
    for cmd in commands:
        parts = cmd.split()
        if parts[0] == "N":
            guard = ReplayGuard(int(parts[1]), max_entries=CAPACITY)
            out.append("OK")
        elif parts[0] == "A":
            now, valid, ts, nonce = (int(x) for x in parts[1:5])
            ok = guard.accept(now, valid != 0, ts, nonce)
            out.append("1" if ok else "0")
    return out


def _assert_agree(commands: list[str]) -> None:
    assert _run_cpp(commands) == _run_python(commands)


def test_handcrafted_sequence() -> None:
    now = 1_700_000_000
    cmds = [
        "N 30",
        f"A {now} 1 {now} 1",          # fresh -> accept
        f"A {now} 1 {now} 1",          # exact replay -> drop
        f"A {now} 1 {now} 2",          # distinct nonce -> accept
        f"A {now} 1 {now - 31} 3",     # stale -> drop
        f"A {now} 1 {now + 31} 4",     # too future -> drop
        f"A {now} 1 {now - 30} 5",     # window edge -> accept
        f"A {now} 0 {now} 6",          # local clock invalid -> drop
        f"A {now} 1 0 7",              # sender had no clock -> drop
        f"A {now + 100} 1 {now + 100} 1",  # window slid past nonce 1 -> accept
    ]
    _assert_agree(cmds)


def test_window_zero_disables() -> None:
    cmds = ["N 0"]
    for _ in range(5):
        cmds.append("A 1700000000 1 1 1")  # same stale replay, all accepted
    _assert_agree(cmds)


def test_cache_overflow_matches() -> None:
    now = 1_700_000_000
    cmds = ["N 3600"]
    # Insert more distinct nonces than the cache holds, then probe the
    # newest (still remembered) and oldest (evicted) -- both impls must agree
    # on which were dropped.
    for n in range(CAPACITY + 20):
        cmds.append(f"A {now} 1 {now} {n}")
    cmds.append(f"A {now} 1 {now} {CAPACITY + 19}")  # newest -> replay drop
    cmds.append(f"A {now} 1 {now} 0")               # oldest, evicted -> accept
    _assert_agree(cmds)


@pytest.mark.parametrize("seed", range(8))
def test_randomized_streams_agree(seed: int) -> None:
    rng = random.Random(seed)
    base = 1_700_000_000
    cmds = [f"N {rng.choice([0, 5, 30, 300])}"]
    for _ in range(400):
        now = base + rng.randint(0, 600)
        valid = rng.randint(0, 1)
        # Mix in 0 timestamps, near-now, and far-off values; a small nonce
        # space forces frequent collisions so the de-dup path is exercised.
        ts = rng.choice([0, now, now - rng.randint(0, 60), now + rng.randint(0, 60)])
        nonce = rng.randint(0, 30)
        cmds.append(f"A {now} {valid} {ts} {nonce}")
    _assert_agree(cmds)
