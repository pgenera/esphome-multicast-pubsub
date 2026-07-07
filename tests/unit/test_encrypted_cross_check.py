"""On-host runtime test of the *encrypted* receive path.

Boots the actual host-platform binary produced from
tests/encrypted_subscriber.yaml (a `sensor: mode: subscribe` on
"test/temp" with `encryption.key: shared-test-secret`) and injects
encrypted datagrams crafted by the Python reference. Verifies that:

1. a packet encrypted with the matching key is authenticated/decrypted and
   delivered (the sensor logs the value), and
2. a packet the subscriber can't decrypt (wrong key) is dropped.

This exercises the real component decrypt path end-to-end on the socket
platform -- the path a unit test of the wire format alone can't reach, and
exactly where the socket-vs-ESP8266 consolidation bug hid. It is
cipher-agnostic: `reference.encode` and the rebuilt binary move in lockstep,
so the same test covers whatever cipher the component ships (currently
ChaCha20-Poly1305 AEAD, RFC 8439).

Replay protection itself (the freshness window) is *not* exercised here: the
host platform has no synchronized clock, so a replay-checking receiver fails
closed. That behavior is covered by the ReplayGuard cross-impl tests
(test_replay.py / test_replay_cpp.py / the Go replay_test.go).

Skipped unless the host binaries are present (run
``esphome compile tests/encrypted_subscriber.yaml`` and
``esphome compile tests/encrypted_subscriber_wrongkey.yaml`` first).
"""

from __future__ import annotations

import os
import re
import signal
import socket
import subprocess
import time
from pathlib import Path

import pytest

from reference import DEFAULT_PORT, derive_key, encode, topic_to_group

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "tests" / ".esphome" / "build"
SUB_ENC = BUILD / "pubsub-subscriber-enc" / ".pioenvs" / "pubsub-subscriber-enc" / "program"
SUB_WRONG = BUILD / "pubsub-subscriber-wrong" / ".pioenvs" / "pubsub-subscriber-wrong" / "program"

TOPIC = "test/temp"
RIGHT_KEY = derive_key("shared-test-secret")  # matches encrypted_subscriber.yaml

pytestmark = pytest.mark.skipif(
    not (SUB_ENC.exists() and SUB_WRONG.exists()),
    reason=(
        "encrypted host binaries not built. Run "
        "`esphome compile tests/encrypted_subscriber.yaml` and "
        "`esphome compile tests/encrypted_subscriber_wrongkey.yaml` first."
    ),
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _spawn(binary: Path, log: Path) -> subprocess.Popen[bytes]:
    return subprocess.Popen(
        [str(binary)],
        stdout=open(log, "wb"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )


def _kill(proc: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        proc.wait(timeout=3)
    except subprocess.TimeoutExpired:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        proc.wait(timeout=3)


def _send_encrypted(value: bytes, key: bytes) -> None:
    """Encrypt `value` for TOPIC under `key` and multicast it once."""
    wire = encode(TOPIC, value, key=key)
    group = topic_to_group(TOPIC)
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    try:
        sock.sendto(wire, (str(group), DEFAULT_PORT))
    finally:
        sock.close()


def _run_and_capture(binary: Path, value: bytes, key: bytes, tmp_path: Path) -> str:
    log = tmp_path / "sub.log"
    sub = _spawn(binary, log)
    try:
        time.sleep(1.5)  # bind + join multicast groups
        _send_encrypted(value, key)
        _send_encrypted(value, key)  # resend: lossy multicast, harmless dup
        time.sleep(1.0)  # let it decode + publish the sensor state
    finally:
        _kill(sub)
    return _ANSI.sub("", log.read_text(errors="replace"))


def test_encrypted_packet_with_matching_key_is_delivered(tmp_path: Path) -> None:
    log = _run_and_capture(SUB_ENC, b"42.5", RIGHT_KEY, tmp_path)
    # The subscribed sensor parses the RAW ASCII float and publishes it; at
    # VERBOSE the value shows up in the log. (If decrypt read the wrong
    # offset -- the old socket-path bug -- the float parse would not yield
    # 42.5.)
    assert "42.5" in log, f"expected decrypted sensor value in log:\n{log[-2000:]}"


def test_encrypted_packet_with_wrong_key_is_dropped(tmp_path: Path) -> None:
    # Subscriber configured with a different key cannot authenticate/decrypt
    # a packet sealed under RIGHT_KEY, so the value never reaches the sensor.
    log = _run_and_capture(SUB_WRONG, b"42.5", RIGHT_KEY, tmp_path)
    assert "42.5" not in log, f"wrong-key subscriber should not decode the value:\n{log[-2000:]}"
