"""The mpubsub library against real ESPHome firmware, over a real socket.

The anti-drift test for the library, mirroring tests/ha/test_host_cross_check.py
but with no Home Assistant in the picture. wire.py is byte-identical to the
protocol reference (drift-gated), so the framing can't drift; this proves the
aio client's *plumbing* -- scope nibble, port, group join, nonce reuse --
agrees with the firmware in both directions.

Skipped unless the host binaries are built (they live in the parent repo):
    esphome compile tests/subscriber.yaml
    esphome compile tests/publisher.yaml
"""

from __future__ import annotations

import asyncio
import os
import re
import signal
import subprocess
from pathlib import Path

import pytest

from mpubsub import MpubsubClient

# The library lives in <repo>/python; the ESPHome build tree is one level up.
REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "tests" / ".esphome" / "build"
SUBSCRIBER = BUILD / "pubsub-subscriber" / ".pioenvs" / "pubsub-subscriber" / "program"
PUBLISHER = BUILD / "pubsub-publisher" / ".pioenvs" / "pubsub-publisher" / "program"

PORT = 18512  # the host YAMLs hardcode this
TOPIC = "test/temp"

pytestmark = pytest.mark.skipif(
    not (SUBSCRIBER.exists() and PUBLISHER.exists()),
    reason="ESPHome host binaries not built (esphome compile tests/{subscriber,publisher}.yaml)",
)

_ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _spawn(binary, log_path):
    return subprocess.Popen(
        ["stdbuf", "-oL", str(binary)],
        stdout=open(log_path, "wb"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )


def _kill(p):
    try:
        os.killpg(os.getpgid(p.pid), signal.SIGTERM)
        p.wait(timeout=3)
    except Exception:  # noqa: BLE001
        try:
            os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        except ProcessLookupError:
            pass


def _log(path):
    return _ANSI.sub("", Path(path).read_text(errors="replace"))


async def test_library_publish_reaches_esphome_subscriber(tmp_path):
    log = tmp_path / "sub.log"
    device = _spawn(SUBSCRIBER, log)
    try:
        await asyncio.sleep(1.5)
        assert device.poll() is None, "subscriber died on startup:\n%s" % _log(log)[-1500:]
        client = MpubsubClient(port=PORT, scope="link-local")
        await client.start()
        client.publish(TOPIC, "42.5")
        client.publish(TOPIC, "42.5")  # multicast is lossy; a dup is harmless
        await asyncio.sleep(1.0)
        await client.stop()
    finally:
        _kill(device)

    text = _log(log)
    assert "42.5" in text, "device never decoded our publish:\n%s" % text[-2000:]
    verify = re.findall(r"'verify ok': Received new state ([0-9.]+)", text)
    # The counter separates "decoded it" from "crashed on the way".
    assert verify and float(verify[-1]) >= 1, "verify_ok should climb:\n%s" % text[-2000:]


async def test_esphome_publisher_reaches_library(tmp_path):
    got = []
    client = MpubsubClient(port=PORT, scope="link-local")
    await client.start()
    await client.subscribe(TOPIC, lambda m: got.append(m.payload))
    device = _spawn(PUBLISHER, tmp_path / "pub.log")
    try:
        for _ in range(90):
            if len(got) >= 3:
                break
            await asyncio.sleep(0.1)
    finally:
        _kill(device)
        await client.stop()

    assert got, "never received anything from the ESPHome publisher"
    # publisher.yaml's first tick is legitimately "nan" (its template sensor
    # has no value yet); require a real reading among the batch.
    readings = [float(x) for x in got if x not in ("nan", "")]
    assert readings, "only got %r" % got
    assert all(20.0 <= v <= 29.0 for v in readings), "unexpected values %r" % readings
