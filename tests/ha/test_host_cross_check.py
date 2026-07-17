"""Home Assistant against real ESPHome firmware, over a real socket.

This is the anti-drift test, and the reason the rest of the suite can be
trusted.

The wire bytes cannot drift: custom_components/mpubsub/reference.py is a
byte-identical copy of the canonical one, and tests/unit/test_vendored_reference.py
fails if it isn't. What *can* drift is everything vendoring does not cover --
the scope nibble, the port, what gets fed to topic_to_group, the group join,
the nonce reuse across retransmits. So this puts the actual ESPHome host
binary on the other end of an actual multicast group and makes the two talk.

Modeled on tests/unit/test_encrypted_cross_check.py, including its hard-won
habits: process groups so a crashed child can't linger, ANSI stripping, and
asserting a *counter climbed* rather than just that a value appeared -- a
subscriber that crashed after delivery leaves a log that passes a weaker
check (that file's comment explains how that bit us).

Skipped unless the host binaries are built:
    esphome compile tests/subscriber.yaml
    esphome compile tests/publisher.yaml
    esphome compile tests/encrypted_subscriber.yaml
"""

from __future__ import annotations

import asyncio
import os
import re
import signal
import subprocess
from pathlib import Path

import pytest
from homeassistant.core import HomeAssistant

from custom_components.mpubsub.client import MpubsubClient
from custom_components.mpubsub.reference import derive_key
from helpers import make_config, requires_multicast, wait_for

REPO = Path(__file__).resolve().parents[2]
BUILD = REPO / "tests" / ".esphome" / "build"


def _program(name: str) -> Path:
    return BUILD / name / ".pioenvs" / name / "program"


SUBSCRIBER = _program("pubsub-subscriber")
PUBLISHER = _program("pubsub-publisher")
SUBSCRIBER_ENC = _program("pubsub-subscriber-enc")

#: The host YAMLs hardcode 18512, so unlike the rest of tests/ha these cannot
#: randomise the port. A stray process holding it will make them fail.
PORT = 18512
TOPIC = "test/temp"  # tests/publisher.yaml and tests/subscriber.yaml
ENC_PASSPHRASE = "shared-test-secret"  # tests/encrypted_subscriber.yaml

pytestmark = [
    requires_multicast,
    pytest.mark.skipif(
        not (SUBSCRIBER.exists() and PUBLISHER.exists() and SUBSCRIBER_ENC.exists()),
        reason=(
            "ESPHome host binaries not built. Run `esphome compile "
            "tests/subscriber.yaml`, `tests/publisher.yaml` and "
            "`tests/encrypted_subscriber.yaml` first."
        ),
    ),
]

_ANSI = re.compile(r"\x1b\[[0-9;]*m")
# Diagnostic sensors log as e.g. "'verify ok': Received new state 2.000000".
_STATE_RE = re.compile(r"'(?P<name>[^']+)': Received new state (?P<val>[0-9.]+)")


class Firmware:
    """A running ESPHome host binary, with its log."""

    def __init__(self, binary: Path, log_path: Path) -> None:
        self._log_path = log_path
        self._fh = open(log_path, "wb")
        self._proc = subprocess.Popen(
            # stdbuf -oL: the host logger block-buffers stdout to a file, so
            # a crash would otherwise leave an empty log and look like "never
            # started" rather than "died after saying something".
            ["stdbuf", "-oL", str(binary)],
            stdout=self._fh,
            stderr=subprocess.STDOUT,
            preexec_fn=os.setsid,
        )

    @property
    def alive(self) -> bool:
        return self._proc.poll() is None

    def log(self) -> str:
        self._fh.flush()
        return _ANSI.sub("", self._log_path.read_text(errors="replace"))

    def counter(self, name: str) -> float | None:
        """Highest value published for a diagnostic sensor; counters only climb."""
        values = [
            float(m.group("val"))
            for m in _STATE_RE.finditer(self.log())
            if m.group("name") == name
        ]
        return max(values) if values else None

    async def wait_for_log(self, needle: str, timeout: float = 5.0) -> bool:
        loop = asyncio.get_running_loop()
        end = loop.time() + timeout
        while loop.time() < end:
            if needle in self.log():
                return True
            if not self.alive:
                return needle in self.log()
            await asyncio.sleep(0.05)
        return False

    def stop(self) -> None:
        try:
            os.killpg(os.getpgid(self._proc.pid), signal.SIGTERM)
        except ProcessLookupError:
            pass
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:  # pragma: no cover
            os.killpg(os.getpgid(self._proc.pid), signal.SIGKILL)
            self._proc.wait(timeout=3)
        self._fh.close()


@pytest.fixture
async def firmware(tmp_path):
    running: list[Firmware] = []

    def _start(binary: Path) -> Firmware:
        fw = Firmware(binary, tmp_path / f"{binary.parent.name}.log")
        running.append(fw)
        return fw

    yield _start
    for fw in running:
        fw.stop()


@pytest.fixture
async def client(hass: HomeAssistant):
    started: list[MpubsubClient] = []

    async def _make(**overrides) -> MpubsubClient:
        cli = MpubsubClient(hass, make_config(PORT, **overrides))
        await cli.async_start()
        started.append(cli)
        return cli

    yield _make
    for cli in started:
        await cli.async_stop()


# --- Home Assistant -> device ------------------------------------------------


async def test_ha_publish_reaches_the_esphome_subscriber(
    hass: HomeAssistant, client, firmware
) -> None:
    """A packet we encode is one the C++ component accepts and decodes."""
    device = firmware(SUBSCRIBER)
    await asyncio.sleep(1.5)  # bind + join
    assert device.alive, f"subscriber died on startup:\n{device.log()[-2000:]}"

    cli = await client()
    cli.async_publish(TOPIC, b"42.5")
    cli.async_publish(TOPIC, b"42.5")  # multicast is lossy; a dup is harmless

    assert await device.wait_for_log("42.5"), (
        f"the ESPHome subscriber never decoded our publish:\n"
        f"{device.log()[-3000:]}"
    )
    # The counter distinguishes "decoded it" from "crashed on the way".
    assert (device.counter("verify ok") or 0) >= 1, (
        f"verify_ok should climb:\n{device.log()[-3000:]}"
    )
    assert (device.counter("verify failed") or 0) == 0
    assert device.alive


async def test_ha_encrypted_publish_reaches_the_esphome_subscriber(
    hass: HomeAssistant, client, firmware
) -> None:
    """Our AEAD, its AEAD, one shared passphrase.

    With cryptography installed we seal with it and the device opens with the
    hand-written C++ -- which is the strongest statement this repo makes
    about the cipher being one cipher.
    """
    device = firmware(SUBSCRIBER_ENC)
    await asyncio.sleep(1.5)
    assert device.alive, f"subscriber died on startup:\n{device.log()[-2000:]}"

    cli = await client(key=derive_key(ENC_PASSPHRASE))
    cli.async_publish(TOPIC, b"42.5")
    cli.async_publish(TOPIC, b"42.5")

    assert await device.wait_for_log("42.5"), (
        f"the encrypted subscriber never decrypted our publish:\n"
        f"{device.log()[-3000:]}"
    )
    assert (device.counter("verify ok") or 0) >= 1
    assert (device.counter("verify failed") or 0) == 0


async def test_wrong_key_publish_is_rejected_by_the_device(
    hass: HomeAssistant, client, firmware
) -> None:
    """The negative half: the device must refuse what it can't authenticate.

    Asserting the counter moved is what separates "rejected it" from "never
    heard it" -- both leave 42.5 out of the log.
    """
    device = firmware(SUBSCRIBER_ENC)
    await asyncio.sleep(1.5)

    cli = await client(key=derive_key("the-wrong-passphrase"))
    cli.async_publish(TOPIC, b"42.5")
    cli.async_publish(TOPIC, b"42.5")
    await asyncio.sleep(1.0)

    log = device.log()
    assert "42.5" not in log, f"a packet under the wrong key must not decode:\n{log[-3000:]}"
    assert (device.counter("verify failed") or 0) >= 1, (
        f"verify_failed should climb, proving it processed and rejected the "
        f"packet rather than never receiving it:\n{log[-3000:]}"
    )


# --- device -> Home Assistant ------------------------------------------------


async def test_esphome_publisher_reaches_ha(
    hass: HomeAssistant, client, firmware
) -> None:
    """The other direction: what the C++ emits, we decode.

    tests/publisher.yaml ticks a synthetic 20..29 degree value once a second
    on test/temp. Its first publish is legitimately "nan": the 1s interval
    fires before the template sensor it reads has produced a value. That is
    the firmware's real behaviour and worth receiving faithfully rather than
    filtering at the socket -- so collect a few and require a real reading
    among them.
    """
    cli = await client()
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    firmware(PUBLISHER)
    await wait_for(got, count=3, timeout=10.0)

    assert got, "never received anything from the ESPHome publisher"
    assert all(m.topic == TOPIC for m in got)
    assert all(m.was_encrypted is False for m in got)

    readings = [
        float(m.payload)
        for m in got
        if m.payload not in ("nan", "")
    ]
    assert readings, f"only got {[m.payload for m in got]!r}; expected a real value"
    assert all(20.0 <= v <= 29.0 for v in readings), f"unexpected values {readings!r}"
