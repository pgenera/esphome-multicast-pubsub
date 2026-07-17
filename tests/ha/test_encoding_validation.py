"""A bad `encoding:` must fail once, at config time.

`bytes.decode()` raises LookupError for an unknown codec -- and LookupError
is not a UnicodeDecodeError, so the obvious `except UnicodeDecodeError` does
not catch it. Unhandled, it escapes into datagram_received once per arriving
packet, forever, with nothing pointing at the typo that caused it.
"""

from __future__ import annotations

import asyncio

import pytest
import voluptuous as vol
from homeassistant.core import HomeAssistant

from custom_components.mpubsub import async_publish, async_subscribe
from custom_components.mpubsub.const import DATA_MPUBSUB, DOMAIN
from custom_components.mpubsub.entity import MPUBSUB_ENTITY_COMMON_SCHEMA
from custom_components.mpubsub.util import valid_encoding
from helpers import requires_multicast, send_raw

pytestmark = requires_multicast

TOPIC = "test/temp"


def _port(hass: HomeAssistant) -> int:
    return hass.data[DATA_MPUBSUB].client.config.port


# --- the validator -----------------------------------------------------------


@pytest.mark.parametrize(
    "codec",
    [
        "utf-8",
        "utf8",
        "latin-1",
        "ascii",
        "utf-16",
        # Python's codec lookup normalises hard -- it lowercases and folds
        # runs of punctuation and spaces to a single underscore, so these are
        # all genuinely utf-8 and accepting them is correct, not sloppy.
        "UTF-8",
        "utf 8",
        "utf__8",
    ],
)
def test_real_codecs_accepted(codec: str) -> None:
    assert valid_encoding(codec) == codec


def test_none_is_valid_and_means_bytes() -> None:
    assert valid_encoding(None) is None


@pytest.mark.parametrize("codec", ["not-a-real-codec", "utf8-mb4", "", "u t f 8"])
def test_unknown_codecs_rejected(codec: str) -> None:
    """The message must name the codec and suggest a real one -- the user is
    looking at a typo, not a protocol limitation."""
    with pytest.raises(vol.Invalid, match="unknown text encoding"):
        valid_encoding(codec)


# --- the schemas -------------------------------------------------------------


def test_entity_schema_rejects_bad_encoding() -> None:
    with pytest.raises(vol.Invalid, match="unknown text encoding"):
        MPUBSUB_ENTITY_COMMON_SCHEMA({"name": "x", "encoding": "not-a-real-codec"})


def test_entity_schema_accepts_null_encoding() -> None:
    assert MPUBSUB_ENTITY_COMMON_SCHEMA({"name": "x", "encoding": None})["encoding"] is None


async def test_sensor_yaml_with_bad_encoding_is_rejected(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    from custom_components.mpubsub.sensor import PLATFORM_SCHEMA

    with pytest.raises(vol.Invalid, match="unknown text encoding"):
        PLATFORM_SCHEMA({"name": "x", "state_topic": TOPIC, "encoding": "bogus"})


async def test_listen_service_rejects_bad_encoding(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    with pytest.raises(vol.Invalid, match="unknown text encoding"):
        await hass.services.async_call(
            DOMAIN,
            "listen",
            {"topic": TOPIC, "encoding": "bogus-codec"},
            blocking=True,
        )


# --- the runtime paths -------------------------------------------------------
# async_subscribe / async_publish are public API, so a Python caller reaches
# them without passing through any schema.


async def test_subscribe_with_bad_encoding_drops_and_logs(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """Must not raise out of datagram_received, once per packet, forever."""
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append, encoding="not-a-real-codec")

    send_raw(TOPIC, b"42.5", _port(hass))
    await asyncio.sleep(0.3)

    assert got == [], "an undecodable message must not be delivered"
    assert "Unknown encoding" in caplog.text
    assert "Traceback" not in caplog.text, (
        "a LookupError must not escape onto the event loop"
    )


async def test_publish_with_bad_encoding_raises_valueerror(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """A ValueError the caller can catch, not a bare LookupError."""
    await setup_mpubsub()
    with pytest.raises(ValueError, match="unknown text encoding"):
        await async_publish(hass, TOPIC, "hi", encoding="not-a-real-codec")


async def test_undecodable_bytes_still_warn_not_crash(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """The other decode failure: a real codec, bytes that aren't valid in it.
    That one is a UnicodeDecodeError and was always handled -- kept here so
    the two paths stay distinguishable."""
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append, encoding="utf-8")

    send_raw(TOPIC, b"\xff\xfe\xff", _port(hass))
    await asyncio.sleep(0.3)

    assert got == []
    assert "Can't decode payload" in caplog.text
