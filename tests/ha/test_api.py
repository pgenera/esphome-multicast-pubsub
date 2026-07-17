"""The mqtt-mirroring API surface.

These are the tests that keep the promise in the integration's docstring:
that code written against homeassistant.components.mqtt keeps working, and
that where it can't, it fails loudly rather than silently doing nothing.
"""

from __future__ import annotations

import dataclasses

import pytest
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from custom_components.mpubsub import (
    async_publish,
    async_subscribe,
    async_wait_for_client,
)
from custom_components.mpubsub.models import ReceiveMessage
from custom_components.mpubsub.util import TopicError, validate_topic
from helpers import requires_multicast, send_raw, wait_for

pytestmark = requires_multicast

TOPIC = "test/temp"


def _port(hass: HomeAssistant) -> int:
    from custom_components.mpubsub.const import DATA_MPUBSUB

    return hass.data[DATA_MPUBSUB].client.config.port


# --- the ReceiveMessage shape ------------------------------------------------


def test_receive_message_matches_the_mqtt_dataclass() -> None:
    """The first six fields are mqtt.ReceiveMessage's, in its order.

    Hard-coded rather than introspected from mqtt so that a rename on either
    side is caught here instead of at a user's callback. The mpubsub-only
    fields come after, all with defaults, so positional construction against
    the MQTT shape still works.
    """
    fields = [f.name for f in dataclasses.fields(ReceiveMessage)]
    assert fields[:6] == [
        "topic",
        "payload",
        "qos",
        "retain",
        "subscribed_topic",
        "timestamp",
    ]
    assert fields[6:] == ["was_encrypted", "wire_encoding", "sender_timestamp"]

    # Constructible exactly as mqtt's is.
    msg = ReceiveMessage("t", "p", 0, False, "t", 1.0)
    assert msg.payload == "p"
    assert msg.was_encrypted is False


# --- topic validation --------------------------------------------------------


@pytest.mark.parametrize("topic", ["home/+/temp", "home/#", "+", "#", "a/+"])
def test_wildcards_rejected(topic: str) -> None:
    """The error must name the limitation, not just say 'invalid'.

    A user reaching for a wildcard is porting an MQTT config and needs to
    know the protocol cannot do this, not that they typed something wrong.
    """
    with pytest.raises(TopicError, match="wildcard"):
        validate_topic(topic)


@pytest.mark.parametrize(
    "topic",
    [
        "a",
        "home/kitchen/temp",
        "x" * 200,  # exactly at the ESPHome limit
        "unicode/ünïcødé",
    ],
)
def test_valid_topics_accepted(topic: str) -> None:
    assert validate_topic(topic) == topic


@pytest.mark.parametrize(
    ("topic", "match"),
    [
        ("", "empty"),
        ("x" * 201, "too long"),
        ("a\x00b", "NUL"),
        ("ü" * 101, "too long"),  # 202 bytes: the limit is bytes, not chars
    ],
)
def test_invalid_topics_rejected(topic: str, match: str) -> None:
    """Same accept/reject set as components/mpubsub/__init__.py:226-241."""
    with pytest.raises(TopicError, match=match):
        validate_topic(topic)


# --- publish -----------------------------------------------------------------


async def test_async_publish_round_trips(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append)

    await async_publish(hass, TOPIC, "21.5")
    await wait_for(got)

    assert got[0].payload == "21.5"


async def test_publish_accepts_non_string_payloads(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """mqtt stringifies numbers; so do we."""
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append)

    await async_publish(hass, TOPIC, 21.5)
    await wait_for(got)

    assert got[0].payload == "21.5"


async def test_publish_bytes_payload(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append, encoding=None)

    await async_publish(hass, TOPIC, b"\x01\x02")
    await wait_for(got)

    assert got[0].payload == b"\x01\x02"


async def test_publish_retain_is_accepted_and_ignored(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """The whole point of accepting retain: MQTT-shaped code must not break.

    It must still publish, and must say why nothing will remember it.
    """
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append)

    await async_publish(hass, TOPIC, "x", retain=True)
    await wait_for(got)

    assert len(got) == 1, "retain=True must not suppress the publish"
    assert got[0].retain is False, "nothing on the wire carries retain"
    assert "retain=True ignored" in caplog.text


async def test_publish_qos_is_accepted(hass: HomeAssistant, setup_mpubsub) -> None:
    """qos must not raise even though promote_qos is off by default."""
    await setup_mpubsub()
    for qos in (0, 1, 2):
        await async_publish(hass, TOPIC, "x", qos=qos)


async def test_publish_wildcard_raises(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub()
    with pytest.raises(TopicError, match="wildcard"):
        await async_publish(hass, "home/+/temp", "x")


async def test_publish_oversize_raises(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub()
    with pytest.raises(ValueError, match="payload too large"):
        await async_publish(hass, TOPIC, "x" * 1221)


# --- subscribe ---------------------------------------------------------------


async def test_subscribe_qos_argument_is_accepted(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """There is no broker to negotiate with, so qos is inert -- but code
    lifted from an mqtt setup will pass it and must not break."""
    await setup_mpubsub()
    got: list = []
    await async_subscribe(hass, TOPIC, got.append, qos=2)

    send_raw(TOPIC, b"x", _port(hass))
    await wait_for(got)
    assert got[0].qos == 0


async def test_subscribe_wildcard_raises(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub()
    with pytest.raises(TopicError, match="wildcard"):
        await async_subscribe(hass, "home/#", lambda _msg: None)


async def test_unsubscribe_stops_delivery(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    got: list = []
    unsub = await async_subscribe(hass, TOPIC, got.append)
    unsub()
    await hass.async_block_till_done()

    send_raw(TOPIC, b"x", _port(hass))
    await hass.async_block_till_done()
    assert got == []


# --- readiness ---------------------------------------------------------------


async def test_wait_for_client(hass: HomeAssistant, setup_mpubsub) -> None:
    assert await async_wait_for_client(hass) is False, "not set up yet"
    await setup_mpubsub()
    assert await async_wait_for_client(hass) is True


async def test_api_without_setup_raises(hass: HomeAssistant) -> None:
    """A clear error beats an AttributeError on hass.data."""
    with pytest.raises(HomeAssistantError, match="not set up"):
        await async_publish(hass, TOPIC, "x")


# --- unload ------------------------------------------------------------------


async def test_unload_closes_the_socket(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    entry = await setup_mpubsub()
    assert await async_wait_for_client(hass) is True

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert await async_wait_for_client(hass) is False
    assert not hass.services.has_service("mpubsub", "publish")
