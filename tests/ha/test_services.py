"""mpubsub.publish and mpubsub.listen -- the debug surface.

Home Assistant's MQTT troubleshooting panel is hardcoded in the frontend to
the mqtt domain, so a custom integration cannot reuse it. These two services
give the same affordances through Developer Tools instead, and this module is
what says they actually work.
"""

from __future__ import annotations

import asyncio

import pytest
import voluptuous as vol
from homeassistant.core import HomeAssistant
from homeassistant.exceptions import HomeAssistantError

from custom_components.mpubsub.const import (
    DATA_MPUBSUB,
    DOMAIN,
    EVENT_MESSAGE_RECEIVED,
)
from custom_components.mpubsub.reference import decode, derive_key
from helpers import Sniffer, requires_multicast, send_raw, wait_for

pytestmark = requires_multicast

TOPIC = "test/temp"


def _port(hass: HomeAssistant) -> int:
    return hass.data[DATA_MPUBSUB].client.config.port


# --- mpubsub.publish ---------------------------------------------------------


async def test_publish_service_is_on_the_wire(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    sniffer = Sniffer(TOPIC, _port(hass))
    try:
        await hass.services.async_call(
            DOMAIN, "publish", {"topic": TOPIC, "payload": "21.5"}, blocking=True
        )
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1
    assert decode(packets[0]).payload == b"21.5"


async def test_publish_service_evaluate_payload(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """evaluate_payload lets a bytes literal through, as mqtt's does."""
    await setup_mpubsub()
    sniffer = Sniffer(TOPIC, _port(hass))
    try:
        await hass.services.async_call(
            DOMAIN,
            "publish",
            {"topic": TOPIC, "payload": r"b'\x01\x02'", "evaluate_payload": True},
            blocking=True,
        )
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert decode(packets[0]).payload == b"\x01\x02"


async def test_publish_service_bad_literal_errors(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    with pytest.raises(HomeAssistantError, match="could not be evaluated"):
        await hass.services.async_call(
            DOMAIN,
            "publish",
            {"topic": TOPIC, "payload": "not a literal(", "evaluate_payload": True},
            blocking=True,
        )


async def test_publish_service_rejects_wildcard(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """Rejected by the service schema, before it reaches the client.

    The message has to survive the trip through voluptuous: a user calling
    this from Developer Tools sees only what comes back, and "invalid topic"
    would leave them guessing.
    """
    await setup_mpubsub()
    with pytest.raises(vol.Invalid, match="wildcard"):
        await hass.services.async_call(
            DOMAIN, "publish", {"topic": "home/+/x", "payload": "y"}, blocking=True
        )


async def test_listen_service_rejects_wildcard(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    with pytest.raises(vol.Invalid, match="wildcard"):
        await hass.services.async_call(
            DOMAIN, "listen", {"topic": "home/#"}, blocking=True
        )


async def test_publish_service_retain_is_ignored(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    await setup_mpubsub()
    sniffer = Sniffer(TOPIC, _port(hass))
    try:
        await hass.services.async_call(
            DOMAIN,
            "publish",
            {"topic": TOPIC, "payload": "x", "retain": True},
            blocking=True,
        )
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1
    assert "retain=True ignored" in caplog.text


# --- mpubsub.listen ----------------------------------------------------------


async def test_listen_returns_messages_and_fires_events(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    events: list = []
    hass.bus.async_listen(EVENT_MESSAGE_RECEIVED, events.append)

    task = hass.async_create_task(
        hass.services.async_call(
            DOMAIN,
            "listen",
            {"topic": TOPIC, "duration": 0.5},
            blocking=True,
            return_response=True,
        )
    )
    await asyncio.sleep(0.15)  # let the subscribe land
    send_raw(TOPIC, b"42.5", _port(hass))
    response = await task
    await hass.async_block_till_done()

    assert response["count"] == 1
    assert response["messages"][0]["topic"] == TOPIC
    assert response["messages"][0]["payload"] == "42.5"
    assert response["messages"][0]["was_encrypted"] is False

    assert len(events) == 1, "each message must also hit the event bus"
    assert events[0].data["payload"] == "42.5"


async def test_listen_reports_encryption_state(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    key = derive_key("s3cret")
    await setup_mpubsub(data={"encryption_key": "s3cret"})

    task = hass.async_create_task(
        hass.services.async_call(
            DOMAIN,
            "listen",
            {"topic": TOPIC, "duration": 0.5},
            blocking=True,
            return_response=True,
        )
    )
    await asyncio.sleep(0.15)
    send_raw(TOPIC, b"42.5", _port(hass), key=key)
    response = await task

    assert response["count"] == 1
    assert response["messages"][0]["was_encrypted"] is True
    assert response["messages"][0]["sender_timestamp"] is not None


async def test_listen_unsubscribes_when_done(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """The obvious bug in a timed debug subscription is leaking it.

    A leaked one would hold its multicast group open for the life of the
    process and keep firing events at nobody.
    """
    await setup_mpubsub()
    client = hass.data[DATA_MPUBSUB].client

    await hass.services.async_call(
        DOMAIN, "listen", {"topic": TOPIC, "duration": 0.2}, blocking=True
    )
    await hass.async_block_till_done()

    assert TOPIC not in client._subs, "listen must leave the group when it ends"
    assert client._crc_index == {}


async def test_listen_finds_nothing_on_a_silent_topic(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """An empty result is a real answer -- it means 'nothing is publishing
    here', which is the most common thing a user is debugging."""
    await setup_mpubsub()
    response = await hass.services.async_call(
        DOMAIN,
        "listen",
        {"topic": "test/silent", "duration": 0.2},
        blocking=True,
        return_response=True,
    )
    assert response == {"messages": [], "count": 0}


async def test_listen_encoding_none_reports_hex(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub()
    task = hass.async_create_task(
        hass.services.async_call(
            DOMAIN,
            "listen",
            {"topic": TOPIC, "duration": 0.5, "encoding": None},
            blocking=True,
            return_response=True,
        )
    )
    await asyncio.sleep(0.15)
    send_raw(TOPIC, b"\x01\xff", _port(hass))
    response = await task

    assert response["messages"][0]["payload"] == "01ff"
