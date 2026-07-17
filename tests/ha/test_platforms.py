"""Entity platforms: sensor, binary_sensor, switch.

The recurring theme is the no-retain contract. In MQTT an entity gets its
state back instantly at startup from the broker's retained message; here
there is nothing to replay, so entities begin unknown and stay there until a
packet arrives. That is asserted as a feature rather than worked around,
because it is the thing most likely to surprise someone porting a config.
"""

from __future__ import annotations

import asyncio

import pytest
import voluptuous as vol
from homeassistant.const import STATE_OFF, STATE_ON, STATE_UNAVAILABLE, STATE_UNKNOWN
from homeassistant.core import HomeAssistant
from homeassistant.util import dt as dt_util
from pytest_homeassistant_custom_component.common import async_fire_time_changed

from datetime import timedelta

from custom_components.mpubsub.const import DATA_MPUBSUB
from custom_components.mpubsub.reference import decode
from helpers import Sniffer, requires_multicast, send_raw

pytestmark = requires_multicast

TOPIC = "test/temp"
CMD = "test/cmd"


def _port(hass: HomeAssistant) -> int:
    return hass.data[DATA_MPUBSUB].client.config.port


async def _settle(hass: HomeAssistant, entity_id: str, want: str, timeout=2.0):
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while loop.time() < end:
        state = hass.states.get(entity_id)
        if state is not None and state.state == want:
            return state
        await asyncio.sleep(0.01)
    return hass.states.get(entity_id)


# --- sensor ------------------------------------------------------------------


SENSOR_YAML = {
    "sensor": [
        {
            "name": "Kitchen Temp",
            "unique_id": "kitchen_temp",
            "state_topic": TOPIC,
            "unit_of_measurement": "°C",
            "device_class": "temperature",
            "state_class": "measurement",
        }
    ]
}


async def test_sensor_starts_unknown(hass: HomeAssistant, setup_mpubsub) -> None:
    """The no-retain contract, asserted as a feature.

    Nothing replays the last value, so until a packet arrives there is
    genuinely nothing to show. Someone porting an mqtt: block will notice
    this first.
    """
    await setup_mpubsub(yaml_config=SENSOR_YAML)
    state = hass.states.get("sensor.kitchen_temp")
    assert state is not None
    assert state.state == STATE_UNKNOWN


async def test_sensor_takes_state_from_a_packet(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub(yaml_config=SENSOR_YAML)
    send_raw(TOPIC, b"21.5", _port(hass))
    state = await _settle(hass, "sensor.kitchen_temp", "21.5")

    assert state.state == "21.5"
    assert state.attributes["unit_of_measurement"] == "°C"
    assert state.attributes["device_class"] == "temperature"


async def test_sensor_value_template(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub(
        yaml_config={
            "sensor": [
                {
                    "name": "Templated",
                    "unique_id": "templated",
                    "state_topic": TOPIC,
                    "value_template": "{{ value_json.temp }}",
                }
            ]
        }
    )
    send_raw(TOPIC, b'{"temp": 19.25}', _port(hass))
    state = await _settle(hass, "sensor.templated", "19.25")
    assert state.state == "19.25"


async def test_sensor_expire_after(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """expire_after is the only liveness mechanism the protocol can offer:
    there is no last will, so nothing announces a dead publisher."""
    await setup_mpubsub(
        yaml_config={
            "sensor": [
                {
                    "name": "Expiring",
                    "unique_id": "expiring",
                    "state_topic": TOPIC,
                    "expire_after": 30,
                }
            ]
        }
    )
    send_raw(TOPIC, b"1.0", _port(hass))
    assert (await _settle(hass, "sensor.expiring", "1.0")).state == "1.0"

    # Jump the scheduler forward rather than freezing the clock: these
    # tests wait on real sockets, and a frozen clock stops asyncio.sleep
    # from ever advancing.
    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=31))
    await hass.async_block_till_done()

    assert hass.states.get("sensor.expiring").state == STATE_UNKNOWN


async def test_sensor_wildcard_topic_rejected(hass: HomeAssistant) -> None:
    from custom_components.mpubsub.sensor import PLATFORM_SCHEMA

    with pytest.raises(vol.Invalid, match="wildcard"):
        PLATFORM_SCHEMA({"name": "x", "state_topic": "home/+/temp"})


async def test_sensor_without_unique_id_warns(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """No discovery means nobody can supply a unique_id but the user, and
    without one the entity can't be customised in the UI."""
    await setup_mpubsub(
        yaml_config={"sensor": [{"name": "Anon", "state_topic": TOPIC}]}
    )
    assert "has no unique_id" in caplog.text


# --- availability ------------------------------------------------------------


async def test_availability_topic(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub(
        yaml_config={
            "sensor": [
                {
                    "name": "Avail",
                    "unique_id": "avail",
                    "state_topic": TOPIC,
                    "availability_topic": "test/status",
                }
            ]
        }
    )
    # An availability_topic means we start unavailable: nothing has said
    # "online" yet, and no retained message will.
    assert hass.states.get("sensor.avail").state == STATE_UNAVAILABLE

    send_raw("test/status", b"online", _port(hass))
    await _settle(hass, "sensor.avail", STATE_UNKNOWN)
    assert hass.states.get("sensor.avail").state == STATE_UNKNOWN

    send_raw("test/status", b"offline", _port(hass))
    await _settle(hass, "sensor.avail", STATE_UNAVAILABLE)
    assert hass.states.get("sensor.avail").state == STATE_UNAVAILABLE


# --- binary_sensor -----------------------------------------------------------


async def test_binary_sensor_payload_on_off(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub(
        yaml_config={
            "binary_sensor": [
                {
                    "name": "Door",
                    "unique_id": "door",
                    "state_topic": TOPIC,
                    "device_class": "door",
                }
            ]
        }
    )
    assert hass.states.get("binary_sensor.door").state == STATE_UNKNOWN

    send_raw(TOPIC, b"ON", _port(hass))
    assert (await _settle(hass, "binary_sensor.door", STATE_ON)).state == STATE_ON

    send_raw(TOPIC, b"OFF", _port(hass))
    assert (await _settle(hass, "binary_sensor.door", STATE_OFF)).state == STATE_OFF


async def test_binary_sensor_custom_payloads(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub(
        yaml_config={
            "binary_sensor": [
                {
                    "name": "Custom",
                    "unique_id": "custom",
                    "state_topic": TOPIC,
                    "payload_on": "1",
                    "payload_off": "0",
                }
            ]
        }
    )
    send_raw(TOPIC, b"1", _port(hass))
    assert (await _settle(hass, "binary_sensor.custom", STATE_ON)).state == STATE_ON


async def test_binary_sensor_off_delay(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """For a device that only ever announces the ON edge -- a doorbell."""
    await setup_mpubsub(
        yaml_config={
            "binary_sensor": [
                {
                    "name": "Bell",
                    "unique_id": "bell",
                    "state_topic": TOPIC,
                    "off_delay": 5,
                }
            ]
        }
    )
    send_raw(TOPIC, b"ON", _port(hass))
    assert (await _settle(hass, "binary_sensor.bell", STATE_ON)).state == STATE_ON

    async_fire_time_changed(hass, dt_util.utcnow() + timedelta(seconds=6))
    await hass.async_block_till_done()
    assert hass.states.get("binary_sensor.bell").state == STATE_OFF


# --- switch ------------------------------------------------------------------


async def test_switch_optimistic_by_default_without_state_topic(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """mqtt's rule, kept: no state_topic means we can only assume."""
    await setup_mpubsub(
        yaml_config={
            "switch": [{"name": "Fan", "unique_id": "fan", "command_topic": CMD}]
        }
    )
    state = hass.states.get("switch.fan")
    assert state.attributes["assumed_state"] is True


async def test_switch_turn_on_publishes(hass: HomeAssistant, setup_mpubsub) -> None:
    await setup_mpubsub(
        yaml_config={
            "switch": [{"name": "Fan", "unique_id": "fan", "command_topic": CMD}]
        }
    )
    sniffer = Sniffer(CMD, _port(hass))
    try:
        await hass.services.async_call(
            "switch", "turn_on", {"entity_id": "switch.fan"}, blocking=True
        )
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1
    assert decode(packets[0]).payload == b"ON"
    # Optimistic, so the state moves without any confirmation.
    assert hass.states.get("switch.fan").state == STATE_ON


async def test_switch_with_state_topic_is_not_optimistic(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """With a state_topic the switch waits for the device.

    mqtt would show the retained state immediately; here there is nothing
    retained, so it reads unknown until the device publishes.
    """
    await setup_mpubsub(
        yaml_config={
            "switch": [
                {
                    "name": "Lamp",
                    "unique_id": "lamp",
                    "command_topic": CMD,
                    "state_topic": TOPIC,
                }
            ]
        }
    )
    state = hass.states.get("switch.lamp")
    assert state.state == STATE_UNKNOWN
    assert state.attributes.get("assumed_state") is not True

    send_raw(TOPIC, b"ON", _port(hass))
    assert (await _settle(hass, "switch.lamp", STATE_ON)).state == STATE_ON


async def test_switch_retain_accepted_and_ignored(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """An mqtt: switch block with retain: true must port over and still work."""
    await setup_mpubsub(
        yaml_config={
            "switch": [
                {
                    "name": "Fan",
                    "unique_id": "fan",
                    "command_topic": CMD,
                    "retain": True,
                }
            ]
        }
    )
    sniffer = Sniffer(CMD, _port(hass))
    try:
        await hass.services.async_call(
            "switch", "turn_on", {"entity_id": "switch.fan"}, blocking=True
        )
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1, "retain must not suppress the command"
    assert "retain=True ignored" in caplog.text


async def test_switch_custom_state_payloads(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    await setup_mpubsub(
        yaml_config={
            "switch": [
                {
                    "name": "Lamp",
                    "unique_id": "lamp",
                    "command_topic": CMD,
                    "state_topic": TOPIC,
                    "state_on": "running",
                    "state_off": "stopped",
                }
            ]
        }
    )
    send_raw(TOPIC, b"running", _port(hass))
    assert (await _settle(hass, "switch.lamp", STATE_ON)).state == STATE_ON


# --- teardown ----------------------------------------------------------------


async def test_unload_stops_the_client_and_strands_entities(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """Unloading closes the socket; the entities go unavailable.

    They do not vanish: an entity with a unique_id is in the registry, so HA
    keeps a restored, unavailable state for it. That is the normal shape of
    an unloaded integration, not a leak.
    """
    entry = await setup_mpubsub(yaml_config=SENSOR_YAML)
    client = hass.data[DATA_MPUBSUB].client
    assert TOPIC in client._subs

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()

    assert hass.states.get("sensor.kitchen_temp").state == STATE_UNAVAILABLE
    assert not client.available, "the socket must be closed"


async def test_removing_an_entity_leaves_its_group(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """The entity's own unsubscribe path, tested without tearing the whole
    entry down (which would clear the subscriptions regardless and prove
    nothing about the entity)."""
    from homeassistant.helpers import entity_registry as er

    await setup_mpubsub(yaml_config=SENSOR_YAML)
    client = hass.data[DATA_MPUBSUB].client
    assert TOPIC in client._subs

    er.async_get(hass).async_remove("sensor.kitchen_temp")
    await hass.async_block_till_done()

    assert TOPIC not in client._subs, "the last subscriber left; leave the group"
    assert client._crc_index == {}
