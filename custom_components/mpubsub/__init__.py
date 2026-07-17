"""mpubsub for Home Assistant -- brokerless IPv6-multicast pub/sub.

This mirrors the API of the built-in ``mqtt`` integration where the semantics
exist, and diverges loudly where they don't:

    from custom_components.mpubsub import async_publish, async_subscribe

    await async_publish(hass, "home/fan/cmd", "ON")
    unsub = await async_subscribe(hass, "home/kitchen/temp", handle)

mpubsub has no broker, no retain, no QoS, no last will, and no wildcards --
the wire carries a CRC32 of the topic rather than the topic itself, so a
receiver must be told the exact string. ``qos`` and ``retain`` are accepted
on publish so MQTT-shaped code keeps working; see docs/HOMEASSISTANT.md for
the full caveat table.
"""

from __future__ import annotations

import asyncio
import logging
from ast import literal_eval
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import CONF_PORT, EVENT_HOMEASSISTANT_STOP, Platform
from homeassistant.core import (
    CALLBACK_TYPE,
    HomeAssistant,
    ServiceCall,
    ServiceResponse,
    SupportsResponse,
    callback,
)
from homeassistant.exceptions import ConfigEntryNotReady, HomeAssistantError
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.typing import ConfigType

from .client import MpubsubClient
from .const import (
    CONF_DURATION,
    CONF_ENCODING,
    CONF_ENCRYPTION_KEY,
    CONF_EVALUATE_PAYLOAD,
    CONF_HOPS,
    CONF_INTERFACE,
    CONF_PAYLOAD,
    CONF_PROMOTE_QOS,
    CONF_QOS,
    CONF_REPLAY_WINDOW,
    CONF_RETAIN,
    CONF_RETRANSMIT_COUNT,
    CONF_RETRANSMIT_DELAY,
    CONF_SCOPE,
    CONF_TOPIC,
    DATA_MPUBSUB,
    DATA_MPUBSUB_CONFIG,
    DEFAULT_ENCODING,
    DEFAULT_HOPS,
    DEFAULT_LISTEN_DURATION,
    DEFAULT_PORT,
    DEFAULT_PROMOTE_QOS,
    DEFAULT_QOS,
    DEFAULT_REPLAY_WINDOW,
    DEFAULT_RETRANSMIT_COUNT,
    DEFAULT_RETRANSMIT_DELAY,
    DEFAULT_SCOPE,
    DOMAIN,
    EVENT_MESSAGE_RECEIVED,
    SCOPES,
)
from .models import (
    MessageCallbackType,
    MpubsubConfig,
    MpubsubData,
    PublishPayloadType,
    ReceiveMessage,
)
from .reference import derive_key
from .util import TopicError, valid_topic, validate_topic

_LOGGER = logging.getLogger(__name__)

__all__ = [
    "DOMAIN",
    "ReceiveMessage",
    "async_publish",
    "async_subscribe",
    "async_wait_for_client",
    "publish",
]

SERVICE_PUBLISH = "publish"
SERVICE_LISTEN = "listen"

# The mpubsub: YAML key carries entity config only -- never connection
# config, which lives in the config entry. Same split as mqtt: post-2022.6.
# The per-platform schemas validate their own entries at platform setup.
CONFIG_SCHEMA = vol.Schema(
    {DOMAIN: vol.Schema({cv.string: vol.All(cv.ensure_list, [dict])})},
    extra=vol.ALLOW_EXTRA,
)

SERVICE_PUBLISH_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_TOPIC): valid_topic,
        vol.Optional(CONF_PAYLOAD): cv.string,
        vol.Optional(CONF_EVALUATE_PAYLOAD, default=False): cv.boolean,
        vol.Optional(CONF_QOS, default=DEFAULT_QOS): vol.All(
            vol.Coerce(int), vol.In([0, 1, 2])
        ),
        vol.Optional(CONF_RETAIN, default=False): cv.boolean,
    }
)

SERVICE_LISTEN_SCHEMA = vol.Schema(
    {
        vol.Required(CONF_TOPIC): valid_topic,
        vol.Optional(CONF_DURATION, default=DEFAULT_LISTEN_DURATION): vol.All(
            vol.Coerce(float), vol.Range(min=0.1, max=300)
        ),
        vol.Optional(CONF_ENCODING, default=DEFAULT_ENCODING): vol.Any(cv.string, None),
    }
)


def _config_from_entry(entry: ConfigEntry) -> MpubsubConfig:
    """Flatten a config entry into what MpubsubClient wants."""
    data = entry.data
    options = entry.options
    passphrase = data.get(CONF_ENCRYPTION_KEY) or ""
    interface = data.get(CONF_INTERFACE) or None
    return MpubsubConfig(
        port=data.get(CONF_PORT, DEFAULT_PORT),
        scope=SCOPES[data.get(CONF_SCOPE, DEFAULT_SCOPE)],
        interface=interface,
        key=derive_key(passphrase) if passphrase else None,
        hops=options.get(CONF_HOPS, DEFAULT_HOPS),
        retransmit_count=options.get(
            CONF_RETRANSMIT_COUNT, DEFAULT_RETRANSMIT_COUNT
        ),
        retransmit_delay=options.get(
            CONF_RETRANSMIT_DELAY, DEFAULT_RETRANSMIT_DELAY
        ),
        promote_qos=options.get(CONF_PROMOTE_QOS, DEFAULT_PROMOTE_QOS),
        replay_window=int(options.get(CONF_REPLAY_WINDOW, DEFAULT_REPLAY_WINDOW)),
    )


async def async_setup(hass: HomeAssistant, config: ConfigType) -> bool:
    """Stash the YAML entity config for the platforms to pick up."""
    conf = config.get(DOMAIN)
    if conf is not None:
        hass.data[DATA_MPUBSUB_CONFIG] = conf
    return True


async def async_setup_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Open the socket and bring up the platforms."""
    client = MpubsubClient(hass, _config_from_entry(entry))
    try:
        await client.async_start()
    except OSError as err:
        # A bind failure (port in use, no IPv6) is worth retrying: the
        # conflicting process may go away.
        raise ConfigEntryNotReady(
            f"Could not open the mpubsub socket on port "
            f"{entry.data.get(CONF_PORT, DEFAULT_PORT)}: {err}"
        ) from err

    yaml_config: dict[str, Any] = hass.data.get(DATA_MPUBSUB_CONFIG, {})
    hass.data[DATA_MPUBSUB] = MpubsubData(client=client, config=yaml_config)

    _async_register_services(hass)
    entry.async_on_unload(entry.add_update_listener(_async_reload_entry))
    entry.async_on_unload(
        hass.bus.async_listen_once(
            EVENT_HOMEASSISTANT_STOP, lambda _event: client.async_stop()
        )
    )

    await hass.config_entries.async_forward_entry_setups(entry, _platforms(yaml_config))
    return True


def _platforms(yaml_config: dict[str, Any]) -> list[Platform]:
    """Only forward to platforms that actually have config.

    There is no discovery, so a platform with no YAML entries has nothing to
    do and forwarding to it just costs startup time.
    """
    return [
        platform
        for platform in (Platform.BINARY_SENSOR, Platform.SENSOR, Platform.SWITCH)
        if yaml_config.get(platform.value)
    ]


async def async_unload_entry(hass: HomeAssistant, entry: ConfigEntry) -> bool:
    """Tear down platforms, then the socket."""
    data: MpubsubData = hass.data[DATA_MPUBSUB]
    unloaded = await hass.config_entries.async_unload_platforms(
        entry, _platforms(data.config)
    )
    if unloaded:
        await data.client.async_stop()
        hass.data.pop(DATA_MPUBSUB, None)
        hass.services.async_remove(DOMAIN, SERVICE_PUBLISH)
        hass.services.async_remove(DOMAIN, SERVICE_LISTEN)
    return unloaded


async def _async_reload_entry(hass: HomeAssistant, entry: ConfigEntry) -> None:
    """An options change rebuilds the client -- port/scope/key all bake in."""
    await hass.config_entries.async_reload(entry.entry_id)


def _get_client(hass: HomeAssistant) -> MpubsubClient:
    data: MpubsubData | None = hass.data.get(DATA_MPUBSUB)
    if data is None:
        raise HomeAssistantError(
            "mpubsub is not set up. Add it under Settings -> Devices & "
            "Services before publishing or subscribing."
        )
    return data.client


# --- Public API (mirrors homeassistant.components.mqtt) ----------------------


async def async_publish(
    hass: HomeAssistant,
    topic: str,
    payload: PublishPayloadType,
    qos: int | None = 0,
    retain: bool | None = False,
    encoding: str | None = DEFAULT_ENCODING,
) -> None:
    """Publish to a topic. Signature-identical to mqtt.async_publish.

    ``retain`` is accepted and ignored: there is no retain flag on the wire
    and no broker to hold anything.

    ``qos`` is accepted and, when the ``promote_qos`` option is on, raises
    the retransmit count (0 -> configured, 1 -> at least 3, 2 -> keep
    resending until superseded). It is not a delivery guarantee -- nothing
    here acknowledges anything.

    Raises TopicError for a wildcard or malformed topic, and ValueError for a
    payload over the ~1220-byte datagram limit.
    """
    client = _get_client(hass)
    payload_bytes = _encode_payload(payload, encoding)
    client.async_publish(topic, payload_bytes, qos or 0, bool(retain))


@callback
def publish(
    hass: HomeAssistant,
    topic: str,
    payload: PublishPayloadType,
    qos: int | None = 0,
    retain: bool | None = False,
    encoding: str | None = DEFAULT_ENCODING,
) -> None:
    """Sync wrapper for :func:`async_publish`, as mqtt.publish is."""
    hass.create_task(async_publish(hass, topic, payload, qos, retain, encoding))


def _encode_payload(payload: PublishPayloadType, encoding: str | None) -> bytes:
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    if not isinstance(payload, str):
        payload = str(payload)
    return payload.encode(encoding or DEFAULT_ENCODING)


async def async_subscribe(
    hass: HomeAssistant,
    topic: str,
    msg_callback: MessageCallbackType,
    qos: int = 0,
    encoding: str | None = DEFAULT_ENCODING,
) -> CALLBACK_TYPE:
    """Subscribe to an exact topic. Signature-identical to mqtt.async_subscribe.

    ``qos`` is accepted and ignored -- there is no broker to negotiate a
    delivery guarantee with.

    Unlike mqtt's, this awaits a real multicast group join, so it can raise
    OSError where mqtt would queue the SUBSCRIBE until reconnect. It raises
    TopicError for a wildcard: the wire carries only a topic CRC32, so there
    is nothing to pattern-match and no group to join for a pattern.
    """
    client = _get_client(hass)
    return await client.async_subscribe(topic, msg_callback, encoding)


async def async_wait_for_client(hass: HomeAssistant) -> bool:
    """True once the socket is open; the analogue of
    mqtt.async_wait_for_mqtt_client.

    There is no connection to establish, so this is immediate in practice. It
    exists so entity and automation code can keep the same "is it ready?"
    idiom.
    """
    data: MpubsubData | None = hass.data.get(DATA_MPUBSUB)
    if data is None:
        return False
    return data.client.available


# --- Services ----------------------------------------------------------------


@callback
def _async_register_services(hass: HomeAssistant) -> None:
    if hass.services.has_service(DOMAIN, SERVICE_PUBLISH):
        return

    hass.services.async_register(
        DOMAIN, SERVICE_PUBLISH, _async_publish_service, SERVICE_PUBLISH_SCHEMA
    )
    hass.services.async_register(
        DOMAIN,
        SERVICE_LISTEN,
        _async_listen_service,
        SERVICE_LISTEN_SCHEMA,
        supports_response=SupportsResponse.OPTIONAL,
    )


async def _async_publish_service(call: ServiceCall) -> None:
    """mpubsub.publish -- the mqtt.publish analogue."""
    payload: PublishPayloadType = call.data.get(CONF_PAYLOAD, "")
    if call.data[CONF_EVALUATE_PAYLOAD] and isinstance(payload, str):
        try:
            payload = literal_eval(payload)
        except (ValueError, TypeError, SyntaxError, MemoryError) as err:
            raise HomeAssistantError(
                f"Payload {payload!r} could not be evaluated as a Python "
                f"literal: {err}"
            ) from err
    try:
        await async_publish(
            call.hass,
            call.data[CONF_TOPIC],
            payload,
            call.data[CONF_QOS],
            call.data[CONF_RETAIN],
        )
    except (TopicError, ValueError) as err:
        raise HomeAssistantError(str(err)) from err


async def _async_listen_service(call: ServiceCall) -> ServiceResponse:
    """mpubsub.listen -- the debug surface.

    Home Assistant's MQTT troubleshooting panel is hardcoded in the frontend
    to the mqtt domain, so a custom integration cannot reuse it. This gives
    the same two affordances through Developer Tools instead: the messages
    are returned as a service response (Actions shows them inline) and each
    is also fired on the event bus as mpubsub_message_received, which
    Developer Tools -> Events can watch live.

    mqtt.dump has no analogue: it needs a '#' subscription, and a receiver
    here has to know the exact topic. tests/probe.py --listen is the
    out-of-HA equivalent.
    """
    hass = call.hass
    topic: str = call.data[CONF_TOPIC]
    duration: float = call.data[CONF_DURATION]
    encoding: str | None = call.data[CONF_ENCODING]

    collected: list[dict[str, Any]] = []

    @callback
    def _got(msg: ReceiveMessage) -> None:
        record = {
            "topic": msg.topic,
            "payload": msg.payload
            if isinstance(msg.payload, str)
            else msg.payload.hex(),
            "was_encrypted": msg.was_encrypted,
            "sender_timestamp": msg.sender_timestamp,
        }
        collected.append(record)
        hass.bus.async_fire(EVENT_MESSAGE_RECEIVED, record)

    try:
        unsub = await async_subscribe(hass, topic, _got, encoding=encoding)
    except TopicError as err:
        raise HomeAssistantError(str(err)) from err

    try:
        await asyncio.sleep(duration)
    finally:
        # Always unsubscribe: a debug subscription that outlived its call
        # would hold a multicast group open forever.
        unsub()

    return {"messages": collected, "count": len(collected)}
