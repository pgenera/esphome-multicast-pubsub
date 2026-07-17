"""Shared entity base and schema for the mpubsub platforms.

Config keys are homeassistant.components.mqtt's, spelled identically, so a
`mqtt:` YAML block usually ports across by renaming the key. What cannot port
is anything that depends on a broker keeping state -- see the retain note on
MpubsubEntity.
"""

from __future__ import annotations

import logging
from typing import Any

import voluptuous as vol
from homeassistant.const import (
    CONF_DEVICE,
    CONF_ENTITY_CATEGORY,
    CONF_ICON,
    CONF_NAME,
    CONF_UNIQUE_ID,
    CONF_VALUE_TEMPLATE,
    EntityCategory,
)
from homeassistant.core import callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.device_registry import DeviceInfo
from homeassistant.helpers.entity import Entity

from . import async_subscribe
from .const import (
    CONF_AVAILABILITY_TEMPLATE,
    CONF_AVAILABILITY_TOPIC,
    CONF_ENCODING,
    CONF_PAYLOAD_AVAILABLE,
    CONF_PAYLOAD_NOT_AVAILABLE,
    CONF_QOS,
    DEFAULT_ENCODING,
    DEFAULT_PAYLOAD_AVAILABLE,
    DEFAULT_PAYLOAD_NOT_AVAILABLE,
    DEFAULT_QOS,
    DOMAIN,
)
from .models import ReceiveMessage
from .util import valid_encoding, valid_topic

_LOGGER = logging.getLogger(__name__)

CONF_ENABLED_BY_DEFAULT = "enabled_by_default"

DEVICE_SCHEMA = vol.Schema(
    {
        vol.Optional("identifiers"): vol.All(cv.ensure_list, [cv.string]),
        vol.Optional("connections"): vol.All(cv.ensure_list, [vol.All(list, vol.Length(2))]),
        vol.Optional("name"): cv.string,
        vol.Optional("manufacturer"): cv.string,
        vol.Optional("model"): cv.string,
        vol.Optional("sw_version"): cv.string,
        vol.Optional("suggested_area"): cv.string,
    }
)

MPUBSUB_ENTITY_COMMON_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_NAME): vol.Any(cv.string, None),
        vol.Optional(CONF_UNIQUE_ID): cv.string,
        vol.Optional(CONF_ICON): cv.icon,
        vol.Optional(CONF_ENTITY_CATEGORY): vol.Coerce(EntityCategory),
        vol.Optional(CONF_ENABLED_BY_DEFAULT, default=True): cv.boolean,
        vol.Optional(CONF_DEVICE): DEVICE_SCHEMA,
        vol.Optional(CONF_QOS, default=DEFAULT_QOS): vol.All(
            vol.Coerce(int), vol.In([0, 1, 2])
        ),
        vol.Optional(CONF_ENCODING, default=DEFAULT_ENCODING): valid_encoding,
        vol.Optional(CONF_VALUE_TEMPLATE): cv.template,
        vol.Optional(CONF_AVAILABILITY_TOPIC): valid_topic,
        vol.Optional(CONF_AVAILABILITY_TEMPLATE): cv.template,
        vol.Optional(
            CONF_PAYLOAD_AVAILABLE, default=DEFAULT_PAYLOAD_AVAILABLE
        ): cv.string,
        vol.Optional(
            CONF_PAYLOAD_NOT_AVAILABLE, default=DEFAULT_PAYLOAD_NOT_AVAILABLE
        ): cv.string,
    }
)


def warn_if_no_unique_id(config: dict[str, Any], platform: str) -> None:
    """Nag once per entity that can't be edited in the UI.

    Deriving a unique_id from the topic is tempting and wrong: it would
    collide between two entities on one topic, and change if the topic were
    renamed, orphaning the registry entry. There is no discovery to supply
    one either, so the user has to.
    """
    if CONF_UNIQUE_ID not in config:
        _LOGGER.warning(
            "mpubsub %s %r has no unique_id, so it cannot be renamed, "
            "assigned to an area, or customised in the UI. Add one.",
            platform,
            config.get(CONF_NAME) or config.get("state_topic") or "<unnamed>",
        )


class MpubsubEntity(Entity):
    """Subscription lifecycle, availability, and value templating."""

    _attr_should_poll = False
    _attr_has_entity_name = False

    def __init__(self, config: dict[str, Any]) -> None:
        self._config = config
        self._sub_state: list = []

        self._attr_name = config.get(CONF_NAME)
        self._attr_unique_id = config.get(CONF_UNIQUE_ID)
        self._attr_icon = config.get(CONF_ICON)
        self._attr_entity_category = config.get(CONF_ENTITY_CATEGORY)
        self._attr_entity_registry_enabled_default = config[CONF_ENABLED_BY_DEFAULT]

        # No retain and no broker: nothing replays the last value at startup,
        # so every entity begins life unknown and stays there until a packet
        # arrives. For a 1 Hz sensor that is a second; for something that
        # only publishes on an event it can be days. This is why expire_after
        # matters more here than it does in mqtt.
        self._attr_available = self._config.get(CONF_AVAILABILITY_TOPIC) is None

        if (device := config.get(CONF_DEVICE)) is not None:
            self._attr_device_info = DeviceInfo(
                identifiers={(DOMAIN, i) for i in device.get("identifiers", [])},
                connections={tuple(c) for c in device.get("connections", [])},
                name=device.get("name"),
                manufacturer=device.get("manufacturer"),
                model=device.get("model"),
                sw_version=device.get("sw_version"),
                suggested_area=device.get("suggested_area"),
            )

    @property
    def _encoding(self) -> str | None:
        return self._config[CONF_ENCODING]

    async def async_added_to_hass(self) -> None:
        await self._subscribe_availability()
        await self._subscribe_topics()

    async def async_will_remove_from_hass(self) -> None:
        for unsub in self._sub_state:
            unsub()
        self._sub_state.clear()

    async def _subscribe_topics(self) -> None:
        """Subclass hook: register the platform's own subscriptions."""

    async def _track(self, topic: str, handler) -> None:
        self._sub_state.append(
            await async_subscribe(self.hass, topic, handler, encoding=self._encoding)
        )

    async def _subscribe_availability(self) -> None:
        topic = self._config.get(CONF_AVAILABILITY_TOPIC)
        if topic is None:
            return

        @callback
        def _availability(msg: ReceiveMessage) -> None:
            payload = msg.payload
            if (tpl := self._config.get(CONF_AVAILABILITY_TEMPLATE)) is not None:
                payload = tpl.async_render_with_possible_json_value(payload, None)
            if payload == self._config[CONF_PAYLOAD_AVAILABLE]:
                self._attr_available = True
            elif payload == self._config[CONF_PAYLOAD_NOT_AVAILABLE]:
                self._attr_available = False
            else:
                return
            self.async_write_ha_state()

        await self._track(topic, _availability)

    def _render(self, payload: str | bytes) -> str | bytes | None:
        """Apply value_template, if configured."""
        if (tpl := self._config.get(CONF_VALUE_TEMPLATE)) is None:
            return payload
        rendered = tpl.async_render_with_possible_json_value(payload, None)
        return rendered
