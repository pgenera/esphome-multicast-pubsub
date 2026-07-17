"""mpubsub switch platform."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components.switch import DEVICE_CLASSES_SCHEMA, SwitchEntity
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_DEVICE_CLASS,
    CONF_OPTIMISTIC,
    CONF_PAYLOAD_OFF,
    CONF_PAYLOAD_ON,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback

from . import async_publish
from .const import (
    CONF_COMMAND_TOPIC,
    CONF_QOS,
    CONF_RETAIN,
    CONF_STATE_OFF,
    CONF_STATE_ON,
    CONF_STATE_TOPIC,
    DATA_MPUBSUB,
    DEFAULT_PAYLOAD_OFF,
    DEFAULT_PAYLOAD_ON,
)
from .entity import (
    MPUBSUB_ENTITY_COMMON_SCHEMA,
    MpubsubEntity,
    warn_if_no_unique_id,
)
from .models import ReceiveMessage
from .util import valid_topic

PLATFORM_SCHEMA = MPUBSUB_ENTITY_COMMON_SCHEMA.extend(
    {
        vol.Required(CONF_COMMAND_TOPIC): valid_topic,
        vol.Optional(CONF_STATE_TOPIC): valid_topic,
        vol.Optional(CONF_PAYLOAD_ON, default=DEFAULT_PAYLOAD_ON): cv.string,
        vol.Optional(CONF_PAYLOAD_OFF, default=DEFAULT_PAYLOAD_OFF): cv.string,
        vol.Optional(CONF_STATE_ON): cv.string,
        vol.Optional(CONF_STATE_OFF): cv.string,
        vol.Optional(CONF_OPTIMISTIC): cv.boolean,
        vol.Optional(CONF_DEVICE_CLASS): vol.Any(DEVICE_CLASSES_SCHEMA, None),
        # Accepted so an mqtt: switch block ports over unchanged; ignored,
        # and debug-logged by the publish path.
        vol.Optional(CONF_RETAIN, default=False): cv.boolean,
    }
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    configs = hass.data[DATA_MPUBSUB].config.get("switch", [])
    entities = []
    for item in configs:
        config = PLATFORM_SCHEMA(item)
        warn_if_no_unique_id(config, "switch")
        entities.append(MpubsubSwitch(config))
    async_add_entities(entities)


class MpubsubSwitch(MpubsubEntity, SwitchEntity):
    """A switch that commands over one topic and optionally reads another."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._attr_device_class = config.get(CONF_DEVICE_CLASS)
        self._state_on = config.get(CONF_STATE_ON) or config[CONF_PAYLOAD_ON]
        self._state_off = config.get(CONF_STATE_OFF) or config[CONF_PAYLOAD_OFF]
        # mqtt's rule, kept: no state_topic means we can only assume.
        self._optimistic = config.get(CONF_OPTIMISTIC)
        if self._optimistic is None:
            self._optimistic = CONF_STATE_TOPIC not in config
        # With a state_topic we wait for the device to speak. mqtt would show
        # the retained state instantly; there is nothing retained here, so an
        # optimistic switch's state also does not survive a restart.
        self._attr_is_on = None

    @property
    def assumed_state(self) -> bool:
        return bool(self._optimistic)

    async def _subscribe_topics(self) -> None:
        if (topic := self._config.get(CONF_STATE_TOPIC)) is None:
            return

        @callback
        def _message(msg: ReceiveMessage) -> None:
            payload = self._render(msg.payload)
            if payload == self._state_on:
                self._attr_is_on = True
            elif payload == self._state_off:
                self._attr_is_on = False
            else:
                return
            self.async_write_ha_state()

        await self._track(topic, _message)

    async def async_turn_on(self, **kwargs: Any) -> None:
        await self._command(self._config[CONF_PAYLOAD_ON], True)

    async def async_turn_off(self, **kwargs: Any) -> None:
        await self._command(self._config[CONF_PAYLOAD_OFF], False)

    async def _command(self, payload: str, state: bool) -> None:
        await async_publish(
            self.hass,
            self._config[CONF_COMMAND_TOPIC],
            payload,
            self._config[CONF_QOS],
            self._config[CONF_RETAIN],
            self._encoding,
        )
        if self._optimistic:
            self._attr_is_on = state
            self.async_write_ha_state()
