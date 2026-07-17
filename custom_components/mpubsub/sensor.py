"""mpubsub sensor platform."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components.sensor import (
    CONF_STATE_CLASS,
    DEVICE_CLASSES_SCHEMA,
    STATE_CLASSES_SCHEMA,
    SensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_DEVICE_CLASS,
    CONF_FORCE_UPDATE,
    CONF_UNIT_OF_MEASUREMENT,
    STATE_UNKNOWN,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import CONF_EXPIRE_AFTER, CONF_STATE_TOPIC, DATA_MPUBSUB
from .entity import (
    MPUBSUB_ENTITY_COMMON_SCHEMA,
    MpubsubEntity,
    warn_if_no_unique_id,
)
from .models import ReceiveMessage
from .util import valid_topic

CONF_SUGGESTED_DISPLAY_PRECISION = "suggested_display_precision"

PLATFORM_SCHEMA = MPUBSUB_ENTITY_COMMON_SCHEMA.extend(
    {
        vol.Required(CONF_STATE_TOPIC): valid_topic,
        vol.Optional(CONF_UNIT_OF_MEASUREMENT): cv.string,
        vol.Optional(CONF_DEVICE_CLASS): vol.Any(DEVICE_CLASSES_SCHEMA, None),
        vol.Optional(CONF_STATE_CLASS): vol.Any(STATE_CLASSES_SCHEMA, None),
        vol.Optional(CONF_SUGGESTED_DISPLAY_PRECISION): cv.positive_int,
        vol.Optional(CONF_FORCE_UPDATE, default=False): cv.boolean,
        # Not a nicety here: there is no last will, so nothing announces a
        # dead publisher. This is the only liveness mechanism the protocol
        # can offer.
        vol.Optional(CONF_EXPIRE_AFTER): cv.positive_int,
    }
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    configs = hass.data[DATA_MPUBSUB].config.get("sensor", [])
    entities = []
    for item in configs:
        config = PLATFORM_SCHEMA(item)
        warn_if_no_unique_id(config, "sensor")
        entities.append(MpubsubSensor(config))
    async_add_entities(entities)


class MpubsubSensor(MpubsubEntity, SensorEntity):
    """A sensor fed by one mpubsub topic."""

    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._attr_native_unit_of_measurement = config.get(CONF_UNIT_OF_MEASUREMENT)
        self._attr_device_class = config.get(CONF_DEVICE_CLASS)
        self._attr_state_class = config.get(CONF_STATE_CLASS)
        self._attr_force_update = config[CONF_FORCE_UPDATE]
        if (precision := config.get(CONF_SUGGESTED_DISPLAY_PRECISION)) is not None:
            self._attr_suggested_display_precision = precision
        # Nothing replays a value at startup; see MpubsubEntity.
        self._attr_native_value = None
        self._expire_cancel = None

    async def _subscribe_topics(self) -> None:
        @callback
        def _message(msg: ReceiveMessage) -> None:
            value = self._render(msg.payload)
            if value is None or value == "":
                return
            self._attr_native_value = value
            self._reset_expiry()
            self.async_write_ha_state()

        await self._track(self._config[CONF_STATE_TOPIC], _message)

    @callback
    def _reset_expiry(self) -> None:
        if (after := self._config.get(CONF_EXPIRE_AFTER)) is None:
            return
        if self._expire_cancel is not None:
            self._expire_cancel()

        @callback
        def _expired(_now) -> None:
            self._expire_cancel = None
            self._attr_native_value = None
            self.async_write_ha_state()

        self._expire_cancel = async_call_later(self.hass, after, _expired)

    async def async_will_remove_from_hass(self) -> None:
        if self._expire_cancel is not None:
            self._expire_cancel()
            self._expire_cancel = None
        await super().async_will_remove_from_hass()
