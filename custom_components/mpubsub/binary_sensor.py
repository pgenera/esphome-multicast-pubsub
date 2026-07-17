"""mpubsub binary_sensor platform."""

from __future__ import annotations

from typing import Any

import voluptuous as vol
from homeassistant.components.binary_sensor import (
    DEVICE_CLASSES_SCHEMA,
    BinarySensorEntity,
)
from homeassistant.config_entries import ConfigEntry
from homeassistant.const import (
    CONF_DEVICE_CLASS,
    CONF_FORCE_UPDATE,
    CONF_PAYLOAD_OFF,
    CONF_PAYLOAD_ON,
)
from homeassistant.core import HomeAssistant, callback
from homeassistant.helpers import config_validation as cv
from homeassistant.helpers.entity_platform import AddEntitiesCallback
from homeassistant.helpers.event import async_call_later

from .const import (
    CONF_EXPIRE_AFTER,
    CONF_OFF_DELAY,
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
        vol.Required(CONF_STATE_TOPIC): valid_topic,
        vol.Optional(CONF_PAYLOAD_ON, default=DEFAULT_PAYLOAD_ON): cv.string,
        vol.Optional(CONF_PAYLOAD_OFF, default=DEFAULT_PAYLOAD_OFF): cv.string,
        vol.Optional(CONF_DEVICE_CLASS): vol.Any(DEVICE_CLASSES_SCHEMA, None),
        vol.Optional(CONF_FORCE_UPDATE, default=False): cv.boolean,
        vol.Optional(CONF_OFF_DELAY): cv.positive_int,
        vol.Optional(CONF_EXPIRE_AFTER): cv.positive_int,
    }
)


async def async_setup_entry(
    hass: HomeAssistant,
    entry: ConfigEntry,
    async_add_entities: AddEntitiesCallback,
) -> None:
    configs = hass.data[DATA_MPUBSUB].config.get("binary_sensor", [])
    entities = []
    for item in configs:
        config = PLATFORM_SCHEMA(item)
        warn_if_no_unique_id(config, "binary_sensor")
        entities.append(MpubsubBinarySensor(config))
    async_add_entities(entities)


class MpubsubBinarySensor(MpubsubEntity, BinarySensorEntity):
    def __init__(self, config: dict[str, Any]) -> None:
        super().__init__(config)
        self._attr_device_class = config.get(CONF_DEVICE_CLASS)
        self._attr_force_update = config[CONF_FORCE_UPDATE]
        self._attr_is_on = None  # unknown until a packet arrives
        self._expire_cancel = None
        self._off_delay_cancel = None

    async def _subscribe_topics(self) -> None:
        @callback
        def _message(msg: ReceiveMessage) -> None:
            payload = self._render(msg.payload)
            if payload == self._config[CONF_PAYLOAD_ON]:
                self._attr_is_on = True
            elif payload == self._config[CONF_PAYLOAD_OFF]:
                self._attr_is_on = False
            else:
                return  # not ours to interpret
            self._reset_expiry()
            self._arm_off_delay()
            self.async_write_ha_state()

        await self._track(self._config[CONF_STATE_TOPIC], _message)

    @callback
    def _arm_off_delay(self) -> None:
        """Auto-off for devices that only ever announce the ON edge."""
        if (delay := self._config.get(CONF_OFF_DELAY)) is None:
            return
        if self._off_delay_cancel is not None:
            self._off_delay_cancel()
            self._off_delay_cancel = None
        if not self._attr_is_on:
            return

        @callback
        def _off(_now) -> None:
            self._off_delay_cancel = None
            self._attr_is_on = False
            self.async_write_ha_state()

        self._off_delay_cancel = async_call_later(self.hass, delay, _off)

    @callback
    def _reset_expiry(self) -> None:
        if (after := self._config.get(CONF_EXPIRE_AFTER)) is None:
            return
        if self._expire_cancel is not None:
            self._expire_cancel()

        @callback
        def _expired(_now) -> None:
            self._expire_cancel = None
            self._attr_is_on = None
            self.async_write_ha_state()

        self._expire_cancel = async_call_later(self.hass, after, _expired)

    async def async_will_remove_from_hass(self) -> None:
        for cancel in (self._expire_cancel, self._off_delay_cancel):
            if cancel is not None:
                cancel()
        self._expire_cancel = self._off_delay_cancel = None
        await super().async_will_remove_from_hass()
