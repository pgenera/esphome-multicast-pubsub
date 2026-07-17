"""Config and options flows.

Validation here reproduces the Go bridge's ``validate()`` errors
(``bridges/mqtt-go/config.go``) and the ESPHome component's final-validation
rules, so a fabric that is legal in one place is legal in all of them.
"""

from __future__ import annotations

import logging
import socket
from typing import Any

import voluptuous as vol
from homeassistant.config_entries import (
    ConfigFlow,
    ConfigFlowResult,
    OptionsFlow,
)
from homeassistant.const import CONF_PORT
from homeassistant.core import callback
from homeassistant.helpers.selector import (
    BooleanSelector,
    NumberSelector,
    NumberSelectorConfig,
    NumberSelectorMode,
    SelectSelector,
    SelectSelectorConfig,
    SelectSelectorMode,
    TextSelector,
    TextSelectorConfig,
    TextSelectorType,
)

from .const import (
    CONF_ENCRYPTION_KEY,
    CONF_HOPS,
    CONF_INTERFACE,
    CONF_PROMOTE_QOS,
    CONF_REPLAY_WINDOW,
    CONF_RETRANSMIT_COUNT,
    CONF_RETRANSMIT_DELAY,
    CONF_SCOPE,
    DEFAULT_HOPS,
    DEFAULT_PORT,
    DEFAULT_PROMOTE_QOS,
    DEFAULT_REPLAY_WINDOW,
    DEFAULT_RETRANSMIT_COUNT,
    DEFAULT_RETRANSMIT_DELAY,
    DEFAULT_SCOPE,
    DOMAIN,
    MIN_INDEFINITE_DELAY,
    RETRANSMIT_INDEFINITE,
    SCOPES,
)

_LOGGER = logging.getLogger(__name__)

USER_SCHEMA = vol.Schema(
    {
        vol.Optional(CONF_PORT, default=DEFAULT_PORT): NumberSelector(
            NumberSelectorConfig(min=1, max=65535, mode=NumberSelectorMode.BOX)
        ),
        vol.Optional(CONF_SCOPE, default=DEFAULT_SCOPE): SelectSelector(
            SelectSelectorConfig(
                options=list(SCOPES), mode=SelectSelectorMode.DROPDOWN
            )
        ),
        vol.Optional(CONF_INTERFACE, default=""): TextSelector(),
        vol.Optional(CONF_ENCRYPTION_KEY, default=""): TextSelector(
            TextSelectorConfig(type=TextSelectorType.PASSWORD)
        ),
    }
)


def _options_schema(current: dict[str, Any]) -> vol.Schema:
    return vol.Schema(
        {
            vol.Optional(
                CONF_HOPS, default=current.get(CONF_HOPS, DEFAULT_HOPS)
            ): NumberSelector(
                NumberSelectorConfig(min=1, max=255, mode=NumberSelectorMode.BOX)
            ),
            vol.Optional(
                CONF_RETRANSMIT_COUNT,
                default=current.get(CONF_RETRANSMIT_COUNT, DEFAULT_RETRANSMIT_COUNT),
            ): NumberSelector(
                # -1 means indefinite; 0 is meaningless and rejected below,
                # matching _retransmit_count_validator in the ESPHome schema.
                NumberSelectorConfig(min=-1, max=255, mode=NumberSelectorMode.BOX)
            ),
            vol.Optional(
                CONF_RETRANSMIT_DELAY,
                default=current.get(CONF_RETRANSMIT_DELAY, DEFAULT_RETRANSMIT_DELAY),
            ): NumberSelector(
                NumberSelectorConfig(
                    min=0, max=3600, step=0.01, mode=NumberSelectorMode.BOX
                )
            ),
            vol.Optional(
                CONF_PROMOTE_QOS,
                default=current.get(CONF_PROMOTE_QOS, DEFAULT_PROMOTE_QOS),
            ): BooleanSelector(),
            vol.Optional(
                CONF_REPLAY_WINDOW,
                default=current.get(CONF_REPLAY_WINDOW, DEFAULT_REPLAY_WINDOW),
            ): NumberSelector(
                NumberSelectorConfig(min=0, max=86400, mode=NumberSelectorMode.BOX)
            ),
        }
    )


def _probe_socket(port: int, interface: str) -> None:
    """Open and close the socket the client will use.

    Raises OSError. Doing this in the flow turns "the entry is set up but
    silently broken" into an error on the form, where it can be fixed.
    """
    if interface:
        socket.if_nametoindex(interface)  # OSError if unknown
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_REUSEPORT"):
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
            except OSError:
                pass
        sock.bind(("::", port))
    finally:
        sock.close()


def _validate_options(options: dict[str, Any], has_key: bool) -> dict[str, str]:
    """Return {field: error_key} for anything the Go bridge would reject."""
    errors: dict[str, str] = {}

    count = int(options.get(CONF_RETRANSMIT_COUNT, DEFAULT_RETRANSMIT_COUNT))
    delay = float(options.get(CONF_RETRANSMIT_DELAY, DEFAULT_RETRANSMIT_DELAY))
    window = float(options.get(CONF_REPLAY_WINDOW, DEFAULT_REPLAY_WINDOW))

    if count == 0:
        errors[CONF_RETRANSMIT_COUNT] = "invalid_retransmit_count"
    elif count == RETRANSMIT_INDEFINITE and delay < MIN_INDEFINITE_DELAY:
        # bridges/mqtt-go/config.go, and components/mpubsub/__init__.py:311.
        errors[CONF_RETRANSMIT_DELAY] = "indefinite_needs_delay"

    if window > 0 and not has_key:
        # Replay protection only ever applies to encrypted packets, so a
        # window without a key is a config that cannot do what it says.
        errors[CONF_REPLAY_WINDOW] = "replay_window_needs_key"

    return errors


class MpubsubConfigFlow(ConfigFlow, domain=DOMAIN):
    """Set up one mpubsub fabric."""

    VERSION = 1

    async def async_step_user(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        # One entry only. The ESPHome side supports several fabrics on
        # different ports, but a second here would need a per-entity "which
        # fabric" key that mqtt has no analogue for.
        if self._async_current_entries():
            return self.async_abort(reason="single_instance_allowed")

        errors: dict[str, str] = {}
        placeholders: dict[str, str] = {}
        if user_input is not None:
            port = int(user_input[CONF_PORT])
            interface = (user_input.get(CONF_INTERFACE) or "").strip()
            try:
                await self.hass.async_add_executor_job(_probe_socket, port, interface)
            except OSError as err:
                if interface and err.errno in (None, 19):  # ENODEV
                    errors[CONF_INTERFACE] = "unknown_interface"
                else:
                    # "port in use" and "IPv6 unavailable" need different
                    # fixes, so the reason has to reach the user. Log it too:
                    # a form error is easy to miss and impossible to paste.
                    _LOGGER.error(
                        "mpubsub cannot open port %s (interface=%s): %s",
                        port,
                        interface or "<kernel-picked>",
                        err,
                    )
                    errors["base"] = "cannot_connect"
                    placeholders["error"] = str(err)
            if not errors:
                return self.async_create_entry(
                    title="mpubsub",
                    data={
                        CONF_PORT: port,
                        CONF_SCOPE: user_input[CONF_SCOPE],
                        CONF_INTERFACE: interface,
                        CONF_ENCRYPTION_KEY: user_input.get(CONF_ENCRYPTION_KEY, ""),
                    },
                )

        return self.async_show_form(
            step_id="user",
            data_schema=USER_SCHEMA,
            errors=errors,
            description_placeholders=placeholders,
        )

    @staticmethod
    @callback
    def async_get_options_flow(config_entry) -> MpubsubOptionsFlow:
        return MpubsubOptionsFlow()


class MpubsubOptionsFlow(OptionsFlow):
    """Tuning that can change without re-identifying the fabric."""

    async def async_step_init(
        self, user_input: dict[str, Any] | None = None
    ) -> ConfigFlowResult:
        errors: dict[str, str] = {}
        if user_input is not None:
            has_key = bool(self.config_entry.data.get(CONF_ENCRYPTION_KEY))
            errors = _validate_options(user_input, has_key)
            if not errors:
                return self.async_create_entry(
                    data={
                        CONF_HOPS: int(user_input[CONF_HOPS]),
                        CONF_RETRANSMIT_COUNT: int(user_input[CONF_RETRANSMIT_COUNT]),
                        CONF_RETRANSMIT_DELAY: float(
                            user_input[CONF_RETRANSMIT_DELAY]
                        ),
                        CONF_PROMOTE_QOS: bool(user_input[CONF_PROMOTE_QOS]),
                        CONF_REPLAY_WINDOW: int(user_input[CONF_REPLAY_WINDOW]),
                    }
                )

        return self.async_show_form(
            step_id="init",
            data_schema=_options_schema(dict(self.config_entry.options)),
            errors=errors,
        )
