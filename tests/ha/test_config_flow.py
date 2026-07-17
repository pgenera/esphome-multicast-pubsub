"""Config and options flows.

The validation assertions here are the Go bridge's rules restated. If
bridges/mqtt-go/config.go's validate() ever accepts something these reject
(or vice versa), one of the two is wrong -- a fabric that is legal in the
bridge and illegal in Home Assistant is a bug in whichever moved.
"""

from __future__ import annotations

from unittest.mock import patch

import pytest
import voluptuous as vol
from homeassistant.config_entries import SOURCE_USER
from homeassistant.core import HomeAssistant
from homeassistant.data_entry_flow import FlowResultType
from pytest_homeassistant_custom_component.common import MockConfigEntry

from custom_components.mpubsub.const import DOMAIN
from helpers import free_port


async def test_user_flow_creates_entry(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["step_id"] == "user"

    port = free_port()
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "port": port,
            "scope": "link-local",
            "interface": "",
            "encryption_key": "s3cret",
        },
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert result["data"] == {
        "port": port,
        "scope": "link-local",
        "interface": "",
        "encryption_key": "s3cret",
    }


async def test_user_flow_defaults(hass: HomeAssistant) -> None:
    """The default port and scope must match the ESPHome component's, or the
    out-of-the-box experience is silence."""
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    schema = result["data_schema"].schema
    defaults = {str(key): key.default() for key in schema if key.default is not vol.UNDEFINED}
    assert defaults["port"] == 18512
    assert defaults["scope"] == "link-local"


async def test_unknown_interface_is_rejected(hass: HomeAssistant) -> None:
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    result = await hass.config_entries.flow.async_configure(
        result["flow_id"],
        {
            "port": free_port(),
            "scope": "link-local",
            "interface": "definitely-not-an-interface",
            "encryption_key": "",
        },
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"interface": "unknown_interface"}


async def test_bind_failure_is_reported(hass: HomeAssistant) -> None:
    """A port we cannot bind must fail on the form, not become a broken entry."""
    with patch(
        "custom_components.mpubsub.config_flow._probe_socket",
        side_effect=OSError(98, "Address already in use"),
    ):
        result = await hass.config_entries.flow.async_init(
            DOMAIN, context={"source": SOURCE_USER}
        )
        result = await hass.config_entries.flow.async_configure(
            result["flow_id"],
            {
                "port": 18512,
                "scope": "link-local",
                "interface": "",
                "encryption_key": "",
            },
        )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"base": "cannot_connect"}


async def test_single_instance(hass: HomeAssistant) -> None:
    """One fabric per Home Assistant. ESPHome allows several on different
    ports; a second here would need a per-entity 'which fabric' key that mqtt
    has no analogue for."""
    MockConfigEntry(domain=DOMAIN, data={"port": 18512}, unique_id=DOMAIN).add_to_hass(
        hass
    )
    result = await hass.config_entries.flow.async_init(
        DOMAIN, context={"source": SOURCE_USER}
    )
    assert result["type"] is FlowResultType.ABORT
    assert result["reason"] == "single_instance_allowed"


# --- options -----------------------------------------------------------------


async def _options_flow(hass: HomeAssistant, entry: MockConfigEntry, user_input: dict):
    result = await hass.config_entries.options.async_init(entry.entry_id)
    return await hass.config_entries.options.async_configure(
        result["flow_id"], user_input
    )


BASE_OPTIONS = {
    "hops": 1,
    "retransmit_count": 1,
    "retransmit_delay": 0.1,
    "promote_qos": False,
    "replay_window": 0,
}


async def test_options_flow_saves(hass: HomeAssistant, setup_mpubsub) -> None:
    entry = await setup_mpubsub()
    result = await _options_flow(
        hass, entry, {**BASE_OPTIONS, "hops": 5, "promote_qos": True}
    )
    await hass.async_block_till_done()

    assert result["type"] is FlowResultType.CREATE_ENTRY
    assert entry.options["hops"] == 5
    assert entry.options["promote_qos"] is True


async def test_replay_window_without_key_rejected(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """Replay protection only ever applies to encrypted packets, so a window
    without a key is a setting that cannot do what it claims.
    Mirrors bridges/mqtt-go/config.go."""
    entry = await setup_mpubsub(data={"encryption_key": ""})
    result = await _options_flow(hass, entry, {**BASE_OPTIONS, "replay_window": 30})

    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"replay_window": "replay_window_needs_key"}


async def test_replay_window_with_key_accepted(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    entry = await setup_mpubsub(data={"encryption_key": "s3cret"})
    result = await _options_flow(hass, entry, {**BASE_OPTIONS, "replay_window": 30})
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_replay_window_zero_without_key_accepted(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """0 disables protection, so it needs neither a key nor a clock -- the
    same fix that landed in the ESPHome component and the Go bridge."""
    entry = await setup_mpubsub(data={"encryption_key": ""})
    result = await _options_flow(hass, entry, {**BASE_OPTIONS, "replay_window": 0})
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_indefinite_retransmit_needs_delay(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """-1 with a 100ms delay would saturate the segment.
    Mirrors components/mpubsub/__init__.py:311-319."""
    entry = await setup_mpubsub()
    result = await _options_flow(
        hass, entry, {**BASE_OPTIONS, "retransmit_count": -1, "retransmit_delay": 0.1}
    )
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"retransmit_delay": "indefinite_needs_delay"}


async def test_indefinite_retransmit_with_1s_delay_accepted(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    entry = await setup_mpubsub()
    result = await _options_flow(
        hass, entry, {**BASE_OPTIONS, "retransmit_count": -1, "retransmit_delay": 1.0}
    )
    assert result["type"] is FlowResultType.CREATE_ENTRY


async def test_retransmit_count_zero_rejected(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """0 is meaningless: every publish sends at least one datagram."""
    entry = await setup_mpubsub()
    result = await _options_flow(hass, entry, {**BASE_OPTIONS, "retransmit_count": 0})
    assert result["type"] is FlowResultType.FORM
    assert result["errors"] == {"retransmit_count": "invalid_retransmit_count"}


async def test_options_change_reloads_the_client(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """hops/promote_qos/replay_window all bake into the client at start, so
    an options change has to rebuild it or the UI lies."""
    from custom_components.mpubsub.const import DATA_MPUBSUB

    entry = await setup_mpubsub()
    assert hass.data[DATA_MPUBSUB].client.config.hops == 1

    await _options_flow(hass, entry, {**BASE_OPTIONS, "hops": 7})
    await hass.async_block_till_done()

    assert hass.data[DATA_MPUBSUB].client.config.hops == 7


# --- strings ------------------------------------------------------------------


def _error_keys_in(node) -> set[str]:
    """String literals assigned into an ``errors`` dict inside this node."""
    import ast

    keys: set[str] = set()
    for sub in ast.walk(node):
        if not isinstance(sub, ast.Assign):
            continue
        for target in sub.targets:
            if (
                isinstance(target, ast.Subscript)
                and isinstance(target.value, ast.Name)
                and target.value.id == "errors"
                and isinstance(sub.value, ast.Constant)
                and isinstance(sub.value.value, str)
            ):
                keys.add(sub.value.value)
    return keys


def _component_dir():
    from pathlib import Path

    return Path(__file__).resolve().parents[2] / "custom_components" / "mpubsub"


def test_every_error_key_has_a_string_in_the_right_section() -> None:
    """An error key with no string renders as the raw key in the UI.

    Home Assistant looks up a config-flow error under config.error and an
    options-flow error under options.error, so a key in the wrong section is
    just as broken as a missing one -- and looks perfectly fine in the
    source. Checking only that the key exists *somewhere* would not catch it
    (it didn't), so the keys are attributed to their flow here: whatever
    _validate_options raises must be an options string, and whatever the
    config flow class raises must be a config string.
    """
    import ast
    import json

    component = _component_dir()
    strings = json.loads((component / "strings.json").read_text())
    tree = ast.parse((component / "config_flow.py").read_text())

    config_used: set[str] = set()
    options_used: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ClassDef) and node.name == "MpubsubConfigFlow":
            config_used |= _error_keys_in(node)
        elif isinstance(node, ast.FunctionDef) and node.name == "_validate_options":
            options_used |= _error_keys_in(node)

    assert config_used, "found no config-flow error keys; did the parse break?"
    assert options_used, "found no options-flow error keys; did the parse break?"

    config_have = set(strings["config"]["error"])
    options_have = set(strings["options"]["error"])

    assert config_used <= config_have, (
        f"config flow raises {sorted(config_used - config_have)} with no entry "
        f"under strings.json config.error"
    )
    assert options_used <= options_have, (
        f"options flow raises {sorted(options_used - options_have)} with no "
        f"entry under strings.json options.error (a key filed under "
        f"config.error does not count -- HA looks it up per flow)"
    )


def test_abort_reasons_have_strings() -> None:
    import ast
    import json

    component = _component_dir()
    strings = json.loads((component / "strings.json").read_text())
    tree = ast.parse((component / "config_flow.py").read_text())

    reasons = {
        kw.value.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and getattr(node.func, "attr", None) == "async_abort"
        for kw in node.keywords
        if kw.arg == "reason" and isinstance(kw.value, ast.Constant)
    }
    assert reasons <= set(strings["config"]["abort"]), (
        f"abort reason(s) {sorted(reasons - set(strings['config']['abort']))} "
        f"have no string"
    )


def test_translations_match_strings() -> None:
    import json
    from pathlib import Path

    component = Path(__file__).resolve().parents[2] / "custom_components" / "mpubsub"
    assert json.loads((component / "strings.json").read_text()) == json.loads(
        (component / "translations" / "en.json").read_text()
    ), "translations/en.json is a copy of strings.json; re-copy it"
