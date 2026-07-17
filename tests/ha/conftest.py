"""Fixtures for the Home Assistant component tests (layer 3).

Run from the repo root so ``custom_components.mpubsub`` imports:

    .venv/bin/python -m pytest tests/ha

pytest_homeassistant_custom_component registers itself via an entry point, so
it must NOT be named in ``pytest_plugins`` here -- that registers it a second
time and aborts collection.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
if str(REPO) not in sys.path:
    sys.path.insert(0, str(REPO))


@pytest.fixture(autouse=True)
def auto_enable_custom_integrations(enable_custom_integrations):
    """Without this, Home Assistant refuses to load custom_components/."""
    return


@pytest.fixture(autouse=True)
def allow_sockets(socket_enabled):
    """pytest-socket blocks real sockets by default; this suite needs genuine
    loopback multicast, which is the entire point of testing the transport."""
    return


@pytest.fixture
async def setup_mpubsub(hass):
    """Set the integration up on a throwaway port. Returns the config entry."""
    from homeassistant.setup import async_setup_component
    from pytest_homeassistant_custom_component.common import MockConfigEntry

    from custom_components.mpubsub.const import DOMAIN

    from helpers import free_port

    async def _setup(
        yaml_config: dict | None = None,
        data: dict | None = None,
        options: dict | None = None,
    ) -> MockConfigEntry:
        entry_data = {"port": free_port(), "scope": "link-local"}
        entry_data.update(data or {})
        entry = MockConfigEntry(
            domain=DOMAIN, data=entry_data, options=options or {}, title="mpubsub"
        )
        entry.add_to_hass(hass)
        # async_setup_component runs async_setup (which stashes the YAML
        # entity config) and then the entry setup, in that order -- which is
        # the order the platforms depend on.
        assert await async_setup_component(
            hass, DOMAIN, {DOMAIN: yaml_config} if yaml_config else {}
        )
        await hass.async_block_till_done()
        return entry

    return _setup
