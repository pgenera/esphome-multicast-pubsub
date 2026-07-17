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
