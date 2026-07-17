"""Shutdown and teardown.

Every test here covers a path the original suite never drove, which is
exactly why bugs lived in them. The suite set the integration up and tore it
down through the config entry; it never fired EVENT_HOMEASSISTANT_STOP, so a
listener that leaked its coroutine and left the socket open passed 108 tests.
"""

from __future__ import annotations

from homeassistant.const import EVENT_HOMEASSISTANT_STOP
from homeassistant.core import HomeAssistant

from custom_components.mpubsub.const import DATA_MPUBSUB
from helpers import requires_multicast

pytestmark = requires_multicast


async def test_socket_closes_when_home_assistant_stops(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """The stop listener must actually run.

    Home Assistant decides whether to await a listener by inspecting the
    callable, so `lambda e: client.async_stop()` hands it a plain function,
    gets a coroutine back, and drops it -- the socket stays open for the life
    of the process and Python emits "coroutine was never awaited".
    """
    await setup_mpubsub()
    client = hass.data[DATA_MPUBSUB].client
    assert client.available

    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()

    assert not client.available, "the socket must be closed when HA stops"


async def test_stop_cancels_retransmits_without_warnings(
    hass: HomeAssistant, setup_mpubsub, caplog
) -> None:
    """A leaked coroutine shows up as a RuntimeWarning, not a failure, so it
    is easy to miss. Fail on it explicitly."""
    await setup_mpubsub(options={"retransmit_count": -1, "retransmit_delay": 1.0})
    client = hass.data[DATA_MPUBSUB].client
    client.async_publish("test/temp", b"x", 0, False)

    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()

    assert not client.available
    assert client._indefinite == {}
    assert "never awaited" not in caplog.text
    assert "Traceback" not in caplog.text


async def test_unload_after_stop_is_not_an_error(
    hass: HomeAssistant, setup_mpubsub
) -> None:
    """HA stopping and the entry unloading both call async_stop. The second
    must be a no-op rather than an exception."""
    entry = await setup_mpubsub()
    hass.bus.async_fire(EVENT_HOMEASSISTANT_STOP)
    await hass.async_block_till_done()

    assert await hass.config_entries.async_unload(entry.entry_id)
    await hass.async_block_till_done()
