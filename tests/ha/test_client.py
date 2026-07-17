"""Real-socket tests for the mpubsub transport.

These drive MpubsubClient over actual IPv6 multicast on ``lo``, with a bare
socket on the other end speaking the wire format via the reference. Nothing
here is mocked at the socket layer: the plumbing (which group, which
interface, when to resend, what to drop) is precisely the part vendoring
reference.py cannot make correct for us, so it has to be exercised for real.

Ports are randomised per test so a stray process from an earlier run cannot
make this suite lie -- an orphan holding :18512 has burned this repo before.
"""

from __future__ import annotations

import asyncio
import socket

import pytest
from homeassistant.core import HomeAssistant

from custom_components.mpubsub.client import MpubsubClient
from custom_components.mpubsub.reference import (
    ENCODING_PROTOBUF,
    decode,
    derive_key,
    encode,
)
from custom_components.mpubsub.util import TopicError
from helpers import (
    Sniffer,
    free_port,
    make_config,
    requires_multicast,
    send_raw,
    send_wire,
    wait_for,
)

pytestmark = requires_multicast

TOPIC = "test/temp"


@pytest.fixture
async def client(hass: HomeAssistant):
    """A started client on its own port, stopped on teardown."""
    started: list[MpubsubClient] = []

    async def _make(**overrides) -> MpubsubClient:
        cli = MpubsubClient(hass, make_config(free_port(), **overrides))
        await cli.async_start()
        started.append(cli)
        return cli

    yield _make
    for cli in started:
        await cli.async_stop()


# --- receive -----------------------------------------------------------------


async def test_subscribe_receives_plaintext(hass: HomeAssistant, client) -> None:
    cli = await client()
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw(TOPIC, b"42.5", cli.config.port)
    await wait_for(got)

    assert len(got) == 1
    msg = got[0]
    assert msg.payload == "42.5"  # utf-8 decoded by default, as mqtt does
    assert msg.topic == TOPIC
    assert msg.subscribed_topic == TOPIC
    assert msg.qos == 0
    assert msg.retain is False
    assert msg.was_encrypted is False
    assert msg.sender_timestamp is None  # plaintext carries no timestamp


async def test_subscribe_encoding_none_yields_bytes(
    hass: HomeAssistant, client
) -> None:
    cli = await client()
    got: list = []
    await cli.async_subscribe(TOPIC, got.append, encoding=None)

    send_raw(TOPIC, b"\xff\xfe binary", cli.config.port)
    await wait_for(got)

    assert got[0].payload == b"\xff\xfe binary"


async def test_encrypted_roundtrip(hass: HomeAssistant, client) -> None:
    key = derive_key("shared-test-secret")
    cli = await client(key=key)
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw(TOPIC, b"42.5", cli.config.port, key=key)
    await wait_for(got)

    assert got[0].payload == "42.5"
    assert got[0].was_encrypted is True
    assert got[0].sender_timestamp is not None


async def test_wrong_key_is_dropped(hass: HomeAssistant, client) -> None:
    cli = await client(key=derive_key("right"))
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw(TOPIC, b"42.5", cli.config.port, key=derive_key("wrong"))
    await asyncio.sleep(0.3)

    assert got == [], "a packet we can't authenticate must not be delivered"


async def test_other_topic_not_delivered(hass: HomeAssistant, client) -> None:
    """A packet for a topic we didn't subscribe to is ignored.

    It can reach our socket: we're bound to the wildcard address, so anything
    on the port for a group we joined arrives here.
    """
    cli = await client()
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw("test/other", b"nope", cli.config.port)
    await asyncio.sleep(0.3)

    assert got == []


async def test_protobuf_encoding_dropped(hass: HomeAssistant, client) -> None:
    """v1 is RAW-only; a typed packet is dropped rather than mis-delivered."""
    cli = await client()
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw(TOPIC, b"\x01\x00body", cli.config.port, encoding=ENCODING_PROTOBUF)
    await asyncio.sleep(0.3)

    assert got == []


# --- subscription bookkeeping ------------------------------------------------


async def test_two_subscribers_both_fire(hass: HomeAssistant, client) -> None:
    cli = await client()
    a: list = []
    b: list = []
    await cli.async_subscribe(TOPIC, a.append)
    await cli.async_subscribe(TOPIC, b.append)

    send_raw(TOPIC, b"x", cli.config.port)
    await wait_for(a)
    await wait_for(b)

    assert len(a) == 1 and len(b) == 1


async def test_unsubscribe_refcounting(hass: HomeAssistant, client) -> None:
    """The group is held until the *last* subscriber goes away.

    len(callbacks) is the refcount, so this is really a test that one
    caller unsubscribing can't silently deafen another.
    """
    cli = await client()
    a: list = []
    b: list = []
    unsub_a = await cli.async_subscribe(TOPIC, a.append)
    await cli.async_subscribe(TOPIC, b.append)

    unsub_a()
    assert TOPIC in cli._subs, "still one subscriber left; must stay joined"

    send_raw(TOPIC, b"x", cli.config.port)
    await wait_for(b)
    assert a == [], "unsubscribed callback must not fire"
    assert len(b) == 1


async def test_last_unsubscribe_leaves_group(hass: HomeAssistant, client) -> None:
    cli = await client()
    got: list = []
    unsub = await cli.async_subscribe(TOPIC, got.append)
    assert TOPIC in cli._subs

    unsub()
    await hass.async_block_till_done()

    assert TOPIC not in cli._subs
    assert cli._crc_index == {}


async def test_double_unsubscribe_is_harmless(hass: HomeAssistant, client) -> None:
    cli = await client()
    unsub = await cli.async_subscribe(TOPIC, lambda _msg: None)
    unsub()
    unsub()  # must not raise


async def test_subscribe_rejects_wildcards(hass: HomeAssistant, client) -> None:
    cli = await client()
    for topic in ("home/+/temp", "home/#"):
        with pytest.raises(TopicError, match="wildcard"):
            await cli.async_subscribe(topic, lambda _msg: None)


# --- publish -----------------------------------------------------------------


async def test_publish_is_on_the_wire(hass: HomeAssistant, client) -> None:
    cli = await client()
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"21.5")
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1
    msg = decode(packets[0])
    assert msg.payload == b"21.5"


async def test_publish_encrypted_is_unreadable_without_the_key(
    hass: HomeAssistant, client
) -> None:
    key = derive_key("s3cret")
    cli = await client(key=key)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"21.5")
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1
    assert b"21.5" not in packets[0]
    assert decode(packets[0], key=key).payload == b"21.5"


async def test_publish_rejects_wildcards(hass: HomeAssistant, client) -> None:
    cli = await client()
    with pytest.raises(TopicError, match="wildcard"):
        cli.async_publish("home/+/temp", b"x")


async def test_publish_rejects_oversize_payload(hass: HomeAssistant, client) -> None:
    cli = await client()
    with pytest.raises(ValueError, match="payload too large"):
        cli.async_publish(TOPIC, b"x" * 1221)


async def test_retain_is_ignored_not_fatal(
    hass: HomeAssistant, client, caplog
) -> None:
    """retain has no wire field. Publishing must still happen, and the caller
    must be told why nothing will remember it."""
    cli = await client()
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"x", retain=True)
        packets = await sniffer.collect()
    finally:
        sniffer.close()

    assert len(packets) == 1, "retain=True must not suppress the publish"
    assert "retain=True ignored" in caplog.text


# --- retransmits -------------------------------------------------------------


async def test_finite_retransmits_reuse_the_same_bytes(
    hass: HomeAssistant, client
) -> None:
    """Retransmits must be byte-identical to the first send.

    Identical bytes mean an identical AEAD nonce, which is the only reason a
    replay-checking receiver can collapse them to one delivery. Re-encoding
    per retransmit would mint a fresh nonce and deliver three times -- the
    single most breakable invariant in the publish path.
    """
    cli = await client(key=derive_key("k"), retransmit_count=3, retransmit_delay=0.02)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"once")
        packets = await sniffer.collect(0.4)
    finally:
        sniffer.close()

    assert len(packets) == 3
    assert packets[0] == packets[1] == packets[2], "retransmits must be identical"


async def test_indefinite_retransmit_is_superseded_by_next_publish(
    hass: HomeAssistant, client
) -> None:
    """A publish stops the previous indefinite chain for the same topic.

    The sniffer is drained before the second publish: it joined the group up
    front, so its socket buffer holds every "first" already sent, and
    collecting only at the end would see those regardless of whether the
    chain was cancelled -- the test would pass either way.
    """
    cli = await client(retransmit_count=-1, retransmit_delay=0.02)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"first")
        await asyncio.sleep(0.1)
        assert await sniffer.collect(0.05), "the first chain should be running"

        cli.async_publish(TOPIC, b"second")
        await asyncio.sleep(0.1)
        packets = await sniffer.collect(0.2)
    finally:
        sniffer.close()

    payloads = {decode(p).payload for p in packets}
    assert payloads == {b"second"}, (
        f"the superseded chain must stop; still seeing {payloads}"
    )


async def test_stop_cancels_pending_retransmits(
    hass: HomeAssistant, client, caplog
) -> None:
    """async_stop cancels chains *before* closing the transport.

    Asserting silence alone would be a weak test: a retransmit that fired
    into an already-closed transport would also send nothing, just noisily.
    So this checks both -- no packets, and nothing raised on the way down.
    """
    cli = await client(retransmit_count=-1, retransmit_delay=0.02)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"x")
        await asyncio.sleep(0.05)
        assert await sniffer.collect(0.05), "the chain should be running"

        await cli.async_stop()
        # A tick landing in the socket buffer between that drain and the stop
        # is a race, not a bug, so discard one tick interval's worth. The
        # property under test is that the chain stops *permanently*: at a
        # 0.02s delay, a live chain would put ~15 packets in the next window.
        await sniffer.collect(0.05)
        packets = await sniffer.collect(0.3)
    finally:
        sniffer.close()

    assert packets == [], "async_stop must cancel in-flight retransmit chains"
    assert cli._indefinite == {}
    # The teeth of this test: if async_stop closed the transport *before*
    # cancelling, the next tick would raise into the event loop instead of
    # sending. That is also silent on the wire, so silence alone proves
    # nothing -- the log has to be clean too.
    assert "Traceback" not in caplog.text


# --- replay ------------------------------------------------------------------


async def test_replay_window_dedups_identical_datagrams(
    hass: HomeAssistant, client
) -> None:
    key = derive_key("k")
    cli = await client(key=key, replay_window=30)
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    # One encoding sent twice == what a retransmit looks like on the wire.
    wire = encode(TOPIC, b"42.5", key=key)
    for _ in range(2):
        send_wire(TOPIC, wire, cli.config.port)

    await wait_for(got)
    await asyncio.sleep(0.3)
    assert len(got) == 1, "the nonce cache must collapse a duplicate datagram"


async def test_replay_window_zero_delivers_duplicates(
    hass: HomeAssistant, client
) -> None:
    """window=0 disables protection, matching ESPHome and the Go bridge."""
    key = derive_key("k")
    cli = await client(key=key, replay_window=0)
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    wire = encode(TOPIC, b"42.5", key=key)
    for _ in range(2):
        send_wire(TOPIC, wire, cli.config.port)

    await wait_for(got, count=2)
    assert len(got) == 2


async def test_stale_timestamp_is_dropped(hass: HomeAssistant, client) -> None:
    key = derive_key("k")
    cli = await client(key=key, replay_window=30)
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    send_raw(TOPIC, b"old", cli.config.port, key=key, timestamp=1_700_000_000)
    await asyncio.sleep(0.3)

    assert got == [], "a packet outside the freshness window must be dropped"


async def test_plaintext_duplicates_are_both_delivered(
    hass: HomeAssistant, client
) -> None:
    """The honest divergence: plaintext has no dedup, at any setting.

    replay_window only ever applies to encrypted packets, so an unencrypted
    retransmit_count=3 publish fires a subscriber's callback three times.
    Asserted rather than glossed -- it is the reason docs recommend
    encryption + replay_window for anything command-shaped.
    """
    cli = await client(replay_window=30)  # no key
    got: list = []
    await cli.async_subscribe(TOPIC, got.append)

    wire = encode(TOPIC, b"42.5")  # plaintext, byte-identical twice
    for _ in range(2):
        send_wire(TOPIC, wire, cli.config.port)

    await wait_for(got, count=2)
    assert len(got) == 2


# --- qos -> retransmit mapping -----------------------------------------------


@pytest.mark.parametrize(
    ("promote", "base", "qos", "expected"),
    [
        # Hard-coded from effectiveRetransmitCount in
        # bridges/mqtt-go/bridge.go:267-286. If that changes, this must too.
        (False, 1, 2, 1),  # promote off: qos is inert
        (False, 5, 1, 5),
        (True, 1, 0, 1),  # qos 0: unchanged
        (True, 1, 1, 3),  # qos 1: at least 3
        (True, 5, 1, 5),  # ...but never bumped *down*
        (True, -1, 1, -1),  # already indefinite stays indefinite
        (True, 1, 2, -1),  # qos 2: indefinite
        (True, -1, 0, -1),
    ],
)
async def test_effective_retransmit_count(
    hass: HomeAssistant, promote: bool, base: int, qos: int, expected: int
) -> None:
    cli = MpubsubClient(
        hass, make_config(18512, promote_qos=promote, retransmit_count=base)
    )
    assert cli._effective_retransmit_count(qos) == expected


async def test_qos1_with_promote_emits_three(hass: HomeAssistant, client) -> None:
    cli = await client(promote_qos=True, retransmit_count=1, retransmit_delay=0.02)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"x", qos=1)
        packets = await sniffer.collect(0.4)
    finally:
        sniffer.close()

    assert len(packets) == 3


async def test_qos0_with_promote_emits_one(hass: HomeAssistant, client) -> None:
    cli = await client(promote_qos=True, retransmit_count=1, retransmit_delay=0.02)
    sniffer = Sniffer(TOPIC, cli.config.port)
    try:
        cli.async_publish(TOPIC, b"x", qos=0)
        packets = await sniffer.collect(0.4)
    finally:
        sniffer.close()

    assert len(packets) == 1
