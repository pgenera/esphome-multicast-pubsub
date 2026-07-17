"""Loopback tests for the asyncio mpubsub client.

The HA-free sibling of tests/ha/test_client.py: same real-socket approach
(nothing mocked at the socket layer), because the plumbing this exercises --
group join, CRC dispatch, replay dedup, retransmit nonce reuse -- is exactly
what the vendored wire code cannot get right on its own.

Sends go out over the kernel-picked interface (loopback has no link-local
address, hence no multicast route), so running these emits a little real
multicast on the LAN; hops=1 keeps it on the segment. Skips cleanly where
IPv6 multicast is unavailable.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from ipaddress import IPv6Address

import pytest

from mpubsub import wire
from mpubsub.aio import MpubsubClient, TopicError

SCOPE = "link-local"
SCOPE_NIBBLE = wire.SCOPE_LINK_LOCAL
TOPIC = "test/temp"


def _multicast_works() -> bool:
    try:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("::", 0))
        s.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
            IPv6Address("ff12::1234").packed + struct.pack("@I", 0),
        )
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        s.sendto(b"", ("ff12::1234", 9))
    except OSError:
        return False
    finally:
        s.close()
    return True


pytestmark = pytest.mark.skipif(
    not _multicast_works(), reason="IPv6 multicast unavailable here"
)


def _free_port() -> int:
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
        s.bind(("::", 0))
        return s.getsockname()[1]


def _send(topic, payload, port, **kw):
    wire_bytes = wire.encode(topic, payload, **kw)
    s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    try:
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        s.sendto(wire_bytes, (str(wire.topic_to_group(topic, SCOPE_NIBBLE)), port))
    finally:
        s.close()


class _Sniffer:
    def __init__(self, topic, port):
        self.s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.s.bind(("::", port))
        self.s.setsockopt(
            socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP,
            wire.topic_to_group(topic, SCOPE_NIBBLE).packed + struct.pack("@I", 0),
        )
        self.s.setblocking(False)

    def close(self):
        self.s.close()

    async def collect(self, seconds=0.3):
        loop = asyncio.get_event_loop()
        out = []
        end = loop.time() + seconds
        while loop.time() < end:
            try:
                out.append(self.s.recv(2048))
            except BlockingIOError:
                await asyncio.sleep(0.005)
        return out


async def _wait(items, n=1, timeout=2.0):
    loop = asyncio.get_event_loop()
    end = loop.time() + timeout
    while len(items) < n and loop.time() < end:
        await asyncio.sleep(0.01)


@pytest.fixture
async def make_client():
    started = []

    async def _make(**kw):
        kw.setdefault("port", _free_port())
        kw.setdefault("scope", SCOPE)
        c = MpubsubClient(**kw)
        await c.start()
        started.append(c)
        return c

    yield _make
    for c in started:
        await c.stop()


# --- receive -----------------------------------------------------------------


async def test_subscribe_receives(make_client):
    c = await make_client()
    got = []
    await c.subscribe(TOPIC, got.append)
    _send(TOPIC, b"42.5", c.port)
    await _wait(got)
    assert got[0].payload == "42.5"
    assert got[0].topic == TOPIC
    assert got[0].was_encrypted is False


async def test_encoding_none_gives_bytes(make_client):
    c = await make_client()
    got = []
    await c.subscribe(TOPIC, got.append, encoding=None)
    _send(TOPIC, b"\xff\xfe", c.port)
    await _wait(got)
    assert got[0].payload == b"\xff\xfe"


async def test_async_callback_is_awaited(make_client):
    c = await make_client()
    got = []

    async def cb(msg):
        await asyncio.sleep(0)
        got.append(msg.payload)

    await c.subscribe(TOPIC, cb)
    _send(TOPIC, b"hi", c.port)
    await _wait(got)
    assert got == ["hi"]


async def test_encrypted_roundtrip(make_client):
    key = wire.derive_key("secret")
    c = await make_client(key="secret")
    got = []
    await c.subscribe(TOPIC, got.append)
    _send(TOPIC, b"42.5", c.port, key=key)
    await _wait(got)
    assert got[0].payload == "42.5"
    assert got[0].was_encrypted is True


async def test_wrong_key_dropped(make_client):
    c = await make_client(key="right")
    got = []
    await c.subscribe(TOPIC, got.append)
    _send(TOPIC, b"42.5", c.port, key=wire.derive_key("wrong"))
    await asyncio.sleep(0.3)
    assert got == []


async def test_bad_callback_does_not_kill_the_client(make_client):
    c = await make_client()
    good = []

    def boom(msg):
        raise RuntimeError("callback error")

    await c.subscribe(TOPIC, boom)
    await c.subscribe(TOPIC, good.append)
    _send(TOPIC, b"x", c.port)
    await _wait(good)
    assert good[0].payload == "x"  # the throwing callback didn't stop the other


# --- subscription bookkeeping ------------------------------------------------


async def test_unsubscribe_refcount(make_client):
    c = await make_client()
    a, b = [], []
    unsub_a = await c.subscribe(TOPIC, a.append)
    await c.subscribe(TOPIC, b.append)
    unsub_a()
    assert TOPIC in c._subs
    _send(TOPIC, b"x", c.port)
    await _wait(b)
    assert a == [] and len(b) == 1


async def test_last_unsubscribe_leaves_group(make_client):
    c = await make_client()
    unsub = await c.subscribe(TOPIC, lambda m: None)
    assert TOPIC in c._subs
    unsub()
    assert TOPIC not in c._subs
    assert c._crc_index == {}


async def test_unsubscribe_from_callback_is_safe(make_client):
    c = await make_client()
    got = []

    def once(msg):
        got.append(msg)
        unsub()

    unsub = await c.subscribe(TOPIC, once)
    _send(TOPIC, b"first", c.port)
    await _wait(got)
    _send(TOPIC, b"second", c.port)
    await asyncio.sleep(0.2)
    assert len(got) == 1
    assert TOPIC not in c._subs


async def test_subscribe_rejects_wildcards(make_client):
    c = await make_client()
    for t in ("home/+/x", "home/#"):
        with pytest.raises(TopicError, match="wildcard"):
            await c.subscribe(t, lambda m: None)


async def test_subscribe_rejects_bad_encoding(make_client):
    c = await make_client()
    with pytest.raises(LookupError):
        await c.subscribe(TOPIC, lambda m: None, encoding="not-a-codec")


# --- publish -----------------------------------------------------------------


async def test_publish_on_the_wire(make_client):
    c = await make_client()
    sniff = _Sniffer(TOPIC, c.port)
    try:
        c.publish(TOPIC, "21.5")
        pkts = await sniff.collect()
    finally:
        sniff.close()
    assert len(pkts) == 1
    assert wire.decode(pkts[0]).payload == b"21.5"


async def test_publish_encrypted_is_opaque(make_client):
    key = wire.derive_key("k")
    c = await make_client(key="k")
    sniff = _Sniffer(TOPIC, c.port)
    try:
        c.publish(TOPIC, "21.5")
        pkts = await sniff.collect()
    finally:
        sniff.close()
    assert b"21.5" not in pkts[0]
    assert wire.decode(pkts[0], key=key).payload == b"21.5"


async def test_publish_numbers_stringify(make_client):
    c = await make_client()
    got = []
    await c.subscribe(TOPIC, got.append)
    c.publish(TOPIC, 21.5)
    await _wait(got)
    assert got[0].payload == "21.5"


async def test_publish_subscribe_loopback(make_client):
    c = await make_client()
    got = []
    await c.subscribe(TOPIC, got.append)
    c.publish(TOPIC, "loopback")
    await _wait(got)
    assert got[0].payload == "loopback"


async def test_finite_retransmits_are_identical(make_client):
    c = await make_client(key="k", retransmit_count=3, retransmit_delay=0.02)
    sniff = _Sniffer(TOPIC, c.port)
    try:
        c.publish(TOPIC, "once")
        pkts = await sniff.collect(0.4)
    finally:
        sniff.close()
    assert len(pkts) == 3
    assert pkts[0] == pkts[1] == pkts[2]  # same nonce -> receiver dedups


async def test_publish_rejects_wildcard(make_client):
    c = await make_client()
    with pytest.raises(TopicError, match="wildcard"):
        c.publish("home/+/x", "y")


# --- replay ------------------------------------------------------------------


async def test_replay_window_dedups(make_client):
    key = wire.derive_key("k")
    c = await make_client(key="k", replay_window=30)
    got = []
    await c.subscribe(TOPIC, got.append)
    data = wire.encode(TOPIC, b"42.5", key=key)
    for _ in range(2):
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        s.sendto(data, (str(wire.topic_to_group(TOPIC, SCOPE_NIBBLE)), c.port))
        s.close()
    await _wait(got)
    await asyncio.sleep(0.2)
    assert len(got) == 1


async def test_replay_window_needs_key():
    with pytest.raises(ValueError, match="replay_window requires a key"):
        MpubsubClient(replay_window=30)


async def test_indefinite_needs_delay():
    with pytest.raises(ValueError, match="requires retransmit_delay"):
        MpubsubClient(retransmit_count=-1, retransmit_delay=0.1)


# --- qos mapping (ported from bridges/mqtt-go/bridge.go) ----------------------


@pytest.mark.parametrize(
    "promote,base,qos,expected",
    [
        (False, 1, 2, 1),
        (True, 1, 0, 1),
        (True, 1, 1, 3),
        (True, 5, 1, 5),
        (True, -1, 1, -1),
        (True, 1, 2, -1),
        (True, -1, 0, -1),
    ],
)
async def test_qos_mapping(promote, base, qos, expected):
    c = MpubsubClient(promote_qos=promote, retransmit_count=base, retransmit_delay=1.0)
    assert c._effective_retransmit_count(qos) == expected
