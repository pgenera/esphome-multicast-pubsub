"""A plain-asyncio mpubsub client: subscribe and publish over IPv6 multicast.

This is the Home Assistant integration's transport with Home Assistant taken
out -- ``loop.call_later`` in place of ``async_call_later``, plain callables
in place of ``HassJob``, and inline socket calls instead of executor hops.
The framing is entirely :mod:`mpubsub.wire` (a byte-identical copy of the
protocol's reference implementation), so this module only has to get the
plumbing right: which group to join, when to resend, and what to drop.

Written to run anywhere Python 3.7+ does, with no required third-party
dependency. ``cryptography`` is used to accelerate the AEAD when present
(see :mod:`mpubsub.wire`) and is otherwise not needed.

    client = MpubsubClient(scope="link-local", key="my-passphrase")
    await client.start()
    unsub = await client.subscribe("home/kitchen/temp", on_message)
    client.publish("home/fan/cmd", "ON")
    ...
    await client.stop()
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from ipaddress import IPv6Address
from typing import Awaitable, Callable, Dict, List, Optional, Union

from . import wire

_LOGGER = logging.getLogger("mpubsub")

#: Matches the Go bridge's de-dup cache (bridges/mqtt-go): a real host can
#: afford a generous one. Only encrypted traffic is de-duplicated.
REPLAY_CACHE_ENTRIES = 4096

#: Keep emitting a publish until a later publish to the same topic supersedes
#: it. An indefinite chain needs a delay >= 1s or it saturates the segment.
RETRANSMIT_INDEFINITE = -1
_MIN_INDEFINITE_DELAY = 1.0

_SCOPE_NAMES = {
    "link-local": wire.SCOPE_LINK_LOCAL,
    "site-local": wire.SCOPE_SITE_LOCAL,
    "organization-local": wire.SCOPE_ORG_LOCAL,
}

_MAX_TOPIC_BYTES = 200
_WILDCARD_CHARS = ("+", "#")

PayloadType = Union[str, bytes, int, float, None]
MessageCallback = Callable[["Message"], Optional[Awaitable[None]]]


class MpubsubError(Exception):
    """Base class for this library's errors."""


class TopicError(MpubsubError, ValueError):
    """A topic string the client will not accept."""


class Message:
    """A received mpubsub message handed to a subscription callback."""

    __slots__ = ("topic", "payload", "was_encrypted", "wire_encoding", "sender_timestamp")

    def __init__(self, topic, payload, was_encrypted, wire_encoding, sender_timestamp):
        self.topic = topic  # str: the exact topic subscribed to
        self.payload = payload  # str or bytes, per the subscription's encoding
        self.was_encrypted = was_encrypted  # bool
        self.wire_encoding = wire_encoding  # wire.ENCODING_RAW / _PROTOBUF
        self.sender_timestamp = sender_timestamp  # int unix secs, or None (plaintext)

    def __repr__(self):
        return (
            "Message(topic=%r, payload=%r, was_encrypted=%r)"
            % (self.topic, self.payload, self.was_encrypted)
        )


def resolve_scope(scope: Union[str, int]) -> int:
    """Accept a scope name (``"link-local"``) or a raw nibble and return the
    nibble. Names match the ESPHome component and the Go bridge."""
    if isinstance(scope, int):
        if scope not in wire.VALID_SCOPES:
            raise ValueError("invalid scope nibble %#x" % scope)
        return scope
    try:
        return _SCOPE_NAMES[scope]
    except KeyError:
        raise ValueError(
            "unknown scope %r; use one of %s"
            % (scope, ", ".join(sorted(_SCOPE_NAMES)))
        )


def validate_topic(topic: str) -> str:
    """Reject topics that cannot work, and wildcards that would never match.

    The wire carries only a CRC32 of the topic, and receiving means joining
    the multicast group derived from the exact string, so there is nothing to
    match a wildcard against. A ``+``/``#`` is a legal literal mpubsub topic,
    but a caller almost always means a pattern, and a subscription that
    silently never fires is worse than an error.
    """
    if not isinstance(topic, str):
        raise TopicError("topic must be a string, got %s" % type(topic).__name__)
    for char in _WILDCARD_CHARS:
        if char in topic:
            raise TopicError(
                "topic %r contains the MQTT wildcard %r, which mpubsub cannot "
                "support: the wire carries only a CRC32 of the topic, so there "
                "is no way to match a pattern. Subscribe to each topic "
                "individually." % (topic, char)
            )
    encoded = topic.encode("utf-8")
    if not encoded:
        raise TopicError("topic must not be empty")
    if b"\x00" in encoded:
        raise TopicError("topic must not contain NUL bytes")
    if len(encoded) > _MAX_TOPIC_BYTES:
        raise TopicError(
            "topic too long: %d bytes (limit %d)" % (len(encoded), _MAX_TOPIC_BYTES)
        )
    return topic


class _Subscription:
    __slots__ = ("callback", "encoding")

    def __init__(self, callback, encoding):
        self.callback = callback
        self.encoding = encoding


class _TopicSub:
    __slots__ = ("topic", "crc", "group", "callbacks")

    def __init__(self, topic, crc, group):
        self.topic = topic
        self.crc = crc
        self.group = group
        #: The refcount *is* this list's length; emptying it leaves the group.
        self.callbacks = []  # type: List[_Subscription]


class _Protocol(asyncio.DatagramProtocol):
    def __init__(self, client):
        self._client = client

    def datagram_received(self, data, addr):
        self._client._handle_datagram(data, addr)

    def error_received(self, exc):
        _LOGGER.debug("mpubsub socket error: %s", exc)


class MpubsubClient:
    """Subscribe and publish over one mpubsub fabric.

    Parameters mirror the ESPHome component's ``mpubsub:`` block and the Go
    bridge's config, so a fabric is described the same way everywhere.
    """

    def __init__(
        self,
        port: int = wire.DEFAULT_PORT,
        scope: Union[str, int] = "link-local",
        interface: Optional[str] = None,
        key: Union[str, bytes, None] = None,
        hops: int = 1,
        replay_window: int = 0,
        retransmit_count: int = 1,
        retransmit_delay: float = 0.1,
        promote_qos: bool = False,
        loop: Optional[asyncio.AbstractEventLoop] = None,
    ):
        self.port = port
        self.scope = resolve_scope(scope)
        self.interface = interface
        self.hops = hops
        self.retransmit_count = retransmit_count
        self.retransmit_delay = retransmit_delay
        self.promote_qos = promote_qos

        if isinstance(key, str):
            key = wire.derive_key(key) if key else None
        self.key = key  # 32-byte key or None

        if retransmit_count == RETRANSMIT_INDEFINITE and retransmit_delay < _MIN_INDEFINITE_DELAY:
            raise ValueError(
                "retransmit_count=-1 (indefinite) requires retransmit_delay >= 1s"
            )
        if retransmit_count == 0 or retransmit_count < RETRANSMIT_INDEFINITE:
            raise ValueError("retransmit_count must be 1..255 or -1 (indefinite)")
        if replay_window and not self.key:
            raise ValueError(
                "replay_window requires a key: replay protection only applies "
                "to encrypted packets"
            )

        self._loop = loop
        self._sock = None  # type: Optional[socket.socket]
        self._transport = None  # type: Optional[asyncio.BaseTransport]
        self._ifindex = 0

        self._subs = {}  # type: Dict[str, _TopicSub]
        self._crc_index = {}  # type: Dict[int, List[_TopicSub]]
        self._groups = {}  # type: Dict[str, IPv6Address]

        self._replay = wire.ReplayGuard(replay_window, max_entries=REPLAY_CACHE_ENTRIES)
        self._indefinite = {}  # type: Dict[str, asyncio.TimerHandle]
        self._finite = set()  # type: set
        self._send_failed = False

    @property
    def available(self) -> bool:
        return self._transport is not None and not self._transport.is_closing()

    # --- lifecycle -----------------------------------------------------------

    async def start(self) -> None:
        """Open the socket and attach it to the running event loop."""
        self._loop = self._loop or asyncio.get_event_loop()
        self._sock = self._make_socket()
        self._transport, _ = await self._loop.create_datagram_endpoint(
            lambda: _Protocol(self), sock=self._sock
        )
        _LOGGER.debug(
            "mpubsub listening on [::]:%s (scope=%#x hops=%s interface=%s key=%s)",
            self.port, self.scope, self.hops, self.interface or "<kernel>",
            "yes" if self.key else "no",
        )

    def _make_socket(self) -> socket.socket:
        # The verified recipe from tests/probe.py plus the send-side options
        # from bridges/mqtt-go/mcast.go. setsockopt on an open fd does no I/O,
        # so this stays inline.
        if self.interface:
            self._ifindex = socket.if_nametoindex(self.interface)
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:
                    pass
            sock.bind(("::", self.port))
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.hops)
            sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, 1)
            if self._ifindex:
                sock.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, self._ifindex
                )
            sock.setblocking(False)
        except BaseException:
            sock.close()
            raise
        return sock

    async def stop(self) -> None:
        """Cancel every pending retransmit, then close the socket."""
        for handle in list(self._indefinite.values()):
            handle.cancel()
        self._indefinite.clear()
        for handle in list(self._finite):
            handle.cancel()
        self._finite.clear()
        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._sock = None
        self._subs.clear()
        self._crc_index.clear()

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc):
        await self.stop()

    # --- subscribe -----------------------------------------------------------

    async def subscribe(
        self, topic: str, callback: MessageCallback, encoding: Optional[str] = "utf-8"
    ) -> Callable[[], None]:
        """Subscribe to an exact topic. Returns a function that unsubscribes.

        ``callback`` receives a :class:`Message`; it may be a plain function
        or a coroutine function. ``encoding`` decodes the payload to ``str``
        (``None`` delivers raw ``bytes``).
        """
        validate_topic(topic)
        if encoding is not None:
            "".encode(encoding)  # fail now on a bad codec, not per packet
        sub = _Subscription(callback, encoding)

        topic_sub = self._subs.get(topic)
        if topic_sub is None:
            topic_sub = self._join(topic)
        topic_sub.callbacks.append(sub)

        def unsubscribe():
            self._unsubscribe(topic, sub)

        return unsubscribe

    def _join(self, topic: str) -> _TopicSub:
        if self._sock is None:
            raise MpubsubError("client is not started")
        crc = wire.topic_crc32(topic)
        group = self._group_for(topic)
        existing = self._crc_index.get(crc)
        if existing is not None and existing[0].topic != topic:
            _LOGGER.warning(
                "topic %r collides with %r on TOPIC_CRC32 %#010x -- each will "
                "receive the other's messages. Rename one.",
                topic, existing[0].topic, crc,
            )
        mreq = group.packed + struct.pack("@I", self._ifindex)
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)
        topic_sub = _TopicSub(topic, crc, group)
        self._subs[topic] = topic_sub
        self._crc_index.setdefault(crc, []).append(topic_sub)
        _LOGGER.debug("joined %s for topic %r", group, topic)
        return topic_sub

    def _unsubscribe(self, topic: str, sub: _Subscription) -> None:
        topic_sub = self._subs.get(topic)
        if topic_sub is None or sub not in topic_sub.callbacks:
            return
        topic_sub.callbacks.remove(sub)
        if topic_sub.callbacks:
            return
        del self._subs[topic]
        siblings = self._crc_index.get(topic_sub.crc, [])
        if topic_sub in siblings:
            siblings.remove(topic_sub)
        if not siblings:
            self._crc_index.pop(topic_sub.crc, None)
        if self._sock is not None:
            mreq = topic_sub.group.packed + struct.pack("@I", self._ifindex)
            try:
                self._sock.setsockopt(
                    socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq
                )
            except OSError as err:
                _LOGGER.debug("leaving %s failed: %s", topic_sub.group, err)
        _LOGGER.debug("left %s (no subscribers for %r)", topic_sub.group, topic)

    # --- receive -------------------------------------------------------------

    def _handle_datagram(self, data, addr):
        try:
            msg = wire.decode(data, key=self.key)
        except wire.WireError as err:
            _LOGGER.debug("dropped packet from %s: %s", addr[0] if addr else "?", err)
            return

        if msg.was_encrypted and not self._replay.accept(
            int(time.time()), True, msg.timestamp, msg.nonce
        ):
            _LOGGER.debug("dropped stale or replayed packet from %s", addr[0] if addr else "?")
            return

        subs = self._crc_index.get(msg.topic_crc)
        if not subs:
            return
        if msg.encoding != wire.ENCODING_RAW:
            _LOGGER.debug(
                "dropped packet for %r: wire encoding %#04x not supported (RAW only)",
                subs[0].topic, msg.encoding,
            )
            return

        # Both lists are copied: a callback may unsubscribe during dispatch,
        # mutating callbacks and, if it was the last one, this subs list.
        for topic_sub in list(subs):
            for sub in list(topic_sub.callbacks):
                self._dispatch(topic_sub, sub, msg)

    def _dispatch(self, topic_sub, sub, msg):
        payload = msg.payload
        if sub.encoding is not None:
            try:
                payload = msg.payload.decode(sub.encoding)
            except UnicodeDecodeError:
                _LOGGER.warning(
                    "can't decode payload on %s with encoding %s",
                    topic_sub.topic, sub.encoding,
                )
                return
        message = Message(
            topic_sub.topic, payload, msg.was_encrypted, msg.encoding, msg.timestamp
        )
        try:
            result = sub.callback(message)
        except Exception:  # noqa: BLE001 - a bad callback must not kill the loop
            _LOGGER.exception("error in mpubsub callback for %s", topic_sub.topic)
            return
        if asyncio.iscoroutine(result):
            self._loop.create_task(result)

    # --- publish -------------------------------------------------------------

    def publish(
        self, topic: str, payload: PayloadType, qos: int = 0, retain: bool = False
    ) -> None:
        """Encode and send one publication, plus any retransmits.

        ``retain`` is accepted and ignored (there is no retain on the wire).
        ``qos`` raises the retransmit count when ``promote_qos`` is set.
        """
        validate_topic(topic)
        if retain:
            _LOGGER.debug("retain=True ignored for %r: mpubsub has no retain flag", topic)
        if self._transport is None:
            raise MpubsubError("client is not started")

        group = self._group_for(topic)
        timestamp = int(time.time()) if self.key else None
        # Encode ONCE and resend these exact bytes: identical bytes mean an
        # identical AEAD nonce, which lets a replay-checking receiver collapse
        # the retransmits into a single delivery. Re-encoding per retransmit
        # would mint a fresh nonce and defeat that.
        data = wire.encode(
            topic, _to_bytes(payload), wire.ENCODING_RAW, key=self.key, timestamp=timestamp
        )

        count = self._effective_retransmit_count(qos)
        self._cancel_indefinite(topic)  # a new publish supersedes an in-flight chain
        self._sendto(data, group)
        if count == RETRANSMIT_INDEFINITE:
            self._start_indefinite(topic, group, data)
        elif count > 1:
            for i in range(1, count):
                self._schedule_one(self.retransmit_delay * i, data, group)

    def _effective_retransmit_count(self, qos: int) -> int:
        # A literal port of effectiveRetransmitCount in bridges/mqtt-go: QoS
        # bumps the count up, never down.
        base = self.retransmit_count
        if not self.promote_qos:
            return base
        if qos == 0:
            return base
        if qos == 1:
            return RETRANSMIT_INDEFINITE if base == RETRANSMIT_INDEFINITE else max(base, 3)
        return RETRANSMIT_INDEFINITE

    def _group_for(self, topic: str) -> IPv6Address:
        group = self._groups.get(topic)
        if group is None:
            group = wire.topic_to_group(topic, self.scope)
            self._groups[topic] = group
        return group

    def _sendto(self, data, group):
        try:
            self._transport.sendto(data, (str(group), self.port))
        except OSError as err:
            if not self._send_failed:
                self._send_failed = True
                _LOGGER.error(
                    "mpubsub send to %s failed: %s. On a multi-homed host, or "
                    "one with no multicast route, pass interface=<name>. "
                    "Further errors log at debug.", group, err,
                )
            else:
                _LOGGER.debug("mpubsub send to %s failed: %s", group, err)

    def _schedule_one(self, when, data, group):
        holder = [None]

        def fire():
            if holder[0] is not None:
                self._finite.discard(holder[0])
            self._sendto(data, group)

        handle = self._loop.call_later(when, fire)
        holder[0] = handle
        self._finite.add(handle)

    def _start_indefinite(self, topic, group, data):
        def tick():
            self._sendto(data, group)
            self._indefinite[topic] = self._loop.call_later(self.retransmit_delay, tick)

        self._indefinite[topic] = self._loop.call_later(self.retransmit_delay, tick)

    def _cancel_indefinite(self, topic):
        handle = self._indefinite.pop(topic, None)
        if handle is not None:
            handle.cancel()


def _to_bytes(payload: PayloadType) -> bytes:
    if payload is None:
        return b""
    if isinstance(payload, bytes):
        return payload
    if not isinstance(payload, str):
        payload = str(payload)
    return payload.encode("utf-8")
