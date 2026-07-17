"""The mpubsub transport: one UDP socket, N multicast groups.

Structurally this is the Go bridge's mpubsub half (``bridges/mqtt-go/``)
rewritten against asyncio, and it is deliberately kept readable as such --
the qos->retransmit mapping, the topic-supersede rule and the socket options
all cite the Go line they mirror. The three implementations agreeing is the
whole point of this protocol's test suite; a fourth that quietly does its own
thing would be worse than none.

The framing itself is not implemented here. It comes from ``reference.py``,
vendored byte-for-byte from tests/unit (see test_vendored_reference.py), so
this module only has to get the *plumbing* right: which group to join, which
interface to use, when to resend, and what to drop.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import struct
import time
from dataclasses import dataclass, field
from ipaddress import IPv6Address
from typing import Any

from homeassistant.core import CALLBACK_TYPE, HassJob, HomeAssistant, callback
from homeassistant.helpers.event import async_call_later

from . import reference
from .const import DEFAULT_QOS, RETRANSMIT_INDEFINITE
from .models import MpubsubConfig, MessageCallbackType, ReceiveMessage
from .reference import ENCODING_RAW, WireError
from .util import validate_topic

_LOGGER = logging.getLogger(__name__)

#: The Go bridge uses 4096 "because the bridge runs on a real host, so a
#: generous de-dup cache costs little" (bridges/mqtt-go/bridge.go). Home
#: Assistant is at least as real a host; the C++ side's 64 is an MCU budget.
REPLAY_CACHE_ENTRIES = 4096


@dataclass(slots=True)
class _Subscription:
    """One caller's interest in a topic."""

    job: HassJob[[ReceiveMessage], Any]
    encoding: str | None


@dataclass(slots=True)
class _TopicSub:
    """Everything the receive path needs for one joined topic."""

    topic: str
    crc: int
    group: IPv6Address
    #: The refcount *is* this list's length -- there is no separate integer
    #: to fall out of sync. Emptying it leaves the group.
    callbacks: list[_Subscription] = field(default_factory=list)


class _MpubsubProtocol(asyncio.DatagramProtocol):
    """Thin asyncio glue; all the thinking is in MpubsubClient."""

    def __init__(self, client: MpubsubClient) -> None:
        self._client = client

    def datagram_received(self, data: bytes, addr: tuple) -> None:
        self._client.handle_datagram(data, addr)

    def error_received(self, exc: Exception) -> None:
        # ICMP errors surface here; a multicast send has no listener to
        # complain, so this is rare and never fatal.
        _LOGGER.debug("mpubsub socket error: %s", exc)

    def connection_lost(self, exc: Exception | None) -> None:
        if exc is not None:
            _LOGGER.warning("mpubsub socket closed unexpectedly: %s", exc)


class MpubsubClient:
    """Publish/subscribe over IPv6 multicast for one fabric."""

    def __init__(self, hass: HomeAssistant, config: MpubsubConfig) -> None:
        self.hass = hass
        self.config = config
        self._sock: socket.socket | None = None
        self._transport: asyncio.DatagramTransport | None = None
        self._ifindex = 0  # 0 = let the kernel choose

        self._subs: dict[str, _TopicSub] = {}
        self._crc_index: dict[int, list[_TopicSub]] = {}
        self._groups: dict[str, IPv6Address] = {}  # topic -> group, memoised

        self._replay = reference.ReplayGuard(
            config.replay_window, max_entries=REPLAY_CACHE_ENTRIES
        )
        # topic -> cancel handle for an indefinite retransmit chain
        self._indefinite: dict[str, CALLBACK_TYPE] = {}
        self._finite: set[CALLBACK_TYPE] = set()
        self._send_failed = False  # rate-limit the ENETUNREACH nag

    @property
    def available(self) -> bool:
        """True once the socket is open. There is no connection to lose."""
        return self._transport is not None and not self._transport.is_closing()

    # --- lifecycle -----------------------------------------------------------

    async def async_start(self) -> None:
        """Open the socket and attach it to the event loop."""
        sock = await self.hass.async_add_executor_job(self._make_socket)
        self._sock = sock
        loop = self.hass.loop
        self._transport, _ = await loop.create_datagram_endpoint(
            lambda: _MpubsubProtocol(self), sock=sock
        )
        _LOGGER.debug(
            "mpubsub listening on [::]:%s (scope=%#x hops=%s interface=%s key=%s)",
            self.config.port,
            self.config.scope,
            self.config.hops,
            self.config.interface or "<kernel-picked>",
            "yes" if self.config.key else "no",
        )

    def _make_socket(self) -> socket.socket:
        """Build the multicast socket. Runs in the executor.

        Not because it must: Home Assistant's blocking-call detector covers
        open/glob/import/sleep and friends, not socket calls, and none of
        these block in any real sense. It is here because async_start awaits
        it during setup, where an executor hop is free, and it keeps
        if_nametoindex and a bind on a contended port off the loop.

        The recipe is tests/probe.py's verified one plus the send-side
        options from bridges/mqtt-go/mcast.go.
        """
        if self.config.interface:
            # Raises OSError for an unknown interface; the config flow
            # resolves it up front so this is the belt to that's braces.
            self._ifindex = socket.if_nametoindex(self.config.interface)

        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            # SO_REUSEPORT lets a probe.py, a Go bridge and Home Assistant all
            # co-bind :18512 on one host (mcast.go). Not universally available.
            if hasattr(socket, "SO_REUSEPORT"):
                try:
                    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEPORT, 1)
                except OSError:  # pragma: no cover - platform dependent
                    _LOGGER.debug("SO_REUSEPORT unavailable; continuing")
            # Bind the wildcard address, not the group: one socket serves
            # every group we join.
            sock.bind(("::", self.config.port))
            sock.setsockopt(
                socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, self.config.hops
            )
            # Explicit even though 1 is the default: this is what lets a
            # probe.py on the same box see what we publish.
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

    async def async_stop(self) -> None:
        """Cancel every pending send, then close.

        Cancelling first mirrors bridges/mqtt-go/bridge.go, but unlike the Go
        bridge's goroutines nothing here can interleave: this function never
        awaits, so no timer callback can run between the cancels and the
        close. The order is for symmetry with Go, not correctness -- don't
        rely on it to prevent a send-after-close.
        """
        for cancel in list(self._indefinite.values()):
            cancel()
        self._indefinite.clear()
        for cancel in list(self._finite):
            cancel()
        self._finite.clear()

        if self._transport is not None:
            self._transport.close()
            self._transport = None
        self._sock = None
        self._subs.clear()
        self._crc_index.clear()

    # --- subscribe -----------------------------------------------------------

    async def async_subscribe(
        self,
        topic: str,
        msg_callback: MessageCallbackType,
        encoding: str | None = "utf-8",
    ) -> CALLBACK_TYPE:
        """Subscribe to an exact topic. Returns the unsubscribe callable.

        Unlike mqtt's async_subscribe, which queues the SUBSCRIBE and returns,
        this actually joins a multicast group and so can raise OSError.
        """
        validate_topic(topic)
        sub = _Subscription(job=HassJob(msg_callback), encoding=encoding)

        topic_sub = self._subs.get(topic)
        if topic_sub is None:
            topic_sub = await self._async_join(topic)
        topic_sub.callbacks.append(sub)

        @callback
        def unsubscribe() -> None:
            self._unsubscribe(topic, sub)

        return unsubscribe

    async def _async_join(self, topic: str) -> _TopicSub:
        crc = reference.topic_crc32(topic)
        group = self._group_for(topic)

        if (existing := self._crc_index.get(crc)) is not None:
            # CRC32 is 32 bits and the group is 112, so two topics can collide
            # on the dispatch key while living in different groups. The
            # datagram carries only the CRC and asyncio's datagram transport
            # doesn't expose which group it arrived on (that needs
            # IPV6_RECVPKTINFO + recvmsg), so this is genuinely
            # undisambiguatable. Say so; don't pretend to fix it.
            _LOGGER.warning(
                "topic %r collides with %r on TOPIC_CRC32 %#010x -- each will "
                "receive the other's messages. Rename one.",
                topic,
                existing[0].topic,
                crc,
            )

        if self._sock is None:
            raise RuntimeError("mpubsub client is not started")
        self._join_group(group)

        topic_sub = _TopicSub(topic=topic, crc=crc, group=group)
        self._subs[topic] = topic_sub
        self._crc_index.setdefault(crc, []).append(topic_sub)
        _LOGGER.debug("joined %s for topic %r (crc %#010x)", group, topic, crc)
        return topic_sub

    # Group join/leave run inline, not in the executor. setsockopt on an
    # already-open fd is a bare syscall -- it does no I/O and Home Assistant's
    # blocking-call detector doesn't cover it (only open/glob/import/sleep and
    # friends). Pushing them to the executor bought nothing and cost
    # correctness: _unsubscribe had to fire the job without awaiting it, so a
    # late unsubscribe -- one arriving as the loop shuts down -- raised
    # "RuntimeError: no running event loop" out of async_add_executor_job.
    # Socket *creation* stays in the executor; that one is awaited.

    def _join_group(self, group: IPv6Address) -> None:
        assert self._sock is not None
        mreq = group.packed + struct.pack("@I", self._ifindex)
        self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, mreq)

    def _leave_group(self, group: IPv6Address) -> None:
        if self._sock is None:
            return  # already stopped; the close left every group for us
        mreq = group.packed + struct.pack("@I", self._ifindex)
        try:
            self._sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_LEAVE_GROUP, mreq)
        except OSError as err:  # pragma: no cover - already gone is fine
            _LOGGER.debug("leaving %s failed: %s", group, err)

    @callback
    def _unsubscribe(self, topic: str, sub: _Subscription) -> None:
        topic_sub = self._subs.get(topic)
        if topic_sub is None or sub not in topic_sub.callbacks:
            return  # already gone; unsubscribing twice is not an error
        topic_sub.callbacks.remove(sub)
        if topic_sub.callbacks:
            return  # other listeners remain -- stay in the group

        del self._subs[topic]
        siblings = self._crc_index.get(topic_sub.crc, [])
        if topic_sub in siblings:
            siblings.remove(topic_sub)
        if not siblings:
            self._crc_index.pop(topic_sub.crc, None)
        self._leave_group(topic_sub.group)
        _LOGGER.debug("left %s (no subscribers for %r)", topic_sub.group, topic)

    # --- receive -------------------------------------------------------------

    @callback
    def handle_datagram(self, data: bytes, addr: tuple) -> None:
        """Decode one datagram and fan it out. Runs on the event loop."""
        try:
            msg = reference.decode(data, key=self.config.key)
        except WireError as err:
            # Debug, not warning: an encrypted packet reaching an unkeyed
            # node is a legitimate mixed fabric, and anyone can send us
            # rubbish. Neither should fill the log.
            _LOGGER.debug("dropped packet from %s: %s", addr[0] if addr else "?", err)
            return

        if msg.was_encrypted and not self._replay.accept(
            int(time.time()),
            # A Home Assistant host has a real clock. The Go bridge assumes
            # the same (bridge.go); the C++ side has to ask, because an MCU
            # may not have synced yet.
            True,
            msg.timestamp,
            msg.nonce,
        ):
            _LOGGER.debug(
                "dropped stale or replayed packet from %s (ts=%s nonce=%s)",
                addr[0] if addr else "?",
                msg.timestamp,
                msg.nonce,
            )
            return

        subs = self._crc_index.get(msg.topic_crc)
        if not subs:
            # We joined this group for another topic, or a CRC we don't want
            # arrived on a group we're in. Cheap and expected.
            return

        if msg.encoding != ENCODING_RAW:
            _LOGGER.debug(
                "dropped packet for %r: wire encoding %#04x is not supported yet "
                "(this integration is RAW-only)",
                subs[0].topic,
                msg.encoding,
            )
            return

        timestamp = time.time()
        # Both lists are copied: a @callback subscriber runs synchronously
        # inside async_run_hass_job and may unsubscribe itself, which removes
        # entries from topic_sub.callbacks *and*, if it was the last listener,
        # from this very `subs` list (see _unsubscribe). Iterating either one
        # live would silently skip a delivery.
        for topic_sub in list(subs):
            for sub in list(topic_sub.callbacks):
                self._dispatch(topic_sub, sub, msg, timestamp)

    @callback
    def _dispatch(
        self,
        topic_sub: _TopicSub,
        sub: _Subscription,
        msg: reference.DecodedMessage,
        timestamp: float,
    ) -> None:
        payload: str | bytes = msg.payload
        if sub.encoding is not None:
            try:
                payload = msg.payload.decode(sub.encoding)
            except UnicodeDecodeError:
                _LOGGER.warning(
                    "Can't decode payload %s on %s with encoding %s (for %s)",
                    msg.payload[:100],
                    topic_sub.topic,
                    sub.encoding,
                    sub.job,
                )
                return
            except LookupError:
                # An unknown codec raises LookupError, which is NOT a
                # UnicodeDecodeError. Unhandled, it escapes into
                # datagram_received once per arriving packet -- forever. The
                # schemas screen this out (util.valid_encoding); this covers
                # async_subscribe's Python callers, who reach it directly.
                _LOGGER.error(
                    "Unknown encoding %r for subscription on %s; dropping the "
                    "message. Use a Python codec name such as 'utf-8', or None "
                    "for raw bytes.",
                    sub.encoding,
                    topic_sub.topic,
                )
                return
        self.hass.async_run_hass_job(
            sub.job,
            ReceiveMessage(
                topic=topic_sub.topic,
                payload=payload,
                qos=0,
                retain=False,
                subscribed_topic=topic_sub.topic,
                timestamp=timestamp,
                was_encrypted=msg.was_encrypted,
                wire_encoding=msg.encoding,
                sender_timestamp=msg.timestamp,
            ),
        )

    # --- publish -------------------------------------------------------------

    @callback
    def async_publish(
        self,
        topic: str,
        payload: bytes,
        qos: int = DEFAULT_QOS,
        retain: bool = False,
    ) -> None:
        """Encode and send one publication, plus any retransmits."""
        validate_topic(topic)
        if retain:
            _LOGGER.debug(
                "retain=True ignored for %r: the mpubsub wire format has no "
                "retain flag and there is no broker to hold the message. "
                "Subscribers see nothing until the next publish.",
                topic,
            )
        if self._transport is None:
            raise RuntimeError("mpubsub client is not started")

        group = self._group_for(topic)
        timestamp = int(time.time()) if self.config.key else None
        # Encode ONCE and resend these exact bytes. Identical bytes mean an
        # identical AEAD nonce, which is what lets a replay-checking receiver
        # collapse our retransmits into a single delivery. Re-encoding per
        # retransmit would mint a fresh nonce and defeat that -- every
        # retransmit would be delivered. See reference.py's ReplayGuard notes.
        data = reference.encode(
            topic, payload, ENCODING_RAW, key=self.config.key, timestamp=timestamp
        )

        count = self._effective_retransmit_count(qos)
        # A new publish supersedes an in-flight indefinite chain for the same
        # topic (bridges/mqtt-go/bridge.go). Note it does NOT cancel a finite
        # chain -- matching the Go bridge, deliberately, so the two agree.
        self._cancel_indefinite(topic)
        self._sendto(data, group)  # first send is always synchronous

        if count == RETRANSMIT_INDEFINITE:
            self._start_indefinite(topic, group, data)
        elif count > 1:
            self._schedule_finite(topic, group, data, count)

    def _effective_retransmit_count(self, qos: int) -> int:
        """Map an MQTT QoS onto a retransmit count.

        A literal port of effectiveRetransmitCount in
        bridges/mqtt-go/bridge.go. The rule is "QoS bumps the count up, never
        down", so an already-indefinite config stays indefinite at QoS 0.
        """
        base = self.config.retransmit_count
        if not self.config.promote_qos:
            return base
        if qos == 0:
            return base
        if qos == 1:
            if base == RETRANSMIT_INDEFINITE:
                return RETRANSMIT_INDEFINITE
            return max(base, 3)
        return RETRANSMIT_INDEFINITE  # qos 2, and any future value >= 2

    def _group_for(self, topic: str) -> IPv6Address:
        group = self._groups.get(topic)
        if group is None:
            group = reference.topic_to_group(topic, self.config.scope)
            self._groups[topic] = group
        return group

    @callback
    def _sendto(self, data: bytes, group: IPv6Address) -> None:
        assert self._transport is not None
        try:
            self._transport.sendto(data, (str(group), self.config.port))
        except OSError as err:
            if not self._send_failed:
                self._send_failed = True
                _LOGGER.error(
                    "mpubsub send to %s failed: %s. If this host has more than "
                    "one network interface, or no route for multicast, set the "
                    "`interface` option (e.g. eth0) to pin the egress "
                    "interface. Further send errors will be logged at debug.",
                    group,
                    err,
                )
            else:
                _LOGGER.debug("mpubsub send to %s failed: %s", group, err)

    def _schedule_finite(
        self, topic: str, group: IPv6Address, data: bytes, count: int
    ) -> None:
        """Queue (count - 1) more sends at absolute offsets from now.

        Offsets are absolute (delay, 2*delay, ...) rather than a chain, so a
        slow loop can't stretch the spacing -- same as the Go bridge.
        """
        delay = self.config.retransmit_delay
        for i in range(1, count):
            self._schedule_one(delay * i, data, group)

    def _schedule_one(self, when: float, data: bytes, group: IPv6Address) -> None:
        # The cancel handle has to be reachable from the callback that
        # discards it, hence the one-slot holder.
        holder: list[CALLBACK_TYPE | None] = [None]

        @callback
        def _fire(_now: Any) -> None:
            if holder[0] is not None:
                self._finite.discard(holder[0])
            self._sendto(data, group)

        cancel = async_call_later(self.hass, when, _fire)
        holder[0] = cancel
        self._finite.add(cancel)

    def _start_indefinite(
        self, topic: str, group: IPv6Address, data: bytes
    ) -> None:
        """Resend forever until a publish to this topic supersedes us."""
        delay = self.config.retransmit_delay

        @callback
        def _tick(_now: Any) -> None:
            self._sendto(data, group)
            # Re-arm rather than using a repeating timer, so the cancel
            # handle stays a single object (as the Go ticker's does).
            self._indefinite[topic] = async_call_later(self.hass, delay, _tick)

        self._indefinite[topic] = async_call_later(self.hass, delay, _tick)

    @callback
    def _cancel_indefinite(self, topic: str) -> None:
        if (cancel := self._indefinite.pop(topic, None)) is not None:
            cancel()
