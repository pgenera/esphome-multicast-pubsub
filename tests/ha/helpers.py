"""Shared socket helpers for the Home Assistant component tests.

Imported plainly (``from helpers import ...``): pytest's default prepend
import mode puts this directory on sys.path, and tests/ha is deliberately
not a package.
"""

from __future__ import annotations

import asyncio
import socket
import struct
from ipaddress import IPv6Address

import pytest

from custom_components.mpubsub.models import MpubsubConfig
from custom_components.mpubsub.reference import encode, topic_to_group

SCOPE_LINK_LOCAL = 0x2

#: Interface index 0 means "let the kernel choose", which is what
#: tests/probe.py and tests/unit/test_encrypted_cross_check.py already do,
#: and the only thing that works.
#:
#: Pinning ``lo`` is the obvious idea and it cannot work: loopback carries
#: only ``::1/128 scope host`` with no link-local address, so it gets no
#: ff00::/8 route and a send to ff12:: fails with ENETUNREACH. Multicast
#: tests therefore go out over a *real* interface -- the kernel picks it from
#: the routing table -- and come back via IPV6_MULTICAST_LOOP. hops=1 keeps
#: the packets on the local segment. This is already how the ESPHome host
#: tests behave; it is worth knowing that running this suite emits a little
#: real multicast on the LAN.
IFINDEX_KERNEL_PICKS = 0


def multicast_works() -> bool:
    """Can this box send to a transient link-local multicast group?

    A container or CI runner with IPv6 disabled cannot, and these tests
    should skip there rather than fail -- the same courtesy the C++
    cross-checks extend when their binaries aren't built. Checks a send, not
    just a join: a join succeeds on a box with no multicast route at all,
    which is precisely the case we need to skip.
    """
    try:
        sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    except OSError:
        return False
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind(("::", 0))
        sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_JOIN_GROUP,
            IPv6Address("ff12::1234").packed
            + struct.pack("@I", IFINDEX_KERNEL_PICKS),
        )
        sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
        sock.sendto(b"", ("ff12::1234", 9))  # discard port
    except OSError:
        return False
    finally:
        sock.close()
    return True


requires_multicast = pytest.mark.skipif(
    not multicast_works(),
    reason="IPv6 multicast is unavailable here",
)


def free_port() -> int:
    """A port nobody is using.

    Tests randomise the port instead of using 18512 so that a stray process
    from an earlier run cannot make the suite lie -- an orphan holding the
    default port has burned this repo before.
    """
    with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as sock:
        sock.bind(("::", 0))
        return sock.getsockname()[1]


def make_config(port: int, **overrides) -> MpubsubConfig:
    defaults = dict(
        port=port,
        scope=SCOPE_LINK_LOCAL,
        interface=None,  # kernel picks; see IFINDEX_KERNEL_PICKS
        key=None,
        hops=1,
        retransmit_count=1,
        retransmit_delay=0.01,
        promote_qos=False,
        replay_window=0,
    )
    defaults.update(overrides)
    return MpubsubConfig(**defaults)


def _sender() -> socket.socket:
    # No IPV6_MULTICAST_IF: the kernel picks the egress interface from the
    # routing table, same as tests/probe.py.
    sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
    sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 1)
    return sock


def send_wire(topic: str, wire: bytes, port: int) -> None:
    """Multicast pre-encoded bytes at a topic's group."""
    sock = _sender()
    try:
        sock.sendto(wire, (str(topic_to_group(topic, SCOPE_LINK_LOCAL)), port))
    finally:
        sock.close()


def send_raw(topic: str, payload: bytes, port: int, **encode_kwargs) -> None:
    """Encode with the reference and multicast one datagram."""
    send_wire(topic, encode(topic, payload, **encode_kwargs), port)


class Sniffer:
    """A bare socket joined to a topic's group, for observing publishes."""

    def __init__(self, topic: str, port: int) -> None:
        self.sock = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("::", port))
        self.sock.setsockopt(
            socket.IPPROTO_IPV6,
            socket.IPV6_JOIN_GROUP,
            topic_to_group(topic, SCOPE_LINK_LOCAL).packed
            + struct.pack("@I", IFINDEX_KERNEL_PICKS),
        )
        self.sock.setblocking(False)

    def close(self) -> None:
        self.sock.close()

    async def collect(self, seconds: float = 0.3) -> list[bytes]:
        """Drain everything that arrives within `seconds`."""
        loop = asyncio.get_running_loop()
        out: list[bytes] = []
        end = loop.time() + seconds
        while loop.time() < end:
            try:
                out.append(self.sock.recv(2048))
            except BlockingIOError:
                await asyncio.sleep(0.005)
        return out


async def wait_for(received: list, count: int = 1, timeout: float = 2.0) -> None:
    loop = asyncio.get_running_loop()
    end = loop.time() + timeout
    while len(received) < count and loop.time() < end:
        await asyncio.sleep(0.01)
