"""mpubsub for Home Assistant -- brokerless IPv6-multicast pub/sub.

Mirrors the API of the built-in ``mqtt`` integration where the semantics
exist, and diverges loudly where they don't. See docs/HOMEASSISTANT.md for
the full caveat table; the short version is that mpubsub has no broker, no
retain, no QoS, no last will, and no wildcards, because the wire carries a
topic CRC32 rather than the topic string.
"""

from __future__ import annotations

__all__: list[str] = []
