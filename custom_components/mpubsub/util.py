"""Validation for the things a user can type: topics and text codecs.

The topic rules are ported from ``components/mpubsub/__init__.py``
``_topic_validator`` so the ESPHome side and this one accept and reject
exactly the same strings, with one deliberate addition: wildcards. See
:func:`validate_topic`.
"""

from __future__ import annotations

import codecs

import voluptuous as vol

from .const import MAX_TOPIC_BYTES, WILDCARD_CHARS


class TopicError(ValueError):
    """A topic string this integration will not accept."""


def validate_topic(topic: str) -> str:
    """Return ``topic`` if it is usable, else raise :class:`TopicError`.

    The length/NUL/emptiness rules are the ESPHome component's, verbatim.

    The wildcard rule is *not*: mpubsub topics may legally contain ``+`` and
    ``#`` (the ESPHome validator says so outright -- "We do not enforce
    MQTT-style wildcards, that's an application choice"), and this rejects
    them anyway. Two facts force it. The wire carries a CRC32 of the topic,
    never the topic itself, and subscribing means joining the multicast group
    derived from SHA-256 of the exact topic string -- so there is nothing to
    pattern-match against and no group to join for a pattern. And a caller
    writing against the mqtt API who passes "home/+/temp" means a wildcard.
    Accepting it as a literal would hand them a subscription that is silently
    never going to fire, which is strictly worse than an error. The cost is
    that a literal mpubsub topic containing + or # is unreachable from Home
    Assistant; that is documented in docs/HOMEASSISTANT.md.
    """
    if not isinstance(topic, str):
        raise TopicError(f"topic must be a string, got {type(topic).__name__}")
    for char in WILDCARD_CHARS:
        if char in topic:
            raise TopicError(
                f"topic {topic!r} contains the MQTT wildcard {char!r}, which "
                f"mpubsub cannot support: the wire carries only a CRC32 of the "
                f"topic, and receiving requires joining the multicast group "
                f"derived from the exact topic string, so there is no way to "
                f"match a pattern. Subscribe to each topic individually. (If "
                f"you meant {char!r} literally, mpubsub allows it but this "
                f"integration does not -- see docs/HOMEASSISTANT.md.)"
            )
    if "\x00" in topic:
        raise TopicError("topic must not contain NUL bytes")
    encoded = topic.encode("utf-8")
    if len(encoded) == 0:
        raise TopicError("topic must not be empty")
    if len(encoded) > MAX_TOPIC_BYTES:
        raise TopicError(
            f"topic too long: {len(encoded)} bytes (limit {MAX_TOPIC_BYTES})"
        )
    return topic


def valid_topic(value: str) -> str:
    """voluptuous wrapper for :func:`validate_topic` (config schemas)."""
    try:
        return validate_topic(value)
    except TopicError as err:
        raise vol.Invalid(str(err)) from err


def valid_encoding(value: str | None) -> str | None:
    """Validate a text codec name at config time.

    ``encoding`` reaches ``bytes.decode()`` on the receive path, where an
    unknown codec raises LookupError -- not UnicodeDecodeError -- once per
    arriving packet, forever. Catching that at the schema turns a typo into
    one error on the config you just wrote, rather than a stream of
    exceptions on the event loop with no obvious cause.

    ``None`` is valid and means "don't decode; give me bytes".
    """
    if value is None:
        return None
    if not isinstance(value, str):
        raise vol.Invalid(f"encoding must be a string, got {type(value).__name__}")
    try:
        codecs.lookup(value)
    except LookupError as err:
        raise vol.Invalid(
            f"unknown text encoding {value!r}: {err}. Use a Python codec name "
            f"such as 'utf-8', or leave it unset for raw bytes."
        ) from err
    return value
