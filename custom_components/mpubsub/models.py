"""Shared types for the mpubsub integration."""

from __future__ import annotations

from collections.abc import Callable, Coroutine
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any

from .reference import ENCODING_RAW

if TYPE_CHECKING:
    from .client import MpubsubClient

PublishPayloadType = str | bytes | int | float | None
ReceivePayloadType = str | bytes

MessageCallbackType = Callable[["ReceiveMessage"], Coroutine[Any, Any, None] | None]


@dataclass(slots=True, frozen=True)
class ReceiveMessage:
    """A received mpubsub message.

    The first six fields are homeassistant.components.mqtt.ReceiveMessage's,
    in its order and with its types, so a callback or template lifted from an
    MQTT setup keeps working. Three of them are constants here rather than
    wire data, which is the honest shape of the difference:

    * ``qos`` and ``retain`` have no wire field at all -- mpubsub is
      fire-and-forget UDP multicast with no broker to store anything.
    * ``subscribed_topic`` always equals ``topic``. In MQTT the two differ
      exactly when a wildcard subscription matched; this integration rejects
      wildcards (see util.validate_topic), so they cannot diverge.

    The mpubsub-only fields are appended with defaults so positional
    construction against the MQTT shape still works.
    """

    topic: str
    payload: ReceivePayloadType
    qos: int
    retain: bool
    subscribed_topic: str
    timestamp: float

    # --- No MQTT equivalent ---
    #: The packet arrived ChaCha20-Poly1305-sealed and authenticated.
    was_encrypted: bool = False
    #: The wire ENCODING byte (reference.ENCODING_RAW / ENCODING_PROTOBUF).
    #: Distinct from the ``encoding`` argument to async_subscribe, which is
    #: the *text codec* used to decode ``payload``.
    wire_encoding: int = ENCODING_RAW
    #: Unix seconds the sender stamped inside the ciphertext, or None for a
    #: plaintext packet (which carries no timestamp).
    sender_timestamp: int | None = None


@dataclass
class MpubsubData:
    """What the integration keeps in ``hass.data[DOMAIN]``."""

    client: MpubsubClient
    #: Entity config from the ``mpubsub:`` YAML block, stashed by
    #: async_setup and consumed by each platform's async_setup_entry.
    config: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class MpubsubConfig:
    """Resolved connection + tuning options for one fabric.

    Flattened out of the config entry so MpubsubClient can be constructed in
    a test without a ConfigEntry.
    """

    port: int
    scope: int
    """The scope *nibble* (reference.SCOPE_LINK_LOCAL etc.), not the name."""
    interface: str | None
    key: bytes | None
    """32-byte ChaCha20-Poly1305 key (reference.derive_key), or None."""
    hops: int
    retransmit_count: int
    retransmit_delay: float
    promote_qos: bool
    replay_window: int
