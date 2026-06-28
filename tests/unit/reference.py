"""Python reference implementation of the mpubsub wire protocol.

This is the source of truth that the C++ implementation in
``components/mpubsub/`` must match byte-for-byte. It is intentionally
free of any ESPHome dependency so it can also be used by:

  * standalone bridges (e.g. an MQTT <-> multicast pub/sub gateway)
  * the wire-format unit tests (``tests/unit/test_wire_format.py``)
  * the probe / smoke-test tool (``tests/probe.py``)
"""

from __future__ import annotations

import collections
import hashlib
import ipaddress
import os
import struct
import time
import zlib
from dataclasses import dataclass
from typing import NamedTuple

MAGIC = b"MP"
VERSION = 0x01
HEADER_LEN = 12
MAX_DATAGRAM = 1232  # IPv6 min MTU (1280, RFC 8200 §5) - 40 (IPv6) - 8 (UDP)
MAX_PAYLOAD = MAX_DATAGRAM - HEADER_LEN  # = 1220

# Body-encoding enum -- one of these goes in header byte 3.
ENCODING_RAW = 0x00
ENCODING_PROTOBUF = 0x01
KNOWN_ENCODINGS = (ENCODING_RAW, ENCODING_PROTOBUF)
# Values 0x02..0xFF are reserved; receivers MUST drop unknown encodings.

# Encryption mode enum -- one of these goes in header byte 10.
ENC_MODE_NONE = 0x00
ENC_MODE_XXTEA = 0x01
KNOWN_ENC_MODES = (ENC_MODE_NONE, ENC_MODE_XXTEA)

SCOPE_LINK_LOCAL = 0x2
SCOPE_SITE_LOCAL = 0x5
SCOPE_ORG_LOCAL = 0x8
VALID_SCOPES = (SCOPE_LINK_LOCAL, SCOPE_SITE_LOCAL, SCOPE_ORG_LOCAL)

DEFAULT_PORT = 18512


def topic_to_group(topic: str, scope: int = SCOPE_LINK_LOCAL) -> ipaddress.IPv6Address:
    """Map a topic string to an IPv6 multicast address.

    The 128-bit address layout is::

        byte 0      : 0xFF                         (multicast prefix)
        byte 1 hi   : 0x1                          (T=1, transient)
        byte 1 lo   : scope nibble (0x2/0x5/0x8)
        bytes 2..15 : SHA-256(utf8 topic)[0..14]   (112-bit topic hash)
    """
    if scope not in VALID_SCOPES:
        raise ValueError(f"Invalid scope nibble {scope:#x}")
    digest = hashlib.sha256(topic.encode("utf-8")).digest()[:14]
    first = 0xFF
    second = (0x1 << 4) | (scope & 0xF)
    return ipaddress.IPv6Address(bytes((first, second)) + digest)


def topic_crc32(topic: str) -> int:
    """CRC-32/IEEE-802.3 of the UTF-8 topic, identical to ``esphome::crc32``."""
    return zlib.crc32(topic.encode("utf-8")) & 0xFFFFFFFF


# ----------------------------------------------------------------------------
# XXTEA-256
#
# Block-cipher operating in place on a vector of uint32_t words. Byte-for-byte
# compatible with ``esphome::xxtea`` (which packet_transport reuses and which
# devices actually run on the wire): 256-bit key = 8 uint32 words, key index
# ``k[(p ^ e) & 7]`` with ``e = sum >> 2`` (NOT the 128-bit-style
# ``k[(p & 3) ^ e]``). The C++ implementation is authoritative here -- the
# bridge must match it to interoperate with devices.
# ----------------------------------------------------------------------------

_DELTA = 0x9E3779B9


def _xxtea_mx(z: int, y: int, sum_: int, p: int, e: int, k: list[int]) -> int:
    return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (k[(p ^ e) & 7] ^ z))) & 0xFFFFFFFF


def xxtea_encrypt(words: list[int], key: list[int]) -> None:
    """In-place XXTEA encrypt of ``words`` (uint32 list) under ``key`` (8 uint32s)."""
    n = len(words)
    if n < 2:
        raise ValueError("XXTEA requires at least 2 words")
    rounds = 6 + 52 // n
    sum_ = 0
    z = words[n - 1]
    for _ in range(rounds):
        sum_ = (sum_ + _DELTA) & 0xFFFFFFFF
        e = sum_ >> 2
        for p in range(n - 1):
            y = words[p + 1]
            words[p] = (words[p] + _xxtea_mx(z, y, sum_, p, e, key)) & 0xFFFFFFFF
            z = words[p]
        y = words[0]
        words[n - 1] = (words[n - 1] + _xxtea_mx(z, y, sum_, n - 1, e, key)) & 0xFFFFFFFF
        z = words[n - 1]


def xxtea_decrypt(words: list[int], key: list[int]) -> None:
    """In-place XXTEA decrypt of ``words`` under ``key``."""
    n = len(words)
    if n < 2:
        raise ValueError("XXTEA requires at least 2 words")
    rounds = 6 + 52 // n
    sum_ = (rounds * _DELTA) & 0xFFFFFFFF
    y = words[0]
    for _ in range(rounds):
        e = sum_ >> 2
        for p in range(n - 1, 0, -1):
            z = words[p - 1]
            words[p] = (words[p] - _xxtea_mx(z, y, sum_, p, e, key)) & 0xFFFFFFFF
            y = words[p]
        z = words[n - 1]
        words[0] = (words[0] - _xxtea_mx(z, y, sum_, 0, e, key)) & 0xFFFFFFFF
        y = words[0]
        sum_ = (sum_ - _DELTA) & 0xFFFFFFFF


def derive_key(passphrase: str) -> bytes:
    """Hash a user passphrase to the 32-byte XXTEA-256 key.

    Matches ``hashlib.sha256(passphrase).digest()`` -- the same key
    derivation packet_transport uses for its ``encryption.key`` option.
    """
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def _bytes_to_words(b: bytes) -> list[int]:
    if len(b) % 4 != 0:
        raise ValueError(f"length {len(b)} is not a multiple of 4")
    return list(struct.unpack(f"<{len(b) // 4}I", b))


def _words_to_bytes(words: list[int]) -> bytes:
    return struct.pack(f"<{len(words)}I", *words)


# Fixed prefix carried at the start of every XXTEA plaintext, ahead of the
# user payload:
#   [ TOPIC_CRC32 LE (4) ][ TIMESTAMP LE (4) ][ NONCE LE (4) ]
# TIMESTAMP is unix epoch seconds (0 = the sender had no synchronized clock);
# NONCE is 4 random bytes per message. Together they give the receiver a
# freshness reference (the clock) and a per-message identity (the nonce) for
# replay rejection -- see ReplayGuard. The CRC stays the integrity tag.
XXTEA_PREFIX_LEN = 12


def xxtea_ciphertext_len(plaintext_len: int) -> int:
    """Length of the ciphertext for an mpubsub payload of ``plaintext_len`` bytes.

    The plaintext is ``[crc32 || timestamp || nonce] (12 bytes) || payload``,
    zero-padded up to a multiple of 4 bytes (XXTEA word size). The 12-byte
    prefix already exceeds XXTEA's 2-word (8-byte) minimum, so no separate
    floor is needed.
    """
    needed = plaintext_len + XXTEA_PREFIX_LEN
    return (needed + 3) & ~3


@dataclass(frozen=True)
class Message:
    topic: str
    payload: bytes
    encoding: int = ENCODING_RAW


def encode(
    topic: str,
    payload: bytes,
    encoding: int = ENCODING_RAW,
    *,
    key: bytes | None = None,
    timestamp: int | None = None,
    nonce: int | None = None,
) -> bytes:
    """Serialize a publication to the on-wire byte sequence.

    Raises ``ValueError`` if the payload exceeds :data:`MAX_PAYLOAD`, the
    encoding value is unknown, or (when ``key`` is set) the encrypted
    datagram would exceed :data:`MAX_DATAGRAM`.

    When ``key`` is set, the body is XXTEA-256 ciphertext over
    ``[crc32 || timestamp || nonce] || payload || zero pad`` (see
    :data:`XXTEA_PREFIX_LEN`). The cleartext header's TOPIC_CRC32 field is
    set to zero; the real CRC32 is the first 4 bytes of the decrypted
    plaintext.

    ``timestamp`` (unix epoch seconds) and ``nonce`` (a 32-bit value) feed
    the receiver's replay rejection. They default to the current wall clock
    and a fresh random value; pass them explicitly for deterministic
    encodings (known-answer vectors). ``timestamp=0`` marks "the sender had
    no synchronized clock" and is rejected by a replay-checking receiver.
    """
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload too large ({len(payload)} > {MAX_PAYLOAD})")
    if encoding not in KNOWN_ENCODINGS:
        raise ValueError(f"unknown encoding: {encoding:#04x}")
    crc = topic_crc32(topic)
    if key is None:
        enc_mode = ENC_MODE_NONE
        header_crc = crc
        body = payload
    else:
        if len(key) != 32:
            raise ValueError(f"key must be 32 bytes, got {len(key)}")
        if timestamp is None:
            timestamp = int(time.time())
        if nonce is None:
            nonce = int.from_bytes(os.urandom(4), "little")
        clen = xxtea_ciphertext_len(len(payload))
        if HEADER_LEN + clen > MAX_DATAGRAM:
            raise ValueError(
                f"encrypted payload too large ({len(payload)} -> {clen}-byte ciphertext)"
            )
        prefix = struct.pack("<III", crc, timestamp & 0xFFFFFFFF, nonce & 0xFFFFFFFF)
        plaintext = prefix + payload + b"\x00" * (clen - XXTEA_PREFIX_LEN - len(payload))
        words = _bytes_to_words(plaintext)
        xxtea_encrypt(words, _bytes_to_words(key))
        body = _words_to_bytes(words)
        enc_mode = ENC_MODE_XXTEA
        header_crc = 0
    # 12-byte header: MAGIC(2) VER(1) ENC(1) CRC(4 LE) PAYLOAD_LEN(2 LE) ENM(1) RSV(1)
    header = (
        MAGIC
        + bytes((VERSION, encoding & 0xFF))
        + struct.pack("<IH", header_crc, len(payload))
        + bytes((enc_mode, 0))
    )
    assert len(header) == HEADER_LEN
    return header + body


class WireError(ValueError):
    """Raised by :func:`decode` when a packet violates the spec."""


class DecodedMessage(NamedTuple):
    """Result of :func:`decode`.

    ``timestamp`` and ``nonce`` are populated only for encrypted packets
    (``was_encrypted=True``); they are ``None`` for plaintext. A replay-aware
    receiver feeds them to :class:`ReplayGuard`. The first three fields keep
    the historical ``(topic_crc, encoding, payload)`` order so callers that
    only care about those can unpack ``crc, encoding, body, *_``.
    """

    topic_crc: int
    encoding: int
    payload: bytes
    timestamp: int | None = None
    nonce: int | None = None
    was_encrypted: bool = False


def decode(data: bytes, *, key: bytes | None = None) -> DecodedMessage:
    """Parse a datagram into a :class:`DecodedMessage`.

    For encrypted packets the caller MUST supply ``key`` (the 32-byte
    XXTEA-256 key); the returned ``topic_crc`` is recovered from the
    decrypted plaintext, ``payload`` is the decrypted slice, and
    ``timestamp`` / ``nonce`` carry the replay fields.

    Raises :class:`WireError` if any validation rule fails or if an
    encrypted packet arrives with ``key=None``. The caller is expected to
    match ``topic_crc`` against the subscriptions on this node.
    """
    if len(data) < HEADER_LEN:
        raise WireError(f"datagram too short ({len(data)} < {HEADER_LEN})")
    if data[0:2] != MAGIC:
        raise WireError(f"bad magic {data[0:2]!r}")
    version = data[2]
    if version != VERSION:
        raise WireError(f"unsupported version {version}")
    encoding = data[3]
    if encoding not in KNOWN_ENCODINGS:
        raise WireError(f"unknown encoding: {encoding:#04x}")
    enc_mode = data[10]
    if enc_mode not in KNOWN_ENC_MODES:
        raise WireError(f"unknown enc_mode: {enc_mode:#04x}")
    header_crc, payload_len = struct.unpack("<IH", data[4:10])
    # byte 11 is reserved; ignored on decode for forward-compatibility.
    if enc_mode == ENC_MODE_XXTEA:
        expected = HEADER_LEN + xxtea_ciphertext_len(payload_len)
        if len(data) != expected:
            raise WireError(
                f"encrypted length mismatch: header says {payload_len} -> "
                f"{expected - HEADER_LEN}-byte ciphertext, datagram has "
                f"{len(data) - HEADER_LEN}"
            )
        if key is None:
            raise WireError("encrypted packet but no key supplied")
        if len(key) != 32:
            raise ValueError(f"key must be 32 bytes, got {len(key)}")
        words = _bytes_to_words(data[HEADER_LEN:])
        xxtea_decrypt(words, _bytes_to_words(key))
        plaintext = _words_to_bytes(words)
        crc, ts, nonce = struct.unpack("<III", plaintext[0:XXTEA_PREFIX_LEN])
        body = plaintext[XXTEA_PREFIX_LEN : XXTEA_PREFIX_LEN + payload_len]
        return DecodedMessage(crc, encoding, body, ts, nonce, was_encrypted=True)
    # Plaintext path
    if HEADER_LEN + payload_len != len(data):
        raise WireError(
            f"length mismatch: header says {payload_len}, datagram has "
            f"{len(data) - HEADER_LEN}"
        )
    return DecodedMessage(header_crc, encoding, data[HEADER_LEN:])


# ----------------------------------------------------------------------------
# Replay rejection (Option B)
#
# A captured encrypted datagram is byte-identical no matter when it is
# resent, so anyone off the segment can replay it. The defense is two-layer
# and needs no persistent state -- it survives a reboot because the freshness
# reference is the externally-synced wall clock, not a stored counter:
#
#   1. Freshness window. The sender stamps each packet with the current unix
#      time inside the ciphertext (an attacker without the key can't move it
#      without breaking the CRC). The receiver drops anything more than
#      `window` seconds from its own clock.
#
#   2. Nonce de-duplication. Within the window an attacker could still resend
#      a verbatim copy, so the receiver remembers the per-message nonces it
#      has seen in the last `window` seconds and drops repeats. The cache is
#      bounded and may be empty after a reboot -- harmless, because layer 1
#      already rejects anything older than the window.
#
# Legitimate retransmits (retransmit_count > 1) reuse the same nonce, so
# de-dup collapses them to a single delivery; two genuinely distinct
# publications carry different nonces even if their payloads are identical.
# ----------------------------------------------------------------------------


class ReplayGuard:
    """Receiver-side freshness window + bounded nonce de-dup cache.

    Mirrors ``components/mpubsub/replay_guard.h`` (C++) and the Go bridge's
    ``replayGuard`` so all three agree on accept/reject for any
    ``(now, timestamp, nonce)``.
    """

    def __init__(self, window_seconds: int, max_entries: int = 128) -> None:
        self.window = window_seconds
        self.max_entries = max_entries
        self._order: collections.deque[tuple[int, int]] = collections.deque()
        self._seen: dict[int, int] = {}

    def accept(
        self, now: int, now_valid: bool, timestamp: int | None, nonce: int | None
    ) -> bool:
        """Return True if a packet stamped ``timestamp``/``nonce`` is fresh
        and unseen, recording it. Return False (drop) otherwise.

        ``window == 0`` disables protection (always accept). When protection
        is on the guard fails closed: an unsynced local clock
        (``now_valid=False``) or a packet with ``timestamp==0`` (sender had
        no clock) is rejected.
        """
        if self.window == 0:
            return True
        if not now_valid:
            return False
        if not timestamp:  # 0 or None -> unverifiable
            return False
        if abs(now - timestamp) > self.window:
            return False
        self._prune(now)
        if nonce in self._seen:
            return False
        self._seen[nonce] = timestamp
        self._order.append((nonce, timestamp))
        if len(self._order) > self.max_entries:
            old_nonce, _ = self._order.popleft()
            self._seen.pop(old_nonce, None)
        return True

    def _prune(self, now: int) -> None:
        cutoff = now - self.window
        while self._order and self._order[0][1] < cutoff:
            old_nonce, _ = self._order.popleft()
            self._seen.pop(old_nonce, None)
