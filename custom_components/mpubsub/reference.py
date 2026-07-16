"""Python reference implementation of the mpubsub wire protocol.

This is the source of truth that the C++ implementation in
``components/mpubsub/`` must match byte-for-byte. It is intentionally
free of any *required* third-party dependency so it can also be used by:

  * standalone bridges (e.g. an MQTT <-> multicast pub/sub gateway)
  * the wire-format unit tests (``tests/unit/test_wire_format.py``)
  * the probe / smoke-test tool (``tests/probe.py``)
  * the Home Assistant component (``custom_components/mpubsub/``, which
    vendors a byte-identical copy of this file)

``cryptography``, if importable, is used to accelerate the AEAD; see
:func:`aead_encrypt`. Everything still works without it.
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

try:
    # Optional accelerator. The pure-Python ChaCha20-Poly1305 below is a
    # readable spec, not a fast one (~1 ms per 1220-byte packet), which
    # matters when the caller decrypts on an event loop. When cryptography
    # is importable we hand the AEAD to its C implementation instead; the
    # two are asserted byte-identical by test_encryption.py.
    from cryptography.exceptions import InvalidTag as _InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import (
        ChaCha20Poly1305 as _FastAEAD,
    )
except ImportError:  # pragma: no cover - exercised by forcing the pure path
    _FastAEAD = None
    _InvalidTag = None

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
ENC_MODE_AEAD = 0x01  # ChaCha20-Poly1305 (RFC 8439)
KNOWN_ENC_MODES = (ENC_MODE_NONE, ENC_MODE_AEAD)

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
# ChaCha20-Poly1305 AEAD (RFC 8439)
#
# A vetted authenticated cipher: confidentiality from ChaCha20 plus a real
# 128-bit Poly1305 tag (a forgery is ~2^-128, vs the 32-bit topic-CRC "tag"
# the XXTEA scheme leaned on). ChaCha20 is a stream cipher, so the ciphertext
# is exactly the plaintext length -- no block padding. Verified against the
# RFC 8439 §2.8.2 test vector by test_encryption.py. 256-bit key.
# ----------------------------------------------------------------------------

AEAD_KEY_LEN = 32
AEAD_NONCE_LEN = 12  # 96-bit ChaCha20 nonce, one per message
AEAD_TAG_LEN = 16  # Poly1305 tag
# Bytes prepended to the *plaintext* (encrypted + authenticated), ahead of the
# user payload: TOPIC_CRC32 (4) for dispatch + TIMESTAMP (4) for the freshness
# check. Both stay confidential (encrypted) and tamper-proof (under the tag).
AEAD_PREFIX_LEN = 8


def _rotl32(x: int, n: int) -> int:
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def _chacha_qr(s: list[int], a: int, b: int, c: int, d: int) -> None:
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 16)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 12)
    s[a] = (s[a] + s[b]) & 0xFFFFFFFF
    s[d] = _rotl32(s[d] ^ s[a], 8)
    s[c] = (s[c] + s[d]) & 0xFFFFFFFF
    s[b] = _rotl32(s[b] ^ s[c], 7)


def _chacha_block(key: bytes, counter: int, nonce: bytes) -> bytes:
    const = [0x61707865, 0x3320646E, 0x79622D32, 0x6B206574]
    state = const + list(struct.unpack("<8I", key)) + [counter & 0xFFFFFFFF] + list(struct.unpack("<3I", nonce))
    w = list(state)
    for _ in range(10):  # 20 rounds = 10 column + 10 diagonal pairs
        _chacha_qr(w, 0, 4, 8, 12)
        _chacha_qr(w, 1, 5, 9, 13)
        _chacha_qr(w, 2, 6, 10, 14)
        _chacha_qr(w, 3, 7, 11, 15)
        _chacha_qr(w, 0, 5, 10, 15)
        _chacha_qr(w, 1, 6, 11, 12)
        _chacha_qr(w, 2, 7, 8, 13)
        _chacha_qr(w, 3, 4, 9, 14)
    return struct.pack("<16I", *[(w[i] + state[i]) & 0xFFFFFFFF for i in range(16)])


def chacha20(key: bytes, counter: int, nonce: bytes, data: bytes) -> bytes:
    """ChaCha20 keystream XOR of ``data`` (RFC 8439 §2.4)."""
    out = bytearray()
    for i in range(0, len(data), 64):
        ks = _chacha_block(key, counter + i // 64, nonce)
        out += bytes(b ^ ks[j] for j, b in enumerate(data[i : i + 64]))
    return bytes(out)


def _poly1305(otk: bytes, msg: bytes) -> bytes:
    r = int.from_bytes(otk[0:16], "little") & 0x0FFFFFFC0FFFFFFC0FFFFFFC0FFFFFFF
    s = int.from_bytes(otk[16:32], "little")
    acc = 0
    p = (1 << 130) - 5
    for i in range(0, len(msg), 16):
        blk = msg[i : i + 16]
        n = int.from_bytes(blk + b"\x01", "little")  # append the high "1" bit
        acc = ((acc + n) * r) % p
    return ((acc + s) & ((1 << 128) - 1)).to_bytes(16, "little")


def _pad16(b: bytes) -> bytes:
    return b"\x00" * ((16 - len(b) % 16) % 16)


def _poly1305_key(key: bytes, nonce: bytes) -> bytes:
    return _chacha_block(key, 0, nonce)[:32]


def _aead_encrypt_py(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    otk = _poly1305_key(key, nonce)
    ct = chacha20(key, 1, nonce, plaintext)
    mac_data = aad + _pad16(aad) + ct + _pad16(ct) + struct.pack("<QQ", len(aad), len(ct))
    return ct, _poly1305(otk, mac_data)


def _aead_decrypt_py(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    otk = _poly1305_key(key, nonce)
    mac_data = aad + _pad16(aad) + ciphertext + _pad16(ciphertext) + struct.pack("<QQ", len(aad), len(ciphertext))
    expected = _poly1305(otk, mac_data)
    # Constant-time-ish compare; the reference isn't a hardening target but
    # this keeps the intent clear.
    if not _ct_eq(expected, tag):
        raise WireError("AEAD authentication failed (wrong key or tampered packet)")
    return chacha20(key, 1, nonce, ciphertext)


# The two public AEAD entry points dispatch on ``_FastAEAD`` at *call* time,
# not import time, so a test can force the pure path with
# ``monkeypatch.setattr(reference, "_FastAEAD", None)``. Both paths are
# RFC 8439 §2.8 and produce identical bytes -- test_encryption.py runs the
# whole encryption suite twice to keep that true.


def aead_encrypt(key: bytes, nonce: bytes, plaintext: bytes, aad: bytes) -> tuple[bytes, bytes]:
    """ChaCha20-Poly1305 encrypt (RFC 8439 §2.8). Returns ``(ciphertext, tag)``."""
    if _FastAEAD is None:
        return _aead_encrypt_py(key, nonce, plaintext, aad)
    # cryptography returns ciphertext||tag; the wire format keeps them apart.
    sealed = _FastAEAD(key).encrypt(nonce, plaintext, aad)
    return sealed[:-AEAD_TAG_LEN], sealed[-AEAD_TAG_LEN:]


def aead_decrypt(key: bytes, nonce: bytes, ciphertext: bytes, tag: bytes, aad: bytes) -> bytes:
    """ChaCha20-Poly1305 decrypt + verify. Raises :class:`WireError` if the
    tag doesn't authenticate (wrong key, tampering, or truncation)."""
    if _FastAEAD is None:
        return _aead_decrypt_py(key, nonce, ciphertext, tag, aad)
    try:
        return _FastAEAD(key).decrypt(nonce, ciphertext + tag, aad)
    except _InvalidTag as err:
        # decode() promises WireError for an unauthentic packet; keep the
        # message identical to the pure path's.
        raise WireError("AEAD authentication failed (wrong key or tampered packet)") from err


def _ct_eq(a: bytes, b: bytes) -> bool:
    if len(a) != len(b):
        return False
    diff = 0
    for x, y in zip(a, b):
        diff |= x ^ y
    return diff == 0


def derive_key(passphrase: str) -> bytes:
    """Hash a user passphrase to the 32-byte AEAD key.

    Matches ``hashlib.sha256(passphrase).digest()`` -- the same key
    derivation packet_transport uses for its ``encryption.key`` option.
    """
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def aead_body_len(payload_len: int) -> int:
    """On-wire encrypted-body length for a payload of ``payload_len`` bytes:
    the 12-byte nonce, the ciphertext (8-byte prefix + payload, no padding),
    and the 16-byte tag."""
    return AEAD_NONCE_LEN + AEAD_PREFIX_LEN + payload_len + AEAD_TAG_LEN


@dataclass(frozen=True)
class Message:
    topic: str
    payload: bytes
    encoding: int = ENCODING_RAW


def _build_header(header_crc: int, encoding: int, payload_len: int, enc_mode: int) -> bytes:
    # 12-byte header: MAGIC(2) VER(1) ENC(1) CRC(4 LE) PAYLOAD_LEN(2 LE) ENM(1) RSV(1)
    header = MAGIC + bytes((VERSION, encoding & 0xFF)) + struct.pack("<IH", header_crc, payload_len) + bytes((enc_mode, 0))
    assert len(header) == HEADER_LEN
    return header


def encode(
    topic: str,
    payload: bytes,
    encoding: int = ENCODING_RAW,
    *,
    key: bytes | None = None,
    timestamp: int | None = None,
    nonce: bytes | None = None,
) -> bytes:
    """Serialize a publication to the on-wire byte sequence.

    Raises ``ValueError`` if the payload exceeds :data:`MAX_PAYLOAD`, the
    encoding value is unknown, or (when ``key`` is set) the encrypted
    datagram would exceed :data:`MAX_DATAGRAM`.

    When ``key`` is set, the body is ChaCha20-Poly1305:
    ``[AEAD_NONCE (12)] || ciphertext || [TAG (16)]`` where the ciphertext
    encrypts ``[TOPIC_CRC32 (4)] || [TIMESTAMP (4)] || payload`` and the
    12-byte cleartext header is the AAD. The cleartext header's TOPIC_CRC32
    field is set to zero (the real CRC is recovered from the decrypted
    plaintext) so the topic identity isn't leaked.

    ``timestamp`` (unix epoch seconds) feeds the receiver's freshness check
    and ``nonce`` (the 12-byte AEAD nonce) is its per-message identity for
    de-duplication. They default to the current wall clock and a fresh random
    nonce; pass them explicitly for deterministic encodings (known-answer
    vectors). ``timestamp=0`` marks "the sender had no synchronized clock"
    and is rejected by a replay-checking receiver.
    """
    if len(payload) > MAX_PAYLOAD:
        raise ValueError(f"payload too large ({len(payload)} > {MAX_PAYLOAD})")
    if encoding not in KNOWN_ENCODINGS:
        raise ValueError(f"unknown encoding: {encoding:#04x}")
    crc = topic_crc32(topic)
    if key is None:
        return _build_header(crc, encoding, len(payload), ENC_MODE_NONE) + payload
    if len(key) != 32:
        raise ValueError(f"key must be 32 bytes, got {len(key)}")
    if timestamp is None:
        timestamp = int(time.time())
    if nonce is None:
        nonce = os.urandom(AEAD_NONCE_LEN)
    if len(nonce) != AEAD_NONCE_LEN:
        raise ValueError(f"nonce must be {AEAD_NONCE_LEN} bytes, got {len(nonce)}")
    body_len = aead_body_len(len(payload))
    if HEADER_LEN + body_len > MAX_DATAGRAM:
        raise ValueError(f"encrypted payload too large ({len(payload)} -> {body_len}-byte body)")
    header = _build_header(0, encoding, len(payload), ENC_MODE_AEAD)
    plaintext = struct.pack("<II", crc, timestamp & 0xFFFFFFFF) + payload
    ct, tag = aead_encrypt(key, nonce, plaintext, aad=header)
    return header + nonce + ct + tag


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
    ChaCha20-Poly1305 key); the returned ``topic_crc`` is recovered from the
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
    if enc_mode == ENC_MODE_AEAD:
        expected = HEADER_LEN + aead_body_len(payload_len)
        if len(data) != expected:
            raise WireError(
                f"encrypted length mismatch: header says {payload_len} -> "
                f"{expected - HEADER_LEN}-byte body, datagram has "
                f"{len(data) - HEADER_LEN}"
            )
        if key is None:
            raise WireError("encrypted packet but no key supplied")
        if len(key) != 32:
            raise ValueError(f"key must be 32 bytes, got {len(key)}")
        aead_nonce = data[HEADER_LEN : HEADER_LEN + AEAD_NONCE_LEN]
        ct = data[HEADER_LEN + AEAD_NONCE_LEN : len(data) - AEAD_TAG_LEN]
        tag = data[len(data) - AEAD_TAG_LEN :]
        aad = data[0:HEADER_LEN]
        plaintext = aead_decrypt(key, aead_nonce, ct, tag, aad)  # raises on auth failure
        crc, ts = struct.unpack("<II", plaintext[0:AEAD_PREFIX_LEN])
        body = plaintext[AEAD_PREFIX_LEN:]
        # The replay de-dup key is the low 32 bits of the (random) AEAD nonce.
        nonce = int.from_bytes(aead_nonce[0:4], "little")
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
#      without breaking the AEAD tag). The receiver drops anything more than
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
