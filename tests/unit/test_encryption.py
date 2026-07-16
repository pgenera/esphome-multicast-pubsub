"""ChaCha20-Poly1305 AEAD payload encryption tests against the Python reference.

Every test here runs **twice**: once against the pure-Python AEAD and once
against the ``cryptography``-backed one (see the ``aead_backend`` fixture).
"""

from __future__ import annotations

import os
import random

import pytest

import reference
from reference import (
    AEAD_NONCE_LEN,
    ENC_MODE_AEAD,
    ENC_MODE_NONE,
    ENCODING_PROTOBUF,
    ENCODING_RAW,
    HEADER_LEN,
    MAX_DATAGRAM,
    WireError,
    aead_body_len,
    aead_decrypt,
    aead_encrypt,
    chacha20,
    decode,
    derive_key,
    encode,
    topic_crc32,
)

# A fixed 12-byte nonce for deterministic encodings in tests.
NONCE = bytes(range(12))

# Grabbed independently of reference._FastAEAD so the equivalence test below
# can reach the real class even while the fixture has blanked the dispatch.
try:
    from cryptography.hazmat.primitives.ciphers.aead import (
        ChaCha20Poly1305 as _REAL_FAST_AEAD,
    )
except ImportError:
    _REAL_FAST_AEAD = None


@pytest.fixture(autouse=True, params=["pure", "fast"])
def aead_backend(request, monkeypatch):
    """Run this whole module against both AEAD implementations.

    ``reference.aead_encrypt`` / ``aead_decrypt`` dispatch on
    ``reference._FastAEAD`` at call time. cryptography is usually installed,
    so the fast path is what runs by default -- which means the pure path has
    to be *forced* here, or it would silently stop being covered the moment
    the accelerator landed. The pure leg always runs (the fallback must work
    on a stdlib-only box); the fast leg skips when cryptography is absent.
    """
    if request.param == "pure":
        monkeypatch.setattr(reference, "_FastAEAD", None)
    elif reference._FastAEAD is None:
        pytest.skip("cryptography not installed; no fast AEAD path to exercise")
    return request.param


# --- The two backends are one cipher -----------------------------------------


def test_fast_and_pure_aead_agree_on_random_vectors() -> None:
    """The accelerator is only safe if it is byte-identical to the spec.

    Checks the pair directly rather than through the dispatch, so it holds
    regardless of which leg of ``aead_backend`` is running.
    """
    if _REAL_FAST_AEAD is None:
        pytest.skip("cryptography not installed")
    rnd = random.Random(0xC0FFEE)  # deterministic: a failure is reproducible
    for _ in range(100):
        key = bytes(rnd.getrandbits(8) for _ in range(32))
        nonce = bytes(rnd.getrandbits(8) for _ in range(12))
        pt = os.urandom(rnd.randrange(0, 300))
        aad = os.urandom(rnd.randrange(0, 40))

        ct_py, tag_py = reference._aead_encrypt_py(key, nonce, pt, aad)
        sealed = _REAL_FAST_AEAD(key).encrypt(nonce, pt, aad)
        assert ct_py + tag_py == sealed, "fast AEAD disagrees with the reference"

        # ...and each can open what the other sealed.
        assert reference._aead_decrypt_py(key, nonce, sealed[:-16], sealed[-16:], aad) == pt
        assert _REAL_FAST_AEAD(key).decrypt(nonce, ct_py + tag_py, aad) == pt


def test_fast_path_raises_wire_error_on_bad_tag(monkeypatch) -> None:
    """decode()'s contract is WireError, but cryptography raises InvalidTag.
    The translation is easy to lose in a refactor, so pin it."""
    if _REAL_FAST_AEAD is None:
        pytest.skip("cryptography not installed")
    monkeypatch.setattr(reference, "_FastAEAD", _REAL_FAST_AEAD)  # undo a "pure" leg
    key = derive_key("k")
    ct, tag = aead_encrypt(key, NONCE, b"hello", b"aad")
    bad = bytes([tag[0] ^ 0x01]) + tag[1:]
    with pytest.raises(WireError, match="authentication failed"):
        aead_decrypt(key, NONCE, ct, bad, b"aad")


# --- AEAD primitive (RFC 8439 known-answer vectors) --------------------------


def test_chacha20_keystream_rfc8439() -> None:
    """RFC 8439 §2.4.2 keystream vector."""
    key = bytes(range(32))
    nonce = bytes.fromhex("000000000000004a00000000")
    ks = chacha20(key, 1, nonce, b"\x00" * 64)
    assert ks[:16].hex() == "224f51f3401bd9e12fde276fb8631ded"


def test_aead_encrypt_rfc8439() -> None:
    """RFC 8439 §2.8.2 AEAD vector -- locks the primitive to the standard so
    the C++ and Go ports can be checked against the same numbers."""
    key = bytes(range(0x80, 0xA0))
    nonce = bytes.fromhex("070000004041424344454647")
    aad = bytes.fromhex("50515253c0c1c2c3c4c5c6c7")
    pt = (
        b"Ladies and Gentlemen of the class of '99: If I could offer you "
        b"only one tip for the future, sunscreen would be it."
    )
    ct, tag = aead_encrypt(key, nonce, pt, aad)
    assert ct.hex().startswith("d31a8d34648e60db7b86afbc53ef7ec2")
    assert tag.hex() == "1ae10b594f09e26a7e902ecbd0600691"


def test_aead_roundtrip_and_auth() -> None:
    key = derive_key("k")
    ct, tag = aead_encrypt(key, NONCE, b"hello", b"aad")
    assert aead_decrypt(key, NONCE, ct, tag, b"aad") == b"hello"
    # A flipped ciphertext byte fails authentication.
    bad = bytearray(ct)
    bad[0] ^= 0x01
    with pytest.raises(WireError, match="authentication failed"):
        aead_decrypt(key, NONCE, bytes(bad), tag, b"aad")


# --- Body length math --------------------------------------------------------


@pytest.mark.parametrize(
    "payload_len,expected",
    [
        (0, 36),    # 12 nonce + 8 prefix + 0 + 16 tag
        (1, 37),
        (5, 41),
        (100, 136),
    ],
)
def test_aead_body_len(payload_len: int, expected: int) -> None:
    assert aead_body_len(payload_len) == expected


# --- End-to-end encode/decode -----------------------------------------------


def test_encrypted_roundtrip_raw() -> None:
    key = derive_key("hunter2")
    payload = b"hello world"
    pkt = encode("home/x", payload, encoding=ENCODING_RAW, key=key)
    crc, encoding, body, *_ = decode(pkt, key=key)
    assert crc == topic_crc32("home/x")
    assert encoding == ENCODING_RAW
    assert body == payload


def test_encrypted_roundtrip_protobuf() -> None:
    key = derive_key("topsecret")
    payload = bytes.fromhex("0d0000a8410d0000484200000000")
    pkt = encode("topic/y", payload, encoding=ENCODING_PROTOBUF, key=key)
    crc, encoding, body, *_ = decode(pkt, key=key)
    assert crc == topic_crc32("topic/y")
    assert encoding == ENCODING_PROTOBUF
    assert body == payload


def test_encrypted_empty_payload() -> None:
    """0-byte payloads still produce a valid 36-byte body (nonce + 8-byte
    prefix + 16-byte tag, no ciphertext padding -- ChaCha20 is a stream)."""
    key = derive_key("k")
    pkt = encode("t", b"", key=key)
    assert len(pkt) == HEADER_LEN + 36
    crc, encoding, body, *_ = decode(pkt, key=key)
    assert crc == topic_crc32("t")
    assert body == b""


def test_encrypted_header_has_zero_crc_field() -> None:
    """When encrypted, bytes 4-7 (header CRC field) must be zero on the wire
    so a passive observer can't fingerprint the topic."""
    key = derive_key("k")
    pkt = encode("home/leaky", b"x", key=key)
    assert pkt[4:8] == b"\x00\x00\x00\x00"


def test_encrypted_enc_mode_byte_is_aead() -> None:
    key = derive_key("k")
    pkt = encode("t", b"x", key=key)
    assert pkt[10] == ENC_MODE_AEAD


def test_encrypted_pay_len_is_plaintext_length() -> None:
    key = derive_key("k")
    payload = b"hello"  # 5 bytes -> 41-byte body
    pkt = encode("t", payload, key=key)
    pay_len = int.from_bytes(pkt[8:10], "little")
    assert pay_len == len(payload)
    assert len(pkt) == HEADER_LEN + aead_body_len(len(payload))


def test_wrong_key_fails_authentication() -> None:
    """Unlike the old 32-bit-CRC scheme, a wrong key fails the 128-bit
    Poly1305 tag outright -- decode raises rather than returning garbage."""
    key = derive_key("right")
    bad = derive_key("wrong")
    pkt = encode("home/x", b"sensitive", key=key)
    with pytest.raises(WireError, match="authentication failed"):
        decode(pkt, key=bad)


def test_decode_encrypted_without_key_raises() -> None:
    key = derive_key("k")
    pkt = encode("t", b"x", key=key)
    with pytest.raises(WireError, match="no key"):
        decode(pkt)


def test_unknown_enc_mode_rejected() -> None:
    pkt = bytearray(encode("t", b""))
    pkt[10] = 0x7F
    with pytest.raises(WireError, match="unknown enc_mode"):
        decode(bytes(pkt))


def test_encrypted_length_mismatch_rejected() -> None:
    key = derive_key("k")
    pkt = bytearray(encode("t", b"hello", key=key))
    pkt.append(0xAA)  # corrupt total length
    with pytest.raises(WireError, match="encrypted length mismatch"):
        decode(bytes(pkt), key=key)


def test_tamper_detected() -> None:
    """Flipping any body byte (nonce, ciphertext, or tag) fails the tag."""
    key = derive_key("k")
    pkt = bytearray(encode("home/x", b"value", key=key))
    pkt[-1] ^= 0x01  # last byte of the tag
    with pytest.raises(WireError, match="authentication failed"):
        decode(bytes(pkt), key=key)


def test_max_payload_under_encryption() -> None:
    """Largest payload that still fits the 1232-byte datagram cap when encrypted."""
    key = derive_key("k")
    # 12 nonce + 8 prefix + 1184 payload + 16 tag = 1220 body -> 1232 total.
    pkt = encode("t", b"x" * 1184, key=key)
    assert len(pkt) == MAX_DATAGRAM
    crc, _, body, *_ = decode(pkt, key=key)
    assert crc == topic_crc32("t")
    assert body == b"x" * 1184


def test_oversize_encrypted_payload_rejected() -> None:
    key = derive_key("k")
    with pytest.raises(ValueError, match="encrypted payload too large"):
        encode("t", b"x" * 1185, key=key)


def test_plaintext_decode_with_key_still_works() -> None:
    """Mixed-mode deployments: a plaintext packet decodes even when a key is
    set -- the decoder picks the path from the header's ENC_MODE byte."""
    key = derive_key("k")
    pkt = encode("t", b"plain", key=None)
    crc, _, body, *_ = decode(pkt, key=key)
    assert crc == topic_crc32("t")
    assert body == b"plain"
    assert pkt[10] == ENC_MODE_NONE


def test_encrypted_packet_is_not_decodable_as_plaintext() -> None:
    """An encrypted packet without a key is identified as encrypted and
    refused, not silently mis-parsed."""
    key = derive_key("k")
    pkt = encode("t", b"x" * 12, key=key)
    with pytest.raises(WireError):
        decode(pkt)


# --- Replay fields (timestamp + nonce) ---------------------------------------


def test_encrypted_timestamp_roundtrip() -> None:
    key = derive_key("k")
    pkt = encode("t", b"hi", key=key, timestamp=1_700_000_000, nonce=NONCE)
    msg = decode(pkt, key=key)
    assert msg.was_encrypted
    assert msg.timestamp == 1_700_000_000
    # The replay de-dup key is the low 32 bits of the AEAD nonce.
    assert msg.nonce == int.from_bytes(NONCE[0:4], "little")
    assert msg.payload == b"hi"


def test_default_nonce_makes_identical_payloads_distinct() -> None:
    key = derive_key("k")
    a = encode("t", b"same", key=key, timestamp=1_700_000_000)
    b = encode("t", b"same", key=key, timestamp=1_700_000_000)
    assert a != b  # random per-message nonce


def test_bad_nonce_length_rejected() -> None:
    key = derive_key("k")
    with pytest.raises(ValueError, match="nonce must be"):
        encode("t", b"x", key=key, timestamp=1, nonce=b"short")


def test_plaintext_has_no_replay_fields() -> None:
    msg = decode(encode("t", b"x"))
    assert msg.timestamp is None
    assert msg.nonce is None
    assert not msg.was_encrypted
