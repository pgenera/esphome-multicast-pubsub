"""Wire-format unit tests against the Python reference implementation."""

from __future__ import annotations

import pytest

from reference import (
    ENCODING_PROTOBUF,
    ENCODING_RAW,
    HEADER_LEN,
    MAGIC,
    MAX_PAYLOAD,
    VERSION,
    WireError,
    decode,
    encode,
    topic_crc32,
)


def test_header_is_exactly_twelve_bytes() -> None:
    pkt = encode("foo", b"")
    assert len(pkt) == HEADER_LEN


def test_header_layout() -> None:
    pkt = encode("hello", b"world")
    assert pkt[0:2] == MAGIC
    assert pkt[2] == VERSION
    assert pkt[3] == ENCODING_RAW
    crc = int.from_bytes(pkt[4:8], "little")
    assert crc == topic_crc32("hello")
    payload_len = int.from_bytes(pkt[8:10], "little")
    assert payload_len == 5
    assert pkt[10:12] == b"\x00\x00"
    assert pkt[12:] == b"world"


def test_roundtrip_raw() -> None:
    payload = b"\x01\x02\x03\xff\xfe"
    pkt = encode("topic/x", payload, encoding=ENCODING_RAW)
    crc, encoding, body, *_ = decode(pkt)
    assert crc == topic_crc32("topic/x")
    assert encoding == ENCODING_RAW
    assert body == payload


def test_roundtrip_protobuf() -> None:
    # Body bytes are whatever the encoder gave us; decode just unwraps the
    # 12-byte header. Real protobuf decode happens in a higher layer.
    payload = bytes.fromhex("0d0000a8410d0000484200000000")
    pkt = encode("topic/y", payload, encoding=ENCODING_PROTOBUF)
    crc, encoding, body, *_ = decode(pkt)
    assert crc == topic_crc32("topic/y")
    assert encoding == ENCODING_PROTOBUF
    assert body == payload


def test_max_payload() -> None:
    pkt = encode("t", b"x" * MAX_PAYLOAD)
    assert len(pkt) == HEADER_LEN + MAX_PAYLOAD
    decode(pkt)  # must not raise


def test_oversize_payload_rejected() -> None:
    with pytest.raises(ValueError, match="payload too large"):
        encode("t", b"x" * (MAX_PAYLOAD + 1))


def test_oversize_payload_rejected_far_above_limit() -> None:
    with pytest.raises(ValueError, match="payload too large"):
        encode("t", b"x" * 65535)


def test_unknown_encoding_rejected_in_encode() -> None:
    with pytest.raises(ValueError, match="unknown encoding"):
        encode("t", b"", encoding=0x02)


def test_unknown_encoding_rejected_in_decode() -> None:
    pkt = bytearray(encode("t", b""))
    pkt[3] = 0x7F  # any reserved value
    with pytest.raises(WireError, match="unknown encoding"):
        decode(bytes(pkt))


def test_short_datagram_rejected() -> None:
    with pytest.raises(WireError):
        decode(b"MP\x01\x00")


def test_bad_magic_rejected() -> None:
    pkt = bytearray(encode("t", b""))
    pkt[0] = ord("X")
    with pytest.raises(WireError, match="bad magic"):
        decode(bytes(pkt))


def test_bad_version_rejected() -> None:
    pkt = bytearray(encode("t", b""))
    pkt[2] = 99
    with pytest.raises(WireError, match="unsupported version"):
        decode(bytes(pkt))


def test_length_mismatch_rejected() -> None:
    pkt = bytearray(encode("t", b"hello"))
    # corrupt the payload length so the recorded value disagrees with reality
    pkt[8] = 99
    with pytest.raises(WireError, match="length mismatch"):
        decode(bytes(pkt))


def test_reserved_byte_11_ignored_on_decode() -> None:
    # Byte 10 is now ENC_MODE (no longer fully reserved); byte 11 still is.
    pkt = bytearray(encode("t", b"hi"))
    pkt[11] = 0xCD
    crc, encoding, body, *_ = decode(bytes(pkt))
    assert body == b"hi"
    assert encoding == ENCODING_RAW


def test_plaintext_enc_mode_byte_is_zero() -> None:
    pkt = encode("t", b"hi")
    assert pkt[10] == 0x00
