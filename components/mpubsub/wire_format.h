// Encoding and decoding of the on-wire packet format.
//
// Header (12 bytes, little-endian multi-byte fields):
//
//   byte:  0    1    2    3    4    5    6    7    8    9   10   11
//         +----+----+----+----+----+----+----+----+----+----+----+----+
//         | 'M'| 'P'| VER| ENC|        TOPIC_CRC32         | PAY_LEN  |ENM | RSV
//         +----+----+----+----+----+----+----+----+----+----+----+----+
//
// Byte 3 (ENCODING) tells the receiver how to parse the body:
//   0x00 = RAW       -- opaque bytes
//   0x01 = PROTOBUF  -- body starts with a 2-byte SCHEMA_ID (LE),
//                       then protobuf-encoded bytes (see docs/TYPED_MESSAGES_PLAN.md)
//   0x02..0xFF       -- reserved, receivers MUST drop
//
// Byte 10 (ENC_MODE) signals whether the body is encrypted:
//   0x00 = NONE  -- plaintext (default; bytes 4-7 carry the topic CRC and
//                    PAY_LEN equals the on-wire body length).
//   0x01 = AEAD  -- ChaCha20-Poly1305 (RFC 8439). The body is
//                      [AEAD_NONCE (12)] || ciphertext || [TAG (16)]
//                    where the ciphertext encrypts an 8-byte prefix followed
//                    by the payload:
//                      [TOPIC_CRC32 LE (4)][TIMESTAMP LE (4)] || payload
//                    and the 12-byte cleartext header is the AAD. ChaCha20 is
//                    a stream cipher, so the ciphertext is exactly
//                    8 + PAY_LEN bytes (no padding). TIMESTAMP is unix epoch
//                    seconds (0 = sender had no synced clock); the AEAD nonce
//                    doubles as the replay identity (see replay_guard.h).
//                    PAY_LEN stays the plaintext payload length; bytes 4-7
//                    are written as zero by the sender (the real CRC32 lives
//                    at the start of the decrypted plaintext).
//   0x02..0xFF       -- reserved, receivers MUST drop.
//
// See ../../docs/PROTOCOL.md for the full specification and matching
// Python reference in tests/unit/reference.py.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

#include "chacha20poly1305.h"  // AEAD_NONCE_LEN, AEAD_TAG_LEN

namespace esphome::multicast_pubsub {

constexpr uint8_t MAGIC0 = 'M';
constexpr uint8_t MAGIC1 = 'P';
constexpr uint8_t VERSION = 0x01;
constexpr size_t HEADER_LEN = 12;
// IPv6 minimum MTU (1280, RFC 8200 §5) minus the 40-byte IPv6 header and
// 8-byte UDP header = 1232 bytes of UDP payload guaranteed deliverable on
// any RFC-compliant IPv6 link without fragmentation.
constexpr size_t MAX_DATAGRAM = 1232;
constexpr size_t MAX_PAYLOAD = MAX_DATAGRAM - HEADER_LEN;  // 1220

enum class Encoding : uint8_t {
  RAW = 0x00,
  PROTOBUF = 0x01,
  // 0x02..0xFF reserved (e.g. future compression flavors).
};

constexpr bool is_known_encoding(uint8_t value) {
  return value == static_cast<uint8_t>(Encoding::RAW) || value == static_cast<uint8_t>(Encoding::PROTOBUF);
}

enum class EncMode : uint8_t {
  NONE = 0x00,
  AEAD = 0x01,  // ChaCha20-Poly1305
  // 0x02..0xFF reserved.
};

constexpr bool is_known_enc_mode(uint8_t value) {
  return value == static_cast<uint8_t>(EncMode::NONE) || value == static_cast<uint8_t>(EncMode::AEAD);
}

// Bytes prepended to the AEAD *plaintext* (encrypted + authenticated), ahead
// of the user payload: TOPIC_CRC32 (4) for dispatch + TIMESTAMP (4) for the
// freshness check. Both stay confidential and tamper-proof under the tag.
constexpr size_t AEAD_PREFIX_LEN = 8;

// On-wire encrypted-body length for a payload of `payload_len` bytes:
// the 12-byte nonce, the ciphertext (8-byte prefix + payload, no padding --
// ChaCha20 is a stream cipher), and the 16-byte Poly1305 tag.
constexpr size_t aead_body_len(size_t payload_len) {
  return AEAD_NONCE_LEN + AEAD_PREFIX_LEN + payload_len + AEAD_TAG_LEN;
}

enum class DecodeError : uint8_t {
  OK = 0,
  TOO_SHORT,
  BAD_MAGIC,
  BAD_VERSION,
  UNKNOWN_ENCODING,
  LENGTH_MISMATCH,
  UNKNOWN_ENC_MODE,
  CIPHERTEXT_TOO_SHORT,
};

struct DecodedPacket {
  uint32_t topic_crc;
  Encoding encoding;
  EncMode enc_mode;
  // Plaintext payload length declared by the sender. For EncMode::NONE this
  // equals payload.size(); for EncMode::AEAD this is the post-decrypt payload
  // length (the caller verifies + decrypts `payload`, then takes the bytes at
  // offset AEAD_PREFIX_LEN .. AEAD_PREFIX_LEN + plaintext_len).
  uint16_t plaintext_len;
  // View into the caller-provided buffer. Valid as long as the buffer is.
  // For EncMode::NONE this is the plaintext body. For EncMode::AEAD this is
  // the full encrypted body ([nonce || ciphertext || tag], length
  // `aead_body_len(plaintext_len)`); the caller authenticates and decrypts.
  std::span<const uint8_t> payload;
};

// Write the header for a topic + payload of length `payload_len` to `out`.
// Returns the number of bytes written (always HEADER_LEN). The payload bytes
// must be appended by the caller. When `enc_mode != EncMode::NONE` the
// caller-supplied `topic_crc` is ignored and bytes 4-7 are written as zero
// (the real CRC32 must be carried in the ciphertext by the caller).
size_t encode_header(uint32_t topic_crc, Encoding encoding, uint16_t payload_len, uint8_t out[HEADER_LEN],
                     EncMode enc_mode = EncMode::NONE);

// Parse `data` (a full datagram). Returns OK and fills `*out` on success,
// otherwise leaves `*out` untouched and returns the specific failure reason.
DecodeError decode(std::span<const uint8_t> data, DecodedPacket *out);

}  // namespace esphome::multicast_pubsub
