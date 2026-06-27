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
//   0x01 = XXTEA -- the body is XXTEA-256 ciphertext over a 12-byte prefix
//                    followed by the plaintext payload:
//                      [TOPIC_CRC32 LE (4)][TIMESTAMP LE (4)][NONCE LE (4)]
//                      || payload
//                    zero-padded up to roundup4(12 + PAY_LEN) bytes (the
//                    12-byte prefix already clears XXTEA's 2-word minimum).
//                    TIMESTAMP is unix epoch seconds (0 = sender had no
//                    synced clock); NONCE is 4 random bytes per message.
//                    Together they drive replay rejection (see replay_guard.h).
//                    PAY_LEN stays the plaintext payload length; bytes 4-7
//                    are written as zero by the sender and ignored on
//                    receive (the real CRC32 lives at the start of the
//                    decrypted plaintext).
//   0x02..0xFF       -- reserved, receivers MUST drop.
//
// See ../../docs/PROTOCOL.md for the full specification and matching
// Python reference in tests/unit/reference.py.

#pragma once

#include <cstddef>
#include <cstdint>
#include <span>

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
  XXTEA = 0x01,
  // 0x02..0xFF reserved.
};

constexpr bool is_known_enc_mode(uint8_t value) {
  return value == static_cast<uint8_t>(EncMode::NONE) || value == static_cast<uint8_t>(EncMode::XXTEA);
}

// Bytes prepended to the plaintext inside the XXTEA ciphertext, ahead of the
// user payload: TOPIC_CRC32 (4) + TIMESTAMP (4) + NONCE (4). The CRC is the
// integrity tag; the timestamp + nonce feed receiver-side replay rejection.
constexpr size_t XXTEA_PREFIX_LEN = 12;

// Ciphertext length for a plaintext payload of `payload_len` bytes under
// EncMode::XXTEA. Equals roundup4(XXTEA_PREFIX_LEN + payload_len): the
// 12-byte prefix plus the payload, zero-padded up to a multiple of 4 bytes
// (XXTEA word size). The prefix alone already exceeds XXTEA's 2-word (8-byte)
// minimum, so no separate floor is needed.
constexpr size_t xxtea_ciphertext_len(size_t payload_len) {
  return (payload_len + XXTEA_PREFIX_LEN + 3) & ~size_t{3};
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
  // equals payload.size(); for EncMode::XXTEA this is the post-decrypt
  // payload length (caller decrypts `payload` then takes the bytes at offset
  // 4 .. 4 + plaintext_len).
  uint16_t plaintext_len;
  // View into the caller-provided buffer. Valid as long as the buffer is.
  // For EncMode::NONE this is the plaintext body. For EncMode::XXTEA this is
  // the *ciphertext* (length is `xxtea_ciphertext_len(plaintext_len)`); the
  // caller is responsible for in-place decryption and slicing.
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
