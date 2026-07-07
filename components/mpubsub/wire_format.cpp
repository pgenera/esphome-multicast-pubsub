#include "wire_format.h"

namespace esphome::multicast_pubsub {

size_t encode_header(uint32_t topic_crc, Encoding encoding, uint16_t payload_len, uint8_t out[HEADER_LEN],
                     EncMode enc_mode) {
  out[0] = MAGIC0;
  out[1] = MAGIC1;
  out[2] = VERSION;
  out[3] = static_cast<uint8_t>(encoding);
  // When encrypted the real CRC lives at the start of the ciphertext --
  // never leak it in cleartext, even if the caller passed one.
  if (enc_mode != EncMode::NONE)
    topic_crc = 0;
  out[4] = uint8_t(topic_crc);
  out[5] = uint8_t(topic_crc >> 8);
  out[6] = uint8_t(topic_crc >> 16);
  out[7] = uint8_t(topic_crc >> 24);
  out[8] = uint8_t(payload_len);
  out[9] = uint8_t(payload_len >> 8);
  out[10] = static_cast<uint8_t>(enc_mode);
  out[11] = 0;  // reserved
  return HEADER_LEN;
}

DecodeError decode(std::span<const uint8_t> data, DecodedPacket *out) {
  if (data.size() < HEADER_LEN)
    return DecodeError::TOO_SHORT;
  if (data[0] != MAGIC0 || data[1] != MAGIC1)
    return DecodeError::BAD_MAGIC;
  if (data[2] != VERSION)
    return DecodeError::BAD_VERSION;
  uint8_t enc = data[3];
  if (!is_known_encoding(enc))
    return DecodeError::UNKNOWN_ENCODING;
  uint8_t enm = data[10];
  if (!is_known_enc_mode(enm))
    return DecodeError::UNKNOWN_ENC_MODE;
  uint32_t crc = uint32_t(data[4]) | (uint32_t(data[5]) << 8) | (uint32_t(data[6]) << 16) | (uint32_t(data[7]) << 24);
  uint16_t payload_len = uint16_t(data[8]) | (uint16_t(data[9]) << 8);
  // byte 11 reserved; ignored on decode for forward-compatibility.
  if (enm == static_cast<uint8_t>(EncMode::AEAD)) {
    size_t expected = HEADER_LEN + aead_body_len(payload_len);
    if (data.size() != expected)
      return DecodeError::CIPHERTEXT_TOO_SHORT;
  } else {
    if (HEADER_LEN + payload_len != data.size())
      return DecodeError::LENGTH_MISMATCH;
  }
  out->topic_crc = crc;
  out->encoding = static_cast<Encoding>(enc);
  out->enc_mode = static_cast<EncMode>(enm);
  out->plaintext_len = payload_len;
  out->payload = data.subspan(HEADER_LEN);
  return DecodeError::OK;
}

}  // namespace esphome::multicast_pubsub
