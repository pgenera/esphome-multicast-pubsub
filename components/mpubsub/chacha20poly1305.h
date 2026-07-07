// Vendored ChaCha20-Poly1305 AEAD (RFC 8439).
//
// Self-contained so it works identically on every target -- in particular the
// ESP8266, whose arduino core ships BearSSL (not the mbedTLS that ESP32 uses),
// and where `__int128` is unavailable (Poly1305 uses the 32-bit
// "poly1305-donna" limb arithmetic instead). Mirrors how sha256 is vendored.
//
// Verified against the RFC 8439 §2.4.2 / §2.8.2 test vectors by the host
// harness (tests/unit/chacha_main.cpp) and the Python reference.

#pragma once

#include <cstddef>
#include <cstdint>

namespace esphome::multicast_pubsub {

constexpr size_t AEAD_KEY_LEN = 32;
constexpr size_t AEAD_NONCE_LEN = 12;  // 96-bit nonce, one per message
constexpr size_t AEAD_TAG_LEN = 16;    // Poly1305 tag

// ChaCha20 keystream XOR of `data` in place (RFC 8439 §2.4). `counter` is the
// initial 32-bit block counter.
void chacha20_xor(const uint8_t key[AEAD_KEY_LEN], uint32_t counter, const uint8_t nonce[AEAD_NONCE_LEN], uint8_t *data,
                  size_t len);

// Encrypt `buf` (length `buf_len`) in place under ChaCha20-Poly1305 and write
// the 16-byte tag to `tag_out`. `aad`/`aad_len` are authenticated, not
// encrypted (pass nullptr/0 for none).
void chacha20poly1305_encrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN], const uint8_t *aad,
                              size_t aad_len, uint8_t *buf, size_t buf_len, uint8_t tag_out[AEAD_TAG_LEN]);

// Decrypt `buf` in place, verifying `tag` over aad+ciphertext first. Returns
// true iff authentication succeeds; on false the buffer is left untouched and
// MUST be discarded.
bool chacha20poly1305_decrypt(const uint8_t key[AEAD_KEY_LEN], const uint8_t nonce[AEAD_NONCE_LEN], const uint8_t *aad,
                              size_t aad_len, uint8_t *buf, size_t buf_len, const uint8_t tag[AEAD_TAG_LEN]);

}  // namespace esphome::multicast_pubsub
