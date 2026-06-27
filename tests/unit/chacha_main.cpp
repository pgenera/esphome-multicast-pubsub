// Self-checking harness for the vendored ChaCha20-Poly1305. Verifies the
// RFC 8439 test vectors and an encrypt/decrypt/auth roundtrip, then exits 0
// on success or non-zero on the first failure. Driven by
// tests/unit/test_chacha_cpp.py.

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <vector>

#include "../../components/mpubsub/chacha20poly1305.h"

using namespace esphome::multicast_pubsub;

static int failures = 0;

static void check(bool ok, const char *name) {
  if (!ok) {
    std::printf("FAIL %s\n", name);
    failures++;
  } else {
    std::printf("ok %s\n", name);
  }
}

static std::vector<uint8_t> hex(const char *s) {
  std::vector<uint8_t> out;
  for (size_t i = 0; s[i] && s[i + 1]; i += 2) {
    auto nyb = [](char c) -> int { return c <= '9' ? c - '0' : (c | 0x20) - 'a' + 10; };
    out.push_back(uint8_t((nyb(s[i]) << 4) | nyb(s[i + 1])));
  }
  return out;
}

int main() {
  // RFC 8439 §2.8.2 AEAD vector.
  uint8_t key[32];
  for (int i = 0; i < 32; i++)
    key[i] = uint8_t(0x80 + i);
  auto nonce = hex("070000004041424344454647");
  auto aad = hex("50515253c0c1c2c3c4c5c6c7");
  const char *pt_str =
      "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
  std::vector<uint8_t> buf(reinterpret_cast<const uint8_t *>(pt_str),
                           reinterpret_cast<const uint8_t *>(pt_str) + std::strlen(pt_str));
  std::vector<uint8_t> plain = buf;
  uint8_t tag[16];
  chacha20poly1305_encrypt(key, nonce.data(), aad.data(), aad.size(), buf.data(), buf.size(), tag);

  auto expect_ct = hex("d31a8d34648e60db7b86afbc53ef7ec2");
  check(std::memcmp(buf.data(), expect_ct.data(), 16) == 0, "rfc8439_ciphertext_prefix");
  auto expect_tag = hex("1ae10b594f09e26a7e902ecbd0600691");
  check(std::memcmp(tag, expect_tag.data(), 16) == 0, "rfc8439_tag");

  // Decrypt + authenticate roundtrip.
  bool ok = chacha20poly1305_decrypt(key, nonce.data(), aad.data(), aad.size(), buf.data(), buf.size(), tag);
  check(ok, "decrypt_auth_ok");
  check(buf == plain, "decrypt_roundtrip");

  // Tamper: a flipped ciphertext byte must fail authentication.
  std::vector<uint8_t> buf2 = plain;
  uint8_t tag2[16];
  chacha20poly1305_encrypt(key, nonce.data(), aad.data(), aad.size(), buf2.data(), buf2.size(), tag2);
  buf2[0] ^= 0x01;
  check(!chacha20poly1305_decrypt(key, nonce.data(), aad.data(), aad.size(), buf2.data(), buf2.size(), tag2),
        "tamper_rejected");

  // Empty plaintext + empty aad still authenticates.
  uint8_t tag3[16];
  chacha20poly1305_encrypt(key, nonce.data(), nullptr, 0, nullptr, 0, tag3);
  check(chacha20poly1305_decrypt(key, nonce.data(), nullptr, 0, nullptr, 0, tag3), "empty_roundtrip");

  std::printf(failures ? "FAILURES %d\n" : "ALL OK\n", failures);
  return failures ? 1 : 0;
}
