#include "chacha20poly1305.h"

#include <cstring>

namespace esphome::multicast_pubsub {

namespace {

inline uint32_t load32_le(const uint8_t *p) {
  return uint32_t(p[0]) | (uint32_t(p[1]) << 8) | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}
inline void store32_le(uint8_t *p, uint32_t v) {
  p[0] = uint8_t(v);
  p[1] = uint8_t(v >> 8);
  p[2] = uint8_t(v >> 16);
  p[3] = uint8_t(v >> 24);
}
inline uint32_t rotl32(uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }

// ---- ChaCha20 (RFC 8439 §2.3) ---------------------------------------------

#define CHACHA_QR(a, b, c, d) \
  a += b;                     \
  d ^= a;                     \
  d = rotl32(d, 16);          \
  c += d;                     \
  b ^= c;                     \
  b = rotl32(b, 12);          \
  a += b;                     \
  d ^= a;                     \
  d = rotl32(d, 8);           \
  c += d;                     \
  b ^= c;                     \
  b = rotl32(b, 7)

void chacha20_block(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t out[64]) {
  uint32_t s[16];
  s[0] = 0x61707865;
  s[1] = 0x3320646E;
  s[2] = 0x79622D32;
  s[3] = 0x6B206574;
  for (int i = 0; i < 8; i++)
    s[4 + i] = load32_le(key + 4 * i);
  s[12] = counter;
  s[13] = load32_le(nonce + 0);
  s[14] = load32_le(nonce + 4);
  s[15] = load32_le(nonce + 8);

  uint32_t w[16];
  std::memcpy(w, s, sizeof(w));
  for (int i = 0; i < 10; i++) {
    CHACHA_QR(w[0], w[4], w[8], w[12]);
    CHACHA_QR(w[1], w[5], w[9], w[13]);
    CHACHA_QR(w[2], w[6], w[10], w[14]);
    CHACHA_QR(w[3], w[7], w[11], w[15]);
    CHACHA_QR(w[0], w[5], w[10], w[15]);
    CHACHA_QR(w[1], w[6], w[11], w[12]);
    CHACHA_QR(w[2], w[7], w[8], w[13]);
    CHACHA_QR(w[3], w[4], w[9], w[14]);
  }
  for (int i = 0; i < 16; i++)
    store32_le(out + 4 * i, w[i] + s[i]);
}

// ---- Poly1305 (poly1305-donna 32-bit, public domain) -----------------------

struct Poly1305 {
  uint32_t r[5];
  uint32_t h[5];
  uint32_t pad[4];
  size_t leftover;
  uint8_t buffer[16];
  uint8_t final;
};

void poly1305_init(Poly1305 *st, const uint8_t key[32]) {
  uint32_t t0 = load32_le(key + 0), t1 = load32_le(key + 4), t2 = load32_le(key + 8), t3 = load32_le(key + 12);
  st->r[0] = (t0) & 0x3ffffff;
  st->r[1] = ((t0 >> 26) | (t1 << 6)) & 0x3ffff03;
  st->r[2] = ((t1 >> 20) | (t2 << 12)) & 0x3ffc0ff;
  st->r[3] = ((t2 >> 14) | (t3 << 18)) & 0x3f03fff;
  st->r[4] = ((t3 >> 8)) & 0x00fffff;
  for (int i = 0; i < 5; i++)
    st->h[i] = 0;
  st->pad[0] = load32_le(key + 16);
  st->pad[1] = load32_le(key + 20);
  st->pad[2] = load32_le(key + 24);
  st->pad[3] = load32_le(key + 28);
  st->leftover = 0;
  st->final = 0;
}

void poly1305_blocks(Poly1305 *st, const uint8_t *m, size_t bytes) {
  const uint32_t hibit = st->final ? 0 : (1u << 24);
  uint32_t r0 = st->r[0], r1 = st->r[1], r2 = st->r[2], r3 = st->r[3], r4 = st->r[4];
  uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
  uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
  while (bytes >= 16) {
    h0 += (load32_le(m + 0)) & 0x3ffffff;
    h1 += (load32_le(m + 3) >> 2) & 0x3ffffff;
    h2 += (load32_le(m + 6) >> 4) & 0x3ffffff;
    h3 += (load32_le(m + 9) >> 6) & 0x3ffffff;
    h4 += (load32_le(m + 12) >> 8) | hibit;

    uint64_t d0 = (uint64_t) h0 * r0 + (uint64_t) h1 * s4 + (uint64_t) h2 * s3 + (uint64_t) h3 * s2 + (uint64_t) h4 * s1;
    uint64_t d1 = (uint64_t) h0 * r1 + (uint64_t) h1 * r0 + (uint64_t) h2 * s4 + (uint64_t) h3 * s3 + (uint64_t) h4 * s2;
    uint64_t d2 = (uint64_t) h0 * r2 + (uint64_t) h1 * r1 + (uint64_t) h2 * r0 + (uint64_t) h3 * s4 + (uint64_t) h4 * s3;
    uint64_t d3 = (uint64_t) h0 * r3 + (uint64_t) h1 * r2 + (uint64_t) h2 * r1 + (uint64_t) h3 * r0 + (uint64_t) h4 * s4;
    uint64_t d4 = (uint64_t) h0 * r4 + (uint64_t) h1 * r3 + (uint64_t) h2 * r2 + (uint64_t) h3 * r1 + (uint64_t) h4 * r0;

    uint32_t c = (uint32_t)(d0 >> 26);
    h0 = (uint32_t) d0 & 0x3ffffff;
    d1 += c;
    c = (uint32_t)(d1 >> 26);
    h1 = (uint32_t) d1 & 0x3ffffff;
    d2 += c;
    c = (uint32_t)(d2 >> 26);
    h2 = (uint32_t) d2 & 0x3ffffff;
    d3 += c;
    c = (uint32_t)(d3 >> 26);
    h3 = (uint32_t) d3 & 0x3ffffff;
    d4 += c;
    c = (uint32_t)(d4 >> 26);
    h4 = (uint32_t) d4 & 0x3ffffff;
    h0 += c * 5;
    c = h0 >> 26;
    h0 &= 0x3ffffff;
    h1 += c;

    m += 16;
    bytes -= 16;
  }
  st->h[0] = h0;
  st->h[1] = h1;
  st->h[2] = h2;
  st->h[3] = h3;
  st->h[4] = h4;
}

void poly1305_update(Poly1305 *st, const uint8_t *m, size_t bytes) {
  if (st->leftover) {
    size_t want = 16 - st->leftover;
    if (want > bytes)
      want = bytes;
    std::memcpy(st->buffer + st->leftover, m, want);
    bytes -= want;
    m += want;
    st->leftover += want;
    if (st->leftover < 16)
      return;
    poly1305_blocks(st, st->buffer, 16);
    st->leftover = 0;
  }
  if (bytes >= 16) {
    size_t want = bytes & ~(size_t) 15;
    poly1305_blocks(st, m, want);
    m += want;
    bytes -= want;
  }
  if (bytes) {
    std::memcpy(st->buffer + st->leftover, m, bytes);
    st->leftover += bytes;
  }
}

void poly1305_finish(Poly1305 *st, uint8_t mac[16]) {
  if (st->leftover) {
    size_t i = st->leftover;
    st->buffer[i++] = 1;
    for (; i < 16; i++)
      st->buffer[i] = 0;
    st->final = 1;
    poly1305_blocks(st, st->buffer, 16);
  }

  uint32_t h0 = st->h[0], h1 = st->h[1], h2 = st->h[2], h3 = st->h[3], h4 = st->h[4];
  uint32_t c = h1 >> 26;
  h1 &= 0x3ffffff;
  h2 += c;
  c = h2 >> 26;
  h2 &= 0x3ffffff;
  h3 += c;
  c = h3 >> 26;
  h3 &= 0x3ffffff;
  h4 += c;
  c = h4 >> 26;
  h4 &= 0x3ffffff;
  h0 += c * 5;
  c = h0 >> 26;
  h0 &= 0x3ffffff;
  h1 += c;

  uint32_t g0 = h0 + 5;
  c = g0 >> 26;
  g0 &= 0x3ffffff;
  uint32_t g1 = h1 + c;
  c = g1 >> 26;
  g1 &= 0x3ffffff;
  uint32_t g2 = h2 + c;
  c = g2 >> 26;
  g2 &= 0x3ffffff;
  uint32_t g3 = h3 + c;
  c = g3 >> 26;
  g3 &= 0x3ffffff;
  uint32_t g4 = h4 + c - (1u << 26);

  uint32_t mask = (g4 >> 31) - 1;
  g0 &= mask;
  g1 &= mask;
  g2 &= mask;
  g3 &= mask;
  g4 &= mask;
  mask = ~mask;
  h0 = (h0 & mask) | g0;
  h1 = (h1 & mask) | g1;
  h2 = (h2 & mask) | g2;
  h3 = (h3 & mask) | g3;
  h4 = (h4 & mask) | g4;

  h0 = (h0) | (h1 << 26);
  h1 = (h1 >> 6) | (h2 << 20);
  h2 = (h2 >> 12) | (h3 << 14);
  h3 = (h3 >> 18) | (h4 << 8);

  uint64_t f = (uint64_t) h0 + st->pad[0];
  h0 = (uint32_t) f;
  f = (uint64_t) h1 + st->pad[1] + (f >> 32);
  h1 = (uint32_t) f;
  f = (uint64_t) h2 + st->pad[2] + (f >> 32);
  h2 = (uint32_t) f;
  f = (uint64_t) h3 + st->pad[3] + (f >> 32);
  h3 = (uint32_t) f;

  store32_le(mac + 0, h0);
  store32_le(mac + 4, h1);
  store32_le(mac + 8, h2);
  store32_le(mac + 12, h3);
}

// Compute the Poly1305 tag over aad || pad16 || ct || pad16 || len(aad) ||
// len(ct), streamed so no scratch buffer the size of the message is needed.
void aead_tag(const uint8_t otk[32], const uint8_t *aad, size_t aad_len, const uint8_t *ct, size_t ct_len,
              uint8_t tag_out[16]) {
  static const uint8_t zeros[16] = {0};
  Poly1305 st;
  poly1305_init(&st, otk);
  poly1305_update(&st, aad, aad_len);
  poly1305_update(&st, zeros, (16 - (aad_len % 16)) % 16);
  poly1305_update(&st, ct, ct_len);
  poly1305_update(&st, zeros, (16 - (ct_len % 16)) % 16);
  uint8_t lenblk[16];
  store32_le(lenblk + 0, (uint32_t) aad_len);
  store32_le(lenblk + 4, (uint32_t)((uint64_t) aad_len >> 32));
  store32_le(lenblk + 8, (uint32_t) ct_len);
  store32_le(lenblk + 12, (uint32_t)((uint64_t) ct_len >> 32));
  poly1305_update(&st, lenblk, 16);
  poly1305_finish(&st, tag_out);
}

bool ct_eq(const uint8_t *a, const uint8_t *b, size_t n) {
  uint8_t diff = 0;
  for (size_t i = 0; i < n; i++)
    diff |= a[i] ^ b[i];
  return diff == 0;
}

}  // namespace

void chacha20_xor(const uint8_t key[32], uint32_t counter, const uint8_t nonce[12], uint8_t *data, size_t len) {
  uint8_t block[64];
  for (size_t off = 0; off < len; off += 64) {
    chacha20_block(key, counter + (uint32_t)(off / 64), nonce, block);
    size_t n = len - off < 64 ? len - off : 64;
    for (size_t i = 0; i < n; i++)
      data[off + i] ^= block[i];
  }
}

void chacha20poly1305_encrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                              uint8_t *buf, size_t buf_len, uint8_t tag_out[16]) {
  uint8_t otk[32] = {0};
  chacha20_xor(key, 0, nonce, otk, 32);  // Poly1305 one-time key = block-0 keystream
  chacha20_xor(key, 1, nonce, buf, buf_len);
  aead_tag(otk, aad, aad_len, buf, buf_len, tag_out);
}

bool chacha20poly1305_decrypt(const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad, size_t aad_len,
                              uint8_t *buf, size_t buf_len, const uint8_t tag[16]) {
  uint8_t otk[32] = {0};
  chacha20_xor(key, 0, nonce, otk, 32);
  uint8_t expected[16];
  aead_tag(otk, aad, aad_len, buf, buf_len, expected);  // over the ciphertext, before decrypt
  if (!ct_eq(expected, tag, 16))
    return false;
  chacha20_xor(key, 1, nonce, buf, buf_len);
  return true;
}

}  // namespace esphome::multicast_pubsub
