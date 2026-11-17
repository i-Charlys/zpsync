#include "zpsync_crypto.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <ntsecapi.h>
#if !defined(SystemFunction036)
BOOLEAN NTAPI SystemFunction036(PVOID RandomBuffer, ULONG RandomBufferLength);
#endif
#else
#include <fcntl.h>
#include <unistd.h>
#endif

static uint32_t rotl32(uint32_t x, uint32_t n) {
  return (x << n) | (x >> (32U - n));
}

static uint32_t rotr32(uint32_t x, uint32_t n) {
  return (x >> n) | (x << (32U - n));
}

static uint32_t load_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static void store_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static void store_be64(uint8_t *p, uint64_t v) {
  store_be32(p, (uint32_t)(v >> 32));
  store_be32(p + 4, (uint32_t)v);
}

static uint64_t load_be64(const uint8_t *p) {
  return ((uint64_t)load_be32(p) << 32) | (uint64_t)load_be32(p + 4);
}

static uint16_t load_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static void store_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

/* ── SHA-1 (FIPS 180-4) ─────────────────────────────────────────────────── */

typedef struct {
  uint32_t state[5];
  uint64_t count;
  uint8_t buf[64];
} sha1_ctx_s;

static void sha1_transform(uint32_t state[5], const uint8_t block[64]) {
  uint32_t w[80];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = load_be32(block + i * 4);
  }
  for (size_t i = 16; i < 80; ++i) {
    w[i] = rotl32(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
  }

  uint32_t a = state[0];
  uint32_t b = state[1];
  uint32_t c = state[2];
  uint32_t d = state[3];
  uint32_t e = state[4];

  for (size_t i = 0; i < 80; ++i) {
    uint32_t f = 0;
    uint32_t k = 0;
    if (i < 20) {
      f = (b & c) | ((~b) & d);
      k = 0x5A827999U;
    } else if (i < 40) {
      f = b ^ c ^ d;
      k = 0x6ED9EBA1U;
    } else if (i < 60) {
      f = (b & c) | (b & d) | (c & d);
      k = 0x8F1BBCDCU;
    } else {
      f = b ^ c ^ d;
      k = 0xCA62C1D6U;
    }
    uint32_t temp = rotl32(a, 5) + f + e + k + w[i];
    e = d;
    d = c;
    c = rotl32(b, 30);
    b = a;
    a = temp;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
}

static void sha1_init(sha1_ctx_s *ctx) {
  ctx->state[0] = 0x67452301U;
  ctx->state[1] = 0xEFCDAB89U;
  ctx->state[2] = 0x98BADCFEU;
  ctx->state[3] = 0x10325476U;
  ctx->state[4] = 0xC3D2E1F0U;
  ctx->count = 0;
}

static void sha1_update(sha1_ctx_s *ctx, const uint8_t *data, size_t len) {
  size_t idx = (size_t)(ctx->count & 63U);
  ctx->count += len;
  size_t i = 0;
  if (idx > 0 && idx + len >= 64U) {
    size_t fill = 64U - idx;
    memcpy(ctx->buf + idx, data, fill);
    sha1_transform(ctx->state, ctx->buf);
    i = fill;
    idx = 0;
  }
  while (i + 64U <= len) {
    sha1_transform(ctx->state, data + i);
    i += 64U;
  }
  if (i < len) {
    memcpy(ctx->buf + idx, data + i, len - i);
  }
}

static void sha1_final(sha1_ctx_s *ctx, uint8_t out[ZPSYNC_SHA1_BYTES]) {
  uint64_t bits = ctx->count * 8ULL;
  uint8_t pad = 0x80U;
  sha1_update(ctx, &pad, 1);
  pad = 0x00U;
  while ((ctx->count & 63U) != 56U) {
    sha1_update(ctx, &pad, 1);
  }
  uint8_t len_be[8];
  store_be64(len_be, bits);
  sha1_update(ctx, len_be, 8);
  for (size_t i = 0; i < 5; ++i) {
    store_be32(out + i * 4, ctx->state[i]);
  }
}

void zpsync_sha1(const uint8_t *data, size_t len, uint8_t out_digest[ZPSYNC_SHA1_BYTES]) {
  sha1_ctx_s ctx;
  sha1_init(&ctx);
  if (data != NULL && len > 0) {
    sha1_update(&ctx, data, len);
  }
  sha1_final(&ctx, out_digest);
}

/* ── SHA-256 (FIPS 180-4) ───────────────────────────────────────────────── */

static const uint32_t K256[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U, 0x3956c25bU, 0x59f111f1U,
    0x923f82a4U, 0xab1c5ed5U, 0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U, 0xe49b69c1U, 0xefbe4786U,
    0x0fc19dc6U, 0x240ca1ccU, 0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U, 0xc6e00bf3U, 0xd5a79147U,
    0x06ca6351U, 0x14292967U, 0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U, 0xa2bfe8a1U, 0xa81a664bU,
    0xc24b8b70U, 0xc76c51a3U, 0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U, 0x391c0cb3U, 0x4ed8aa4aU,
    0x5b9cca4fU, 0x682e6ff3U, 0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U};

typedef struct {
  uint32_t state[8];
  uint64_t count;
  uint8_t buf[64];
} sha256_ctx_s;

static void sha256_transform(uint32_t state[8], const uint8_t block[64]) {
  uint32_t w[64];
  for (size_t i = 0; i < 16; ++i) {
    w[i] = load_be32(block + i * 4);
  }
  for (size_t i = 16; i < 64; ++i) {
    uint32_t s0 = rotr32(w[i - 15], 7) ^ rotr32(w[i - 15], 18) ^ (w[i - 15] >> 3);
    uint32_t s1 = rotr32(w[i - 2], 17) ^ rotr32(w[i - 2], 19) ^ (w[i - 2] >> 10);
    w[i] = w[i - 16] + s0 + w[i - 7] + s1;
  }

  uint32_t a = state[0], b = state[1], c = state[2], d = state[3];
  uint32_t e = state[4], f = state[5], g = state[6], h = state[7];

  for (size_t i = 0; i < 64; ++i) {
    uint32_t S1 = rotr32(e, 6) ^ rotr32(e, 11) ^ rotr32(e, 25);
    uint32_t ch = (e & f) ^ ((~e) & g);
    uint32_t temp1 = h + S1 + ch + K256[i] + w[i];
    uint32_t S0 = rotr32(a, 2) ^ rotr32(a, 13) ^ rotr32(a, 22);
    uint32_t maj = (a & b) ^ (a & c) ^ (b & c);
    uint32_t temp2 = S0 + maj;

    h = g;
    g = f;
    f = e;
    e = d + temp1;
    d = c;
    c = b;
    b = a;
    a = temp1 + temp2;
  }

  state[0] += a;
  state[1] += b;
  state[2] += c;
  state[3] += d;
  state[4] += e;
  state[5] += f;
  state[6] += g;
  state[7] += h;
}

static void sha256_init(sha256_ctx_s *ctx) {
  ctx->state[0] = 0x6a09e667U;
  ctx->state[1] = 0xbb67ae85U;
  ctx->state[2] = 0x3c6ef372U;
  ctx->state[3] = 0xa54ff53aU;
  ctx->state[4] = 0x510e527fU;
  ctx->state[5] = 0x9b05688cU;
  ctx->state[6] = 0x1f83d9abU;
  ctx->state[7] = 0x5be0cd19U;
  ctx->count = 0;
}

static void sha256_update(sha256_ctx_s *ctx, const uint8_t *data, size_t len) {
  size_t idx = (size_t)(ctx->count & 63U);
  ctx->count += len;
  size_t i = 0;
  if (idx > 0 && idx + len >= 64U) {
    size_t fill = 64U - idx;
    memcpy(ctx->buf + idx, data, fill);
    sha256_transform(ctx->state, ctx->buf);
    i = fill;
    idx = 0;
  }
  while (i + 64U <= len) {
    sha256_transform(ctx->state, data + i);
    i += 64U;
  }
  if (i < len) {
    memcpy(ctx->buf + idx, data + i, len - i);
  }
}

static void sha256_final(sha256_ctx_s *ctx, uint8_t out[ZPSYNC_SHA256_BYTES]) {
  uint64_t bits = ctx->count * 8ULL;
  uint8_t pad = 0x80U;
  sha256_update(ctx, &pad, 1);
  pad = 0x00U;
  while ((ctx->count & 63U) != 56U) {
    sha256_update(ctx, &pad, 1);
  }
  uint8_t len_be[8];
  store_be64(len_be, bits);
  sha256_update(ctx, len_be, 8);
  for (size_t i = 0; i < 8; ++i) {
    store_be32(out + i * 4, ctx->state[i]);
  }
}

void zpsync_sha256(const uint8_t *data, size_t len,
                   uint8_t out_digest[ZPSYNC_SHA256_BYTES]) {
  sha256_ctx_s ctx;
  sha256_init(&ctx);
  if (data != NULL && len > 0) {
    sha256_update(&ctx, data, len);
  }
  sha256_final(&ctx, out_digest);
}

/* ── Key, Node_ID, and Deterministic Port Derivations ───────────────────── */

int zpsync_derive_session_key(const uint8_t *secret, size_t secret_len,
                              uint8_t out_key[ZPSYNC_KEY_BYTES]) {
  if (secret == NULL || secret_len == 0 || out_key == NULL) return -1;
  static const uint8_t domain[] = "zpsync-v1-master-key";
  sha256_ctx_s ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, domain, sizeof(domain) - 1U);
  sha256_update(&ctx, secret, secret_len);
  sha256_final(&ctx, out_key);
  return 0;
}

int zpsync_derive_dht_node_id(const uint8_t *secret, size_t secret_len,
                              uint64_t utc_hour_bucket,
                              uint8_t out_node_id[ZPSYNC_SHA1_BYTES]) {
  if (secret == NULL || secret_len == 0 || out_node_id == NULL) return -1;
  uint8_t hour_be[8];
  store_be64(hour_be, utc_hour_bucket);

  sha1_ctx_s ctx;
  sha1_init(&ctx);
  sha1_update(&ctx, secret, secret_len);
  sha1_update(&ctx, hour_be, sizeof(hour_be));
  sha1_final(&ctx, out_node_id);
  return 0;
}

uint16_t zpsync_derive_target_port(const uint8_t *secret, size_t secret_len,
                                   uint64_t time_window) {
  if (secret == NULL || secret_len == 0) return 0;
  static const uint8_t domain[] = "zpsync-v1-port";
  uint8_t win_be[8];
  store_be64(win_be, time_window);

  uint8_t digest[ZPSYNC_SHA256_BYTES];
  sha256_ctx_s ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, domain, sizeof(domain) - 1U);
  sha256_update(&ctx, secret, secret_len);
  sha256_update(&ctx, win_be, sizeof(win_be));
  sha256_final(&ctx, digest);

  uint32_t h = load_be32(digest);
  return (uint16_t)(ZPSYNC_PORT_BASE + (h % ZPSYNC_PORT_SPAN_V6));
}

uint16_t zpsync_derive_birthday_port(const uint8_t *secret, size_t secret_len,
                                     uint32_t index) {
  if (secret == NULL || secret_len == 0) return 0;
  static const uint8_t domain[] = "zpsync-v1-bday";
  uint8_t idx_be[4];
  store_be32(idx_be, index);

  uint8_t digest[ZPSYNC_SHA256_BYTES];
  sha256_ctx_s ctx;
  sha256_init(&ctx);
  sha256_update(&ctx, domain, sizeof(domain) - 1U);
  sha256_update(&ctx, secret, secret_len);
  sha256_update(&ctx, idx_be, sizeof(idx_be));
  sha256_final(&ctx, digest);

  uint32_t h = load_be32(digest);
  return (uint16_t)(ZPSYNC_PORT_BASE + (h % ZPSYNC_PORT_SPAN_BDAY));
}

/* ── AEAD Mailbox Sealing (ChaCha20-Poly1305 via zcrudp) ────────────────── */

int zpsync_mailbox_seal(const uint8_t key[ZPSYNC_KEY_BYTES],
                        const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                        const zpsync_mailbox_s *mb, uint8_t *out_sealed,
                        size_t max_out_len) {
  if (key == NULL || nonce == NULL || mb == NULL || out_sealed == NULL ||
      max_out_len < ZPSYNC_MAILBOX_SEALED_BYTES) {
    return -1;
  }

  uint8_t plain[ZPSYNC_MAILBOX_PLAIN_BYTES];
  memcpy(plain, mb->ipv6, 16);
  memcpy(plain + 16, mb->ipv4, 4);
  store_be16(plain + 20, mb->ipv4_port);
  store_be16(plain + 22, mb->local_port);
  plain[24] = mb->has_ipv6 ? 1U : 0U;
  plain[25] = mb->has_ipv4 ? 1U : 0U;
  plain[26] = mb->nat_type;
  plain[27] = mb->role_hint;
  store_be64(plain + 28, mb->timestamp_s);
  /* Pack low 32 bits of peer_nonce in bytes 36..39 for compact 40B layout */
  store_be32(plain + 36, (uint32_t)(mb->peer_nonce & 0xFFFFFFFFU));

  static const uint8_t aad[] = "zpsync-mailbox-v1";
  memcpy(out_sealed, nonce, ZPSYNC_NONCE_BYTES);
  int rc = rudp_chacha20_poly1305_encrypt(
      key, nonce, aad, sizeof(aad) - 1U, plain, sizeof(plain),
      out_sealed + ZPSYNC_NONCE_BYTES,
      out_sealed + ZPSYNC_NONCE_BYTES + ZPSYNC_MAILBOX_PLAIN_BYTES);
  if (rc != RUDP_OK) return -1;
  return (int)ZPSYNC_MAILBOX_SEALED_BYTES;
}

int zpsync_mailbox_open(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *sealed,
                        size_t sealed_len, zpsync_mailbox_s *out_mb) {
  if (key == NULL || sealed == NULL || out_mb == NULL ||
      sealed_len != ZPSYNC_MAILBOX_SEALED_BYTES) {
    return -1;
  }

  static const uint8_t aad[] = "zpsync-mailbox-v1";
  uint8_t plain[ZPSYNC_MAILBOX_PLAIN_BYTES];
  int rc = rudp_chacha20_poly1305_decrypt(
      key, sealed, aad, sizeof(aad) - 1U, sealed + ZPSYNC_NONCE_BYTES,
      ZPSYNC_MAILBOX_PLAIN_BYTES,
      sealed + ZPSYNC_NONCE_BYTES + ZPSYNC_MAILBOX_PLAIN_BYTES, plain);
  if (rc != RUDP_OK) return -1;

  memset(out_mb, 0, sizeof(*out_mb));
  memcpy(out_mb->ipv6, plain, 16);
  memcpy(out_mb->ipv4, plain + 16, 4);
  out_mb->ipv4_port = load_be16(plain + 20);
  out_mb->local_port = load_be16(plain + 22);
  out_mb->has_ipv6 = plain[24];
  out_mb->has_ipv4 = plain[25];
  out_mb->nat_type = plain[26];
  out_mb->role_hint = plain[27];
  out_mb->timestamp_s = load_be64(plain + 28);
  out_mb->peer_nonce = (uint64_t)load_be32(plain + 36);
  return 0;
}

int zpsync_random_bytes(uint8_t *buf, size_t len) {
  if (buf == NULL || len == 0) return -1;
#if defined(_WIN32)
  if (!SystemFunction036(buf, (ULONG)len)) return -1;
  return 0;
#else
  int fd = open("/dev/urandom", O_RDONLY);
  if (fd < 0) return -1;
  size_t off = 0;
  while (off < len) {
    ssize_t n = read(fd, buf + off, len - off);
    if (n <= 0) {
      close(fd);
      return -1;
    }
    off += (size_t)n;
  }
  close(fd);
  return 0;
#endif
}
