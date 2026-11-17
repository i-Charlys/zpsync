#include "zpsync_crypto.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_sha1_nist(void) {
  /* SHA1("abc") = a9993e36 4706816a ba3e2571 7850c26c 9cd0d89d */
  static const uint8_t expected[20] = {0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81,
                                       0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50,
                                       0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d};
  uint8_t out[20];
  zpsync_sha1((const uint8_t *)"abc", 3, out);
  assert(memcmp(out, expected, 20) == 0);
}

static void test_sha256_nist(void) {
  /* SHA256("abc") = ba7816bf 8f01cfea 414140de 5dae2223 b00361a3 96177a9c b410ff61 f20015ad */
  static const uint8_t expected[32] = {
      0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40,
      0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17,
      0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad};
  uint8_t out[32];
  zpsync_sha256((const uint8_t *)"abc", 3, out);
  assert(memcmp(out, expected, 32) == 0);
}

static void test_determinism_and_mailbox(void) {
  const uint8_t secret[] = "zpsync-super-secret-session-code";
  size_t slen = sizeof(secret) - 1U;

  uint8_t id1[20], id2[20], id3[20];
  assert(zpsync_derive_dht_node_id(secret, slen, 490000ULL, id1) == 0);
  assert(zpsync_derive_dht_node_id(secret, slen, 490000ULL, id2) == 0);
  assert(zpsync_derive_dht_node_id(secret, slen, 490001ULL, id3) == 0);
  assert(memcmp(id1, id2, 20) == 0);
  assert(memcmp(id1, id3, 20) != 0);

  uint16_t p1 = zpsync_derive_target_port(secret, slen, 12345ULL);
  uint16_t p2 = zpsync_derive_target_port(secret, slen, 12345ULL);
  assert(p1 == p2);
  assert(p1 >= 10000U && p1 < 65000U);

  for (uint32_t i = 0; i < 500U; ++i) {
    uint16_t bp = zpsync_derive_birthday_port(secret, slen, i);
    assert(bp >= 10000U && bp <= 65534U);
  }

  uint8_t key[ZPSYNC_KEY_BYTES];
  assert(zpsync_derive_session_key(secret, slen, key) == 0);

  uint8_t nonce[ZPSYNC_NONCE_BYTES] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  zpsync_mailbox_s mb_in = {
      .ipv6 = {0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
      .ipv4 = {203, 0, 113, 42},
      .ipv4_port = 51234U,
      .local_port = p1,
      .has_ipv6 = 1,
      .has_ipv4 = 1,
      .nat_type = 2,
      .role_hint = 1,
      .timestamp_s = 1794872959ULL,
      .peer_nonce = 0x12345678ULL};

  uint8_t sealed[ZPSYNC_MAILBOX_SEALED_BYTES];
  assert(zpsync_mailbox_seal(key, nonce, &mb_in, sealed, sizeof(sealed)) ==
         (int)ZPSYNC_MAILBOX_SEALED_BYTES);

  zpsync_mailbox_s mb_out;
  assert(zpsync_mailbox_open(key, sealed, sizeof(sealed), &mb_out) == 0);
  assert(memcmp(mb_in.ipv6, mb_out.ipv6, 16) == 0);
  assert(memcmp(mb_in.ipv4, mb_out.ipv4, 4) == 0);
  assert(mb_out.ipv4_port == mb_in.ipv4_port);
  assert(mb_out.local_port == mb_in.local_port);
  assert(mb_out.timestamp_s == mb_in.timestamp_s);

  /* Tamper check */
  sealed[ZPSYNC_NONCE_BYTES + 5] ^= 0xFFU;
  assert(zpsync_mailbox_open(key, sealed, sizeof(sealed), &mb_out) != 0);
}

int main(void) {
  test_sha1_nist();
  test_sha256_nist();
  test_determinism_and_mailbox();
  printf("test_crypto_derivation: PASS\n");
  return 0;
}
