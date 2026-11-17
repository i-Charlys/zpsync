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

static void test_x25519_rfc7748(void) {
  /* RFC 7748 Section 6.1 Alice & Bob test vector */
  static const uint8_t alice_priv[32] = {
      0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d, 0x3c, 0x16, 0xc1,
      0x72, 0x51, 0xb2, 0x66, 0x45, 0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0,
      0x99, 0x2a, 0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a};
  static const uint8_t alice_pub_expected[32] = {
      0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54, 0x74, 0x8b, 0x7d,
      0xdc, 0xb4, 0x3e, 0xf7, 0x5a, 0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38,
      0x1a, 0xf4, 0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a};
  static const uint8_t bob_priv[32] = {
      0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b, 0x79, 0xe1, 0x7f,
      0x8b, 0x83, 0x80, 0x0e, 0xe6, 0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18,
      0xb6, 0xfd, 0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb};
  static const uint8_t bob_pub_expected[32] = {
      0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4, 0xd3, 0x5b, 0x61,
      0xc2, 0xec, 0xe4, 0x35, 0x37, 0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78,
      0x67, 0x4d, 0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f};
  static const uint8_t shared_expected[32] = {
      0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1, 0x72, 0x8e, 0x3b,
      0xf4, 0x80, 0x35, 0x0f, 0x25, 0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1,
      0x9e, 0x33, 0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42};
  static const uint8_t basepoint[32] = {9};

  uint8_t alice_pub[32], bob_pub[32], s1[32], s2[32];
  zpsync_x25519(alice_pub, alice_priv, basepoint);
  zpsync_x25519(bob_pub, bob_priv, basepoint);
  assert(memcmp(alice_pub, alice_pub_expected, 32) == 0);
  assert(memcmp(bob_pub, bob_pub_expected, 32) == 0);

  assert(zpsync_x25519_shared(alice_priv, bob_pub, s1) == 0);
  assert(zpsync_x25519_shared(bob_priv, alice_pub, s2) == 0);
  assert(memcmp(s1, shared_expected, 32) == 0);
  assert(memcmp(s2, shared_expected, 32) == 0);

  /* Low-order point (all-zero) must be rejected */
  uint8_t zero_pub[32] = {0};
  assert(zpsync_x25519_shared(alice_priv, zero_pub, s1) != 0);

  /* Keygen + PFS key derivation */
  uint8_t kp1[32], pub1[32], kp2[32], pub2[32], sh1[32], sh2[32];
  assert(zpsync_x25519_keygen(kp1, pub1) == 0);
  assert(zpsync_x25519_keygen(kp2, pub2) == 0);
  assert(zpsync_x25519_shared(kp1, pub2, sh1) == 0);
  assert(zpsync_x25519_shared(kp2, pub1, sh2) == 0);
  assert(memcmp(sh1, sh2, 32) == 0);

  uint8_t base[32] = {0x42}, pfs1[32], pfs2[32];
  assert(zpsync_derive_pfs_key(base, sh1, 0x123456789ABCDEF0ULL, pfs1) == 0);
  assert(zpsync_derive_pfs_key(base, sh2, 0x123456789ABCDEF0ULL, pfs2) == 0);
  assert(memcmp(pfs1, pfs2, 32) == 0);
}

int main(void) {
  test_sha1_nist();
  test_sha256_nist();
  test_determinism_and_mailbox();
  test_x25519_rfc7748();
  printf("test_crypto_derivation: PASS\n");
  return 0;
}
