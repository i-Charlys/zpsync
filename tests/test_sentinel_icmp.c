#include "zpsync_sentinel.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  const uint8_t secret[] = "sentinel-shared-secret";
  uint8_t key[ZPSYNC_KEY_BYTES];
  assert(zpsync_derive_session_key(secret, sizeof(secret) - 1U, key) == 0);

  uint8_t nonce[ZPSYNC_NONCE_BYTES] = {9, 8, 7, 6, 5, 4, 3, 2, 1, 0, 11, 22};
  zpsync_sentinel_info_s info_in = {.timestamp_ms = 123456789ULL,
                                    .flow_entropy = 0xCAFEBABEU,
                                    .session_salt = 0x11223344U,
                                    .udp_port = 42424U,
                                    .dscp = 46U,
                                    .flags = 1U};

  uint8_t icmp[ZPSYNC_SENTINEL_ICMP_BYTES];
  int len = zpsync_sentinel_build_icmp(key, 0x1234U, 1U, nonce, &info_in, icmp,
                                       sizeof(icmp));
  assert(len == (int)ZPSYNC_SENTINEL_ICMP_BYTES);
  assert(zpsync_icmp_checksum(icmp, sizeof(icmp)) == 0);

  zpsync_sentinel_info_s info_out;
  assert(zpsync_sentinel_parse_icmp(key, icmp, sizeof(icmp), &info_out) == 0);
  assert(info_out.timestamp_ms == info_in.timestamp_ms);
  assert(info_out.flow_entropy == info_in.flow_entropy);
  assert(info_out.session_salt == info_in.session_salt);
  assert(info_out.udp_port == info_in.udp_port);
  assert(info_out.dscp == info_in.dscp);
  assert(info_out.flags == info_in.flags);

  /* Test IPv4-wrapped raw socket packet stripping (20B IP header + 60B ICMP) */
  uint8_t wrapped[20U + ZPSYNC_SENTINEL_ICMP_BYTES];
  memset(wrapped, 0, 20);
  wrapped[0] = 0x45U; /* IPv4, IHL=5 (20 bytes) */
  wrapped[9] = 1U;    /* IPPROTO_ICMP */
  memcpy(wrapped + 20, icmp, sizeof(icmp));
  assert(zpsync_sentinel_parse_icmp(key, wrapped, sizeof(wrapped), &info_out) == 0);

  /* Wrong key must fail */
  uint8_t wrong_key[ZPSYNC_KEY_BYTES];
  memcpy(wrong_key, key, sizeof(key));
  wrong_key[0] ^= 0x01U;
  assert(zpsync_sentinel_parse_icmp(wrong_key, icmp, sizeof(icmp), &info_out) != 0);

  /* Tampered payload must fail */
  icmp[20] ^= 0x80U;
  assert(zpsync_sentinel_parse_icmp(key, icmp, sizeof(icmp), &info_out) != 0);

  printf("test_sentinel_icmp: PASS\n");
  return 0;
}
