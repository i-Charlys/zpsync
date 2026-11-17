#include "zpsync_stun.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

int main(void) {
  uint8_t tx_id[12] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12};
  uint8_t req[20];
  assert(zpsync_stun_build_binding_request(tx_id, req, sizeof(req)) == 20);
  assert(req[0] == 0x00 && req[1] == 0x01);

  /* Synthetic STUN Binding Response with XOR-MAPPED-ADDRESS 203.0.113.5:41234 */
  /* 41234 (0xA112) ^ 0x2112 = 0x8000 */
  /* 203.0.113.5 (0xCB007105) ^ 0x2112A442 = 0xEA12D547 */
  uint8_t resp[32] = {
      0x01, 0x01, 0x00, 0x0C, /* Binding Response, len 12 */
      0x21, 0x12, 0xA4, 0x42, /* Magic cookie */
      1,    2,    3,    4,    5, 6, 7, 8, 9, 10, 11, 12, /* tx_id */
      0x00, 0x20, 0x00, 0x08, /* XOR-MAPPED-ADDRESS, len 8 */
      0x00, 0x01, 0x80, 0x00, /* IPv4, xport */
      0xEA, 0x12, 0xD5, 0x47  /* xip */
  };

  zpsync_mapped_addr_s mapped;
  assert(zpsync_stun_parse_binding_response(tx_id, resp, sizeof(resp), &mapped) == 0);
  assert(mapped.valid == 1 && mapped.family == 4);
  assert(mapped.port == 41234U);
  assert(mapped.addr[0] == 203 && mapped.addr[1] == 0 && mapped.addr[2] == 113 &&
         mapped.addr[3] == 5);

  /* Wrong tx_id must be rejected */
  uint8_t bad_tx[12] = {0};
  assert(zpsync_stun_parse_binding_response(bad_tx, resp, sizeof(resp), &mapped) != 0);

  printf("test_stun_codec: PASS\n");
  return 0;
}
