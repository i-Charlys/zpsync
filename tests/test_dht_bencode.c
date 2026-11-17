#include "zpsync_dht.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

static void test_bencode_roundtrip(void) {
  uint8_t buf[256];
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, buf, sizeof(buf));
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "k1");
  zpsync_benc_write_int(&w, -42);
  zpsync_benc_write_str(&w, "k2");
  zpsync_benc_begin_list(&w);
  zpsync_benc_write_str(&w, "hello");
  zpsync_benc_write_int(&w, 1337);
  zpsync_benc_end(&w);
  zpsync_benc_end(&w);
  assert(w.err == 0);

  zpsync_benc_reader_s r;
  zpsync_benc_reader_init(&r, buf, w.len);
  zpsync_benc_type_e ty;
  assert(zpsync_benc_peek_type(&r, &ty) == 0 && ty == ZPSYNC_BENC_DICT);
  assert(zpsync_benc_skip(&r) == 0);
  assert(r.pos == w.len);
}

static void test_krpc_encode_decode(void) {
  uint8_t self_id[20];
  uint8_t info_hash[20];
  memset(self_id, 0xAA, 20);
  memset(info_hash, 0xBB, 20);
  uint8_t tx[2] = {'a', 'b'};

  uint8_t pkt[256];
  int len = zpsync_dht_encode_get_peers(tx, self_id, info_hash, pkt, sizeof(pkt));
  assert(len > 20);
  len = zpsync_dht_encode_announce_peer(tx, self_id, info_hash, 51820,
                                        (const uint8_t *)"tok1", 4, pkt,
                                        sizeof(pkt));
  assert(len > 20);

  /* Build a synthetic KRPC response with 1 node (26B) + 1 peer (6B) + token */
  uint8_t rep_buf[256];
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, rep_buf, sizeof(rep_buf));
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "r");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, 20);
  uint8_t node26[26];
  memset(node26, 0xCC, 20);
  node26[20] = 192;
  node26[21] = 0;
  node26[22] = 2;
  node26[23] = 10;
  node26[24] = 0x1A;
  node26[25] = 0xE1; /* port 6881 */
  zpsync_benc_write_str(&w, "nodes");
  zpsync_benc_write_bytes(&w, node26, 26);
  zpsync_benc_write_str(&w, "token");
  zpsync_benc_write_str(&w, "mytok");
  zpsync_benc_write_str(&w, "values");
  zpsync_benc_begin_list(&w);
  uint8_t peer6[6] = {198, 51, 100, 77, 0xC3, 0x50}; /* 198.51.100.77:50000 */
  zpsync_benc_write_bytes(&w, peer6, 6);
  zpsync_benc_end(&w);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "r");
  zpsync_benc_end(&w);
  assert(w.err == 0);

  zpsync_dht_reply_s rep;
  assert(zpsync_dht_decode_reply(rep_buf, w.len, &rep) == 0);
  assert(rep.is_response == 1);
  assert(rep.node_count == 1);
  assert(rep.nodes[0].port == 6881U);
  assert(rep.peer_count == 1);
  assert(rep.peers[0].ip[0] == 198 && rep.peers[0].port == 50000U);
  assert(rep.token_len == 5 && memcmp(rep.token, "mytok", 5) == 0);

  /* Kademlia XOR distance comparison */
  uint8_t target[20] = {0};
  uint8_t closer[20] = {0};
  uint8_t farther[20] = {0};
  closer[19] = 0x01U;
  farther[0] = 0x80U;
  assert(zpsync_dht_xor_cmp(target, closer, farther) < 0);
  assert(zpsync_dht_xor_cmp(target, farther, closer) > 0);
  assert(zpsync_dht_xor_cmp(target, closer, closer) == 0);

  /* BEP 44 immutable put */
  uint8_t put_pkt[256];
  uint8_t payload[68] = {0x42};
  int put_len = zpsync_dht_encode_bep44_put_imm(
      tx, self_id, (const uint8_t *)"tok1", 4, payload, sizeof(payload),
      put_pkt, sizeof(put_pkt));
  assert(put_len > 80);
}

int main(void) {
  test_bencode_roundtrip();
  test_krpc_encode_decode();
  printf("test_dht_bencode: PASS\n");
  return 0;
}
