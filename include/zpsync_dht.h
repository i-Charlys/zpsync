#ifndef ZPSYNC_DHT_H
#define ZPSYNC_DHT_H

/**
 * @file zpsync_dht.h
 * @brief Zero-malloc Bencode codec & BitTorrent Mainline DHT (BEP 5 / BEP 44)
 *        rendezvous client for serverless peer discovery.
 *
 * Uses Node_ID = SHA1(S || utc_hour) across time windows [H-1, H, H+1] to locate
 * peers on the public Mainline DHT without any proprietary signaling server.
 */

#include "zpsync_crypto.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_DHT_NODE_ID_BYTES 20U
#define ZPSYNC_DHT_MAX_NODES 32U
#define ZPSYNC_DHT_MAX_PEERS 32U
#define ZPSYNC_DHT_MAX_TOKEN_LEN 64U
#define ZPSYNC_DHT_MAX_PACKET 1500U

/* ── Zero-malloc Bencode Writer ─────────────────────────────────────────── */

typedef struct {
  uint8_t *buf;
  size_t cap;
  size_t len;
  int err;
} zpsync_benc_writer_s;

void zpsync_benc_writer_init(zpsync_benc_writer_s *w, uint8_t *buf, size_t cap);
int zpsync_benc_write_int(zpsync_benc_writer_s *w, int64_t val);
int zpsync_benc_write_bytes(zpsync_benc_writer_s *w, const uint8_t *data, size_t len);
int zpsync_benc_write_str(zpsync_benc_writer_s *w, const char *s);
int zpsync_benc_begin_dict(zpsync_benc_writer_s *w);
int zpsync_benc_begin_list(zpsync_benc_writer_s *w);
int zpsync_benc_end(zpsync_benc_writer_s *w);

/* ── Zero-malloc Bencode Reader ─────────────────────────────────────────── */

typedef struct {
  const uint8_t *buf;
  size_t len;
  size_t pos;
} zpsync_benc_reader_s;

typedef enum {
  ZPSYNC_BENC_INT = 1,
  ZPSYNC_BENC_STR = 2,
  ZPSYNC_BENC_LIST = 3,
  ZPSYNC_BENC_DICT = 4
} zpsync_benc_type_e;

void zpsync_benc_reader_init(zpsync_benc_reader_s *r, const uint8_t *buf, size_t len);
int zpsync_benc_peek_type(const zpsync_benc_reader_s *r, zpsync_benc_type_e *out_type);
int zpsync_benc_read_int(zpsync_benc_reader_s *r, int64_t *out_val);
int zpsync_benc_read_bytes(zpsync_benc_reader_s *r, const uint8_t **out_ptr,
                           size_t *out_len);
int zpsync_benc_skip(zpsync_benc_reader_s *r);

/* ── Mainline DHT KRPC Structures ───────────────────────────────────────── */

typedef struct {
  uint8_t id[ZPSYNC_DHT_NODE_ID_BYTES];
  uint8_t ip[4];
  uint16_t port; /**< Host byte order */
} zpsync_dht_node_s;

typedef struct {
  uint8_t ip[4];
  uint16_t port; /**< Host byte order */
} zpsync_dht_peer_s;

typedef struct {
  uint8_t tx_id[8];
  size_t tx_id_len;
  uint8_t sender_id[ZPSYNC_DHT_NODE_ID_BYTES];
  uint8_t has_sender_id;
  uint8_t is_response; /**< 1 = 'r', 0 = other */
  uint8_t is_error;
  uint8_t token[ZPSYNC_DHT_MAX_TOKEN_LEN];
  size_t token_len;
  zpsync_dht_node_s nodes[ZPSYNC_DHT_MAX_NODES];
  size_t node_count;
  zpsync_dht_peer_s peers[ZPSYNC_DHT_MAX_PEERS];
  size_t peer_count;
  uint8_t bep44_v[256];
  size_t bep44_v_len;
} zpsync_dht_reply_s;

/**
 * @brief Encodes a KRPC `ping` query.
 */
int zpsync_dht_encode_ping(const uint8_t tx_id[2],
                           const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                           uint8_t *out_buf, size_t max_len);

/**
 * @brief Encodes a KRPC `find_node` query.
 */
int zpsync_dht_encode_find_node(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t target[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len);

/**
 * @brief Encodes a KRPC `get_peers` query for @p info_hash (Node_ID).
 */
int zpsync_dht_encode_get_peers(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t info_hash[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len);

/**
 * @brief Encodes a KRPC `announce_peer` query using a token from `get_peers`.
 */
int zpsync_dht_encode_announce_peer(const uint8_t tx_id[2],
                                    const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                    const uint8_t info_hash[ZPSYNC_DHT_NODE_ID_BYTES],
                                    uint16_t port, const uint8_t *token,
                                    size_t token_len, uint8_t *out_buf,
                                    size_t max_len);

/**
 * @brief Encodes a BEP 44 `get` query for an immutable/mutable item target.
 */
int zpsync_dht_encode_bep44_get(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t target[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len);

/**
 * @brief Parses a KRPC response packet into @p out_reply.
 */
int zpsync_dht_decode_reply(const uint8_t *pkt, size_t pkt_len,
                            zpsync_dht_reply_s *out_reply);

/**
 * @brief Runs an iterative Mainline DHT rendezvous across windows [H-1, H, H+1]
 *        to announce our local port and discover peer endpoints for secret S.
 *
 * @param secret Shared secret S.
 * @param secret_len Length of S.
 * @param local_announce_port Local UDP port to announce (e.g. STUN/RUDP port).
 * @param utc_now_s Current UTC Unix timestamp in seconds.
 * @param timeout_ms Total discovery budget in milliseconds.
 * @param out_peers Discovered peer IPv4:port candidates.
 * @param max_peers Capacity of @p out_peers.
 * @return Number of discovered peers (>= 0), or negative error code.
 */
int zpsync_dht_rendezvous(const uint8_t *secret, size_t secret_len,
                          uint16_t local_announce_port, uint64_t utc_now_s,
                          uint32_t timeout_ms, zpsync_dht_peer_s *out_peers,
                          size_t max_peers);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_DHT_H */
