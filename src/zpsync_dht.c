#include "zpsync_dht.h"
#include "zpsync_net.h"

#include <stdio.h>
#include <string.h>

/* ── Zero-malloc Bencode Writer ─────────────────────────────────────────── */

static void benc_put_raw(zpsync_benc_writer_s *w, const void *data, size_t len) {
  if (w == NULL || w->err) return;
  if (w->len + len > w->cap) {
    w->err = -1;
    return;
  }
  memcpy(w->buf + w->len, data, len);
  w->len += len;
}

void zpsync_benc_writer_init(zpsync_benc_writer_s *w, uint8_t *buf, size_t cap) {
  w->buf = buf;
  w->cap = cap;
  w->len = 0;
  w->err = (buf == NULL) ? -1 : 0;
}

int zpsync_benc_write_int(zpsync_benc_writer_s *w, int64_t val) {
  char tmp[32];
  int n = snprintf(tmp, sizeof(tmp), "i%llde", (long long)val);
  if (n <= 0 || (size_t)n >= sizeof(tmp)) {
    w->err = -1;
    return -1;
  }
  benc_put_raw(w, tmp, (size_t)n);
  return w->err;
}

int zpsync_benc_write_bytes(zpsync_benc_writer_s *w, const uint8_t *data, size_t len) {
  char hdr[24];
  int n = snprintf(hdr, sizeof(hdr), "%zu:", len);
  if (n <= 0 || (size_t)n >= sizeof(hdr)) {
    w->err = -1;
    return -1;
  }
  benc_put_raw(w, hdr, (size_t)n);
  if (len > 0) benc_put_raw(w, data, len);
  return w->err;
}

int zpsync_benc_write_str(zpsync_benc_writer_s *w, const char *s) {
  if (s == NULL) return -1;
  return zpsync_benc_write_bytes(w, (const uint8_t *)s, strlen(s));
}

int zpsync_benc_begin_dict(zpsync_benc_writer_s *w) {
  benc_put_raw(w, "d", 1);
  return w->err;
}

int zpsync_benc_begin_list(zpsync_benc_writer_s *w) {
  benc_put_raw(w, "l", 1);
  return w->err;
}

int zpsync_benc_end(zpsync_benc_writer_s *w) {
  benc_put_raw(w, "e", 1);
  return w->err;
}

/* ── Zero-malloc Bencode Reader ─────────────────────────────────────────── */

void zpsync_benc_reader_init(zpsync_benc_reader_s *r, const uint8_t *buf, size_t len) {
  r->buf = buf;
  r->len = len;
  r->pos = 0;
}

int zpsync_benc_peek_type(const zpsync_benc_reader_s *r, zpsync_benc_type_e *out_type) {
  if (r == NULL || out_type == NULL || r->pos >= r->len) return -1;
  uint8_t c = r->buf[r->pos];
  if (c == 'i') {
    *out_type = ZPSYNC_BENC_INT;
    return 0;
  }
  if (c == 'l') {
    *out_type = ZPSYNC_BENC_LIST;
    return 0;
  }
  if (c == 'd') {
    *out_type = ZPSYNC_BENC_DICT;
    return 0;
  }
  if (c >= '0' && c <= '9') {
    *out_type = ZPSYNC_BENC_STR;
    return 0;
  }
  return -1;
}

int zpsync_benc_read_int(zpsync_benc_reader_s *r, int64_t *out_val) {
  if (r == NULL || out_val == NULL || r->pos >= r->len || r->buf[r->pos] != 'i') {
    return -1;
  }
  size_t p = r->pos + 1;
  bool neg = false;
  if (p < r->len && r->buf[p] == '-') {
    neg = true;
    ++p;
  }
  if (p >= r->len || r->buf[p] < '0' || r->buf[p] > '9') return -1;
  uint64_t acc = 0;
  while (p < r->len && r->buf[p] >= '0' && r->buf[p] <= '9') {
    acc = acc * 10ULL + (uint64_t)(r->buf[p] - '0');
    ++p;
  }
  if (p >= r->len || r->buf[p] != 'e') return -1;
  r->pos = p + 1;
  *out_val = neg ? -(int64_t)acc : (int64_t)acc;
  return 0;
}

int zpsync_benc_read_bytes(zpsync_benc_reader_s *r, const uint8_t **out_ptr,
                           size_t *out_len) {
  if (r == NULL || out_ptr == NULL || out_len == NULL || r->pos >= r->len) {
    return -1;
  }
  size_t p = r->pos;
  if (r->buf[p] < '0' || r->buf[p] > '9') return -1;
  size_t slen = 0;
  while (p < r->len && r->buf[p] >= '0' && r->buf[p] <= '9') {
    slen = slen * 10U + (size_t)(r->buf[p] - '0');
    if (slen > r->len) return -1;
    ++p;
  }
  if (p >= r->len || r->buf[p] != ':') return -1;
  ++p;
  if (p + slen > r->len) return -1;
  *out_ptr = r->buf + p;
  *out_len = slen;
  r->pos = p + slen;
  return 0;
}

int zpsync_benc_skip(zpsync_benc_reader_s *r) {
  if (r == NULL || r->pos >= r->len) return -1;
  uint8_t c = r->buf[r->pos];
  if (c == 'i') {
    int64_t dummy = 0;
    return zpsync_benc_read_int(r, &dummy);
  }
  if (c >= '0' && c <= '9') {
    const uint8_t *p = NULL;
    size_t l = 0;
    return zpsync_benc_read_bytes(r, &p, &l);
  }
  if (c == 'l' || c == 'd') {
    ++r->pos;
    while (r->pos < r->len && r->buf[r->pos] != 'e') {
      if (zpsync_benc_skip(r) != 0) return -1;
    }
    if (r->pos >= r->len || r->buf[r->pos] != 'e') return -1;
    ++r->pos;
    return 0;
  }
  return -1;
}

/* ── KRPC Encoders ──────────────────────────────────────────────────────── */

int zpsync_dht_encode_ping(const uint8_t tx_id[2],
                           const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                           uint8_t *out_buf, size_t max_len) {
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "ping");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_encode_find_node(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t target[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len) {
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "target");
  zpsync_benc_write_bytes(&w, target, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "find_node");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_encode_get_peers(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t info_hash[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len) {
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "info_hash");
  zpsync_benc_write_bytes(&w, info_hash, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "get_peers");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_encode_announce_peer(const uint8_t tx_id[2],
                                    const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                    const uint8_t info_hash[ZPSYNC_DHT_NODE_ID_BYTES],
                                    uint16_t port, const uint8_t *token,
                                    size_t token_len, uint8_t *out_buf,
                                    size_t max_len) {
  if (token == NULL || token_len == 0) return -1;
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "implied_port");
  zpsync_benc_write_int(&w, port == 0 ? 1 : 0);
  zpsync_benc_write_str(&w, "info_hash");
  zpsync_benc_write_bytes(&w, info_hash, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "port");
  zpsync_benc_write_int(&w, (int64_t)port);
  zpsync_benc_write_str(&w, "token");
  zpsync_benc_write_bytes(&w, token, token_len);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "announce_peer");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_encode_bep44_get(const uint8_t tx_id[2],
                                const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                const uint8_t target[ZPSYNC_DHT_NODE_ID_BYTES],
                                uint8_t *out_buf, size_t max_len) {
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "target");
  zpsync_benc_write_bytes(&w, target, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "get");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_encode_bep44_put_imm(const uint8_t tx_id[2],
                                    const uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES],
                                    const uint8_t *token, size_t token_len,
                                    const uint8_t *value, size_t value_len,
                                    uint8_t *out_buf, size_t max_len) {
  if (token == NULL || token_len == 0 || value == NULL || value_len == 0) {
    return -1;
  }
  zpsync_benc_writer_s w;
  zpsync_benc_writer_init(&w, out_buf, max_len);
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "a");
  zpsync_benc_begin_dict(&w);
  zpsync_benc_write_str(&w, "id");
  zpsync_benc_write_bytes(&w, self_id, ZPSYNC_DHT_NODE_ID_BYTES);
  zpsync_benc_write_str(&w, "token");
  zpsync_benc_write_bytes(&w, token, token_len);
  zpsync_benc_write_str(&w, "v");
  zpsync_benc_write_bytes(&w, value, value_len);
  zpsync_benc_end(&w);
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_write_str(&w, "put");
  zpsync_benc_write_str(&w, "t");
  zpsync_benc_write_bytes(&w, tx_id, 2);
  zpsync_benc_write_str(&w, "y");
  zpsync_benc_write_str(&w, "q");
  zpsync_benc_end(&w);
  return w.err == 0 ? (int)w.len : -1;
}

int zpsync_dht_xor_cmp(const uint8_t target[ZPSYNC_DHT_NODE_ID_BYTES],
                       const uint8_t a[ZPSYNC_DHT_NODE_ID_BYTES],
                       const uint8_t b[ZPSYNC_DHT_NODE_ID_BYTES]) {
  for (size_t i = 0; i < ZPSYNC_DHT_NODE_ID_BYTES; ++i) {
    uint8_t da = (uint8_t)(target[i] ^ a[i]);
    uint8_t db = (uint8_t)(target[i] ^ b[i]);
    if (da < db) return -1;
    if (da > db) return 1;
  }
  return 0;
}

/* ── KRPC Reply Decoder ─────────────────────────────────────────────────── */

static bool key_eq(const uint8_t *k, size_t klen, const char *lit) {
  size_t llen = strlen(lit);
  return klen == llen && memcmp(k, lit, llen) == 0;
}

static int parse_r_dict(zpsync_benc_reader_s *r, zpsync_dht_reply_s *rep) {
  if (r->pos >= r->len || r->buf[r->pos] != 'd') return -1;
  ++r->pos;
  while (r->pos < r->len && r->buf[r->pos] != 'e') {
    const uint8_t *k = NULL;
    size_t klen = 0;
    if (zpsync_benc_read_bytes(r, &k, &klen) != 0) return -1;

    if (key_eq(k, klen, "id")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(r, &v, &vlen) != 0) return -1;
      if (vlen == ZPSYNC_DHT_NODE_ID_BYTES) {
        memcpy(rep->sender_id, v, ZPSYNC_DHT_NODE_ID_BYTES);
        rep->has_sender_id = 1;
      }
    } else if (key_eq(k, klen, "token")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(r, &v, &vlen) != 0) return -1;
      if (vlen <= ZPSYNC_DHT_MAX_TOKEN_LEN) {
        memcpy(rep->token, v, vlen);
        rep->token_len = vlen;
      }
    } else if (key_eq(k, klen, "nodes")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(r, &v, &vlen) != 0) return -1;
      for (size_t off = 0; off + 26U <= vlen && rep->node_count < ZPSYNC_DHT_MAX_NODES;
           off += 26U) {
        zpsync_dht_node_s *nd = &rep->nodes[rep->node_count++];
        memcpy(nd->id, v + off, 20);
        memcpy(nd->ip, v + off + 20, 4);
        nd->port = (uint16_t)(((uint16_t)v[off + 24] << 8) | (uint16_t)v[off + 25]);
      }
    } else if (key_eq(k, klen, "values")) {
      if (r->pos >= r->len || r->buf[r->pos] != 'l') {
        if (zpsync_benc_skip(r) != 0) return -1;
      } else {
        ++r->pos;
        while (r->pos < r->len && r->buf[r->pos] != 'e') {
          const uint8_t *v = NULL;
          size_t vlen = 0;
          if (zpsync_benc_read_bytes(r, &v, &vlen) != 0) return -1;
          if (vlen == 6U && rep->peer_count < ZPSYNC_DHT_MAX_PEERS) {
            zpsync_dht_peer_s *pr = &rep->peers[rep->peer_count++];
            memcpy(pr->ip, v, 4);
            pr->port = (uint16_t)(((uint16_t)v[4] << 8) | (uint16_t)v[5]);
          }
        }
        if (r->pos >= r->len || r->buf[r->pos] != 'e') return -1;
        ++r->pos;
      }
    } else if (key_eq(k, klen, "v")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(r, &v, &vlen) == 0 &&
          vlen <= sizeof(rep->bep44_v)) {
        memcpy(rep->bep44_v, v, vlen);
        rep->bep44_v_len = vlen;
      }
    } else {
      if (zpsync_benc_skip(r) != 0) return -1;
    }
  }
  if (r->pos >= r->len || r->buf[r->pos] != 'e') return -1;
  ++r->pos;
  return 0;
}

int zpsync_dht_decode_reply(const uint8_t *pkt, size_t pkt_len,
                            zpsync_dht_reply_s *out_reply) {
  if (pkt == NULL || pkt_len < 2 || out_reply == NULL) return -1;
  memset(out_reply, 0, sizeof(*out_reply));

  zpsync_benc_reader_s r;
  zpsync_benc_reader_init(&r, pkt, pkt_len);
  if (r.buf[r.pos] != 'd') return -1;
  ++r.pos;

  while (r.pos < r.len && r.buf[r.pos] != 'e') {
    const uint8_t *k = NULL;
    size_t klen = 0;
    if (zpsync_benc_read_bytes(&r, &k, &klen) != 0) return -1;

    if (key_eq(k, klen, "t")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(&r, &v, &vlen) != 0) return -1;
      if (vlen <= sizeof(out_reply->tx_id)) {
        memcpy(out_reply->tx_id, v, vlen);
        out_reply->tx_id_len = vlen;
      }
    } else if (key_eq(k, klen, "y")) {
      const uint8_t *v = NULL;
      size_t vlen = 0;
      if (zpsync_benc_read_bytes(&r, &v, &vlen) != 0) return -1;
      if (vlen == 1 && v[0] == 'r') out_reply->is_response = 1;
      if (vlen == 1 && v[0] == 'e') out_reply->is_error = 1;
    } else if (key_eq(k, klen, "r")) {
      if (parse_r_dict(&r, out_reply) != 0) return -1;
    } else {
      if (zpsync_benc_skip(&r) != 0) return -1;
    }
  }
  return out_reply->is_response ? 0 : -1;
}

/* ── Mainline DHT Iterative Rendezvous ──────────────────────────────────── */

static const char *const DHT_BOOTSTRAPS[] = {
    "router.bittorrent.com",
    "dht.transmissionbt.com",
    "router.utorrent.com",
    "dht.aelitis.com",
};

static void insert_sorted_node(zpsync_dht_node_s *frontier, size_t *count,
                               size_t cap, const uint8_t target[20],
                               const zpsync_dht_node_s *cand, size_t min_pos) {
  for (size_t i = 0; i < *count; ++i) {
    if (memcmp(frontier[i].ip, cand->ip, 4) == 0 && frontier[i].port == cand->port) {
      return;
    }
  }
  size_t pos = *count;
  while (pos > min_pos &&
         zpsync_dht_xor_cmp(target, cand->id, frontier[pos - 1].id) < 0) {
    --pos;
  }
  if (pos >= cap) return;
  size_t end = (*count < cap) ? (*count) : (cap - 1U);
  for (size_t i = end; i > pos; --i) {
    frontier[i] = frontier[i - 1U];
  }
  frontier[pos] = *cand;
  if (*count < cap) ++(*count);
}

static void add_unique_peer(zpsync_dht_peer_s *peers, size_t *count, size_t max_peers,
                            const zpsync_dht_peer_s *cand) {
  if (*count >= max_peers || cand->port == 0) return;
  for (size_t i = 0; i < *count; ++i) {
    if (memcmp(peers[i].ip, cand->ip, 4) == 0 && peers[i].port == cand->port) {
      return;
    }
  }
  peers[(*count)++] = *cand;
}

int zpsync_dht_rendezvous(const uint8_t *secret, size_t secret_len,
                          uint16_t local_announce_port, uint64_t utc_now_s,
                          uint32_t timeout_ms, zpsync_dht_peer_s *out_peers,
                          size_t max_peers) {
  if (secret == NULL || secret_len == 0 || out_peers == NULL || max_peers == 0) {
    return -1;
  }

  uint8_t self_id[ZPSYNC_DHT_NODE_ID_BYTES];
  if (zpsync_random_bytes(self_id, sizeof(self_id)) != 0) {
    zpsync_sha1(secret, secret_len, self_id);
  }

  /* Compute Node_IDs for [H-1, H, H+1] */
  uint64_t hour = utc_now_s / 3600ULL;
  uint8_t info_hashes[3][ZPSYNC_DHT_NODE_ID_BYTES];
  zpsync_derive_dht_node_id(secret, secret_len, hour > 0 ? hour - 1ULL : 0ULL,
                            info_hashes[0]);
  zpsync_derive_dht_node_id(secret, secret_len, hour, info_hashes[1]);
  zpsync_derive_dht_node_id(secret, secret_len, hour + 1ULL, info_hashes[2]);

  zpsync_sock_t sock = zpsync_udp_open(4, 0, true, true, NULL);
  if (sock == ZPSYNC_INVALID_SOCK) return -1;

  /* Seed frontier with public Mainline DHT bootstrap nodes */
  zpsync_dht_node_s frontier[64];
  size_t frontier_count = 0;
  for (size_t i = 0; i < sizeof(DHT_BOOTSTRAPS) / sizeof(DHT_BOOTSTRAPS[0]); ++i) {
    uint8_t fam = 0;
    uint8_t addr[16];
    if (zpsync_resolve_host(DHT_BOOTSTRAPS[i], 4, &fam, addr) == 0 && fam == 4 &&
        frontier_count < 64U) {
      memset(&frontier[frontier_count], 0, sizeof(frontier[frontier_count]));
      memcpy(frontier[frontier_count].ip, addr, 4);
      frontier[frontier_count].port = 6881U;
      ++frontier_count;
    }
  }

  if (frontier_count == 0) {
    zpsync_sock_close(sock);
    return 0;
  }

  size_t peer_count = 0;
  uint64_t deadline = zpsync_now_ms() + (timeout_ms > 0 ? timeout_ms : 4000U);
  uint16_t tx_seq = 1;
  size_t next_node_idx = 0;

  while (zpsync_now_ms() < deadline) {
    /* Query up to 4 frontier nodes per burst across H, H-1, H+1 */
    for (int burst = 0; burst < 4 && next_node_idx < frontier_count; ++burst) {
      const zpsync_dht_node_s *nd = &frontier[next_node_idx++];
      for (size_t w = 0; w < 3; ++w) {
        uint8_t pkt[256];
        uint8_t tx_id[2] = {(uint8_t)(tx_seq >> 8), (uint8_t)(tx_seq & 0xFFU)};
        ++tx_seq;
        int len = zpsync_dht_encode_get_peers(tx_id, self_id, info_hashes[w], pkt,
                                              sizeof(pkt));
        if (len > 0) {
          uint8_t addr16[16] = {0};
          memcpy(addr16, nd->ip, 4);
          zpsync_udp_sendto(sock, 4, addr16, nd->port, pkt, (size_t)len);
        }
      }
    }

    uint8_t ready = 0;
    uint64_t now = zpsync_now_ms();
    if (now >= deadline) break;
    uint32_t rem = (uint32_t)(deadline - now);
    uint32_t wait_ms = rem < 120U ? rem : 120U;
    if (zpsync_poll_readable(&sock, 1, wait_ms, &ready) > 0 && (ready & 1U)) {
      for (int drain = 0; drain < 16; ++drain) {
        uint8_t rx[ZPSYNC_DHT_MAX_PACKET];
        uint8_t src_fam = 0;
        uint8_t src_ip[16];
        uint16_t src_port = 0;
        int n = zpsync_udp_recvfrom(sock, &src_fam, src_ip, &src_port, rx, sizeof(rx));
        if (n <= 0) break;

        zpsync_dht_reply_s rep;
        if (zpsync_dht_decode_reply(rx, (size_t)n, &rep) == 0) {
          for (size_t p = 0; p < rep.peer_count; ++p) {
            add_unique_peer(out_peers, &peer_count, max_peers, &rep.peers[p]);
          }
          for (size_t k = 0; k < rep.node_count; ++k) {
            insert_sorted_node(frontier, &frontier_count, 64U, info_hashes[1],
                               &rep.nodes[k], next_node_idx);
          }
          if (rep.token_len > 0 && local_announce_port > 0) {
            uint8_t apkt[256];
            uint8_t tx_id[2] = {(uint8_t)(tx_seq >> 8), (uint8_t)(tx_seq & 0xFFU)};
            ++tx_seq;
            int alen = zpsync_dht_encode_announce_peer(
                tx_id, self_id, info_hashes[1], local_announce_port, rep.token,
                rep.token_len, apkt, sizeof(apkt));
            if (alen > 0) {
              zpsync_udp_sendto(sock, 4, src_ip, src_port, apkt, (size_t)alen);
            }
          }
        }
      }
    } else if (next_node_idx >= frontier_count) {
      break;
    }
  }

  zpsync_sock_close(sock);
  return (int)peer_count;
}
