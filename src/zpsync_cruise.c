#include "zpsync_cruise.h"
#include "zpsync_net.h"

#include <string.h>

static void write_be16(uint8_t *p, uint16_t v) {
  p[0] = (uint8_t)(v >> 8);
  p[1] = (uint8_t)v;
}

static void write_be32(uint8_t *p, uint32_t v) {
  p[0] = (uint8_t)(v >> 24);
  p[1] = (uint8_t)(v >> 16);
  p[2] = (uint8_t)(v >> 8);
  p[3] = (uint8_t)v;
}

static uint16_t read_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

/* ── GF(2^8) Arithmetic (Primitive Polynomial 0x11D) ────────────────────── */

static uint8_t gf_mul(uint8_t a, uint8_t b) {
  uint8_t p = 0;
  for (int i = 0; i < 8; ++i) {
    if (b & 1U) p ^= a;
    uint8_t hi = (uint8_t)(a & 0x80U);
    a <<= 1;
    if (hi) a ^= 0x1DU;
    b >>= 1;
  }
  return p;
}

static uint8_t gf_pow(uint8_t a, uint8_t e) {
  uint8_t r = 1;
  while (e > 0) {
    if (e & 1U) r = gf_mul(r, a);
    a = gf_mul(a, a);
    e >>= 1;
  }
  return r;
}

static uint8_t gf_inv(uint8_t a) { return a == 0 ? 0 : gf_pow(a, 254U); }

static uint8_t cauchy_coeff(uint8_t parity_idx, uint16_t data_idx) {
  /* x_i = 64 + i, y_j = j -> x_i ^ y_j != 0 and all pairwise distinct => MDS */
  return gf_inv((uint8_t)((64U + data_idx) ^ parity_idx));
}

int zpsync_fec_encode(const uint8_t data[][ZPSYNC_CRUISE_MTU],
                      const uint16_t data_lens[], uint16_t k,
                      uint16_t max_frag_len, uint8_t parity_shards,
                      uint8_t out_parity[][ZPSYNC_CRUISE_MTU]) {
  if (data == NULL || data_lens == NULL || out_parity == NULL || k == 0 ||
      k > ZPSYNC_CRUISE_MAX_FRAGS || parity_shards == 0 ||
      parity_shards > ZPSYNC_CRUISE_MAX_PARITY ||
      max_frag_len > ZPSYNC_CRUISE_MTU) {
    return -1;
  }

  for (uint8_t p = 0; p < parity_shards; ++p) {
    memset(out_parity[p], 0, max_frag_len);
    for (uint16_t i = 0; i < k; ++i) {
      uint8_t c = cauchy_coeff(p, i);
      uint16_t len = data_lens[i] < max_frag_len ? data_lens[i] : max_frag_len;
      for (uint16_t b = 0; b < len; ++b) {
        out_parity[p][b] ^= gf_mul(c, data[i][b]);
      }
    }
  }
  return 0;
}

int zpsync_fec_decode(uint8_t data[][ZPSYNC_CRUISE_MTU], uint16_t data_lens[],
                      uint8_t data_present[], uint16_t k, uint16_t max_frag_len,
                      uint16_t last_frag_len,
                      const uint8_t parity[][ZPSYNC_CRUISE_MTU],
                      const uint8_t parity_present[], uint8_t max_parity) {
  if (data == NULL || data_lens == NULL || data_present == NULL ||
      parity == NULL || parity_present == NULL || k == 0 ||
      k > ZPSYNC_CRUISE_MAX_FRAGS || max_parity > ZPSYNC_CRUISE_MAX_PARITY ||
      max_frag_len > ZPSYNC_CRUISE_MTU) {
    return -1;
  }

  uint16_t missing_idx[ZPSYNC_CRUISE_MAX_PARITY];
  uint8_t m = 0;
  for (uint16_t i = 0; i < k; ++i) {
    if (!data_present[i]) {
      if (m >= max_parity) return -1;
      missing_idx[m++] = i;
    }
  }
  if (m == 0) return 0;

  uint8_t avail_par[ZPSYNC_CRUISE_MAX_PARITY];
  uint8_t pcount = 0;
  for (uint8_t p = 0; p < max_parity && pcount < m; ++p) {
    if (parity_present[p]) avail_par[pcount++] = p;
  }
  if (pcount < m) return -1;

  /* Build m x m Cauchy submatrix A and invert via Gauss-Jordan over GF(2^8) */
  uint8_t mat[ZPSYNC_CRUISE_MAX_PARITY][ZPSYNC_CRUISE_MAX_PARITY];
  uint8_t inv[ZPSYNC_CRUISE_MAX_PARITY][ZPSYNC_CRUISE_MAX_PARITY];
  memset(inv, 0, sizeof(inv));
  for (uint8_t r = 0; r < m; ++r) {
    inv[r][r] = 1U;
    for (uint8_t c = 0; c < m; ++c) {
      mat[r][c] = cauchy_coeff(avail_par[r], missing_idx[c]);
    }
  }

  for (uint8_t col = 0; col < m; ++col) {
    uint8_t piv = col;
    while (piv < m && mat[piv][col] == 0) ++piv;
    if (piv == m) return -1;
    if (piv != col) {
      for (uint8_t j = 0; j < m; ++j) {
        uint8_t t = mat[col][j];
        mat[col][j] = mat[piv][j];
        mat[piv][j] = t;
        t = inv[col][j];
        inv[col][j] = inv[piv][j];
        inv[piv][j] = t;
      }
    }
    uint8_t s = gf_inv(mat[col][col]);
    for (uint8_t j = 0; j < m; ++j) {
      mat[col][j] = gf_mul(mat[col][j], s);
      inv[col][j] = gf_mul(inv[col][j], s);
    }
    for (uint8_t r = 0; r < m; ++r) {
      if (r == col || mat[r][col] == 0) continue;
      uint8_t f = mat[r][col];
      for (uint8_t j = 0; j < m; ++j) {
        mat[r][j] ^= gf_mul(f, mat[col][j]);
        inv[r][j] ^= gf_mul(f, inv[col][j]);
      }
    }
  }

  /* Subtract known data contributions from each available parity shard */
  uint8_t rhs[ZPSYNC_CRUISE_MAX_PARITY][ZPSYNC_CRUISE_MTU];
  for (uint8_t r = 0; r < m; ++r) {
    memcpy(rhs[r], parity[avail_par[r]], max_frag_len);
    for (uint16_t i = 0; i < k; ++i) {
      if (!data_present[i]) continue;
      uint8_t c = cauchy_coeff(avail_par[r], i);
      uint16_t len = data_lens[i] < max_frag_len ? data_lens[i] : max_frag_len;
      for (uint16_t b = 0; b < len; ++b) {
        rhs[r][b] ^= gf_mul(c, data[i][b]);
      }
    }
  }

  /* Reconstruct each missing fragment: data[missing_idx[r]] = sum_c inv[r][c] * rhs[c] */
  for (uint8_t r = 0; r < m; ++r) {
    uint16_t idx = missing_idx[r];
    memset(data[idx], 0, max_frag_len);
    for (uint8_t c = 0; c < m; ++c) {
      uint8_t w = inv[r][c];
      if (w == 0) continue;
      for (uint16_t b = 0; b < max_frag_len; ++b) {
        data[idx][b] ^= gf_mul(w, rhs[c][b]);
      }
    }
    data_lens[idx] = (idx + 1U == k && last_frag_len > 0) ? last_frag_len : max_frag_len;
    data_present[idx] = 1U;
  }

  return (int)m;
}

void zpsync_cruise_tx_init(zpsync_cruise_tx_s *tx) {
  if (tx != NULL) memset(tx, 0, sizeof(*tx));
}

void zpsync_cruise_rx_init(zpsync_cruise_rx_s *rx) {
  if (rx != NULL) memset(rx, 0, sizeof(*rx));
}

static int seal_and_send(zpsync_result_s *res, uint32_t frame_id,
                         uint16_t frag_idx, uint16_t total_frags,
                         uint16_t payload_len, uint8_t flags,
                         const uint8_t *payload) {
  uint8_t plain[ZPSYNC_CRUISE_HDR_BYTES + ZPSYNC_CRUISE_MTU];
  write_be16(plain, ZPSYNC_CRUISE_MAGIC);
  plain[2] = flags;
  plain[3] = 0;
  write_be32(plain + 4, frame_id);
  write_be16(plain + 8, frag_idx);
  write_be16(plain + 10, total_frags);
  if (payload_len > 0) memcpy(plain + ZPSYNC_CRUISE_HDR_BYTES, payload, payload_len);

  uint8_t wire[ZPSYNC_CRUISE_HDR_BYTES + ZPSYNC_CRUISE_MTU + RUDP_CRYPTO_OVERHEAD_BYTES];
  int slen = rudp_crypto_seal(&res->crypto, NULL, 0, plain,
                              ZPSYNC_CRUISE_HDR_BYTES + payload_len, wire,
                              sizeof(wire));
  if (slen <= 0) return -1;
  int sent = send(res->sock, (const char *)wire, slen, 0);
  return sent == slen ? 0 : -1;
}

int zpsync_cruise_send_frame_fec(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                                 const uint8_t *frame, size_t frame_len,
                                 bool is_keyframe, uint8_t parity_shards) {
  if (res == NULL || tx == NULL || frame == NULL || frame_len == 0 ||
      res->sock == ZPSYNC_INVALID_SOCK) {
    return -1;
  }
  if (parity_shards > ZPSYNC_CRUISE_MAX_PARITY) {
    parity_shards = ZPSYNC_CRUISE_MAX_PARITY;
  }

  size_t total = (frame_len + ZPSYNC_CRUISE_MTU - 1U) / ZPSYNC_CRUISE_MTU;
  if (total == 0 || total > ZPSYNC_CRUISE_MAX_FRAGS) return -1;

  uint32_t fid = ++tx->next_frame_id;
  uint8_t base_flags = is_keyframe ? ZPSYNC_CRUISE_FLAG_KEYFRAME : 0U;

  uint8_t data_mat[ZPSYNC_CRUISE_MAX_FRAGS][ZPSYNC_CRUISE_MTU];
  uint16_t data_lens[ZPSYNC_CRUISE_MAX_FRAGS];
  uint16_t max_frag_len = 0;

  for (size_t i = 0; i < total; ++i) {
    size_t off = i * ZPSYNC_CRUISE_MTU;
    size_t rem = frame_len - off;
    uint16_t chunk = (uint16_t)(rem > ZPSYNC_CRUISE_MTU ? ZPSYNC_CRUISE_MTU : rem);
    data_lens[i] = chunk;
    if (chunk > max_frag_len) max_frag_len = chunk;
    if (parity_shards > 0 && total >= 2U) {
      memcpy(data_mat[i], frame + off, chunk);
    }
    if (seal_and_send(res, fid, (uint16_t)i, (uint16_t)total, chunk, base_flags,
                      frame + off) != 0) {
      return -1;
    }
    ++tx->frags_sent;
    tx->bytes_sent += chunk;
  }

  if (parity_shards > 0 && total >= 2U) {
    uint8_t par[ZPSYNC_CRUISE_MAX_PARITY][ZPSYNC_CRUISE_MTU];
    if (zpsync_fec_encode(data_mat, data_lens, (uint16_t)total, max_frag_len,
                          parity_shards, par) == 0) {
      for (uint8_t p = 0; p < parity_shards; ++p) {
        if (seal_and_send(res, fid, (uint16_t)(total + p), (uint16_t)total,
                          max_frag_len,
                          (uint8_t)(base_flags | ZPSYNC_CRUISE_FLAG_PARITY),
                          par[p]) == 0) {
          ++tx->fec_sent;
        }
      }
    }
  }

  ++tx->frames_sent;
  return 0;
}

int zpsync_cruise_send_frame(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                             const uint8_t *frame, size_t frame_len,
                             bool is_keyframe, bool enable_xor_fec) {
  return zpsync_cruise_send_frame_fec(res, tx, frame, frame_len, is_keyframe,
                                      enable_xor_fec ? 1U : 0U);
}

static void reset_rx_frame(zpsync_cruise_rx_s *rx, uint32_t fid, uint16_t total,
                           uint8_t flags) {
  rx->active_frame_id = fid;
  rx->total_frags = total;
  rx->received_count = 0;
  rx->last_frag_len = 0;
  rx->flags = (uint8_t)(flags & ZPSYNC_CRUISE_FLAG_KEYFRAME);
  rx->parity_count = 0;
  memset(rx->parity_present, 0, sizeof(rx->parity_present));
  memset(rx->parity_lens, 0, sizeof(rx->parity_lens));
  memset(rx->frag_present, 0, total);
}

static int try_assemble_frame(zpsync_cruise_rx_s *rx, uint8_t *out_frame,
                              size_t max_frame_len, bool *out_is_keyframe) {
  if (rx->total_frags == 0) return 0;

  if (rx->received_count < rx->total_frags && rx->parity_count > 0) {
    uint16_t missing = (uint16_t)(rx->total_frags - rx->received_count);
    if (missing <= rx->parity_count) {
      uint16_t max_plen = 0;
      for (uint8_t p = 0; p < ZPSYNC_CRUISE_MAX_PARITY; ++p) {
        if (rx->parity_present[p] && rx->parity_lens[p] > max_plen) {
          max_plen = rx->parity_lens[p];
        }
      }
      int rec = zpsync_fec_decode(rx->frags, rx->frag_lens, rx->frag_present,
                                  rx->total_frags, max_plen, rx->last_frag_len,
                                  rx->parity, rx->parity_present,
                                  ZPSYNC_CRUISE_MAX_PARITY);
      if (rec > 0) {
        rx->received_count = (uint16_t)(rx->received_count + (uint16_t)rec);
        rx->fec_recoveries += (uint64_t)rec;
      }
    }
  }

  if (rx->received_count < rx->total_frags) return 0;

  size_t pos = 0;
  for (uint16_t i = 0; i < rx->total_frags; ++i) {
    if (pos + rx->frag_lens[i] > max_frame_len) return -1;
    memcpy(out_frame + pos, rx->frags[i], rx->frag_lens[i]);
    pos += rx->frag_lens[i];
  }
  if (out_is_keyframe != NULL) {
    *out_is_keyframe = (rx->flags & ZPSYNC_CRUISE_FLAG_KEYFRAME) != 0;
  }
  ++rx->frames_completed;
  rx->total_frags = 0;
  return (int)pos;
}

int zpsync_cruise_recv_frame(zpsync_result_s *res, zpsync_cruise_rx_s *rx,
                             uint8_t *out_frame, size_t max_frame_len,
                             uint32_t timeout_ms, bool *out_is_keyframe) {
  if (res == NULL || rx == NULL || out_frame == NULL ||
      res->sock == ZPSYNC_INVALID_SOCK) {
    return -1;
  }

  uint64_t deadline = zpsync_now_ms() + timeout_ms;
  do {
    uint8_t ready = 0;
    uint64_t now = zpsync_now_ms();
    uint32_t rem = (now < deadline) ? (uint32_t)(deadline - now) : 0U;
    if (zpsync_poll_readable(&res->sock, 1, rem < 20U ? rem : 20U, &ready) > 0 &&
        (ready & 1U)) {
      uint8_t wire[ZPSYNC_CRUISE_HDR_BYTES + ZPSYNC_CRUISE_MTU +
                   RUDP_CRYPTO_OVERHEAD_BYTES];
      int n = recv(res->sock, (char *)wire, (int)sizeof(wire), 0);
      if (n <= (int)(ZPSYNC_CRUISE_HDR_BYTES + RUDP_CRYPTO_OVERHEAD_BYTES)) {
        continue;
      }
      uint8_t plain[ZPSYNC_CRUISE_HDR_BYTES + ZPSYNC_CRUISE_MTU];
      int pt_len = rudp_crypto_open(&res->crypto, NULL, 0, wire, (size_t)n, plain,
                                    sizeof(plain));
      if (pt_len < (int)ZPSYNC_CRUISE_HDR_BYTES) {
        ++rx->auth_drops;
        continue;
      }
      if (read_be16(plain) != ZPSYNC_CRUISE_MAGIC) continue;

      uint8_t flags = plain[2];
      uint32_t fid = read_be32(plain + 4);
      uint16_t fidx = read_be16(plain + 8);
      uint16_t total = read_be16(plain + 10);
      uint16_t plen = (uint16_t)(pt_len - (int)ZPSYNC_CRUISE_HDR_BYTES);
      if (total == 0 || total > ZPSYNC_CRUISE_MAX_FRAGS ||
          plen > ZPSYNC_CRUISE_MTU) {
        continue;
      }

      if (fid > rx->active_frame_id) {
        reset_rx_frame(rx, fid, total, flags);
      } else if (fid < rx->active_frame_id) {
        continue;
      }

      if ((flags & ZPSYNC_CRUISE_FLAG_PARITY) != 0) {
        uint16_t p_idx = (fidx >= total) ? (uint16_t)(fidx - total) : 0U;
        if (p_idx < ZPSYNC_CRUISE_MAX_PARITY && !rx->parity_present[p_idx]) {
          memcpy(rx->parity[p_idx], plain + ZPSYNC_CRUISE_HDR_BYTES, plen);
          rx->parity_lens[p_idx] = plen;
          rx->parity_present[p_idx] = 1;
          ++rx->parity_count;
        }
      } else if (fidx < total && !rx->frag_present[fidx]) {
        memcpy(rx->frags[fidx], plain + ZPSYNC_CRUISE_HDR_BYTES, plen);
        rx->frag_lens[fidx] = plen;
        rx->frag_present[fidx] = 1;
        ++rx->received_count;
        if (fidx + 1U == total) rx->last_frag_len = plen;
      }

      int done = try_assemble_frame(rx, out_frame, max_frame_len, out_is_keyframe);
      if (done != 0) return done;
    }
  } while (zpsync_now_ms() < deadline);

  return 0;
}
