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

int zpsync_cruise_send_frame(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                             const uint8_t *frame, size_t frame_len,
                             bool is_keyframe, bool enable_xor_fec) {
  if (res == NULL || tx == NULL || frame == NULL || frame_len == 0 ||
      res->sock == ZPSYNC_INVALID_SOCK) {
    return -1;
  }

  size_t total = (frame_len + ZPSYNC_CRUISE_MTU - 1U) / ZPSYNC_CRUISE_MTU;
  if (total == 0 || total > ZPSYNC_CRUISE_MAX_FRAGS) return -1;

  uint32_t fid = ++tx->next_frame_id;
  uint8_t base_flags = is_keyframe ? ZPSYNC_CRUISE_FLAG_KEYFRAME : 0U;

  uint8_t parity[ZPSYNC_CRUISE_MTU];
  uint16_t max_frag_len = 0;
  if (enable_xor_fec && total >= 2U) memset(parity, 0, sizeof(parity));

  for (size_t i = 0; i < total; ++i) {
    size_t off = i * ZPSYNC_CRUISE_MTU;
    size_t rem = frame_len - off;
    uint16_t chunk = (uint16_t)(rem > ZPSYNC_CRUISE_MTU ? ZPSYNC_CRUISE_MTU : rem);
    if (chunk > max_frag_len) max_frag_len = chunk;
    if (enable_xor_fec && total >= 2U) {
      for (uint16_t b = 0; b < chunk; ++b) parity[b] ^= frame[off + b];
    }
    if (seal_and_send(res, fid, (uint16_t)i, (uint16_t)total, chunk, base_flags,
                      frame + off) != 0) {
      return -1;
    }
    ++tx->frags_sent;
    tx->bytes_sent += chunk;
  }

  if (enable_xor_fec && total >= 2U) {
    if (seal_and_send(res, fid, (uint16_t)total, (uint16_t)total, max_frag_len,
                      (uint8_t)(base_flags | ZPSYNC_CRUISE_FLAG_PARITY),
                      parity) == 0) {
      ++tx->fec_sent;
    }
  }

  ++tx->frames_sent;
  return 0;
}

static void reset_rx_frame(zpsync_cruise_rx_s *rx, uint32_t fid, uint16_t total,
                           uint8_t flags) {
  rx->active_frame_id = fid;
  rx->total_frags = total;
  rx->received_count = 0;
  rx->last_frag_len = 0;
  rx->flags = (uint8_t)(flags & ZPSYNC_CRUISE_FLAG_KEYFRAME);
  rx->has_parity = 0;
  rx->parity_len = 0;
  memset(rx->frag_present, 0, total);
}

static int try_assemble_frame(zpsync_cruise_rx_s *rx, uint8_t *out_frame,
                              size_t max_frame_len, bool *out_is_keyframe) {
  if (rx->total_frags == 0) return 0;

  /* Recover 1 missing fragment via XOR parity if available */
  if (rx->received_count + 1U == rx->total_frags && rx->has_parity) {
    uint16_t missing = ZPSYNC_CRUISE_MAX_FRAGS;
    for (uint16_t i = 0; i < rx->total_frags; ++i) {
      if (!rx->frag_present[i]) {
        missing = i;
        break;
      }
    }
    if (missing < rx->total_frags) {
      memset(rx->frags[missing], 0, rx->parity_len);
      memcpy(rx->frags[missing], rx->parity, rx->parity_len);
      for (uint16_t i = 0; i < rx->total_frags; ++i) {
        if (i == missing) continue;
        for (uint16_t b = 0; b < rx->frag_lens[i]; ++b) {
          rx->frags[missing][b] ^= rx->frags[i][b];
        }
      }
      rx->frag_lens[missing] =
          (missing + 1U == rx->total_frags && rx->last_frag_len > 0)
              ? rx->last_frag_len
              : rx->parity_len;
      rx->frag_present[missing] = 1;
      ++rx->received_count;
      ++rx->fec_recoveries;
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
        memcpy(rx->parity, plain + ZPSYNC_CRUISE_HDR_BYTES, plen);
        rx->parity_len = plen;
        rx->has_parity = 1;
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
