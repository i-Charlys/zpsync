#ifndef ZPSYNC_CRUISE_H
#define ZPSYNC_CRUISE_H

/**
 * @file zpsync_cruise.h
 * @brief Video-aware encrypted RUDP cruise bridge with MTU fragmentation,
 *        zero-RTT XOR Forward Error Correction (FEC), and ECMP hop hints.
 */

#include "zpsync.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_CRUISE_MAGIC 0x5A56U /* 'ZV' */
#define ZPSYNC_CRUISE_MTU 1180U
#define ZPSYNC_CRUISE_MAX_FRAGS 64U
#define ZPSYNC_CRUISE_HDR_BYTES 12U
#define ZPSYNC_CRUISE_FLAG_KEYFRAME 0x01U
#define ZPSYNC_CRUISE_FLAG_PARITY 0x02U

typedef struct {
  uint32_t frame_id;
  uint16_t frag_idx;
  uint16_t total_frags;
  uint16_t payload_len;
  uint8_t flags;
  uint8_t fec_group;
} zpsync_video_frag_hdr_s;

typedef struct {
  uint32_t next_frame_id;
  uint64_t frames_sent;
  uint64_t frags_sent;
  uint64_t fec_sent;
  uint64_t bytes_sent;
} zpsync_cruise_tx_s;

typedef struct {
  uint32_t active_frame_id;
  uint16_t total_frags;
  uint16_t received_count;
  uint16_t last_frag_len;
  uint8_t flags;
  uint8_t has_parity;
  uint16_t parity_len;
  uint8_t frag_present[ZPSYNC_CRUISE_MAX_FRAGS];
  uint16_t frag_lens[ZPSYNC_CRUISE_MAX_FRAGS];
  uint8_t frags[ZPSYNC_CRUISE_MAX_FRAGS][ZPSYNC_CRUISE_MTU];
  uint8_t parity[ZPSYNC_CRUISE_MTU];
  uint64_t frames_completed;
  uint64_t fec_recoveries;
  uint64_t auth_drops;
} zpsync_cruise_rx_s;

void zpsync_cruise_tx_init(zpsync_cruise_tx_s *tx);
void zpsync_cruise_rx_init(zpsync_cruise_rx_s *rx);

/**
 * @brief Fragments, optionally adds XOR FEC parity, seals with X25519-PFS
 *        ChaCha20-Poly1305, and transmits a video frame over @p res->sock.
 */
int zpsync_cruise_send_frame(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                             const uint8_t *frame, size_t frame_len,
                             bool is_keyframe, bool enable_xor_fec);

/**
 * @brief Polls @p res->sock for up to @p timeout_ms, authenticates incoming
 *        datagrams, reassembles fragments (and recovers 1 missing fragment via
 *        XOR FEC), and outputs a complete frame into @p out_frame.
 *
 * @return >0 (frame byte length) when a frame completes, 0 if still assembling
 *         or timed out, <0 on error.
 */
int zpsync_cruise_recv_frame(zpsync_result_s *res, zpsync_cruise_rx_s *rx,
                             uint8_t *out_frame, size_t max_frame_len,
                             uint32_t timeout_ms, bool *out_is_keyframe);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_CRUISE_H */
