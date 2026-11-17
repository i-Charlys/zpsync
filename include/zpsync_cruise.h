#ifndef ZPSYNC_CRUISE_H
#define ZPSYNC_CRUISE_H

/**
 * @file zpsync_cruise.h
 * @brief Video-aware encrypted RUDP cruise bridge with MTU fragmentation,
 *        systematic GF(2^8) Cauchy MDS Erasure Coding (recovers up to 4 lost
 *        fragments per frame with zero retransmissions), and adaptive FEC.
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
#define ZPSYNC_CRUISE_MAX_PARITY 4U
#define ZPSYNC_CRUISE_HDR_BYTES 12U
#define ZPSYNC_CRUISE_FLAG_KEYFRAME 0x01U
#define ZPSYNC_CRUISE_FLAG_PARITY 0x02U

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
  uint8_t parity_present[ZPSYNC_CRUISE_MAX_PARITY];
  uint16_t parity_lens[ZPSYNC_CRUISE_MAX_PARITY];
  uint8_t parity[ZPSYNC_CRUISE_MAX_PARITY][ZPSYNC_CRUISE_MTU];
  uint8_t parity_count;
  uint8_t frag_present[ZPSYNC_CRUISE_MAX_FRAGS];
  uint16_t frag_lens[ZPSYNC_CRUISE_MAX_FRAGS];
  uint8_t frags[ZPSYNC_CRUISE_MAX_FRAGS][ZPSYNC_CRUISE_MTU];
  uint64_t frames_completed;
  uint64_t fec_recoveries;
  uint64_t auth_drops;
} zpsync_cruise_rx_s;

void zpsync_cruise_tx_init(zpsync_cruise_tx_s *tx);
void zpsync_cruise_rx_init(zpsync_cruise_rx_s *rx);

/**
 * @brief Encodes @p parity_shards (1..4) systematic GF(2^8) Cauchy MDS parity
 *        shards from @p k data fragments.
 *        Parity 0 is pure XOR (row = 1); parities 1..3 use Cauchy rows
 *        1 / (x_i ^ y_j) over GF(2^8) with primitive polynomial 0x11D.
 */
int zpsync_fec_encode(const uint8_t data[][ZPSYNC_CRUISE_MTU],
                      const uint16_t data_lens[], uint16_t k,
                      uint16_t max_frag_len, uint8_t parity_shards,
                      uint8_t out_parity[][ZPSYNC_CRUISE_MTU]);

/**
 * @brief Recovers up to @p parity_shards missing data fragments in-place using
 *        Gaussian elimination over GF(2^8).
 * @return Number of recovered fragments (>= 0), or -1 if unrecoverable.
 */
int zpsync_fec_decode(uint8_t data[][ZPSYNC_CRUISE_MTU], uint16_t data_lens[],
                      uint8_t data_present[], uint16_t k, uint16_t max_frag_len,
                      uint16_t last_frag_len,
                      const uint8_t parity[][ZPSYNC_CRUISE_MTU],
                      const uint8_t parity_present[], uint8_t max_parity);

/**
 * @brief Fragments, adds @p parity_shards (0..4) GF(2^8) MDS parity shards,
 *        seals with X25519-PFS ChaCha20-Poly1305, and transmits over @p res->sock.
 */
int zpsync_cruise_send_frame_fec(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                                 const uint8_t *frame, size_t frame_len,
                                 bool is_keyframe, uint8_t parity_shards);

/**
 * @brief Convenience wrapper: 1 XOR parity shard when @p enable_xor_fec is true.
 */
int zpsync_cruise_send_frame(zpsync_result_s *res, zpsync_cruise_tx_s *tx,
                             const uint8_t *frame, size_t frame_len,
                             bool is_keyframe, bool enable_xor_fec);

/**
 * @brief Polls @p res->sock for up to @p timeout_ms, authenticates incoming
 *        datagrams, reassembles fragments (recovering up to 4 missing fragments
 *        via GF(2^8) MDS FEC), and outputs a complete frame into @p out_frame.
 */
int zpsync_cruise_recv_frame(zpsync_result_s *res, zpsync_cruise_rx_s *rx,
                             uint8_t *out_frame, size_t max_frame_len,
                             uint32_t timeout_ms, bool *out_is_keyframe);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_CRUISE_H */
