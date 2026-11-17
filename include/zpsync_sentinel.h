#ifndef ZPSYNC_SENTINEL_H
#define ZPSYNC_SENTINEL_H

/**
 * @file zpsync_sentinel.h
 * @brief Brique 3: Portless Layer-3 ICMP Sentinel for IPv4 NAT/CGNAT wake-up.
 *
 * Sends an ICMP Echo Request carrying an AEAD-encrypted sentinel payload
 * (authenticated by shared secret S). Because ICMP traverses almost all
 * residential boxes and mobile CGNATs, the receiver wakes up on the exact
 * millisecond and immediately fires its RUDP UDP handshake toward the sender's
 * advertised UDP port + ECMP flow-entropy hint.
 */

#include "zpsync_crypto.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_SENTINEL_MAGIC 0x5A50534EU /* 'ZPSN' */
#define ZPSYNC_ICMP_ECHO_REQUEST 8U
#define ZPSYNC_ICMP_ECHO_REPLY 0U
#define ZPSYNC_ICMP_HEADER_BYTES 8U

/**
 * Plaintext sentinel payload (24 bytes):
 *   magic(4) + timestamp_ms(8) + udp_port(2) + dscp(1) + flags(1) +
 *   flow_entropy(4) + session_salt(4)
 * Sealed wire payload:
 *   12B nonce + 24B ciphertext + 16B Poly1305 tag = 52 bytes
 * Full ICMP Echo packet:
 *   8B ICMP header + 52B sealed payload = 60 bytes
 */
#define ZPSYNC_SENTINEL_PLAIN_BYTES 24U
#define ZPSYNC_SENTINEL_SEALED_BYTES                                                   \
  (ZPSYNC_NONCE_BYTES + ZPSYNC_SENTINEL_PLAIN_BYTES + ZPSYNC_TAG_BYTES)
#define ZPSYNC_SENTINEL_ICMP_BYTES                                                     \
  (ZPSYNC_ICMP_HEADER_BYTES + ZPSYNC_SENTINEL_SEALED_BYTES)

typedef struct {
  uint64_t timestamp_ms; /**< Sender UTC/monotonic timestamp in ms */
  uint32_t flow_entropy; /**< zcrudp ECMP/LAG hash hint (rudp_calc_entropy) */
  uint32_t session_salt; /**< Random per-attempt anti-reflection token */
  uint16_t udp_port;     /**< UDP port A just opened locally for RUDP */
  uint8_t dscp;          /**< DSCP hint (0..63) for zcrudp QoS */
  uint8_t flags;         /**< Bit 0: request immediate RUDP burst */
} zpsync_sentinel_info_s;

/**
 * @brief Computes RFC 1071 16-bit one's-complement Internet checksum.
 */
uint16_t zpsync_icmp_checksum(const uint8_t *data, size_t len);

/**
 * @brief Builds a complete 60-byte ICMP Echo Request containing an AEAD-sealed
 *        sentinel payload authenticated with @p key.
 *
 * @param key 32-byte key derived from S via zpsync_derive_session_key().
 * @param icmp_id ICMP identifier (host byte order).
 * @param icmp_seq ICMP sequence number (host byte order).
 * @param nonce 12-byte unique nonce.
 * @param info Sentinel metadata (UDP port, timestamp, ECMP flow hint).
 * @param out_icmp Output buffer (>= ZPSYNC_SENTINEL_ICMP_BYTES).
 * @return ZPSYNC_SENTINEL_ICMP_BYTES (60) on success, or negative error code.
 */
int zpsync_sentinel_build_icmp(const uint8_t key[ZPSYNC_KEY_BYTES], uint16_t icmp_id,
                               uint16_t icmp_seq,
                               const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                               const zpsync_sentinel_info_s *info, uint8_t *out_icmp,
                               size_t max_len);

/**
 * @brief Validates an incoming ICMP Echo Request (or IPv4-wrapped ICMP packet),
 *        verifies the ChaCha20-Poly1305 tag with @p key, and extracts @p out_info.
 *
 * Automatically strips a 20+ byte IPv4 header if present (Windows/Linux RAW RX).
 *
 * @return 0 on authentic sentinel, negative error code on non-sentinel/tamper.
 */
int zpsync_sentinel_parse_icmp(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *pkt,
                               size_t pkt_len, zpsync_sentinel_info_s *out_info);

/**
 * @brief Sends an encrypted ICMP Echo Request sentinel to @p dst_ipv4.
 *        Uses raw ICMP socket (or Windows IcmpSendEcho2 fallback if unprivileged).
 *
 * @return 0 on success, or negative error code (e.g. -EACCES if blocked).
 */
int zpsync_sentinel_send_v4(const uint8_t key[ZPSYNC_KEY_BYTES],
                            const uint8_t dst_ipv4[4], uint16_t icmp_id,
                            uint16_t icmp_seq, const zpsync_sentinel_info_s *info);

/**
 * @brief Listens on a raw ICMP socket for up to @p timeout_ms for a valid
 *        sentinel encrypted with @p key.
 *
 * @param out_src_ipv4 Receives the sender's source IPv4 address.
 * @param out_info Receives the decrypted sentinel metadata.
 * @return 0 if a valid sentinel arrived, 1 on timeout, or negative on OS error.
 */
int zpsync_sentinel_recv_v4(const uint8_t key[ZPSYNC_KEY_BYTES], uint32_t timeout_ms,
                            uint8_t out_src_ipv4[4],
                            zpsync_sentinel_info_s *out_info);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_SENTINEL_H */
