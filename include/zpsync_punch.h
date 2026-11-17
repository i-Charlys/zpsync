#ifndef ZPSYNC_PUNCH_H
#define ZPSYNC_PUNCH_H

/**
 * @file zpsync_punch.h
 * @brief Briques 2, 3 & 4: Adaptive NAT traversal engines.
 *
 * - Brique 2 (IPv6 Priority): Deterministic Port_Cible = 10000 + (Hash(S||T) % 55000).
 * - Brique 3 (IPv4 Sentinel): ICMP Layer-3 wake-up + synchronized UDP punch.
 * - Brique 4 (Birthday Paradox): 256..500 UDP sockets derived from Hash(S||i) % 55535,
 *   combining incremental +1/+2 port prediction and mathematical dispersion.
 *   As soon as an authenticated ACK arrives, locks that IP:Port and closes the rest.
 */

#include "zpsync_crypto.h"
#include "zpsync_sentinel.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_HANDSHAKE_MAGIC 0x5A504853U /* 'ZPHS' */
#define ZPSYNC_HS_TYPE_SYN 1U
#define ZPSYNC_HS_TYPE_SYN_ACK 2U
#define ZPSYNC_HS_TYPE_ACK 3U

#define ZPSYNC_BIRTHDAY_MIN_SOCKETS 256U
#define ZPSYNC_BIRTHDAY_DEFAULT_SOCKETS 384U
#define ZPSYNC_BIRTHDAY_MAX_SOCKETS 500U

/**
 * Sealed handshake datagram:
 *   12B nonce + 24B plaintext + 16B tag = 52 bytes
 * Plaintext (24B):
 *   magic(4) + msg_type(1) + flags(1) + hop_epoch(2) + session_id(8) + peer_nonce(8)
 */
#define ZPSYNC_HS_PLAIN_BYTES 24U
#define ZPSYNC_HS_WIRE_BYTES                                                           \
  (ZPSYNC_NONCE_BYTES + ZPSYNC_HS_PLAIN_BYTES + ZPSYNC_TAG_BYTES)

#if defined(_WIN32)
#include <winsock2.h>
typedef SOCKET zpsync_sock_t;
#define ZPSYNC_INVALID_SOCK INVALID_SOCKET
#else
typedef int zpsync_sock_t;
#define ZPSYNC_INVALID_SOCK (-1)
#endif

typedef struct {
  uint8_t msg_type;    /**< ZPSYNC_HS_TYPE_SYN / SYN_ACK / ACK */
  uint8_t flags;
  uint16_t hop_epoch;
  uint64_t session_id;
  uint64_t peer_nonce;
} zpsync_hs_msg_s;

typedef struct {
  zpsync_sock_t sock;
  uint8_t peer_addr[16]; /**< IPv4 in first 4 bytes, or IPv6 in 16 bytes */
  uint8_t family;        /**< 4 or 6 */
  uint16_t local_port;
  uint16_t peer_port;
  uint64_t session_id;
  uint64_t remote_nonce;
  uint32_t rtt_ms;
  uint8_t local_is_initiator;
} zpsync_punch_out_s;

/**
 * @brief Seals an authenticated handshake packet using @p key.
 */
int zpsync_hs_seal(const uint8_t key[ZPSYNC_KEY_BYTES],
                   const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                   const zpsync_hs_msg_s *msg, uint8_t *out_wire, size_t max_len);

/**
 * @brief Authenticates and decrypts a handshake packet using @p key.
 */
int zpsync_hs_open(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *wire,
                   size_t wire_len, zpsync_hs_msg_s *out_msg);

/**
 * @brief Brique 2: IPv6 direct deterministic-port handshake.
 *        Opens an AF_INET6 UDP socket on @p local_port (or Port_Cible), sends
 *        authenticated SYN/SYN-ACK/ACK to [peer_ipv6]:peer_port, and returns the
 *        connected native socket.
 */
int zpsync_punch_ipv6_direct(const uint8_t key[ZPSYNC_KEY_BYTES],
                             const uint8_t peer_ipv6[16], uint16_t local_port,
                             uint16_t peer_port, uint64_t local_nonce,
                             uint32_t timeout_ms, zpsync_punch_out_s *out);

/**
 * @brief Brique 3: IPv4 simultaneous open with Layer-3 ICMP Sentinel wake-up.
 *        Sends encrypted ICMP sentinel (if permitted) and performs synchronized
 *        UDP handshake with @p peer_ipv4:@p peer_port.
 */
int zpsync_punch_ipv4_sentinel(const uint8_t key[ZPSYNC_KEY_BYTES],
                               const uint8_t peer_ipv4[4], uint16_t local_port,
                               uint16_t peer_port, uint64_t local_nonce,
                               uint32_t flow_entropy, uint32_t timeout_ms,
                               bool use_icmp_sentinel, zpsync_punch_out_s *out);

/**
 * @brief Brique 4: Birthday-Paradox statistical NAT punch for symmetric CGNAT.
 *        Opens @p socket_count (256..500) UDP sockets on ports derived from
 *        zpsync_derive_birthday_port(S, i), sprays @p peer_ipv4 across derived
 *        ports + incremental (+1/+2) predictions around @p peer_base_port for
 *        @p timeout_ms, locks the first socket that receives an authenticated
 *        ACK/SYN-ACK, and immediately closes all other sockets.
 */
int zpsync_punch_ipv4_birthday(const uint8_t *secret, size_t secret_len,
                               const uint8_t key[ZPSYNC_KEY_BYTES],
                               const uint8_t peer_ipv4[4],
                               uint16_t peer_base_port, uint32_t socket_count,
                               uint64_t local_nonce, uint32_t timeout_ms,
                               zpsync_punch_out_s *out);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_PUNCH_H */
