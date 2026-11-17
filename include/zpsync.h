#ifndef ZPSYNC_H
#define ZPSYNC_H

/**
 * @file zpsync.h
 * @brief ZPSync (Zero Proxy Sync) — 4-layer serverless NAT traversal & RUDP handoff.
 *
 * Orchestrates:
 *   1. Discovery: Mainline DHT encrypted mailbox (Node_ID = SHA1(S || UTC_Hour))
 *      + STUN/IPv6 probing, or offline manual peer IP/port.
 *   2. IPv6 Priority: Deterministic Port_Cible = 10000 + (Hash(S || T) mod 55000).
 *   3. IPv4 Sentinel: Portless Layer-3 ICMP Echo Request wake-up + UDP punch.
 *   4. Birthday Paradox: 256..500 UDP sockets spray for strict symmetric CGNAT.
 *   5. Cruise Handoff: Returns a native connected UDP socket + initialized
 *      zcrudp `rudp_session_s` and `rudp_crypto_ctx_s` with zero added latency,
 *      plus dynamic port hopping (`zpsync_hop_port`) on ECMP/LAG congestion.
 */

#include "rudp_crypto.h"
#include "rudp_session.h"
#include "zpsync_crypto.h"
#include "zpsync_dht.h"
#include "zpsync_punch.h"
#include "zpsync_sentinel.h"
#include "zpsync_stun.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
  ZPSYNC_PATH_NONE = 0,
  ZPSYNC_PATH_IPV6_DIRECT = 1,
  ZPSYNC_PATH_IPV4_SENTINEL = 2,
  ZPSYNC_PATH_IPV4_BIRTHDAY = 3,
  ZPSYNC_PATH_MANUAL = 4
} zpsync_path_e;

typedef struct {
  const uint8_t *secret;       /**< Shared secret S (required) */
  size_t secret_len;           /**< Length of S in bytes (> 0) */

  /* Optional manual / offline mode (skips DHT when manual_ip is set) */
  const char *manual_peer_ip;  /**< IPv4 or IPv6 string, or NULL for DHT */
  uint16_t manual_peer_port;   /**< 0 = use deterministic Port_Cible */
  uint16_t local_port_override;/**< 0 = use deterministic Port_Cible */

  /* Layer toggles & tuning */
  bool disable_dht;            /**< Skip Mainline DHT discovery */
  bool disable_ipv6;           /**< Skip Brique 2 (IPv6 priority) */
  bool disable_sentinel;       /**< Skip ICMP Sentinel in Brique 3 */
  bool force_birthday;         /**< Jump straight to Brique 4 on IPv4 */
  uint32_t birthday_sockets;   /**< 256..500 (0 = default 384) */

  /* Timeouts (0 = sensible defaults) */
  uint32_t stun_timeout_ms;    /**< Default: 1500 ms */
  uint32_t dht_timeout_ms;     /**< Default: 4000 ms */
  uint32_t punch_timeout_ms;   /**< Default: 2500 ms */
  uint64_t time_window_override; /**< 0 = current UTC minute/hour */
} zpsync_config_s;

typedef struct {
  zpsync_sock_t sock;          /**< Connected native UDP socket for cruise */
  rudp_session_s session;      /**< Ready-to-use zcrudp multi-channel session */
  rudp_crypto_ctx_s crypto;    /**< Ready-to-use ChaCha20-Poly1305 AEAD context */
  zpsync_path_e active_path;   /**< Traversal path that succeeded */
  zpsync_nat_type_e local_nat; /**< Detected local NAT type */
  uint8_t peer_addr[16];       /**< Connected peer IP (v4 in [0..3], v6 in [0..15]) */
  uint8_t family;              /**< 4 or 6 */
  uint16_t local_port;         /**< Bound local UDP port */
  uint16_t peer_port;          /**< Connected remote UDP port */
  uint64_t session_id;         /**< Negotiated 64-bit session ID */
  uint64_t hop_epoch;          /**< Current deterministic port-hop epoch */
  uint32_t rtt_ms;             /**< Measured handshake RTT */
  uint8_t local_is_initiator;  /**< 1 if initiator, 0 if responder */
  uint8_t pfs_enabled;         /**< 1 if X25519 Forward Secrecy is active */
} zpsync_result_s;

/**
 * @brief Executes the full 4-layer ZPSync connection establishment and hands off
 *        a native UDP socket + initialized zcrudp session/crypto context.
 *
 * @return 0 on success, or negative error code on failure.
 */
int zpsync_connect(const zpsync_config_s *cfg, zpsync_result_s *out_res);

/**
 * @brief Dynamic port hopping during cruise (IPv6 or non-symmetric NAT).
 *        Switches the local & target UDP port to `zpsync_derive_target_port(S, new_epoch)`
 *        when ECMP/LAG congestion is detected, without tearing down `res->session`.
 *
 * @return 0 on success, negative error code on failure (previous socket kept).
 */
int zpsync_hop_port(zpsync_result_s *res, const uint8_t *secret, size_t secret_len,
                    uint64_t new_epoch);

/**
 * @brief Hitless Make-Before-Break port migration during cruise:
 *        Opens the new socket on `Port_Hop(S, new_epoch)` while keeping
 *        `res->sock` active, verifies the new path with an authenticated probe
 *        for up to @p verify_timeout_ms, and switches atomically only on ACK.
 *        Zero video frames are dropped if the new port is blocked.
 */
int zpsync_hop_make_before_break(zpsync_result_s *res, const uint8_t *secret,
                                 size_t secret_len, uint64_t new_epoch,
                                 uint32_t verify_timeout_ms);

int zpsync_hop_make_before_break_ex(zpsync_result_s *res, const uint8_t *secret,
                                    size_t secret_len, uint64_t new_epoch,
                                    uint16_t local_port_override,
                                    uint16_t peer_port_override,
                                    uint32_t verify_timeout_ms);

/**
 * @brief Closes the cruise socket and zeroizes the AEAD crypto context.
 */
void zpsync_close(zpsync_result_s *res);

/**
 * @brief Returns a human-readable name for @p path.
 */
const char *zpsync_path_name(zpsync_path_e path);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_H */
