#ifndef ZPSYNC_STUN_H
#define ZPSYNC_STUN_H

/**
 * @file zpsync_stun.h
 * @brief RFC 5389 STUN client for public IPv4/port discovery & NAT classification,
 *        plus local global-unicast IPv6 discovery.
 */

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_STUN_MAGIC_COOKIE 0x2112A442U
#define ZPSYNC_STUN_HEADER_BYTES 20U
#define ZPSYNC_STUN_DEFAULT_HOST "stun.cloudflare.com"
#define ZPSYNC_STUN_DEFAULT_PORT 3478U
#define ZPSYNC_STUN_ALT_HOST "stun.l.google.com"
#define ZPSYNC_STUN_ALT_PORT 19302U

typedef enum {
  ZPSYNC_NAT_UNKNOWN = 0,
  ZPSYNC_NAT_OPEN_INTERNET = 1,
  ZPSYNC_NAT_CONE = 2,      /**< Endpoint-independent mapping (box standard) */
  ZPSYNC_NAT_SYMMETRIC = 3  /**< Endpoint-dependent mapping (CGNAT / 4G / 5G IPv4) */
} zpsync_nat_type_e;

typedef struct {
  uint8_t family;      /**< 4 for IPv4, 6 for IPv6 */
  uint8_t addr[16];    /**< IPv4 in first 4 bytes, or IPv6 in 16 bytes (net order) */
  uint16_t port;       /**< Mapped public UDP port (host byte order) */
  uint8_t valid;       /**< Non-zero if discovery succeeded */
} zpsync_mapped_addr_s;

typedef struct {
  zpsync_mapped_addr_s public_v4;
  uint8_t local_ipv6[16];
  uint8_t has_ipv6;
  zpsync_nat_type_e nat_type;
  uint32_t rtt_ms;
} zpsync_net_probe_s;

/**
 * @brief Builds a 20-byte RFC 5389 STUN Binding Request.
 *
 * @param tx_id 12-byte random transaction ID.
 * @param out_buf Output buffer (>= 20 bytes).
 * @return 20 on success, or negative error code.
 */
int zpsync_stun_build_binding_request(const uint8_t tx_id[12], uint8_t *out_buf,
                                      size_t max_len);

/**
 * @brief Parses an RFC 5389 STUN Binding Response and extracts
 *        XOR-MAPPED-ADDRESS (0x0020) or MAPPED-ADDRESS (0x0001).
 *
 * @param expected_tx_id 12-byte transaction ID from the request.
 * @param pkt Raw UDP response payload.
 * @param pkt_len Length of @p pkt in bytes.
 * @param out_addr Extracted public IP and port.
 * @return 0 on success, or negative error code.
 */
int zpsync_stun_parse_binding_response(const uint8_t expected_tx_id[12],
                                       const uint8_t *pkt, size_t pkt_len,
                                       zpsync_mapped_addr_s *out_addr);

/**
 * @brief Probes a single STUN server over UDP to obtain public IPv4:port.
 *        If @p local_port_hint is non-zero, binds the probe socket to it so
 *        cone-NAT mappings match the port used by RUDP.
 */
int zpsync_stun_query_v4(const char *host, uint16_t port, uint16_t local_port_hint,
                         uint32_t timeout_ms, zpsync_mapped_addr_s *out_addr,
                         uint32_t *out_rtt_ms);

/**
 * @brief Discovers the host's global unicast IPv6 address (non-link-local,
 *        non-loopback) without emitting network packets (UDP connect trick).
 */
int zpsync_discover_local_ipv6(uint8_t out_ipv6[16]);

/**
 * @brief Runs full local + public network discovery:
 *        1. Local global IPv6 check.
 *        2. Primary STUN query (stun.cloudflare.com:3478).
 *        3. Secondary STUN query (stun.l.google.com:19302) from the same local
 *           socket to detect Symmetric NAT (different external ports).
 */
int zpsync_probe_network(uint16_t local_port_hint, uint32_t timeout_ms,
                         zpsync_net_probe_s *out_probe);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_STUN_H */
