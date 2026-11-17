#include "zpsync_stun.h"
#include "zpsync_crypto.h"
#include "zpsync_net.h"

#include <string.h>

#define STUN_TYPE_BINDING_REQUEST 0x0001U
#define STUN_TYPE_BINDING_RESPONSE 0x0101U
#define STUN_ATTR_MAPPED_ADDRESS 0x0001U
#define STUN_ATTR_XOR_MAPPED_ADDRESS 0x0020U

static uint16_t read_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

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

int zpsync_stun_build_binding_request(const uint8_t tx_id[12], uint8_t *out_buf,
                                      size_t max_len) {
  if (tx_id == NULL || out_buf == NULL || max_len < ZPSYNC_STUN_HEADER_BYTES) {
    return -1;
  }
  write_be16(out_buf, STUN_TYPE_BINDING_REQUEST);
  write_be16(out_buf + 2, 0);
  write_be32(out_buf + 4, ZPSYNC_STUN_MAGIC_COOKIE);
  memcpy(out_buf + 8, tx_id, 12);
  return (int)ZPSYNC_STUN_HEADER_BYTES;
}

int zpsync_stun_parse_binding_response(const uint8_t expected_tx_id[12],
                                       const uint8_t *pkt, size_t pkt_len,
                                       zpsync_mapped_addr_s *out_addr) {
  if (expected_tx_id == NULL || pkt == NULL || out_addr == NULL ||
      pkt_len < ZPSYNC_STUN_HEADER_BYTES) {
    return -1;
  }

  uint16_t msg_type = read_be16(pkt);
  uint16_t msg_len = read_be16(pkt + 2);
  uint32_t cookie = read_be32(pkt + 4);
  if (msg_type != STUN_TYPE_BINDING_RESPONSE || cookie != ZPSYNC_STUN_MAGIC_COOKIE) {
    return -1;
  }
  if (memcmp(pkt + 8, expected_tx_id, 12) != 0) {
    return -1;
  }
  if ((size_t)msg_len + ZPSYNC_STUN_HEADER_BYTES > pkt_len) {
    return -1;
  }

  memset(out_addr, 0, sizeof(*out_addr));
  bool found_mapped = false;
  size_t pos = ZPSYNC_STUN_HEADER_BYTES;
  size_t end = ZPSYNC_STUN_HEADER_BYTES + msg_len;

  while (pos + 4U <= end) {
    uint16_t attr_type = read_be16(pkt + pos);
    uint16_t attr_len = read_be16(pkt + pos + 2);
    pos += 4U;
    if (pos + attr_len > end) break;

    if (attr_type == STUN_ATTR_XOR_MAPPED_ADDRESS && attr_len >= 8U) {
      uint8_t fam = pkt[pos + 1];
      uint16_t xport = read_be16(pkt + pos + 2);
      out_addr->port = (uint16_t)(xport ^ (uint16_t)(ZPSYNC_STUN_MAGIC_COOKIE >> 16));
      if (fam == 0x01U && attr_len >= 8U) {
        out_addr->family = 4;
        uint32_t xip = read_be32(pkt + pos + 4) ^ ZPSYNC_STUN_MAGIC_COOKIE;
        write_be32(out_addr->addr, xip);
        out_addr->valid = 1;
        return 0; /* Prefer XOR-MAPPED-ADDRESS */
      } else if (fam == 0x02U && attr_len >= 20U) {
        out_addr->family = 6;
        uint8_t mask[16];
        write_be32(mask, ZPSYNC_STUN_MAGIC_COOKIE);
        memcpy(mask + 4, expected_tx_id, 12);
        for (size_t i = 0; i < 16; ++i) {
          out_addr->addr[i] = (uint8_t)(pkt[pos + 4 + i] ^ mask[i]);
        }
        out_addr->valid = 1;
        return 0;
      }
    } else if (attr_type == STUN_ATTR_MAPPED_ADDRESS && attr_len >= 8U &&
               !found_mapped) {
      uint8_t fam = pkt[pos + 1];
      out_addr->port = read_be16(pkt + pos + 2);
      if (fam == 0x01U && attr_len >= 8U) {
        out_addr->family = 4;
        memcpy(out_addr->addr, pkt + pos + 4, 4);
        out_addr->valid = 1;
        found_mapped = true;
      } else if (fam == 0x02U && attr_len >= 20U) {
        out_addr->family = 6;
        memcpy(out_addr->addr, pkt + pos + 4, 16);
        out_addr->valid = 1;
        found_mapped = true;
      }
    }

    size_t padded = (attr_len + 3U) & ~3U;
    pos += padded;
  }

  return found_mapped ? 0 : -1;
}

static int stun_query_on_sock(zpsync_sock_t sock, const char *host, uint16_t port,
                              uint32_t timeout_ms, zpsync_mapped_addr_s *out_addr,
                              uint32_t *out_rtt_ms) {
  uint8_t fam = 0;
  uint8_t server_ip[16];
  if (zpsync_resolve_host(host, 4, &fam, server_ip) != 0 || fam != 4) {
    return -1;
  }

  uint8_t tx_id[12];
  if (zpsync_random_bytes(tx_id, sizeof(tx_id)) != 0) {
    memset(tx_id, 0x5A, sizeof(tx_id));
  }

  uint8_t req[ZPSYNC_STUN_HEADER_BYTES];
  zpsync_stun_build_binding_request(tx_id, req, sizeof(req));

  uint64_t t0 = zpsync_now_ms();
  uint64_t deadline = t0 + (timeout_ms > 0 ? timeout_ms : 1500U);
  uint64_t next_tx = t0;

  while (zpsync_now_ms() < deadline) {
    uint64_t now = zpsync_now_ms();
    if (now >= next_tx) {
      zpsync_udp_sendto(sock, 4, server_ip, port, req, sizeof(req));
      next_tx = now + 350U;
    }

    uint8_t ready = 0;
    uint32_t rem = (uint32_t)(deadline - now);
    uint32_t wait_ms = rem < 100U ? rem : 100U;
    if (zpsync_poll_readable(&sock, 1, wait_ms, &ready) > 0 && (ready & 1U)) {
      uint8_t rx_buf[512];
      uint8_t src_fam = 0;
      uint8_t src_ip[16];
      uint16_t src_port = 0;
      int n = zpsync_udp_recvfrom(sock, &src_fam, src_ip, &src_port, rx_buf,
                                  sizeof(rx_buf));
      if (n > 0 &&
          zpsync_stun_parse_binding_response(tx_id, rx_buf, (size_t)n, out_addr) == 0) {
        if (out_rtt_ms != NULL) {
          uint64_t elapsed = zpsync_now_ms() - t0;
          *out_rtt_ms = (uint32_t)(elapsed > 0 ? elapsed : 1U);
        }
        return 0;
      }
    }
  }
  return -1;
}

int zpsync_stun_query_v4(const char *host, uint16_t port, uint16_t local_port_hint,
                         uint32_t timeout_ms, zpsync_mapped_addr_s *out_addr,
                         uint32_t *out_rtt_ms) {
  if (host == NULL || port == 0 || out_addr == NULL) return -1;
  uint16_t bound = 0;
  zpsync_sock_t sock = zpsync_udp_open(4, local_port_hint, true, true, &bound);
  if (sock == ZPSYNC_INVALID_SOCK) return -1;
  int rc = stun_query_on_sock(sock, host, port, timeout_ms, out_addr, out_rtt_ms);
  zpsync_sock_close(sock);
  return rc;
}

int zpsync_discover_local_ipv6(uint8_t out_ipv6[16]) {
  if (out_ipv6 == NULL) return -1;
  if (zpsync_net_init() != 0) return -1;

  zpsync_sock_t sock = socket(AF_INET6, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == ZPSYNC_INVALID_SOCK) return -1;

  /* UDP connect to Cloudflare public DNS IPv6 (no packets sent on wire) */
  struct sockaddr_in6 dst;
  memset(&dst, 0, sizeof(dst));
  dst.sin6_family = AF_INET6;
  dst.sin6_port = htons(53);
  inet_pton(AF_INET6, "2606:4700:4700::1111", &dst.sin6_addr);

  int rc = -1;
  if (connect(sock, (struct sockaddr *)&dst, sizeof(dst)) == 0) {
    struct sockaddr_in6 local;
    socklen_t len = sizeof(local);
    if (getsockname(sock, (struct sockaddr *)&local, &len) == 0 &&
        local.sin6_family == AF_INET6) {
      const uint8_t *b = (const uint8_t *)&local.sin6_addr;
      /* Reject unspecified (::), loopback (::1), and link-local (fe80::/10) */
      bool is_link_local = (b[0] == 0xFEU && (b[1] & 0xC0U) == 0x80U);
      bool is_ula = ((b[0] & 0xFEU) == 0xFCU);
      static const uint8_t zeros[15] = {0};
      bool is_unspec_or_loop = (memcmp(b, zeros, 15) == 0 && (b[15] == 0 || b[15] == 1));
      if (!is_link_local && !is_ula && !is_unspec_or_loop) {
        memcpy(out_ipv6, b, 16);
        rc = 0;
      }
    }
  }

  zpsync_sock_close(sock);
  return rc;
}

int zpsync_probe_network(uint16_t local_port_hint, uint32_t timeout_ms,
                         zpsync_net_probe_s *out_probe) {
  if (out_probe == NULL) return -1;
  memset(out_probe, 0, sizeof(*out_probe));

  if (zpsync_discover_local_ipv6(out_probe->local_ipv6) == 0) {
    out_probe->has_ipv6 = 1;
  }

  uint16_t bound_port = 0;
  zpsync_sock_t sock = zpsync_udp_open(4, local_port_hint, true, true, &bound_port);
  if (sock == ZPSYNC_INVALID_SOCK) {
    return out_probe->has_ipv6 ? 0 : -1;
  }

  uint32_t rtt1 = 0;
  int rc1 = stun_query_on_sock(sock, ZPSYNC_STUN_DEFAULT_HOST, ZPSYNC_STUN_DEFAULT_PORT,
                               timeout_ms, &out_probe->public_v4, &rtt1);
  if (rc1 == 0) {
    out_probe->rtt_ms = rtt1;
    zpsync_mapped_addr_s alt;
    memset(&alt, 0, sizeof(alt));
    if (stun_query_on_sock(sock, ZPSYNC_STUN_ALT_HOST, ZPSYNC_STUN_ALT_PORT,
                           timeout_ms, &alt, NULL) == 0) {
      if (alt.port != out_probe->public_v4.port) {
        out_probe->nat_type = ZPSYNC_NAT_SYMMETRIC;
      } else if (alt.port == bound_port) {
        out_probe->nat_type = ZPSYNC_NAT_OPEN_INTERNET;
      } else {
        out_probe->nat_type = ZPSYNC_NAT_CONE;
      }
    } else {
      out_probe->nat_type = ZPSYNC_NAT_CONE;
    }
  }

  zpsync_sock_close(sock);
  return (out_probe->has_ipv6 || out_probe->public_v4.valid) ? 0 : -1;
}
