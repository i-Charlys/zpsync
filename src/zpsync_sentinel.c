#include "zpsync_sentinel.h"
#include "zpsync_net.h"

#include <string.h>

#if defined(_WIN32)
#include <windows.h>
#include <iphlpapi.h>
#include <icmpapi.h>
#else
#include <fcntl.h>
#include <unistd.h>
#endif

static uint16_t read_be16(const uint8_t *p) {
  return (uint16_t)(((uint16_t)p[0] << 8) | (uint16_t)p[1]);
}

static uint32_t read_be32(const uint8_t *p) {
  return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
         (uint32_t)p[3];
}

static uint64_t read_be64(const uint8_t *p) {
  return ((uint64_t)read_be32(p) << 32) | (uint64_t)read_be32(p + 4);
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

static void write_be64(uint8_t *p, uint64_t v) {
  write_be32(p, (uint32_t)(v >> 32));
  write_be32(p + 4, (uint32_t)v);
}

uint16_t zpsync_icmp_checksum(const uint8_t *data, size_t len) {
  uint32_t sum = 0;
  size_t i = 0;
  while (i + 1U < len) {
    uint16_t word = (uint16_t)(((uint16_t)data[i] << 8) | (uint16_t)data[i + 1]);
    sum += word;
    i += 2U;
  }
  if (i < len) {
    sum += (uint32_t)((uint16_t)data[i] << 8);
  }
  while ((sum >> 16) != 0) {
    sum = (sum & 0xFFFFU) + (sum >> 16);
  }
  return (uint16_t)(~sum & 0xFFFFU);
}

static int seal_sentinel_payload(const uint8_t key[ZPSYNC_KEY_BYTES],
                                 const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                                 const zpsync_sentinel_info_s *info,
                                 uint8_t *out_sealed) {
  uint8_t plain[ZPSYNC_SENTINEL_PLAIN_BYTES];
  write_be32(plain, ZPSYNC_SENTINEL_MAGIC);
  write_be64(plain + 4, info->timestamp_ms);
  write_be16(plain + 12, info->udp_port);
  plain[14] = info->dscp;
  plain[15] = info->flags;
  write_be32(plain + 16, info->flow_entropy);
  write_be32(plain + 20, info->session_salt);

  static const uint8_t aad[] = "zpsync-sentinel-v1";
  memcpy(out_sealed, nonce, ZPSYNC_NONCE_BYTES);
  int rc = rudp_chacha20_poly1305_encrypt(
      key, nonce, aad, sizeof(aad) - 1U, plain, sizeof(plain),
      out_sealed + ZPSYNC_NONCE_BYTES,
      out_sealed + ZPSYNC_NONCE_BYTES + ZPSYNC_SENTINEL_PLAIN_BYTES);
  return rc == RUDP_OK ? 0 : -1;
}

int zpsync_sentinel_build_icmp(const uint8_t key[ZPSYNC_KEY_BYTES], uint16_t icmp_id,
                               uint16_t icmp_seq,
                               const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                               const zpsync_sentinel_info_s *info, uint8_t *out_icmp,
                               size_t max_len) {
  if (key == NULL || nonce == NULL || info == NULL || out_icmp == NULL ||
      max_len < ZPSYNC_SENTINEL_ICMP_BYTES) {
    return -1;
  }

  out_icmp[0] = ZPSYNC_ICMP_ECHO_REQUEST;
  out_icmp[1] = 0; /* Code 0 */
  out_icmp[2] = 0;
  out_icmp[3] = 0;
  write_be16(out_icmp + 4, icmp_id);
  write_be16(out_icmp + 6, icmp_seq);

  if (seal_sentinel_payload(key, nonce, info, out_icmp + ZPSYNC_ICMP_HEADER_BYTES) != 0) {
    return -1;
  }

  uint16_t csum = zpsync_icmp_checksum(out_icmp, ZPSYNC_SENTINEL_ICMP_BYTES);
  write_be16(out_icmp + 2, csum);
  return (int)ZPSYNC_SENTINEL_ICMP_BYTES;
}

int zpsync_sentinel_parse_icmp(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *pkt,
                               size_t pkt_len, zpsync_sentinel_info_s *out_info) {
  if (key == NULL || pkt == NULL || out_info == NULL) return -1;

  const uint8_t *icmp = pkt;
  size_t icmp_len = pkt_len;

  /* Strip IPv4 header if raw socket delivered the IP header (IHL * 4) */
  if (icmp_len >= 20U + ZPSYNC_SENTINEL_ICMP_BYTES && (pkt[0] >> 4) == 4U) {
    size_t ihl = (size_t)(pkt[0] & 0x0FU) * 4U;
    if (ihl < 20U || ihl + ZPSYNC_SENTINEL_ICMP_BYTES > icmp_len) return -1;
    if (pkt[9] != IPPROTO_ICMP) return -1;
    icmp = pkt + ihl;
    icmp_len -= ihl;
  }

  if (icmp_len < ZPSYNC_SENTINEL_ICMP_BYTES) return -1;
  if (icmp[0] != ZPSYNC_ICMP_ECHO_REQUEST && icmp[0] != ZPSYNC_ICMP_ECHO_REPLY) {
    return -1;
  }

  /* Verify RFC 1071 checksum */
  if (zpsync_icmp_checksum(icmp, ZPSYNC_SENTINEL_ICMP_BYTES) != 0) {
    return -1;
  }

  const uint8_t *sealed = icmp + ZPSYNC_ICMP_HEADER_BYTES;
  static const uint8_t aad[] = "zpsync-sentinel-v1";
  uint8_t plain[ZPSYNC_SENTINEL_PLAIN_BYTES];
  int rc = rudp_chacha20_poly1305_decrypt(
      key, sealed, aad, sizeof(aad) - 1U, sealed + ZPSYNC_NONCE_BYTES,
      ZPSYNC_SENTINEL_PLAIN_BYTES,
      sealed + ZPSYNC_NONCE_BYTES + ZPSYNC_SENTINEL_PLAIN_BYTES, plain);
  if (rc != RUDP_OK) return -1;

  if (read_be32(plain) != ZPSYNC_SENTINEL_MAGIC) return -1;

  out_info->timestamp_ms = read_be64(plain + 4);
  out_info->udp_port = read_be16(plain + 12);
  out_info->dscp = plain[14];
  out_info->flags = plain[15];
  out_info->flow_entropy = read_be32(plain + 16);
  out_info->session_salt = read_be32(plain + 20);
  return 0;
}

int zpsync_sentinel_send_v4(const uint8_t key[ZPSYNC_KEY_BYTES],
                            const uint8_t dst_ipv4[4], uint16_t icmp_id,
                            uint16_t icmp_seq, const zpsync_sentinel_info_s *info) {
  if (key == NULL || dst_ipv4 == NULL || info == NULL) return -1;
  if (zpsync_net_init() != 0) return -1;

  uint8_t nonce[ZPSYNC_NONCE_BYTES];
  if (zpsync_random_bytes(nonce, sizeof(nonce)) != 0) return -1;

  uint8_t icmp_pkt[ZPSYNC_SENTINEL_ICMP_BYTES];
  if (zpsync_sentinel_build_icmp(key, icmp_id, icmp_seq, nonce, info, icmp_pkt,
                                 sizeof(icmp_pkt)) < 0) {
    return -1;
  }

  /* Try raw ICMP socket first */
  zpsync_sock_t raw = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  if (raw != ZPSYNC_INVALID_SOCK) {
    struct sockaddr_in dst;
    memset(&dst, 0, sizeof(dst));
    dst.sin_family = AF_INET;
    memcpy(&dst.sin_addr, dst_ipv4, 4);
    int sent = sendto(raw, (const char *)icmp_pkt, (int)sizeof(icmp_pkt), 0,
                      (struct sockaddr *)&dst, sizeof(dst));
    zpsync_sock_close(raw);
    if (sent == (int)sizeof(icmp_pkt)) return 0;
  }

#if defined(_WIN32)
  /* Unprivileged Windows fallback via IcmpSendEcho (sends sealed 52B payload) */
  HANDLE hIcmp = IcmpCreateFile();
  if (hIcmp != INVALID_HANDLE_VALUE) {
    IPAddr dst_addr = 0;
    memcpy(&dst_addr, dst_ipv4, 4);
    uint8_t reply_buf[sizeof(ICMP_ECHO_REPLY) + ZPSYNC_SENTINEL_SEALED_BYTES + 16U];
    IcmpSendEcho(hIcmp, dst_addr, icmp_pkt + ZPSYNC_ICMP_HEADER_BYTES,
                 (WORD)ZPSYNC_SENTINEL_SEALED_BYTES, NULL, reply_buf,
                 (DWORD)sizeof(reply_buf), 50U);
    IcmpCloseHandle(hIcmp);
    return 0;
  }
#endif

  return -1;
}

int zpsync_sentinel_recv_v4(const uint8_t key[ZPSYNC_KEY_BYTES], uint32_t timeout_ms,
                            uint8_t out_src_ipv4[4],
                            zpsync_sentinel_info_s *out_info) {
  if (key == NULL || out_src_ipv4 == NULL || out_info == NULL) return -1;
  if (zpsync_net_init() != 0) return -1;

#if defined(__linux__)
  zpsync_sock_t sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_ICMP);
  if (sock == ZPSYNC_INVALID_SOCK) {
    sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
  }
#else
  zpsync_sock_t sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
#endif
  if (sock == ZPSYNC_INVALID_SOCK) return -1;

#if defined(_WIN32)
  u_long nb = 1UL;
  ioctlsocket(sock, FIONBIO, &nb);
#else
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
#endif

  uint64_t deadline = zpsync_now_ms() + timeout_ms;
  int rc = 1; /* timeout */
  while (zpsync_now_ms() < deadline) {
    uint8_t ready = 0;
    uint32_t rem = (uint32_t)(deadline - zpsync_now_ms());
    uint32_t wait_ms = rem < 50U ? rem : 50U;
    if (zpsync_poll_readable(&sock, 1, wait_ms, &ready) > 0 && (ready & 1U)) {
      uint8_t buf[512];
      uint8_t fam = 0;
      uint8_t src_addr[16];
      uint16_t src_port = 0;
      int n = zpsync_udp_recvfrom(sock, &fam, src_addr, &src_port, buf, sizeof(buf));
      if (n > 0 && zpsync_sentinel_parse_icmp(key, buf, (size_t)n, out_info) == 0) {
        memcpy(out_src_ipv4, src_addr, 4);
        rc = 0;
        break;
      }
    }
  }

  zpsync_sock_close(sock);
  return rc;
}
