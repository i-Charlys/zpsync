#include "zpsync_punch.h"
#include "zpsync_net.h"

#include <string.h>

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

int zpsync_hs_seal(const uint8_t key[ZPSYNC_KEY_BYTES],
                   const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                   const zpsync_hs_msg_s *msg, uint8_t *out_wire, size_t max_len) {
  if (key == NULL || nonce == NULL || msg == NULL || out_wire == NULL ||
      max_len < ZPSYNC_HS_WIRE_BYTES) {
    return -1;
  }

  uint8_t plain[ZPSYNC_HS_PLAIN_BYTES];
  write_be32(plain, ZPSYNC_HANDSHAKE_MAGIC);
  plain[4] = msg->msg_type;
  plain[5] = msg->flags;
  write_be16(plain + 6, msg->hop_epoch);
  write_be64(plain + 8, msg->session_id);
  write_be64(plain + 16, msg->peer_nonce);

  static const uint8_t aad[] = "zpsync-hs-v1";
  memcpy(out_wire, nonce, ZPSYNC_NONCE_BYTES);
  int rc = rudp_chacha20_poly1305_encrypt(
      key, nonce, aad, sizeof(aad) - 1U, plain, sizeof(plain),
      out_wire + ZPSYNC_NONCE_BYTES,
      out_wire + ZPSYNC_NONCE_BYTES + ZPSYNC_HS_PLAIN_BYTES);
  return rc == RUDP_OK ? (int)ZPSYNC_HS_WIRE_BYTES : -1;
}

int zpsync_hs_open(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *wire,
                   size_t wire_len, zpsync_hs_msg_s *out_msg) {
  if (key == NULL || wire == NULL || out_msg == NULL ||
      wire_len != ZPSYNC_HS_WIRE_BYTES) {
    return -1;
  }

  static const uint8_t aad[] = "zpsync-hs-v1";
  uint8_t plain[ZPSYNC_HS_PLAIN_BYTES];
  int rc = rudp_chacha20_poly1305_decrypt(
      key, wire, aad, sizeof(aad) - 1U, wire + ZPSYNC_NONCE_BYTES,
      ZPSYNC_HS_PLAIN_BYTES, wire + ZPSYNC_NONCE_BYTES + ZPSYNC_HS_PLAIN_BYTES,
      plain);
  if (rc != RUDP_OK) return -1;
  if (read_be32(plain) != ZPSYNC_HANDSHAKE_MAGIC) return -1;

  out_msg->msg_type = plain[4];
  out_msg->flags = plain[5];
  out_msg->hop_epoch = read_be16(plain + 6);
  out_msg->session_id = read_be64(plain + 8);
  out_msg->peer_nonce = read_be64(plain + 16);
  return 0;
}

static int send_hs(zpsync_sock_t sock, uint8_t family, const uint8_t addr[16],
                   uint16_t port, const uint8_t key[ZPSYNC_KEY_BYTES],
                   uint8_t msg_type, uint64_t session_id, uint64_t local_nonce) {
  uint8_t nonce[ZPSYNC_NONCE_BYTES];
  if (zpsync_random_bytes(nonce, sizeof(nonce)) != 0) return -1;
  zpsync_hs_msg_s msg = {.msg_type = msg_type,
                         .flags = 0,
                         .hop_epoch = 0,
                         .session_id = session_id,
                         .peer_nonce = local_nonce};
  uint8_t wire[ZPSYNC_HS_WIRE_BYTES];
  if (zpsync_hs_seal(key, nonce, &msg, wire, sizeof(wire)) < 0) return -1;
  return zpsync_udp_sendto(sock, family, addr, port, wire, sizeof(wire));
}

static int run_single_socket_handshake(const uint8_t key[ZPSYNC_KEY_BYTES],
                                       uint8_t family, const uint8_t peer_addr[16],
                                       uint16_t local_port, uint16_t peer_port,
                                       uint64_t local_nonce, uint32_t timeout_ms,
                                       zpsync_punch_out_s *out) {
  uint16_t bound_port = 0;
  zpsync_sock_t sock = zpsync_udp_open(family, local_port, true, true, &bound_port);
  if (sock == ZPSYNC_INVALID_SOCK) return -1;

  uint64_t t0 = zpsync_now_ms();
  uint64_t deadline = t0 + (timeout_ms > 0 ? timeout_ms : 2500U);
  uint64_t next_tx = t0;
  uint64_t first_syn_tx = 0;
  bool sent_syn_ack = false;
  bool established = false;
  uint64_t remote_nonce = 0;
  uint64_t session_id = 0;
  uint16_t actual_peer_port = peer_port;
  uint8_t actual_peer_addr[16];
  memcpy(actual_peer_addr, peer_addr, 16);

  while (zpsync_now_ms() < deadline) {
    uint64_t now = zpsync_now_ms();
    if (now >= next_tx) {
      if (!sent_syn_ack) {
        send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                ZPSYNC_HS_TYPE_SYN, 0, local_nonce);
        if (first_syn_tx == 0) first_syn_tx = now;
      } else {
        send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                ZPSYNC_HS_TYPE_SYN_ACK, session_id, local_nonce);
      }
      next_tx = now + 40U;
    }

    uint8_t ready = 0;
    uint32_t rem = (uint32_t)(deadline - now);
    uint32_t wait_ms = rem < 25U ? rem : 25U;
    if (zpsync_poll_readable(&sock, 1, wait_ms, &ready) > 0 && (ready & 1U)) {
      uint8_t rx[256];
      uint8_t r_fam = 0;
      uint8_t r_addr[16];
      uint16_t r_port = 0;
      int n = zpsync_udp_recvfrom(sock, &r_fam, r_addr, &r_port, rx, sizeof(rx));
      zpsync_hs_msg_s msg;
      if (n == (int)ZPSYNC_HS_WIRE_BYTES &&
          zpsync_hs_open(key, rx, (size_t)n, &msg) == 0 &&
          msg.peer_nonce != local_nonce) {
        memcpy(actual_peer_addr, r_addr, 16);
        actual_peer_port = r_port;
        remote_nonce = msg.peer_nonce;
        session_id = local_nonce ^ remote_nonce;
        if (session_id == 0) session_id = 1ULL;

        if (msg.msg_type == ZPSYNC_HS_TYPE_SYN) {
          sent_syn_ack = true;
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_SYN_ACK, session_id, local_nonce);
        } else if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK) {
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_ACK, session_id, local_nonce);
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_ACK, session_id, local_nonce);
          established = true;
          break;
        } else if (msg.msg_type == ZPSYNC_HS_TYPE_ACK) {
          established = true;
          break;
        }
      }
    }
  }

  if (!established) {
    zpsync_sock_close(sock);
    return -1;
  }

  zpsync_sock_connect_peer(sock, family, actual_peer_addr, actual_peer_port);

  memset(out, 0, sizeof(*out));
  out->sock = sock;
  memcpy(out->peer_addr, actual_peer_addr, 16);
  out->family = family;
  out->local_port = bound_port;
  out->peer_port = actual_peer_port;
  out->session_id = session_id;
  out->remote_nonce = remote_nonce;
  out->local_is_initiator = (local_nonce < remote_nonce) ? 1U : 0U;
  uint64_t rtt = (first_syn_tx > 0) ? (zpsync_now_ms() - first_syn_tx) : 1ULL;
  out->rtt_ms = (uint32_t)(rtt > 0 ? rtt : 1ULL);
  return 0;
}

int zpsync_punch_ipv6_direct(const uint8_t key[ZPSYNC_KEY_BYTES],
                             const uint8_t peer_ipv6[16], uint16_t local_port,
                             uint16_t peer_port, uint64_t local_nonce,
                             uint32_t timeout_ms, zpsync_punch_out_s *out) {
  if (key == NULL || peer_ipv6 == NULL || peer_port == 0 || out == NULL) {
    return -1;
  }
  return run_single_socket_handshake(key, 6, peer_ipv6, local_port, peer_port,
                                     local_nonce, timeout_ms, out);
}

int zpsync_punch_ipv4_sentinel(const uint8_t key[ZPSYNC_KEY_BYTES],
                               const uint8_t peer_ipv4[4], uint16_t local_port,
                               uint16_t peer_port, uint64_t local_nonce,
                               uint32_t flow_entropy, uint32_t timeout_ms,
                               bool use_icmp_sentinel, zpsync_punch_out_s *out) {
  if (key == NULL || peer_ipv4 == NULL || peer_port == 0 || out == NULL) {
    return -1;
  }

  if (use_icmp_sentinel) {
    zpsync_sentinel_info_s sinfo = {.timestamp_ms = zpsync_now_ms(),
                                    .flow_entropy = flow_entropy,
                                    .session_salt = (uint32_t)(local_nonce & 0xFFFFFFFFU),
                                    .udp_port = local_port,
                                    .dscp = 46U, /* EF for ultra-low-latency video */
                                    .flags = 1U};
    /* Best-effort Layer 3 ICMP sentinel wake-up; ignore OS privilege errors */
    (void)zpsync_sentinel_send_v4(key, peer_ipv4, (uint16_t)(local_nonce & 0xFFFFU),
                                  1U, &sinfo);
  }

  uint8_t addr16[16] = {0};
  memcpy(addr16, peer_ipv4, 4);
  return run_single_socket_handshake(key, 4, addr16, local_port, peer_port,
                                     local_nonce, timeout_ms, out);
}

int zpsync_punch_ipv4_birthday(const uint8_t *secret, size_t secret_len,
                               const uint8_t key[ZPSYNC_KEY_BYTES],
                               const uint8_t peer_ipv4[4],
                               uint16_t peer_base_port, uint32_t socket_count,
                               uint64_t local_nonce, uint32_t timeout_ms,
                               zpsync_punch_out_s *out) {
  if (secret == NULL || secret_len == 0 || key == NULL || peer_ipv4 == NULL ||
      out == NULL) {
    return -1;
  }

  if (socket_count < ZPSYNC_BIRTHDAY_MIN_SOCKETS) {
    socket_count = ZPSYNC_BIRTHDAY_DEFAULT_SOCKETS;
  }
  if (socket_count > ZPSYNC_BIRTHDAY_MAX_SOCKETS) {
    socket_count = ZPSYNC_BIRTHDAY_MAX_SOCKETS;
  }

  zpsync_sock_t socks[ZPSYNC_BIRTHDAY_MAX_SOCKETS];
  uint16_t local_ports[ZPSYNC_BIRTHDAY_MAX_SOCKETS];
  uint16_t target_ports[ZPSYNC_BIRTHDAY_MAX_SOCKETS];
  size_t opened = 0;

  for (uint32_t i = 0; i < socket_count; ++i) {
    uint16_t derived = zpsync_derive_birthday_port(secret, secret_len, i);
    uint16_t bound = 0;
    zpsync_sock_t s = zpsync_udp_open(4, derived, true, true, &bound);
    if (s == ZPSYNC_INVALID_SOCK) {
      /* Fallback to ephemeral port if derived port is busy locally */
      s = zpsync_udp_open(4, 0, true, true, &bound);
    }
    if (s != ZPSYNC_INVALID_SOCK) {
      socks[opened] = s;
      local_ports[opened] = bound;
      /* Combine incremental +1/+2 prediction on first 32 slots & birthday ports */
      if (peer_base_port > 0 && i < 32U) {
        uint32_t p = (uint32_t)peer_base_port + i;
        target_ports[opened] = (uint16_t)(p <= 65535U ? p : derived);
      } else {
        target_ports[opened] = derived;
      }
      ++opened;
    }
  }

  if (opened == 0) return -1;

  uint8_t peer_addr16[16] = {0};
  memcpy(peer_addr16, peer_ipv4, 4);

  uint64_t t0 = zpsync_now_ms();
  uint64_t deadline = t0 + (timeout_ms > 0 ? timeout_ms : 2000U);
  size_t spray_cursor = 0;
  size_t winner_idx = (size_t)-1;
  uint16_t winner_peer_port = 0;
  uint8_t winner_peer_addr[16] = {0};
  uint64_t winner_session_id = 0;
  uint64_t winner_remote_nonce = 0;

  while (zpsync_now_ms() < deadline && winner_idx == (size_t)-1) {
    /* Spray a paced batch of 32 packets per iteration to avoid OS buffer drops */
    for (int b = 0; b < 32; ++b) {
      size_t idx = spray_cursor % opened;
      uint16_t dst_p = target_ports[(spray_cursor + (size_t)b) % opened];
      send_hs(socks[idx], 4, peer_addr16, dst_p, key, ZPSYNC_HS_TYPE_SYN, 0,
              local_nonce);
      ++spray_cursor;
    }

    uint8_t ready_bmap[(ZPSYNC_BIRTHDAY_MAX_SOCKETS + 7U) / 8U];
    if (zpsync_poll_readable(socks, opened, 15U, ready_bmap) > 0) {
      for (size_t i = 0; i < opened; ++i) {
        if ((ready_bmap[i >> 3] & (1U << (i & 7U))) == 0) continue;
        uint8_t rx[256];
        uint8_t r_fam = 0;
        uint8_t r_addr[16];
        uint16_t r_port = 0;
        int n = zpsync_udp_recvfrom(socks[i], &r_fam, r_addr, &r_port, rx, sizeof(rx));
        zpsync_hs_msg_s msg;
        if (n == (int)ZPSYNC_HS_WIRE_BYTES &&
            zpsync_hs_open(key, rx, (size_t)n, &msg) == 0 &&
            msg.peer_nonce != local_nonce) {
          uint64_t sid = local_nonce ^ msg.peer_nonce;
          if (sid == 0) sid = 1ULL;
          if (msg.msg_type == ZPSYNC_HS_TYPE_SYN) {
            send_hs(socks[i], 4, r_addr, r_port, key, ZPSYNC_HS_TYPE_SYN_ACK, sid,
                    local_nonce);
          } else if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK) {
            send_hs(socks[i], 4, r_addr, r_port, key, ZPSYNC_HS_TYPE_ACK, sid,
                    local_nonce);
            send_hs(socks[i], 4, r_addr, r_port, key, ZPSYNC_HS_TYPE_ACK, sid,
                    local_nonce);
          }
          /* Lock the winning socket immediately on SYN_ACK or ACK (or SYN+ACK) */
          if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK ||
              msg.msg_type == ZPSYNC_HS_TYPE_ACK) {
            winner_idx = i;
            winner_peer_port = r_port;
            memcpy(winner_peer_addr, r_addr, 16);
            winner_session_id = sid;
            winner_remote_nonce = msg.peer_nonce;
            break;
          }
        }
      }
    }
  }

  /* Close all non-winning sockets immediately */
  for (size_t i = 0; i < opened; ++i) {
    if (i != winner_idx) {
      zpsync_sock_close(socks[i]);
    }
  }

  if (winner_idx == (size_t)-1) return -1;

  zpsync_sock_t win_sock = socks[winner_idx];
  zpsync_sock_connect_peer(win_sock, 4, winner_peer_addr, winner_peer_port);

  memset(out, 0, sizeof(*out));
  out->sock = win_sock;
  memcpy(out->peer_addr, winner_peer_addr, 16);
  out->family = 4;
  out->local_port = local_ports[winner_idx];
  out->peer_port = winner_peer_port;
  out->session_id = winner_session_id;
  out->remote_nonce = winner_remote_nonce;
  out->local_is_initiator = (local_nonce < winner_remote_nonce) ? 1U : 0U;
  uint64_t rtt = zpsync_now_ms() - t0;
  out->rtt_ms = (uint32_t)(rtt > 0 ? rtt : 1ULL);
  return 0;
}
