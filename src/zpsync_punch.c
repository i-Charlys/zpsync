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
  memcpy(plain + 24, msg->ephemeral_pub, ZPSYNC_X25519_BYTES);

  static const uint8_t aad[] = "zpsync-hs-v2";
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

  static const uint8_t aad[] = "zpsync-hs-v2";
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
  memcpy(out_msg->ephemeral_pub, plain + 24, ZPSYNC_X25519_BYTES);
  return 0;
}

static int send_hs(zpsync_sock_t sock, uint8_t family, const uint8_t addr[16],
                   uint16_t port, const uint8_t key[ZPSYNC_KEY_BYTES],
                   uint8_t msg_type, uint64_t session_id, uint64_t local_nonce,
                   const uint8_t eph_pub[ZPSYNC_X25519_BYTES]) {
  uint8_t nonce[ZPSYNC_NONCE_BYTES];
  if (zpsync_random_bytes(nonce, sizeof(nonce)) != 0) return -1;
  zpsync_hs_msg_s msg = {.msg_type = msg_type,
                         .flags = 0,
                         .hop_epoch = 0,
                         .session_id = session_id,
                         .peer_nonce = local_nonce};
  memcpy(msg.ephemeral_pub, eph_pub, ZPSYNC_X25519_BYTES);
  uint8_t wire[ZPSYNC_HS_WIRE_BYTES];
  if (zpsync_hs_seal(key, nonce, &msg, wire, sizeof(wire)) < 0) return -1;
  return zpsync_udp_sendto(sock, family, addr, port, wire, sizeof(wire));
}

static void finalize_pfs(const uint8_t base_key[ZPSYNC_KEY_BYTES],
                         const uint8_t eph_priv[ZPSYNC_X25519_BYTES],
                         const uint8_t remote_pub[ZPSYNC_X25519_BYTES],
                         uint64_t session_id, zpsync_punch_out_s *out) {
  uint8_t shared[ZPSYNC_X25519_BYTES];
  if (zpsync_x25519_shared(eph_priv, remote_pub, shared) == 0 &&
      zpsync_derive_pfs_key(base_key, shared, session_id, out->pfs_key) == 0) {
    out->pfs_enabled = 1U;
  } else {
    memcpy(out->pfs_key, base_key, ZPSYNC_KEY_BYTES);
    out->pfs_enabled = 0U;
  }
}

static int run_single_socket_handshake(const uint8_t key[ZPSYNC_KEY_BYTES],
                                       uint8_t family, const uint8_t peer_addr[16],
                                       uint16_t local_port, uint16_t peer_port,
                                       uint64_t local_nonce, uint32_t timeout_ms,
                                       zpsync_punch_out_s *out) {
  uint8_t eph_priv[ZPSYNC_X25519_BYTES];
  uint8_t eph_pub[ZPSYNC_X25519_BYTES];
  if (zpsync_x25519_keygen(eph_priv, eph_pub) != 0) return -1;

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
  uint8_t remote_eph_pub[ZPSYNC_X25519_BYTES] = {0};
  memcpy(actual_peer_addr, peer_addr, 16);

  while (zpsync_now_ms() < deadline) {
    uint64_t now = zpsync_now_ms();
    if (now >= next_tx) {
      if (!sent_syn_ack) {
        send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                ZPSYNC_HS_TYPE_SYN, 0, local_nonce, eph_pub);
        if (first_syn_tx == 0) first_syn_tx = now;
      } else {
        send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                ZPSYNC_HS_TYPE_SYN_ACK, session_id, local_nonce, eph_pub);
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
        memcpy(remote_eph_pub, msg.ephemeral_pub, ZPSYNC_X25519_BYTES);
        session_id = local_nonce ^ remote_nonce;
        if (session_id == 0) session_id = 1ULL;

        if (msg.msg_type == ZPSYNC_HS_TYPE_SYN) {
          sent_syn_ack = true;
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_SYN_ACK, session_id, local_nonce, eph_pub);
        } else if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK) {
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_ACK, session_id, local_nonce, eph_pub);
          send_hs(sock, family, actual_peer_addr, actual_peer_port, key,
                  ZPSYNC_HS_TYPE_ACK, session_id, local_nonce, eph_pub);
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
  finalize_pfs(key, eph_priv, remote_eph_pub, session_id, out);
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
                                    .dscp = 46U,
                                    .flags = 1U};
    (void)zpsync_sentinel_send_v4(key, peer_ipv4, (uint16_t)(local_nonce & 0xFFFFU),
                                  1U, &sinfo);
  }

  uint8_t addr16[16] = {0};
  memcpy(addr16, peer_ipv4, 4);
  return run_single_socket_handshake(key, 4, addr16, local_port, peer_port,
                                     local_nonce, timeout_ms, out);
}

int zpsync_punch_race_v6_v4(const uint8_t key[ZPSYNC_KEY_BYTES],
                            const uint8_t *peer_ipv6, uint16_t v6_local_port,
                            uint16_t v6_peer_port, const uint8_t *peer_ipv4,
                            uint16_t v4_local_port, uint16_t v4_peer_port,
                            uint64_t local_nonce, uint32_t flow_entropy,
                            bool use_icmp_sentinel, uint32_t timeout_ms,
                            zpsync_punch_out_s *out) {
  if (key == NULL || out == NULL) return -1;
  if (peer_ipv6 == NULL && peer_ipv4 == NULL) return -1;
  if (peer_ipv6 == NULL) {
    return zpsync_punch_ipv4_sentinel(key, peer_ipv4, v4_local_port, v4_peer_port,
                                      local_nonce, flow_entropy, timeout_ms,
                                      use_icmp_sentinel, out);
  }
  if (peer_ipv4 == NULL) {
    return zpsync_punch_ipv6_direct(key, peer_ipv6, v6_local_port, v6_peer_port,
                                    local_nonce, timeout_ms, out);
  }

  uint8_t eph_priv[ZPSYNC_X25519_BYTES];
  uint8_t eph_pub[ZPSYNC_X25519_BYTES];
  if (zpsync_x25519_keygen(eph_priv, eph_pub) != 0) return -1;

  uint16_t bound_v6 = 0, bound_v4 = 0;
  zpsync_sock_t s6 = zpsync_udp_open(6, v6_local_port, true, true, &bound_v6);
  zpsync_sock_t s4 = ZPSYNC_INVALID_SOCK;
  bool v4_started = false;
  bool sent_syn_ack_v6 = false, sent_syn_ack_v4 = false;

  uint64_t t0 = zpsync_now_ms();
  uint64_t deadline = t0 + (timeout_ms > 0 ? timeout_ms : 2500U);
  uint64_t v4_start_at = t0 + 80U; /* Happy-Eyeballs 80ms head-start for IPv6 */
  uint64_t next_tx_v6 = t0, next_tx_v4 = v4_start_at;

  uint8_t v4_addr16[16] = {0};
  memcpy(v4_addr16, peer_ipv4, 4);

  int winner = -1; /* 0 = v6, 1 = v4 */
  uint8_t win_addr[16] = {0};
  uint16_t win_port = 0;
  uint64_t win_sid = 0, win_rnonce = 0;
  uint8_t win_rpub[ZPSYNC_X25519_BYTES] = {0};

  while (zpsync_now_ms() < deadline && winner < 0) {
    uint64_t now = zpsync_now_ms();
    if (!v4_started && now >= v4_start_at) {
      v4_started = true;
      if (use_icmp_sentinel) {
        zpsync_sentinel_info_s sinfo = {.timestamp_ms = now,
                                        .flow_entropy = flow_entropy,
                                        .session_salt = (uint32_t)(local_nonce & 0xFFFFFFFFU),
                                        .udp_port = v4_local_port,
                                        .dscp = 46U,
                                        .flags = 1U};
        (void)zpsync_sentinel_send_v4(key, peer_ipv4, (uint16_t)(local_nonce & 0xFFFFU),
                                      1U, &sinfo);
      }
      s4 = zpsync_udp_open(4, v4_local_port, true, true, &bound_v4);
    }

    if (s6 != ZPSYNC_INVALID_SOCK && now >= next_tx_v6) {
      send_hs(s6, 6, peer_ipv6, v6_peer_port, key,
              sent_syn_ack_v6 ? ZPSYNC_HS_TYPE_SYN_ACK : ZPSYNC_HS_TYPE_SYN,
              win_sid, local_nonce, eph_pub);
      next_tx_v6 = now + 40U;
    }
    if (s4 != ZPSYNC_INVALID_SOCK && now >= next_tx_v4) {
      send_hs(s4, 4, v4_addr16, v4_peer_port, key,
              sent_syn_ack_v4 ? ZPSYNC_HS_TYPE_SYN_ACK : ZPSYNC_HS_TYPE_SYN,
              win_sid, local_nonce, eph_pub);
      next_tx_v4 = now + 40U;
    }

    zpsync_sock_t socks[2];
    int sock_map[2];
    size_t scount = 0;
    if (s6 != ZPSYNC_INVALID_SOCK) {
      socks[scount] = s6;
      sock_map[scount++] = 0;
    }
    if (s4 != ZPSYNC_INVALID_SOCK) {
      socks[scount] = s4;
      sock_map[scount++] = 1;
    }
    if (scount == 0) break;

    uint8_t ready = 0;
    if (zpsync_poll_readable(socks, scount, 20U, &ready) > 0) {
      for (size_t i = 0; i < scount; ++i) {
        if ((ready & (1U << i)) == 0) continue;
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
          uint8_t fam = (sock_map[i] == 0) ? 6 : 4;
          if (msg.msg_type == ZPSYNC_HS_TYPE_SYN) {
            if (sock_map[i] == 0) sent_syn_ack_v6 = true;
            else sent_syn_ack_v4 = true;
            win_sid = sid;
            send_hs(socks[i], fam, r_addr, r_port, key, ZPSYNC_HS_TYPE_SYN_ACK, sid,
                    local_nonce, eph_pub);
          } else if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK ||
                     msg.msg_type == ZPSYNC_HS_TYPE_ACK) {
            if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK) {
              send_hs(socks[i], fam, r_addr, r_port, key, ZPSYNC_HS_TYPE_ACK, sid,
                      local_nonce, eph_pub);
            }
            winner = sock_map[i];
            memcpy(win_addr, r_addr, 16);
            win_port = r_port;
            win_sid = sid;
            win_rnonce = msg.peer_nonce;
            memcpy(win_rpub, msg.ephemeral_pub, ZPSYNC_X25519_BYTES);
            break;
          }
        }
      }
    }
  }

  if (winner < 0) {
    if (s6 != ZPSYNC_INVALID_SOCK) zpsync_sock_close(s6);
    if (s4 != ZPSYNC_INVALID_SOCK) zpsync_sock_close(s4);
    return -1;
  }

  zpsync_sock_t win_sock = (winner == 0) ? s6 : s4;
  zpsync_sock_t lose_sock = (winner == 0) ? s4 : s6;
  if (lose_sock != ZPSYNC_INVALID_SOCK) zpsync_sock_close(lose_sock);

  uint8_t fam = (winner == 0) ? 6 : 4;
  zpsync_sock_connect_peer(win_sock, fam, win_addr, win_port);

  memset(out, 0, sizeof(*out));
  out->sock = win_sock;
  memcpy(out->peer_addr, win_addr, 16);
  out->family = fam;
  out->local_port = (winner == 0) ? bound_v6 : bound_v4;
  out->peer_port = win_port;
  out->session_id = win_sid;
  out->remote_nonce = win_rnonce;
  out->local_is_initiator = (local_nonce < win_rnonce) ? 1U : 0U;
  uint64_t rtt = zpsync_now_ms() - t0;
  out->rtt_ms = (uint32_t)(rtt > 0 ? rtt : 1ULL);
  finalize_pfs(key, eph_priv, win_rpub, win_sid, out);
  return 0;
}

static uint16_t clamp_port(int32_t p) {
  while (p < 1024) p += 64511;
  while (p > 65535) p -= 64511;
  return (uint16_t)p;
}

int zpsync_punch_ipv4_birthday(const uint8_t *secret, size_t secret_len,
                               const uint8_t key[ZPSYNC_KEY_BYTES],
                               const uint8_t peer_ipv4[4],
                               uint16_t peer_base_port,
                               int32_t peer_port_stride, uint32_t socket_count,
                               uint64_t local_nonce, uint32_t timeout_ms,
                               zpsync_punch_out_s *out) {
  if (secret == NULL || secret_len == 0 || key == NULL || peer_ipv4 == NULL ||
      out == NULL) {
    return -1;
  }

  uint8_t eph_priv[ZPSYNC_X25519_BYTES];
  uint8_t eph_pub[ZPSYNC_X25519_BYTES];
  if (zpsync_x25519_keygen(eph_priv, eph_pub) != 0) return -1;

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

  int32_t stride = (peer_port_stride != 0) ? peer_port_stride : 1;

  for (uint32_t i = 0; i < socket_count; ++i) {
    uint16_t derived = zpsync_derive_birthday_port(secret, secret_len, i);
    uint16_t bound = 0;
    zpsync_sock_t s = zpsync_udp_open(4, derived, true, true, &bound);
    if (s == ZPSYNC_INVALID_SOCK) {
      s = zpsync_udp_open(4, 0, true, true, &bound);
    }
    if (s != ZPSYNC_INVALID_SOCK) {
      socks[opened] = s;
      local_ports[opened] = bound;
      /* Hybrid targeting:
         - Slots 0..31: measured-stride arithmetic progression around peer_base_port
         - Slots 32..63: +1/+2/+4 fallback strides around peer_base_port
         - Slots 64..N-1: Birthday-Paradox coprime-dispersed derived ports */
      if (peer_base_port > 0 && i < 32U) {
        target_ports[opened] = clamp_port((int32_t)peer_base_port + (int32_t)i * stride);
      } else if (peer_base_port > 0 && i < 64U) {
        int32_t off = (int32_t)(i - 32U);
        target_ports[opened] = clamp_port((int32_t)peer_base_port + off);
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
  uint8_t winner_rpub[ZPSYNC_X25519_BYTES] = {0};

  while (zpsync_now_ms() < deadline && winner_idx == (size_t)-1) {
    /* Coprime modulo dispersion: step by 17 across target ports */
    for (int b = 0; b < 32; ++b) {
      size_t idx = spray_cursor % opened;
      size_t p_idx = (spray_cursor * 17U + (size_t)b) % opened;
      send_hs(socks[idx], 4, peer_addr16, target_ports[p_idx], key,
              ZPSYNC_HS_TYPE_SYN, 0, local_nonce, eph_pub);
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
                    local_nonce, eph_pub);
          } else if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK) {
            send_hs(socks[i], 4, r_addr, r_port, key, ZPSYNC_HS_TYPE_ACK, sid,
                    local_nonce, eph_pub);
            send_hs(socks[i], 4, r_addr, r_port, key, ZPSYNC_HS_TYPE_ACK, sid,
                    local_nonce, eph_pub);
          }
          if (msg.msg_type == ZPSYNC_HS_TYPE_SYN_ACK ||
              msg.msg_type == ZPSYNC_HS_TYPE_ACK) {
            winner_idx = i;
            winner_peer_port = r_port;
            memcpy(winner_peer_addr, r_addr, 16);
            winner_session_id = sid;
            winner_remote_nonce = msg.peer_nonce;
            memcpy(winner_rpub, msg.ephemeral_pub, ZPSYNC_X25519_BYTES);
            break;
          }
        }
      }
    }
  }

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
  finalize_pfs(key, eph_priv, winner_rpub, winner_session_id, out);
  return 0;
}
