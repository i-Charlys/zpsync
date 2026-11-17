#include "zpsync.h"
#include "zpsync_net.h"

#include <string.h>

static int finalize_cruise_handoff(const uint8_t key[ZPSYNC_KEY_BYTES],
                                   zpsync_path_e path,
                                   zpsync_nat_type_e local_nat,
                                   uint64_t hop_epoch,
                                   const zpsync_punch_out_s *pout,
                                   zpsync_result_s *out_res) {
  out_res->sock = pout->sock;
  out_res->active_path = path;
  out_res->local_nat = local_nat;
  memcpy(out_res->peer_addr, pout->peer_addr, 16);
  out_res->family = pout->family;
  out_res->local_port = pout->local_port;
  out_res->peer_port = pout->peer_port;
  out_res->session_id = pout->session_id;
  out_res->hop_epoch = hop_epoch;
  out_res->rtt_ms = pout->rtt_ms;
  out_res->local_is_initiator = pout->local_is_initiator;

  if (rudp_session_init(&out_res->session) != RUDP_OK) {
    zpsync_sock_close(out_res->sock);
    out_res->sock = ZPSYNC_INVALID_SOCK;
    return -1;
  }
  rudp_session_set_seed(&out_res->session, (uint16_t)(pout->session_id & 0xFFFFU));
  /* Channel 0: reliable ordered control/keyframes; Channel 1: zero-HoL video */
  rudp_session_config_channel(&out_res->session, 0,
                              RUDP_CHANNEL_FLAG_RELIABLE | RUDP_CHANNEL_FLAG_ORDERED);
  rudp_session_config_channel(&out_res->session, 1, RUDP_CHANNEL_FLAG_RELIABLE);
  rudp_session_set_qos(&out_res->session, 0, 0, 46U);
  rudp_session_set_qos(&out_res->session, 1, 1, 34U);

  if (rudp_crypto_init(&out_res->crypto, key, pout->session_id,
                       pout->local_is_initiator) != RUDP_OK) {
    zpsync_sock_close(out_res->sock);
    out_res->sock = ZPSYNC_INVALID_SOCK;
    return -1;
  }
  return 0;
}

int zpsync_connect(const zpsync_config_s *cfg, zpsync_result_s *out_res) {
  if (cfg == NULL || cfg->secret == NULL || cfg->secret_len == 0 || out_res == NULL) {
    return -1;
  }
  if (zpsync_net_init() != 0) return -1;

  memset(out_res, 0, sizeof(*out_res));
  out_res->sock = ZPSYNC_INVALID_SOCK;

  uint8_t key[ZPSYNC_KEY_BYTES];
  if (zpsync_derive_session_key(cfg->secret, cfg->secret_len, key) != 0) {
    return -1;
  }

  uint64_t utc_s = zpsync_utc_now_s();
  uint64_t time_win =
      cfg->time_window_override > 0 ? cfg->time_window_override : (utc_s / 60ULL);
  uint16_t target_port =
      zpsync_derive_target_port(cfg->secret, cfg->secret_len, time_win);
  uint16_t local_port =
      cfg->local_port_override > 0 ? cfg->local_port_override : target_port;

  uint64_t local_nonce = 0;
  if (zpsync_random_bytes((uint8_t *)&local_nonce, sizeof(local_nonce)) != 0 ||
      local_nonce == 0) {
    local_nonce = zpsync_now_ms() ^ 0xA55AA55A5A5AA55AULL;
  }

  uint32_t stun_ms = cfg->stun_timeout_ms > 0 ? cfg->stun_timeout_ms : 1500U;
  uint32_t dht_ms = cfg->dht_timeout_ms > 0 ? cfg->dht_timeout_ms : 4000U;
  uint32_t punch_ms = cfg->punch_timeout_ms > 0 ? cfg->punch_timeout_ms : 2500U;

  /* ── Mode Manuel / Hors-Ligne ────────────────────────────────────────── */
  if (cfg->manual_peer_ip != NULL) {
    uint8_t fam = 0;
    uint8_t peer_addr[16];
    if (zpsync_parse_ip(cfg->manual_peer_ip, &fam, peer_addr) != 0) {
      return -1;
    }
    uint16_t peer_port =
        cfg->manual_peer_port > 0 ? cfg->manual_peer_port : target_port;

    zpsync_punch_out_s pout;
    if (fam == 6 && !cfg->disable_ipv6) {
      if (zpsync_punch_ipv6_direct(key, peer_addr, local_port, peer_port,
                                   local_nonce, punch_ms, &pout) == 0) {
        return finalize_cruise_handoff(key, ZPSYNC_PATH_IPV6_DIRECT,
                                       ZPSYNC_NAT_OPEN_INTERNET, time_win, &pout,
                                       out_res);
      }
      return -1;
    }

    if (fam == 4) {
      if (!cfg->force_birthday) {
        uint32_t entropy =
            rudp_calc_entropy((uint16_t)(local_nonce & 0xFFFFU), 0, 0);
        if (zpsync_punch_ipv4_sentinel(key, peer_addr, local_port, peer_port,
                                       local_nonce, entropy, punch_ms,
                                       !cfg->disable_sentinel, &pout) == 0) {
          return finalize_cruise_handoff(key, ZPSYNC_PATH_MANUAL,
                                         ZPSYNC_NAT_CONE, time_win, &pout, out_res);
        }
      }
      if (zpsync_punch_ipv4_birthday(cfg->secret, cfg->secret_len, key, peer_addr,
                                     peer_port, cfg->birthday_sockets, local_nonce,
                                     punch_ms, &pout) == 0) {
        return finalize_cruise_handoff(key, ZPSYNC_PATH_IPV4_BIRTHDAY,
                                       ZPSYNC_NAT_SYMMETRIC, time_win, &pout,
                                       out_res);
      }
    }
    return -1;
  }

  /* ── Brique 1: Découverte STUN/IPv6 + Mainline DHT ──────────────────── */
  zpsync_net_probe_s probe;
  memset(&probe, 0, sizeof(probe));
  (void)zpsync_probe_network(local_port, stun_ms, &probe);

  zpsync_dht_peer_s dht_peers[16];
  int found = 0;
  if (!cfg->disable_dht) {
    uint16_t announce_port =
        probe.public_v4.valid ? probe.public_v4.port : local_port;
    found = zpsync_dht_rendezvous(cfg->secret, cfg->secret_len, announce_port,
                                  utc_s, dht_ms, dht_peers, 16);
  }

  if (found <= 0) {
    return -1;
  }

  /* Try Brique 3 (Sentinel + IPv4 simultaneous open) then Brique 4 (Birthday) */
  for (int i = 0; i < found; ++i) {
    zpsync_punch_out_s pout;
    uint16_t peer_port = dht_peers[i].port > 0 ? dht_peers[i].port : target_port;

    if (probe.nat_type != ZPSYNC_NAT_SYMMETRIC && !cfg->force_birthday) {
      uint32_t entropy =
          rudp_calc_entropy((uint16_t)(local_nonce & 0xFFFFU), 0, (uint16_t)i);
      if (zpsync_punch_ipv4_sentinel(key, dht_peers[i].ip, local_port, peer_port,
                                     local_nonce, entropy, punch_ms,
                                     !cfg->disable_sentinel, &pout) == 0) {
        return finalize_cruise_handoff(key, ZPSYNC_PATH_IPV4_SENTINEL,
                                       probe.nat_type, time_win, &pout, out_res);
      }
    }

    if (zpsync_punch_ipv4_birthday(cfg->secret, cfg->secret_len, key,
                                   dht_peers[i].ip, peer_port,
                                   cfg->birthday_sockets, local_nonce, punch_ms,
                                   &pout) == 0) {
      return finalize_cruise_handoff(key, ZPSYNC_PATH_IPV4_BIRTHDAY,
                                     ZPSYNC_NAT_SYMMETRIC, time_win, &pout,
                                     out_res);
    }
  }

  return -1;
}

int zpsync_hop_port(zpsync_result_s *res, const uint8_t *secret, size_t secret_len,
                    uint64_t new_epoch) {
  if (res == NULL || secret == NULL || secret_len == 0 ||
      res->sock == ZPSYNC_INVALID_SOCK) {
    return -1;
  }
  uint16_t hop_port = zpsync_derive_target_port(secret, secret_len, new_epoch);
  if (hop_port == 0) return -1;

  uint16_t bound = 0;
  zpsync_sock_t new_sock = zpsync_udp_open(res->family, hop_port, true, true, &bound);
  if (new_sock == ZPSYNC_INVALID_SOCK) return -1;

  if (zpsync_sock_connect_peer(new_sock, res->family, res->peer_addr, hop_port) != 0) {
    zpsync_sock_close(new_sock);
    return -1;
  }

  zpsync_sock_close(res->sock);
  res->sock = new_sock;
  res->local_port = bound;
  res->peer_port = hop_port;
  res->hop_epoch = new_epoch;
  return 0;
}

void zpsync_close(zpsync_result_s *res) {
  if (res == NULL) return;
  if (res->sock != ZPSYNC_INVALID_SOCK) {
    zpsync_sock_close(res->sock);
    res->sock = ZPSYNC_INVALID_SOCK;
  }
  rudp_crypto_wipe(&res->crypto);
}

const char *zpsync_path_name(zpsync_path_e path) {
  switch (path) {
    case ZPSYNC_PATH_IPV6_DIRECT: return "IPv6-Direct";
    case ZPSYNC_PATH_IPV4_SENTINEL: return "IPv4-ICMP-Sentinel";
    case ZPSYNC_PATH_IPV4_BIRTHDAY: return "IPv4-Birthday-Paradox";
    case ZPSYNC_PATH_MANUAL: return "Manual-Direct";
    default: return "None";
  }
}
