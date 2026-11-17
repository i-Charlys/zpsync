#include "zpsync.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void print_usage(const char *prog) {
  printf("Usage: %s --secret <S> [options]\n"
         "  --peer <ip>          Manual/offline peer IPv4 or IPv6 (skips DHT)\n"
         "  --port <port>        Manual peer UDP port\n"
         "  --local-port <port>  Local UDP port override\n"
         "  --birthday           Force Brique 4 (256-500 socket Birthday Paradox)\n"
         "  --no-sentinel        Disable Layer-3 ICMP Sentinel\n"
         "  --probe              Only probe local IPv6 & STUN NAT type\n",
         prog);
}

static const char *nat_name(zpsync_nat_type_e nat) {
  switch (nat) {
    case ZPSYNC_NAT_OPEN_INTERNET: return "Open Internet (No NAT)";
    case ZPSYNC_NAT_CONE: return "Cone NAT (Endpoint-Independent)";
    case ZPSYNC_NAT_SYMMETRIC: return "Symmetric NAT / CGNAT";
    default: return "Unknown";
  }
}

int main(int argc, char **argv) {
  const char *secret = NULL;
  const char *peer_ip = NULL;
  uint16_t peer_port = 0;
  uint16_t local_port = 0;
  bool force_birthday = false;
  bool disable_sentinel = false;
  bool probe_only = false;

  for (int i = 1; i < argc; ++i) {
    if (strcmp(argv[i], "--secret") == 0 && i + 1 < argc) {
      secret = argv[++i];
    } else if (strcmp(argv[i], "--peer") == 0 && i + 1 < argc) {
      peer_ip = argv[++i];
    } else if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
      peer_port = (uint16_t)atoi(argv[++i]);
    } else if (strcmp(argv[i], "--local-port") == 0 && i + 1 < argc) {
      local_port = (uint16_t)atoi(argv[++i]);
    } else if (strcmp(argv[i], "--birthday") == 0) {
      force_birthday = true;
    } else if (strcmp(argv[i], "--no-sentinel") == 0) {
      disable_sentinel = true;
    } else if (strcmp(argv[i], "--probe") == 0) {
      probe_only = true;
    } else {
      print_usage(argv[0]);
      return 1;
    }
  }

  if (probe_only) {
    zpsync_net_probe_s probe;
    if (zpsync_probe_network(local_port, 1500U, &probe) != 0) {
      fprintf(stderr, "[zpsync] Network probe failed.\n");
      return 1;
    }
    printf("[zpsync] IPv6 available : %s\n", probe.has_ipv6 ? "YES" : "NO");
    if (probe.public_v4.valid) {
      printf("[zpsync] Public IPv4    : %u.%u.%u.%u:%u (RTT %u ms)\n",
             probe.public_v4.addr[0], probe.public_v4.addr[1],
             probe.public_v4.addr[2], probe.public_v4.addr[3],
             probe.public_v4.port, probe.rtt_ms);
    }
    printf("[zpsync] NAT type       : %s\n", nat_name(probe.nat_type));
    return 0;
  }

  if (secret == NULL) {
    print_usage(argv[0]);
    return 1;
  }

  zpsync_config_s cfg = {.secret = (const uint8_t *)secret,
                         .secret_len = strlen(secret),
                         .manual_peer_ip = peer_ip,
                         .manual_peer_port = peer_port,
                         .local_port_override = local_port,
                         .disable_sentinel = disable_sentinel,
                         .force_birthday = force_birthday,
                         .birthday_sockets = ZPSYNC_BIRTHDAY_DEFAULT_SOCKETS};

  printf("[zpsync] Connecting via 4-layer zero-proxy stack...\n");
  zpsync_result_s res;
  if (zpsync_connect(&cfg, &res) != 0) {
    fprintf(stderr, "[zpsync] Connection failed.\n");
    return 1;
  }

  printf("[zpsync] Connected! Path=%s | Session=0x%llx | Role=%s | Ports %u -> %u | RTT=%u ms\n",
         zpsync_path_name(res.active_path), (unsigned long long)res.session_id,
         res.local_is_initiator ? "Initiator" : "Responder", res.local_port,
         res.peer_port, res.rtt_ms);

  /* Send one encrypted cruise test datagram */
  const uint8_t hello[] = "zpsync-rudp-cruise-ready";
  uint8_t wire[128];
  int slen =
      rudp_crypto_seal(&res.crypto, NULL, 0, hello, sizeof(hello), wire, sizeof(wire));
  if (slen > 0) {
    send(res.sock, (const char *)wire, slen, 0);
  }

  zpsync_close(&res);
  return 0;
}
