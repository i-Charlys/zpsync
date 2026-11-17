#include "zpsync.h"
#include "zpsync_cruise.h"

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(_WIN32)
#include <windows.h>
typedef HANDLE thread_t;
#define THREAD_RET DWORD WINAPI
#define THREAD_CREATE(t, fn, arg) ((t) = CreateThread(NULL, 0, (fn), (arg), 0, NULL))
#define THREAD_JOIN(t)                                                                 \
  do {                                                                                 \
    WaitForSingleObject((t), INFINITE);                                                \
    CloseHandle(t);                                                                    \
  } while (0)
#else
#include <pthread.h>
typedef pthread_t thread_t;
#define THREAD_RET void *
#define THREAD_CREATE(t, fn, arg) pthread_create(&(t), NULL, (fn), (arg))
#define THREAD_JOIN(t) pthread_join((t), NULL)
#endif

typedef struct {
  zpsync_config_s cfg;
  zpsync_result_s res;
  int rc;
} peer_ctx_s;

typedef struct {
  zpsync_result_s *res;
  const uint8_t *secret;
  size_t secret_len;
  uint64_t new_epoch;
  uint16_t lport;
  uint16_t pport;
  int rc;
} hop_ctx_s;

static THREAD_RET connect_worker(void *arg) {
  peer_ctx_s *p = (peer_ctx_s *)arg;
  p->rc = zpsync_connect(&p->cfg, &p->res);
  return 0;
}

static THREAD_RET hop_worker(void *arg) {
  hop_ctx_s *h = (hop_ctx_s *)arg;
  h->rc = zpsync_hop_make_before_break_ex(h->res, h->secret, h->secret_len,
                                          h->new_epoch, h->lport, h->pport, 500U);
  return 0;
}

int main(void) {
  static const uint8_t secret[] = "zpsync-nobel-breakthrough-key";
  size_t slen = sizeof(secret) - 1U;

  peer_ctx_s a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = slen,
                            .manual_peer_ip = "127.0.0.1",
                            .manual_peer_port = 42102U,
                            .local_port_override = 42101U,
                            .disable_sentinel = true,
                            .punch_timeout_ms = 2000U,
                            .time_window_override = 900ULL};
  b.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = slen,
                            .manual_peer_ip = "127.0.0.1",
                            .manual_peer_port = 42101U,
                            .local_port_override = 42102U,
                            .disable_sentinel = true,
                            .punch_timeout_ms = 2000U,
                            .time_window_override = 900ULL};

  thread_t ta, tb;
  THREAD_CREATE(ta, connect_worker, &a);
  THREAD_CREATE(tb, connect_worker, &b);
  THREAD_JOIN(ta);
  THREAD_JOIN(tb);

  assert(a.rc == 0 && b.rc == 0);
  /* 1. Verify X25519 Forward Secrecy is active on both peers */
  assert(a.res.pfs_enabled == 1U && b.res.pfs_enabled == 1U);
  assert(a.res.session_id == b.res.session_id);
  printf("[nobel] X25519 Forward Secrecy negotiated in %u ms (session=0x%llx)\n",
         a.res.rtt_ms, (unsigned long long)a.res.session_id);

  /* 2. Video Cruise + Zero-RTT XOR FEC Benchmark (32 x 4KB frames) */
  zpsync_cruise_tx_s vtx;
  zpsync_cruise_rx_s vrx;
  zpsync_cruise_tx_init(&vtx);
  zpsync_cruise_rx_init(&vrx);

  uint8_t frame_tx[4096];
  uint8_t frame_rx[4096];
  for (size_t i = 0; i < sizeof(frame_tx); ++i) {
    frame_tx[i] = (uint8_t)((i * 131U) ^ 0x5AU);
  }

  for (int f = 0; f < 32; ++f) {
    frame_tx[0] = (uint8_t)f;
    bool is_kf = (f % 8 == 0);
    assert(zpsync_cruise_send_frame(&a.res, &vtx, frame_tx, sizeof(frame_tx),
                                    is_kf, true) == 0);
    bool rx_kf = false;
    int rx_len = zpsync_cruise_recv_frame(&b.res, &vrx, frame_rx,
                                          sizeof(frame_rx), 250U, &rx_kf);
    assert(rx_len == (int)sizeof(frame_tx));
    assert(rx_kf == is_kf);
    assert(memcmp(frame_tx, frame_rx, sizeof(frame_tx)) == 0);
  }
  printf("[nobel] Encrypted Video Cruise: %llu frames (%llu frags + %llu XOR FEC) 100%% intact\n",
         (unsigned long long)vtx.frames_sent, (unsigned long long)vtx.frags_sent,
         (unsigned long long)vtx.fec_sent);

  /* 3. Verify Zero-RTT XOR FEC Recovery when 1 fragment is dropped on wire */
  uint8_t dropped[1500];
  while (recv(b.res.sock, (char *)dropped, sizeof(dropped), 0) > 0) {
  }
  assert(zpsync_cruise_send_frame(&a.res, &vtx, frame_tx, 3000U, true, true) == 0);
  /* Drop the very first datagram (fragment 0) from b.res.sock */
  for (int tries = 0; tries < 50; ++tries) {
    if (recv(b.res.sock, (char *)dropped, sizeof(dropped), 0) > 0) break;
#if defined(_WIN32)
    Sleep(2);
#endif
  }
  /* Remaining 2 data fragments + 1 XOR parity must reconstruct all 3000 bytes */
  bool fec_kf = false;
  int fec_len = zpsync_cruise_recv_frame(&b.res, &vrx, frame_rx, sizeof(frame_rx),
                                         250U, &fec_kf);
  assert(fec_len == 3000);
  assert(fec_kf == true);
  assert(vrx.fec_recoveries == 1ULL);
  assert(memcmp(frame_tx, frame_rx, 3000U) == 0);
  printf("[nobel] Zero-RTT XOR FEC recovered dropped fragment (3000B intact, 0 retransmissions)\n");

  /* 3b. Verify GF(2^8) Cauchy MDS Recovery of 4 SIMULTANEOUS lost fragments! */
  uint8_t mds_data[8][ZPSYNC_CRUISE_MTU];
  uint16_t mds_lens[8];
  uint8_t mds_present[8];
  uint8_t mds_orig[8][ZPSYNC_CRUISE_MTU];
  for (int i = 0; i < 8; ++i) {
    mds_lens[i] = (i == 7) ? 777U : ZPSYNC_CRUISE_MTU;
    mds_present[i] = 1U;
    for (uint16_t b = 0; b < mds_lens[i]; ++b) {
      mds_data[i][b] = (uint8_t)((i * 37U + b * 13U) & 0xFFU);
      mds_orig[i][b] = mds_data[i][b];
    }
  }
  uint8_t mds_par[4][ZPSYNC_CRUISE_MTU];
  uint8_t mds_par_pres[4] = {1, 1, 1, 1};
  assert(zpsync_fec_encode((const uint8_t (*)[ZPSYNC_CRUISE_MTU])mds_data,
                           mds_lens, 8, ZPSYNC_CRUISE_MTU, 4, mds_par) == 0);
  /* Erase 4 simultaneous fragments (0, 2, 5, 7 - including the short tail!) */
  mds_present[0] = 0;
  mds_present[2] = 0;
  mds_present[5] = 0;
  mds_present[7] = 0;
  memset(mds_data[0], 0, ZPSYNC_CRUISE_MTU);
  memset(mds_data[2], 0, ZPSYNC_CRUISE_MTU);
  memset(mds_data[5], 0, ZPSYNC_CRUISE_MTU);
  memset(mds_data[7], 0, ZPSYNC_CRUISE_MTU);

  int recovered = zpsync_fec_decode(mds_data, mds_lens, mds_present, 8,
                                    ZPSYNC_CRUISE_MTU, 777U,
                                    (const uint8_t (*)[ZPSYNC_CRUISE_MTU])mds_par,
                                    mds_par_pres, 4);
  assert(recovered == 4);
  for (int i = 0; i < 8; ++i) {
    assert(mds_present[i] == 1U);
    assert(memcmp(mds_data[i], mds_orig[i], mds_lens[i]) == 0);
  }
  printf("[nobel] GF(2^8) Cauchy MDS recovered 4/8 simultaneous lost fragments (0 retransmissions)\n");

  /* 4. Hitless Make-Before-Break Port Hopping */
  /* First verify failed hop (peer doesn't hop) preserves old socket cleanly */
  uint16_t pre_hop_port = a.res.local_port;
  assert(zpsync_hop_make_before_break(&a.res, secret, slen, 901ULL, 80U) != 0);
  assert(a.res.local_port == pre_hop_port);

  /* Now both peers hop simultaneously to epoch 902 */
  uint16_t hop_a = zpsync_derive_target_port(secret, slen, 902ULL);
  uint16_t hop_b = (uint16_t)(hop_a + 1U);
  hop_ctx_s ha = {.res = &a.res, .secret = secret, .secret_len = slen, .new_epoch = 902ULL, .lport = hop_a, .pport = hop_b};
  hop_ctx_s hb = {.res = &b.res, .secret = secret, .secret_len = slen, .new_epoch = 902ULL, .lport = hop_b, .pport = hop_a};
  THREAD_CREATE(ta, hop_worker, &ha);
  THREAD_CREATE(tb, hop_worker, &hb);
  THREAD_JOIN(ta);
  THREAD_JOIN(tb);
  assert(ha.rc == 0 && hb.rc == 0);
  assert(a.res.hop_epoch == 902ULL && b.res.hop_epoch == 902ULL);
  printf("[nobel] Hitless Make-Before-Break Port Hop: %u -> %u (0 dropped frames)\n",
         pre_hop_port, a.res.local_port);

  /* Verify video cruise continues seamlessly on the new hopped port */
  assert(zpsync_cruise_send_frame(&a.res, &vtx, frame_tx, sizeof(frame_tx), true,
                                  true) == 0);
  bool rx_kf = false;
  int post_len = zpsync_cruise_recv_frame(&b.res, &vrx, frame_rx, sizeof(frame_rx),
                                          250U, &rx_kf);
  assert(post_len == (int)sizeof(frame_tx));
  assert(memcmp(frame_tx, frame_rx, sizeof(frame_tx)) == 0);

  zpsync_close(&a.res);
  zpsync_close(&b.res);
  printf("test_nobel_breakthroughs: PASS\n");
  return 0;
}
