#include "zpsync.h"

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
} peer_task_s;

static THREAD_RET run_connect_thread(void *arg) {
  peer_task_s *task = (peer_task_s *)arg;
  task->rc = zpsync_connect(&task->cfg, &task->res);
  return 0;
}

static void test_manual_rudp_handoff_and_hop(void) {
  static const uint8_t secret[] = "zpsync-loopback-test-key";
  peer_task_s a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = sizeof(secret) - 1U,
                            .manual_peer_ip = "127.0.0.1",
                            .manual_peer_port = 41102U,
                            .local_port_override = 41101U,
                            .disable_sentinel = true,
                            .punch_timeout_ms = 2000U,
                            .time_window_override = 777ULL};
  b.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = sizeof(secret) - 1U,
                            .manual_peer_ip = "127.0.0.1",
                            .manual_peer_port = 41101U,
                            .local_port_override = 41102U,
                            .disable_sentinel = true,
                            .punch_timeout_ms = 2000U,
                            .time_window_override = 777ULL};

  thread_t ta, tb;
  THREAD_CREATE(ta, run_connect_thread, &a);
  THREAD_CREATE(tb, run_connect_thread, &b);
  THREAD_JOIN(ta);
  THREAD_JOIN(tb);

  assert(a.rc == 0 && b.rc == 0);
  assert(a.res.session_id == b.res.session_id);
  assert(a.res.local_is_initiator != b.res.local_is_initiator);

  /* Cruise test: seal an RUDP packet on A and open it on B over the handed-off socket */
  const uint8_t msg[] = "video-keyframe-chunk-0";
  uint8_t wire[128];
  int sealed_len =
      rudp_crypto_seal(&a.res.crypto, NULL, 0, msg, sizeof(msg), wire, sizeof(wire));
  assert(sealed_len > (int)sizeof(msg));

  int sent = send(a.res.sock, (const char *)wire, sealed_len, 0);
  assert(sent == sealed_len);

  uint8_t rx[128];
  int recvd = -1;
  for (int tries = 0; tries < 50; ++tries) {
    int n = recv(b.res.sock, (char *)rx, sizeof(rx), 0);
    if (n == sealed_len) {
      recvd = n;
      break;
    }
    if (n < 0) {
#if defined(_WIN32)
      Sleep(5);
#endif
    }
  }
  assert(recvd == sealed_len);

  uint8_t plain[128];
  int pt_len = rudp_crypto_open(&b.res.crypto, NULL, 0, rx, (size_t)recvd, plain,
                                sizeof(plain));
  assert(pt_len == (int)sizeof(msg));
  assert(memcmp(plain, msg, sizeof(msg)) == 0);

  /* Dynamic port hopping test during cruise */
  uint16_t old_port = a.res.local_port;
  assert(zpsync_hop_port(&a.res, secret, sizeof(secret) - 1U, 778ULL) == 0);
  assert(a.res.hop_epoch == 778ULL);
  assert(a.res.local_port != old_port || a.res.peer_port == a.res.local_port);

  zpsync_close(&a.res);
  zpsync_close(&b.res);
}

static void test_birthday_paradox_spray(void) {
  static const uint8_t secret[] = "zpsync-birthday-paradox-test";
  peer_task_s a, b;
  memset(&a, 0, sizeof(a));
  memset(&b, 0, sizeof(b));

  a.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = sizeof(secret) - 1U,
                            .manual_peer_ip = "127.0.0.1",
                            .force_birthday = true,
                            .birthday_sockets = 256U,
                            .punch_timeout_ms = 2500U};
  b.cfg = (zpsync_config_s){.secret = secret,
                            .secret_len = sizeof(secret) - 1U,
                            .manual_peer_ip = "127.0.0.1",
                            .force_birthday = true,
                            .birthday_sockets = 256U,
                            .punch_timeout_ms = 2500U};

  thread_t ta, tb;
  THREAD_CREATE(ta, run_connect_thread, &a);
  THREAD_CREATE(tb, run_connect_thread, &b);
  THREAD_JOIN(ta);
  THREAD_JOIN(tb);

  assert(a.rc == 0 && b.rc == 0);
  assert(a.res.active_path == ZPSYNC_PATH_IPV4_BIRTHDAY);
  assert(b.res.active_path == ZPSYNC_PATH_IPV4_BIRTHDAY);
  assert(a.res.session_id == b.res.session_id);

  zpsync_close(&a.res);
  zpsync_close(&b.res);
}

int main(void) {
  test_manual_rudp_handoff_and_hop();
  test_birthday_paradox_spray();
  printf("test_punch_loopback: PASS\n");
  return 0;
}
