#if !defined(_WIN32) && !defined(_POSIX_C_SOURCE)
#define _POSIX_C_SOURCE 200809L
#endif
#include "zpsync_net.h"

#include <string.h>
#include <time.h>

#if defined(_WIN32)
#include <windows.h>
#include <mswsock.h>
#ifndef SIO_UDP_CONNRESET
#define SIO_UDP_CONNRESET _WSAIOW(IOC_VENDOR, 12)
#endif
#else
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#endif

int zpsync_net_init(void) {
#if defined(_WIN32)
  static volatile LONG state = 0; /* 0 = uninit, 1 = initing, 2 = ready */
  while (InterlockedCompareExchange(&state, 1, 0) != 0) {
    if (state == 2) return 0;
    Sleep(0);
  }
  WSADATA wsa;
  if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
    InterlockedExchange(&state, 0);
    return -1;
  }
  InterlockedExchange(&state, 2);
#endif
  return 0;
}

uint64_t zpsync_now_ms(void) {
#if defined(_WIN32)
  static LARGE_INTEGER freq = {0};
  LARGE_INTEGER counter;
  if (freq.QuadPart == 0) {
    QueryPerformanceFrequency(&freq);
  }
  QueryPerformanceCounter(&counter);
  return (uint64_t)((counter.QuadPart * 1000ULL) / (uint64_t)freq.QuadPart);
#else
  struct timespec ts;
  clock_gettime(CLOCK_MONOTONIC, &ts);
  return (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;
#endif
}

uint64_t zpsync_utc_now_s(void) {
  time_t now = time(NULL);
  return now > 0 ? (uint64_t)now : 0ULL;
}

void zpsync_sleep_ms(uint32_t ms) {
#if defined(_WIN32)
  Sleep(ms);
#else
  struct timespec ts;
  ts.tv_sec = (time_t)(ms / 1000U);
  ts.tv_nsec = (long)((ms % 1000U) * 1000000UL);
  nanosleep(&ts, NULL);
#endif
}

static int set_nonblocking(zpsync_sock_t sock, bool non_blocking) {
#if defined(_WIN32)
  u_long mode = non_blocking ? 1UL : 0UL;
  return ioctlsocket(sock, FIONBIO, &mode) == 0 ? 0 : -1;
#else
  int flags = fcntl(sock, F_GETFL, 0);
  if (flags < 0) return -1;
  if (non_blocking) {
    flags |= O_NONBLOCK;
  } else {
    flags &= ~O_NONBLOCK;
  }
  return fcntl(sock, F_SETFL, flags) == 0 ? 0 : -1;
#endif
}

zpsync_sock_t zpsync_udp_open(uint8_t family, uint16_t bind_port, bool reuse_addr,
                              bool non_blocking, uint16_t *out_bound_port) {
  if (zpsync_net_init() != 0) return ZPSYNC_INVALID_SOCK;
  int af = (family == 6) ? AF_INET6 : AF_INET;
  zpsync_sock_t sock = socket(af, SOCK_DGRAM, IPPROTO_UDP);
  if (sock == ZPSYNC_INVALID_SOCK) return ZPSYNC_INVALID_SOCK;

  if (reuse_addr) {
    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, (const char *)&opt, sizeof(opt));
  }
#if defined(_WIN32)
  /* Prevent ICMP Port Unreachable from poisoning UDP sockets during NAT punch */
  BOOL new_behavior = FALSE;
  DWORD bytes_returned = 0;
  WSAIoctl(sock, SIO_UDP_CONNRESET, &new_behavior, sizeof(new_behavior), NULL, 0,
           &bytes_returned, NULL, NULL);
#endif
  if (family == 6) {
    int v6only = 1;
    setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, (const char *)&v6only, sizeof(v6only));
  }

  struct sockaddr_storage ss;
  socklen_t ss_len = 0;
  memset(&ss, 0, sizeof(ss));
  if (family == 6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(bind_port);
    sin6->sin6_addr = in6addr_any;
    ss_len = sizeof(*sin6);
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(bind_port);
    sin->sin_addr.s_addr = htonl(INADDR_ANY);
    ss_len = sizeof(*sin);
  }

  if (bind(sock, (struct sockaddr *)&ss, ss_len) != 0) {
    zpsync_sock_close(sock);
    return ZPSYNC_INVALID_SOCK;
  }

  if (out_bound_port != NULL) {
    struct sockaddr_storage bound;
    socklen_t bound_len = sizeof(bound);
    if (getsockname(sock, (struct sockaddr *)&bound, &bound_len) == 0) {
      if (bound.ss_family == AF_INET6) {
        *out_bound_port = ntohs(((struct sockaddr_in6 *)&bound)->sin6_port);
      } else {
        *out_bound_port = ntohs(((struct sockaddr_in *)&bound)->sin_port);
      }
    } else {
      *out_bound_port = bind_port;
    }
  }

  if (non_blocking && set_nonblocking(sock, true) != 0) {
    zpsync_sock_close(sock);
    return ZPSYNC_INVALID_SOCK;
  }

  return sock;
}

void zpsync_sock_close(zpsync_sock_t sock) {
  if (sock == ZPSYNC_INVALID_SOCK) return;
#if defined(_WIN32)
  closesocket(sock);
#else
  close(sock);
#endif
}

static void fill_sockaddr(uint8_t family, const uint8_t addr[16], uint16_t port,
                          struct sockaddr_storage *ss, socklen_t *out_len) {
  memset(ss, 0, sizeof(*ss));
  if (family == 6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)ss;
    sin6->sin6_family = AF_INET6;
    sin6->sin6_port = htons(port);
    memcpy(&sin6->sin6_addr, addr, 16);
    *out_len = sizeof(*sin6);
  } else {
    struct sockaddr_in *sin = (struct sockaddr_in *)ss;
    sin->sin_family = AF_INET;
    sin->sin_port = htons(port);
    memcpy(&sin->sin_addr, addr, 4);
    *out_len = sizeof(*sin);
  }
}

int zpsync_sock_connect_peer(zpsync_sock_t sock, uint8_t family,
                             const uint8_t addr[16], uint16_t port) {
  struct sockaddr_storage ss;
  socklen_t ss_len = 0;
  fill_sockaddr(family, addr, port, &ss, &ss_len);
  return connect(sock, (struct sockaddr *)&ss, ss_len) == 0 ? 0 : -1;
}

int zpsync_udp_sendto(zpsync_sock_t sock, uint8_t family, const uint8_t addr[16],
                      uint16_t port, const void *buf, size_t len) {
  struct sockaddr_storage ss;
  socklen_t ss_len = 0;
  fill_sockaddr(family, addr, port, &ss, &ss_len);
  int sent = sendto(sock, (const char *)buf, (int)len, 0, (struct sockaddr *)&ss,
                    ss_len);
  return sent;
}

int zpsync_udp_recvfrom(zpsync_sock_t sock, uint8_t *out_family,
                        uint8_t out_addr[16], uint16_t *out_port, void *buf,
                        size_t max_len) {
  struct sockaddr_storage ss;
  socklen_t ss_len = sizeof(ss);
  int n = recvfrom(sock, (char *)buf, (int)max_len, 0, (struct sockaddr *)&ss,
                   &ss_len);
  if (n < 0) return -1;

  if (out_addr != NULL) memset(out_addr, 0, 16);
  if (ss.ss_family == AF_INET6) {
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *)&ss;
    if (out_family != NULL) *out_family = 6;
    if (out_addr != NULL) memcpy(out_addr, &sin6->sin6_addr, 16);
    if (out_port != NULL) *out_port = ntohs(sin6->sin6_port);
  } else if (ss.ss_family == AF_INET) {
    struct sockaddr_in *sin = (struct sockaddr_in *)&ss;
    if (out_family != NULL) *out_family = 4;
    if (out_addr != NULL) memcpy(out_addr, &sin->sin_addr, 4);
    if (out_port != NULL) *out_port = ntohs(sin->sin_port);
  }
  return n;
}

int zpsync_parse_ip(const char *ip_str, uint8_t *out_family, uint8_t out_addr[16]) {
  if (ip_str == NULL || out_family == NULL || out_addr == NULL) return -1;
  memset(out_addr, 0, 16);
  struct in_addr v4;
  if (inet_pton(AF_INET, ip_str, &v4) == 1) {
    *out_family = 4;
    memcpy(out_addr, &v4, 4);
    return 0;
  }
  struct in6_addr v6;
  if (inet_pton(AF_INET6, ip_str, &v6) == 1) {
    *out_family = 6;
    memcpy(out_addr, &v6, 16);
    return 0;
  }
  return -1;
}

int zpsync_resolve_host(const char *host, uint8_t family_pref, uint8_t *out_family,
                        uint8_t out_addr[16]) {
  if (zpsync_net_init() != 0) return -1;
  if (host == NULL || out_family == NULL || out_addr == NULL) return -1;
  if (zpsync_parse_ip(host, out_family, out_addr) == 0) return 0;

  struct addrinfo hints;
  struct addrinfo *res = NULL;
  memset(&hints, 0, sizeof(hints));
  hints.ai_socktype = SOCK_DGRAM;
  hints.ai_family = (family_pref == 4) ? AF_INET :
                    (family_pref == 6) ? AF_INET6 : AF_UNSPEC;
  if (getaddrinfo(host, NULL, &hints, &res) != 0 || res == NULL) {
    return -1;
  }

  int rc = -1;
  for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {
    memset(out_addr, 0, 16);
    if (p->ai_family == AF_INET) {
      *out_family = 4;
      memcpy(out_addr, &((struct sockaddr_in *)p->ai_addr)->sin_addr, 4);
      rc = 0;
      break;
    }
    if (p->ai_family == AF_INET6) {
      *out_family = 6;
      memcpy(out_addr, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr, 16);
      rc = 0;
      break;
    }
  }
  freeaddrinfo(res);
  return rc;
}

int zpsync_poll_readable(const zpsync_sock_t *socks, size_t count,
                         uint32_t timeout_ms, uint8_t *out_ready_bitmap) {
  if (socks == NULL || count == 0 || out_ready_bitmap == NULL) return -1;
  size_t bmap_bytes = (count + 7U) / 8U;
  memset(out_ready_bitmap, 0, bmap_bytes);

#if defined(_WIN32)
  /* WSAPoll handles arbitrary socket counts cleanly (unlike FD_SETSIZE=64) */
  WSAPOLLFD fds[512];
  if (count > 512U) return -1;
  for (size_t i = 0; i < count; ++i) {
    fds[i].fd = socks[i];
    fds[i].events = POLLRDNORM;
    fds[i].revents = 0;
  }
  int n = WSAPoll(fds, (ULONG)count, (INT)timeout_ms);
  if (n <= 0) return n;
  int ready = 0;
  for (size_t i = 0; i < count; ++i) {
    if ((fds[i].revents & (POLLRDNORM | POLLIN)) != 0) {
      out_ready_bitmap[i >> 3] |= (uint8_t)(1U << (i & 7U));
      ++ready;
    }
  }
  return ready;
#else
  struct pollfd fds[512];
  if (count > 512U) return -1;
  for (size_t i = 0; i < count; ++i) {
    fds[i].fd = socks[i];
    fds[i].events = POLLIN;
    fds[i].revents = 0;
  }
  int n = poll(fds, (nfds_t)count, (int)timeout_ms);
  if (n <= 0) return n;
  int ready = 0;
  for (size_t i = 0; i < count; ++i) {
    if ((fds[i].revents & POLLIN) != 0) {
      out_ready_bitmap[i >> 3] |= (uint8_t)(1U << (i & 7U));
      ++ready;
    }
  }
  return ready;
#endif
}
