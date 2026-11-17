#ifndef ZPSYNC_NET_H
#define ZPSYNC_NET_H

#include "zpsync_punch.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#if defined(_WIN32)
#include <ws2tcpip.h>
#else
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/types.h>
#endif

int zpsync_net_init(void);
uint64_t zpsync_now_ms(void);
uint64_t zpsync_utc_now_s(void);
void zpsync_sleep_ms(uint32_t ms);

zpsync_sock_t zpsync_udp_open(uint8_t family, uint16_t bind_port, bool reuse_addr,
                              bool non_blocking, uint16_t *out_bound_port);
void zpsync_sock_close(zpsync_sock_t sock);
int zpsync_sock_connect_peer(zpsync_sock_t sock, uint8_t family,
                             const uint8_t addr[16], uint16_t port);

int zpsync_udp_sendto(zpsync_sock_t sock, uint8_t family, const uint8_t addr[16],
                      uint16_t port, const void *buf, size_t len);
int zpsync_udp_recvfrom(zpsync_sock_t sock, uint8_t *out_family,
                        uint8_t out_addr[16], uint16_t *out_port, void *buf,
                        size_t max_len);

int zpsync_resolve_host(const char *host, uint8_t family_pref, uint8_t *out_family,
                        uint8_t out_addr[16]);
int zpsync_parse_ip(const char *ip_str, uint8_t *out_family, uint8_t out_addr[16]);
int zpsync_poll_readable(const zpsync_sock_t *socks, size_t count,
                         uint32_t timeout_ms, uint8_t *out_ready_bitmap);

#endif /* ZPSYNC_NET_H */
