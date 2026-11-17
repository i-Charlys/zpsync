#ifndef ZPSYNC_CRYPTO_H
#define ZPSYNC_CRYPTO_H

/**
 * @file zpsync_crypto.h
 * @brief Deterministic key, Node_ID, and port derivation + AEAD mailbox sealing.
 *
 * Built on top of zcrudp's zero-malloc ChaCha20-Poly1305 (RFC 8439) implementation,
 * adding SHA-1 (for 160-bit Mainline DHT Node_IDs) and SHA-256 (for key and
 * deterministic port derivation).
 */

#include "rudp_crypto.h"
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZPSYNC_SHA1_BYTES 20U
#define ZPSYNC_SHA256_BYTES 32U
#define ZPSYNC_KEY_BYTES RUDP_CRYPTO_KEY_BYTES
#define ZPSYNC_NONCE_BYTES RUDP_CRYPTO_NONCE_BYTES
#define ZPSYNC_TAG_BYTES RUDP_CRYPTO_TAG_BYTES

#define ZPSYNC_PORT_BASE 10000U
#define ZPSYNC_PORT_SPAN_V6 55000U
#define ZPSYNC_PORT_SPAN_BDAY 55535U

/**
 * @brief Ephemeral rendezvous payload exchanged via DHT or manual signaling.
 */
typedef struct {
  uint8_t ipv6[16];     /**< Public/global IPv6 address (network byte order) */
  uint8_t ipv4[4];      /**< Public IPv4 address (network byte order) */
  uint16_t ipv4_port;   /**< Public STUN-mapped IPv4 UDP port (host byte order) */
  uint16_t local_port;  /**< Local bound UDP port hint (host byte order) */
  uint8_t has_ipv6;     /**< Non-zero if ipv6 is valid */
  uint8_t has_ipv4;     /**< Non-zero if ipv4 is valid */
  uint8_t nat_type;     /**< zpsync_nat_type_e value */
  uint8_t role_hint;    /**< 0 = auto, 1 = initiator, 2 = responder */
  uint64_t timestamp_s; /**< UTC Unix timestamp when published */
  uint64_t peer_nonce;  /**< Random 64-bit tie-breaker for initiator/responder */
} zpsync_mailbox_s;

/**
 * @brief Serialized wire size of a plaintext mailbox: 40 bytes.
 *        Sealed size: 12B nonce + 40B ciphertext + 16B tag = 68 bytes.
 */
#define ZPSYNC_MAILBOX_PLAIN_BYTES 40U
#define ZPSYNC_MAILBOX_SEALED_BYTES                                                    \
  (ZPSYNC_NONCE_BYTES + ZPSYNC_MAILBOX_PLAIN_BYTES + ZPSYNC_TAG_BYTES)

/**
 * @brief Computes SHA-1 (FIPS 180-4) over @p data. Used for 160-bit DHT Node_IDs.
 */
void zpsync_sha1(const uint8_t *data, size_t len, uint8_t out_digest[ZPSYNC_SHA1_BYTES]);

/**
 * @brief Computes SHA-256 (FIPS 180-4) over @p data.
 */
void zpsync_sha256(const uint8_t *data, size_t len,
                   uint8_t out_digest[ZPSYNC_SHA256_BYTES]);

/**
 * @brief Derives a 256-bit symmetric key from an arbitrary-length shared secret S.
 *        Uses domain separation "zpsync-v1-master-key".
 */
int zpsync_derive_session_key(const uint8_t *secret, size_t secret_len,
                              uint8_t out_key[ZPSYNC_KEY_BYTES]);

/**
 * @brief Derives the 160-bit Mainline DHT rendezvous Node_ID:
 *        Node_ID = SHA1(S || utc_hour_be64)
 *
 * @param secret Shared secret S.
 * @param secret_len Length of S in bytes.
 * @param utc_hour_bucket UTC Unix timestamp divided by 3600 (hourly window).
 * @param out_node_id 20-byte DHT info_hash / target Node_ID.
 */
int zpsync_derive_dht_node_id(const uint8_t *secret, size_t secret_len,
                              uint64_t utc_hour_bucket,
                              uint8_t out_node_id[ZPSYNC_SHA1_BYTES]);

/**
 * @brief Derives the deterministic IPv6 / non-symmetric target port:
 *        Port_Cible = 10000 + (Hash(S || time_window) mod 55000)
 *
 * @param secret Shared secret S.
 * @param secret_len Length of S in bytes.
 * @param time_window Coarse time window (e.g. utc_seconds / 60 or hop epoch).
 * @return Port in [10000, 64999], or 0 on invalid arguments.
 */
uint16_t zpsync_derive_target_port(const uint8_t *secret, size_t secret_len,
                                   uint64_t time_window);

/**
 * @brief Derives the i-th port for Birthday-Paradox NAT traversal:
 *        Port_i = 10000 + (Hash(S || i) mod 55535)
 *
 * @param secret Shared secret S.
 * @param secret_len Length of S in bytes.
 * @param index Socket index (0..499).
 * @return Port in [10000, 65534], or 0 on invalid arguments.
 */
uint16_t zpsync_derive_birthday_port(const uint8_t *secret, size_t secret_len,
                                     uint32_t index);

/**
 * @brief Encrypts and authenticates a mailbox payload with ChaCha20-Poly1305.
 *
 * @param key 32-byte key derived from S via zpsync_derive_session_key().
 * @param nonce 12-byte unique nonce.
 * @param mb Plaintext mailbox fields.
 * @param out_sealed Output buffer of at least ZPSYNC_MAILBOX_SEALED_BYTES bytes.
 * @return ZPSYNC_MAILBOX_SEALED_BYTES on success, or negative error code.
 */
int zpsync_mailbox_seal(const uint8_t key[ZPSYNC_KEY_BYTES],
                        const uint8_t nonce[ZPSYNC_NONCE_BYTES],
                        const zpsync_mailbox_s *mb, uint8_t *out_sealed,
                        size_t max_out_len);

/**
 * @brief Verifies and decrypts a sealed mailbox payload.
 *
 * @return 0 on success, negative error code on tampering or invalid format.
 */
int zpsync_mailbox_open(const uint8_t key[ZPSYNC_KEY_BYTES], const uint8_t *sealed,
                        size_t sealed_len, zpsync_mailbox_s *out_mb);

/**
 * @brief Fills @p buf with @p len cryptographically strong random bytes.
 */
int zpsync_random_bytes(uint8_t *buf, size_t len);

#ifdef __cplusplus
}
#endif

#endif /* ZPSYNC_CRYPTO_H */
