/*
 * vless_internal.h - Internal definitions
 */

#ifndef VLESS_INTERNAL_H
#define VLESS_INTERNAL_H

#include "vless.h"

/** Internal symbol visibility — hides from consumers in both static and shared builds.
 *  Functions declared with VLESS_INTERNAL are cross-TU within the library but
 *  not part of the public ABI. */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_INTERNAL __attribute__((visibility("hidden")))
#else
#define VLESS_INTERNAL
#endif

#include <stdatomic.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/ssl.h>

/* Read big-endian uint16_t from a byte buffer without -Wconversion warnings.
 * C integer promotion rules cause (uint16_t)buf[i] << 8 | buf[i+1] to produce
 * int, and assigning back to uint16_t triggers -Wimplicit-int-conversion. */
static inline uint16_t rd_u16be(const uint8_t *p) {
    return (uint16_t)((unsigned)p[0] << 8 | p[1]);
}

/* Safe errno-to-string.  Falls back to numeric format on failure.
 * Handles both XSI and GNU strerror_r variants: XSI returns int (0 = success),
 * GNU returns char* (may differ from buf).  _GNU_SOURCE, if defined by the
 * build system, overrides _POSIX_C_SOURCE and selects the GNU variant. */
static inline void safe_strerror(int errnum, char *buf, size_t buflen) {
    if (buflen == 0) return;
#if defined(__GLIBC__) && defined(_GNU_SOURCE)
    char *s = strerror_r(errnum, buf, buflen);
    if (s != buf) snprintf(buf, buflen, "%s", s);
#else
    if (strerror_r(errnum, buf, buflen) != 0)
        snprintf(buf, buflen, "errno %d", errnum);
#endif
}

/* ─── VLESS protocol constants ──────────────────────────────── */

#define VLESS_PROTO_VERSION 0
#define VLESS_CMD_TCP       0x01
#define VLESS_ADDR_IPV4     1
#define VLESS_ADDR_DOMAIN   2
#define VLESS_ADDR_IPV6     3
#define VLESS_MAX_HEADER    512

/* ─── TLS 1.3 constants ────────────────────────────────────── */

#define TLS_RECORD_CCS              20
#define TLS_RECORD_ALERT            21
#define TLS_RECORD_HANDSHAKE        22
#define TLS_RECORD_APPLICATION_DATA 23

#define TLS_VERSION_10  0x0301
#define TLS_VERSION_12  0x0303
#define TLS_VERSION_13  0x0304

#define TLS_HS_CLIENT_HELLO         1
#define TLS_HS_SERVER_HELLO         2
#define TLS_HS_NEW_SESSION_TICKET   4
#define TLS_HS_ENCRYPTED_EXT        8
#define TLS_HS_CERTIFICATE          11
#define TLS_HS_CERT_VERIFY          15
#define TLS_HS_FINISHED             20
#define TLS_HS_MESSAGE_HASH         254  /* synthetic message_hash for HRR transcript */

#define TLS_AES_128_GCM_SHA256      0x1301
#define TLS_AES_256_GCM_SHA384      0x1302
#define TLS_CHACHA20_POLY1305_SHA256 0x1303
#define TLS_GCM_TAG_LEN             16
#define TLS_GCM_KEY_LEN_128         16
#define TLS_GCM_KEY_LEN_256         32
#define TLS_GCM_IV_LEN              12
#define TLS_HASH_LEN_256            32
#define TLS_HASH_LEN_384            48
#define TLS_MAX_RECORD_PAYLOAD      16384
#define VLESS_MAX_SKIP_RECORDS      100  /* max non-app-data records to skip in recv */

/* Note: the old TLS_GCM_KEY_LEN alias has been removed.
 * Use TLS_GCM_KEY_LEN_128 or TLS_GCM_KEY_LEN_256 explicitly. */

/* ─── Vision flow constants ─────────────────────────────────── */

#define VISION_PADDING_INITIAL_COUNT  8
#define VISION_PADDING_MAX_LEN        900  /* matches xray-core XtlsPadding */

/* Guard: Vision max_chunk calculation in vless_send must not underflow.
 * max_chunk = TLS_MAX_RECORD_PAYLOAD - (16+1+2+2) - VISION_PADDING_MAX_LEN */
_Static_assert(TLS_MAX_RECORD_PAYLOAD > 21 + VISION_PADDING_MAX_LEN + 1,
               "VISION_PADDING_MAX_LEN too large for TLS record payload");

/* Vision command bytes */
#define VISION_CMD_CONTINUE  0x00
#define VISION_CMD_END       0x01
#define VISION_CMD_DIRECT    0x02

/* ─── X25519MLKEM768 constants ─────────────────────────────── */

#define TLS_X25519MLKEM768   0x6399
#define MLKEM768_EK_LEN      1184
#define MLKEM768_CT_LEN      1088

/* ─── Chrome fingerprint profile ────────────────────────────── */

typedef struct {
    /* Cipher suites (after GREASE) */
    const uint16_t *ciphers;
    int num_ciphers;

    /* Signature algorithms */
    const uint16_t *sigalgs;
    int num_sigalgs;

    /* Supported groups (after GREASE) */
    const uint16_t *groups;
    int num_groups;

    /* ALPS extension type */
    uint16_t alps_ext_type;

    /* Include ECH GREASE? */
    int has_ech_grease;

    /* Include MLKEM in key_share? */
    int has_mlkem;

    /* Delegated credentials signature algorithms (subset of sigalgs:
     * ECDSA + RSA-PSS only, no PKCS1 or SHA-1 — per Chrome behavior).
     * When has_delegated_credentials is true, dc_sigalgs/num_dc_sigalgs
     * are used for the delegated_credentials extension instead of sigalgs. */
    int has_delegated_credentials;
    const uint16_t *dc_sigalgs;
    int num_dc_sigalgs;

    /* Include record_size_limit? */
    int has_record_size_limit;
} chrome_profile_t;

/* ─── REALITY TLS context ───────────────────────────────────── */

typedef struct {
    int fd;
    int io_timeout_ms;

    /* x25519 ephemeral key pair (used for REALITY auth + standalone X25519 key_share) */
    uint8_t eph_private[32];
    uint8_t eph_public[32];

    /* Separate X25519 key pair for the MLKEM hybrid key_share entry.
     * Real Chrome uses independent X25519 keys for the hybrid (X25519MLKEM768)
     * and standalone (X25519) key_share entries.  Sharing the same key is a
     * trivially detectable fingerprint (DPI compares the two 32-byte values). */
    uint8_t mlkem_eph_private[32];
    uint8_t mlkem_eph_public[32];

    /* Server's REALITY public key */
    uint8_t server_pub[32];

    /* Short ID */
    uint8_t short_id[8];
    size_t  short_id_len;

    /* Saved client_random for REALITY auth on HRR retry */
    uint8_t client_random[32];

    /* Guard against AES-GCM (key, nonce) reuse on HRR retry.
     * On HRR, client_random (and thus the GCM nonce) is reused per RFC 8446.
     * The ephemeral X25519 key MUST be regenerated so auth_key differs.
     * This field saves the eph_public used in the last REALITY auth call
     * so we can verify it changed before encrypting again. */
    uint8_t last_auth_eph_pub[32];
    int     reality_auth_done;

    /* Negotiated cipher suite parameters */
    uint16_t     cipher_suite;  /* 0x1301, 0x1302, or 0x1303 */
    size_t       hash_len;      /* 32 (SHA-256) or 48 (SHA-384) */
    size_t       key_len;       /* 16 (AES-128) or 32 (AES-256/ChaCha20) */
    const EVP_MD *hash_md;      /* EVP_sha256() or EVP_sha384() */
    const EVP_CIPHER *aead_cipher; /* EVP_aes_128_gcm(), EVP_aes_256_gcm(), or EVP_chacha20_poly1305() */

    /* TLS transcript hash (running digest of all handshake messages) */
    EVP_MD_CTX *transcript;

    /* Handshake traffic keys (max size: AES-256 = 32 bytes) */
    uint8_t s_hs_key[TLS_GCM_KEY_LEN_256];
    uint8_t s_hs_iv[TLS_GCM_IV_LEN];
    uint8_t c_hs_key[TLS_GCM_KEY_LEN_256];
    uint8_t c_hs_iv[TLS_GCM_IV_LEN];

    /* Application traffic keys (max size: AES-256 = 32 bytes) */
    uint8_t s_app_key[TLS_GCM_KEY_LEN_256];
    uint8_t s_app_iv[TLS_GCM_IV_LEN];
    uint8_t c_app_key[TLS_GCM_KEY_LEN_256];
    uint8_t c_app_iv[TLS_GCM_IV_LEN];

    /* Record sequence numbers */
    uint64_t read_seq;
    uint64_t write_seq;

    /* Which keys are active for read/write */
    const uint8_t *cur_read_key;
    const uint8_t *cur_read_iv;
    const uint8_t *cur_write_key;
    const uint8_t *cur_write_iv;

    /* Handshake read buffer (for reassembly across records).
     * 64KB accommodates large certificate chains (multiple intermediates).
     * Must be heap-allocated due to large buffers — vless_reality_ctx_t
     * is always allocated on the heap via calloc. */
    uint8_t  hs_buf[65536];
    size_t   hs_buf_len;

    /* Decrypted application data buffer.
     * The 256-byte margin accommodates the TLS record header (5 bytes),
     * content type byte (1 byte), and AEAD tag (16 bytes) that may be
     * present during in-place decryption before the plaintext is extracted. */
    uint8_t  app_buf[TLS_MAX_RECORD_PAYLOAD + 256];
    size_t   app_buf_len;
    size_t   app_buf_off;

    /* Pre-allocated ciphertext buffer for tls_read_encrypted, avoiding
     * repeated heap allocations on every record read.  Allocated once during
     * handshake, freed in vless_reality_free().  Stored as pointer to avoid
     * bloating the struct (which can affect code layout and cache alignment). */
    uint8_t *ct_buf;
    size_t   ct_buf_cap;

    /* Pre-allocated write buffer for tls_write_encrypted, avoiding
     * per-record malloc/free on every application data send.
     * Layout: [5-byte header][ciphertext].  Same lifetime as ct_buf. */
    uint8_t *wt_buf;
    size_t   wt_buf_cap;

    /* Track whether first ClientHello has been sent (for record version) */
    int initial_ch_sent;

    /* Chrome fingerprint profile */
    const chrome_profile_t *profile;

    /* X25519MLKEM768 (ML-KEM-768 hybrid, optional) */
    EVP_PKEY *mlkem_key;       /* ML-KEM-768 keypair for decapsulation */
    int       mlkem_available; /* 1 if OpenSSL supports ML-KEM-768 */

    /* P-256/P-384 ECDH ephemeral keys (for HRR fallback) */
    EVP_PKEY *ecdh_p256_key;
    uint8_t   ecdh_p256_pub[65];   /* uncompressed point: 1 + 32 + 32 */
    size_t    ecdh_p256_pub_len;

    EVP_PKEY *ecdh_p384_key;
    uint8_t   ecdh_p384_pub[97];   /* uncompressed point: 1 + 48 + 48 */
    size_t    ecdh_p384_pub_len;
} vless_reality_ctx_t;

/* Guard against accidental stack allocation — this struct is ~180KB+
 * due to hs_buf[65536] and app_buf[~16640]. Always heap-allocate via calloc. */
_Static_assert(sizeof(vless_reality_ctx_t) > 65536,
               "vless_reality_ctx_t must be heap-allocated (too large for stack)");

/* ─── Connection state ──────────────────────────────────────── */

typedef enum {
    VLESS_STATE_INIT,
    VLESS_STATE_CONNECTED,
    VLESS_STATE_HEADER_SENT,
    VLESS_STATE_READY,
    VLESS_STATE_CLOSED
} vless_state_t;

struct vless_conn {
    int           fd;
    int           io_timeout_ms;
    _Atomic vless_state_t state;
    uint8_t       uuid[16];
    int           response_parsed;

    /* Mode: 0 = plain TLS (BoringSSL), 1 = REALITY */
    int use_reality;

    /* Plain TLS mode */
    SSL_CTX *ssl_ctx;
    SSL     *ssl;

    /* REALITY mode */
    vless_reality_ctx_t *reality;

    /* Vision flow */
    int vision_enabled;
    int vision_send_remaining;    /* number of padded messages left to send */
    int vision_recv_remaining;    /* number of padded messages left to recv */
    int vision_first_send;        /* 1 = first send (includes UUID in frame) */
    int vision_recv_uuid_seen;    /* 1 = UUID header already stripped from recv */
    int vision_direct;            /* 1 = server sent end/direct cmd, stop framing */

    /* Vision recv spillover buffer for content that didn't fit in caller's buf */
    uint8_t *vision_spill;        /* heap-allocated, NULL when empty */
    size_t   vision_spill_len;    /* total bytes in spill buffer */
    size_t   vision_spill_off;    /* bytes already consumed from spill buffer */

    /* Pool management */
    int64_t idle_since;           /* CLOCK_MONOTONIC seconds (int64_t, not time_t, to signal monotonic semantics) */
    struct vless_pool *owner_pool; /* Back-pointer to pool, or NULL if not pooled */
};

#define CONN_STATE_LOAD(c)     atomic_load_explicit(&(c)->state, memory_order_acquire)
#define CONN_STATE_STORE(c, s) atomic_store_explicit(&(c)->state, (s), memory_order_release)

/* ─── Internal helpers ──────────────────────────────────────── */

/* Thread-local error */
#if defined(__GNUC__) || defined(__clang__)
__attribute__((format(printf, 1, 2)))
#endif
VLESS_INTERNAL void vless_set_error(const char *fmt, ...);

/* Poll helpers for non-blocking I/O (EINTR-safe, default 30s if timeout_ms <= 0) */
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_poll_read(int fd, int timeout_ms);
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_poll_write(int fd, int timeout_ms);

/* TCP connect with timeout.  On success sets *fd_out to the connected
 * non-blocking socket and returns VLESS_OK.  On failure returns a negative
 * error code and *fd_out is set to -1. */
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_tcp_connect(const char *host, uint16_t port, int timeout_ms, int *fd_out);

/* Plain TLS helpers (BoringSSL) */
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_tls_init(vless_conn_t *conn, const vless_tls_config_t *cfg,
                   const char *server_host);
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_tls_handshake(vless_conn_t *conn);

/* REALITY handshake + record layer */
VLESS_INTERNAL VLESS_WARN_UNUSED
int  vless_reality_handshake(vless_conn_t *conn, const vless_config_t *config);
VLESS_INTERNAL VLESS_WARN_UNUSED
int  vless_reality_send(vless_conn_t *conn, const void *data, size_t len);
VLESS_INTERNAL VLESS_WARN_UNUSED
int  vless_reality_recv(vless_conn_t *conn, void *buf, size_t buf_len);
VLESS_INTERNAL void vless_reality_close_notify(vless_reality_ctx_t *ctx);
VLESS_INTERNAL void vless_reality_free(vless_reality_ctx_t *ctx);

/* Pool back-pointer helper (called from vless_close to auto-decrement in_use_count).
 * Also drops the connection's reference on the pool — may free the pool if this
 * was the last reference. */
VLESS_INTERNAL void vless_pool_dec_in_use(struct vless_pool *pool);

/* Two-phase connect for connection pooling */
VLESS_INTERNAL VLESS_WARN_UNUSED
vless_conn_t *vless_connect_no_request(const vless_config_t *config);
VLESS_INTERNAL VLESS_WARN_UNUSED
int vless_send_request(vless_conn_t *conn, const uint8_t uuid[16],
                       const char *dest_host, uint16_t dest_port,
                       int vision_enabled);

#endif /* VLESS_INTERNAL_H */
