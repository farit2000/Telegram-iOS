/*
 * vless_reality.c - REALITY protocol implementation
 *
 * Manual TLS 1.3 client with:
 *   - Chrome browser TLS fingerprint (cipher suites, extensions, GREASE)
 *   - REALITY x25519 authentication via encrypted session_id
 *   - AES-128-GCM / AES-256-GCM / ChaCha20-Poly1305 record encryption
 *
 * The REALITY protocol makes traffic indistinguishable from legitimate
 * HTTPS to any real website. The server presents the real website's
 * certificate, and DPI cannot differentiate the connection from normal
 * browser traffic.
 *
 * Protocol flow:
 *   1. Client sends Chrome-fingerprinted ClientHello with REALITY auth in session_id
 *   2. Server verifies via x25519 shared secret, proxies real site's cert
 *   3. TLS 1.3 handshake completes (keys derived from ECDHE)
 *   4. VLESS protocol data sent over encrypted TLS records
 */

/* _POSIX_C_SOURCE for standard APIs (clock_gettime, etc.) */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200112L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "vless_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <errno.h>
#include <inttypes.h>

#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/crypto.h> /* OPENSSL_cleanse */
#include <openssl/ec.h>    /* EC_KEY, NID_X9_62_prime256v1, NID_secp384r1 */
#include <openssl/x509.h>  /* d2i_X509, X509_get_pubkey */
#include <openssl/rsa.h>   /* RSA_PKCS1_PSS_PADDING */

/* BoringSSL doesn't define RSA_PSS_SALTLEN_DIGEST.
 * Value -1 means "salt length equals digest length" (RFC 8446 §4.2.3). */
#ifndef RSA_PSS_SALTLEN_DIGEST
#define RSA_PSS_SALTLEN_DIGEST -1
#endif

/* safe_strerror() is provided by vless_internal.h */

#ifdef OPENSSL_IS_BORINGSSL
#include <openssl/curve25519.h>
/* BoringSSL X25519_keypair returns void; wrap for uniform int-returning API */
static int x25519_generate(uint8_t pub[32], uint8_t priv[32]) {
    X25519_keypair(pub, priv);
    return 1;
}
static int x25519_shared(uint8_t out[32], const uint8_t priv[32], const uint8_t peer[32]) {
    return X25519(out, priv, peer);
}
#else
/* OpenSSL 3.x compatibility for X25519 */
#include <openssl/core_names.h>

static int x25519_generate(uint8_t out_public[32], uint8_t out_private[32]) {
    EVP_PKEY *pkey = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    if (!ctx) return 0;
    if (EVP_PKEY_keygen_init(ctx) <= 0 ||
        EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        return 0;
    }
    EVP_PKEY_CTX_free(ctx);

    size_t len = 32;
    if (EVP_PKEY_get_raw_private_key(pkey, out_private, &len) <= 0) {
        EVP_PKEY_free(pkey);
        return 0;
    }
    len = 32;
    if (EVP_PKEY_get_raw_public_key(pkey, out_public, &len) <= 0) {
        OPENSSL_cleanse(out_private, 32);
        OPENSSL_cleanse(out_public, 32);
        EVP_PKEY_free(pkey);
        return 0;
    }
    EVP_PKEY_free(pkey);
    return 1;
}

static int x25519_shared(uint8_t out_shared[32],
                          const uint8_t private_key[32],
                          const uint8_t peer_public[32]) {
    EVP_PKEY *priv = EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, NULL,
                                                    private_key, 32);
    EVP_PKEY *pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL,
                                                  peer_public, 32);
    if (!priv || !pub) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return 0;
    }
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(priv, NULL);
    if (!ctx) {
        EVP_PKEY_free(priv);
        EVP_PKEY_free(pub);
        return 0;
    }
    int ok = EVP_PKEY_derive_init(ctx) > 0 &&
             EVP_PKEY_derive_set_peer(ctx, pub) > 0;
    size_t len = 32;
    if (ok) ok = EVP_PKEY_derive(ctx, out_shared, &len) > 0;
    if (!ok) OPENSSL_cleanse(out_shared, 32);
    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(priv);
    EVP_PKEY_free(pub);
    return ok ? 1 : 0;
}
#endif

/* ─── P-256 / P-384 ECDH helpers (for HRR fallback) ───────── */

/*
 * Generate an ephemeral ECDH key pair for P-256 (NID_X9_62_prime256v1)
 * or P-384 (NID_secp384r1).
 *
 * pub_out receives the uncompressed point (65 bytes for P-256, 97 for P-384).
 * key_out receives the EVP_PKEY* (caller must EVP_PKEY_free).
 * Returns 1 on success, 0 on failure.
 */
static int ecdh_generate(int nid, uint8_t *pub_out, size_t *pub_len, EVP_PKEY **key_out) {
    *key_out = NULL;
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    if (!ctx) return 0;

    EVP_PKEY *key = NULL;
    int ok = EVP_PKEY_keygen_init(ctx) > 0 &&
             EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, nid) > 0 &&
             EVP_PKEY_keygen(ctx, &key) > 0;
    EVP_PKEY_CTX_free(ctx);
    if (!ok || !key) { EVP_PKEY_free(key); return 0; }

    /* Extract public key in uncompressed point format */
    size_t len = 0;
#ifdef OPENSSL_IS_BORINGSSL
    /* BoringSSL: use EVP_PKEY_get1_EC_KEY + EC_POINT_point2oct */
    EC_KEY *ec = EVP_PKEY_get1_EC_KEY(key);
    if (!ec) { EVP_PKEY_free(key); return 0; }
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    const EC_POINT *point = EC_KEY_get0_public_key(ec);
    len = EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                             NULL, 0, NULL);
    if (len == 0 || len > 97) { EC_KEY_free(ec); EVP_PKEY_free(key); return 0; }
    if (EC_POINT_point2oct(group, point, POINT_CONVERSION_UNCOMPRESSED,
                           pub_out, len, NULL) != len) {
        EC_KEY_free(ec); EVP_PKEY_free(key); return 0;
    }
    EC_KEY_free(ec);
#else
    /* OpenSSL 3.x: use OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY */
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                          NULL, 0, &len)) {
        EVP_PKEY_free(key);
        return 0;
    }
    if (len > 97) { EVP_PKEY_free(key); return 0; }
    if (!EVP_PKEY_get_octet_string_param(key, OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                          pub_out, len, &len)) {
        EVP_PKEY_free(key);
        return 0;
    }
#endif
    *pub_len = len;
    *key_out = key;
    return 1;
}

/*
 * Compute ECDH shared secret using our private key and peer's uncompressed
 * public point.  out must be at least 48 bytes.  *out_len receives the
 * actual shared secret length (32 for P-256, 48 for P-384).
 * Returns 1 on success, 0 on failure.
 */
static int ecdh_shared(EVP_PKEY *priv_key, const uint8_t *peer_pub, size_t peer_pub_len,
                        int nid, uint8_t *out, size_t *out_len) {
    /* Reconstruct peer EVP_PKEY from raw uncompressed point */
    EVP_PKEY *peer = NULL;

#ifdef OPENSSL_IS_BORINGSSL
    EC_KEY *ec = EC_KEY_new_by_curve_name(nid);
    if (!ec) return 0;
    const EC_GROUP *group = EC_KEY_get0_group(ec);
    EC_POINT *point = EC_POINT_new(group);
    if (!point) { EC_KEY_free(ec); return 0; }
    if (!EC_POINT_oct2point(group, point, peer_pub, peer_pub_len, NULL)) {
        EC_POINT_free(point);
        EC_KEY_free(ec);
        return 0;
    }
    if (!EC_KEY_set_public_key(ec, point)) {
        EC_POINT_free(point);
        EC_KEY_free(ec);
        return 0;
    }
    EC_POINT_free(point);
    /* Validate the peer public key is on the curve */
    if (!EC_KEY_check_key(ec)) {
        EC_KEY_free(ec);
        return 0;
    }
    peer = EVP_PKEY_new();
    if (!peer || !EVP_PKEY_set1_EC_KEY(peer, ec)) {
        EC_KEY_free(ec);
        EVP_PKEY_free(peer);
        return 0;
    }
    EC_KEY_free(ec);
#else
    /* OpenSSL 3.x: build peer key from raw encoded public key + group name */
    const char *group_name = (nid == NID_X9_62_prime256v1) ? "P-256" : "P-384";
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("group", (char *)group_name, 0),
        OSSL_PARAM_construct_octet_string("pub", (void *)peer_pub, peer_pub_len),
        OSSL_PARAM_END
    };
    EVP_PKEY_CTX *pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx) return 0;
    if (EVP_PKEY_fromdata_init(pctx) <= 0 ||
        EVP_PKEY_fromdata(pctx, &peer, EVP_PKEY_PUBLIC_KEY, params) <= 0) {
        EVP_PKEY_CTX_free(pctx);
        return 0;
    }
    EVP_PKEY_CTX_free(pctx);

    /* Explicitly validate peer public key is on the curve.
     * EVP_PKEY_fromdata does not guarantee validation; without this check,
     * an invalid-curve attack could extract the private key. */
    {
        EVP_PKEY_CTX *check_ctx = EVP_PKEY_CTX_new(peer, NULL);
        if (!check_ctx || EVP_PKEY_public_check(check_ctx) <= 0) {
            EVP_PKEY_CTX_free(check_ctx);
            EVP_PKEY_free(peer);
            return 0;
        }
        EVP_PKEY_CTX_free(check_ctx);
    }
#endif

    /* Derive shared secret */
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(priv_key, NULL);
    if (!dctx) { EVP_PKEY_free(peer); return 0; }

    int ok = 0;
    size_t slen = 0;
    if (EVP_PKEY_derive_init(dctx) > 0 &&
        EVP_PKEY_derive_set_peer(dctx, peer) > 0) {
        if (EVP_PKEY_derive(dctx, NULL, &slen) > 0 && slen <= 48) {
            if (EVP_PKEY_derive(dctx, out, &slen) > 0) {
                *out_len = slen;
                ok = 1;
            }
        }
    }

    if (!ok) {
        /* Cleanse the exact derived secret size, or max (48) if unknown.
         * P-256 = 32 bytes, P-384 = 48 bytes. */
        OPENSSL_cleanse(out, slen > 0 ? slen : 48);
    }
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer);
    return ok;
}

/* ─── Utility: write/read exact bytes on socket (non-blocking + poll) ── */

static int sock_write_all(vless_reality_ctx_t *r, const uint8_t *data, size_t len) {
    if (r->fd < 0) return VLESS_ERR_IO;
    size_t sent = 0;
    /* Overall deadline prevents indefinite loops on slow peers (M7) */
    struct timespec deadline;
    int use_deadline = (r->io_timeout_ms > 0 &&
                        clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    if (use_deadline) {
        int timeout_sec = r->io_timeout_ms / 1000;
        /* Clamp to prevent time_t overflow on 32-bit systems */
        if (timeout_sec > 86400) timeout_sec = 86400;
        deadline.tv_sec += timeout_sec;
        deadline.tv_nsec += (long)(r->io_timeout_ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }
    while (sent < len) {
#ifdef MSG_NOSIGNAL
        ssize_t n = send(r->fd, data + sent, len - sent, MSG_NOSIGNAL);
#else
        /* macOS/BSD: no MSG_NOSIGNAL; rely on SO_NOSIGPIPE set on the socket
         * (in vless_tcp_connect) or process-wide SIGPIPE ignore. Use send()
         * with flags=0 instead of write() for consistency. */
        ssize_t n = send(r->fd, data + sent, len - sent, 0);
#endif
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                int poll_ms = r->io_timeout_ms;
                if (use_deadline) {
                    struct timespec now;
                    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                        int64_t diff_s = (int64_t)deadline.tv_sec - (int64_t)now.tv_sec;
                        long diff_ns = deadline.tv_nsec - now.tv_nsec;
                        if (diff_ns < 0) { diff_s--; diff_ns += 1000000000L; }
                        int64_t rem64 = diff_s * 1000 + diff_ns / 1000000;
                        int remaining = rem64 > INT_MAX ? INT_MAX : (int)rem64;
                        if (remaining <= 0) {
                            vless_set_error("write deadline exceeded (sent %zu/%zu)", sent, len);
                            return VLESS_ERR_TIMEOUT;
                        }
                        poll_ms = remaining;
                    }
                }
                int rc = vless_poll_write(r->fd, poll_ms);
                if (rc != VLESS_OK) return rc;
                continue;
            }
            {
                char errbuf[64];
                safe_strerror(errno, errbuf, sizeof(errbuf));
                vless_set_error("write error: %s (sent %zu/%zu)", errbuf, sent, len);
            }
            return VLESS_ERR_IO;
        }
        sent += (size_t)n;
    }
    return VLESS_OK;
}

static int sock_read_all(vless_reality_ctx_t *r, uint8_t *buf, size_t len) {
    if (r->fd < 0) return VLESS_ERR_IO;
    size_t got = 0;
    /* Overall deadline prevents indefinite loops on slow peers (M7) */
    struct timespec deadline;
    int use_deadline = (r->io_timeout_ms > 0 &&
                        clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    if (use_deadline) {
        int timeout_sec = r->io_timeout_ms / 1000;
        /* Clamp to prevent time_t overflow on 32-bit systems */
        if (timeout_sec > 86400) timeout_sec = 86400;
        deadline.tv_sec += timeout_sec;
        deadline.tv_nsec += (long)(r->io_timeout_ms % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }
    while (got < len) {
        ssize_t n = recv(r->fd, buf + got, len - got, 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == EAGAIN || errno == EWOULDBLOCK) {
                int poll_ms = r->io_timeout_ms;
                if (use_deadline) {
                    struct timespec now;
                    if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                        int64_t diff_s = (int64_t)deadline.tv_sec - (int64_t)now.tv_sec;
                        long diff_ns = deadline.tv_nsec - now.tv_nsec;
                        if (diff_ns < 0) { diff_s--; diff_ns += 1000000000L; }
                        int64_t rem64 = diff_s * 1000 + diff_ns / 1000000;
                        int remaining = rem64 > INT_MAX ? INT_MAX : (int)rem64;
                        if (remaining <= 0) {
                            vless_set_error("read deadline exceeded (got %zu/%zu)", got, len);
                            return VLESS_ERR_TIMEOUT;
                        }
                        poll_ms = remaining;
                    }
                }
                int rc = vless_poll_read(r->fd, poll_ms);
                if (rc != VLESS_OK) return rc;
                continue;
            }
            {
                char errbuf[64];
                safe_strerror(errno, errbuf, sizeof(errbuf));
                vless_set_error("read error: %s (got %zu/%zu)", errbuf, got, len);
            }
            return VLESS_ERR_IO;
        }
        if (n == 0) {
            vless_set_error("connection closed after %zu/%zu bytes", got, len);
            return VLESS_ERR_CLOSED;
        }
        got += (size_t)n;
    }
    return VLESS_OK;
}

/* ─── Base64 decoder ────────────────────────────────────────── */

static int b64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+' || c == '-') return 62;  /* + or base64url - */
    if (c == '/' || c == '_') return 63;  /* / or base64url _ */
    return -1;
}

static int base64_decode(const char *in, uint8_t *out, size_t max_out, size_t *out_len) {
    if (!in || !out || !out_len) return VLESS_ERR_INVALID_ARG;
    size_t len = strlen(in);
    while (len > 0 && in[len - 1] == '=') len--;

    size_t olen = 0;
    int trailing_bits = 0;
    uint32_t last_acc = 0;
    for (size_t i = 0; i < len; ) {
        uint32_t acc = 0;
        int bits = 0;
        for (int j = 0; j < 4 && i < len; j++, i++) {
            int v = b64_val(in[i]);
            if (v < 0) return VLESS_ERR_INVALID_ARG;
            acc = (acc << 6) | (uint32_t)v;
            bits += 6;
        }
        while (bits >= 8) {
            bits -= 8;
            if (olen >= max_out) return VLESS_ERR_INVALID_ARG;
            out[olen++] = (uint8_t)(acc >> bits);
        }
        trailing_bits = bits;
        last_acc = acc;
    }
    /* Reject invalid base64: 1-char remainder (6 bits) can't form a byte */
    if (trailing_bits >= 6 && len % 4 == 1) return VLESS_ERR_INVALID_ARG;
    /* RFC 4648: unused trailing bits must be zero */
    if (trailing_bits > 0 && (last_acc & ((1u << trailing_bits) - 1)) != 0)
        return VLESS_ERR_INVALID_ARG;
    *out_len = olen;
    return VLESS_OK;
}

/* ─── Hex decoder ───────────────────────────────────────────── */

static int hex_val(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int hex_decode(const char *in, uint8_t *out, size_t max_out, size_t *out_len) {
    if (!in || !out || !out_len) return VLESS_ERR_INVALID_ARG;
    size_t slen = strlen(in);
    if (slen % 2 != 0) return VLESS_ERR_INVALID_ARG;
    *out_len = 0;
    for (size_t i = 0; i + 1 < slen; i += 2) {
        if (*out_len >= max_out) return VLESS_ERR_INVALID_ARG;
        int hi = hex_val(in[i]), lo = hex_val(in[i + 1]);
        if (hi < 0 || lo < 0) return VLESS_ERR_INVALID_ARG;
        out[(*out_len)++] = (uint8_t)((hi << 4) | lo);
    }
    return VLESS_OK;
}

/* ─── HMAC (parameterized by hash) ──────────────────────────── */

/*
 * Generic HMAC using any EVP_MD. out must be at least EVP_MD_size(md) bytes.
 * Returns VLESS_OK or VLESS_ERR_CRYPTO.
 */
static int hmac_hash(const EVP_MD *md,
                     const uint8_t *key, size_t key_len,
                     const uint8_t *data, size_t data_len,
                     uint8_t *out, size_t *out_len_actual) {
    if (key_len > INT_MAX) return VLESS_ERR_INVALID_ARG;
    unsigned int len = 0;
    if (!HMAC(md, key, (int)key_len, data, data_len, out, &len))
        return VLESS_ERR_CRYPTO;
    if (out_len_actual) *out_len_actual = len;
    return VLESS_OK;
}

/* Convenience wrapper for SHA-256 (used by tests and non-parameterized paths) */
VLESS_UNUSED
static int hmac_sha256(const uint8_t *key, size_t key_len,
                       const uint8_t *data, size_t data_len,
                       uint8_t out[32]) {
    return hmac_hash(EVP_sha256(), key, key_len, data, data_len, out, NULL);
}

/* ─── HKDF (parameterized by hash) ──────────────────────────── */

/*
 * HKDF-Extract(salt, IKM) = HMAC-Hash(salt, IKM)
 * hash_len is the output size of the hash (32 for SHA-256, 48 for SHA-384).
 * prk must have space for hash_len bytes.
 */
static int hkdf_extract_ex(const EVP_MD *md, size_t hash_len,
                            const uint8_t *salt, size_t salt_len,
                            const uint8_t *ikm, size_t ikm_len,
                            uint8_t *prk) {
    uint8_t zeros[TLS_HASH_LEN_384] = {0};
    if (!salt || salt_len == 0) { salt = zeros; salt_len = hash_len; }
    return hmac_hash(md, salt, salt_len, ikm, ikm_len, prk, NULL);
}

/* SHA-256 convenience wrapper (backwards compat for tests) */
static int hkdf_extract(const uint8_t *salt, size_t salt_len,
                         const uint8_t *ikm, size_t ikm_len,
                         uint8_t prk[32]) {
    return hkdf_extract_ex(EVP_sha256(), TLS_HASH_LEN_256,
                           salt, salt_len, ikm, ikm_len, prk);
}

/*
 * HKDF-Expand(PRK, info, L) - supports up to 2 hash blocks of output.
 * hash_len is the hash output size. prk must be hash_len bytes.
 */
static int hkdf_expand_ex(const EVP_MD *md, size_t hash_len,
                            const uint8_t *prk,
                            const uint8_t *info, size_t info_len,
                            uint8_t *out, size_t out_len) {
    /* Supports up to 2 hash blocks of output per RFC 5869 */
    if (out_len > 2 * hash_len) return VLESS_ERR_INVALID_ARG;

    /* T(1) = HMAC(PRK, info || 0x01) */
    uint8_t input[512 + TLS_HASH_LEN_384 + 1];

    /* T(2) needs: hash_len + info_len + 1 <= sizeof(input) */
    if (hash_len + info_len + 1 > sizeof(input)) {
        OPENSSL_cleanse(input, sizeof(input));
        return VLESS_ERR_CRYPTO;
    }
    if (info_len > 0) memcpy(input, info, info_len);
    input[info_len] = 0x01;
    uint8_t t[TLS_HASH_LEN_384];
    int rc = hmac_hash(md, prk, hash_len, input, info_len + 1, t, NULL);
    if (rc != VLESS_OK) goto done;
    memcpy(out, t, out_len < hash_len ? out_len : hash_len);

    /* T(2) if needed */
    if (out_len > hash_len) {
        size_t off = 0;
        memcpy(input, t, hash_len);
        off = hash_len;
        if (info_len > 0) memcpy(input + off, info, info_len);
        off += info_len;
        input[off++] = 0x02;
        rc = hmac_hash(md, prk, hash_len, input, off, t, NULL);
        if (rc != VLESS_OK) goto done;
        memcpy(out + hash_len, t, out_len - hash_len);
    }

done:
    OPENSSL_cleanse(t, sizeof(t));
    OPENSSL_cleanse(input, sizeof(input));
    return rc;
}

/* SHA-256 convenience wrapper (backwards compat for tests) */
static int hkdf_expand(const uint8_t prk[32],
                        const uint8_t *info, size_t info_len,
                        uint8_t *out, size_t out_len) {
    /* Max info_len = sizeof(input in hkdf_expand_ex) - hash_len - 1
     * = (512 + TLS_HASH_LEN_384 + 1) - TLS_HASH_LEN_256 - 1 = 528 */
    if (info_len > (512 + TLS_HASH_LEN_384 + 1) - TLS_HASH_LEN_256 - 1)
        return VLESS_ERR_CRYPTO;
    return hkdf_expand_ex(EVP_sha256(), TLS_HASH_LEN_256,
                           prk, info, info_len, out, out_len);
}

/*
 * HKDF-Expand-Label(Secret, Label, Context, Length)
 * TLS 1.3 label format: struct { uint16 length; opaque label<7..255>; opaque context<0..255>; }
 * Label is prefixed with "tls13 "
 */
static int hkdf_expand_label_ex(const EVP_MD *md, size_t hash_len,
                                  const uint8_t *secret,
                                  const char *label,
                                  const uint8_t *context, size_t ctx_len,
                                  uint8_t *out, size_t out_len) {
    uint8_t info[256];
    size_t pos = 0;
    size_t label_len = strlen(label);

    /* 2 + 1 + 6 + label_len + 1 + ctx_len must fit in info[256] */
    if (label_len + ctx_len + 10 > sizeof(info)) return VLESS_ERR_CRYPTO;

    /* uint16 length */
    info[pos++] = (uint8_t)(out_len >> 8);
    info[pos++] = (uint8_t)(out_len);

    /* opaque label<7..255> = "tls13 " + label */
    info[pos++] = (uint8_t)(6 + label_len);
    memcpy(info + pos, "tls13 ", 6); pos += 6;
    memcpy(info + pos, label, label_len); pos += label_len;

    /* opaque context<0..255> */
    info[pos++] = (uint8_t)ctx_len;
    if (ctx_len > 0) { memcpy(info + pos, context, ctx_len); pos += ctx_len; }

    return hkdf_expand_ex(md, hash_len, secret, info, pos, out, out_len);
}

/* SHA-256 convenience wrapper (backwards compat for tests) */
VLESS_UNUSED
static int hkdf_expand_label(const uint8_t secret[32],
                               const char *label,
                               const uint8_t *context, size_t ctx_len,
                               uint8_t *out, size_t out_len) {
    return hkdf_expand_label_ex(EVP_sha256(), TLS_HASH_LEN_256,
                                 secret, label, context, ctx_len, out, out_len);
}

/*
 * Derive-Secret(Secret, Label, Messages)
 * = HKDF-Expand-Label(Secret, Label, Hash(Messages), hash_len)
 */
static int derive_secret_ex(const EVP_MD *md, size_t hash_len,
                              const uint8_t *secret, const char *label,
                              const uint8_t *hash, uint8_t *out) {
    return hkdf_expand_label_ex(md, hash_len, secret, label,
                                 hash, hash_len, out, hash_len);
}

/* SHA-256 convenience wrapper */
VLESS_UNUSED
static int derive_secret(const uint8_t secret[32], const char *label,
                          const uint8_t hash[32], uint8_t out[32]) {
    return derive_secret_ex(EVP_sha256(), TLS_HASH_LEN_256, secret, label, hash, out);
}

/* ─── AEAD encrypt/decrypt (AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305) ── */

static int aead_seal_ex(const EVP_CIPHER *cipher, const uint8_t *key,
                        const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *plaintext, size_t pt_len,
                        uint8_t *out /* pt_len + 16 */) {
    if (aad_len > INT_MAX || pt_len > INT_MAX) return VLESS_ERR_INVALID_ARG;
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return VLESS_ERR_CRYPTO;

    int len = 0, ct_len;
    int ok = EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL) &&
             EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) &&
             EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) &&
             EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_len) &&
             EVP_EncryptUpdate(ctx, out, &len, plaintext, (int)pt_len);
    ct_len = len;
    ok = ok && EVP_EncryptFinal_ex(ctx, out + ct_len, &len);
    ct_len += len;
    ok = ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, 16, out + ct_len);
    EVP_CIPHER_CTX_free(ctx);
    if (!ok) {
        OPENSSL_cleanse(out, pt_len + 16);
        return VLESS_ERR_CRYPTO;
    }
    return VLESS_OK;
}

static int aead_open_ex(const EVP_CIPHER *cipher, const uint8_t *key,
                        const uint8_t nonce[12],
                        const uint8_t *aad, size_t aad_len,
                        const uint8_t *ciphertext, size_t ct_len, /* includes 16-byte tag */
                        uint8_t *out /* ct_len - 16 */) {
    if (ct_len < 16) return VLESS_ERR_CRYPTO;
    if (aad_len > INT_MAX || ct_len > INT_MAX) return VLESS_ERR_INVALID_ARG;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) return VLESS_ERR_CRYPTO;

    size_t data_len = ct_len - 16;
    int len = 0;

    uint8_t tag[16];
    memcpy(tag, ciphertext + data_len, 16);

    int dok = EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL) &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, 12, NULL) &&
              EVP_DecryptInit_ex(ctx, NULL, NULL, key, nonce) &&
              EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_len) &&
              EVP_DecryptUpdate(ctx, out, &len, ciphertext, (int)data_len) &&
              EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_TAG, 16, tag);
    dok = dok && EVP_DecryptFinal_ex(ctx, out + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (!dok) {
        /* Zero output on authentication failure to prevent use of unauthenticated data */
        OPENSSL_cleanse(out, data_len);
        return VLESS_ERR_CRYPTO;
    }
    return VLESS_OK;
}

/* Backwards-compatible wrappers for tests (AES-128-GCM) */
VLESS_UNUSED
static int aead_seal(const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *plaintext, size_t pt_len,
                     uint8_t *out) {
    return aead_seal_ex(EVP_aes_128_gcm(), key, nonce, aad, aad_len,
                        plaintext, pt_len, out);
}

VLESS_UNUSED
static int aead_open(const uint8_t key[16], const uint8_t nonce[12],
                     const uint8_t *aad, size_t aad_len,
                     const uint8_t *ciphertext, size_t ct_len,
                     uint8_t *out) {
    return aead_open_ex(EVP_aes_128_gcm(), key, nonce, aad, aad_len,
                        ciphertext, ct_len, out);
}

/* ─── TLS record nonce computation ──────────────────────────── */

static void compute_nonce(const uint8_t iv[12], uint64_t seq, uint8_t nonce[12]) {
    memcpy(nonce, iv, 12);
    for (int i = 0; i < 8; i++) {
        nonce[12 - 1 - i] ^= (uint8_t)(seq >> (i * 8));
    }
}

/* ─── TLS record I/O ───────────────────────────────────────── */

/* Write a plaintext TLS record.
 * Version field: first ClientHello uses 0x0301 (TLS 1.0) for max compat.
 * Retry ClientHello and all other records use 0x0303 (TLS 1.2) per TLS 1.3 spec.
 * is_initial_ch: 1 for the very first ClientHello, 0 for everything else. */
static int tls_write_record(vless_reality_ctx_t *r, uint8_t type,
                              const uint8_t *data, size_t len) {
    if (len > 16384) {
        vless_set_error("TLS record too large to send: %zu", len);
        return VLESS_ERR_INVALID_ARG;
    }

    /* Combine header and data into a single write to avoid sending
     * partial TLS records that could be distinguished by DPI.
     * Use stack buffer for small records (ClientHello ~1.8KB, CCS 1 byte)
     * to avoid heap allocation during handshake. */
    size_t total = 5 + len;
    uint8_t stack_buf[4096];
    uint8_t *buf;
    int on_heap = 0;
    if (total <= sizeof(stack_buf)) {
        buf = stack_buf;
    } else {
        buf = malloc(total);
        if (!buf) return VLESS_ERR_NOMEM;
        on_heap = 1;
    }

    buf[0] = type;
    buf[1] = 0x03;
    /* First CH uses 0x0301 (TLS 1.0); retry CH and everything else uses 0x0303 */
    buf[2] = (type == TLS_RECORD_HANDSHAKE && !r->initial_ch_sent) ? 0x01 : 0x03;
    if (type == TLS_RECORD_HANDSHAKE && !r->initial_ch_sent) r->initial_ch_sent = 1;
    buf[3] = (uint8_t)(len >> 8);
    buf[4] = (uint8_t)(len);
    memcpy(buf + 5, data, len);

    int rc = sock_write_all(r, buf, total);
    if (on_heap) {
        OPENSSL_cleanse(buf, total);
        free(buf);
    } else {
        /* Cleanse stack buffer: may contain ClientHello with encrypted
         * REALITY session_id and client_random. */
        OPENSSL_cleanse(stack_buf, total);
    }
    return rc;
}

/* Read a TLS record header + body.
 * buf_cap is the caller's buffer size; returns VLESS_ERR_PROTOCOL if record exceeds it. */
static int tls_read_record(vless_reality_ctx_t *r, uint8_t *type,
                            uint8_t *buf, size_t buf_cap, size_t *len) {
    uint8_t hdr[5];
    int rc = sock_read_all(r, hdr, 5);
    if (rc != VLESS_OK) {
        vless_set_error("failed to read TLS record header: rc=%d", rc);
        return rc;
    }

    *type = hdr[0];

    /* Validate TLS record layer version: must be 0x0301 or 0x0303 */
    if (hdr[1] != 0x03 || (hdr[2] != 0x01 && hdr[2] != 0x03)) {
        vless_set_error("TLS record invalid version 0x%02x%02x", hdr[1], hdr[2]);
        return VLESS_ERR_PROTOCOL;
    }

    size_t record_len = ((size_t)hdr[3] << 8) | hdr[4];

    if (record_len > TLS_MAX_RECORD_PAYLOAD + 256) {
        vless_set_error("TLS record too large: %zu (type=%d)", record_len, hdr[0]);
        return VLESS_ERR_PROTOCOL;
    }

    if (record_len > buf_cap) {
        vless_set_error("TLS record %zu exceeds buffer %zu (type=%d)",
                        record_len, buf_cap, hdr[0]);
        return VLESS_ERR_PROTOCOL;
    }

    rc = sock_read_all(r, buf, record_len);
    if (rc != VLESS_OK) return rc;
    *len = record_len;
    return VLESS_OK;
}

/* Write encrypted TLS 1.3 record (application_data wrapper) */
static int tls_write_encrypted(vless_reality_ctx_t *r,
                                uint8_t inner_type,
                                const uint8_t *data, size_t data_len) {
    /* Check sequence number BEFORE encryption to avoid nonce reuse */
    if (r->write_seq == UINT64_MAX) {
        vless_set_error("TLS write sequence number exhausted");
        return VLESS_ERR_PROTOCOL;
    }

    /* Enforce TLS 1.3 max record size */
    size_t pt_len = data_len + 1;
    size_t ct_len = pt_len + TLS_GCM_TAG_LEN;
    if (ct_len > TLS_MAX_RECORD_PAYLOAD + 256) {
        vless_set_error("TLS record payload too large: %zu", data_len);
        return VLESS_ERR_INVALID_ARG;
    }

    /* Use pre-allocated write buffer: [5-byte header][ciphertext(ct_len)].
     * Plaintext is assembled at offset 5, then encrypted in-place.
     * OpenSSL EVP_EncryptUpdate supports overlapping in == out for GCM/ChaCha20.
     * Lazily allocates if not yet set (test contexts bypass handshake). */
    size_t record_len = 5 + ct_len;
    if (!r->wt_buf) {
        r->wt_buf_cap = 5 + TLS_MAX_RECORD_PAYLOAD + 256;
        r->wt_buf = malloc(r->wt_buf_cap);
        if (!r->wt_buf) return VLESS_ERR_NOMEM;
    }
    uint8_t *record = r->wt_buf;

    /* Build plaintext at record+5: [data][content_type_byte] */
    memcpy(record + 5, data, data_len);
    record[5 + data_len] = inner_type;

    /* Fill record header (also serves as AAD) */
    record[0] = TLS_RECORD_APPLICATION_DATA;
    record[1] = 0x03;
    record[2] = 0x03;
    record[3] = (uint8_t)(ct_len >> 8);
    record[4] = (uint8_t)ct_len;

    /* Nonce from IV XOR seq */
    uint8_t nonce[12];
    compute_nonce(r->cur_write_iv, r->write_seq, nonce);

    /* Encrypt in-place: plaintext at record+5 → ciphertext+tag at record+5 */
    int rc = aead_seal_ex(r->aead_cipher, r->cur_write_key, nonce,
                          record, 5, /* AAD = header */
                          record + 5, pt_len, /* plaintext */
                          record + 5); /* output overwrites plaintext, tag appended */
    OPENSSL_cleanse(nonce, sizeof(nonce));
    if (rc != VLESS_OK) {
        OPENSSL_cleanse(record, record_len);
        return rc;
    }

    /* Increment sequence number after successful encryption but BEFORE
     * the network write.  This avoids AES-GCM nonce reuse: if the write
     * fails, the caller will close the connection (state → CLOSED),
     * and the incremented seq prevents reuse even if a retry were attempted.
     * A nonce gap from a failed write is harmless (peer never saw it). */
    r->write_seq++;

    rc = sock_write_all(r, record, record_len);
    OPENSSL_cleanse(record, record_len);

    return rc;
}

/* Read and decrypt a TLS 1.3 record. Returns inner content type.
 * Uses pre-allocated r->ct_buf to avoid heap allocation per record.
 * Lazily allocates if not yet set (test contexts bypass handshake). */
static int tls_read_encrypted(vless_reality_ctx_t *r,
                               uint8_t *inner_type,
                               uint8_t *out, size_t out_cap,
                               size_t *out_len) {
    /* Lazy allocation for contexts created outside vless_reality_handshake */
    if (!r->ct_buf) {
        r->ct_buf_cap = TLS_MAX_RECORD_PAYLOAD + 256 + TLS_GCM_TAG_LEN;
        r->ct_buf = malloc(r->ct_buf_cap);
        if (!r->ct_buf) return VLESS_ERR_NOMEM;
    }

    uint8_t rec_type;
    size_t ct_len;

    int ccs_retries = 0;
retry:
    ;
    int rc = tls_read_record(r, &rec_type, r->ct_buf, r->ct_buf_cap, &ct_len);
    if (rc != VLESS_OK) return rc;

    /* Skip ChangeCipherSpec (middlebox compat, not encrypted) */
    if (rec_type == TLS_RECORD_CCS) {
        if (++ccs_retries > 4) {
            vless_set_error("Too many CCS records");
            return VLESS_ERR_PROTOCOL;
        }
        goto retry;
    }

    if (rec_type != TLS_RECORD_APPLICATION_DATA) {
        /* After handshake keys are installed, all records MUST be encrypted
         * (wrapped as application_data). A plaintext alert here indicates
         * either middlebox interference or an active attacker injecting
         * records to force-close the connection. Reject as protocol error. */
        if (rec_type == TLS_RECORD_ALERT) {
            vless_set_error("Plaintext TLS alert after handshake keys installed "
                           "(possible injection): %d %d",
                           ct_len >= 1 ? r->ct_buf[0] : -1,
                           ct_len >= 2 ? r->ct_buf[1] : -1);
            return VLESS_ERR_PROTOCOL;
        }
        vless_set_error("Unexpected TLS record type: %d", rec_type);
        return VLESS_ERR_PROTOCOL;
    }

    if (ct_len < TLS_GCM_TAG_LEN) return VLESS_ERR_PROTOCOL;

    /* Check sequence number BEFORE decryption to avoid nonce reuse */
    if (r->read_seq == UINT64_MAX) {
        vless_set_error("TLS read sequence number exhausted");
        return VLESS_ERR_PROTOCOL;
    }

    uint8_t nonce[12];
    compute_nonce(r->cur_read_iv, r->read_seq, nonce);

    uint8_t aad[5] = { TLS_RECORD_APPLICATION_DATA, 0x03, 0x03,
                        (uint8_t)(ct_len >> 8), (uint8_t)ct_len };

    size_t pt_len = ct_len - TLS_GCM_TAG_LEN;
    if (pt_len > out_cap) {
        vless_set_error("TLS record plaintext %zu exceeds buffer %zu", pt_len, out_cap);
        return VLESS_ERR_PROTOCOL;
    }
    rc = aead_open_ex(r->aead_cipher, r->cur_read_key, nonce, aad, 5, r->ct_buf, ct_len, out);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    if (rc != VLESS_OK) {
        vless_set_error("TLS record decryption failed (seq=%" PRIu64 ")", r->read_seq);
        return rc;
    }

    r->read_seq++;

    /* Last byte of plaintext is the real content type */
    /* Strip trailing zeros (padding) */
    while (pt_len > 0 && out[pt_len - 1] == 0) pt_len--;
    if (pt_len == 0) return VLESS_ERR_PROTOCOL;

    *inner_type = out[pt_len - 1];
    *out_len = pt_len - 1;
    return VLESS_OK;
}

/* ─── GREASE values (random 0xXaXa for Chrome fingerprint) ── */

static int grease_value(uint16_t *out) {
    uint8_t r;
    if (RAND_bytes(&r, 1) != 1) return VLESS_ERR_CRYPTO;
    uint8_t nibble = (r & 0x0F);
    *out = (uint16_t)((nibble << 12) | 0x0a0a | (nibble << 4));
    return VLESS_OK;
}

/* ─── Buffer writer helper ──────────────────────────────────── */

typedef struct { uint8_t *buf; size_t pos; size_t cap; int overflow; } wbuf_t;

static void wb_u8(wbuf_t *w, uint8_t v) {
    if (w->pos + 1 > w->cap) { w->overflow = 1; return; }
    w->buf[w->pos++] = v;
}
static void wb_u16(wbuf_t *w, uint16_t v) {
    if (w->pos + 2 > w->cap) { w->overflow = 1; return; }
    w->buf[w->pos++] = (uint8_t)(v >> 8); w->buf[w->pos++] = (uint8_t)(v & 0xFF);
}
static void wb_bytes(wbuf_t *w, const uint8_t *d, size_t n) {
    if (n == 0) return;
    if (w->pos + n > w->cap) { w->overflow = 1; return; }
    memcpy(w->buf + w->pos, d, n); w->pos += n;
}

/* Write extension header (type + length placeholder), return offset of length field */
static size_t wb_ext_begin(wbuf_t *w, uint16_t type) {
    wb_u16(w, type);
    size_t off = w->pos;
    wb_u16(w, 0); /* placeholder */
    return off;
}

static void wb_ext_end(wbuf_t *w, size_t off) {
    if (w->overflow) return;
    if (w->pos < off + 2) { w->overflow = 1; return; }
    uint16_t len = (uint16_t)(w->pos - off - 2);
    w->buf[off] = (uint8_t)(len >> 8);
    w->buf[off + 1] = (uint8_t)(len & 0xFF);
}

/* Session_id offset in the ClientHello handshake message:
 * byte 0: hs type (1) + bytes 1-3: hs length (3) + bytes 4-5: version (2)
 * + bytes 6-37: random (32) + byte 38: session_id_length (1) = offset 39 */
#define REALITY_SESSION_ID_OFFSET 39
#define REALITY_VERSION_X  26
#define REALITY_VERSION_Y   2
#define REALITY_VERSION_Z   6
#define CH_BUF_SIZE       8192
_Static_assert(CH_BUF_SIZE <= UINT16_MAX,
               "CH_BUF_SIZE must fit in uint16_t for extension length fields");

/* Forward declaration (defined after read_hs_message/consume_hs_message) */
static int transcript_hash_current(vless_reality_ctx_t *r, uint8_t *out);

/* ─── HelloRetryRequest detection (RFC 8446 Section 4.1.3) ── */

static const uint8_t TLS_HRR_RANDOM[32] = {
    0xCF, 0x21, 0xAD, 0x74, 0xE5, 0x9A, 0x61, 0x11,
    0xBE, 0x1D, 0x8C, 0x02, 0x1E, 0x65, 0xB8, 0x91,
    0xC2, 0xA2, 0x11, 0x16, 0x7A, 0xBB, 0x8C, 0x5E,
    0x07, 0x9E, 0x09, 0xE2, 0xC8, 0xA8, 0x33, 0x9C
};

static int is_hello_retry_request(const uint8_t *sh_body, size_t body_len) {
    /* sh_body starts at version(2) + random(32). Random is at offset 2. */
    if (body_len < 2 + 32) return 0;
    return CRYPTO_memcmp(sh_body + 2, TLS_HRR_RANDOM, 32) == 0;
}

/* Parse HRR extensions to find the selected group from key_share ext (0x0033).
 * Also extract cookie extension (0x002c) if present. */
static int parse_hrr_selected_group(const uint8_t *sh_body, size_t body_len,
                                     uint16_t *out_group,
                                     const uint8_t **out_cookie, size_t *out_cookie_len) {
    /* Skip: version(2) + random(32) + session_id_len(1) + session_id + cipher(2) + compression(1) */
    if (body_len < 2 + 32 + 1) return VLESS_ERR_PROTOCOL;

    /* RFC 8446 §4.1.3: legacy_version MUST be 0x0303 */
    uint16_t hrr_version = rd_u16be(sh_body);
    if (hrr_version != TLS_VERSION_12) {
        vless_set_error("HRR legacy_version 0x%04x != 0x0303", hrr_version);
        return VLESS_ERR_PROTOCOL;
    }

    size_t pos = 2 + 32;
    uint8_t sid_len = sh_body[pos++];
    if (sid_len > 32) {
        vless_set_error("Invalid session_id length: %d", sid_len);
        return VLESS_ERR_PROTOCOL;
    }
    pos += sid_len;
    if (pos + 3 > body_len) return VLESS_ERR_PROTOCOL;
    pos += 2; /* cipher_suite */

    /* RFC 8446 §4.1.3: legacy_compression_method MUST be 0 */
    uint8_t hrr_compression = sh_body[pos++];
    if (hrr_compression != 0) {
        vless_set_error("HRR compression 0x%02x != 0", hrr_compression);
        return VLESS_ERR_PROTOCOL;
    }

    if (pos + 2 > body_len) return VLESS_ERR_PROTOCOL;
    uint16_t ext_len = rd_u16be(sh_body + pos);
    pos += 2;
    size_t ext_end = pos + ext_len;
    if (ext_end > body_len) return VLESS_ERR_PROTOCOL;

    *out_group = 0;
    *out_cookie = NULL;
    *out_cookie_len = 0;
    int found_supported_versions = 0;

    while (pos + 4 <= ext_end) {
        uint16_t etype = rd_u16be(sh_body + pos);
        uint16_t elen = rd_u16be(sh_body + pos + 2);
        pos += 4;
        if (pos + elen > ext_end) {
            vless_set_error("HRR extension 0x%04x truncated (need %u, have %zu)",
                            etype, elen, ext_end - pos);
            return VLESS_ERR_PROTOCOL;
        }

        if (etype == 0x002b /* supported_versions */) {
            /* HRR supported_versions: exactly 2 bytes = selected version */
            if (elen != 2) {
                vless_set_error("HRR supported_versions bad length %u (expected 2)", elen);
                return VLESS_ERR_PROTOCOL;
            }
            uint16_t sv = rd_u16be(sh_body + pos);
            if (sv != TLS_VERSION_13) {
                vless_set_error("HRR supported_versions 0x%04x != TLS 1.3", sv);
                return VLESS_ERR_PROTOCOL;
            }
            found_supported_versions = 1;
        } else if (etype == 0x0033 /* key_share / selected_group in HRR */) {
            if (elen >= 2) {
                *out_group = rd_u16be(sh_body + pos);
            }
        } else if (etype == 0x002c /* cookie */) {
            *out_cookie = sh_body + pos;
            *out_cookie_len = elen;
        }
        pos += elen;
    }
    if (pos != ext_end) {
        vless_set_error("HRR extensions: %zu trailing bytes", ext_end - pos);
        return VLESS_ERR_PROTOCOL;
    }
    if (!found_supported_versions) {
        vless_set_error("HRR missing supported_versions extension");
        return VLESS_ERR_PROTOCOL;
    }
    if (*out_group == 0) {
        vless_set_error("HRR missing key_share extension");
        return VLESS_ERR_PROTOCOL;
    }
    return VLESS_OK;
}

/* Replace transcript with message_hash construct (RFC 8446 Section 4.4.1)
 * old_hash_len: the hash length of the transcript BEFORE any cipher param update.
 * When HRR changes hash from SHA-256 to SHA-384, the existing transcript hash
 * (ch1_hash) has only old_hash_len (32) valid bytes, not the new hash_len (48). */
static int transcript_replace_with_message_hash(vless_reality_ctx_t *r, size_t old_hash_len) {
    uint8_t ch1_hash[TLS_HASH_LEN_384];
    if (transcript_hash_current(r, ch1_hash) != VLESS_OK) {
        OPENSSL_cleanse(ch1_hash, sizeof(ch1_hash));
        return VLESS_ERR_CRYPTO;
    }

    /* Re-initialize transcript with the (possibly new) negotiated hash */
    if (!EVP_DigestInit_ex(r->transcript, r->hash_md, NULL)) {
        OPENSSL_cleanse(ch1_hash, sizeof(ch1_hash));
        return VLESS_ERR_CRYPTO;
    }

    /* Feed synthetic message_hash construct:
     * handshake_type = 0xFE (message_hash)
     * length = old hash length (size of ch1_hash data)
     * body = Hash(CH1) using the OLD hash */
    uint8_t synthetic[4 + TLS_HASH_LEN_384];
    synthetic[0] = TLS_HS_MESSAGE_HASH; /* 0xFE */
    synthetic[1] = 0;
    synthetic[2] = 0;
    synthetic[3] = (uint8_t)old_hash_len;
    memcpy(synthetic + 4, ch1_hash, (size_t)old_hash_len);
    if (!EVP_DigestUpdate(r->transcript, synthetic, 4 + (size_t)old_hash_len)) {
        OPENSSL_cleanse(ch1_hash, sizeof(ch1_hash));
        OPENSSL_cleanse(synthetic, sizeof(synthetic));
        return VLESS_ERR_CRYPTO;
    }

    OPENSSL_cleanse(ch1_hash, sizeof(ch1_hash));
    OPENSSL_cleanse(synthetic, sizeof(synthetic));
    return VLESS_OK;
}

/* ─── Cipher suite parameter helper ─────────────────────────── */

/* Set hash_len, key_len, hash_md, and aead_cipher on the context
 * based on the negotiated TLS 1.3 cipher suite. */
static void set_cipher_params(vless_reality_ctx_t *r, uint16_t cipher_suite) {
    r->cipher_suite = cipher_suite;
    if (cipher_suite == TLS_AES_256_GCM_SHA384) {
        r->hash_len = TLS_HASH_LEN_384;
        r->key_len = TLS_GCM_KEY_LEN_256;
        r->hash_md = EVP_sha384();
        r->aead_cipher = EVP_aes_256_gcm();
    } else if (cipher_suite == TLS_CHACHA20_POLY1305_SHA256) {
        r->hash_len = TLS_HASH_LEN_256;
        r->key_len = TLS_GCM_KEY_LEN_256;
        r->hash_md = EVP_sha256();
#ifdef OPENSSL_IS_BORINGSSL
        /* BoringSSL doesn't expose ChaCha20-Poly1305 via EVP_CIPHER API.
         * Set NULL — caller checks and returns VLESS_ERR_CRYPTO. */
        r->aead_cipher = NULL;
#else
        r->aead_cipher = EVP_chacha20_poly1305();
#endif
    } else {
        r->cipher_suite = TLS_AES_128_GCM_SHA256;
        r->hash_len = TLS_HASH_LEN_256;
        r->key_len = TLS_GCM_KEY_LEN_128;
        r->hash_md = EVP_sha256();
        r->aead_cipher = EVP_aes_128_gcm();
    }
}

/* ─── Chrome fingerprint profiles ───────────────────────────── */
/*
 * Last updated: 2026-03. Profiles verified against:
 *   Chrome 120.0.6099 (Dec 2023), Chrome 124.0.6367 (Apr 2024),
 *   Chrome 131.0.6778 (Nov 2024).
 * When new Chrome versions change the fingerprint (new extensions,
 * cipher order, ALPS code points), add a new profile here and update
 * VLESS_CHROME_AUTO to point to it.
 */

/* Chrome 120 (Dec 2023): no MLKEM, no delegated_credentials, no record_size_limit,
 * 8 sigalgs (no SHA-1 wrappers), ALPS 0x4469 */
static const uint16_t chrome120_ciphers[] = {
    0x1301, 0x1302, 0x1303,
    0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8,
    0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035
};
static const uint16_t chrome120_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503,
    0x0805, 0x0501, 0x0806, 0x0601
};
static const uint16_t chrome120_groups[] = {
    0x001d, /* X25519 */
    0x0017, /* P-256 */
    0x0018, /* P-384 */
};
static const chrome_profile_t CHROME_120 = {
    .ciphers = chrome120_ciphers,
    .num_ciphers = sizeof(chrome120_ciphers) / sizeof(chrome120_ciphers[0]),
    .sigalgs = chrome120_sigalgs,
    .num_sigalgs = sizeof(chrome120_sigalgs) / sizeof(chrome120_sigalgs[0]),
    .groups = chrome120_groups,
    .num_groups = sizeof(chrome120_groups) / sizeof(chrome120_groups[0]),
    .alps_ext_type = 0x4469,
    .has_ech_grease = 1,
    .has_mlkem = 0,
    .has_delegated_credentials = 0,
    .dc_sigalgs = NULL,
    .num_dc_sigalgs = 0,
    .has_record_size_limit = 0,
};

/* Delegated credentials sigalgs (Chrome 124+): ECDSA + RSA-PSS only.
 * Delegated credentials do NOT support PKCS1 or SHA-1 signature schemes,
 * so this list is a strict subset of the full signature_algorithms list. */
static const uint16_t chrome_dc_sigalgs[] = {
    0x0403, /* ecdsa_secp256r1_sha256 */
    0x0503, /* ecdsa_secp384r1_sha384 */
    0x0603, /* ecdsa_secp521r1_sha512 */
    0x0804, /* rsa_pss_rsae_sha256 */
    0x0805, /* rsa_pss_rsae_sha384 */
    0x0806, /* rsa_pss_rsae_sha512 */
};

/* Chrome 124 (Apr 2024): first with MLKEM, adds delegated_credentials + record_size_limit,
 * 10 sigalgs (adds SHA-1: 0x0203, 0x0201), ALPS 0x4469 */
static const uint16_t chrome124_ciphers[] = {
    0x1301, 0x1302, 0x1303,
    0xc02b, 0xc02f, 0xc02c, 0xc030,
    0xcca9, 0xcca8,
    0xc013, 0xc014,
    0x009c, 0x009d,
    0x002f, 0x0035
};
static const uint16_t chrome124_sigalgs[] = {
    0x0403, 0x0804, 0x0401, 0x0503,
    0x0805, 0x0501, 0x0806, 0x0601,
    0x0203, 0x0201
};
static const uint16_t chrome124_groups[] = {
    TLS_X25519MLKEM768, /* X25519MLKEM768 */
    0x001d, /* X25519 */
    0x0017, /* P-256 */
    0x0018, /* P-384 */
};
static const chrome_profile_t CHROME_124 = {
    .ciphers = chrome124_ciphers,
    .num_ciphers = sizeof(chrome124_ciphers) / sizeof(chrome124_ciphers[0]),
    .sigalgs = chrome124_sigalgs,
    .num_sigalgs = sizeof(chrome124_sigalgs) / sizeof(chrome124_sigalgs[0]),
    .groups = chrome124_groups,
    .num_groups = sizeof(chrome124_groups) / sizeof(chrome124_groups[0]),
    .alps_ext_type = 0x4469,
    .has_ech_grease = 1,
    .has_mlkem = 1,
    .has_delegated_credentials = 1,
    .dc_sigalgs = chrome_dc_sigalgs,
    .num_dc_sigalgs = sizeof(chrome_dc_sigalgs) / sizeof(chrome_dc_sigalgs[0]),
    .has_record_size_limit = 1,
};

/* Chrome 131 (Nov 2024): identical ciphers/sigalgs/groups as 124, only ALPS code point differs */
static const chrome_profile_t CHROME_131 = {
    .ciphers = chrome124_ciphers,
    .num_ciphers = sizeof(chrome124_ciphers) / sizeof(chrome124_ciphers[0]),
    .sigalgs = chrome124_sigalgs,
    .num_sigalgs = sizeof(chrome124_sigalgs) / sizeof(chrome124_sigalgs[0]),
    .groups = chrome124_groups,
    .num_groups = sizeof(chrome124_groups) / sizeof(chrome124_groups[0]),
    .alps_ext_type = 0x4588,
    .has_ech_grease = 1,
    .has_mlkem = 1,
    .has_delegated_credentials = 1,
    .dc_sigalgs = chrome_dc_sigalgs,
    .num_dc_sigalgs = sizeof(chrome_dc_sigalgs) / sizeof(chrome_dc_sigalgs[0]),
    .has_record_size_limit = 1,
};

/* Look up chrome profile from fingerprint enum */
static const chrome_profile_t *chrome_profile_for(vless_chrome_fingerprint_t fp) {
    switch (fp) {
    case VLESS_CHROME_120: return &CHROME_120;
    case VLESS_CHROME_124: return &CHROME_124;
    case VLESS_CHROME_131: return &CHROME_131;
    case VLESS_CHROME_AUTO:
    default:               return &CHROME_131; /* latest */
    }
}

/* ─── Build Chrome-fingerprinted ClientHello ────────────────── */

/*
 * hrr_selected_group: when non-zero, this is a retry after HRR.
 * Only include the selected group in key_share, reuse saved client_random/session_id.
 * hrr_cookie/hrr_cookie_len: cookie from HRR to include in retry CH.
 */
static int build_client_hello(vless_reality_ctx_t *r,
                               const char *server_name,
                               uint16_t hrr_selected_group,
                               const uint8_t *hrr_cookie, size_t hrr_cookie_len,
                               uint8_t *out, size_t out_cap, size_t *out_len) {
    wbuf_t w = { .buf = out, .pos = 0, .cap = out_cap, .overflow = 0 };

    /* Generate 5 independent GREASE values + 1 shared.
     * Chrome draws each GREASE value independently from the 16-value set;
     * collisions are natural (~1/16) and expected.
     *
     * EXCEPTION: grease_keyshare MUST equal grease_groups.  RFC 8446 §4.2.8
     * requires every key_share group to appear in supported_groups.  Real
     * Chrome (BoringSSL) reuses the same GREASE value for both.  Microsoft
     * SChannel enforces this strictly and sends illegal_parameter (47) if
     * the key_share GREASE is not present in supported_groups. */
    uint16_t grease_ciphers, grease_ext_first, grease_groups, grease_keyshare,
             grease_versions, grease_ext_last;
    int grc;
    if ((grc = grease_value(&grease_ciphers)) != VLESS_OK) return grc;
    if ((grc = grease_value(&grease_ext_first)) != VLESS_OK) return grc;
    if ((grc = grease_value(&grease_groups)) != VLESS_OK) return grc;
    grease_keyshare = grease_groups;  /* must match for RFC 8446 compliance */
    if ((grc = grease_value(&grease_versions)) != VLESS_OK) return grc;
    if ((grc = grease_value(&grease_ext_last)) != VLESS_OK) return grc;

    /* === Handshake header (filled later) === */
    size_t hs_start = w.pos;
    wb_u8(&w, TLS_HS_CLIENT_HELLO); /* handshake type */
    size_t hs_len_off = w.pos;
    wb_u8(&w, 0); wb_u8(&w, 0); wb_u8(&w, 0); /* 3-byte length placeholder */

    /* === ClientHello body === */
    size_t body_start = w.pos;

    /* client_version: TLS 1.2 (real version in supported_versions extension) */
    wb_u16(&w, TLS_VERSION_12);

    /* client_random: generate once and reuse on HRR retry per RFC 8446 §4.1.2.
     * Real Chrome reuses client_random on HRR, so we must do the same to
     * avoid fingerprinting. AES-GCM nonce reuse in REALITY auth is avoided
     * by regenerating the X25519 ephemeral key before each HRR retry (done
     * by the caller), which produces a different REALITY auth_key even with
     * the same client_random-derived nonce. */
    if (hrr_selected_group == 0) {
        /* First ClientHello: generate fresh client_random */
        if (RAND_bytes(r->client_random, 32) != 1) return VLESS_ERR_CRYPTO;
    }
    /* On HRR retry (hrr_selected_group != 0): reuse saved r->client_random */
    wb_bytes(&w, r->client_random, 32);

    /* session_id: 32 zero bytes (REALITY auth is computed after
     * build_client_hello returns; the caller encrypts the session_id
     * in-place using the raw ClientHello bytes as AES-256-GCM AAD) */
    wb_u8(&w, 32); /* session_id length */
    {
        uint8_t zeros_sid[32] = {0};
        wb_bytes(&w, zeros_sid, 32);
    }

    /* cipher_suites (from profile, GREASE prepended) */
    const chrome_profile_t *profile = r->profile ? r->profile : &CHROME_131;
    int nciphers = 1 + profile->num_ciphers; /* 1 for GREASE */
    wb_u16(&w, (uint16_t)(nciphers * 2));
    wb_u16(&w, grease_ciphers); /* first entry is GREASE */
    for (int i = 0; i < profile->num_ciphers; i++) wb_u16(&w, profile->ciphers[i]);

    /* compression_methods: null only */
    wb_u8(&w, 1); wb_u8(&w, 0);

    /* === Extensions (with Chrome 110+ order shuffling) === */
    size_t ext_total_off = w.pos;
    wb_u16(&w, 0); /* extensions length placeholder */
    size_t ext_start = w.pos;

    /*
     * Extension writing via index-based dispatch.
     * Chrome 110+ shuffles extension order on each connection.
     * Fixed positions: GREASE first (#0), SNI second (#1),
     * GREASE+padding last (#20, #21).
     * Extensions #2..#19 are shuffled (Fisher-Yates), but some are
     * conditionally included based on profile and HRR state.
     */
    size_t sni_len = strlen(server_name);
    if (sni_len == 0 || sni_len > 255) {
        vless_set_error("SNI length invalid: %zu (must be 1-255 per RFC 6066)", sni_len);
        return VLESS_ERR_INVALID_ARG;
    }

    /* Build list of shuffleable extension indices based on profile.
     * Cases 2..14 are always included; 15 (ALPS) always; 16..18 conditional.
     * Case 19 (cookie) is included only on HRR retry — Chrome shuffles the
     * cookie extension together with the other non-fixed extensions. */
    int ext_order[18]; /* max 18 shuffleable extensions (17 base + cookie) */
    int num_shuffle = 0;
    for (int i = 2; i <= 15; i++) ext_order[num_shuffle++] = i;
    if (profile->has_ech_grease)            ext_order[num_shuffle++] = 16;
    if (profile->has_delegated_credentials) ext_order[num_shuffle++] = 17;
    if (profile->has_record_size_limit)     ext_order[num_shuffle++] = 18;
    if (hrr_cookie && hrr_cookie_len > 0)   ext_order[num_shuffle++] = 19;

    /* Fisher-Yates shuffle with rejection sampling to avoid modulo bias.
     * Iteration limit prevents infinite loop if CSPRNG malfunctions. */
    for (int i = num_shuffle - 1; i > 0; i--) {
        uint8_t rb;
        int limit = 256 - (256 % (i + 1)); /* rejection threshold */
        int attempts = 0;
        do {
            if (RAND_bytes(&rb, 1) != 1) return VLESS_ERR_CRYPTO;
            if (++attempts > 100) return VLESS_ERR_CRYPTO; /* CSPRNG stuck */
        } while (rb >= limit);
        int j = rb % (i + 1);
        int tmp = ext_order[i];
        ext_order[i] = ext_order[j];
        ext_order[j] = tmp;
    }

    /* Write fixed first: GREASE, SNI */
    /* ext 0: GREASE extension (independent value from cipher GREASE) */
    { size_t o = wb_ext_begin(&w, grease_ext_first); wb_u8(&w, 0); wb_ext_end(&w, o); }

    /* ext 1: server_name (SNI) — stays near top */
    {
        size_t o = wb_ext_begin(&w, 0x0000);
        wb_u16(&w, (uint16_t)(sni_len + 3)); /* list content: type(1) + name_len(2) + name */
        wb_u8(&w, 0);
        wb_u16(&w, (uint16_t)sni_len);
        wb_bytes(&w, (const uint8_t *)server_name, sni_len);
        wb_ext_end(&w, o);
    }

    /* Write shuffled middle extensions */
    for (int idx = 0; idx < num_shuffle; idx++) {
        switch (ext_order[idx]) {
        case 2: /* extended_master_secret */
            { size_t o = wb_ext_begin(&w, 0x0017); wb_ext_end(&w, o); }
            break;
        case 3: /* renegotiation_info */
            { size_t o = wb_ext_begin(&w, 0xff01); wb_u8(&w, 0); wb_ext_end(&w, o); }
            break;
        case 4: /* supported_groups (from profile, GREASE prepended) */
            {
                size_t o = wb_ext_begin(&w, 0x000a);
                /* Skip X25519MLKEM768 from the group list when MLKEM is not
                 * available (e.g. BoringSSL).  Advertising MLKEM in
                 * supported_groups without a corresponding key_share entry
                 * is a detectable fingerprint deviation from real Chrome. */
                int skip_mlkem = !(r->mlkem_available && r->mlkem_key);
                int ngroups = 1; /* GREASE */
                for (int gi = 0; gi < profile->num_groups; gi++) {
                    if (skip_mlkem && profile->groups[gi] == TLS_X25519MLKEM768)
                        continue;
                    ngroups++;
                }
                wb_u16(&w, (uint16_t)(ngroups * 2));
                wb_u16(&w, grease_groups);
                for (int gi = 0; gi < profile->num_groups; gi++) {
                    if (skip_mlkem && profile->groups[gi] == TLS_X25519MLKEM768)
                        continue;
                    wb_u16(&w, profile->groups[gi]);
                }
                wb_ext_end(&w, o);
            }
            break;
        case 5: /* ec_point_formats */
            {
                size_t o = wb_ext_begin(&w, 0x000b);
                wb_u8(&w, 1); wb_u8(&w, 0);
                wb_ext_end(&w, o);
            }
            break;
        case 6: /* session_ticket (empty) */
            { size_t o = wb_ext_begin(&w, 0x0023); wb_ext_end(&w, o); }
            break;
        case 7: /* ALPN [h2, http/1.1] */
            {
                size_t o = wb_ext_begin(&w, 0x0010);
                wb_u16(&w, 12);
                wb_u8(&w, 2); wb_bytes(&w, (const uint8_t *)"h2", 2);
                wb_u8(&w, 8); wb_bytes(&w, (const uint8_t *)"http/1.1", 8);
                wb_ext_end(&w, o);
            }
            break;
        case 8: /* status_request (OCSP) */
            {
                size_t o = wb_ext_begin(&w, 0x0005);
                wb_u8(&w, 1);
                wb_u16(&w, 0);
                wb_u16(&w, 0);
                wb_ext_end(&w, o);
            }
            break;
        case 9: /* signature_algorithms (from profile) */
            {
                size_t o = wb_ext_begin(&w, 0x000d);
                wb_u16(&w, (uint16_t)(profile->num_sigalgs * 2));
                for (int si = 0; si < profile->num_sigalgs; si++)
                    wb_u16(&w, profile->sigalgs[si]);
                wb_ext_end(&w, o);
            }
            break;
        case 10: /* signed_certificate_timestamp (empty) */
            { size_t o = wb_ext_begin(&w, 0x0012); wb_ext_end(&w, o); }
            break;
        case 11: /* key_share [GREASE + X25519MLKEM768(if avail) + X25519] */
            {
                size_t o = wb_ext_begin(&w, 0x0033);
                if (hrr_selected_group != 0) {
                    /* HRR retry: only include the group the server selected */
#ifndef OPENSSL_IS_BORINGSSL
                    if (hrr_selected_group == TLS_X25519MLKEM768 && r->mlkem_available && r->mlkem_key) {
                        size_t mlkem_e = 2 + 2 + MLKEM768_EK_LEN + 32;
                        wb_u16(&w, (uint16_t)mlkem_e);
                        uint8_t mlkem_ek[MLKEM768_EK_LEN];
                        size_t ek_len = MLKEM768_EK_LEN;
                        if (!EVP_PKEY_get_octet_string_param(r->mlkem_key,
                                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                mlkem_ek, sizeof(mlkem_ek), &ek_len) ||
                            ek_len != MLKEM768_EK_LEN) {
                            OPENSSL_cleanse(mlkem_ek, sizeof(mlkem_ek));
                            vless_set_error("Failed to extract MLKEM encapsulation key (HRR)");
                            return VLESS_ERR_CRYPTO;
                        }
                        wb_u16(&w, TLS_X25519MLKEM768);
                        wb_u16(&w, (uint16_t)(MLKEM768_EK_LEN + 32));
                        wb_bytes(&w, mlkem_ek, MLKEM768_EK_LEN);
                        wb_bytes(&w, r->mlkem_eph_public, 32);
                        OPENSSL_cleanse(mlkem_ek, sizeof(mlkem_ek));
                    } else
#endif
                    if (hrr_selected_group == 0x0017) {
                        /* P-256: generate key pair and write uncompressed point */
                        if (!ecdh_generate(NID_X9_62_prime256v1,
                                           r->ecdh_p256_pub, &r->ecdh_p256_pub_len,
                                           &r->ecdh_p256_key)) {
                            vless_set_error("P-256 ECDH key generation failed (HRR)");
                            return VLESS_ERR_CRYPTO;
                        }
                        size_t entry_len = 2 + 2 + r->ecdh_p256_pub_len;
                        wb_u16(&w, (uint16_t)entry_len);
                        wb_u16(&w, 0x0017);
                        wb_u16(&w, (uint16_t)r->ecdh_p256_pub_len);
                        wb_bytes(&w, r->ecdh_p256_pub, r->ecdh_p256_pub_len);
                    } else if (hrr_selected_group == 0x0018) {
                        /* P-384: generate key pair and write uncompressed point */
                        if (!ecdh_generate(NID_secp384r1,
                                           r->ecdh_p384_pub, &r->ecdh_p384_pub_len,
                                           &r->ecdh_p384_key)) {
                            vless_set_error("P-384 ECDH key generation failed (HRR)");
                            return VLESS_ERR_CRYPTO;
                        }
                        size_t entry_len = 2 + 2 + r->ecdh_p384_pub_len;
                        wb_u16(&w, (uint16_t)entry_len);
                        wb_u16(&w, 0x0018);
                        wb_u16(&w, (uint16_t)r->ecdh_p384_pub_len);
                        wb_bytes(&w, r->ecdh_p384_pub, r->ecdh_p384_pub_len);
                    } else {
                        /* Plain X25519 */
                        wb_u16(&w, 36); /* group(2)+len(2)+key(32) */
                        wb_u16(&w, 0x001d); wb_u16(&w, 32);
                        wb_bytes(&w, r->eph_public, 32);
                    }
                } else {
                    /* Normal CH: GREASE + optional MLKEM + X25519 */
#ifndef OPENSSL_IS_BORINGSSL
                    int use_mlkem = profile->has_mlkem && r->mlkem_available && r->mlkem_key != NULL;
#else
                    int use_mlkem = 0;
#endif
                    size_t grease_entry = 5;     /* group(2) + len(2) + data(1) */
                    size_t x25519_entry = 36;    /* group(2) + len(2) + key(32) */
                    size_t mlkem_entry = use_mlkem
                        ? (2 + 2 + MLKEM768_EK_LEN + 32) : 0;
                    wb_u16(&w, (uint16_t)(grease_entry + mlkem_entry + x25519_entry));
                    /* 1. GREASE entry */
                    wb_u16(&w, grease_keyshare); wb_u16(&w, 1); wb_u8(&w, 0);
                    /* 2. X25519MLKEM768 entry (if available and profile supports it) */
#ifndef OPENSSL_IS_BORINGSSL
                    if (use_mlkem) {
                        uint8_t mlkem_ek[MLKEM768_EK_LEN];
                        size_t ek_len = MLKEM768_EK_LEN;
                        if (!EVP_PKEY_get_octet_string_param(r->mlkem_key,
                                OSSL_PKEY_PARAM_ENCODED_PUBLIC_KEY,
                                mlkem_ek, sizeof(mlkem_ek), &ek_len) ||
                            ek_len != MLKEM768_EK_LEN) {
                            OPENSSL_cleanse(mlkem_ek, sizeof(mlkem_ek));
                            vless_set_error("Failed to extract MLKEM encapsulation key");
                            return VLESS_ERR_CRYPTO;
                        }
                        wb_u16(&w, TLS_X25519MLKEM768);
                        wb_u16(&w, (uint16_t)(MLKEM768_EK_LEN + 32));
                        wb_bytes(&w, mlkem_ek, MLKEM768_EK_LEN);
                        wb_bytes(&w, r->mlkem_eph_public, 32);
                        OPENSSL_cleanse(mlkem_ek, sizeof(mlkem_ek));
                    }
#endif
                    /* 3. X25519 entry */
                    wb_u16(&w, 0x001d); wb_u16(&w, 32);
                    wb_bytes(&w, r->eph_public, 32);
                }
                wb_ext_end(&w, o);
            }
            break;
        case 12: /* psk_key_exchange_modes */
            {
                size_t o = wb_ext_begin(&w, 0x002d);
                wb_u8(&w, 1); wb_u8(&w, 1);
                wb_ext_end(&w, o);
            }
            break;
        case 13: /* supported_versions [GREASE, TLS 1.3, TLS 1.2] */
            {
                size_t o = wb_ext_begin(&w, 0x002b);
                wb_u8(&w, 6); /* list length: 3 versions x 2 bytes */
                wb_u16(&w, grease_versions);
                wb_u16(&w, TLS_VERSION_13);
                wb_u16(&w, TLS_VERSION_12);
                wb_ext_end(&w, o);
            }
            break;
        case 14: /* compress_certificate [brotli] */
            {
                size_t o = wb_ext_begin(&w, 0x001b);
                wb_u8(&w, 2);
                wb_u16(&w, 0x0002);
                wb_ext_end(&w, o);
            }
            break;
        case 15: /* application_settings (ALPS) [h2] — type from profile */
            {
                size_t o = wb_ext_begin(&w, profile->alps_ext_type);
                wb_u16(&w, 3); /* protocol list length */
                wb_u8(&w, 2); wb_bytes(&w, (const uint8_t *)"h2", 2);
                wb_ext_end(&w, o);
            }
            break;
        case 16: /* encrypted_client_hello (ECH GREASE) — Chrome 117+ */
            {
                size_t o = wb_ext_begin(&w, 0xfe0d);
                wb_u8(&w, 0);       /* type: outer */
                wb_u16(&w, 0x0001); /* kdf_id: HKDF-SHA256 */
                wb_u16(&w, 0x0001); /* aead_id: AES-128-GCM */
                uint8_t config_id;
                if (RAND_bytes(&config_id, 1) != 1) return VLESS_ERR_CRYPTO;
                wb_u8(&w, config_id);
                wb_u16(&w, 32); /* enc length (X25519 KEM) */
                uint8_t ech_enc[32];
                if (RAND_bytes(ech_enc, 32) != 1) return VLESS_ERR_CRYPTO;
                wb_bytes(&w, ech_enc, 32);
                /* Payload: Chrome dynamically sizes ECH GREASE payload to
                 * reach specific total CH sizes. Without MLKEM the CH is
                 * around 450-480 bytes; Chrome targets 512. With MLKEM the
                 * CH is much larger and ECH payload stays at a small default.
                 * We compute the payload length to reach a ~512 byte CH,
                 * clamped to [32, 224]. This avoids the fixed-128-byte
                 * fingerprint that distinguishes us from real Chrome. */
                /* Overhead AFTER the extension header (already counted in w.pos):
                 * type(1) + kdf(2) + aead(2) + cfg_id(1) + enc_len(2) + enc(32) + payload_len(2) */
                size_t ech_hdr_overhead = 1 + 2 + 2 + 1 + 2 + 32 + 2;
                size_t current_msg = w.pos - hs_start + ech_hdr_overhead;
                uint16_t payload_len;
                if (current_msg < 480) {
                    /* Target: CH msg = 512 bytes, minus what we have so far */
                    size_t target_pad = 512 - current_msg;
                    if (target_pad < 32) target_pad = 32;
                    if (target_pad > 224) target_pad = 224;
                    payload_len = (uint16_t)target_pad;
                } else {
                    /* Large CH (MLKEM present): Chrome 124+ uses ~128 bytes
                     * of ECH GREASE payload. Using 32 was detectable by DPI
                     * correlating small ECH payload with MLKEM in key_share. */
                    payload_len = 128;
                }
                wb_u16(&w, payload_len);
                uint8_t ech_payload[224];
                if (RAND_bytes(ech_payload, (int)payload_len) != 1)
                    return VLESS_ERR_CRYPTO;
                wb_bytes(&w, ech_payload, payload_len);
                wb_ext_end(&w, o);
            }
            break;
        case 17: /* delegated_credentials (0x0022) — uses dc_sigalgs
                  * (ECDSA + RSA-PSS only, no PKCS1/SHA-1 per Chrome) */
            {
                const uint16_t *dc_sa = profile->dc_sigalgs;
                int dc_n = profile->num_dc_sigalgs;
                size_t o = wb_ext_begin(&w, 0x0022);
                wb_u16(&w, (uint16_t)(dc_n * 2));
                for (int si = 0; si < dc_n; si++)
                    wb_u16(&w, dc_sa[si]);
                wb_ext_end(&w, o);
            }
            break;
        case 18: /* record_size_limit (0x001c) */
            {
                size_t o = wb_ext_begin(&w, 0x001c);
                wb_u16(&w, 16385); /* 2^14 + 1 */
                wb_ext_end(&w, o);
            }
            break;
        case 19: /* cookie from HRR (0x002c) — shuffled with other extensions
                  * to match real Chrome behavior (added to ext_order only when
                  * hrr_cookie is non-NULL, so this case is never reached on
                  * initial ClientHello). */
            {
                size_t o = wb_ext_begin(&w, 0x002c);
                wb_u16(&w, (uint16_t)hrr_cookie_len);
                wb_bytes(&w, hrr_cookie, hrr_cookie_len);
                wb_ext_end(&w, o);
            }
            break;
        }
    }

    /* Fixed last: GREASE (separate value from supported_versions), then padding */
    { size_t o = wb_ext_begin(&w, grease_ext_last); wb_u8(&w, 0); wb_ext_end(&w, o); }

    /* padding — pad to make the handshake message a target size, matching
     * real Chrome. The target is 512 bytes for initial CH, but when a cookie
     * extension is present (HRR retry), account for its size. When MLKEM is
     * included, key_share alone is ~1220 bytes, so the CH exceeds the target
     * and no padding is needed (matches Chrome behavior). */
    {
        size_t hs_msg_len = w.pos - hs_start; /* handshake message size */
        size_t pad_target = 512;
        /* If HRR cookie pushed us past 512, use the next 256-aligned target
         * so the retry CH has a plausible padded size rather than unpadded */
        if (hrr_cookie && hrr_cookie_len > 0 && hs_msg_len > pad_target && hs_msg_len < 768) {
            pad_target = (hs_msg_len + 255) & ~(size_t)255; /* round up to 256 boundary */
        }
        if (hs_msg_len < pad_target) {
            size_t pad_total = pad_target - hs_msg_len;
            if (pad_total >= 4) {
                size_t pad_needed = pad_total - 4; /* subtract ext header */
                size_t o = wb_ext_begin(&w, 0x0015);
                if (w.pos + pad_needed <= w.cap) {
                    memset(w.buf + w.pos, 0, pad_needed);
                    w.pos += pad_needed;
                } else {
                    w.overflow = 1;
                }
                wb_ext_end(&w, o);
            }
        }
    }

    /* Check for buffer overflow before writing back lengths */
    if (w.overflow) {
        vless_set_error("ClientHello buffer overflow");
        return VLESS_ERR_NOMEM;
    }

    /* Fill extensions length */
    {
        uint16_t ext_len = (uint16_t)(w.pos - ext_start);
        w.buf[ext_total_off] = (uint8_t)(ext_len >> 8);
        w.buf[ext_total_off + 1] = (uint8_t)(ext_len & 0xFF);
    }

    /* Fill handshake length (3 bytes) */
    {
        uint32_t hs_len = (uint32_t)(w.pos - body_start);
        w.buf[hs_len_off + 0] = (uint8_t)(hs_len >> 16);
        w.buf[hs_len_off + 1] = (uint8_t)(hs_len >> 8);
        w.buf[hs_len_off + 2] = (uint8_t)(hs_len);
    }

    *out_len = w.pos;
    return VLESS_OK;
}

/* ─── Parse ServerHello, extract cipher suite and key_share ──────── */

/*
 * Parse ServerHello extensions, returning the key_share group and data.
 * For X25519 (0x001d): ks_data = 32-byte server public key
 * For X25519MLKEM768 (0x6399): ks_data = MLKEM768_CT_LEN + 32 bytes
 */
static int parse_server_hello(const uint8_t *data, size_t len,
                               uint8_t *ks_data, size_t ks_data_cap,
                               size_t *ks_data_len,
                               uint16_t *out_ks_group,
                               uint16_t *out_cipher) {
    /*
     * ServerHello format (after handshake type+length):
     *   ProtocolVersion (2) + random (32) + session_id_len (1) + session_id
     *   + cipher_suite (2) + compression (1) + extensions_len (2) + extensions
     */
    if (len < 2 + 32 + 1) return VLESS_ERR_PROTOCOL;

    /* RFC 8446 §4.1.3: legacy_version MUST be 0x0303 (TLS 1.2) */
    uint16_t sh_version = rd_u16be(data);
    if (sh_version != TLS_VERSION_12) {
        vless_set_error("ServerHello legacy_version 0x%04x != 0x0303", sh_version);
        return VLESS_ERR_PROTOCOL;
    }

    size_t pos = 2 + 32; /* skip version + random */

    uint8_t sid_len = data[pos++];
    if (sid_len > 32) {
        vless_set_error("Invalid session_id length: %d", sid_len);
        return VLESS_ERR_PROTOCOL;
    }
    pos += sid_len;
    if (pos + 3 > len) return VLESS_ERR_PROTOCOL;

    /* Read cipher suite */
    uint16_t cipher = rd_u16be(data + pos);

    /* Validate cipher suite -- we support AES-128-GCM, AES-256-GCM, and ChaCha20-Poly1305 */
    if (cipher != TLS_AES_128_GCM_SHA256 &&
        cipher != TLS_AES_256_GCM_SHA384 &&
        cipher != TLS_CHACHA20_POLY1305_SHA256) {
        vless_set_error("Unsupported cipher suite 0x%04x (need 0x1301, 0x1302, or 0x1303)", cipher);
        return VLESS_ERR_PROTOCOL;
    }

    *out_cipher = cipher;
    pos += 2; /* cipher_suite */

    /* RFC 8446 §4.1.3: legacy_compression_method MUST be 0 (null) */
    uint8_t compression = data[pos++];
    if (compression != 0) {
        vless_set_error("ServerHello compression 0x%02x != 0 (TLS 1.3 requires null)", compression);
        return VLESS_ERR_PROTOCOL;
    }

    if (pos + 2 > len) return VLESS_ERR_PROTOCOL;
    uint16_t ext_len = rd_u16be(data + pos);
    pos += 2;

    size_t ext_end = pos + ext_len;
    if (ext_end > len) return VLESS_ERR_PROTOCOL;

    int found_ks = 0;
    int found_supported_versions = 0;
    while (pos + 4 <= ext_end) {
        uint16_t etype = rd_u16be(data + pos);
        uint16_t elen = rd_u16be(data + pos + 2);
        pos += 4;
        if (pos + elen > ext_end) {
            vless_set_error("ServerHello extension 0x%04x truncated (need %u, have %zu)",
                            etype, elen, ext_end - pos);
            return VLESS_ERR_PROTOCOL;
        }

        if (etype == 0x002b /* supported_versions */) {
            /* ServerHello supported_versions: exactly 2 bytes = selected version */
            if (elen != 2) {
                vless_set_error("ServerHello supported_versions bad length %u (expected 2)", elen);
                return VLESS_ERR_PROTOCOL;
            }
            uint16_t sv = rd_u16be(data + pos);
            if (sv != TLS_VERSION_13) {
                vless_set_error("ServerHello supported_versions 0x%04x != TLS 1.3", sv);
                return VLESS_ERR_PROTOCOL;
            }
            found_supported_versions = 1;
        } else if (etype == 0x0033 /* key_share */) {
            /* ServerHello key_share: NamedGroup(2) + key_len(2) + key_data */
            if (elen >= 4) {
                uint16_t group = rd_u16be(data + pos);
                uint16_t klen = rd_u16be(data + pos + 2);

                if (group == 0x001d && klen == 32 && elen >= 4 + 32) {
                    /* Plain X25519 */
                    if (ks_data_cap >= 32) {
                        memcpy(ks_data, data + pos + 4, 32);
                        *ks_data_len = 32;
                        *out_ks_group = 0x001d;
                        found_ks = 1;
                    }
                } else if (group == TLS_X25519MLKEM768 &&
                           klen == MLKEM768_CT_LEN + 32 &&
                           elen >= 4 + MLKEM768_CT_LEN + 32) {
                    /* X25519MLKEM768 hybrid: mlkem_ct(1088) + x25519_pub(32) */
                    size_t total = MLKEM768_CT_LEN + 32;
                    if (ks_data_cap >= total) {
                        memcpy(ks_data, data + pos + 4, total);
                        *ks_data_len = total;
                        *out_ks_group = TLS_X25519MLKEM768;
                        found_ks = 1;
                    }
                } else if (group == 0x0017 && klen == 65 && elen >= 4 + 65) {
                    /* P-256: uncompressed point (65 bytes, must start with 0x04) */
                    if (ks_data_cap >= 65 && data[pos + 4] == 0x04) {
                        memcpy(ks_data, data + pos + 4, 65);
                        *ks_data_len = 65;
                        *out_ks_group = 0x0017;
                        found_ks = 1;
                    }
                } else if (group == 0x0018 && klen == 97 && elen >= 4 + 97) {
                    /* P-384: uncompressed point (97 bytes, must start with 0x04) */
                    if (ks_data_cap >= 97 && data[pos + 4] == 0x04) {
                        memcpy(ks_data, data + pos + 4, 97);
                        *ks_data_len = 97;
                        *out_ks_group = 0x0018;
                        found_ks = 1;
                    }
                }
            }
        } else if (etype != 0x0029 /* pre_shared_key */) {
            /* RFC 8446 §4.3.1: ServerHello may only contain supported_versions,
             * key_share, and pre_shared_key extensions. Reject anything else. */
            vless_set_error("ServerHello: unknown extension type 0x%04x", etype);
            return VLESS_ERR_PROTOCOL;
        }
        pos += elen;
    }

    if (pos != ext_end) {
        vless_set_error("ServerHello extensions: %zu trailing bytes", ext_end - pos);
        return VLESS_ERR_PROTOCOL;
    }
    if (!found_supported_versions) {
        vless_set_error("ServerHello missing supported_versions extension");
        return VLESS_ERR_PROTOCOL;
    }
    if (!found_ks) {
        vless_set_error("ServerHello missing supported key_share");
        return VLESS_ERR_PROTOCOL;
    }
    return VLESS_OK;
}

/* ─── Read handshake messages from encrypted records ────────── */

/*
 * Reads encrypted records until we have a complete handshake message.
 * Handles message reassembly across record boundaries.
 * Returns the handshake message type and body in hs_buf.
 */
static int read_hs_message(vless_reality_ctx_t *r,
                            uint8_t *hs_type,
                            const uint8_t **body, size_t *body_len) {
    /* Check if we already have a complete message buffered.
     * Reuse app_buf as the decryption scratch buffer during handshake.
     * app_buf is only used for application data buffering (after handshake
     * completes), so there is no overlap. This avoids a ~16KB heap
     * allocation per read_hs_message call (called 4+ times per handshake). */
    int skip_count = 0;
    int iter_count = 0;
    uint8_t *dec_buf = r->app_buf;
    while (r->hs_buf_len < 4 ||
           r->hs_buf_len < 4 + (((size_t)r->hs_buf[1] << 16) |
                                 ((size_t)r->hs_buf[2] << 8) |
                                 r->hs_buf[3])) {
        /* Early reject: if we have the header, check the claimed message size
         * against the buffer capacity to fail fast instead of reading many
         * records before hitting the overflow check below. */
        if (r->hs_buf_len >= 4) {
            size_t claimed = 4 + (((size_t)r->hs_buf[1] << 16) |
                                   ((size_t)r->hs_buf[2] << 8) |
                                   r->hs_buf[3]);
            if (claimed > sizeof(r->hs_buf)) {
                vless_set_error("Handshake message too large: %zu bytes", claimed);
                return VLESS_ERR_PROTOCOL;
            }
        }
        if (++iter_count > 64) {
            vless_set_error("read_hs_message: iteration limit exceeded");
            return VLESS_ERR_PROTOCOL;
        }
        size_t dec_len;
        uint8_t inner_type;
        int rc = tls_read_encrypted(r, &inner_type, dec_buf, sizeof(r->app_buf), &dec_len);
        if (rc != VLESS_OK) return rc;

        if (inner_type == TLS_RECORD_ALERT) {
            /* Process TLS alerts during handshake instead of silently discarding */
            if (dec_len >= 2)
                vless_set_error("TLS alert during handshake: level=%d desc=%d",
                                dec_buf[0], dec_buf[1]);
            else
                vless_set_error("TLS alert during handshake (truncated)");
            return VLESS_ERR_TLS;
        }
        if (inner_type != TLS_RECORD_HANDSHAKE) {
            if (++skip_count > 32) {
                vless_set_error("Too many non-handshake records during handshake");
                return VLESS_ERR_PROTOCOL;
            }
            continue;
        }

        if (r->hs_buf_len + dec_len > sizeof(r->hs_buf)) {
            vless_set_error("Handshake message too large");
            return VLESS_ERR_PROTOCOL;
        }
        memcpy(r->hs_buf + r->hs_buf_len, dec_buf, dec_len);
        r->hs_buf_len += dec_len;
    }

    /* Parse handshake header */
    *hs_type = r->hs_buf[0];
    size_t msg_len = ((size_t)r->hs_buf[1] << 16) |
                     ((size_t)r->hs_buf[2] << 8) |
                     r->hs_buf[3];
    *body = r->hs_buf + 4;
    *body_len = msg_len;

    return VLESS_OK;
}

/* Consume the current handshake message from the buffer and hash it.
 * Returns VLESS_OK or VLESS_ERR_CRYPTO if transcript update fails. */
static int consume_hs_message(vless_reality_ctx_t *r) {
    if (r->hs_buf_len < 4) return VLESS_ERR_PROTOCOL;

    size_t msg_len = 4 + (((size_t)r->hs_buf[1] << 16) |
                           ((size_t)r->hs_buf[2] << 8) |
                           r->hs_buf[3]);

    /* Validate that the full message is within the buffer */
    if (msg_len > r->hs_buf_len) return VLESS_ERR_PROTOCOL;

    /* Add to transcript hash */
    if (!EVP_DigestUpdate(r->transcript, r->hs_buf, msg_len))
        return VLESS_ERR_CRYPTO;

    /* Shift remaining data */
    if (msg_len < r->hs_buf_len) {
        memmove(r->hs_buf, r->hs_buf + msg_len, r->hs_buf_len - msg_len);
        r->hs_buf_len -= msg_len;
    } else {
        r->hs_buf_len = 0;
    }
    return VLESS_OK;
}

/* ─── Transcript hash helpers ───────────────────────────────── */

/* Get intermediate transcript hash without consuming the context */
static int transcript_hash_current(vless_reality_ctx_t *r, uint8_t *out) {
    EVP_MD_CTX *tmp = EVP_MD_CTX_new();
    if (!tmp) return VLESS_ERR_CRYPTO;
    if (!EVP_MD_CTX_copy_ex(tmp, r->transcript)) {
        EVP_MD_CTX_free(tmp);
        return VLESS_ERR_CRYPTO;
    }
    unsigned int len = 0;
    if (!EVP_DigestFinal_ex(tmp, out, &len)) {
        EVP_MD_CTX_free(tmp);
        return VLESS_ERR_CRYPTO;
    }
    EVP_MD_CTX_free(tmp);
    return VLESS_OK;
}

/* ─── REALITY auth: encrypt session_id helper ───────────────── */

/*
 * Encrypts the REALITY session_id in-place inside a ClientHello message.
 * ch_msg must have 32 zero bytes at REALITY_SESSION_ID_OFFSET.
 * Uses r->client_random (saved in build_client_hello), r->eph_private, r->server_pub.
 */
static int reality_encrypt_session_id(vless_reality_ctx_t *r,
                                       uint8_t *ch_msg, size_t ch_len) {
    const uint8_t *client_random = r->client_random;

    /* Build session_id plaintext (16 bytes) */
    uint8_t sid_plain[16] = {0};
    sid_plain[0] = REALITY_VERSION_X;  /* Version_x (match latest xray-core) */
    sid_plain[1] = REALITY_VERSION_Y;  /* Version_y */
    sid_plain[2] = REALITY_VERSION_Z;  /* Version_z */
    sid_plain[3] = 0;   /* reserved */
    /* REALITY timestamp: server checks this within its MaxTimeDiff window
     * (typically 120 seconds). Ensure system clock is reasonably accurate. */
    time_t now = time(NULL);
    if (now == (time_t)-1) {
        vless_set_error("REALITY auth: time() failed — cannot generate timestamp");
        return VLESS_ERR_CRYPTO;
    }
    /* REALITY protocol uses a 32-bit timestamp. After Y2038 this wraps,
     * causing the server to reject connections. Fail explicitly.
     * Also reject negative time_t (32-bit signed overflow after 2038). */
    if (now < 0) {
        vless_set_error("REALITY auth: negative time_t (system clock error or 32-bit overflow)");
        return VLESS_ERR_CRYPTO;
    }
    if (sizeof(time_t) > 4 && (uint64_t)now > (uint64_t)UINT32_MAX) {
        vless_set_error("REALITY auth: system time past Y2038 limit for 32-bit protocol timestamp");
        return VLESS_ERR_CRYPTO;
    }
    uint32_t ts32 = (uint32_t)now;
    sid_plain[4] = (uint8_t)(ts32 >> 24);
    sid_plain[5] = (uint8_t)(ts32 >> 16);
    sid_plain[6] = (uint8_t)(ts32 >> 8);
    sid_plain[7] = (uint8_t)(ts32);
    if (r->short_id_len > 8) {
        vless_set_error("REALITY auth: short_id_len %zu exceeds maximum 8", r->short_id_len);
        return VLESS_ERR_INVALID_ARG;
    }
    memcpy(sid_plain + 8, r->short_id, r->short_id_len);

    /* Safety guard: on HRR retry, client_random (and thus the AES-GCM nonce
     * at client_random[20:32]) is reused per RFC 8446 §4.1.2. Verify the
     * ephemeral X25519 key was regenerated so the derived auth_key differs,
     * preventing catastrophic AES-GCM (key, nonce) reuse. */
    if (r->reality_auth_done &&
        CRYPTO_memcmp(r->eph_public, r->last_auth_eph_pub, 32) == 0) {
        OPENSSL_cleanse(sid_plain, sizeof(sid_plain));
        vless_set_error("REALITY: ephemeral key not regenerated before HRR retry "
                        "(would cause AES-GCM nonce reuse)");
        return VLESS_ERR_CRYPTO;
    }
    memcpy(r->last_auth_eph_pub, r->eph_public, 32);
    r->reality_auth_done = 1;

    /* Derive AuthKey via HKDF(x25519 shared secret) */
    uint8_t ecdhe_shared[32];
    if (!x25519_shared(ecdhe_shared, r->eph_private, r->server_pub)) {
        OPENSSL_cleanse(sid_plain, sizeof(sid_plain));
        vless_set_error("REALITY x25519 shared secret failed");
        return VLESS_ERR_CRYPTO;
    }
    /* Reject all-zero shared secret (low-order server public key) */
    {
        uint8_t zero[32] = {0};
        if (CRYPTO_memcmp(ecdhe_shared, zero, 32) == 0) {
            OPENSSL_cleanse(ecdhe_shared, sizeof(ecdhe_shared));
            OPENSSL_cleanse(sid_plain, sizeof(sid_plain));
            vless_set_error("REALITY X25519 shared secret is zero (low-order point)");
            return VLESS_ERR_CRYPTO;
        }
    }

    uint8_t prk[32];
    int rc = hkdf_extract(client_random, 20, ecdhe_shared, 32, prk);
    OPENSSL_cleanse(ecdhe_shared, sizeof(ecdhe_shared));
    if (rc != VLESS_OK) { OPENSSL_cleanse(sid_plain, sizeof(sid_plain)); return rc; }

    uint8_t auth_key[32];
    rc = hkdf_expand(prk, (const uint8_t *)"REALITY", 7, auth_key, 32);
    OPENSSL_cleanse(prk, sizeof(prk));
    if (rc != VLESS_OK) { OPENSSL_cleanse(sid_plain, sizeof(sid_plain)); return rc; }

    /* Verify session_id field is zero before using the ClientHello as AAD.
     * The server reconstructs AAD with a zeroed session_id for decryption;
     * if any code populates session_id before this point, AEAD will fail. */
    if (ch_len >= REALITY_SESSION_ID_OFFSET + 32) {
        static const uint8_t sid_zeros[32] = {0};
        if (memcmp(ch_msg + REALITY_SESSION_ID_OFFSET, sid_zeros, 32) != 0) {
            OPENSSL_cleanse(auth_key, sizeof(auth_key));
            OPENSSL_cleanse(sid_plain, sizeof(sid_plain));
            vless_set_error("REALITY: session_id non-zero before encryption (invariant violation)");
            return VLESS_ERR_CRYPTO;
        }
    }

    uint8_t encrypted_sid[32];
    rc = aead_seal_ex(EVP_aes_256_gcm(), auth_key,
                      client_random + 20,
                      ch_msg, ch_len,
                      sid_plain, 16,
                      encrypted_sid);
    OPENSSL_cleanse(auth_key, sizeof(auth_key));
    OPENSSL_cleanse(sid_plain, sizeof(sid_plain));
    if (rc != VLESS_OK) {
        vless_set_error("REALITY session_id encryption failed");
        return rc;
    }

    if (ch_len < REALITY_SESSION_ID_OFFSET + 32) {
        OPENSSL_cleanse(encrypted_sid, sizeof(encrypted_sid));
        vless_set_error("REALITY: ClientHello too short for session_id (%zu < %d)",
                        ch_len, REALITY_SESSION_ID_OFFSET + 32);
        return VLESS_ERR_PROTOCOL;
    }
    memcpy(ch_msg + REALITY_SESSION_ID_OFFSET, encrypted_sid, 32);
    OPENSSL_cleanse(encrypted_sid, sizeof(encrypted_sid));
    return VLESS_OK;
}

/* ─── CertificateVerify signature validation (RFC 8446 §4.4.3) ── */

/*
 * Verify the server's CertificateVerify signature.
 *
 * cert_body/cert_body_len: body of the Certificate handshake message
 * cv_body/cv_body_len:     body of the CertificateVerify handshake message
 * transcript_hash:         hash of transcript up to (including) Certificate
 * hash_len:                length of transcript_hash (32 for SHA-256, 48 for SHA-384)
 *
 * IMPORTANT: REALITY mode intentionally does NOT validate the certificate chain.
 * There is no trust store, no hostname matching, and no expiry check.
 * Authentication of the server is performed via the REALITY X25519 shared
 * secret mechanism (encrypted session_id in ClientHello), NOT via PKI.
 * The CertificateVerify check here only proves that the server holds the
 * private key corresponding to the presented certificate, which prevents
 * a man-in-the-middle from tampering with the handshake transcript.
 *
 * Returns VLESS_OK on success, VLESS_ERR_CERT on verification failure,
 * VLESS_ERR_PROTOCOL on parse errors, VLESS_ERR_CRYPTO on OpenSSL errors.
 */
static int verify_certificate_verify(const uint8_t *cert_body, size_t cert_body_len,
                                      const uint8_t *cv_body, size_t cv_body_len,
                                      const uint8_t *transcript_hash, size_t hash_len) {
    int result = VLESS_ERR_CERT;
    X509 *cert = NULL;
    EVP_PKEY *pkey = NULL;
    EVP_MD_CTX *md_ctx = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;  /* owned by md_ctx after DigestVerifyInit */

    /* ── 1. Parse first certificate from Certificate message body ── */
    /* Format: certificate_request_context_len(1) + certificate_list_len(3) +
     *         [cert_data_len(3) + cert_data + extensions_len(2) + extensions]... */
    if (cert_body_len < 4) {
        vless_set_error("Certificate message too short");
        return VLESS_ERR_PROTOCOL;
    }

    size_t off = 0;
    uint8_t ctx_len = cert_body[off++];
    if (ctx_len != 0) {
        /* Server Certificate should have empty certificate_request_context */
        if (off + ctx_len > cert_body_len) {
            vless_set_error("Certificate: invalid context length");
            return VLESS_ERR_PROTOCOL;
        }
        off += ctx_len;
    }

    if (off + 3 > cert_body_len) {
        vless_set_error("Certificate: truncated certificate_list length");
        return VLESS_ERR_PROTOCOL;
    }
    size_t cert_list_len = ((size_t)cert_body[off] << 16) |
                           ((size_t)cert_body[off + 1] << 8) |
                           cert_body[off + 2];
    off += 3;

    if (off + cert_list_len > cert_body_len || cert_list_len < 3) {
        vless_set_error("Certificate: invalid certificate_list length");
        return VLESS_ERR_PROTOCOL;
    }

    /* First CertificateEntry: cert_data_len(3) + cert_data */
    size_t cert_data_len = ((size_t)cert_body[off] << 16) |
                           ((size_t)cert_body[off + 1] << 8) |
                           cert_body[off + 2];
    off += 3;

    if (cert_data_len == 0 || off + cert_data_len > cert_body_len) {
        vless_set_error("Certificate: invalid cert_data length");
        return VLESS_ERR_PROTOCOL;
    }

    const uint8_t *cert_der = cert_body + off;

    /* Parse DER-encoded X.509 certificate */
    if (cert_data_len > (size_t)LONG_MAX) {
        vless_set_error("Certificate: cert_data_len exceeds LONG_MAX");
        return VLESS_ERR_PROTOCOL;
    }
    const uint8_t *p = cert_der;
    cert = d2i_X509(NULL, &p, (long)cert_data_len);
    if (!cert) {
        vless_set_error("Certificate: failed to parse X.509 certificate");
        result = VLESS_ERR_CRYPTO;
        goto cv_cleanup;
    }
    if (p != cert_der + cert_data_len) {
        vless_set_error("Certificate: %ld trailing bytes after DER",
                        (long)(cert_der + cert_data_len - p));
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    }

    /* Extract public key from certificate */
    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        vless_set_error("Certificate: failed to extract public key");
        result = VLESS_ERR_CRYPTO;
        goto cv_cleanup;
    }

    /* ── 2. Parse CertificateVerify body ── */
    /* Format: SignatureScheme algorithm(2) + signature_len(2) + signature */
    if (cv_body_len < 4) {
        vless_set_error("CertificateVerify: message too short");
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    }

    uint16_t sig_scheme = rd_u16be(cv_body);
    uint16_t sig_len = rd_u16be(cv_body + 2);

    if (4 + (size_t)sig_len > cv_body_len) {
        vless_set_error("CertificateVerify: signature truncated");
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    }
    if (4 + (size_t)sig_len != cv_body_len) {
        vless_set_error("CertificateVerify: trailing data after signature (%zu extra bytes)",
                        cv_body_len - 4 - (size_t)sig_len);
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    }
    const uint8_t *sig_data = cv_body + 4;

    /* ── 3. Determine digest and padding from SignatureScheme ── */
    const EVP_MD *sig_md = NULL;
    int is_rsa_pss = 0;
    int is_eddsa = 0;

    switch (sig_scheme) {
    case 0x0403: /* ecdsa_secp256r1_sha256 */
        sig_md = EVP_sha256();
        break;
    case 0x0503: /* ecdsa_secp384r1_sha384 */
        sig_md = EVP_sha384();
        break;
    case 0x0603: /* ecdsa_secp521r1_sha512 */
        sig_md = EVP_sha512();
        break;
    case 0x0804: /* rsa_pss_rsae_sha256 */
        sig_md = EVP_sha256();
        is_rsa_pss = 1;
        break;
    case 0x0805: /* rsa_pss_rsae_sha384 */
        sig_md = EVP_sha384();
        is_rsa_pss = 1;
        break;
    case 0x0806: /* rsa_pss_rsae_sha512 */
        sig_md = EVP_sha512();
        is_rsa_pss = 1;
        break;
    case 0x0807: /* ed25519 */
        sig_md = NULL; /* Ed25519 does signing internally, no separate digest */
        is_eddsa = 1;
        break;
    case 0x0808: /* ed448 */
        sig_md = NULL; /* Ed448 does signing internally, no separate digest */
        is_eddsa = 1;
        break;
    case 0x0401: /* rsa_pkcs1_sha256 — FORBIDDEN in TLS 1.3 CertificateVerify (RFC 8446 §4.4.3) */
    case 0x0501: /* rsa_pkcs1_sha384 — FORBIDDEN in TLS 1.3 CertificateVerify (RFC 8446 §4.4.3) */
    case 0x0601: /* rsa_pkcs1_sha512 — FORBIDDEN in TLS 1.3 CertificateVerify (RFC 8446 §4.4.3) */
        vless_set_error("CertificateVerify: RSASSA-PKCS1-v1_5 scheme 0x%04x forbidden in TLS 1.3",
                        sig_scheme);
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    default:
        vless_set_error("CertificateVerify: unsupported SignatureScheme 0x%04x",
                        sig_scheme);
        result = VLESS_ERR_PROTOCOL;
        goto cv_cleanup;
    }

    /* ── 3b. Validate public key type matches SignatureScheme ── */
    {
        int pkey_type = EVP_PKEY_base_id(pkey);
        int type_ok = 0;
        switch (sig_scheme) {
        case 0x0403: /* ecdsa_secp256r1_sha256 */
        case 0x0503: /* ecdsa_secp384r1_sha384 */
        case 0x0603: /* ecdsa_secp521r1_sha512 */
            if (pkey_type == EVP_PKEY_EC) {
                /* Enforce curve-to-scheme binding per RFC 8446 §4.2.3 */
                int curve_nid = 0;
#ifdef OPENSSL_IS_BORINGSSL
                EC_KEY *eckey = EVP_PKEY_get0_EC_KEY(pkey);
                if (eckey) curve_nid = EC_GROUP_get_curve_name(EC_KEY_get0_group(eckey));
#else
                char curve_name[64] = {0};
                size_t curve_name_len = 0;
                if (EVP_PKEY_get_utf8_string_param(pkey, OSSL_PKEY_PARAM_GROUP_NAME,
                        curve_name, sizeof(curve_name), &curve_name_len)) {
                    if (strcmp(curve_name, "P-256") == 0 || strcmp(curve_name, "prime256v1") == 0)
                        curve_nid = NID_X9_62_prime256v1;
                    else if (strcmp(curve_name, "P-384") == 0 || strcmp(curve_name, "secp384r1") == 0)
                        curve_nid = NID_secp384r1;
                    else if (strcmp(curve_name, "P-521") == 0 || strcmp(curve_name, "secp521r1") == 0)
                        curve_nid = NID_secp521r1;
                }
#endif
                int expected_nid = 0;
                if (sig_scheme == 0x0403) expected_nid = NID_X9_62_prime256v1;
                else if (sig_scheme == 0x0503) expected_nid = NID_secp384r1;
                else if (sig_scheme == 0x0603) expected_nid = NID_secp521r1;
                type_ok = (curve_nid == expected_nid);
            }
            break;
        case 0x0804: /* rsa_pss_rsae_sha256 */
        case 0x0805: /* rsa_pss_rsae_sha384 */
        case 0x0806: /* rsa_pss_rsae_sha512 */
            if (pkey_type == EVP_PKEY_RSA || pkey_type == EVP_PKEY_RSA_PSS) {
                /* RFC 8446 §9.1: RSA keys SHOULD be at least 2048 bits */
                int key_bits = EVP_PKEY_bits(pkey);
                type_ok = (key_bits >= 2048);
                if (!type_ok) {
                    vless_set_error("CertificateVerify: RSA key too small (%d bits, min 2048)", key_bits);
                    result = VLESS_ERR_TLS;
                    goto cv_cleanup;
                }
            }
            break;
        case 0x0807: /* ed25519 */
            type_ok = (pkey_type == EVP_PKEY_ED25519);
            break;
        case 0x0808: /* ed448 */
            type_ok = (pkey_type == EVP_PKEY_ED448);
            break;
        default:
            break; /* unreachable: already handled above */
        }
        if (!type_ok) {
            vless_set_error("CertificateVerify: key type %d does not match scheme 0x%04x",
                            pkey_type, sig_scheme);
            result = VLESS_ERR_TLS;
            goto cv_cleanup;
        }
    }

    /* ── 4. Build verification content (RFC 8446 §4.4.3) ── */
    /* 64 spaces + "TLS 1.3, server CertificateVerify" + 0x00 + transcript_hash */
    static const char cv_label[] = "TLS 1.3, server CertificateVerify";
    size_t content_len = 64 + sizeof(cv_label) + (size_t)hash_len; /* sizeof includes \0 */
    uint8_t content[64 + sizeof(cv_label) + TLS_HASH_LEN_384];

    memset(content, 0x20, 64);
    memcpy(content + 64, cv_label, sizeof(cv_label)); /* copies label + NUL byte */
    memcpy(content + 64 + sizeof(cv_label), transcript_hash, (size_t)hash_len);

    /* ── 5. Verify the signature ── */
    md_ctx = EVP_MD_CTX_new();
    if (!md_ctx) {
        vless_set_error("CertificateVerify: EVP_MD_CTX_new failed");
        result = VLESS_ERR_CRYPTO;
        goto cv_cleanup;
    }

    if (EVP_DigestVerifyInit(md_ctx, &pkey_ctx, sig_md, NULL, pkey) != 1) {
        vless_set_error("CertificateVerify: EVP_DigestVerifyInit failed");
        result = VLESS_ERR_CRYPTO;
        goto cv_cleanup;
    }

    /* Set RSA-PSS padding parameters if needed.
     * Explicitly set MGF1 hash to match the digest (RFC 8446 Section 4.2.3)
     * rather than relying on OpenSSL's default, which could change. */
    if (is_rsa_pss) {
        if (EVP_PKEY_CTX_set_rsa_padding(pkey_ctx, RSA_PKCS1_PSS_PADDING) <= 0 ||
            EVP_PKEY_CTX_set_rsa_pss_saltlen(pkey_ctx, RSA_PSS_SALTLEN_DIGEST) <= 0 ||
            EVP_PKEY_CTX_set_rsa_mgf1_md(pkey_ctx, sig_md) <= 0) {
            vless_set_error("CertificateVerify: failed to set RSA-PSS padding");
            result = VLESS_ERR_CRYPTO;
            goto cv_cleanup;
        }
    }

    if (is_eddsa) {
        /* Ed25519/Ed448: use one-shot EVP_DigestVerify (no separate Update+Final) */
        if (EVP_DigestVerify(md_ctx, sig_data, (size_t)sig_len,
                             content, content_len) != 1) {
            vless_set_error("CertificateVerify: EdDSA signature verification failed");
            result = VLESS_ERR_CERT;
            goto cv_cleanup;
        }
    } else {
        if (EVP_DigestVerifyUpdate(md_ctx, content, content_len) != 1) {
            vless_set_error("CertificateVerify: EVP_DigestVerifyUpdate failed");
            result = VLESS_ERR_CRYPTO;
            goto cv_cleanup;
        }

        if (EVP_DigestVerifyFinal(md_ctx, sig_data, (size_t)sig_len) != 1) {
            vless_set_error("CertificateVerify: signature verification failed");
            result = VLESS_ERR_CERT;
            goto cv_cleanup;
        }
    }

    result = VLESS_OK;

cv_cleanup:
    OPENSSL_cleanse(content, sizeof(content));
    EVP_MD_CTX_free(md_ctx);   /* also frees pkey_ctx */
    EVP_PKEY_free(pkey);
    X509_free(cert);
    return result;
}

/* ─── Full REALITY handshake ────────────────────────────────── */

VLESS_INTERNAL
int vless_reality_handshake(vless_conn_t *conn, const vless_config_t *config) {
    int rc = VLESS_OK;
    uint8_t *ch_msg = NULL;  /* heap-allocated ClientHello buffer (8192 bytes) */
    uint8_t *sh_buf = NULL;  /* heap-allocated ServerHello buffer */

    /* Certificate body + pre-CertificateVerify hash — declared up front
     * so the goto-cleanup pattern handles cleansing on all error paths. */
    uint8_t *saved_cert_body = NULL;
    size_t saved_cert_body_len = 0;
    uint8_t hash_pre_cv[TLS_HASH_LEN_384];
    memset(hash_pre_cv, 0, sizeof(hash_pre_cv));

    vless_reality_ctx_t *r = calloc(1, sizeof(vless_reality_ctx_t));
    if (!r) { vless_set_error("Out of memory"); return VLESS_ERR_NOMEM; }

    conn->reality = r;
    r->fd = conn->fd;
    r->io_timeout_ms = config->io_timeout_ms;

    /* Select Chrome fingerprint profile */
    r->profile = chrome_profile_for(config->reality.fingerprint);

    /* Default to SHA-256 / AES-128 until ServerHello tells us otherwise */
    set_cipher_params(r, TLS_AES_128_GCM_SHA256);

    /* Initialize transcript hash context */
    r->transcript = EVP_MD_CTX_new();
    if (!r->transcript) {
        vless_set_error("EVP_MD_CTX_new failed");
        rc = VLESS_ERR_NOMEM;
        goto cleanup;
    }
    /* Start with SHA-256; will re-init if server selects SHA-384 */
    if (!EVP_DigestInit_ex(r->transcript, EVP_sha256(), NULL)) {
        vless_set_error("EVP_DigestInit_ex failed");
        rc = VLESS_ERR_CRYPTO;
        goto cleanup;
    }

    /* Pre-allocate ciphertext buffer for tls_read_encrypted (avoids
     * per-record malloc/free during handshake and data transfer). */
    r->ct_buf_cap = TLS_MAX_RECORD_PAYLOAD + 256 + TLS_GCM_TAG_LEN;
    r->ct_buf = malloc(r->ct_buf_cap);
    if (!r->ct_buf) {
        vless_set_error("Out of memory for TLS record buffer");
        rc = VLESS_ERR_NOMEM;
        goto cleanup;
    }

    /* Pre-allocate write buffer for tls_write_encrypted (avoids
     * per-record malloc/free during application data transfer).
     * Layout: [5-byte header][ciphertext(max ct_len)]. */
    r->wt_buf_cap = 5 + TLS_MAX_RECORD_PAYLOAD + 256;
    r->wt_buf = malloc(r->wt_buf_cap);
    if (!r->wt_buf) {
        vless_set_error("Out of memory for TLS write buffer");
        rc = VLESS_ERR_NOMEM;
        goto cleanup;
    }

    int had_hrr = 0; /* Track whether HRR was received */
    uint16_t hrr_requested_group = 0; /* Group requested by HRR (for post-SH validation) */

    /* All intermediate secrets -- declared up front for goto cleanup.
     * Sized for max(SHA-256=32, SHA-384=48).
     * ecdhe_secret is 64 bytes max for MLKEM hybrid (mlkem_ss(32) || x25519_ss(32)). */
    uint8_t server_ks_data[MLKEM768_CT_LEN + 32]; /* max: mlkem_ct(1088) + x25519(32) */
    memset(server_ks_data, 0, sizeof(server_ks_data));
    size_t server_ks_data_len = 0;
    uint16_t server_ks_group = 0;
    uint8_t ecdhe_secret[64] = {0};
    size_t ecdhe_secret_len = 32; /* default: plain X25519 */
    uint8_t early_secret[TLS_HASH_LEN_384] = {0};
    uint8_t derived1[TLS_HASH_LEN_384] = {0};
    uint8_t derived2[TLS_HASH_LEN_384] = {0};
    uint8_t handshake_secret[TLS_HASH_LEN_384] = {0};
    uint8_t master_secret[TLS_HASH_LEN_384] = {0};
    uint8_t c_hs_traffic[TLS_HASH_LEN_384] = {0}, s_hs_traffic[TLS_HASH_LEN_384] = {0};
    uint8_t c_ap_traffic[TLS_HASH_LEN_384] = {0}, s_ap_traffic[TLS_HASH_LEN_384] = {0};
    uint8_t hash_hello[TLS_HASH_LEN_384] = {0};
    uint8_t hash_pre_finished[TLS_HASH_LEN_384] = {0};
    uint8_t hash_with_sf[TLS_HASH_LEN_384] = {0};
    uint8_t finished_key[TLS_HASH_LEN_384] = {0};
    uint8_t c_finished_key[TLS_HASH_LEN_384] = {0};
    uint8_t c_verify_data[TLS_HASH_LEN_384] = {0};
    uint8_t expected_verify[TLS_HASH_LEN_384] = {0};
    uint8_t zeros[TLS_HASH_LEN_384] = {0};
    uint8_t empty_hash[TLS_HASH_LEN_384];
    /* empty_hash will be computed after cipher negotiation determines the hash algorithm */
    memset(empty_hash, 0, sizeof(empty_hash));

    /* Decode server's REALITY public key */
    size_t pk_len;
    rc = base64_decode(config->reality.public_key, r->server_pub, 32, &pk_len);
    if (rc != VLESS_OK || pk_len != 32) {
        vless_set_error("Invalid REALITY public key");
        rc = VLESS_ERR_AUTH;
        goto cleanup;
    }

    /* Decode short_id */
    r->short_id_len = 0;
    if (config->reality.short_id && strlen(config->reality.short_id) > 0) {
        rc = hex_decode(config->reality.short_id, r->short_id, 8, &r->short_id_len);
        if (rc != VLESS_OK || r->short_id_len > 8) {
            vless_set_error("Invalid short_id");
            rc = VLESS_ERR_AUTH;
            goto cleanup;
        }
    }

    /* Generate ephemeral x25519 key pair */
    if (!x25519_generate(r->eph_public, r->eph_private)) {
        vless_set_error("x25519 key generation failed");
        rc = VLESS_ERR_CRYPTO;
        goto cleanup;
    }

    /* Try to generate ML-KEM-768 keypair (only if profile wants MLKEM).
     * If OpenSSL doesn't support it, mlkem_available stays 0. */
#ifndef OPENSSL_IS_BORINGSSL
    if (r->profile->has_mlkem) {
        EVP_PKEY_CTX *kctx = EVP_PKEY_CTX_new_from_name(NULL, "ML-KEM-768", NULL);
        if (kctx) {
            if (EVP_PKEY_keygen_init(kctx) > 0 &&
                EVP_PKEY_keygen(kctx, &r->mlkem_key) > 0 &&
                r->mlkem_key != NULL) {
                r->mlkem_available = 1;
            }
            EVP_PKEY_CTX_free(kctx);
        }
    }
    /* Generate a separate X25519 key pair for the MLKEM hybrid key_share entry.
     * Chrome uses independent X25519 keys in the hybrid (X25519MLKEM768) and
     * standalone (X25519) entries; reusing the same key is a trivially
     * detectable fingerprint (DPI compares the 32-byte values in both entries). */
    if (r->mlkem_available && r->mlkem_key) {
        if (!x25519_generate(r->mlkem_eph_public, r->mlkem_eph_private)) {
            vless_set_error("x25519 key generation for MLKEM hybrid failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
    }
#else
    /* BoringSSL: ML-KEM-768 not available through EVP API */
    r->mlkem_available = 0;
#endif

    /* Build and send ClientHello, then read ServerHello.
     * Both CH and SH raw bytes are kept for potential SHA-384 transcript replay. */
    ch_msg = malloc(CH_BUF_SIZE);
    if (!ch_msg) { rc = VLESS_ERR_NOMEM; goto cleanup; }
    size_t ch_len = 0;
    size_t sh_buf_cap = TLS_MAX_RECORD_PAYLOAD + 256;
    sh_buf = malloc(sh_buf_cap);
    if (!sh_buf) { rc = VLESS_ERR_NOMEM; goto cleanup; }
    size_t sh_len = 0;

    {
        const char *sni = config->reality.server_name;
        if (!sni) sni = config->server_host;

        rc = build_client_hello(r, sni, 0, NULL, 0, ch_msg, CH_BUF_SIZE, &ch_len);
        if (rc != VLESS_OK) goto cleanup;

        /* REALITY auth: encrypt session_id */
        rc = reality_encrypt_session_id(r, ch_msg, ch_len);
        if (rc != VLESS_OK) goto cleanup;

        /* Hash ClientHello for transcript (SHA-256 initially) */
        if (!EVP_DigestUpdate(r->transcript, ch_msg, ch_len)) { rc = VLESS_ERR_CRYPTO; goto cleanup; }

        /* Send ClientHello as TLS record */
        rc = tls_write_record(r, TLS_RECORD_HANDSHAKE, ch_msg, ch_len);
        if (rc != VLESS_OK) goto cleanup;

        /* CCS will be sent after ServerHello, before client Finished */
    }

    /* Read ServerHello (plaintext record) — may be a HelloRetryRequest */
    {
        uint8_t rec_type;
        rc = tls_read_record(r, &rec_type, sh_buf, sh_buf_cap, &sh_len);
        if (rc != VLESS_OK) { vless_set_error("read ServerHello failed rc=%d", rc); goto cleanup; }

        if (rec_type != TLS_RECORD_HANDSHAKE || sh_len < 4 ||
            sh_buf[0] != TLS_HS_SERVER_HELLO) {
            if (rec_type == TLS_RECORD_ALERT && sh_len >= 2)
                vless_set_error("TLS alert from server: level=%d desc=%d",
                                sh_buf[0], sh_buf[1]);
            else
                vless_set_error("Expected ServerHello, got record type %d",
                                rec_type);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* Check body length */
        uint16_t negotiated_cipher = 0;
        size_t sh_body_len = ((size_t)sh_buf[1] << 16) |
                             ((size_t)sh_buf[2] << 8) | sh_buf[3];
        if (4 + sh_body_len > sh_len) {
            vless_set_error("ServerHello body exceeds record");
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* ─── HelloRetryRequest handling (RFC 8446 Section 4.1.4) ─── */
        if (is_hello_retry_request(sh_buf + 4, sh_body_len)) {
            /* 1. Parse cipher suite from HRR to update cipher params */
            if (sh_body_len < 2 + 32 + 1) { rc = VLESS_ERR_PROTOCOL; goto cleanup; }
            size_t hrr_pos = 4 + 2 + 32;
            uint8_t hrr_sid_len = sh_buf[hrr_pos++];
            if (hrr_sid_len > 32) { rc = VLESS_ERR_PROTOCOL; goto cleanup; }
            hrr_pos += hrr_sid_len;
            if (hrr_pos + 3 > 4 + sh_body_len) { rc = VLESS_ERR_PROTOCOL; goto cleanup; }
            uint16_t hrr_cipher = rd_u16be(sh_buf + hrr_pos);

            /* Validate HRR cipher is one of the three supported suites */
            if (hrr_cipher != TLS_AES_128_GCM_SHA256 &&
                hrr_cipher != TLS_AES_256_GCM_SHA384 &&
                hrr_cipher != TLS_CHACHA20_POLY1305_SHA256) {
                vless_set_error("HRR unsupported cipher suite 0x%04x", hrr_cipher);
                rc = VLESS_ERR_PROTOCOL;
                goto cleanup;
            }

            /* Save old hash length BEFORE updating cipher params.
             * This is critical: when HRR changes hash from SHA-256 to SHA-384,
             * the transcript hash computed from CH1 is only old_hash_len bytes. */
            size_t old_hash_len = r->hash_len;

            /* 2. Update cipher params if changed */
            set_cipher_params(r, hrr_cipher);
            if (!r->aead_cipher) {
                vless_set_error("HRR cipher 0x%04x not supported (BoringSSL lacks EVP_CIPHER ChaCha20)", hrr_cipher);
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }

            /* 3. Parse selected_group and cookie from HRR extensions */
            uint16_t hrr_group = 0;
            const uint8_t *hrr_cookie = NULL;
            size_t hrr_cookie_len = 0;
            rc = parse_hrr_selected_group(sh_buf + 4, sh_body_len,
                                           &hrr_group, &hrr_cookie, &hrr_cookie_len);
            if (rc != VLESS_OK) goto cleanup;

            /* Validate HRR selected group against the groups we offered.
             * RFC 8446 §4.2.8: server MUST select a group the client offered. */
            if (hrr_group != 0) {
                const chrome_profile_t *prof = r->profile ? r->profile : &CHROME_131;
                int group_offered = 0;
                for (int gi = 0; gi < prof->num_groups; gi++) {
                    if (prof->groups[gi] == hrr_group) { group_offered = 1; break; }
                }
                if (!group_offered) {
                    vless_set_error("HRR selected group 0x%04x not in offered groups", hrr_group);
                    rc = VLESS_ERR_PROTOCOL;
                    goto cleanup;
                }
            }

            /* 4. Transcript replacement (RFC 8446 Section 4.4.1):
             * Replace Hash(CH1) with synthetic message_hash construct.
             * Pass old_hash_len so the synthetic message uses the correct
             * hash size from BEFORE the cipher params were updated. */
            rc = transcript_replace_with_message_hash(r, old_hash_len);
            if (rc != VLESS_OK) goto cleanup;

            /* 5. Add HRR to transcript */
            if (!EVP_DigestUpdate(r->transcript, sh_buf, sh_len)) { rc = VLESS_ERR_CRYPTO; goto cleanup; }

            had_hrr = 1;
            hrr_requested_group = hrr_group;

            /* 6. Regenerate X25519 ephemeral key so REALITY auth produces a
             * different auth_key, avoiding AES-GCM nonce reuse when
             * client_random is reused per RFC 8446 §4.1.2. */
            OPENSSL_cleanse(r->eph_private, sizeof(r->eph_private));
            if (!x25519_generate(r->eph_public, r->eph_private)) {
                vless_set_error("x25519 key regeneration for HRR failed");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
            /* Also regenerate the MLKEM hybrid X25519 key for fingerprint
             * fidelity — Chrome regenerates all key_share keys on HRR. */
            if (r->mlkem_available && r->mlkem_key) {
                OPENSSL_cleanse(r->mlkem_eph_private, sizeof(r->mlkem_eph_private));
                if (!x25519_generate(r->mlkem_eph_public, r->mlkem_eph_private)) {
                    vless_set_error("x25519 key regeneration for MLKEM hybrid (HRR) failed");
                    rc = VLESS_ERR_CRYPTO;
                    goto cleanup;
                }
            }

            /* 7. Send CCS before retry ClientHello (Chrome/BoringSSL timing).
             * Per RFC 8446 Appendix D.4: "the client sends a dummy
             * change_cipher_spec record immediately before its second flight",
             * which in the HRR case is the retry ClientHello. */
            {
                uint8_t ccs_byte = 1;
                rc = tls_write_record(r, TLS_RECORD_CCS, &ccs_byte, 1);
                if (rc != VLESS_OK) goto cleanup;
            }

            /* 8. Rebuild ClientHello with only the selected key_share group */
            ch_len = 0;
            const char *sni2 = config->reality.server_name;
            if (!sni2) sni2 = config->server_host;
            rc = build_client_hello(r, sni2, hrr_group,
                                     hrr_cookie, hrr_cookie_len,
                                     ch_msg, CH_BUF_SIZE, &ch_len);
            if (rc != VLESS_OK) goto cleanup;

            /* 9. Apply REALITY auth encryption to new CH */
            rc = reality_encrypt_session_id(r, ch_msg, ch_len);
            if (rc != VLESS_OK) goto cleanup;

            /* 10. Add new CH to transcript */
            if (!EVP_DigestUpdate(r->transcript, ch_msg, ch_len)) { rc = VLESS_ERR_CRYPTO; goto cleanup; }

            /* 11. Send new CH */
            rc = tls_write_record(r, TLS_RECORD_HANDSHAKE, ch_msg, ch_len);
            if (rc != VLESS_OK) goto cleanup;

            /* 12. Read actual ServerHello (must NOT be another HRR) */
            sh_len = 0;
            rc = tls_read_record(r, &rec_type, sh_buf, sh_buf_cap, &sh_len);
            if (rc != VLESS_OK) { vless_set_error("read ServerHello (post-HRR) failed"); goto cleanup; }

            if (rec_type != TLS_RECORD_HANDSHAKE || sh_len < 4 ||
                sh_buf[0] != TLS_HS_SERVER_HELLO) {
                vless_set_error("Expected ServerHello after HRR, got type %d", rec_type);
                rc = VLESS_ERR_PROTOCOL;
                goto cleanup;
            }

            sh_body_len = ((size_t)sh_buf[1] << 16) |
                          ((size_t)sh_buf[2] << 8) | sh_buf[3];
            if (4 + sh_body_len > sh_len) { rc = VLESS_ERR_PROTOCOL; goto cleanup; }

            if (is_hello_retry_request(sh_buf + 4, sh_body_len)) {
                vless_set_error("Server sent multiple HelloRetryRequests");
                rc = VLESS_ERR_PROTOCOL;
                goto cleanup;
            }
        }

        /* Parse the (real) ServerHello */
        sh_body_len = ((size_t)sh_buf[1] << 16) |
                      ((size_t)sh_buf[2] << 8) | sh_buf[3];
        rc = parse_server_hello(sh_buf + 4, sh_body_len,
                                server_ks_data, sizeof(server_ks_data),
                                &server_ks_data_len, &server_ks_group,
                                &negotiated_cipher);
        if (rc != VLESS_OK) goto cleanup;

        /* RFC 8446 §4.1.3: legacy_session_id_echo MUST match ClientHello.
         * For REALITY, session_id carries encrypted auth — mismatch indicates
         * middlebox interference or protocol confusion. */
        {
            uint8_t ch_sid_len = ch_msg[REALITY_SESSION_ID_OFFSET - 1];
            uint8_t sh_sid_len = sh_buf[4 + 2 + 32]; /* body: version(2) + random(32) */
            if (sh_sid_len != ch_sid_len ||
                (sh_sid_len > 0 &&
                 CRYPTO_memcmp(sh_buf + 4 + 2 + 32 + 1,
                               ch_msg + REALITY_SESSION_ID_OFFSET,
                               sh_sid_len) != 0)) {
                vless_set_error("ServerHello session_id echo mismatch");
                rc = VLESS_ERR_PROTOCOL;
                goto cleanup;
            }
        }

        /* RFC 8446 Section 4.1.4: cipher suite in ServerHello must match HRR.
         * had_hrr indicates we went through the HRR path and r->cipher_suite
         * was set from the HRR cipher above; verify consistency. */
        if (had_hrr && negotiated_cipher != r->cipher_suite) {
            vless_set_error("ServerHello cipher 0x%04x mismatches HRR cipher 0x%04x",
                           negotiated_cipher, r->cipher_suite);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* Set cipher parameters based on negotiated suite */
        set_cipher_params(r, negotiated_cipher);
        if (!r->aead_cipher) {
            vless_set_error("Negotiated cipher 0x%04x not supported (BoringSSL lacks EVP_CIPHER ChaCha20)", negotiated_cipher);
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }

        /* SHA-384 transcript re-initialization if needed */
        if (negotiated_cipher == TLS_AES_256_GCM_SHA384) {
            /* If transcript was already using SHA-384 (from HRR), just add SH.
             * If not, re-init and replay. */
            int cur_md_size_ret = EVP_MD_CTX_size(r->transcript);
            if (cur_md_size_ret <= 0) {
                vless_set_error("EVP_MD_CTX_size failed");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
            unsigned int cur_md_size = (unsigned int)cur_md_size_ret;
            if (cur_md_size != TLS_HASH_LEN_384) {
                /* This path should only be reached without HRR.
                 * After HRR, the transcript was already re-initialized with
                 * the correct hash in transcript_replace_with_message_hash(). */
                if (had_hrr) {
                    vless_set_error("BUG: SHA-384 transcript replay after HRR");
                    rc = VLESS_ERR_PROTOCOL;
                    goto cleanup;
                }
                if (!EVP_DigestInit_ex(r->transcript, EVP_sha384(), NULL)) {
                    vless_set_error("EVP_DigestInit_ex SHA-384 failed");
                    rc = VLESS_ERR_CRYPTO;
                    goto cleanup;
                }
                if (!EVP_DigestUpdate(r->transcript, ch_msg, ch_len)) {
                    rc = VLESS_ERR_CRYPTO; goto cleanup;
                }
            }
        }
        if (!EVP_DigestUpdate(r->transcript, sh_buf, sh_len)) {
            rc = VLESS_ERR_CRYPTO; goto cleanup;
        }

        /* Recompute empty_hash with the negotiated hash */
        {
            unsigned int ehlen = 0;
            EVP_MD_CTX *ehctx = EVP_MD_CTX_new();
            if (!ehctx) { rc = VLESS_ERR_CRYPTO; goto cleanup; }
            if (!EVP_DigestInit_ex(ehctx, r->hash_md, NULL) ||
                !EVP_DigestFinal_ex(ehctx, empty_hash, &ehlen)) {
                EVP_MD_CTX_free(ehctx);
                vless_set_error("Failed to compute empty hash");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
            EVP_MD_CTX_free(ehctx);
        }
    }

    /* ─── Send CCS (Chrome/BoringSSL timing, RFC 8446 Appendix D.4) ─── */
    /* In the HRR flow, CCS was already sent before the retry ClientHello
     * (matching Chrome: "before its second ClientHello").
     * In the non-HRR flow, CCS is sent here after ServerHello
     * (matching Chrome: "before its encrypted handshake flight"). */
    if (!had_hrr) {
        uint8_t ccs_byte = 1;
        rc = tls_write_record(r, TLS_RECORD_CCS, &ccs_byte, 1);
        if (rc != VLESS_OK) goto cleanup;
    }

    /* ─── TLS 1.3 Key Schedule ─── */

    /* Validate that the server selected a group that the client offered */
    if (server_ks_group != 0x001d /* X25519 */ &&
        server_ks_group != 0x0017 /* P-256 */ &&
        server_ks_group != 0x0018 /* P-384 */ &&
        server_ks_group != TLS_X25519MLKEM768) {
        vless_set_error("Server selected unsupported key_share group 0x%04x",
                       server_ks_group);
        rc = VLESS_ERR_PROTOCOL;
        goto cleanup;
    }

    /* P-256/P-384 key_shares are only sent after HRR selects those groups.
     * In the initial ClientHello we only offer X25519 (and optionally MLKEM).
     * Accepting P-256/P-384 without HRR would mean the server selected a group
     * for which we never sent a key_share, which is a protocol violation. */
    if ((server_ks_group == 0x0017 || server_ks_group == 0x0018) && !had_hrr) {
        vless_set_error("Server selected group 0x%04x without HRR", server_ks_group);
        rc = VLESS_ERR_PROTOCOL;
        goto cleanup;
    }

    /* RFC 8446 §4.2.8: after HRR, the server MUST select the same group
     * that was requested in the HelloRetryRequest. */
    if (had_hrr && hrr_requested_group != 0 &&
        server_ks_group != hrr_requested_group) {
        vless_set_error("Server selected group 0x%04x but HRR requested 0x%04x",
                       server_ks_group, hrr_requested_group);
        rc = VLESS_ERR_PROTOCOL;
        goto cleanup;
    }

    /* Defense-in-depth: reject MLKEM selection when we lack support */
    if (server_ks_group == TLS_X25519MLKEM768 && !r->mlkem_available) {
        vless_set_error("Server selected X25519MLKEM768 but MLKEM is not available");
        rc = VLESS_ERR_PROTOCOL;
        goto cleanup;
    }

    /* Compute ECDHE shared secret based on server's selected group */
    if (server_ks_group == TLS_X25519MLKEM768 && r->mlkem_available) {
        /* Hybrid X25519MLKEM768:
         * server_ks_data = mlkem_ciphertext(1088) + x25519_public(32)
         * ecdhe_secret = mlkem_ss(32) || x25519_ss(32) = 64 bytes */
#ifndef OPENSSL_IS_BORINGSSL
        uint8_t mlkem_ss[32] = {0};
        uint8_t x25519_ss[32] = {0};

        /* Decapsulate MLKEM */
        EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new(r->mlkem_key, NULL);
        if (!dctx) {
            vless_set_error("EVP_PKEY_CTX_new for MLKEM decapsulate failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        if (EVP_PKEY_decapsulate_init(dctx, NULL) <= 0) {
            EVP_PKEY_CTX_free(dctx);
            vless_set_error("EVP_PKEY_decapsulate_init failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        size_t ss_len = 32;
        if (EVP_PKEY_decapsulate(dctx, mlkem_ss, &ss_len,
                                  server_ks_data, MLKEM768_CT_LEN) <= 0) {
            OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
            EVP_PKEY_CTX_free(dctx);
            vless_set_error("MLKEM decapsulation failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        EVP_PKEY_CTX_free(dctx);

        /* Reject all-zero MLKEM shared secret (broken implementation guard) */
        {
            uint8_t zero_check[32] = {0};
            if (CRYPTO_memcmp(mlkem_ss, zero_check, 32) == 0) {
                OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
                vless_set_error("MLKEM shared secret is zero");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
        }

        /* X25519 shared secret from the X25519 portion of server's key_share.
         * Uses the MLKEM-specific X25519 private key (not the standalone one). */
        const uint8_t *server_x25519_pub = server_ks_data + MLKEM768_CT_LEN;
        if (!x25519_shared(x25519_ss, r->mlkem_eph_private, server_x25519_pub)) {
            OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
            OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
            vless_set_error("X25519 shared secret (MLKEM hybrid) failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        {
            uint8_t zero_check[32] = {0};
            if (CRYPTO_memcmp(x25519_ss, zero_check, 32) == 0) {
                OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
                OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
                vless_set_error("X25519 shared secret is zero in MLKEM hybrid (low-order point)");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
        }

        /* Concatenate: ecdhe_secret = mlkem_ss(32) || x25519_ss(32) */
        memcpy(ecdhe_secret, mlkem_ss, 32);
        memcpy(ecdhe_secret + 32, x25519_ss, 32);
        ecdhe_secret_len = 64;

        OPENSSL_cleanse(mlkem_ss, sizeof(mlkem_ss));
        OPENSSL_cleanse(x25519_ss, sizeof(x25519_ss));
#else
        vless_set_error("MLKEM not supported on BoringSSL");
        rc = VLESS_ERR_PROTOCOL;
        goto cleanup;
#endif
    } else if (server_ks_group == 0x0017 && r->ecdh_p256_key) {
        /* P-256: server_ks_data = 65-byte uncompressed point */
        size_t ss_len = 0;
        if (!ecdh_shared(r->ecdh_p256_key, server_ks_data, server_ks_data_len,
                          NID_X9_62_prime256v1, ecdhe_secret, &ss_len)) {
            vless_set_error("P-256 ECDH shared secret failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        {
            uint8_t zero_check[48] = {0};
            if (CRYPTO_memcmp(ecdhe_secret, zero_check, ss_len) == 0) {
                vless_set_error("ECDH produced zero shared secret");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
        }
        ecdhe_secret_len = ss_len; /* 32 bytes for P-256 */
    } else if (server_ks_group == 0x0018 && r->ecdh_p384_key) {
        /* P-384: server_ks_data = 97-byte uncompressed point */
        size_t ss_len = 0;
        if (!ecdh_shared(r->ecdh_p384_key, server_ks_data, server_ks_data_len,
                          NID_secp384r1, ecdhe_secret, &ss_len)) {
            vless_set_error("P-384 ECDH shared secret failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        {
            uint8_t zero_check[48] = {0};
            if (CRYPTO_memcmp(ecdhe_secret, zero_check, ss_len) == 0) {
                vless_set_error("ECDH produced zero shared secret");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
        }
        ecdhe_secret_len = ss_len; /* 48 bytes for P-384 */
    } else {
        /* Plain X25519: server_ks_data = 32-byte server public key */
        if (!x25519_shared(ecdhe_secret, r->eph_private, server_ks_data)) {
            vless_set_error("ECDHE key exchange failed");
            rc = VLESS_ERR_CRYPTO;
            goto cleanup;
        }
        {
            uint8_t zero_check[32] = {0};
            if (CRYPTO_memcmp(ecdhe_secret, zero_check, 32) == 0) {
                vless_set_error("X25519 shared secret is zero (low-order point)");
                rc = VLESS_ERR_CRYPTO;
                goto cleanup;
            }
        }
        ecdhe_secret_len = 32;
    }

    /* Early Secret = HKDF-Extract(salt=0, IKM=0) [no PSK] */
    rc = hkdf_extract_ex(r->hash_md, r->hash_len, NULL, 0, zeros, (size_t)r->hash_len, early_secret);
    if (rc != VLESS_OK) goto cleanup;

    /* derived_secret = Derive-Secret(early_secret, "derived", "") */
    rc = derive_secret_ex(r->hash_md, r->hash_len, early_secret, "derived", empty_hash, derived1);
    if (rc != VLESS_OK) goto cleanup;

    /* Handshake Secret = HKDF-Extract(salt=derived1, IKM=ecdhe_secret) */
    rc = hkdf_extract_ex(r->hash_md, r->hash_len, derived1, (size_t)r->hash_len,
                          ecdhe_secret, ecdhe_secret_len, handshake_secret);
    if (rc != VLESS_OK) goto cleanup;

    /* Transcript hash up to ServerHello */
    rc = transcript_hash_current(r, hash_hello);
    if (rc != VLESS_OK) goto cleanup;

    /* Client/Server handshake traffic secrets */
    rc = derive_secret_ex(r->hash_md, r->hash_len, handshake_secret, "c hs traffic", hash_hello, c_hs_traffic);
    if (rc != VLESS_OK) goto cleanup;
    rc = derive_secret_ex(r->hash_md, r->hash_len, handshake_secret, "s hs traffic", hash_hello, s_hs_traffic);
    if (rc != VLESS_OK) goto cleanup;

    /* Handshake traffic keys */
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, c_hs_traffic, "key", NULL, 0, r->c_hs_key, (size_t)r->key_len);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, c_hs_traffic, "iv",  NULL, 0, r->c_hs_iv,  TLS_GCM_IV_LEN);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, s_hs_traffic, "key", NULL, 0, r->s_hs_key, (size_t)r->key_len);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, s_hs_traffic, "iv",  NULL, 0, r->s_hs_iv,  TLS_GCM_IV_LEN);
    if (rc != VLESS_OK) goto cleanup;

    /* Set handshake keys for reading server's encrypted messages */
    r->cur_read_key = r->s_hs_key;
    r->cur_read_iv = r->s_hs_iv;
    r->cur_write_key = r->c_hs_key;
    r->cur_write_iv = r->c_hs_iv;
    r->read_seq = 0;
    r->write_seq = 0;

    /* ─── Process encrypted handshake messages ─── */
    /* EncryptedExtensions, Certificate, CertificateVerify, Finished */
    {
        uint8_t hs_type;
        const uint8_t *body;
        size_t body_len;

        /* Read EncryptedExtensions — validate structure but don't process
         * individual extensions. REALITY authenticates the server via X25519
         * shared secret, not PKI, so extension contents are not security-relevant. */
        rc = read_hs_message(r, &hs_type, &body, &body_len);
        if (rc != VLESS_OK) goto cleanup;
        if (hs_type != TLS_HS_ENCRYPTED_EXT) {
            vless_set_error("Expected EncryptedExtensions, got %d", hs_type);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }
        /* Validate extensions_length matches body */
        if (body_len < 2) {
            vless_set_error("EncryptedExtensions too short: %zu", body_len);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }
        {
            size_t ee_ext_len = ((size_t)body[0] << 8) | body[1];
            if (ee_ext_len + 2 != body_len) {
                vless_set_error("EncryptedExtensions length mismatch: declared %zu, body %zu",
                                ee_ext_len, body_len - 2);
                rc = VLESS_ERR_PROTOCOL;
                goto cleanup;
            }
        }
        rc = consume_hs_message(r);
        if (rc != VLESS_OK) goto cleanup;

        /* Read Certificate -- save body for CertificateVerify validation */
        rc = read_hs_message(r, &hs_type, &body, &body_len);
        if (rc != VLESS_OK) goto cleanup;
        if (hs_type != TLS_HS_CERTIFICATE) {
            vless_set_error("Expected Certificate, got %d", hs_type);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* Save Certificate body before consume_hs_message shifts hs_buf */
        saved_cert_body_len = body_len;
        if (body_len > 0) {
            saved_cert_body = malloc(body_len);
            if (!saved_cert_body) {
                vless_set_error("Out of memory saving certificate");
                rc = VLESS_ERR_NOMEM;
                goto cleanup;
            }
            memcpy(saved_cert_body, body, body_len);
        }

        rc = consume_hs_message(r);
        if (rc != VLESS_OK) goto cleanup;

        /* Transcript hash after Certificate (input to CertificateVerify) */
        rc = transcript_hash_current(r, hash_pre_cv);
        if (rc != VLESS_OK) goto cleanup;

        /* Read CertificateVerify */
        rc = read_hs_message(r, &hs_type, &body, &body_len);
        if (rc != VLESS_OK) goto cleanup;
        if (hs_type != TLS_HS_CERT_VERIFY) {
            vless_set_error("Expected CertificateVerify, got %d", hs_type);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* Verify the CertificateVerify signature against the certificate */
        rc = verify_certificate_verify(saved_cert_body, saved_cert_body_len,
                                        body, body_len,
                                        hash_pre_cv, r->hash_len);
        if (rc != VLESS_OK) goto cleanup;

        rc = consume_hs_message(r);
        if (rc != VLESS_OK) goto cleanup;

        /* Get transcript hash before Finished (for verifying server Finished) */
        rc = transcript_hash_current(r, hash_pre_finished);
        if (rc != VLESS_OK) goto cleanup;

        /* Read server Finished */
        rc = read_hs_message(r, &hs_type, &body, &body_len);
        if (rc != VLESS_OK) goto cleanup;
        if (hs_type != TLS_HS_FINISHED) {
            vless_set_error("Expected Finished, got %d", hs_type);
            rc = VLESS_ERR_PROTOCOL;
            goto cleanup;
        }

        /* Verify server Finished */
        rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, s_hs_traffic,
                                   "finished", NULL, 0, finished_key, (size_t)r->hash_len);
        if (rc != VLESS_OK) goto cleanup;
        rc = hmac_hash(r->hash_md, finished_key, (size_t)r->hash_len,
                       hash_pre_finished, (size_t)r->hash_len, expected_verify, NULL);
        if (rc != VLESS_OK) goto cleanup;

        if (body_len != (size_t)r->hash_len ||
            CRYPTO_memcmp(body, expected_verify, (size_t)r->hash_len) != 0) {
            vless_set_error("Server Finished verification failed");
            rc = VLESS_ERR_AUTH;
            goto cleanup;
        }
        rc = consume_hs_message(r);
        if (rc != VLESS_OK) goto cleanup;
    }

    /* ─── Send client Finished ─── */

    /* Transcript hash including server Finished */
    rc = transcript_hash_current(r, hash_with_sf);
    if (rc != VLESS_OK) goto cleanup;

    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, c_hs_traffic,
                               "finished", NULL, 0, c_finished_key, (size_t)r->hash_len);
    if (rc != VLESS_OK) goto cleanup;
    rc = hmac_hash(r->hash_md, c_finished_key, (size_t)r->hash_len,
                   hash_with_sf, (size_t)r->hash_len, c_verify_data, NULL);
    if (rc != VLESS_OK) goto cleanup;

    /* Build Finished handshake message */
    {
        uint8_t c_finished_msg[4 + TLS_HASH_LEN_384];
        c_finished_msg[0] = TLS_HS_FINISHED;
        c_finished_msg[1] = 0;
        c_finished_msg[2] = 0;
        c_finished_msg[3] = (uint8_t)r->hash_len;
        memcpy(c_finished_msg + 4, c_verify_data, (size_t)r->hash_len);

        /* Add client Finished to transcript */
        if (!EVP_DigestUpdate(r->transcript, c_finished_msg, 4 + (size_t)r->hash_len)) { OPENSSL_cleanse(c_finished_msg, sizeof(c_finished_msg)); rc = VLESS_ERR_CRYPTO; goto cleanup; }

        /* Send client Finished (encrypted with handshake key) */
        rc = tls_write_encrypted(r, TLS_RECORD_HANDSHAKE, c_finished_msg, 4 + (size_t)r->hash_len);
        OPENSSL_cleanse(c_finished_msg, sizeof(c_finished_msg));
        if (rc != VLESS_OK) goto cleanup;
    }

    /* ─── Derive application traffic keys ─── */
    /*
     * RFC 8446 Section 7.1: application traffic secrets use
     * Transcript-Hash(ClientHello...server Finished) — i.e. hash_with_sf,
     * computed BEFORE client Finished was added to the transcript.
     */

    rc = derive_secret_ex(r->hash_md, r->hash_len, handshake_secret, "derived", empty_hash, derived2);
    if (rc != VLESS_OK) goto cleanup;

    rc = hkdf_extract_ex(r->hash_md, r->hash_len, derived2, (size_t)r->hash_len,
                          zeros, (size_t)r->hash_len, master_secret);
    if (rc != VLESS_OK) goto cleanup;

    rc = derive_secret_ex(r->hash_md, r->hash_len, master_secret, "c ap traffic", hash_with_sf, c_ap_traffic);
    if (rc != VLESS_OK) goto cleanup;
    rc = derive_secret_ex(r->hash_md, r->hash_len, master_secret, "s ap traffic", hash_with_sf, s_ap_traffic);
    if (rc != VLESS_OK) goto cleanup;

    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, c_ap_traffic, "key", NULL, 0, r->c_app_key, (size_t)r->key_len);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, c_ap_traffic, "iv",  NULL, 0, r->c_app_iv,  TLS_GCM_IV_LEN);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, s_ap_traffic, "key", NULL, 0, r->s_app_key, (size_t)r->key_len);
    if (rc != VLESS_OK) goto cleanup;
    rc = hkdf_expand_label_ex(r->hash_md, r->hash_len, s_ap_traffic, "iv",  NULL, 0, r->s_app_iv,  TLS_GCM_IV_LEN);
    if (rc != VLESS_OK) goto cleanup;

    /* Cleanse handshake keys before switching to application keys.
     * Handshake keys are no longer needed and should not persist in memory. */
    OPENSSL_cleanse(r->c_hs_key, sizeof(r->c_hs_key));
    OPENSSL_cleanse(r->c_hs_iv, sizeof(r->c_hs_iv));
    OPENSSL_cleanse(r->s_hs_key, sizeof(r->s_hs_key));
    OPENSSL_cleanse(r->s_hs_iv, sizeof(r->s_hs_iv));

    /* Switch to application keys */
    r->cur_read_key = r->s_app_key;
    r->cur_read_iv = r->s_app_iv;
    r->cur_write_key = r->c_app_key;
    r->cur_write_iv = r->c_app_iv;
    r->read_seq = 0;
    r->write_seq = 0;

cleanup:
    OPENSSL_cleanse(server_ks_data, sizeof(server_ks_data));
    OPENSSL_cleanse(ecdhe_secret, sizeof(ecdhe_secret));
    OPENSSL_cleanse(early_secret, sizeof(early_secret));
    OPENSSL_cleanse(derived1, sizeof(derived1));
    OPENSSL_cleanse(derived2, sizeof(derived2));
    OPENSSL_cleanse(handshake_secret, sizeof(handshake_secret));
    OPENSSL_cleanse(master_secret, sizeof(master_secret));
    OPENSSL_cleanse(c_hs_traffic, sizeof(c_hs_traffic));
    OPENSSL_cleanse(s_hs_traffic, sizeof(s_hs_traffic));
    OPENSSL_cleanse(c_ap_traffic, sizeof(c_ap_traffic));
    OPENSSL_cleanse(s_ap_traffic, sizeof(s_ap_traffic));
    OPENSSL_cleanse(hash_hello, sizeof(hash_hello));
    OPENSSL_cleanse(hash_pre_finished, sizeof(hash_pre_finished));
    OPENSSL_cleanse(hash_with_sf, sizeof(hash_with_sf));
    OPENSSL_cleanse(finished_key, sizeof(finished_key));
    OPENSSL_cleanse(c_finished_key, sizeof(c_finished_key));
    OPENSSL_cleanse(c_verify_data, sizeof(c_verify_data));
    OPENSSL_cleanse(expected_verify, sizeof(expected_verify));
    OPENSSL_cleanse(hash_pre_cv, sizeof(hash_pre_cv));
    if (saved_cert_body) {
        OPENSSL_cleanse(saved_cert_body, saved_cert_body_len);
        free(saved_cert_body);
        saved_cert_body = NULL;
    }
    OPENSSL_cleanse(r->eph_private, sizeof(r->eph_private));
    OPENSSL_cleanse(r->mlkem_eph_private, sizeof(r->mlkem_eph_private));
    OPENSSL_cleanse(r->client_random, sizeof(r->client_random));
    /* Cleanse handshake buffers containing client_random and REALITY auth material */
    if (ch_msg) { OPENSSL_cleanse(ch_msg, CH_BUF_SIZE); free(ch_msg); ch_msg = NULL; }
    if (sh_buf) { OPENSSL_cleanse(sh_buf, sh_buf_cap); free(sh_buf); sh_buf = NULL; }
    if (rc != VLESS_OK) {
        /* Best-effort TLS alert on handshake failure (Chrome sends alerts;
         * omitting them is a detectable fingerprint deviation).
         * Encrypted if handshake keys are installed, plaintext otherwise. */
        uint8_t alert[2] = {2, 40}; /* fatal(2), handshake_failure(40) */
        if (r->cur_write_key && r->cur_write_iv && r->aead_cipher) {
            (void)tls_write_encrypted(r, TLS_RECORD_ALERT, alert, 2);
        } else if (r->fd >= 0) {
            (void)tls_write_record(r, TLS_RECORD_ALERT, alert, 2);
        }
        conn->reality = NULL;
        vless_reality_free(r);
    }
    return rc;
}

/* ─── TLS close_notify ──────────────────────────────────────────────────── */

/*
 * Send a TLS close_notify alert before closing the connection.
 * This signals a clean shutdown to the peer, matching real browser behavior.
 */
VLESS_INTERNAL
void vless_reality_close_notify(vless_reality_ctx_t *r) {
    if (!r || r->fd < 0 || !r->cur_write_key || !r->cur_write_iv || !r->aead_cipher) return;
    /* TLS close_notify alert: level=warning(1), description=close_notify(0).
     * Return value intentionally ignored: close_notify is best-effort during
     * teardown — there is nothing useful to do if the write fails. */
    uint8_t alert[2] = {1, 0};
    int wrc = tls_write_encrypted(r, TLS_RECORD_ALERT, alert, 2);

    /* Best-effort read of server's close_notify for bidirectional shutdown.
     * This matches Chrome/plain-TLS behavior (SSL_shutdown retry loop in
     * vless_close) and avoids server-side RST that DPI could fingerprint.
     * Use a short timeout to avoid delaying connection teardown. */
    if (wrc == VLESS_OK && r->cur_read_key && r->cur_read_iv) {
        int saved_timeout = r->io_timeout_ms;
        r->io_timeout_ms = 500; /* matches plain TLS shutdown timeout */
        uint8_t inner_type;
        size_t resp_len = 0;
        /* Use app_buf (16KB+) instead of a small stack buffer so that
         * NewSessionTicket or other large records don't cause spurious
         * failures during the bidirectional shutdown sequence. */
        (void)tls_read_encrypted(r, &inner_type, r->app_buf, sizeof(r->app_buf), &resp_len);
        if (resp_len > 0) OPENSSL_cleanse(r->app_buf, resp_len);
        r->io_timeout_ms = saved_timeout;
    }
}

/* ─── REALITY send/recv (application data through encrypted TLS records) ─── */

VLESS_INTERNAL
int vless_reality_send(vless_conn_t *conn, const void *data, size_t len) {
    vless_reality_ctx_t *r = conn->reality;
    if (!r) return VLESS_ERR_INVALID_ARG;
    if (!data && len > 0) return VLESS_ERR_INVALID_ARG;
    if (len > (size_t)INT_MAX) len = (size_t)INT_MAX;

    /* Chunk into max-size TLS records */
    const uint8_t *p = data;
    size_t remaining = len;
    size_t total_sent = 0;

    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > TLS_MAX_RECORD_PAYLOAD - 1) /* -1 for content type */
            chunk = TLS_MAX_RECORD_PAYLOAD - 1;

        int rc = tls_write_encrypted(r, TLS_RECORD_APPLICATION_DATA, p, chunk);
        if (rc != VLESS_OK) {
            conn->state = VLESS_STATE_CLOSED;
            /* Return bytes already sent if any; otherwise propagate error.
             * Caller cannot retry (state is CLOSED) but knows how much data
             * the peer received. */
            return total_sent > 0
                ? (total_sent > (size_t)INT_MAX ? INT_MAX : (int)total_sent)
                : rc;
        }

        p += chunk;
        remaining -= chunk;
        total_sent += chunk;
    }

    return total_sent > (size_t)INT_MAX ? INT_MAX : (int)total_sent;
}

VLESS_INTERNAL
int vless_reality_recv(vless_conn_t *conn, void *buf, size_t buf_len) {
    vless_reality_ctx_t *r = conn->reality;
    if (!r) return VLESS_ERR_INVALID_ARG;
    if (buf_len == 0) return VLESS_ERR_INVALID_ARG;
    if (buf_len > (size_t)INT_MAX) buf_len = (size_t)INT_MAX;

    /* Return buffered data first */
    if (r->app_buf_len > r->app_buf_off) {
        size_t avail = r->app_buf_len - r->app_buf_off;
        size_t copy = avail < buf_len ? avail : buf_len;
        memcpy(buf, r->app_buf + r->app_buf_off, copy);
        r->app_buf_off += copy;
        return (int)copy;
    }

    /* Read encrypted records, skipping non-application-data (e.g. NewSessionTicket).
     * Only return 0 for actual EOF, never for skipped records. */
    uint8_t inner_type;
    size_t dec_len;

    for (int skip_count = 0; skip_count < VLESS_MAX_SKIP_RECORDS; skip_count++) {
        int rc = tls_read_encrypted(r, &inner_type, r->app_buf, sizeof(r->app_buf), &dec_len);
        if (rc != VLESS_OK) return rc;

        if (inner_type == TLS_RECORD_ALERT) {
            if (dec_len >= 2) {
                vless_set_error("TLS alert: level=%d desc=%d", r->app_buf[0], r->app_buf[1]);
                /* close_notify (level=1, desc=0) is a clean shutdown.
                 * All other alerts are fatal errors per RFC 8446 Section 6. */
                conn->state = VLESS_STATE_CLOSED;
                if (r->app_buf[1] == 0)
                    return VLESS_ERR_CLOSED;
                return VLESS_ERR_TLS;
            }
            vless_set_error("TLS alert (truncated)");
            conn->state = VLESS_STATE_CLOSED;
            return VLESS_ERR_TLS;
        }

        if (inner_type == TLS_RECORD_APPLICATION_DATA) {
            if (dec_len == 0) continue; /* skip zero-length records */
            r->app_buf_len = dec_len;
            r->app_buf_off = 0;

            size_t copy = dec_len < buf_len ? dec_len : buf_len;
            memcpy(buf, r->app_buf, copy);
            r->app_buf_off = copy;
            return (int)copy;
        }

        /* Detect KeyUpdate (handshake type 24) — not implemented, but we must
         * not silently skip it: the server switches keys after sending it, so
         * all subsequent records would fail AEAD decryption. */
        if (inner_type == TLS_RECORD_HANDSHAKE && dec_len >= 1 && r->app_buf[0] == 24) {
            vless_set_error("Server sent KeyUpdate (not supported); closing connection");
            conn->state = VLESS_STATE_CLOSED;
            return VLESS_ERR_PROTOCOL;
        }

        /* Other non-app-data records (e.g. NewSessionTicket) — skip and read next */
    }

    vless_set_error("Too many non-application-data records");
    return VLESS_ERR_PROTOCOL;
}

VLESS_INTERNAL
void vless_reality_free(vless_reality_ctx_t *ctx) {
    if (!ctx) return;
    /* Free the EVP_MD_CTX for transcript hash */
    if (ctx->transcript) {
        EVP_MD_CTX_free(ctx->transcript);
        ctx->transcript = NULL;
    }
    /* Free ML-KEM-768 key if allocated */
    if (ctx->mlkem_key) {
        EVP_PKEY_free(ctx->mlkem_key);
        ctx->mlkem_key = NULL;
    }
    /* Free P-256/P-384 ECDH keys if allocated */
    if (ctx->ecdh_p256_key) {
        EVP_PKEY_free(ctx->ecdh_p256_key);
        ctx->ecdh_p256_key = NULL;
    }
    if (ctx->ecdh_p384_key) {
        EVP_PKEY_free(ctx->ecdh_p384_key);
        ctx->ecdh_p384_key = NULL;
    }
    /* Free pre-allocated ciphertext buffer */
    if (ctx->ct_buf) {
        OPENSSL_cleanse(ctx->ct_buf, ctx->ct_buf_cap);
        free(ctx->ct_buf);
        ctx->ct_buf = NULL;
    }
    /* Free pre-allocated write buffer */
    if (ctx->wt_buf) {
        OPENSSL_cleanse(ctx->wt_buf, ctx->wt_buf_cap);
        free(ctx->wt_buf);
        ctx->wt_buf = NULL;
    }
    /* Clear all key material (OPENSSL_cleanse cannot be optimized out) */
    OPENSSL_cleanse(ctx, sizeof(*ctx));
    free(ctx);
}
