/*
 * vless.c - VLESS protocol core + Vision flow
 *
 * Supports two transport modes:
 *   1. Plain TLS (BoringSSL) - basic, detectable by DPI
 *   2. REALITY - manual TLS 1.3, Chrome fingerprint, undetectable
 *
 * Vision flow adds random padding to the first N messages
 * to resist traffic analysis / pattern matching.
 */

/* _POSIX_C_SOURCE for standard APIs (clock_gettime, getaddrinfo, etc.) */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200112L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include "vless_internal.h"

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <poll.h>
#include <limits.h>
#include <signal.h>
#include <pthread.h>

#include <openssl/rand.h>
#include <openssl/crypto.h> /* OPENSSL_cleanse */

#define VLESS_ZERO_IO_MAX_RETRIES 100
#define VLESS_MAX_HOSTNAME_LEN    253  /* DNS maximum hostname length */

/* ABI guard: catch accidental struct layout changes at compile time.
 * Uses offsetof(_reserved) to detect field insertion/removal/reordering
 * without being fragile to cross-platform padding differences. */
#if UINTPTR_MAX == UINT64_MAX /* 64-bit platforms (primary target) */
_Static_assert(offsetof(vless_reality_config_t, _reserved) == 28,
               "ABI break: vless_reality_config_t layout changed");
_Static_assert(offsetof(vless_tls_config_t, _reserved) == 32,
               "ABI break: vless_tls_config_t layout changed");
_Static_assert(offsetof(vless_config_t, _reserved) == 148,
               "ABI break: vless_config_t layout changed");
#endif

/* safe_strerror() is provided by vless_internal.h */

/* ─── SIGPIPE suppression (once per process, not per connection) ── */
/* On macOS/BSD, SO_NOSIGPIPE is set per-socket in vless_tcp_connect().
 * On Linux, there is no per-socket equivalent; we must set SIGPIPE to
 * SIG_IGN process-wide (MSG_NOSIGNAL handles REALITY sends, but OpenSSL's
 * internal send() calls in plain TLS mode cannot use it).
 * NOTE: This overrides any application-level SIGPIPE handler. Library
 * consumers that rely on SIGPIPE should be aware of this side effect. */
#ifndef SO_NOSIGPIPE
static pthread_once_t sigpipe_once = PTHREAD_ONCE_INIT;
static void ignore_sigpipe(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sigemptyset(&sa.sa_mask);
    sa.sa_handler = SIG_IGN;
    (void)sigaction(SIGPIPE, &sa, NULL);
}
#endif

/* ─── Thread-local error handling ─────────────────────────────── */

/* Forward declaration needed by vless_clear_error */

/* Thread-local storage portability (C11 _Thread_local is always available;
 * MSVC uses __declspec(thread) instead) */
#if defined(_MSC_VER)
#define VLESS_THREAD_LOCAL __declspec(thread)
#else
#define VLESS_THREAD_LOCAL _Thread_local
#endif

static VLESS_THREAD_LOCAL char tl_error_buf[512];

VLESS_INTERNAL
void vless_set_error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(tl_error_buf, sizeof(tl_error_buf), fmt, ap);
    va_end(ap);
}

VLESS_API const char *vless_last_error(void) {
    return tl_error_buf;
}

VLESS_API void vless_clear_error(void) {
    tl_error_buf[0] = '\0';
}

VLESS_API const char *vless_version(void) {
    return VLESS_VERSION_STRING;
}

/* Compile-time check: vless.h version macros must match CMakeLists.txt.
 * VLESS_CMAKE_VERSION_* are passed via target_compile_definitions(). */
#if defined(VLESS_CMAKE_VERSION_MAJOR)
_Static_assert(VLESS_VERSION_MAJOR == VLESS_CMAKE_VERSION_MAJOR &&
               VLESS_VERSION_MINOR == VLESS_CMAKE_VERSION_MINOR &&
               VLESS_VERSION_PATCH == VLESS_CMAKE_VERSION_PATCH,
               "Version mismatch between vless.h and CMakeLists.txt");
#endif

/* ─── Poll helpers for non-blocking I/O ──────────────────────── */

/* Common poll implementation for both read and write directions */
static int vless_poll_fd(int fd, short events, int timeout_ms, const char *dir) {
    if (fd < 0) return VLESS_ERR_IO;
    int timeout = timeout_ms > 0 ? timeout_ms : 30000;

    struct timespec deadline;
    int have_deadline = (clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    if (have_deadline) {
        deadline.tv_sec += timeout / 1000;
        deadline.tv_nsec += (long)(timeout % 1000) * 1000000L;
        if (deadline.tv_nsec >= 1000000000L) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000L;
        }
    }

    for (;;) {
        struct pollfd pfd = {.fd = fd, .events = events};
        int remaining = timeout;
        if (have_deadline) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                int64_t diff_s = (int64_t)deadline.tv_sec - (int64_t)now.tv_sec;
                long diff_ns = deadline.tv_nsec - now.tv_nsec;
                if (diff_ns < 0) { diff_s--; diff_ns += 1000000000L; }
                int64_t rem64 = diff_s * 1000 + diff_ns / 1000000;
                remaining = rem64 <= 0 ? 0 : (rem64 > INT_MAX ? INT_MAX : (int)rem64);
                if (remaining <= 0) {
                    vless_set_error("poll_%s timed out (fd=%d)", dir, fd);
                    return VLESS_ERR_TIMEOUT;
                }
            }
        }
        int ret = poll(&pfd, 1, remaining);
        if (ret < 0) {
            if (errno == EINTR) continue;
            char errbuf[64];
            safe_strerror(errno, errbuf, sizeof(errbuf));
            vless_set_error("poll_%s failed: %s (fd=%d)", dir, errbuf, fd);
            return VLESS_ERR_IO;
        }
        if (ret == 0) {
            vless_set_error("poll_%s timed out (fd=%d)", dir, fd);
            return VLESS_ERR_TIMEOUT;
        }
        if (pfd.revents & (POLLERR | POLLNVAL)) {
            vless_set_error("poll_%s error event (fd=%d, revents=0x%x)", dir, fd, pfd.revents);
            return VLESS_ERR_IO;
        }
        /* POLLHUP: for write, treat as error; for read, data may still be available */
        if ((events & POLLOUT) && (pfd.revents & POLLHUP)) {
            vless_set_error("poll_%s: connection hung up (fd=%d)", dir, fd);
            return VLESS_ERR_IO;
        }
        return VLESS_OK;
    }
}

VLESS_INTERNAL
int vless_poll_read(int fd, int timeout_ms) {
    return vless_poll_fd(fd, POLLIN, timeout_ms, "read");
}

VLESS_INTERNAL
int vless_poll_write(int fd, int timeout_ms) {
    return vless_poll_fd(fd, POLLOUT, timeout_ms, "write");
}

/* Check whether a monotonic-clock deadline has been exceeded.
 * Returns 0 if no deadline is set or clock_gettime fails (fail-open). */
static inline int deadline_exceeded(int has_deadline, const struct timespec *dl) {
    if (!has_deadline) return 0;
    struct timespec now;
    if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) return 0;
    return (now.tv_sec > dl->tv_sec ||
            (now.tv_sec == dl->tv_sec && now.tv_nsec >= dl->tv_nsec));
}

/* ─── UUID parsing ────────────────────────────────────────────── */

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

VLESS_API int vless_parse_uuid(const char *uuid_str, uint8_t uuid_out[16]) {
    if (!uuid_str || !uuid_out) {
        vless_set_error("UUID: NULL argument");
        return VLESS_ERR_INVALID_ARG;
    }
    memset(uuid_out, 0, 16); /* ensure clean output on any error path */
    size_t len = strlen(uuid_str);
    if (len != 36) {
        vless_set_error("UUID must be 36 characters, got %zu", len);
        return VLESS_ERR_UUID;
    }

    static const int dash_pos[] = {8, 13, 18, 23};
    for (int i = 0; i < 4; i++) {
        if (uuid_str[dash_pos[i]] != '-') {
            vless_set_error("UUID missing dash at position %d", dash_pos[i]);
            return VLESS_ERR_UUID;
        }
    }

    int out_idx = 0;
    for (int i = 0; i < 36; i++) {
        if (uuid_str[i] == '-') continue;
        int hi = hex_digit(uuid_str[i]);
        int lo = hex_digit(uuid_str[i + 1]);
        if (hi < 0 || lo < 0) {
            vless_set_error("UUID invalid hex at position %d", i);
            return VLESS_ERR_UUID;
        }
        if (out_idx >= 16) {
            vless_set_error("UUID too many hex digits");
            return VLESS_ERR_UUID;
        }
        uuid_out[out_idx++] = (uint8_t)((hi << 4) | lo);
        i++;
    }
    if (out_idx != 16) {
        vless_set_error("UUID produced %d bytes instead of 16", out_idx);
        return VLESS_ERR_UUID;
    }
    return VLESS_OK;
}

/* ─── TCP connection ──────────────────────────────────────────── */

VLESS_INTERNAL
int vless_tcp_connect(const char *host, uint16_t port, int timeout_ms, int *fd_out) {
    *fd_out = -1;
    if (!host || host[0] == '\0') {
        vless_set_error("vless_tcp_connect: host is NULL or empty");
        return VLESS_ERR_INVALID_ARG;
    }
    if (port == 0) {
        vless_set_error("vless_tcp_connect: port is 0");
        return VLESS_ERR_INVALID_ARG;
    }
    if (timeout_ms > 300000) timeout_ms = 300000; /* cap at 5 minutes */
    struct addrinfo hints, *res, *rp;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[6];
    snprintf(port_str, sizeof(port_str), "%u", port);

    int gai_err = getaddrinfo(host, port_str, &hints, &res);
    if (gai_err != 0) {
        vless_set_error("DNS failed for %s: %s", host, gai_strerror(gai_err));
        return (gai_err == EAI_MEMORY) ? VLESS_ERR_NOMEM : VLESS_ERR_RESOLVE;
    }

    int fd = -1;
    int first_errno = 0; /* track most meaningful error (H-5) */

    /* Compute aggregate deadline across all addresses so total connect time
     * never exceeds the caller's timeout, even for multi-homed hosts. */
    int aggregate_ms = (timeout_ms > 0) ? timeout_ms : 15000;
    struct timespec agg_start;
    int have_agg = (clock_gettime(CLOCK_MONOTONIC, &agg_start) == 0);

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        /* Check aggregate deadline before trying next address */
        int remaining_ms = aggregate_ms;
        if (have_agg) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                int64_t elapsed = ((int64_t)now.tv_sec - (int64_t)agg_start.tv_sec) * 1000 +
                                  (now.tv_nsec - agg_start.tv_nsec) / 1000000;
                remaining_ms = elapsed >= (int64_t)aggregate_ms ? 0 : aggregate_ms - (int)elapsed;
                if (remaining_ms <= 0) {
                    if (!first_errno) first_errno = ETIMEDOUT;
                    break;
                }
            }
        }

#ifdef SOCK_CLOEXEC
        fd = socket(rp->ai_family, rp->ai_socktype | SOCK_CLOEXEC, rp->ai_protocol);
#else
        fd = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
        if (fd < 0) {
            if (!first_errno) first_errno = errno;
            continue;
        }

        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            if (!first_errno) first_errno = errno;
            close(fd); fd = -1; continue;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
            if (!first_errno) first_errno = errno;
            close(fd); fd = -1; continue;
        }
#ifndef SOCK_CLOEXEC
        (void)fcntl(fd, F_SETFD, FD_CLOEXEC); /* prevent fd leak on fork */
#endif

        int ret = connect(fd, rp->ai_addr, rp->ai_addrlen);
        if (ret == 0) {
            /* Keep socket non-blocking for poll()-based I/O */
            break;
        }

        if (errno == EINPROGRESS) {
            struct pollfd pfd = {.fd = fd, .events = POLLOUT};
            int poll_to = remaining_ms;
            struct timespec conn_start, conn_now;
            int have_start = (clock_gettime(CLOCK_MONOTONIC, &conn_start) == 0);
            int conn_remaining = poll_to;
            do {
                ret = poll(&pfd, 1, conn_remaining);
                if (ret < 0 && errno == EINTR) {
                    if (!have_start || clock_gettime(CLOCK_MONOTONIC, &conn_now) != 0) {
                        ret = 0; break; /* can't track time — treat as timeout */
                    }
                    int64_t elapsed64 = ((int64_t)conn_now.tv_sec - (int64_t)conn_start.tv_sec) * 1000 +
                                       (conn_now.tv_nsec - conn_start.tv_nsec) / 1000000;
                    conn_remaining = elapsed64 >= (int64_t)poll_to ? 0 : poll_to - (int)elapsed64;
                    if (conn_remaining <= 0) { ret = 0; break; }
                }
            } while (ret < 0 && errno == EINTR);

            if (ret > 0) {
                int sock_err = 0;
                socklen_t err_len = sizeof(sock_err);
                if (getsockopt(fd, SOL_SOCKET, SO_ERROR, &sock_err, &err_len) < 0 || sock_err != 0) {
                    int e = sock_err ? sock_err : errno;
                    if (!first_errno) first_errno = e;
                    close(fd); fd = -1;
                    continue;
                }
                /* Keep socket non-blocking for poll()-based I/O */
                break;
            } else if (ret == 0) {
                if (!first_errno) first_errno = ETIMEDOUT;
                close(fd); fd = -1;
                continue; /* try next address */
            }
        }
        int saved_errno = errno; /* save before close() may reset it */
        if (!first_errno) first_errno = saved_errno;
        close(fd); fd = -1;
        errno = saved_errno;
    }
    int connect_errno = first_errno ? first_errno : errno;
    freeaddrinfo(res);

    if (fd < 0) {
        {
            char errbuf[64];
            safe_strerror(connect_errno, errbuf, sizeof(errbuf));
            vless_set_error("Failed to connect to %s:%u: %s", host, port, errbuf);
        }
        return VLESS_ERR_CONNECT;
    }

    int val = 1;
    (void)setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &val, sizeof(val));
#ifdef SO_NOSIGPIPE
    if (setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &val, sizeof(val)) != 0) {
        vless_set_error("setsockopt(SO_NOSIGPIPE) failed: errno %d", errno);
        close(fd);
        return VLESS_ERR_IO;
    }
#else
    /* On Linux (no SO_NOSIGPIPE), ignore SIGPIPE process-wide once.
     * Uses pthread_once + sigaction instead of signal() per-connection to
     * avoid repeatedly overwriting the disposition and to be async-signal-safe. */
    pthread_once(&sigpipe_once, ignore_sigpipe);
#endif
    *fd_out = fd;
    return VLESS_OK;
}

/* ─── Plain TLS (BoringSSL) ───────────────────────────────────── */

VLESS_INTERNAL
int vless_tls_init(vless_conn_t *conn, const vless_tls_config_t *cfg,
                   const char *server_host) {
    conn->ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!conn->ssl_ctx) {
        vless_set_error("SSL_CTX_new failed");
        return VLESS_ERR_TLS;
    }

    if (!SSL_CTX_set_min_proto_version(conn->ssl_ctx, TLS1_2_VERSION)) {
        vless_set_error("Failed to set minimum TLS version");
        goto tls_init_cleanup;
    }

    if (cfg->verify_peer) {
        if (cfg->ca_path) {
            if (SSL_CTX_load_verify_locations(conn->ssl_ctx, cfg->ca_path, NULL) != 1) {
                vless_set_error("Failed to load CA from %s", cfg->ca_path);
                goto tls_init_cleanup;
            }
        } else {
            if (!SSL_CTX_set_default_verify_paths(conn->ssl_ctx)) {
                vless_set_error("Failed to load system CA certificates");
                goto tls_init_cleanup;
            }
        }
        SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_PEER, NULL);
    } else {
        SSL_CTX_set_verify(conn->ssl_ctx, SSL_VERIFY_NONE, NULL);
    }

    conn->ssl = SSL_new(conn->ssl_ctx);
    if (!conn->ssl) { vless_set_error("SSL_new failed"); goto tls_init_cleanup; }

    const char *sni = cfg->sni ? cfg->sni : server_host;
    if (!SSL_set_tlsext_host_name(conn->ssl, sni)) {
        vless_set_error("Failed to set TLS SNI: %s", sni);
        goto tls_init_cleanup;
    }

    /* Hostname verification: ensure the server certificate matches the SNI.
     * Without this, any valid certificate from a trusted CA would be accepted,
     * making MITM trivial. */
    if (cfg->verify_peer) {
        if (!SSL_set1_host(conn->ssl, sni)) {
            vless_set_error("Failed to set hostname verification: %s", sni);
            goto tls_init_cleanup;
        }
    }

    if (cfg->alpn) {
        uint8_t alpn_buf[256];
        size_t alpn_len = 0;
        const char *p = cfg->alpn;
        while (*p && alpn_len < sizeof(alpn_buf) - 1) {
            const char *comma = strchr(p, ',');
            size_t plen = comma ? (size_t)(comma - p) : strlen(p);
            if (plen == 0) {
                if (!comma) break; /* trailing comma: stop to avoid reading past NUL */
                p += 1; continue;  /* skip empty segments (e.g. "h2,,http/1.1") */
            }
            if (plen > 255) {
                vless_set_error("ALPN protocol name too long: %zu", plen);
                goto tls_init_cleanup;
            }
            if (alpn_len + 1 + plen > sizeof(alpn_buf)) {
                vless_set_error("ALPN list too long to fit in buffer");
                goto tls_init_cleanup;
            }
            alpn_buf[alpn_len++] = (uint8_t)plen;
            memcpy(alpn_buf + alpn_len, p, plen);
            alpn_len += plen;
            p += plen + (comma ? 1 : 0);
            if (!comma) break;
        }
        /* Detect truncation: protocols remain but buffer is full */
        if (*p) {
            vless_set_error("ALPN list too long to fit in buffer");
            goto tls_init_cleanup;
        }
        if (alpn_len == 0) {
            vless_set_error("ALPN list is empty after parsing");
            goto tls_init_cleanup;
        }
        if (SSL_set_alpn_protos(conn->ssl, alpn_buf, (unsigned int)alpn_len) != 0) {
            vless_set_error("SSL_set_alpn_protos failed");
            goto tls_init_cleanup;
        }
    }

    if (!SSL_set_fd(conn->ssl, conn->fd)) {
        vless_set_error("SSL_set_fd failed");
        goto tls_init_cleanup;
    }
    return VLESS_OK;

tls_init_cleanup:
    if (conn->ssl) { SSL_free(conn->ssl); conn->ssl = NULL; }
    if (conn->ssl_ctx) { SSL_CTX_free(conn->ssl_ctx); conn->ssl_ctx = NULL; }
    return VLESS_ERR_TLS;
}

VLESS_INTERNAL
int vless_tls_handshake(vless_conn_t *conn) {
    /* Overall handshake deadline: prevents a server that alternates between
     * WANT_READ and WANT_WRITE from keeping the handshake going indefinitely,
     * even though each individual poll has its own timeout. */
    struct timespec deadline;
    int have_deadline = (clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
    int64_t total_timeout_ms = conn->io_timeout_ms > 0
        ? (int64_t)conn->io_timeout_ms * 4 : 120000;
    if (total_timeout_ms > 300000) total_timeout_ms = 300000; /* cap at 5 minutes */
    /* Fallback: if clock_gettime fails, use an iteration counter instead */
    int max_iterations = (int)(total_timeout_ms / 50) + 100; /* ~50ms per poll */
    int iterations = 0;
    if (have_deadline) {
        deadline.tv_sec += (time_t)(total_timeout_ms / 1000);
        deadline.tv_nsec += (long)(total_timeout_ms % 1000) * 1000000;
        if (deadline.tv_nsec >= 1000000000) {
            deadline.tv_sec++;
            deadline.tv_nsec -= 1000000000;
        }
    }

    for (;;) {
        /* Always increment iteration counter as a secondary safeguard,
         * even when clock-based deadline is available (in case clock_gettime
         * starts failing mid-loop). */
        if (++iterations > max_iterations) {
            vless_set_error("TLS handshake: iteration limit exceeded (%d)", max_iterations);
            return VLESS_ERR_TIMEOUT;
        }
        /* Check clock-based deadline (primary) */
        if (have_deadline) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
                (now.tv_sec > deadline.tv_sec ||
                 (now.tv_sec == deadline.tv_sec && now.tv_nsec >= deadline.tv_nsec))) {
                vless_set_error("TLS handshake: overall timeout exceeded (%" PRId64 " ms)", total_timeout_ms);
                return VLESS_ERR_TIMEOUT;
            }
        }

        int ret = SSL_connect(conn->ssl);
        if (ret == 1) {
            CONN_STATE_STORE(conn, VLESS_STATE_CONNECTED);
            return VLESS_OK;
        }
        int saved_errno = errno;
        int e = SSL_get_error(conn->ssl, ret);
        if (e == SSL_ERROR_WANT_READ) {
            int rc = vless_poll_read(conn->fd, conn->io_timeout_ms);
            if (rc != VLESS_OK) return rc;
            continue;
        }
        if (e == SSL_ERROR_WANT_WRITE) {
            int rc = vless_poll_write(conn->fd, conn->io_timeout_ms);
            if (rc != VLESS_OK) return rc;
            continue;
        }
        if (e == SSL_ERROR_SYSCALL) {
            if (saved_errno == EINTR) continue;
            if (saved_errno == 0) {
                vless_set_error("TLS handshake: unexpected EOF from peer");
                return VLESS_ERR_TLS;
            }
            char errbuf[64];
            safe_strerror(saved_errno, errbuf, sizeof(errbuf));
            vless_set_error("TLS handshake failed: %s (errno=%d)", errbuf, saved_errno);
            return VLESS_ERR_TLS;
        }
        vless_set_error("TLS handshake failed: SSL error %d (errno=%d)", e, saved_errno);
        return VLESS_ERR_TLS;
    }
}

/* ─── VLESS request builder ───────────────────────────────────── */

static int vless_build_request(uint8_t *buf, size_t buf_size,
                                const uint8_t uuid[16],
                                const char *dest_host, uint16_t dest_port,
                                int vision_enabled,
                                size_t *out_len) {
    size_t offset = 0;
    struct in_addr ipv4;
    struct in6_addr ipv6;
    uint8_t addr_type;
    size_t addr_len;

    if (inet_pton(AF_INET, dest_host, &ipv4) == 1) {
        addr_type = VLESS_ADDR_IPV4; addr_len = 4;
    } else if (inet_pton(AF_INET6, dest_host, &ipv6) == 1) {
        addr_type = VLESS_ADDR_IPV6; addr_len = 16;
    } else {
        size_t dlen = strlen(dest_host);
        if (dlen == 0) {
            vless_set_error("Empty domain name");
            return VLESS_ERR_INVALID_ARG;
        }
        if (dlen > 255) {
            vless_set_error("Domain name too long: %zu bytes", dlen);
            return VLESS_ERR_INVALID_ARG;
        }
        addr_type = VLESS_ADDR_DOMAIN; addr_len = 1 + dlen;
    }

    /* Addons for Vision flow: protobuf { field1: "xtls-rprx-vision" } */
    static const uint8_t vision_addons[] = {
        0x0a, 0x10, /* protobuf: field 1, length 16 */
        'x','t','l','s','-','r','p','r','x','-','v','i','s','i','o','n'
    };
    size_t addons_len = vision_enabled ? sizeof(vision_addons) : 0;

    size_t total = 1 + 16 + 1 + addons_len + 1 + 2 + 1 + addr_len;
    if (total > buf_size) {
        vless_set_error("VLESS request header too large (%zu > %zu)", total, buf_size);
        return VLESS_ERR_NOMEM;
    }

    /* Version */
    buf[offset++] = VLESS_PROTO_VERSION;

    /* UUID */
    memcpy(buf + offset, uuid, 16); offset += 16;

    /* Addons */
    buf[offset++] = (uint8_t)addons_len;
    if (addons_len > 0) {
        memcpy(buf + offset, vision_addons, addons_len);
        offset += addons_len;
    }

    /* Command: TCP */
    buf[offset++] = VLESS_CMD_TCP;

    /* Port (big-endian) */
    buf[offset++] = (uint8_t)(dest_port >> 8);
    buf[offset++] = (uint8_t)(dest_port & 0xFF);

    /* Address */
    buf[offset++] = addr_type;
    switch (addr_type) {
        case VLESS_ADDR_IPV4:
            memcpy(buf + offset, &ipv4, 4); offset += 4;
            break;
        case VLESS_ADDR_IPV6:
            memcpy(buf + offset, &ipv6, 16); offset += 16;
            break;
        case VLESS_ADDR_DOMAIN: {
            size_t dlen = addr_len - 1; /* already validated <= 255 */
            buf[offset++] = (uint8_t)dlen;
            memcpy(buf + offset, dest_host, dlen); offset += dlen;
            break;
        }
        default:
            vless_set_error("VLESS request: unknown address type %d", addr_type);
            return VLESS_ERR_INVALID_ARG;
    }

    *out_len = offset;
    return VLESS_OK;
}

/* ─── Vision (XTLS-Vision) flow ──────────────────────────────── */

/*
 * Vision framing format (xray-core compatible):
 *   [UUID(16)] [Command(1)] [ContentLen(2)] [PaddingLen(2)] [Content] [Padding]
 *
 * UUID:       User UUID, sent on the first message then omitted (NULL).
 * Command:    0x00 = data continues, 0x01 = end, 0x02 = direct.
 * ContentLen: Big-endian length of actual data.
 * PaddingLen: Big-endian length of random padding.
 *
 * The first VISION_PADDING_INITIAL_COUNT messages carry this framing.
 * After that, data is sent directly without framing.
 */

/* Build a Vision-framed message. uuid may be NULL after the first message. */
static int vision_pad_data(const uint8_t *uuid, /* NULL after first msg */
                            const void *data, size_t data_len,
                            uint8_t *out, size_t out_cap, size_t *out_len) {
    if (data_len > 65535) {
        vless_set_error("vision_pad_data: data_len %zu exceeds uint16 max", data_len);
        return VLESS_ERR_INVALID_ARG;
    }
    if (data_len > 0 && !data) {
        vless_set_error("vision_pad_data: data is NULL with non-zero length");
        return VLESS_ERR_INVALID_ARG;
    }

    /* Rejection sampling to avoid modulo bias for uint16_t % 901 */
    uint16_t pad_len;
    unsigned int limit = 65536u - (65536u % (VISION_PADDING_MAX_LEN + 1));
    int attempts = 0;
    do {
        if (++attempts > 100) {
            vless_set_error("vision_pad_data: rejection sampling exceeded 100 attempts");
            return VLESS_ERR_CRYPTO;
        }
        if (RAND_bytes((uint8_t *)&pad_len, 2) != 1) {
            vless_set_error("vision_pad_data: RAND_bytes failed");
            return VLESS_ERR_CRYPTO;
        }
    } while (pad_len >= limit);
    pad_len = pad_len % (VISION_PADDING_MAX_LEN + 1);

    size_t header_size = (uuid ? 16 : 0) + 1 + 2 + 2;
    size_t total = header_size + data_len + pad_len;
    if (total > out_cap) {
        vless_set_error("vision_pad_data: frame size %zu exceeds buffer capacity %zu", total, out_cap);
        return VLESS_ERR_NOMEM;
    }

    size_t pos = 0;

    /* UUID (first message only) */
    if (uuid) {
        memcpy(out + pos, uuid, 16);
        pos += 16;
    }

    /* Command: 0x00 = data continues */
    out[pos++] = 0x00;

    /* Content length (big-endian) */
    out[pos++] = (uint8_t)(data_len >> 8);
    out[pos++] = (uint8_t)(data_len & 0xFF);

    /* Padding length (big-endian) */
    out[pos++] = (uint8_t)(pad_len >> 8);
    out[pos++] = (uint8_t)(pad_len & 0xFF);

    /* Content (memmove: safe if data and out overlap) */
    memmove(out + pos, data, data_len);
    pos += data_len;

    /* Random padding */
    if (pad_len > 0) {
        if (RAND_bytes(out + pos, pad_len) != 1) {
            vless_set_error("vision_pad_data: RAND_bytes failed for padding");
            OPENSSL_cleanse(out, pos + pad_len);
            return VLESS_ERR_CRYPTO;
        }
        pos += pad_len;
    }

    *out_len = pos;
    return VLESS_OK;
}

/*
 * Strip Vision framing from received data.
 * Sets *content_start and *content_len to the actual data within buf.
 * Also consumes UUID (16 bytes) + command header (5 bytes) from the front.
 * Returns VLESS_OK, or VLESS_ERR_PROTOCOL on malformed framing.
 */
static int vision_unpad_data(const uint8_t *buf, size_t buf_len,
                              const uint8_t *uuid, int *uuid_seen,
                              uint8_t *out_cmd,
                              uint16_t *out_content_len, uint16_t *out_pad_len) {
    size_t pos = 0;

    /* First response includes UUID */
    if (!*uuid_seen) {
        if (buf_len < 16) {
            vless_set_error("vision_unpad: buffer too short for UUID (%zu < 16)", buf_len);
            return VLESS_ERR_PROTOCOL;
        }
        /* Verify UUID matches */
        if (CRYPTO_memcmp(buf, uuid, 16) != 0) {
            vless_set_error("vision_unpad: UUID mismatch in server response");
            return VLESS_ERR_PROTOCOL;
        }
        pos += 16;
        *uuid_seen = 1;
    }

    /* Command header: cmd(1) + content_len(2) + pad_len(2) = 5 bytes */
    if (pos + 5 > buf_len) {
        vless_set_error("vision_unpad: buffer too short for command header (%zu < %zu)",
                        buf_len, pos + 5);
        return VLESS_ERR_PROTOCOL;
    }

    *out_cmd = buf[pos]; /* 0x00=continue, 0x01=end, 0x02=direct */
    if (*out_cmd > VISION_CMD_DIRECT) {
        vless_set_error("vision_unpad: unknown command byte 0x%02x", *out_cmd);
        return VLESS_ERR_PROTOCOL;
    }
    pos += 1;

    *out_content_len = rd_u16be(buf + pos);
    pos += 2;
    *out_pad_len = rd_u16be(buf + pos);

    /* Reject padding lengths that exceed the xray-core spec maximum.
     * Without this, a malicious server could force large reads to skip padding. */
    if (*out_pad_len > VISION_PADDING_MAX_LEN) {
        vless_set_error("vision_unpad: padding length %u exceeds max %d",
                        *out_pad_len, VISION_PADDING_MAX_LEN);
        return VLESS_ERR_PROTOCOL;
    }

    /* Sanity-check: content + padding should not exceed reasonable TLS record size */
    if ((size_t)*out_content_len + (size_t)*out_pad_len > TLS_MAX_RECORD_PAYLOAD) {
        vless_set_error("vision_unpad: content(%u) + padding(%u) exceeds TLS record limit",
                        *out_content_len, *out_pad_len);
        return VLESS_ERR_PROTOCOL;
    }

    return VLESS_OK;
}

/* ─── Internal send/recv dispatchers ──────────────────────────── */

/* Common SSL I/O loop for both send and recv.
 * is_send: 1 = SSL_write, 0 = SSL_read.
 * Returns bytes transferred (positive), 0 for EOF (recv only), or negative error code. */
static int do_ssl_io(vless_conn_t *conn, const void *buf, int len, int is_send) {
    if (!conn->ssl) return VLESS_ERR_TLS;
    if (len <= 0) return VLESS_ERR_INVALID_ARG;

    struct timespec deadline;
    int have_deadline = 0;
    if (conn->io_timeout_ms > 0) {
        have_deadline = (clock_gettime(CLOCK_MONOTONIC, &deadline) == 0);
        if (have_deadline) {
            int64_t total_timeout_ms = (int64_t)conn->io_timeout_ms * 4;
            if (total_timeout_ms > 300000) total_timeout_ms = 300000;
            deadline.tv_sec += (time_t)(total_timeout_ms / 1000);
            deadline.tv_nsec += (long)(total_timeout_ms % 1000) * 1000000L;
            if (deadline.tv_nsec >= 1000000000L) {
                deadline.tv_sec++;
                deadline.tv_nsec -= 1000000000L;
            }
        }
    }
    int iterations = 0;
    /* Always compute a finite iteration cap as a safety net.
     * When have_deadline is true, the deadline provides tighter control,
     * but the iteration guard prevents infinite loops if clock_gettime fails. */
    int max_iterations = (int)((conn->io_timeout_ms > 0 ?
        (int64_t)conn->io_timeout_ms * 4 : 120000) / 50) + 100;
    int zero_retries = 0;
    const char *op_name = is_send ? "SSL_write" : "SSL_read";

    for (;;) {
        /* Iteration safety guard — always runs to prevent infinite loops
         * (e.g. if clock_gettime fails when have_deadline is true). */
        if (++iterations > max_iterations) {
            vless_set_error("%s: iteration limit exceeded", op_name);
            return VLESS_ERR_TIMEOUT;
        }

        /* Check deadline (provides tighter timeout than iteration guard) */
        if (have_deadline) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0) {
                int64_t rem = ((int64_t)deadline.tv_sec - (int64_t)now.tv_sec) * 1000 +
                              (deadline.tv_nsec - now.tv_nsec) / 1000000;
                if (rem <= 0) {
                    vless_set_error("%s: deadline exceeded", op_name);
                    return VLESS_ERR_TIMEOUT;
                }
            }
        }

        int n = is_send ? SSL_write(conn->ssl, buf, len) : SSL_read(conn->ssl, (void *)buf, len);
        if (n > 0) return n;
        if (n == 0) {
            if (!is_send) return 0; /* EOF for recv */
            /* SSL_write returning 0 is an error — diagnose via SSL_get_error
             * instead of blindly retrying (which would spin on a closed conn). */
            {
                int saved_errno_z = errno;
                int zerr = SSL_get_error(conn->ssl, n);
                if (zerr == SSL_ERROR_ZERO_RETURN) return VLESS_ERR_CLOSED;
                if (zerr == SSL_ERROR_WANT_READ) {
                    int rc = vless_poll_read(conn->fd, conn->io_timeout_ms);
                    if (rc != VLESS_OK) return rc;
                    continue;
                }
                if (zerr == SSL_ERROR_WANT_WRITE) {
                    int rc = vless_poll_write(conn->fd, conn->io_timeout_ms);
                    if (rc != VLESS_OK) return rc;
                    continue;
                }
                if (zerr == SSL_ERROR_SYSCALL) {
                    if (saved_errno_z == EINTR) continue;
                    char errbuf[64];
                    safe_strerror(saved_errno_z, errbuf, sizeof(errbuf));
                    vless_set_error("%s: zero return with syscall error: %s", op_name, errbuf);
                    return VLESS_ERR_IO;
                }
                if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) {
                    vless_set_error("%s: too many zero-byte results (ssl_error=%d)", op_name, zerr);
                    return VLESS_ERR_IO;
                }
                continue;
            }
        }

        /* Save errno before SSL_get_error — SSL_get_error may call
         * internal OpenSSL functions that clobber errno. */
        int saved_errno = errno;
        int err = SSL_get_error(conn->ssl, n);
        switch (err) {
        case SSL_ERROR_WANT_READ: {
            int rc = vless_poll_read(conn->fd, conn->io_timeout_ms);
            if (rc != VLESS_OK) return rc;
            continue;
        }
        case SSL_ERROR_WANT_WRITE: {
            int rc = vless_poll_write(conn->fd, conn->io_timeout_ms);
            if (rc != VLESS_OK) return rc;
            continue;
        }
        case SSL_ERROR_SYSCALL: {
            if (saved_errno == EINTR) continue;
            if (saved_errno == 0) {
                vless_set_error("%s: unexpected EOF from peer", op_name);
                return VLESS_ERR_IO;
            }
            char errbuf[64];
            safe_strerror(saved_errno, errbuf, sizeof(errbuf));
            vless_set_error("%s error: %s", op_name, errbuf);
            return VLESS_ERR_IO;
        }
        case SSL_ERROR_ZERO_RETURN:
            return is_send ? VLESS_ERR_CLOSED : 0;
        default:
            vless_set_error("%s error: ssl_error=%d", op_name, err);
            return VLESS_ERR_TLS;
        }
    }
}

static int do_send(vless_conn_t *conn, const void *data, size_t len) {
    if (conn->use_reality) {
        return vless_reality_send(conn, data, len);
    }
    if (len > (size_t)INT_MAX) len = (size_t)INT_MAX;
    return do_ssl_io(conn, data, (int)len, 1);
}

static int do_recv(vless_conn_t *conn, void *buf, size_t len) {
    if (conn->use_reality) {
        return vless_reality_recv(conn, buf, len);
    }
    if (len > (size_t)INT_MAX) len = (size_t)INT_MAX;
    return do_ssl_io(conn, buf, (int)len, 0);
}

/* ─── VLESS response header reader ────────────────────────────── */

static int vless_read_response(vless_conn_t *conn) {
    /* Aggregate deadline: prevents a slow server from holding the client
     * indefinitely by trickling response header bytes one at a time,
     * each within the per-call io_timeout_ms. */
    struct timespec resp_deadline;
    int have_resp_deadline = (clock_gettime(CLOCK_MONOTONIC, &resp_deadline) == 0);
    if (have_resp_deadline) {
        int64_t total_ms = conn->io_timeout_ms > 0
            ? (int64_t)conn->io_timeout_ms * 4 : 120000;
        if (total_ms > 300000) total_ms = 300000; /* cap at 5 minutes */
        resp_deadline.tv_sec += (time_t)(total_ms / 1000);
        resp_deadline.tv_nsec += (long)(total_ms % 1000) * 1000000;
        if (resp_deadline.tv_nsec >= 1000000000) {
            resp_deadline.tv_sec++;
            resp_deadline.tv_nsec -= 1000000000;
        }
    }

    uint8_t header[2];
    size_t got = 0;
    int zero_retries = 0;
    while (got < 2) {
        if (deadline_exceeded(have_resp_deadline, &resp_deadline)) {
            vless_set_error("VLESS response: deadline exceeded");
            CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
            return VLESS_ERR_TIMEOUT;
        }
        int n = do_recv(conn, header + got, 2 - got);
        if (n < 0) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return n; }
        if (n == 0) {
            /* REALITY recv returns 0 for non-data records (NewSessionTicket).
             * Not a real EOF — retry. Poll already waited, so no busy-spin.
             * 100 retries: each iteration waits in poll() up to io_timeout_ms.
             * In practice, zero-returns happen for NewSessionTicket records
             * which are processed and discarded, so retries complete quickly.
             * For plain TLS, zero means real EOF — return immediately. */
            if (!conn->use_reality) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; }
            if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; }
            continue;
        }
        zero_retries = 0;
        got += (size_t)n;
    }

    if (header[0] != VLESS_PROTO_VERSION) {
        vless_set_error("VLESS response version mismatch: %d", header[0]);
        CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
        return VLESS_ERR_PROTOCOL;
    }

    /* Skip addons */
    uint8_t addons_len = header[1];
    if (addons_len > 0) {
        uint8_t discard[256];
        size_t remaining = addons_len;
        zero_retries = 0;
        while (remaining > 0) {
            if (deadline_exceeded(have_resp_deadline, &resp_deadline)) {
                vless_set_error("VLESS response: deadline exceeded");
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return VLESS_ERR_TIMEOUT;
            }
            size_t chunk = remaining < sizeof(discard) ? remaining : sizeof(discard);
            int n = do_recv(conn, discard, chunk);
            if (n < 0) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return n; }
            if (n == 0) {
                if (!conn->use_reality) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; }
                if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; }
                continue;
            }
            zero_retries = 0;
            remaining -= (size_t)n;
        }
    }

    conn->response_parsed = 1;
    CONN_STATE_STORE(conn, VLESS_STATE_READY);
    return VLESS_OK;
}

/* ─── Public API ──────────────────────────────────────────────── */

VLESS_API void vless_config_init(vless_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    config->server_port = 443;
    config->connect_timeout_ms = 15000;
    config->io_timeout_ms = 30000;
    config->tls.verify_peer = 1;
    config->vision_enabled = 1; /* Vision on by default for stealth */
}

/*
 * Phase 1 implementation: TCP connect + TLS handshake only (no VLESS header).
 * Returns VLESS_OK with *out set to a conn in VLESS_STATE_CONNECTED,
 * or a negative error code with *out = NULL.
 */
static int connect_no_request_impl(const vless_config_t *config, vless_conn_t **out) {
    *out = NULL;

    if (!config) {
        vless_set_error("Invalid config: NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    if (!config->server_host || config->server_host[0] == '\0') {
        vless_set_error("Invalid config: server_host is missing or empty");
        return VLESS_ERR_INVALID_ARG;
    }
    size_t host_len = strlen(config->server_host);
    if (host_len > VLESS_MAX_HOSTNAME_LEN) {
        vless_set_error("Invalid config: server_host too long (%zu bytes, max %d)",
                        host_len, VLESS_MAX_HOSTNAME_LEN);
        return VLESS_ERR_INVALID_ARG;
    }
    if (!config->uuid) {
        vless_set_error("Invalid config: uuid is missing");
        return VLESS_ERR_INVALID_ARG;
    }
    if (config->server_port == 0) {
        vless_set_error("Invalid config: server_port is 0");
        return VLESS_ERR_INVALID_ARG;
    }

    vless_conn_t *conn = calloc(1, sizeof(vless_conn_t));
    if (!conn) { vless_set_error("Out of memory"); return VLESS_ERR_NOMEM; }
    conn->fd = -1;
    CONN_STATE_STORE(conn, VLESS_STATE_INIT);
    conn->use_reality = (config->reality.public_key != NULL);

    /* Validate REALITY config consistency */
    if (conn->use_reality && (!config->reality.server_name || config->reality.server_name[0] == '\0')) {
        vless_set_error("REALITY public_key set but server_name is missing");
        free(conn);
        return VLESS_ERR_INVALID_ARG;
    }
    if (conn->use_reality && strlen(config->reality.server_name) > 255) {
        vless_set_error("REALITY server_name too long (%zu bytes, max 255)",
                        strlen(config->reality.server_name));
        free(conn);
        return VLESS_ERR_INVALID_ARG;
    }
    if (conn->use_reality && !config->reality.short_id) {
        vless_set_error("REALITY public_key set but short_id is NULL");
        free(conn);
        return VLESS_ERR_INVALID_ARG;
    }
    if (conn->use_reality) {
        size_t sid_len = strlen(config->reality.short_id);
        if (sid_len > VLESS_REALITY_SHORTID_STRLEN) {
            vless_set_error("REALITY short_id too long: %zu chars, max %d",
                            sid_len, VLESS_REALITY_SHORTID_STRLEN);
            free(conn);
            return VLESS_ERR_INVALID_ARG;
        }
        if (sid_len % 2 != 0) {
            vless_set_error("REALITY short_id must have even length (got %zu)", sid_len);
            free(conn);
            return VLESS_ERR_INVALID_ARG;
        }
        /* Validate hex characters early to avoid wasting a TCP round trip */
        for (size_t i = 0; i < sid_len; i++) {
            if (hex_digit(config->reality.short_id[i]) < 0) {
                vless_set_error("REALITY short_id contains non-hex character at position %zu", i);
                free(conn);
                return VLESS_ERR_INVALID_ARG;
            }
        }
    }

    conn->vision_enabled = config->vision_enabled ? 1 : 0;
    conn->vision_send_remaining = conn->vision_enabled ? VISION_PADDING_INITIAL_COUNT : 0;
    conn->vision_recv_remaining = conn->vision_enabled ? VISION_PADDING_INITIAL_COUNT : 0;
    conn->vision_first_send = conn->vision_enabled ? 1 : 0;
    conn->vision_recv_uuid_seen = 0;

    /* Parse UUID */
    int rc = vless_parse_uuid(config->uuid, conn->uuid);
    if (rc != VLESS_OK) {
        free(conn); return rc;
    }

    /* Validate REALITY public_key format early (before TCP connect) to avoid
     * wasting a network round trip on misconfigured keys. */
    if (conn->use_reality) {
        const char *pk = config->reality.public_key;
        size_t pk_slen = strlen(pk);
        /* X25519 public key = 32 bytes = 44 base64 chars (with padding) or 43 without */
        if (pk_slen < 43 || pk_slen > 44) {
            vless_set_error("REALITY public_key: expected 43-44 base64 chars, got %zu", pk_slen);
            free(conn); return VLESS_ERR_INVALID_ARG;
        }
        /* Validate base64 alphabet early (standard + URL-safe variants) */
        for (size_t i = 0; i < pk_slen; i++) {
            char c = pk[i];
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                  (c >= '0' && c <= '9') || c == '+' || c == '/' ||
                  c == '-' || c == '_' || c == '=')) {
                vless_set_error("REALITY public_key: invalid base64 character at position %zu", i);
                free(conn); return VLESS_ERR_INVALID_ARG;
            }
        }
    }

    /* TCP connect */
    int tcp_fd = -1;
    int tcp_rc = vless_tcp_connect(config->server_host, config->server_port,
                                   config->connect_timeout_ms, &tcp_fd);
    if (tcp_rc != VLESS_OK) {
        free(conn);
        return tcp_rc;
    }
    conn->fd = tcp_fd;

    /* I/O timeout */
    conn->io_timeout_ms = config->io_timeout_ms;
    /* Normalize non-positive io_timeout to default 30s.
     * This ensures REALITY I/O loops always have an aggregate deadline,
     * preventing indefinite stalls against malicious/slow servers. */
    if (conn->io_timeout_ms <= 0)
        conn->io_timeout_ms = 30000;

    /* TLS handshake.
     * Pass the normalized io_timeout_ms via a local config copy so that
     * REALITY I/O functions (sock_write_all, sock_read_all) inherit the
     * same default timeout, avoiding infinite stalls when the caller
     * passes io_timeout_ms=0. */
    if (conn->use_reality) {
        vless_config_t norm_config = *config;
        norm_config.io_timeout_ms = conn->io_timeout_ms;
        rc = vless_reality_handshake(conn, &norm_config);
    } else {
        rc = vless_tls_init(conn, &config->tls, config->server_host);
        if (rc == VLESS_OK) rc = vless_tls_handshake(conn);
    }
    if (rc != VLESS_OK) { vless_close(conn); return rc; }

    CONN_STATE_STORE(conn, VLESS_STATE_CONNECTED);
    *out = conn;
    return VLESS_OK;
}

/* Phase 1 wrapper: returns conn or NULL (used by connection pool). */
VLESS_INTERNAL
vless_conn_t *vless_connect_no_request(const vless_config_t *config) {
    vless_conn_t *conn = NULL;
    (void)connect_no_request_impl(config, &conn);
    return conn;
}

/*
 * Phase 2: Send VLESS request header for a specific destination.
 * conn must be in VLESS_STATE_CONNECTED.
 */
VLESS_INTERNAL
int vless_send_request(vless_conn_t *conn, const uint8_t uuid[16],
                       const char *dest_host, uint16_t dest_port,
                       int vision_enabled) {
    if (!conn || !uuid || !dest_host || dest_host[0] == '\0' || dest_port == 0) {
        vless_set_error("vless_send_request: invalid argument (conn=%p dest=%s port=%u)",
                        (void *)conn, dest_host ? dest_host : "NULL", dest_port);
        return VLESS_ERR_INVALID_ARG;
    }
    if (CONN_STATE_LOAD(conn) != VLESS_STATE_CONNECTED) {
        vless_set_error("vless_send_request: wrong state %d (expected CONNECTED)", CONN_STATE_LOAD(conn));
        return VLESS_ERR_INVALID_ARG;
    }

    /* Sync conn state with the parameters used for this request.
     * Reset all Vision state unconditionally for correct behavior when
     * vless_send_request is called on a pooled connection. */
    /* memmove: uuid may alias conn->uuid (e.g. vless_connect passes conn->uuid) */
    memmove(conn->uuid, uuid, 16);
    conn->vision_enabled = vision_enabled ? 1 : 0;
    conn->vision_send_remaining = vision_enabled ? VISION_PADDING_INITIAL_COUNT : 0;
    conn->vision_recv_remaining = vision_enabled ? VISION_PADDING_INITIAL_COUNT : 0;
    conn->vision_first_send = vision_enabled ? 1 : 0;
    conn->vision_recv_uuid_seen = 0;
    conn->vision_direct = 0;
    conn->response_parsed = 0;
    /* Free stale spill buffer to prevent leak if called on a reused connection */
    if (conn->vision_spill) {
        OPENSSL_cleanse(conn->vision_spill, conn->vision_spill_len);
        free(conn->vision_spill);
        conn->vision_spill = NULL;
        conn->vision_spill_len = 0;
        conn->vision_spill_off = 0;
    }

    uint8_t req_buf[VLESS_MAX_HEADER];
    size_t req_len = 0;
    int rc = vless_build_request(req_buf, sizeof(req_buf), uuid,
                                  dest_host, dest_port,
                                  vision_enabled, &req_len);
    if (rc != VLESS_OK) return rc;

    /* VLESS header must be sent atomically — retry on partial writes */
    size_t total_written = 0;
    while (total_written < req_len) {
        int written = do_send(conn, req_buf + total_written, req_len - total_written);
        if (written < 0) {
            CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
            return written;
        }
        if (written == 0) {
            CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
            vless_set_error("send_request: transport returned 0 bytes");
            return VLESS_ERR_IO;
        }
        total_written += (size_t)written;
    }

    CONN_STATE_STORE(conn, VLESS_STATE_HEADER_SENT);
    return VLESS_OK;
}

VLESS_API int vless_connect_ex(const vless_config_t *config, vless_conn_t **out) {
    if (!out) {
        vless_set_error("vless_connect_ex: out parameter is NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    *out = NULL;
    if (!config) {
        vless_set_error("vless_connect_ex: config is NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    if (!config->dest_host || config->dest_host[0] == '\0') {
        vless_set_error("vless_connect_ex: dest_host is missing or empty");
        return VLESS_ERR_INVALID_ARG;
    }
    if (config->dest_port == 0) {
        vless_set_error("vless_connect_ex: dest_port is 0");
        return VLESS_ERR_INVALID_ARG;
    }
    /* Validate dest_host length early, before the expensive TCP+TLS handshake.
     * VLESS address type 0x02 (domain) uses a 1-byte length field (max 255). */
    {
        size_t dlen = strlen(config->dest_host);
        if (dlen > 255) {
            vless_set_error("vless_connect_ex: dest_host too long (%zu bytes, max 255)", dlen);
            return VLESS_ERR_INVALID_ARG;
        }
    }

    vless_conn_t *conn = NULL;
    int rc = connect_no_request_impl(config, &conn);
    if (rc != VLESS_OK) return rc;

    rc = vless_send_request(conn, conn->uuid,
                             config->dest_host, config->dest_port,
                             conn->vision_enabled);
    if (rc != VLESS_OK) {
        vless_close(conn);
        return rc;
    }
    *out = conn;
    return VLESS_OK;
}

VLESS_API vless_conn_t *vless_connect(const vless_config_t *config) {
    vless_conn_t *conn = NULL;
    int rc = vless_connect_ex(config, &conn);
    (void)rc;
    return conn;
}

VLESS_API int vless_send(vless_conn_t *conn, const void *data, size_t len) {
    if (!conn || !data || len == 0) {
        vless_set_error("vless_send: invalid argument (conn=%p data=%p len=%zu)",
                        (const void *)conn, data, len);
        return VLESS_ERR_INVALID_ARG;
    }
    if (CONN_STATE_LOAD(conn) == VLESS_STATE_CLOSED) return VLESS_ERR_CLOSED;
    if (CONN_STATE_LOAD(conn) < VLESS_STATE_HEADER_SENT) {
        vless_set_error("Cannot send: VLESS header not yet sent (state=%d)", CONN_STATE_LOAD(conn));
        return VLESS_ERR_INVALID_ARG;
    }
    if (len > INT_MAX) len = INT_MAX;

    /* Vision framing on first N messages:
     * [UUID(16, first msg only)] [cmd(1)] [content_len(2)] [pad_len(2)] [content] [padding]
     * Vision overhead: UUID(16, first only) + cmd(1) + content_len(2) + pad_len(2) + padding(0..255)
     * Max safe content per frame = TLS_MAX_RECORD_PAYLOAD - max_overhead
     * to guarantee the padded frame fits in the stack buffer. */
    if (conn->vision_enabled && conn->vision_send_remaining > 0) {
        const uint8_t *p = data;
        size_t remaining = len;
        size_t total_consumed = 0;

        /* Aggregate deadline for Vision send to prevent DoS from a slow peer
         * that accepts data one byte at a time, each within io_timeout_ms.
         * Mirrors the vision_deadline in vless_recv. */
        struct timespec vision_send_deadline;
        int has_vision_send_deadline = 0;
        if (clock_gettime(CLOCK_MONOTONIC, &vision_send_deadline) == 0) {
            int64_t total_ms = conn->io_timeout_ms > 0
                ? (int64_t)conn->io_timeout_ms * 4 : 120000;
            if (total_ms > 300000) total_ms = 300000;
            vision_send_deadline.tv_sec += (time_t)(total_ms / 1000);
            vision_send_deadline.tv_nsec += (long)(total_ms % 1000) * 1000000;
            if (vision_send_deadline.tv_nsec >= 1000000000) {
                vision_send_deadline.tv_sec++;
                vision_send_deadline.tv_nsec -= 1000000000;
            }
            has_vision_send_deadline = 1;
        }

        uint8_t *padded = malloc(TLS_MAX_RECORD_PAYLOAD);
        if (!padded) {
            vless_set_error("send: out of memory for Vision padding buffer");
            return VLESS_ERR_NOMEM;
        }
        while (remaining > 0 && conn->vision_send_remaining > 0) {
            /* Check aggregate deadline */
            if (deadline_exceeded(has_vision_send_deadline, &vision_send_deadline)) {
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
                free(padded);
                if (total_consumed > 0) {
                    if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                    return (int)total_consumed;
                }
                vless_set_error("Vision send: overall deadline exceeded");
                return VLESS_ERR_TIMEOUT;
            }
            /* Compute max content that fits: buf - header - max_padding */
            size_t hdr_size = (conn->vision_first_send ? 16 : 0) + 1 + 2 + 2;
            size_t max_chunk = TLS_MAX_RECORD_PAYLOAD - hdr_size - VISION_PADDING_MAX_LEN;
            if (max_chunk > 65535) max_chunk = 65535;
            size_t chunk = remaining > max_chunk ? max_chunk : remaining;
            size_t padded_len;
            const uint8_t *uuid_for_frame = conn->vision_first_send ? conn->uuid : NULL;
            int rc = vision_pad_data(uuid_for_frame, p, chunk,
                                      padded, TLS_MAX_RECORD_PAYLOAD, &padded_len);
            if (rc != VLESS_OK) {
                OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
                free(padded);
                /* Always mark closed: RNG failure is systemic, and
                 * vision_send_remaining is already decremented for any
                 * previously sent frames — retry would desync framing. */
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                if (total_consumed > 0) {
                    if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                    return (int)total_consumed;
                }
                return rc;
            }
            /* Send the full padded frame — must be atomic */
            size_t frame_sent = 0;
            while (frame_sent < padded_len) {
                /* Check aggregate deadline within the frame send loop too,
                 * not just between frames — a slow peer could stall here. */
                if (deadline_exceeded(has_vision_send_deadline, &vision_send_deadline)) {
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
                    free(padded);
                    if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                    if (total_consumed > 0) return (int)total_consumed;
                    vless_set_error("Vision send: deadline exceeded during frame send");
                    return VLESS_ERR_TIMEOUT;
                }
                int sent = do_send(conn, padded + frame_sent, padded_len - frame_sent);
                if (sent < 0) {
                    /* Any send failure breaks the connection: partial frame
                     * causes protocol desync, and even a failure on the first
                     * byte leaves the transport in an undefined state (plain
                     * TLS do_ssl_io doesn't set CLOSED). */
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
                    free(padded);
                    if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                    return total_consumed > 0 ? (int)total_consumed : sent;
                }
                if (sent == 0) {
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
                    free(padded);
                    vless_set_error("Vision send: transport returned 0 bytes");
                    if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                    return total_consumed > 0 ? (int)total_consumed : VLESS_ERR_IO;
                }
                frame_sent += (size_t)sent;
            }
            conn->vision_send_remaining--;
            conn->vision_first_send = 0;
            p += chunk;
            remaining -= chunk;
            total_consumed += chunk;
        }
        OPENSSL_cleanse(padded, TLS_MAX_RECORD_PAYLOAD);
        free(padded);

        /* Any remaining data after Vision exhausted: send directly */
        if (remaining > 0) {
            int sent = do_send(conn, p, remaining);
            if (sent < 0) {
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                return total_consumed > 0 ? (int)total_consumed : sent;
            }
            if (sent == 0) {
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
                return total_consumed > 0 ? (int)total_consumed : VLESS_ERR_IO;
            }
            total_consumed += (size_t)sent;
        }
        if (total_consumed > (size_t)INT_MAX) total_consumed = (size_t)INT_MAX;
        return (int)total_consumed;
    }

    {
        int rc = do_send(conn, data, len);
        if (rc < 0) CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
        if (rc == 0) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_IO; }
        return rc;
    }
}

VLESS_API int vless_recv(vless_conn_t *conn, void *buf, size_t buf_len) {
    if (!conn || !buf || buf_len == 0) {
        vless_set_error("vless_recv: invalid argument (conn=%p buf=%p len=%zu)",
                        (const void *)conn, buf, buf_len);
        return VLESS_ERR_INVALID_ARG;
    }
    if (CONN_STATE_LOAD(conn) == VLESS_STATE_CLOSED) return VLESS_ERR_CLOSED;
    if (CONN_STATE_LOAD(conn) < VLESS_STATE_HEADER_SENT) {
        vless_set_error("Cannot recv: VLESS header not yet sent (state=%d)", CONN_STATE_LOAD(conn));
        return VLESS_ERR_INVALID_ARG;
    }
    if (buf_len > (size_t)INT_MAX) buf_len = (size_t)INT_MAX;

    /* First recv: read VLESS response header */
    if (!conn->response_parsed) {
        int rc = vless_read_response(conn);
        if (rc != VLESS_OK) return rc;
    }

    /* Return spillover data from previous Vision frame regardless of vision state.
     * This handles the case where vision_recv_remaining transitions to 0 or
     * vision_direct becomes 1 while there is still spill data buffered. */
    if (conn->vision_spill && conn->vision_spill_off < conn->vision_spill_len) {
        size_t avail = conn->vision_spill_len - conn->vision_spill_off;
        size_t copy = avail < buf_len ? avail : buf_len;
        memcpy(buf, conn->vision_spill + conn->vision_spill_off, copy);
        conn->vision_spill_off += copy;
        if (conn->vision_spill_off >= conn->vision_spill_len) {
            OPENSSL_cleanse(conn->vision_spill, conn->vision_spill_len);
            free(conn->vision_spill);
            conn->vision_spill = NULL;
            conn->vision_spill_len = 0;
            conn->vision_spill_off = 0;
        }
        return (int)copy;
    }

    /* Vision: strip framing from received data.
     * The server wraps response data in Vision frames:
     *   [UUID(16, first msg)] [cmd(1)] [content_len(2)] [pad_len(2)] [content] [padding]
     * We need to read the frame header, extract the content, and skip padding.
     * If server sent end/direct cmd, stop Vision framing for subsequent messages. */
    /* Overall deadline for Vision recv to prevent DoS from a slow server
     * that trickles data to hold the client indefinitely. */
    struct timespec vision_deadline;
    int has_vision_deadline = 0;
    if (conn->vision_enabled && conn->vision_recv_remaining > 0 &&
        !conn->vision_direct) {
        if (clock_gettime(CLOCK_MONOTONIC, &vision_deadline) == 0) {
            int64_t total_ms = conn->io_timeout_ms > 0
                ? (int64_t)conn->io_timeout_ms * 4 : 120000;
            if (total_ms > 300000) total_ms = 300000;
            vision_deadline.tv_sec += (time_t)(total_ms / 1000);
            vision_deadline.tv_nsec += (long)(total_ms % 1000) * 1000000;
            if (vision_deadline.tv_nsec >= 1000000000) {
                vision_deadline.tv_sec++;
                vision_deadline.tv_nsec -= 1000000000;
            }
            has_vision_deadline = 1;
        }
    }

    while (conn->vision_enabled && conn->vision_recv_remaining > 0 &&
           !conn->vision_direct) {

        /* Check overall deadline */
        if (has_vision_deadline) {
            struct timespec now;
            if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
                (now.tv_sec > vision_deadline.tv_sec ||
                 (now.tv_sec == vision_deadline.tv_sec &&
                  now.tv_nsec >= vision_deadline.tv_nsec))) {
                vless_set_error("Vision recv: overall deadline exceeded");
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return VLESS_ERR_TIMEOUT;
            }
        }

        /* Read frame header.
         * 100 retries: each iteration waits in poll() up to io_timeout_ms.
         * In practice, zero-returns happen for NewSessionTicket records
         * which are processed and discarded, so retries complete quickly. */
        size_t hdr_size = (conn->vision_recv_uuid_seen ? 0 : 16) + 5;
        uint8_t hdr_buf[16 + 5];
        size_t hdr_got = 0;
        int zero_retries = 0;
        while (hdr_got < hdr_size) {
            if (deadline_exceeded(has_vision_deadline, &vision_deadline)) {
                vless_set_error("Vision recv: overall deadline exceeded");
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return VLESS_ERR_TIMEOUT;
            }
            int n = do_recv(conn, hdr_buf + hdr_got, hdr_size - hdr_got);
            if (n < 0) {
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                /* Map close_notify to EOF when no frame data received yet,
                 * consistent with the non-Vision recv path. */
                if (n == VLESS_ERR_CLOSED && hdr_got == 0) return 0;
                return n;
            }
            if (n == 0) { if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; } continue; }
            zero_retries = 0;
            hdr_got += (size_t)n;
        }

        uint8_t cmd;
        uint16_t content_len, pad_len;
        int rc = vision_unpad_data(hdr_buf, hdr_got, conn->uuid,
                                    &conn->vision_recv_uuid_seen,
                                    &cmd, &content_len, &pad_len);
        if (rc != VLESS_OK) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return rc; }

        /* If server sent end or direct command, stop Vision framing */
        if (cmd == VISION_CMD_END || cmd == VISION_CMD_DIRECT) {
            conn->vision_direct = 1;
            conn->vision_recv_remaining = 0; /* prevent stale counter */
        }

        /* Skip padding for zero-content frames and retry next frame
         * instead of returning 0 (which callers interpret as EOF). */
        if (content_len == 0) {
            size_t skip = (size_t)pad_len;
            zero_retries = 0;
            while (skip > 0) {
                if (deadline_exceeded(has_vision_deadline, &vision_deadline)) {
                    vless_set_error("Vision recv: deadline exceeded during padding skip");
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    return VLESS_ERR_TIMEOUT;
                }
                uint8_t discard[1024];
                size_t chunk = skip < sizeof(discard) ? skip : sizeof(discard);
                int n = do_recv(conn, discard, chunk);
                if (n < 0) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return n; }
                if (n == 0) { if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; } continue; }
                zero_retries = 0;
                skip -= (size_t)n;
            }
            if (conn->vision_recv_remaining > 0)
                conn->vision_recv_remaining--;
            continue; /* retry with next frame */
        }

        /* Read content_len bytes of actual data into caller's buffer.
         * 100 retries: each iteration waits in poll() up to io_timeout_ms.
         * In practice, zero-returns happen for NewSessionTicket records
         * which are processed and discarded, so retries complete quickly. */
        size_t to_read = (size_t)content_len < buf_len ? (size_t)content_len : buf_len;
        size_t got = 0;
        zero_retries = 0;
        while (got < to_read) {
            if (deadline_exceeded(has_vision_deadline, &vision_deadline)) {
                vless_set_error("Vision recv: overall deadline exceeded");
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return VLESS_ERR_TIMEOUT;
            }
            int n = do_recv(conn, (uint8_t *)buf + got, to_read - got);
            if (n < 0) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return n; }
            if (n == 0) { if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return VLESS_ERR_CLOSED; } continue; }
            zero_retries = 0;
            got += (size_t)n;
        }

        /* Buffer excess content that didn't fit in caller's buf */
        size_t excess_content = (size_t)content_len - to_read;
        if (excess_content > 0) {
            /* Defensive: should always be NULL here (spill fully consumed above) */
            if (conn->vision_spill) {
                OPENSSL_cleanse(conn->vision_spill, conn->vision_spill_len);
                free(conn->vision_spill);
                conn->vision_spill = NULL;
                conn->vision_spill_len = 0;
                conn->vision_spill_off = 0;
            }
            conn->vision_spill = malloc(excess_content);
            if (!conn->vision_spill) {
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                vless_set_error("Out of memory for Vision spill buffer");
                return (int)to_read; /* deliver already-read data; conn is broken */
            }
            conn->vision_spill_len = excess_content;
            conn->vision_spill_off = 0;
            size_t spill_got = 0;
            zero_retries = 0;
            while (spill_got < excess_content) {
                if (deadline_exceeded(has_vision_deadline, &vision_deadline)) {
                    OPENSSL_cleanse(conn->vision_spill, excess_content);
                    free(conn->vision_spill); conn->vision_spill = NULL;
                    conn->vision_spill_len = 0; conn->vision_spill_off = 0;
                    if (conn->vision_recv_remaining > 0)
                        conn->vision_recv_remaining--;
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    vless_set_error("Vision recv: deadline exceeded during spill read");
                    return (int)to_read;
                }
                int n = do_recv(conn, conn->vision_spill + spill_got, excess_content - spill_got);
                if (n < 0) {
                    /* Spill read failed, but we already delivered to_read bytes
                     * to the caller. Return those bytes; mark conn broken. */
                    OPENSSL_cleanse(conn->vision_spill, excess_content);
                    free(conn->vision_spill); conn->vision_spill = NULL;
                    conn->vision_spill_len = 0; conn->vision_spill_off = 0;
                    if (conn->vision_recv_remaining > 0)
                        conn->vision_recv_remaining--;
                    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                    vless_set_error("Vision spill read failed mid-frame");
                    return (int)to_read;
                }
                if (n == 0) {
                    if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) {
                        OPENSSL_cleanse(conn->vision_spill, excess_content);
                        free(conn->vision_spill); conn->vision_spill = NULL;
                        conn->vision_spill_len = 0; conn->vision_spill_off = 0;
                        if (conn->vision_recv_remaining > 0)
                            conn->vision_recv_remaining--;
                        CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                        return (int)to_read;
                    }
                    continue;
                }
                zero_retries = 0;
                spill_got += (size_t)n;
            }
        }

        /* Skip padding bytes */
        size_t skip = (size_t)pad_len;
        zero_retries = 0;
        while (skip > 0) {
            if (deadline_exceeded(has_vision_deadline, &vision_deadline)) {
                vless_set_error("Vision recv: deadline exceeded during padding skip");
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return (int)to_read;
            }
            uint8_t discard[1024];
            size_t chunk = skip < sizeof(discard) ? skip : sizeof(discard);
            int n = do_recv(conn, discard, chunk);
            if (n < 0) {
                /* Padding skip failed, but content already delivered to caller.
                 * Return the data we have; mark connection as broken. */
                CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
                return (int)to_read;
            }
            if (n == 0) { if (++zero_retries > VLESS_ZERO_IO_MAX_RETRIES) { CONN_STATE_STORE(conn, VLESS_STATE_CLOSED); return (int)to_read; } continue; }
            zero_retries = 0;
            skip -= (size_t)n;
        }

        if (!conn->vision_direct)
            conn->vision_recv_remaining--;
        return (int)to_read;
    }

    {
        int rc = do_recv(conn, buf, buf_len);
        /* Map REALITY close_notify (VLESS_ERR_CLOSED) to EOF (0) for API consistency.
         * The public API documents "0 on EOF" but REALITY returns VLESS_ERR_CLOSED
         * for TLS close_notify alerts. */
        if (rc == VLESS_ERR_CLOSED) {
            CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
            return 0;
        }
        if (rc < 0) CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);
        return rc;
    }
}

VLESS_API int vless_get_fd(const vless_conn_t *conn) {
    return conn ? conn->fd : -1;
}

VLESS_API void vless_close(vless_conn_t *conn) {
    if (!conn) return;

    CONN_STATE_STORE(conn, VLESS_STATE_CLOSED);

    if (conn->reality) {
        /* Best-effort close_notify; errors ignored during teardown */
        vless_reality_close_notify(conn->reality);
        vless_reality_free(conn->reality);
        conn->reality = NULL;
    }
    if (conn->ssl) {
        if (SSL_is_init_finished(conn->ssl) && conn->fd >= 0) {
            /* Best-effort shutdown with poll retry for non-blocking sockets.
             * Limited retries to avoid hanging during teardown. */
            /* Best-effort shutdown: 2 attempts × 500ms = 1s max instead of 4s */
            for (int attempt = 0; attempt < 2; attempt++) {
                int shut_rc = SSL_shutdown(conn->ssl);
                if (shut_rc == 1) break; /* clean bidirectional shutdown */
                if (shut_rc < 0) {
                    int e = SSL_get_error(conn->ssl, shut_rc);
                    if (e == SSL_ERROR_WANT_READ) {
                        if (vless_poll_read(conn->fd, 500) != VLESS_OK) break;
                        continue;
                    }
                    if (e == SSL_ERROR_WANT_WRITE) {
                        if (vless_poll_write(conn->fd, 500) != VLESS_OK) break;
                        continue;
                    }
                    break; /* non-retryable error */
                }
                /* shut_rc == 0: sent close_notify, need to read peer's */
            }
        }
        /* SSL_free closes the fd via BIO_CLOSE when SSL_set_fd was used.
         * Mark fd = -1 BEFORE SSL_free to prevent double-close below. */
        conn->fd = -1;
        SSL_free(conn->ssl);
        conn->ssl = NULL;
    }
    if (conn->ssl_ctx) {
        SSL_CTX_free(conn->ssl_ctx);
        conn->ssl_ctx = NULL;
    }
    if (conn->fd >= 0) {
        close(conn->fd);
        conn->fd = -1;
    }

    if (conn->vision_spill) {
        OPENSSL_cleanse(conn->vision_spill, conn->vision_spill_len);
        free(conn->vision_spill);
        conn->vision_spill = NULL;
    }

    /* Auto-decrement pool in_use_count if this conn was acquired from a pool.
     * This prevents in_use_count leak when callers use vless_close() directly
     * instead of vless_pool_release().
     * Save and clear owner_pool BEFORE calling dec_in_use to prevent
     * reentrancy if dec_in_use triggers pool destruction. */
    if (conn->owner_pool) {
        struct vless_pool *pool = conn->owner_pool;
        conn->owner_pool = NULL;
        vless_pool_dec_in_use(pool);
    }

    OPENSSL_cleanse(conn, sizeof(*conn));
    free(conn);
}

/* ─── vless_connect_fd: plain-fd bridge over VLESS tunnel ──────── */

typedef struct vless_fd_bridge {
    vless_conn_t *conn;
    int           internal_fd;  /* socketpair[1], used by bridge threads */
    _Atomic int   shutdown;
    _Atomic int   threads_done; /* when reaches 2, last thread cleans up */
} vless_fd_bridge_t;

static void bridge_cleanup(vless_fd_bridge_t *br) {
    vless_close(br->conn);
    close(br->internal_fd);
    free(br);
}

static void *bridge_send_fn(void *arg) {
    vless_fd_bridge_t *br = (vless_fd_bridge_t *)arg;
    uint8_t buf[16384];
    const char *exit_reason = "shutdown flag";

    fprintf(stderr, "[vless-bridge] send thread started, app_fd_pair=%d\n",
            br->internal_fd);

    while (!atomic_load_explicit(&br->shutdown, memory_order_acquire)) {
        ssize_t n = read(br->internal_fd, buf, sizeof(buf));
        if (n == 0) { exit_reason = "app closed fd (read=0 EOF)"; break; }
        if (n < 0) {
            exit_reason = (errno == EINTR) ? "EINTR" : "read error";
            if (errno == EINTR) continue;
            fprintf(stderr, "[vless-bridge] send: read() error: %s (errno=%d)\n",
                    strerror(errno), errno);
            break;
        }

        size_t sent = 0;
        while (sent < (size_t)n) {
            int rc = vless_send(br->conn, buf + sent, (size_t)n - sent);
            if (rc <= 0) {
                fprintf(stderr, "[vless-bridge] send: vless_send()=%d, "
                        "error=\"%s\"\n", rc, vless_last_error());
                exit_reason = "vless_send failed";
                goto done;
            }
            sent += (size_t)rc;
        }
    }
done:
    fprintf(stderr, "[vless-bridge] send thread exiting: %s\n", exit_reason);

    atomic_store_explicit(&br->shutdown, 1, memory_order_release);
    shutdown(br->internal_fd, SHUT_RD);

    if (atomic_fetch_add_explicit(&br->threads_done, 1, memory_order_acq_rel) == 1)
        bridge_cleanup(br);
    return NULL;
}

static void *bridge_recv_fn(void *arg) {
    vless_fd_bridge_t *br = (vless_fd_bridge_t *)arg;
    uint8_t buf[16384];
    const char *exit_reason = "shutdown flag";

    fprintf(stderr, "[vless-bridge] recv thread started, app_fd_pair=%d\n",
            br->internal_fd);

    while (!atomic_load_explicit(&br->shutdown, memory_order_acquire)) {
        int n = vless_recv(br->conn, buf, sizeof(buf));
        if (n == 0) { exit_reason = "vless_recv=0 (server EOF)"; break; }
        if (n < 0) {
            fprintf(stderr, "[vless-bridge] recv: vless_recv()=%d, "
                    "error=\"%s\"\n", n, vless_last_error());
            exit_reason = "vless_recv error";
            break;
        }

        size_t written = 0;
        while (written < (size_t)n) {
            ssize_t w = write(br->internal_fd, buf + written, (size_t)n - written);
            if (w < 0) {
                if (errno == EINTR) continue;
                fprintf(stderr, "[vless-bridge] recv: write() error: %s "
                        "(errno=%d)\n", strerror(errno), errno);
                exit_reason = "write to app_fd failed (EPIPE = app closed)";
                goto done;
            }
            written += (size_t)w;
        }
    }
done:
    fprintf(stderr, "[vless-bridge] recv thread exiting: %s\n", exit_reason);

    atomic_store_explicit(&br->shutdown, 1, memory_order_release);
    shutdown(br->internal_fd, SHUT_WR);

    if (atomic_fetch_add_explicit(&br->threads_done, 1, memory_order_acq_rel) == 1)
        bridge_cleanup(br);
    return NULL;
}

int vless_connect_fd(const vless_config_t *config, int *app_fd) {
    if (!app_fd) return VLESS_ERR_INVALID_ARG;
    *app_fd = -1;
    if (!config) {
        vless_set_error("vless_connect_fd: config is NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    if (!config->reality.public_key || !config->reality.public_key[0]) {
        vless_set_error("vless_connect_fd requires REALITY mode "
                        "(plain TLS does not support concurrent send/recv)");
        return VLESS_ERR_INVALID_ARG;
    }

    /* 1. Establish VLESS connection (blocking) */
    vless_conn_t *conn = NULL;
    int rc = vless_connect_ex(config, &conn);
    if (rc != VLESS_OK) return rc;

    /* 2. Create TCP loopback socket pair.
     * We use a real AF_INET pair (not AF_UNIX socketpair) because the
     * returned app_fd must be a genuine TCP socket — GCDAsyncSocket,
     * CFStream, and dispatch_source all expect AF_INET and will
     * malfunction on AF_UNIX fds (e.g., getpeername fails, TCP_NODELAY
     * fails, dispatch_source_get_data returns 0 → spurious EOF). */
    int sv[2] = {-1, -1};
    {
        int listener = socket(AF_INET, SOCK_STREAM, 0);
        if (listener < 0) goto pair_fail;

        struct sockaddr_in lo;
        memset(&lo, 0, sizeof(lo));
        lo.sin_family = AF_INET;
        lo.sin_addr.s_addr = htonl(0x7f000001); /* 127.0.0.1 */
        lo.sin_port = 0; /* kernel picks a free port */

        if (bind(listener, (struct sockaddr *)&lo, sizeof(lo)) < 0 ||
            listen(listener, 1) < 0) {
            close(listener);
            goto pair_fail;
        }

        /* Read back the assigned port */
        socklen_t alen = sizeof(lo);
        getsockname(listener, (struct sockaddr *)&lo, &alen);

        sv[0] = socket(AF_INET, SOCK_STREAM, 0);
        if (sv[0] < 0) { close(listener); goto pair_fail; }

        if (connect(sv[0], (struct sockaddr *)&lo, sizeof(lo)) < 0) {
            close(sv[0]); sv[0] = -1;
            close(listener);
            goto pair_fail;
        }

        sv[1] = accept(listener, NULL, NULL);
        close(listener);
        if (sv[1] < 0) { close(sv[0]); sv[0] = -1; goto pair_fail; }

        /* Disable Nagle on both ends for minimal latency */
        setsockopt(sv[0], IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));
        setsockopt(sv[1], IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));

        goto pair_ok;
    pair_fail:
        {
            char errbuf[64];
            safe_strerror(errno, errbuf, sizeof(errbuf));
            vless_set_error("vless_connect_fd: loopback pair: %s", errbuf);
            vless_close(conn);
            return VLESS_ERR_IO;
        }
    pair_ok:;
    }

    /* FD_CLOEXEC + SO_NOSIGPIPE on both ends */
    fcntl(sv[0], F_SETFD, FD_CLOEXEC);
    fcntl(sv[1], F_SETFD, FD_CLOEXEC);
#ifdef SO_NOSIGPIPE
    setsockopt(sv[0], SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
    setsockopt(sv[1], SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif

    /* 3. Allocate bridge state (owned by the bridge threads) */
    vless_fd_bridge_t *br = calloc(1, sizeof(vless_fd_bridge_t));
    if (!br) {
        vless_close(conn);
        close(sv[0]); close(sv[1]);
        return VLESS_ERR_NOMEM;
    }
    br->conn = conn;
    br->internal_fd = sv[1];
    atomic_init(&br->shutdown, 0);
    atomic_init(&br->threads_done, 0);

    /* 4. Spawn send thread (detached) */
    pthread_t t_send;
    rc = pthread_create(&t_send, NULL, bridge_send_fn, br);
    if (rc != 0) {
        vless_set_error("vless_connect_fd: pthread_create(send): %d", rc);
        vless_close(conn);
        close(sv[0]); close(sv[1]);
        free(br);
        return VLESS_ERR_IO;
    }
    pthread_detach(t_send);

    /* 5. Spawn recv thread (detached) */
    pthread_t t_recv;
    rc = pthread_create(&t_recv, NULL, bridge_recv_fn, br);
    if (rc != 0) {
        vless_set_error("vless_connect_fd: pthread_create(recv): %d", rc);
        /* Send thread is already running — signal it to exit */
        atomic_store_explicit(&br->shutdown, 1, memory_order_release);
        shutdown(sv[1], SHUT_WR);
        /* Mark recv thread as "done" so send thread does cleanup */
        atomic_fetch_add_explicit(&br->threads_done, 1, memory_order_acq_rel);
        close(sv[0]);
        return VLESS_ERR_IO;
    }
    pthread_detach(t_recv);

    /* 6. Success */
    *app_fd = sv[0];
    return VLESS_OK;
}

/* ─── vless_listen_start: accept-one listener for GCDAsyncSocket ── */

static char *strdup_or_null(const char *s) {
    return s ? strdup(s) : NULL;
}

typedef struct vless_listener {
    /* Deep-copied config strings (freed after vless_connect) */
    char *server_host, *uuid, *dest_host;
    char *reality_server_name, *reality_public_key, *reality_short_id;
    char *tls_sni, *tls_alpn, *tls_ca_path;
    vless_config_t config; /* pointers reference the strings above */
    int listener_fd;
} vless_listener_t;

static void listener_free(vless_listener_t *l) {
    if (l->listener_fd >= 0) close(l->listener_fd);
    free(l->server_host);  free(l->uuid);  free(l->dest_host);
    free(l->reality_server_name); free(l->reality_public_key);
    free(l->reality_short_id);
    free(l->tls_sni); free(l->tls_alpn); free(l->tls_ca_path);
    free(l);
}

static void *listener_accept_fn(void *arg) {
    vless_listener_t *l = (vless_listener_t *)arg;

    /* Wait for exactly one client connection */
    int app_fd = accept(l->listener_fd, NULL, NULL);
    int accept_errno = errno;

    /* Close listener immediately — one-shot */
    close(l->listener_fd);
    l->listener_fd = -1;

    if (app_fd < 0) {
        fprintf(stderr, "[vless-listen] accept failed: %s (errno=%d)\n",
                strerror(accept_errno), accept_errno);
        listener_free(l);
        return NULL;
    }

    fprintf(stderr, "[vless-listen] accepted client fd=%d, connecting VLESS...\n",
            app_fd);

    /* Set TCP_NODELAY + SO_NOSIGPIPE on the accepted connection */
    setsockopt(app_fd, IPPROTO_TCP, TCP_NODELAY, &(int){1}, sizeof(int));
#ifdef SO_NOSIGPIPE
    setsockopt(app_fd, SOL_SOCKET, SO_NOSIGPIPE, &(int){1}, sizeof(int));
#endif
    fcntl(app_fd, F_SETFD, FD_CLOEXEC);

    /* Establish VLESS connection (blocking ~200ms) */
    vless_conn_t *conn = NULL;
    int rc = vless_connect_ex(&l->config, &conn);
    if (rc != VLESS_OK) {
        fprintf(stderr, "[vless-listen] vless_connect failed: %s\n",
                vless_last_error());
        close(app_fd);
        listener_free(l);
        return NULL;
    }

    fprintf(stderr, "[vless-listen] VLESS connected, starting bridge\n");

    /* Allocate bridge (same as vless_connect_fd) */
    vless_fd_bridge_t *br = calloc(1, sizeof(vless_fd_bridge_t));
    if (!br) {
        vless_close(conn);
        close(app_fd);
        listener_free(l);
        return NULL;
    }
    br->conn = conn;
    br->internal_fd = app_fd; /* bridge uses the accepted fd directly */
    atomic_init(&br->shutdown, 0);
    atomic_init(&br->threads_done, 0);

    /* Spawn bridge threads (detached) */
    pthread_t t_send, t_recv;
    rc = pthread_create(&t_send, NULL, bridge_send_fn, br);
    if (rc != 0) {
        fprintf(stderr, "[vless-listen] pthread_create(send) failed: %d\n", rc);
        vless_close(conn);
        close(app_fd);
        free(br);
        listener_free(l);
        return NULL;
    }
    pthread_detach(t_send);

    rc = pthread_create(&t_recv, NULL, bridge_recv_fn, br);
    if (rc != 0) {
        fprintf(stderr, "[vless-listen] pthread_create(recv) failed: %d\n", rc);
        atomic_store_explicit(&br->shutdown, 1, memory_order_release);
        shutdown(app_fd, SHUT_WR);
        atomic_fetch_add_explicit(&br->threads_done, 1, memory_order_acq_rel);
        listener_free(l);
        return NULL;
    }
    pthread_detach(t_recv);

    /* Config strings no longer needed — bridge owns conn now */
    listener_free(l);
    return NULL;
}

int vless_listen_start(const vless_config_t *config, uint16_t *port) {
    if (!port) return VLESS_ERR_INVALID_ARG;
    *port = 0;
    if (!config) {
        vless_set_error("vless_listen_start: config is NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    if (!config->reality.public_key || !config->reality.public_key[0]) {
        vless_set_error("vless_listen_start requires REALITY mode");
        return VLESS_ERR_INVALID_ARG;
    }

    /* Deep-copy config strings (caller's may be stack/transient) */
    vless_listener_t *l = calloc(1, sizeof(vless_listener_t));
    if (!l) return VLESS_ERR_NOMEM;
    l->listener_fd = -1;

    l->server_host          = strdup_or_null(config->server_host);
    l->uuid                 = strdup_or_null(config->uuid);
    l->dest_host            = strdup_or_null(config->dest_host);
    l->reality_server_name  = strdup_or_null(config->reality.server_name);
    l->reality_public_key   = strdup_or_null(config->reality.public_key);
    l->reality_short_id     = strdup_or_null(config->reality.short_id);
    l->tls_sni              = strdup_or_null(config->tls.sni);
    l->tls_alpn             = strdup_or_null(config->tls.alpn);
    l->tls_ca_path          = strdup_or_null(config->tls.ca_path);

    /* Build config pointing to our deep copies */
    l->config = *config;
    l->config.server_host          = l->server_host;
    l->config.uuid                 = l->uuid;
    l->config.dest_host            = l->dest_host;
    l->config.reality.server_name  = l->reality_server_name;
    l->config.reality.public_key   = l->reality_public_key;
    l->config.reality.short_id     = l->reality_short_id;
    l->config.tls.sni              = l->tls_sni;
    l->config.tls.alpn             = l->tls_alpn;
    l->config.tls.ca_path          = l->tls_ca_path;

    /* Create listener on 127.0.0.1:0 */
    l->listener_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (l->listener_fd < 0) {
        vless_set_error("vless_listen_start: socket: %s", strerror(errno));
        listener_free(l);
        return VLESS_ERR_IO;
    }

    setsockopt(l->listener_fd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int));
    fcntl(l->listener_fd, F_SETFD, FD_CLOEXEC);

    struct sockaddr_in lo;
    memset(&lo, 0, sizeof(lo));
    lo.sin_family = AF_INET;
    lo.sin_addr.s_addr = htonl(0x7f000001);
    lo.sin_port = 0;

    if (bind(l->listener_fd, (struct sockaddr *)&lo, sizeof(lo)) < 0 ||
        listen(l->listener_fd, 1) < 0) {
        vless_set_error("vless_listen_start: bind/listen: %s", strerror(errno));
        listener_free(l);
        return VLESS_ERR_IO;
    }

    /* Read assigned port */
    socklen_t alen = sizeof(lo);
    getsockname(l->listener_fd, (struct sockaddr *)&lo, &alen);
    *port = ntohs(lo.sin_port);

    /* Spawn accept thread (detached) — returns immediately */
    pthread_t t_accept;
    int rc = pthread_create(&t_accept, NULL, listener_accept_fn, l);
    if (rc != 0) {
        vless_set_error("vless_listen_start: pthread_create: %d", rc);
        listener_free(l);
        return VLESS_ERR_IO;
    }
    pthread_detach(t_accept);

    fprintf(stderr, "[vless-listen] listening on 127.0.0.1:%u\n", *port);
    return VLESS_OK;
}
