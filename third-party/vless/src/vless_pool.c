/*
 * vless_pool.c - Connection pool for VLESS+REALITY
 *
 * Pre-warms TCP+TLS connections (the expensive part) without sending
 * the VLESS header. On acquire, the VLESS header is sent for the
 * requested destination.
 *
 * Thread-safe: all pool state is protected by a mutex.
 * Lifecycle safety: a reference count prevents use-after-free when
 * pool_destroy races with in-flight acquire/release operations.
 * Each acquired connection holds a reference; the pool is freed only
 * when the last reference is dropped.
 */

/* Ensure POSIX APIs (clock_gettime, pthread_condattr_setclock) are available.
 * _DEFAULT_SOURCE is needed for MSG_DONTWAIT on glibc. */
#if !defined(_POSIX_C_SOURCE) || _POSIX_C_SOURCE < 200112L
#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif
#ifndef _DEFAULT_SOURCE
#define _DEFAULT_SOURCE 1
#endif

#include "vless_internal.h"

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <time.h>
#include <pthread.h>
#include <poll.h>
#include <sys/socket.h>
#include <openssl/crypto.h>

#define POOL_LOCK(pool) do { \
    int pool_mrc_ = pthread_mutex_lock(&(pool)->lock); \
    if (pool_mrc_ != 0) abort(); \
} while(0)
#define POOL_UNLOCK(pool) do { \
    int pool_mrc_ = pthread_mutex_unlock(&(pool)->lock); \
    if (pool_mrc_ != 0) abort(); \
} while(0)

/* Maximum pool_size; also sizes the dead-conn array.
 * Must match VLESS_POOL_MAX_SIZE in vless.h. */
#define POOL_MAX_SIZE VLESS_POOL_MAX_SIZE
_Static_assert(POOL_MAX_SIZE * sizeof(void *) <= 4096,
               "dead[] stack array in pool_acquire_impl must fit in one page");

#define POOL_NST_GRACE_SECONDS  5    /* NewSessionTicket grace period for liveness check */
#define POOL_DRAIN_TIMEOUT_S   30    /* Max seconds to wait for active_ops to drain */

/* ─── Pool structure ──────────────────────────────────────────── */

struct vless_pool {
    pthread_mutex_t lock;
    pthread_cond_t  drain_cond; /* signaled when active_ops reaches 0 */

    /* Reference count: starts at 1 (owner). Each acquired connection holds
     * an additional reference via owner_pool. The pool struct (and mutex) is
     * freed only when refcount drops to 0, preventing use-after-free when
     * connections outlive vless_pool_destroy(). */
    int             refcount;   /* protected by lock */

    /* Connection template (no dest) — immutable after vless_pool_create() returns.
     * The following fields are also immutable after create and may be safely
     * read outside the lock: template, uuid, pool_size, max_connections,
     * idle_timeout_s, clock_id, and all owned string pointers below. */
    vless_config_t  template;
    uint8_t         uuid[16];

    /* Idle connections (pre-warmed TCP+TLS, no VLESS header sent) */
    vless_conn_t  **idle;
    int             idle_count;
    int             in_use_count;
    int             pool_size;        /* immutable after create */
    int             max_connections;  /* 0 = unlimited; immutable after create */
    int             idle_timeout_s;   /* seconds, 0 = no timeout; immutable after create */
    int             destroyed;   /* set by vless_pool_destroy */
    int             active_ops;  /* threads inside acquire/release */
    int             deferred_owner_unref; /* set on drain timeout, last thread drops owner ref */
    int             clock_id;    /* clock used for condvar (CLOCK_MONOTONIC or CLOCK_REALTIME) */

    /* Owned string copies */
    char *server_host;
    char *uuid_str;
    char *pub_key;
    char *short_id;
    char *sni;
    char *tls_sni;
    char *tls_alpn;
    char *tls_ca_path;
};

/* Cleanse and free a string (no-op if NULL) */
static void cleanse_free_str(char **s) {
    if (*s) {
        OPENSSL_cleanse(*s, strlen(*s) + 1);
        free(*s);
        *s = NULL;
    }
}

/* Free all pool resources. Caller must ensure no other thread accesses pool. */
static void pool_do_free(struct vless_pool *pool) {
    /* Close idle connections BEFORE destroying mutex/condvar, so that
     * vless_close() can safely call vless_pool_dec_in_use() if any
     * connection unexpectedly has owner_pool set (defense-in-depth). */
    if (pool->idle) {
        for (int i = 0; i < pool->idle_count; i++) {
            if (pool->idle[i]) {
                pool->idle[i]->owner_pool = NULL; /* prevent dec_in_use callback */
                vless_close(pool->idle[i]);
            }
        }
    }
    free(pool->idle);

    OPENSSL_cleanse(pool->uuid, sizeof(pool->uuid));
    cleanse_free_str(&pool->uuid_str);
    cleanse_free_str(&pool->server_host);
    cleanse_free_str(&pool->pub_key);
    cleanse_free_str(&pool->short_id);
    cleanse_free_str(&pool->sni);
    cleanse_free_str(&pool->tls_sni);
    free(pool->tls_alpn);     /* not secrets */
    free(pool->tls_ca_path);  /* not secrets */

    /* Destroy synchronization primitives AFTER all fields are cleaned up,
     * so that any defense-in-depth code paths that might lock can still do so. */
    pthread_cond_destroy(&pool->drain_cond);
    pthread_mutex_destroy(&pool->lock);

    OPENSSL_cleanse(pool, sizeof(*pool));
    free(pool);
}

/* Decrement refcount while the lock is held.  Returns 1 if refcount
 * reached 0 (caller MUST call pool_do_free after releasing the lock).
 * Centralizes the underflow check — all refcount decrements go through here. */
static int pool_dec_ref_locked(struct vless_pool *pool) {
    if (pool->refcount <= 0) abort(); /* refcount underflow — logic bug */
    pool->refcount--;
    return (pool->refcount == 0);
}

/* Drop a reference. If this was the last ref, free the pool.
 * The pool's lock must NOT be held when calling this. */
static void pool_unref(struct vless_pool *pool) {
    POOL_LOCK(pool);
    int should_free = pool_dec_ref_locked(pool);
    POOL_UNLOCK(pool);
    if (should_free)
        pool_do_free(pool);
}

/* ─── Pool back-pointer helper (called from vless_close) ──────── */

/* Decrement in_use_count when a pooled connection is closed directly.
 * This is called from vless_close() via the owner_pool back-pointer,
 * preventing in_use_count leak when callers bypass vless_pool_release().
 * Also drops the connection's reference on the pool — may free the pool
 * if this was the last reference (e.g., after vless_pool_destroy returned). */
VLESS_INTERNAL void vless_pool_dec_in_use(struct vless_pool *pool) {
    if (!pool) return;
    POOL_LOCK(pool);
    if (pool->in_use_count > 0)
        pool->in_use_count--;
    int should_free = pool_dec_ref_locked(pool);
    POOL_UNLOCK(pool);
    if (should_free)
        pool_do_free(pool);
}

/* ─── Helpers ─────────────────────────────────────────────────── */

static char *safe_strdup(const char *s) {
    if (!s) return NULL;
    return strdup(s);
}

/* Check if an idle connection is still alive */
static int conn_is_alive(vless_conn_t *conn, int idle_timeout_s) {
    if (!conn || conn->fd < 0) return 0;
    int saved_errno = errno;
    /* Check for pending socket errors */
    int err = 0;
    socklen_t err_len = sizeof(err);
    if (getsockopt(conn->fd, SOL_SOCKET, SO_ERROR, &err, &err_len) < 0 || err != 0) {
        errno = saved_errno;
        return 0;
    }
    /* Apply idle timeout (unified for both REALITY and plain TLS).
     * idle_timeout_s <= 0 means no timeout. */
    if (idle_timeout_s > 0 && conn->idle_since > 0) {
        struct timespec now;
        if (clock_gettime(CLOCK_MONOTONIC, &now) != 0) {
            errno = saved_errno;
            return 0; /* conservative: treat as dead */
        }
        if ((int64_t)now.tv_sec - conn->idle_since >= idle_timeout_s) {
            errno = saved_errno;
            return 0;
        }
    }
    /* For REALITY connections, data is encrypted TLS records — peeking raw
     * bytes would desynchronize the record parser. Use poll(POLLIN, 0) to
     * detect TCP FIN/RST without reading any data. If the socket is readable
     * but no data was expected (idle connection), it indicates FIN/RST.
     *
     * Grace period: TLS 1.3 servers commonly send NewSessionTicket messages
     * shortly after the handshake. Ignore POLLIN for the first 5 seconds
     * after connection creation to avoid falsely discarding good connections. */
    /* Common liveness check via poll(POLLIN, 0) for both REALITY and plain TLS.
     * Detects TCP FIN/RST without reading data. Grace period handles
     * TLS 1.3 NewSessionTicket messages sent shortly after handshake. */
    {
        struct pollfd pfd = {.fd = conn->fd, .events = POLLIN};
        int pr;
        do {
            pr = poll(&pfd, 1, 0);
        } while (pr < 0 && errno == EINTR);
        if (pr < 0) {
            /* poll error — treat as dead (conservative) */
            errno = saved_errno;
            return 0;
        }
        if (pr > 0 && (pfd.revents & (POLLHUP | POLLERR))) {
            errno = saved_errno;
            return 0;
        }
        if (pr > 0 && (pfd.revents & POLLIN)) {
            /* POLLIN within grace period: likely NewSessionTicket, not FIN */
            if (conn->idle_since > 0) {
                struct timespec now;
                if (clock_gettime(CLOCK_MONOTONIC, &now) == 0 &&
                    (int64_t)now.tv_sec - conn->idle_since < POOL_NST_GRACE_SECONDS) {
                    errno = saved_errno;
                    return 1; /* grace period: assume alive */
                }
            }
            /* Past grace period: unexpected data on idle connection.
             * For plain TLS, also check SSL_pending as a hint. */
            if (!conn->use_reality && conn->ssl && SSL_pending(conn->ssl) > 0) {
                errno = saved_errno;
                return 1; /* SSL has buffered data — still alive */
            }
            errno = saved_errno;
            return 0; /* FIN/RST or unexpected data */
        }
    }
    errno = saved_errno;
    return 1;
}

/* Create a pre-warmed connection (TCP+TLS, no VLESS header) */
static vless_conn_t *pool_create_idle(struct vless_pool *pool) {
    vless_conn_t *c = vless_connect_no_request(&pool->template);
    if (c) {
        struct timespec ts;
        if (clock_gettime(CLOCK_MONOTONIC, &ts) == 0)
            c->idle_since = (int64_t)ts.tv_sec;
    }
    return c;
}

/* ─── Public API ──────────────────────────────────────────────── */

VLESS_API void vless_pool_config_init(vless_pool_config_t *config) {
    if (!config) return;
    memset(config, 0, sizeof(*config));
    vless_config_init(&config->conn);
    config->pool_size = 4;
    config->max_connections = 0;  /* unlimited */
    config->idle_timeout_s = 120;
    config->prefill = 0;
}

VLESS_API vless_pool_t *vless_pool_create(const vless_pool_config_t *config) {
    if (!config || !config->conn.server_host || config->conn.server_host[0] == '\0' ||
        !config->conn.uuid) {
        vless_set_error("Invalid pool config: missing required fields");
        return NULL;
    }
    if (config->conn.server_port == 0) {
        vless_set_error("Invalid pool config: server_port is 0");
        return NULL;
    }

    /* Validate REALITY config consistency: if public_key is set,
     * server_name and short_id must also be set for the handshake to succeed. */
    if (config->conn.reality.public_key && !config->conn.reality.server_name) {
        vless_set_error("Invalid pool config: REALITY public_key set but server_name is missing");
        return NULL;
    }
    if (config->conn.reality.public_key && !config->conn.reality.short_id) {
        vless_set_error("Invalid pool config: REALITY public_key set but short_id is NULL");
        return NULL;
    }
    if (config->conn.reality.short_id) {
        size_t sid_len = strlen(config->conn.reality.short_id);
        if (sid_len > VLESS_REALITY_SHORTID_STRLEN) {
            vless_set_error("Invalid pool config: REALITY short_id too long");
            return NULL;
        }
        if (sid_len % 2 != 0) {
            vless_set_error("Invalid pool config: REALITY short_id must have even length (got %zu)", sid_len);
            return NULL;
        }
        for (size_t i = 0; i < sid_len; i++) {
            char c = config->conn.reality.short_id[i];
            if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F'))) {
                vless_set_error("Invalid pool config: REALITY short_id contains non-hex character");
                return NULL;
            }
        }
    }

    int pool_sz = config->pool_size > 0 ? config->pool_size : 4;
    if (pool_sz > POOL_MAX_SIZE) {
        pool_sz = POOL_MAX_SIZE;
    }

    vless_pool_t *pool = calloc(1, sizeof(vless_pool_t));
    if (!pool) { vless_set_error("Out of memory"); return NULL; }

    pool->refcount = 1; /* owner reference */

    if (pthread_mutex_init(&pool->lock, NULL) != 0) {
        free(pool);
        vless_set_error("pthread_mutex_init failed");
        return NULL;
    }
    /* Use CLOCK_MONOTONIC for timedwait to avoid issues with system clock jumps.
     * Track which clock was used so vless_pool_destroy uses the matching one. */
    pool->clock_id = CLOCK_REALTIME; /* default fallback */
    {
        pthread_condattr_t cattr;
        int cond_ok = 0;
        if (pthread_condattr_init(&cattr) == 0) {
#if defined(CLOCK_MONOTONIC) && !defined(__APPLE__)
            int setclock_ok = (pthread_condattr_setclock(&cattr, CLOCK_MONOTONIC) == 0);
#else
            int setclock_ok = 0;
#endif
            if (pthread_cond_init(&pool->drain_cond, &cattr) == 0) {
                cond_ok = 1;
                if (setclock_ok)
                    pool->clock_id = CLOCK_MONOTONIC;
            }
            pthread_condattr_destroy(&cattr);
        }
        if (!cond_ok) {
            /* Fallback: init without monotonic clock — use CLOCK_REALTIME */
            if (pthread_cond_init(&pool->drain_cond, NULL) != 0) {
                pthread_mutex_destroy(&pool->lock);
                free(pool);
                vless_set_error("pthread_cond_init failed");
                return NULL;
            }
        }
    }

    pool->pool_size = pool_sz;
    pool->max_connections = config->max_connections > 0 ? config->max_connections : 0;
    /* Validate pool_size <= max_connections when both are bounded */
    if (pool->max_connections > 0 && pool_sz > pool->max_connections) {
        pool_sz = pool->max_connections;
        pool->pool_size = pool_sz;
    }
    pool->idle_timeout_s = config->idle_timeout_s >= 0 ? config->idle_timeout_s : 120;

    /* Copy strings so caller doesn't need to keep them alive.
     * Check required strings for allocation failure.
     * IMPORTANT: mutex and condvar are already initialized above, so
     * vless_pool_destroy() can safely be called for cleanup from here on.
     * Do not reorder initialization above this point. */
    pool->server_host = safe_strdup(config->conn.server_host);
    pool->uuid_str    = safe_strdup(config->conn.uuid);
    if (!pool->server_host || !pool->uuid_str) {
        vless_set_error("Out of memory copying pool config strings");
        vless_pool_destroy(pool);
        return NULL;
    }
    pool->pub_key     = safe_strdup(config->conn.reality.public_key);
    pool->short_id    = safe_strdup(config->conn.reality.short_id);
    pool->sni         = safe_strdup(config->conn.reality.server_name);
    pool->tls_sni     = safe_strdup(config->conn.tls.sni);
    pool->tls_alpn    = safe_strdup(config->conn.tls.alpn);
    pool->tls_ca_path = safe_strdup(config->conn.tls.ca_path);
    /* Check that strdup succeeded for all non-NULL input strings */
    if ((config->conn.reality.public_key && !pool->pub_key) ||
        (config->conn.reality.short_id && !pool->short_id) ||
        (config->conn.reality.server_name && !pool->sni) ||
        (config->conn.tls.sni && !pool->tls_sni) ||
        (config->conn.tls.alpn && !pool->tls_alpn) ||
        (config->conn.tls.ca_path && !pool->tls_ca_path)) {
        vless_set_error("Out of memory copying pool config strings");
        vless_pool_destroy(pool);
        return NULL;
    }

    /* Parse UUID once */
    if (vless_parse_uuid(pool->uuid_str, pool->uuid) != VLESS_OK) {
        vless_pool_destroy(pool);
        return NULL;
    }

    /* Build connection template from embedded config, then override string
     * pointers to our owned copies (so caller's strings can be freed). */
    pool->template = config->conn;
    pool->template.server_host         = pool->server_host;
    pool->template.server_port         = config->conn.server_port;
    pool->template.uuid                = pool->uuid_str;
    pool->template.reality.public_key  = pool->pub_key;
    pool->template.reality.short_id    = pool->short_id;
    pool->template.reality.server_name = pool->sni;
    pool->template.tls.sni             = pool->tls_sni;
    pool->template.tls.alpn            = pool->tls_alpn;
    pool->template.tls.ca_path         = pool->tls_ca_path;
    /* dest_host/dest_port intentionally left NULL/0 */
    pool->template.dest_host = NULL;
    pool->template.dest_port = 0;

    /* Allocate idle array */
    pool->idle = calloc((size_t)pool_sz, sizeof(vless_conn_t *));
    if (!pool->idle) {
        vless_set_error("Out of memory");
        vless_pool_destroy(pool);
        return NULL;
    }

    /* Prefill idle connections (lock not needed, no other thread has the handle).
     * Prefill failures are intentionally silent — the pool is still usable
     * with fewer pre-warmed connections; acquire will create on demand. */
    int prefill = config->prefill;
    if (prefill < 0) prefill = 0;
    if (prefill > pool_sz) prefill = pool_sz;
    if (pool->max_connections > 0 && prefill > pool->max_connections)
        prefill = pool->max_connections;
    for (int i = 0; i < prefill; i++) {
        vless_conn_t *c = pool_create_idle(pool);
        if (c) {
            pool->idle[pool->idle_count++] = c;
        }
    }

    return pool;
}

/* Decrement active_ops. If deferred_owner_unref is set and this was the
 * last in-flight operation, set *should_unref to 1. Caller MUST call
 * pool_unref(pool) after POOL_UNLOCK if *should_unref is 1. */
static void pool_dec_active_ops(struct vless_pool *pool, int *should_unref) {
    if (pool->active_ops <= 0) abort(); /* active_ops underflow — logic bug */
    pool->active_ops--;
    *should_unref = (pool->deferred_owner_unref && pool->active_ops == 0);
    if (pool->active_ops == 0)
        pthread_cond_signal(&pool->drain_cond);
}

/* Internal implementation shared by vless_pool_acquire and vless_pool_acquire_ex.
 * Returns VLESS_OK on success (conn written to *out_conn), or negative error code. */
static int pool_acquire_impl(vless_pool_t *pool, const char *dest_host,
                              uint16_t dest_port, vless_conn_t **out_conn) {
    *out_conn = NULL;

    if (!pool || !dest_host || dest_host[0] == '\0' || dest_port == 0) {
        vless_set_error("Invalid pool acquire args (pool=%p dest=%s port=%u)",
                        (const void *)pool, dest_host ? dest_host : "NULL", dest_port);
        return VLESS_ERR_INVALID_ARG;
    }
    if (strlen(dest_host) > 255) {
        vless_set_error("Pool acquire: dest_host too long (%zu bytes, max 255)",
                        strlen(dest_host));
        return VLESS_ERR_INVALID_ARG;
    }

    vless_conn_t *conn = NULL;

    POOL_LOCK(pool);

    if (pool->destroyed) {
        POOL_UNLOCK(pool);
        vless_set_error("Pool is destroyed");
        return VLESS_ERR_CLOSED;
    }

    pool->active_ops++;

    /* Pop idle connections, checking liveness, until we find a live one
     * or exhaust the idle array. Close dead ones along the way.
     * Use pool_size for dead array to avoid closing under lock. */
    vless_conn_t *dead[POOL_MAX_SIZE]; /* Bounded by pool_size clamp in vless_pool_create */
    int dead_count = 0;

    while (pool->idle_count > 0) {
        conn = pool->idle[--pool->idle_count];
        pool->idle[pool->idle_count] = NULL;
        /* Quick fd check under lock; full liveness check outside */
        if (!conn || conn->fd < 0) {
            if (conn) dead[dead_count++] = conn;
            conn = NULL;
            continue;
        }
        /* Speculatively count as in-use under the same lock as the pop
         * to prevent TOCTOU races on max_connections. */
        if (pool->in_use_count >= INT_MAX) {
            dead[dead_count++] = conn;
            conn = NULL;
            break;
        }
        pool->in_use_count++;
        break;
    }

    POOL_UNLOCK(pool);

    /* Close dead connections outside the lock (idle conns have owner_pool==NULL) */
    for (int i = 0; i < dead_count; i++) {
        dead[i]->owner_pool = NULL; /* defensive: prevent dec_in_use callback */
        vless_close(dead[i]);
    }

    /* Full liveness check (SO_ERROR + idle timeout) outside lock.
     * If the connection is dead, undo the speculative increment and retry
     * popping the next idle connection instead of creating a new one. */
    while (conn && !conn_is_alive(conn, pool->idle_timeout_s)) {
        conn->owner_pool = NULL; /* defensive: prevent spurious dec_in_use */
        vless_close(conn);
        conn = NULL;
        /* Undo speculative in_use_count increment and try next idle.
         * Collect dead connections to close outside the lock (same pattern
         * as the first pop loop above). */
        vless_conn_t *retry_dead[POOL_MAX_SIZE];
        int retry_dead_count = 0;
        POOL_LOCK(pool);
        if (pool->destroyed) {
            if (pool->in_use_count > 0) pool->in_use_count--;
            int should_unref_owner = 0;
            pool_dec_active_ops(pool, &should_unref_owner);
            POOL_UNLOCK(pool);
            /* retry_dead_count is always 0 here (just initialized above) */
            if (should_unref_owner) pool_unref(pool);
            vless_set_error("Pool destroyed during acquire");
            return VLESS_ERR_CLOSED;
        }
        if (pool->in_use_count > 0) pool->in_use_count--;
        while (pool->idle_count > 0) {
            conn = pool->idle[--pool->idle_count];
            pool->idle[pool->idle_count] = NULL;
            if (!conn || conn->fd < 0) {
                if (conn) retry_dead[retry_dead_count++] = conn;
                conn = NULL;
                continue;
            }
            if (pool->in_use_count >= INT_MAX) { retry_dead[retry_dead_count++] = conn; conn = NULL; break; }
            pool->in_use_count++;
            break;
        }
        POOL_UNLOCK(pool);
        /* Close dead connections outside the lock */
        for (int i = 0; i < retry_dead_count; i++) {
            retry_dead[i]->owner_pool = NULL;
            vless_close(retry_dead[i]);
        }
        /* Loop continues: if conn is set, re-check liveness outside lock */
    }

    if (conn) {
        POOL_LOCK(pool);
        if (pool->destroyed) {
            if (pool->in_use_count > 0) pool->in_use_count--;
            int should_unref_owner = 0;
            pool_dec_active_ops(pool, &should_unref_owner);
            POOL_UNLOCK(pool);
            vless_close(conn);
            if (should_unref_owner) pool_unref(pool);
            vless_set_error("Pool destroyed during acquire");
            return VLESS_ERR_CLOSED;
        }
        /* in_use_count already incremented in the pop loop above */
        POOL_UNLOCK(pool);
    }

    /* If no idle connection, create a new one (outside lock).
     * Enforce max_connections atomically under lock to prevent TOCTOU races
     * where two threads both pass the check and exceed the limit. */
    if (!conn) {
        /* Check destroyed before expensive TCP+TLS handshake to avoid
         * delaying vless_pool_destroy() by the handshake duration. */
        POOL_LOCK(pool);
        if (pool->destroyed) {
            int should_unref_owner = 0;
            pool_dec_active_ops(pool, &should_unref_owner);
            POOL_UNLOCK(pool);
            if (should_unref_owner) pool_unref(pool);
            vless_set_error("Pool destroyed during acquire");
            return VLESS_ERR_CLOSED;
        }
        if (pool->max_connections > 0) {
            int total = pool->idle_count + pool->in_use_count;
            if (total >= pool->max_connections) {
                int should_unref_owner = 0;
                pool_dec_active_ops(pool, &should_unref_owner);
                POOL_UNLOCK(pool);
                if (should_unref_owner) pool_unref(pool);
                vless_set_error("Pool max_connections limit reached (%d)", pool->max_connections);
                return VLESS_ERR_POOL_FULL;
            }
            /* Speculatively reserve a slot so concurrent threads see it */
            pool->in_use_count++;
        }
        POOL_UNLOCK(pool);
        conn = pool_create_idle(pool);
        if (!conn) {
            POOL_LOCK(pool);
            /* Undo speculative reservation if max_connections was enforced */
            if (pool->max_connections > 0 && pool->in_use_count > 0)
                pool->in_use_count--;
            int should_unref_owner = 0;
            pool_dec_active_ops(pool, &should_unref_owner);
            POOL_UNLOCK(pool);
            if (should_unref_owner) pool_unref(pool);
            return VLESS_ERR_CONNECT;
        }

        POOL_LOCK(pool);
        if (pool->destroyed) {
            /* Undo speculative reservation if max_connections was enforced */
            if (pool->max_connections > 0 && pool->in_use_count > 0)
                pool->in_use_count--;
            int should_unref_owner = 0;
            pool_dec_active_ops(pool, &should_unref_owner);
            POOL_UNLOCK(pool);
            vless_close(conn);
            if (should_unref_owner) pool_unref(pool);
            vless_set_error("Pool destroyed during acquire");
            return VLESS_ERR_CLOSED;
        }
        /* If max_connections was not enforced (unlimited), do the increment now */
        if (pool->max_connections <= 0) {
            if (pool->in_use_count >= INT_MAX) {
                int should_unref_owner = 0;
                pool_dec_active_ops(pool, &should_unref_owner);
                POOL_UNLOCK(pool);
                vless_close(conn);
                if (should_unref_owner) pool_unref(pool);
                vless_set_error("Pool in_use_count overflow");
                return VLESS_ERR_POOL_FULL;
            }
            pool->in_use_count++;
        }
        POOL_UNLOCK(pool);
    }

    /* Set pool back-pointer so vless_close() auto-decrements in_use_count.
     * Take a reference so the pool stays alive until this connection is closed. */
    POOL_LOCK(pool);
    if (pool->refcount >= INT_MAX) {
        /* Prevent refcount overflow — extremely unlikely but guard against it */
        int should_unref_owner = 0;
        if (pool->in_use_count > 0) pool->in_use_count--;
        pool_dec_active_ops(pool, &should_unref_owner);
        POOL_UNLOCK(pool);
        vless_close(conn);
        if (should_unref_owner) pool_unref(pool);
        vless_set_error("Pool refcount overflow");
        return VLESS_ERR_NOMEM;
    }
    pool->refcount++;
    conn->owner_pool = pool;
    POOL_UNLOCK(pool);

    /* Send VLESS request header for the requested destination */
    int rc = vless_send_request(conn, pool->uuid, dest_host, dest_port,
                                 pool->template.vision_enabled);
    if (rc != VLESS_OK) {
        /* Clear owner_pool to prevent vless_close from calling dec_in_use,
         * since we handle in_use_count and refcount manually below. */
        conn->owner_pool = NULL;
        vless_close(conn);
        POOL_LOCK(pool);
        if (pool->in_use_count > 0) pool->in_use_count--;
        int should_free = pool_dec_ref_locked(pool);
        int should_unref_owner = 0;
        pool_dec_active_ops(pool, &should_unref_owner);
        POOL_UNLOCK(pool);
        /* Dual-path free: pool_do_free when the connection's ref drop brings
         * refcount to 0; pool_unref for the deferred owner ref (a different
         * reference — these never overlap due to the else-if guard). */
        if (should_free) pool_do_free(pool);
        else if (should_unref_owner) pool_unref(pool);
        return rc;
    }

    POOL_LOCK(pool);
    int should_unref_owner = 0;
    pool_dec_active_ops(pool, &should_unref_owner);
    POOL_UNLOCK(pool);
    if (should_unref_owner) pool_unref(pool);

    *out_conn = conn;
    return VLESS_OK;
}

VLESS_API vless_conn_t *vless_pool_acquire(vless_pool_t *pool,
                                  const char *dest_host, uint16_t dest_port) {
    vless_conn_t *conn = NULL;
    (void)pool_acquire_impl(pool, dest_host, dest_port, &conn);
    return conn;
}

VLESS_API int vless_pool_acquire_ex(vless_pool_t *pool, const char *dest_host,
                           uint16_t dest_port, vless_conn_t **out) {
    if (!out) {
        vless_set_error("vless_pool_acquire_ex: out parameter is NULL");
        return VLESS_ERR_INVALID_ARG;
    }
    *out = NULL;
    return pool_acquire_impl(pool, dest_host, dest_port, out);
}

VLESS_API void vless_pool_release(vless_pool_t *pool, vless_conn_t *conn) {
    if (!pool || !conn) return;

    POOL_LOCK(pool);
    /* Verify conn belongs to this pool under lock to prevent TOCTOU race:
     * without the lock, two threads releasing the same conn could both pass
     * the owner_pool check before either sets owner_pool = NULL, leading to
     * a double-free.  Reject connections that were never acquired from a pool
     * (owner_pool == NULL) as well as connections from a different pool. */
    if (conn->owner_pool != pool) {
        POOL_UNLOCK(pool);
        vless_set_error("vless_pool_release: connection does not belong to this pool");
        vless_close(conn); /* close to prevent resource leak */
        return;
    }
    /* Increment active_ops BEFORE checking destroyed, consistent with
     * vless_pool_acquire(). This ensures vless_pool_destroy()'s drain
     * loop does not return while this release is still in progress. */
    pool->active_ops++;
    if (pool->destroyed) {
        /* Pool is being torn down. Still clean up the connection.
         * Dec active_ops so destroy's drain can complete. */
        int should_unref_owner = 0;
        pool_dec_active_ops(pool, &should_unref_owner);
        POOL_UNLOCK(pool);
        /* Let vless_close handle dec_in_use + refcount via owner_pool */
        vless_close(conn);
        if (should_unref_owner) pool_unref(pool);
        return;
    }
    /* Clear owner_pool under lock to guard against double-release:
     * a second concurrent release of the same conn would see NULL here
     * and be rejected by the owner_pool != pool check above. */
    conn->owner_pool = NULL;
    POOL_UNLOCK(pool);

    /* Close the used connection outside lock (can't reuse for a different dest) */
    vless_close(conn);

    POOL_LOCK(pool);
    if (pool->in_use_count > 0)
        pool->in_use_count--;
    /* Drop the connection's reference on the pool */
    int should_free = pool_dec_ref_locked(pool);
    int should_unref_owner = 0;
    pool_dec_active_ops(pool, &should_unref_owner);
    POOL_UNLOCK(pool);
    if (should_free)
        pool_do_free(pool);
    else if (should_unref_owner)
        pool_unref(pool);
}

VLESS_API void vless_pool_destroy(vless_pool_t *pool) {
    if (!pool) return;

    /* Collect idle connections under lock, then close outside */
    vless_conn_t **to_close = NULL;
    int close_count = 0;

    /* Guard against concurrent double-destroy: the first caller sets
     * destroyed=1 and proceeds; any concurrent caller sees the flag and returns.
     * Note: calling destroy after it has already completed and freed the pool
     * is undefined behavior (same as double-free). */
    POOL_LOCK(pool);
    if (pool->destroyed) {
        POOL_UNLOCK(pool);
        return;
    }
    pool->destroyed = 1;

    /* Wait for in-flight acquire/release operations to finish.
     * We only wait for active_ops here, NOT in_use_count — outstanding
     * connections hold a refcount and will keep the pool alive until closed.
     * Use a timed wait to avoid blocking indefinitely. */
    {
        struct timespec abs_deadline;
        if (clock_gettime((clockid_t)pool->clock_id, &abs_deadline) != 0) {
            /* clock_gettime failed — skip drain wait entirely */
            vless_set_error("pool_destroy: clock_gettime failed, skipping drain");
            pool->deferred_owner_unref = (pool->active_ops > 0);
        } else {
            abs_deadline.tv_sec += POOL_DRAIN_TIMEOUT_S;
            while (pool->active_ops > 0) {
                int wrc = pthread_cond_timedwait(&pool->drain_cond, &pool->lock,
                                                  &abs_deadline);
                if (wrc == ETIMEDOUT) {
                    vless_set_error("pool_destroy: timed out waiting for %d active_ops",
                                    pool->active_ops);
                    /* Do NOT zero active_ops — in-flight threads still reference
                     * the pool. Defer the owner unref to the last finishing thread
                     * to prevent use-after-free. */
                    pool->deferred_owner_unref = 1;
                    break;
                }
                if (wrc != 0) {
                    /* Unexpected error (e.g. EINVAL) — treat as timeout to
                     * avoid spinning indefinitely on a persistent error. */
                    vless_set_error("pool_destroy: pthread_cond_timedwait failed (%d)", wrc);
                    pool->deferred_owner_unref = (pool->active_ops > 0);
                    break;
                }
            }
        }
    }

    /* Guard against condvar timeout racing with the last active_ops decrement.
     * POSIX allows timedwait to return ETIMEDOUT even if the condition was
     * signaled, so active_ops may already be 0 when deferred_owner_unref is set.
     * In that case, no in-flight thread will trigger the deferred unref —
     * clear the flag so vless_pool_destroy drops the owner reference itself. */
    if (pool->deferred_owner_unref && pool->active_ops == 0)
        pool->deferred_owner_unref = 0;

    if (pool->idle) {
        to_close = pool->idle;
        close_count = pool->idle_count;
        pool->idle = NULL;
        pool->idle_count = 0;
    }
    int deferred = pool->deferred_owner_unref;
    POOL_UNLOCK(pool);

    /* Close idle connections outside the lock */
    for (int i = 0; i < close_count; i++) {
        if (to_close[i]) {
            to_close[i]->owner_pool = NULL; /* prevent dec_in_use callback */
            vless_close(to_close[i]);
        }
    }
    free(to_close);

    /* Drop the owner reference. If no connections are outstanding (refcount
     * was 1), this frees the pool. Otherwise the pool stays alive until the
     * last connection calls vless_close() -> vless_pool_dec_in_use().
     * If drain timed out, the last in-flight thread drops the owner ref. */
    if (!deferred)
        pool_unref(pool);
}

VLESS_API void vless_pool_stats(vless_pool_t *pool, vless_pool_stats_t *out) {
    if (!pool || !out) {
        if (out) memset(out, 0, sizeof(*out));
        if (pool && !out)
            vless_set_error("vless_pool_stats: out parameter is NULL");
        return;
    }

    POOL_LOCK(pool);
    if (pool->destroyed) {
        memset(out, 0, sizeof(*out));
        POOL_UNLOCK(pool);
        return;
    }
    /* Participate in active_ops to prevent use-after-free if
     * vless_pool_destroy() races with this call. */
    pool->active_ops++;
    memset(out, 0, sizeof(*out)); /* zero reserved fields */
    out->idle    = pool->idle_count;
    out->in_use  = pool->in_use_count;
    out->total   = (pool->idle_count <= INT_MAX - pool->in_use_count)
                   ? pool->idle_count + pool->in_use_count : INT_MAX;
    int should_unref = 0;
    pool_dec_active_ops(pool, &should_unref);
    POOL_UNLOCK(pool);
    if (should_unref) pool_unref(pool);
}
