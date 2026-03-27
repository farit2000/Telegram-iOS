/*
 * vless.h - Cross-platform VLESS + REALITY client library
 *
 * Supports:
 *   - VLESS over plain TLS (basic mode)
 *   - VLESS + REALITY + Vision (stealth mode, recommended)
 *     Chrome TLS fingerprint, x25519 REALITY auth, Vision padding
 *
 * Uses BoringSSL/OpenSSL for crypto primitives only.
 * TLS 1.3 handshake is implemented manually for full fingerprint control.
 *
 * NOTE: On Linux, the first call to vless_connect() or vless_pool_acquire()
 * sets SIGPIPE to SIG_IGN process-wide (required because OpenSSL's internal
 * send() cannot use MSG_NOSIGNAL). On macOS/BSD, SO_NOSIGPIPE is used
 * per-socket instead. Applications that rely on SIGPIPE should be aware.
 *
 * Thread safety:
 *   - Different connections may be used from different threads freely.
 *   - For REALITY mode, vless_send and vless_recv may be called concurrently
 *     on the same connection from different threads (full-duplex).
 *   - The first vless_recv must complete before starting concurrent access.
 *   - vless_close must not be called while send/recv is in progress.
 *   - Plain TLS mode does not support concurrent send/recv.
 */

#ifndef VLESS_H
#define VLESS_H

#include <stddef.h>
#include <stdint.h>

/** Library version (updated per release) */
#define VLESS_VERSION_MAJOR 1
#define VLESS_VERSION_MINOR 0
#define VLESS_VERSION_PATCH 0

/** Stringify helpers for version string construction */
#define VLESS_STR_(x)  VLESS_STR2_(x)
#define VLESS_STR2_(x) #x
#define VLESS_VERSION_STRING \
    VLESS_STR_(VLESS_VERSION_MAJOR) "." \
    VLESS_STR_(VLESS_VERSION_MINOR) "." \
    VLESS_STR_(VLESS_VERSION_PATCH)

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @defgroup errors Error codes
 * All public functions return these codes (0 = success, negative = error).
 * Named enum enables -Wswitch exhaustiveness checking in consumer code.
 * @{
 */
typedef enum {
    VLESS_OK                =  0,  /**< Success */
    VLESS_ERR_INVALID_ARG   = -1,  /**< NULL pointer or invalid parameter */
    VLESS_ERR_RESOLVE       = -2,  /**< DNS resolution failed */
    VLESS_ERR_CONNECT       = -3,  /**< TCP connection failed */
    VLESS_ERR_TLS           = -4,  /**< TLS handshake or protocol error */
    VLESS_ERR_PROTOCOL      = -5,  /**< VLESS/TLS framing violation */
    VLESS_ERR_CLOSED        = -6,  /**< Connection closed by peer */
    VLESS_ERR_TIMEOUT       = -7,  /**< Operation timed out */
    VLESS_ERR_NOMEM         = -8,  /**< Memory allocation failed */
    VLESS_ERR_UUID          = -9,  /**< Malformed UUID string */
    VLESS_ERR_IO            = -10, /**< Socket read/write error */
    VLESS_ERR_AUTH          = -11, /**< REALITY authentication failed */
    VLESS_ERR_CRYPTO        = -12, /**< Cryptographic operation failed */
    VLESS_ERR_POOL_FULL     = -13, /**< Pool max_connections limit reached */
    VLESS_ERR_CERT          = -14  /**< Server certificate verification failed */
    /* New error codes may be added with more-negative values in future
     * versions. Switch statements should include a default case. */
} vless_error_t;
/** @} */

/** UUID constants for buffer sizing */
#define VLESS_UUID_BYTES    16   /**< Raw UUID size in bytes */
#define VLESS_UUID_STRLEN   36   /**< UUID string length (without NUL terminator) */
#define VLESS_UUID_BUF_SIZE 37   /**< Buffer size for UUID string (including NUL) */

/** Symbol visibility for public API.
 *  On GCC/Clang, always mark public symbols as default visibility so they
 *  remain exported when the library is built with -fvisibility=hidden
 *  (applied for both static and shared builds to prevent internal symbol
 *  leakage when a static libvless is linked into a consumer's shared lib).
 *  MSVC dllexport/dllimport is only needed for shared builds. */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_API __attribute__((visibility("default")))
#elif defined(VLESS_SHARED) && defined(_MSC_VER)
#ifdef VLESS_BUILDING
#define VLESS_API __declspec(dllexport)
#else
#define VLESS_API __declspec(dllimport)
#endif
#else
#define VLESS_API
#endif

/** Compiler attribute to warn when return value is ignored */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_WARN_UNUSED __attribute__((warn_unused_result))
#else
#define VLESS_WARN_UNUSED
#endif

/** Compiler attribute to warn when non-NULL parameter receives NULL */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_NONNULL(...) __attribute__((nonnull(__VA_ARGS__)))
#else
#define VLESS_NONNULL(...)
#endif

/** Suppress unused-function warnings portably (GCC/Clang/MSVC) */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_UNUSED __attribute__((unused))
#elif defined(_MSC_VER)
#define VLESS_UNUSED __pragma(warning(suppress: 4505))
#else
#define VLESS_UNUSED
#endif

/** Mark a function as deprecated with a message */
#if defined(__GNUC__) || defined(__clang__)
#define VLESS_DEPRECATED(msg) __attribute__((deprecated(msg)))
#elif defined(_MSC_VER)
#define VLESS_DEPRECATED(msg) __declspec(deprecated(msg))
#else
#define VLESS_DEPRECATED(msg)
#endif

/**
 * @brief Opaque connection handle.
 *
 * Represents a VLESS tunnel (TCP + TLS + VLESS protocol).
 * Created by vless_connect(), destroyed by vless_close().
 * See top-of-file "Thread safety" section for concurrent access rules.
 */
typedef struct vless_conn vless_conn_t;

/** Chrome version fingerprint for REALITY stealth.
 *  Values are actual Chrome version numbers; use VLESS_CHROME_AUTO for latest.
 *  Unsupported values fall back to VLESS_CHROME_AUTO. */
typedef enum {
    VLESS_CHROME_AUTO = 0,   /**< Latest supported (currently 131) */
    VLESS_CHROME_120  = 120, /**< Chrome 120 (Dec 2023) */
    VLESS_CHROME_124  = 124, /**< Chrome 124 (Apr 2024) -- first with MLKEM */
    VLESS_CHROME_131  = 131, /**< Chrome 131 (Nov 2024) -- new ALPS code point */
    VLESS_CHROME_LATEST = VLESS_CHROME_131 /**< Alias for latest supported profile */
} vless_chrome_fingerprint_t;

/** REALITY public key max string length (base64-encoded X25519, 43 without padding or 44 with) */
#define VLESS_REALITY_PUBKEY_STRLEN  44
/** REALITY short ID max string length (hex-encoded, 8 bytes) */
#define VLESS_REALITY_SHORTID_STRLEN 16
/** Maximum pool size (idle connections) */
#define VLESS_POOL_MAX_SIZE 256

/**
 * @brief REALITY configuration (recommended for censorship resistance).
 *
 * When reality.public_key is set, REALITY mode is used instead of plain TLS.
 * REALITY makes traffic indistinguishable from legitimate HTTPS to the
 * specified server_name. The TLS handshake mimics Chrome's fingerprint and
 * uses the real website's certificate chain.
 */
typedef struct {
    const char *server_name;    /**< SNI domain to front (e.g. "www.microsoft.com") */
    const char *public_key;     /**< Server's x25519 public key, base64 (VLESS_REALITY_PUBKEY_STRLEN chars) */
    const char *short_id;       /**< Hex-encoded short ID, up to VLESS_REALITY_SHORTID_STRLEN hex chars */
    vless_chrome_fingerprint_t fingerprint; /**< Chrome version to emulate (default: AUTO) */
    int _reserved[4]; /**< Reserved for future use — must be zero-initialized */
} vless_reality_config_t;

/**
 * @brief Plain TLS configuration (basic mode).
 *
 * Used when reality.public_key is NULL. Traffic is standard TLS and may
 * be identifiable by DPI as a proxy connection.
 */
typedef struct {
    const char *sni;            /**< Server Name Indication, NULL = use server_host */
    const char *alpn;           /**< ALPN protocols, comma-separated, NULL for none */
    int         verify_peer;    /**< Non-zero = verify server cert, 0 = skip */
    const char *ca_path;        /**< CA bundle path, NULL for system default */
    int _reserved[4]; /**< Reserved for future use — must be zero-initialized */
} vless_tls_config_t;

/**
 * @brief Connection configuration.
 *
 * Holds all parameters needed to establish a VLESS tunnel.
 * Initialize with vless_config_init() before setting individual fields.
 *
 * Ownership: all string pointer members are borrowed. The library copies
 * them internally during vless_connect() and vless_pool_create(). They
 * need only remain valid for the duration of those calls.
 */
typedef struct {
    /* VLESS server */
    const char *server_host;    /**< Proxy server hostname or IP */
    uint16_t    server_port;    /**< Proxy server port (default: 443) */

    /* VLESS authentication */
    const char *uuid;           /**< UUID string "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" */

    /* Destination to tunnel to */
    const char *dest_host;      /**< Destination hostname or IP (max 255 bytes) */
    uint16_t    dest_port;      /**< Destination port */

    /* REALITY config (set public_key to enable; overrides tls settings) */
    vless_reality_config_t reality;

    /* Plain TLS config (used only when reality.public_key is NULL) */
    vless_tls_config_t tls;

    /** Vision flow: adds padding to resist traffic analysis (recommended) */
    int vision_enabled;

    /** Connect timeout in milliseconds. 0 or negative = default (15s) */
    int connect_timeout_ms;
    /** I/O timeout in milliseconds. 0 or negative = default (30s) */
    int io_timeout_ms;
    int _reserved[8]; /**< Reserved for future use — must be zero-initialized */
} vless_config_t;

/**
 * @brief Initialize config with safe defaults.
 * @param config Config struct to initialize. No-op if NULL.
 *
 * Sets: server_port=443, connect_timeout=15s, io_timeout=30s,
 * verify_peer=1, vision=enabled.
 */
VLESS_API void vless_config_init(vless_config_t *config);

/**
 * @brief Establish a VLESS connection.
 * @param config Connection parameters. Must remain valid only during this call.
 * @return Opaque connection handle, or NULL on failure.
 *
 * With REALITY (config->reality.public_key != NULL):
 *   1. TCP connect to server
 *   2. Manual TLS 1.3 handshake with Chrome fingerprint + REALITY auth
 *   3. VLESS request header with Vision flow (if enabled)
 *
 * Without REALITY:
 *   1. TCP connect to server
 *   2. Standard TLS handshake via BoringSSL/OpenSSL
 *   3. VLESS request header
 *
 * On failure, call vless_last_error() for a human-readable description.
 *
 * Side effect: on Linux, the first call sets SIGPIPE to SIG_IGN process-wide
 * (required because OpenSSL's internal send() cannot use MSG_NOSIGNAL).
 * On macOS/BSD, SO_NOSIGPIPE is used per-socket instead.
 */
VLESS_API VLESS_WARN_UNUSED
vless_conn_t *vless_connect(const vless_config_t *config);

/**
 * @brief Establish a VLESS connection with structured error codes.
 * @param config Connection parameters. Must remain valid only during this call.
 * @param out    On success, set to the connection handle. On failure, set to NULL.
 *               Must not be NULL.
 * @return VLESS_OK on success, or a negative error code:
 *         VLESS_ERR_INVALID_ARG  — NULL/invalid config or destination.
 *         VLESS_ERR_NOMEM        — Memory allocation failed.
 *         VLESS_ERR_UUID         — Malformed UUID string.
 *         VLESS_ERR_RESOLVE      — DNS resolution failed.
 *         VLESS_ERR_CONNECT      — TCP connection failed.
 *         VLESS_ERR_TLS          — TLS handshake failed.
 *         VLESS_ERR_AUTH         — REALITY authentication failed.
 *         VLESS_ERR_CRYPTO       — Cryptographic operation failed.
 *         VLESS_ERR_CERT         — Certificate verification failed.
 *         VLESS_ERR_PROTOCOL     — Protocol framing violation.
 *         VLESS_ERR_IO           — Socket I/O error.
 *         VLESS_ERR_TIMEOUT      — Connection or handshake timed out.
 *         VLESS_ERR_CLOSED       — Connection closed by peer.
 *
 * Like vless_connect(), but returns a structured error code instead of NULL,
 * allowing callers to distinguish failure modes programmatically.
 * Call vless_last_error() for a human-readable description on failure.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_connect_ex(const vless_config_t *config, vless_conn_t **out);

/**
 * @brief Establish a VLESS tunnel and return a plain file descriptor.
 *
 * Creates a REALITY+VLESS connection and returns a standard Unix fd that
 * the caller can use with read()/write()/poll()/close(). Two internal
 * threads bridge data between the fd and the encrypted VLESS tunnel.
 *
 * Closing app_fd is the only cleanup required: the bridge threads detect
 * EOF and automatically close the VLESS connection and free all resources.
 *
 * The returned fd is blocking. The caller may set it non-blocking with
 * fcntl() for use with event loops (GCD dispatch sources, epoll, etc.).
 *
 * Requires REALITY mode (config must have reality.public_key set).
 * Plain TLS does not support the concurrent send/recv needed internally.
 *
 * @param config  Connection parameters (same as vless_connect).
 * @param app_fd  On success, set to a file descriptor for the caller.
 *                On failure, set to -1.
 * @return VLESS_OK on success, or a negative error code.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_connect_fd(const vless_config_t *config, int *app_fd);

/**
 * @brief Start a local TCP listener that bridges to a VLESS tunnel.
 *
 * Creates a TCP listener on 127.0.0.1 with a kernel-assigned port.
 * Returns immediately (non-blocking). When a client connects to the
 * port, a background thread establishes the VLESS+REALITY tunnel and
 * bridges data between the local TCP connection and the tunnel.
 *
 * The listener accepts exactly one connection, then closes itself.
 * All resources (VLESS connection, bridge threads, listener) are freed
 * automatically when the client disconnects.
 *
 * Designed for GCDAsyncSocket / CFStream integration:
 * @code
 *   uint16_t port;
 *   vless_listen_start(&config, &port);
 *   [socket connectToHost:@"127.0.0.1" onPort:port];
 * @endcode
 *
 * Requires REALITY mode.
 *
 * @param config  Connection parameters (deep-copied internally).
 * @param port    On success, set to the listening port number.
 * @return VLESS_OK on success, or a negative error code.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_listen_start(const vless_config_t *config, uint16_t *port);

/**
 * @brief Send data through the VLESS tunnel.
 * @param conn  Connection handle from vless_connect().
 * @param data  Buffer to send. Must not be NULL.
 * @param len   Number of bytes to send. Must be > 0. Internally clamped
 *              to INT_MAX per call.
 * @return Number of bytes sent (may be less than @p len), or negative error code.
 *         The return value is clamped to INT_MAX even if more bytes were sent.
 *
 * During Vision flow, the first 8 messages are automatically framed with
 * random padding. After that, data is sent directly.
 *
 * Note: during Vision framing, a partial return (less than @p len) may
 * indicate the connection has been closed due to a framing error.
 * Subsequent calls will return VLESS_ERR_CLOSED.
 *
 * Thread safety: for REALITY mode, one thread may call vless_send while
 * another calls vless_recv on the same connection. The first vless_recv
 * must complete before concurrent access begins.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_send(vless_conn_t *conn, const void *data, size_t len);

/**
 * @brief Receive data from the VLESS tunnel.
 * @param conn    Connection handle from vless_connect().
 * @param buf     Buffer to receive into. Must not be NULL.
 * @param buf_len Size of @p buf in bytes. Must be > 0. Internally clamped
 *                to INT_MAX per call.
 * @return Number of bytes read, 0 on EOF, or negative error code.
 *         The return value is clamped to INT_MAX even if more bytes were read.
 *
 * The first call triggers parsing of the VLESS response header.
 * Vision framing is automatically stripped from received data.
 *
 * Thread safety: for REALITY mode, one thread may call vless_recv while
 * another calls vless_send on the same connection. The first vless_recv
 * must complete before concurrent access begins.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_recv(vless_conn_t *conn, void *buf, size_t buf_len);

/**
 * @brief Get the underlying socket file descriptor.
 * @param conn Connection handle, or NULL.
 * @return Socket fd for use with poll()/epoll(), or -1 if @p conn is NULL.
 *
 * Useful for integrating with event loops. Do not read/write the fd directly;
 * use vless_send()/vless_recv() instead.
 */
VLESS_API VLESS_WARN_UNUSED int vless_get_fd(const vless_conn_t *conn);

/**
 * @brief Close connection and free all resources.
 * @param conn Connection handle, or NULL (no-op if NULL).
 *
 * Sends a TLS close_notify alert (REALITY mode) or SSL_shutdown (plain TLS)
 * before closing the socket. Safe to call with NULL (no-op).
 * After this call, the conn pointer must not be used again (it is freed).
 * All key material is securely erased with OPENSSL_cleanse().
 *
 * Thread safety: the caller must ensure no other thread is calling
 * vless_send or vless_recv on this connection when vless_close is called.
 */
VLESS_API void vless_close(vless_conn_t *conn);

/**
 * @brief Get the last error description (thread-local).
 * @return NUL-terminated string describing the most recent error in this thread.
 *
 * The returned pointer is valid until the next VLESS API call on the same thread.
 * Returns an empty string if no error has occurred.
 * Note: successful calls do NOT clear the error buffer. Call vless_clear_error()
 * explicitly if you need to distinguish stale errors from fresh ones.
 */
VLESS_API const char *vless_last_error(void);

/**
 * @brief Clear the thread-local error buffer.
 *
 * After this call, vless_last_error() returns an empty string until the next error.
 */
VLESS_API void vless_clear_error(void);

/**
 * @brief Get the library version string at runtime.
 * @return NUL-terminated version string, e.g. "1.0.0". Always valid.
 */
VLESS_API const char *vless_version(void);

/**
 * @brief Parse a UUID string into 16 raw bytes.
 * @param uuid_str  UUID in "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" format.
 * @param uuid_out  Output buffer, must be at least 16 bytes.
 * @return VLESS_OK on success, VLESS_ERR_INVALID_ARG if uuid_str or uuid_out
 *         is NULL, VLESS_ERR_UUID on malformed input.
 */
VLESS_API VLESS_WARN_UNUSED
#ifndef __cplusplus
int vless_parse_uuid(const char *uuid_str, uint8_t uuid_out[static 16]);
#else
int vless_parse_uuid(const char *uuid_str, uint8_t uuid_out[16]);
#endif

/* ─── Connection Pool ──────────────────────────────────────── */

/**
 * @brief Opaque connection pool handle.
 *
 * Manages a pool of pre-warmed TCP+TLS connections to a VLESS server.
 * On acquire, the VLESS header is sent for the requested destination.
 * Thread-safe: all operations are protected by an internal mutex.
 */
typedef struct vless_pool vless_pool_t;

/**
 * @brief Pool configuration.
 *
 * Embeds vless_config_t for connection parameters (server, auth, TLS).
 * Pool-specific fields (pool_size, max_connections, etc.) follow.
 * The conn.dest_host and conn.dest_port fields are ignored — destinations
 * are specified per-acquire via vless_pool_acquire().
 */
typedef struct {
    vless_config_t conn;  /**< Connection parameters (dest_host/dest_port ignored) */
    int pool_size;        /**< Max idle connections (default: 4, max: VLESS_POOL_MAX_SIZE, <=0 = default).
                               Silently clamped to max_connections if both are set and pool_size exceeds it. */
    int max_connections;  /**< Max total connections (idle+in_use), 0 = unlimited */
    int idle_timeout_s;   /**< Idle timeout in seconds (default: 120, 0 = no timeout, <0 = default) */
    int prefill;          /**< Pre-warm this many on create (default: 0, <0 treated as 0) */
    int _reserved[4]; /**< Reserved for future use — must be zero-initialized */
} vless_pool_config_t;

/**
 * @brief Initialize pool config with safe defaults.
 * @param config Config struct to initialize. No-op if NULL.
 */
VLESS_API void vless_pool_config_init(vless_pool_config_t *config);

/**
 * @brief Create a connection pool.
 * @param config Pool parameters. String pointers are copied internally.
 * @return Pool handle, or NULL on failure.
 */
VLESS_API VLESS_WARN_UNUSED
vless_pool_t *vless_pool_create(const vless_pool_config_t *config);

/**
 * @brief Acquire a connection from the pool for a specific destination.
 * @param pool Pool handle from vless_pool_create().
 * @param dest_host Destination hostname or IP.
 * @param dest_port Destination port. Must be non-zero.
 * @return Connection handle ready for vless_send/vless_recv, or NULL on failure.
 *
 * Takes an idle pre-warmed connection (or creates a new one),
 * sends the VLESS header for the given destination, and returns it.
 * On failure, call vless_last_error() for details. For structured error
 * handling (e.g. distinguishing pool-full from connect failure), use
 * vless_pool_acquire_ex() instead.
 */
VLESS_API VLESS_WARN_UNUSED
vless_conn_t *vless_pool_acquire(vless_pool_t *pool,
                                  const char *dest_host, uint16_t dest_port);

/**
 * @brief Acquire a connection with structured error codes.
 * @param pool      Pool handle from vless_pool_create().
 * @param dest_host Destination hostname or IP.
 * @param dest_port Destination port.
 * @param out       On success, set to the acquired connection handle.
 *                  On failure, set to NULL. Must not be NULL.
 * @return VLESS_OK on success, or a negative error code:
 *         VLESS_ERR_INVALID_ARG  — NULL pool/dest_host/out or dest_port==0.
 *         VLESS_ERR_POOL_FULL    — max_connections limit reached.
 *         VLESS_ERR_CLOSED       — pool has been destroyed.
 *         VLESS_ERR_CONNECT      — TCP/TLS connection failed.
 *         Other negative codes   — VLESS header send or crypto errors.
 */
VLESS_API VLESS_WARN_UNUSED
int vless_pool_acquire_ex(vless_pool_t *pool, const char *dest_host,
                           uint16_t dest_port, vless_conn_t **out);

/**
 * @brief Release a connection back to the pool.
 * @param pool Pool handle. If NULL or mismatched, the connection is closed directly.
 * @param conn Connection to release (will be closed and freed).
 *
 * VLESS connections are destination-bound after the header is sent,
 * so the connection is closed. The next vless_pool_acquire() will
 * create a new connection on demand if the pool has no idle ones.
 * After this call, the conn pointer must not be used again (it is freed).
 */
VLESS_API void vless_pool_release(vless_pool_t *pool, vless_conn_t *conn);

/**
 * @brief Destroy pool and close all connections.
 * @param pool Pool handle, or NULL (no-op if NULL).
 *
 * Blocks until all in-flight vless_pool_acquire() and vless_pool_release()
 * operations complete (up to 30 seconds), then closes all idle connections
 * and frees resources. If in-flight operations do not complete within the
 * timeout, the pool stays alive via reference counting until the last
 * connection is closed.
 */
VLESS_API void vless_pool_destroy(vless_pool_t *pool);

/**
 * @brief Pool statistics.
 */
typedef struct {
    int total;   /**< Total connections (idle + in_use) */
    int idle;    /**< Idle (pre-warmed, available for acquire) */
    int in_use;  /**< Currently acquired by callers */
    int _reserved[4]; /**< Reserved for future use */
} vless_pool_stats_t;

/**
 * @brief Get pool statistics.
 * @param pool Pool handle. Safe to call concurrently with acquire/release,
 *             but must not be called after vless_pool_destroy() has returned
 *             and the pool has been freed.
 * @param out  Output struct. Zeroed if pool is NULL or destroyed.
 */
VLESS_API void vless_pool_stats(vless_pool_t *pool, vless_pool_stats_t *out);

#ifdef __cplusplus
}
#endif

#endif /* VLESS_H */
