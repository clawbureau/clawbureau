/**
 * Clawsig Interposition Library — God-Mode EDR Layer
 *
 * Implements: Perfect Process Genealogy, Server Socket Awareness,
 * Full IPC Lifecycle, Nanosecond Kinematics, Causal Sequence Numbers,
 * Causal DAG (cause_t/cause_f), Merkle Transcript Commitment (per-event),
 * Stack-only SHA-256 Env Auditing, Credential DLP, LLM recv() Sampling,
 * Semantic Harness/MCP Fingerprinting, TLS/HTTPS Decryption via
 * SSL_CTX_set_keylog_callback Chaining, SSLKEYLOGFILE Injection,
 * Trace FD Hardening, LLM Timing Fingerprints (TTFT/P50/P99/burst),
 * and Post-Mortem Memory Forensics.
 */

#if defined(__linux__) || defined(__APPLE__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif

#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <time.h>
#include <spawn.h>
#include <errno.h>
#include <signal.h>

#ifdef __APPLE__
#include <crt_externs.h>
#include <mach/mach.h>
#include <mach/vm_map.h>
#endif

#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif
#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ================================================================== */
/*                 Causal Sequence & Monotonic Time                   */
/* ================================================================== */

static volatile uint64_t global_seq = 0;
static inline uint64_t next_seq(void) { return __sync_fetch_and_add(&global_seq, 1); }
static inline uint64_t get_mono_ns(void) {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

/* ================================================================== */
/*                          Global State                              */
/* ================================================================== */

static volatile pid_t cached_pid = 0;   /* R25: fork/vfork child detection */
static __thread int in_hook = 0;
static int trace_fd = -1;

#define MAX_DNS_CACHE 256
typedef struct { volatile int in_use; char ip[INET6_ADDRSTRLEN]; char hostname[256]; } dns_cache_t;
static dns_cache_t dns_cache[MAX_DNS_CACHE];

#define MAX_TRACKED_FDS 1024
typedef struct { volatile int fd; int port; char ip[INET6_ADDRSTRLEN]; } tracked_fd_t;
static tracked_fd_t tracked_fds[MAX_TRACKED_FDS];

static volatile uint64_t llm_fds_bitset[16] = {0};
static inline void set_llm_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_or(&llm_fds_bitset[fd / 64], 1ULL << (fd % 64)); }
static inline void clear_llm_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_and(&llm_fds_bitset[fd / 64], ~(1ULL << (fd % 64))); }
static inline int is_llm_fd(int fd) { return fd >= 0 && fd < 1024 && (llm_fds_bitset[fd / 64] & (1ULL << (fd % 64))); }

/* SSL FD tracking — prevents plaintext HTTP parser from double-processing
 * encrypted traffic that SSL_read/SSL_write already handle (from I-Genesis) */
static volatile uint64_t ssl_fds_bitset[16] = {0};
static inline void set_ssl_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_or(&ssl_fds_bitset[fd / 64], 1ULL << (fd % 64)); }
static inline void clear_ssl_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_and(&ssl_fds_bitset[fd / 64], ~(1ULL << (fd % 64))); }
static inline int is_ssl_fd(int fd) { return fd >= 0 && fd < 1024 && (ssl_fds_bitset[fd / 64] & (1ULL << (fd % 64))); }

/* --- HTTP/2 FD tracking (from L-SelfVerify stealable idea #64) --- */
static volatile uint64_t h2_fds_bitset[16] = {0};
static inline void set_h2_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_or(&h2_fds_bitset[fd / 64], 1ULL << (fd % 64)); }
static inline void clear_h2_fd(int fd) { if (fd >= 0 && fd < 1024) __sync_fetch_and_and(&h2_fds_bitset[fd / 64], ~(1ULL << (fd % 64))); }
static inline int is_h2_fd(int fd) { return fd >= 0 && fd < 1024 && (h2_fds_bitset[fd / 64] & (1ULL << (fd % 64))); }

/* O(1) FD→h2_conn slot lookup (from K-ConstraintsLast #72) — replaces linear scan */
static volatile int fd_to_h2[1024];

/* --- Causal DAG state (from C-Naked stealable idea #1) --- */
static __thread uint64_t tl_last_seq = 0;          /* thread-local: previous event seq */
static volatile uint64_t fd_last_seq[MAX_TRACKED_FDS]; /* per-fd: previous event seq    */
static __thread int tl_event_fd = -1;               /* set by hooks before emit        */

/* --- Merkle transcript commitment (incremental SHA-256 from E-Synthesis) --- */
static volatile uint64_t merkle_count = 0;
static volatile int merkle_lock = 0;
static char current_merkle_hex[65] = "0000000000000000000000000000000000000000000000000000000000000000";
static inline void merkle_acquire(void) { while (__sync_lock_test_and_set(&merkle_lock, 1)) {} }
static inline void merkle_release(void) { __sync_lock_release(&merkle_lock); }

/* --- SSLKEYLOGFILE injection path (from B-Debate stealable idea #9) --- */
static char sslkeylog_path[512] = {0};

/* --- Anti-stripping: saved env vars for re-injection (from F-RedTeam) --- */
static char saved_trace_env[1024] = {0};
static char saved_preload_env[1024] = {0};

/* --- Data-flow causal DAG thread-locals (from F-RedTeam) --- */
static __thread int tl_causal_read_fd = -1;
static __thread uint64_t tl_causal_read_seq = 0;

/* ================================================================== */
/*              LLM Timing Fingerprints (from E-Synthesis)            */
/* ================================================================== */

typedef struct {
    uint64_t req_start_ns;
    uint64_t first_token_ns;
    uint64_t last_token_ns;
    uint32_t latencies[128];    /* inter-token intervals in microseconds */
    uint32_t token_bytes[128];  /* per-token byte counts (burst pattern) */
    uint32_t count;
    int active;
    volatile int lock;
} llm_timing_t;

static llm_timing_t llm_timings[MAX_TRACKED_FDS];

/* Forward declarations — defined later in file */
static void emit_log_event(const char *syscall_name, int pid, int rc, const char *fmt, ...);
static void escape_json(const char *src, char *dest, size_t dest_len);
static int peek_fd(int fd, char *ip_out, int *port_out);
static int lookup_dns(const char *ip, char *hostname_out);
static void feed_anomaly_engine(const char *hostname, double ttft,
    double mean_iti, double p50, double p95, double burst, double bpt);
/* Auto-detect LLM FD by HTTP method prefix (from I-Genesis #63) */
static inline void sniff_and_set_llm_fd(int fd, const void *buf, size_t len) {
    if (len < 15 || is_llm_fd(fd)) return;
    const char *b = (const char *)buf;
    if (!memcmp(b, "POST /v1/chat/", 14) || !memcmp(b, "POST /v1/compl", 14) ||
        !memcmp(b, "POST /v1/messa", 14) || !memcmp(b, "POST /api/gene", 14) ||
        !memcmp(b, "POST /api/chat", 14))
        set_llm_fd(fd);
}

static void emit_timing_fingerprint(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return;
    while (__sync_lock_test_and_set(&llm_timings[fd].lock, 1)) {}
    if (llm_timings[fd].active && llm_timings[fd].count > 0) {
        uint64_t ttft = llm_timings[fd].first_token_ns > llm_timings[fd].req_start_ns ?
                        llm_timings[fd].first_token_ns - llm_timings[fd].req_start_ns : 0;
        uint32_t sorted[128]; uint32_t count = llm_timings[fd].count;
        if (count > 128) count = 128;
        for (uint32_t i = 0; i < count; i++) sorted[i] = llm_timings[fd].latencies[i];
        /* Insertion sort — O(n^2) but n<=128, fires once per LLM request */
        for (uint32_t i = 0; i < count; i++)
            for (uint32_t j = i + 1; j < count; j++)
                if (sorted[i] > sorted[j]) { uint32_t t = sorted[i]; sorted[i] = sorted[j]; sorted[j] = t; }
        uint32_t p50 = sorted[count / 2];
        uint32_t p99 = sorted[(count * 99) / 100];

        char burst[512] = "[";
        for (uint32_t i = 0; i < count && i < 32; i++) {
            char tmp[32]; snprintf(tmp, sizeof(tmp), "%s%u", i == 0 ? "" : ",", llm_timings[fd].token_bytes[i]);
            if (strlen(burst) + strlen(tmp) < sizeof(burst) - 2) strcat(burst, tmp);
        }
        strcat(burst, "]");

        tl_event_fd = fd;
        emit_log_event("model_timing_fingerprint", getpid(), -999,
            ",\"fd\":%d,\"ttft_ns\":%llu,\"p50_us\":%u,\"p99_us\":%u,\"tokens\":%u,\"burst\":%s",
            fd, (unsigned long long)ttft, p50, p99, count, burst);

        /* Model substitution detection (from J-Crucible): p50 < 1ms with
         * >10 tokens strongly suggests local proxy / mocked endpoint,
         * not a real cloud LLM API (minimum ~2-10ms network RTT). */
        if (p50 > 0 && p50 < 1000 && count > 10) {
            emit_log_event("security_anomaly", getpid(), -999,
                ",\"fd\":%d,\"type\":\"model_substitution\","
                "\"reason\":\"p50_us_%u_below_1ms_threshold\"", fd, p50);
        }

        /* Feed EMA anomaly engine per hostname (from H-Omega) */
        char ip[INET6_ADDRSTRLEN] = ""; char host[256] = "llm";
        if (peek_fd(fd, ip, NULL)) lookup_dns(ip, host);
        uint64_t sum = 0;
        for (uint32_t x = 0; x < count; x++) sum += sorted[x];
        double mean_iti = count > 0 ? (double)sum / count : 0;
        uint32_t p95 = sorted[(count * 95) / 100];
        double var = 0;
        for (uint32_t x = 0; x < count; x++) {
            double d = (double)sorted[x] - mean_iti;
            var += d * d;
        }
        var = count > 1 ? var / (count - 1) : 0;
        double burstiness_val = mean_iti > 0 ? var / mean_iti : 0;
        uint64_t total_bytes = 0;
        for (uint32_t x = 0; x < count; x++) total_bytes += llm_timings[fd].token_bytes[x];
        double bpt_val = count > 0 ? (double)total_bytes / count : 0;
        feed_anomaly_engine(host, (double)ttft, mean_iti, (double)p50,
            (double)p95, burstiness_val, bpt_val);
    }
    llm_timings[fd].active = 0;
    __sync_lock_release(&llm_timings[fd].lock);
}

static void timing_start_req(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return;
    emit_timing_fingerprint(fd); /* flush previous request's timing */
    while (__sync_lock_test_and_set(&llm_timings[fd].lock, 1)) {}
    llm_timings[fd].active = 1;
    llm_timings[fd].req_start_ns = get_mono_ns();
    llm_timings[fd].first_token_ns = 0;
    llm_timings[fd].last_token_ns = 0;
    llm_timings[fd].count = 0;
    __sync_lock_release(&llm_timings[fd].lock);
}

static void timing_add_token(int fd, size_t bytes) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return;
    while (__sync_lock_test_and_set(&llm_timings[fd].lock, 1)) {}
    if (!llm_timings[fd].active) { __sync_lock_release(&llm_timings[fd].lock); return; }
    uint64_t now = get_mono_ns();
    if (llm_timings[fd].first_token_ns == 0)
        llm_timings[fd].first_token_ns = now;
    if (llm_timings[fd].last_token_ns > 0 && llm_timings[fd].count < 128) {
        uint64_t delta_us = (now - llm_timings[fd].last_token_ns) / 1000;
        llm_timings[fd].latencies[llm_timings[fd].count] = (uint32_t)(delta_us > UINT32_MAX ? UINT32_MAX : delta_us);
        llm_timings[fd].token_bytes[llm_timings[fd].count] = (uint32_t)(bytes > UINT32_MAX ? UINT32_MAX : bytes);
        llm_timings[fd].count++;
    }
    llm_timings[fd].last_token_ns = now;
    __sync_lock_release(&llm_timings[fd].lock);
}

/* ================================================================== */
/*    HTTP FSM & Content-Addressable Receipts (J-Crucible + H-Omega)  */
/*    Zero-allocation streaming HTTP parser with req/res pairing,     */
/*    three-context SHA-256, SSE canonicalization, model extraction,   */
/*    EMA behavioral anomaly detection, and prompt injection scan.    */
/* ================================================================== */

/* Forward-declare SHA-256 (defined in SHA-256 section below) */
typedef struct { uint32_t state[8]; uint32_t count[2]; uint8_t buffer[64]; } sha256_ctx_t;
static void sha256_init(sha256_ctx_t *ctx);
static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len);
static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]);


/* ================================================================== */
/*   R26: Transcript Extraction (llm_msg & llm_tool_call)            */
/*   Streaming JSON DFA for structured event extraction from LLM     */
/*   API traffic. Synthesized from U1 (#110-#113), V1 (#115-#117),   */
/*   W2 (#119-#120). Covers HTTP/1.1 SSE, HTTP/2, gRPC.             */
/* ================================================================== */

/* FNV-1a key hashes for hot-loop matching (#115) — pre-computed, never hallucinated */
#define FNV1A_ROLE       0x0fff3219u
#define FNV1A_CONTENT    0x90bec3c2u
#define FNV1A_NAME       0x8d39bde6u
#define FNV1A_ID         0x37386ae0u
#define FNV1A_ARGUMENTS  0x2951c89fu
#define FNV1A_FUNCTION   0x9ed64249u
#define FNV1A_TOOL_CALLS 0x4114df01u
#define FNV1A_DELTA      0x6b017c21u
#define FNV1A_CHOICES    0xf796e83fu
#define FNV1A_MESSAGES   0xc00385b5u
#define FNV1A_INPUT      0x3f88e1a7u  /* Anthropic: "input" for tool args */
#define FNV1A_TEXT       0x364492dfu  /* "text" alt content key */

static inline uint32_t fnv1a_str(const char *s, int len) {
    uint32_t h = 0x811c9dc5u;
    for (int i = 0; i < len; i++)
        h = (h ^ (uint8_t)s[i]) * 0x01000193u;
    return h;
}

/* Transcript DFA state — one per direction, embedded in FSM structs (#110) */
typedef struct {
    /* JSON tokenizer state */
    int in_str;         /* inside a JSON string */
    int in_esc;         /* previous char was backslash */
    int depth;          /* brace/bracket nesting depth */
    uint8_t container_stack; /* #119: bitmask — bit=1 for object, bit=0 for array (8 levels) */

    /* Key accumulation */
    char key[64];
    int key_len;
    int after_colon;    /* just saw ':' */

    /* Current capture target (set by key hash) */
    int capture_type;   /* 0=none, 1=role, 2=content, 3=id, 4=name, 5=arguments */
    int capture_depth;  /* depth at which capture started */
    int capture_started;/* have we begun reading the value? */

    /* Message state */
    int msg_active;
    char role[32];
    int role_len;
    int has_content;
    char preview[128];
    int preview_len;
    sha256_ctx_t content_ctx;

    /* Tool call state */
    int tool_active;
    char tool_id[64];
    int tool_id_len;
    char tool_name[64];
    int tool_name_len;
    int has_args;
    sha256_ctx_t args_ctx;
    int tool_index;     /* #120: tracks tool_calls[*].index */
} transcript_dfa_t;

static void tx_init(transcript_dfa_t *tx) {
    memset(tx, 0, sizeof(*tx));
    tx->tool_index = -1;
    sha256_init(&tx->content_ctx);
    sha256_init(&tx->args_ctx);
}

static void tx_emit_msg(int fd, uint32_t stream_id, transcript_dfa_t *tx) {
    if (!tx->msg_active) return;
    if (!tx->has_content && tx->role[0] == '\0') { tx->msg_active = 0; return; }

    tx->role[tx->role_len < 31 ? tx->role_len : 31] = '\0';
    tx->preview[tx->preview_len < 127 ? tx->preview_len : 127] = '\0';

    /* Snapshot content hash (#113) */
    uint8_t hash[32]; sha256_ctx_t snap = tx->content_ctx; sha256_final(&snap, hash);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(&hex[i*2], 3, "%02x", hash[i]);

    /* Empty content → SHA-256 of empty string */
    static const char *empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    char role_esc[64]; escape_json(tx->role[0] ? tx->role : "unknown", role_esc, sizeof(role_esc));
    char preview_esc[512]; escape_json(tx->preview, preview_esc, sizeof(preview_esc));

    int old_fd = tl_event_fd; tl_event_fd = fd;
    emit_log_event("llm_msg", getpid(), -999,
        ",\"fd\":%d,\"stream_id\":%u,\"role\":\"%s\""
        ",\"content_sha256\":\"%s\",\"preview\":\"%s\"",
        fd, stream_id, role_esc,
        tx->has_content ? hex : empty_sha, preview_esc);
    tl_event_fd = old_fd;

    /* Reset msg state for next message */
    tx->msg_active = 0;
    tx->role[0] = '\0'; tx->role_len = 0;
    tx->preview[0] = '\0'; tx->preview_len = 0;
    tx->has_content = 0;
    sha256_init(&tx->content_ctx);
}

static void tx_emit_tool(int fd, uint32_t stream_id, transcript_dfa_t *tx) {
    if (!tx->tool_active) return;
    if (!tx->has_args && tx->tool_name[0] == '\0' && tx->tool_id[0] == '\0') {
        tx->tool_active = 0; return;
    }

    tx->tool_name[tx->tool_name_len < 63 ? tx->tool_name_len : 63] = '\0';
    tx->tool_id[tx->tool_id_len < 63 ? tx->tool_id_len : 63] = '\0';

    uint8_t hash[32]; sha256_ctx_t snap = tx->args_ctx; sha256_final(&snap, hash);
    char hex[65];
    for (int i = 0; i < 32; i++) snprintf(&hex[i*2], 3, "%02x", hash[i]);

    static const char *empty_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

    char name_esc[128]; escape_json(tx->tool_name, name_esc, sizeof(name_esc));
    char id_esc[128]; escape_json(tx->tool_id, id_esc, sizeof(id_esc));

    int old_fd = tl_event_fd; tl_event_fd = fd;
    emit_log_event("llm_tool_call", getpid(), -999,
        ",\"fd\":%d,\"stream_id\":%u,\"call_id\":\"%s\""
        ",\"name\":\"%s\",\"arguments_sha256\":\"%s\"",
        fd, stream_id, id_esc, name_esc,
        tx->has_args ? hex : empty_sha);
    tl_event_fd = old_fd;

    /* Reset tool state */
    tx->tool_active = 0;
    tx->tool_id[0] = '\0'; tx->tool_id_len = 0;
    tx->tool_name[0] = '\0'; tx->tool_name_len = 0;
    tx->has_args = 0;
    sha256_init(&tx->args_ctx);
    tx->tool_index = -1;
}

/* Flush pending msg + tool on receipt emission (#116) */
static void tx_flush(int fd, uint32_t stream_id, transcript_dfa_t *tx) {
    tx_emit_msg(fd, stream_id, tx);
    tx_emit_tool(fd, stream_id, tx);
}

/**
 * Streaming JSON transcript DFA — feed raw bytes, emit llm_msg/llm_tool_call.
 * Uses FNV-1a key hashing (#115) for O(1) key matching in the hot loop.
 * Handles SSE delta accumulation and non-streaming bodies.
 * Zero-malloc. Bounded buffers. Stream-safe across chunk boundaries.
 */
static void tx_feed_json(int fd, uint32_t stream_id, transcript_dfa_t *tx,
                         const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];

        /* === String state tracking === */
        if (tx->in_str) {
            if (tx->in_esc) { tx->in_esc = 0; }
            else if (c == '\\') { tx->in_esc = 1; }
            else if (c == '"') { tx->in_str = 0; }

            /* Capture string value bytes */
            if (tx->in_str && tx->capture_started) {
                if (tx->capture_type == 1 && tx->role_len < 31)
                    tx->role[tx->role_len++] = (char)c;
                else if (tx->capture_type == 2) {
                    sha256_update(&tx->content_ctx, &c, 1);
                    tx->has_content = 1;
                    if (tx->preview_len < 120 && c != '\n' && c != '\r')
                        tx->preview[tx->preview_len++] = (char)c;
                } else if (tx->capture_type == 3 && tx->tool_id_len < 63) {
                    tx->tool_id[tx->tool_id_len++] = (char)c;
                } else if (tx->capture_type == 4 && tx->tool_name_len < 63) {
                    tx->tool_name[tx->tool_name_len++] = (char)c;
                } else if (tx->capture_type == 5) {
                    sha256_update(&tx->args_ctx, &c, 1);
                    tx->has_args = 1;
                }
            }

            /* Accumulate key chars when not in a capture */
            if (tx->in_str && !tx->after_colon && !tx->capture_started) {
                if (tx->key_len < 63) tx->key[tx->key_len++] = (char)c;
            }

            /* String ended — finalize key or end capture */
            if (!tx->in_str) {
                if (tx->capture_started && tx->capture_type > 0 && tx->capture_type <= 5) {
                    /* String capture complete — check if at correct depth */
                    /* (Object captures end via '}', not here) */
                }
                tx->after_colon = 0;
            }
            continue;
        }

        /* === Non-string structural characters === */
        if (c == '"') {
            tx->in_str = 1;
            if (tx->after_colon && !tx->capture_started) {
                /* Starting to capture a string value */
                tx->capture_started = 1;
                tx->capture_depth = tx->depth;
                /* Activate msg/tool based on capture type */
                if (tx->capture_type == 1 || tx->capture_type == 2) {
                    if (!tx->msg_active) { tx->msg_active = 1; }
                } else if (tx->capture_type >= 3 && tx->capture_type <= 5) {
                    if (!tx->tool_active) { tx->tool_active = 1; }
                }
            } else if (!tx->after_colon) {
                /* Starting a key string */
                tx->key_len = 0;
            }
            continue;
        }

        if (c == '{') {
            tx->depth++;
            if (tx->depth <= 8)
                tx->container_stack |= (1u << (tx->depth - 1)); /* mark as object */
            if (tx->after_colon && !tx->capture_started && tx->capture_type == 5) {
                /* arguments is an object — hash its raw JSON */
                tx->capture_started = 1;
                tx->capture_depth = tx->depth;
                if (!tx->tool_active) tx->tool_active = 1;
                sha256_update(&tx->args_ctx, (const uint8_t*)"{", 1);
                tx->has_args = 1;
            }
            continue;
        }

        if (c == '[') {
            tx->depth++;
            if (tx->depth <= 8)
                tx->container_stack &= ~(1u << (tx->depth - 1)); /* mark as array */
            continue;
        }

        if (c == '}') {
            /* Emit captured object value (e.g., arguments) */
            if (tx->capture_started && tx->capture_type == 5 && tx->depth == tx->capture_depth) {
                sha256_update(&tx->args_ctx, (const uint8_t*)"}", 1);
                tx->capture_started = 0;
                tx->capture_type = 0;
            }
            if (tx->depth <= 8)
                tx->container_stack &= ~(1u << (tx->depth - 1));
            tx->depth--;
            continue;
        }

        if (c == ']') {
            if (tx->depth <= 8)
                tx->container_stack &= ~(1u << (tx->depth - 1));
            tx->depth--;
            continue;
        }

        if (c == ':') {
            tx->after_colon = 1;
            /* Hash the key to determine capture type (#115) */
            tx->key[tx->key_len < 63 ? tx->key_len : 63] = '\0';
            uint32_t h = fnv1a_str(tx->key, tx->key_len);
            if (h == FNV1A_ROLE)            tx->capture_type = 1;
            else if (h == FNV1A_CONTENT || h == FNV1A_TEXT) tx->capture_type = 2;
            else if (h == FNV1A_ID)         tx->capture_type = 3;
            else if (h == FNV1A_NAME)       tx->capture_type = 4;
            else if (h == FNV1A_ARGUMENTS || h == FNV1A_INPUT) tx->capture_type = 5;
            else tx->capture_type = 0;

            /* On "role" key in SSE delta, emit previous msg if active */
            if (tx->capture_type == 1 && tx->msg_active && tx->has_content) {
                tx_emit_msg(fd, stream_id, tx);
            }
            /* On "id"/"name" key, emit previous tool if active */
            if ((tx->capture_type == 3 || tx->capture_type == 4) &&
                tx->tool_active && tx->has_args) {
                tx_emit_tool(fd, stream_id, tx);
            }
            continue;
        }

        if (c == ',') {
            if (tx->capture_started && tx->capture_type > 0 &&
                tx->depth <= tx->capture_depth) {
                tx->capture_started = 0;
            }
            tx->after_colon = 0;
            tx->capture_type = 0;
            tx->key_len = 0;
            continue;
        }

        /* Raw value bytes (numbers, booleans, null) inside arguments object */
        if (tx->capture_started && tx->capture_type == 5) {
            sha256_update(&tx->args_ctx, &c, 1);
            tx->has_args = 1;
        }
    }
}

/**
 * gRPC transcript feed — extract printable text runs from protobuf wire format.
 * Uses role-string heuristic from U1: detects "user"/"assistant"/"model"/"system"
 * in printable runs to segment messages. Hashes all printable content.
 */
static void tx_feed_grpc(int fd, uint32_t stream_id, transcript_dfa_t *tx,
                         const uint8_t *data, size_t len) {
    for (size_t i = 0; i < len; i++) {
        uint8_t c = data[i];
        int is_print = (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t';
        if (is_print) {
            if (tx->key_len < 63) tx->key[tx->key_len++] = (char)c;
            if (tx->msg_active) {
                sha256_update(&tx->content_ctx, &c, 1);
                tx->has_content = 1;
                if (tx->preview_len < 120 && c != '\n' && c != '\r')
                    tx->preview[tx->preview_len++] = (char)c;
            }
        } else {
            /* Non-printable byte — check if accumulated run is a role marker */
            if (tx->key_len >= 4 && tx->key_len <= 9) {
                tx->key[tx->key_len] = '\0';
                if (!strcmp(tx->key, "user") || !strcmp(tx->key, "model") ||
                    !strcmp(tx->key, "assistant") || !strcmp(tx->key, "system")) {
                    /* New role boundary — emit previous msg if active */
                    if (tx->msg_active && tx->has_content)
                        tx_emit_msg(fd, stream_id, tx);
                    tx->msg_active = 1;
                    strncpy(tx->role, tx->key, sizeof(tx->role) - 1);
                    tx->role_len = (int)strlen(tx->role);
                    tx->has_content = 0;
                    tx->preview_len = 0;
                    sha256_init(&tx->content_ctx);
                }
            }
            tx->key_len = 0;
        }
    }
}


/* Newton-Raphson sqrt — avoids -lm dependency (from H-Omega) */
static double fast_sqrt(double n) {
    if (n <= 0) return 0;
    double x = n, y = (x + 1) / 2;
    while (y < x) { x = y; y = (x + n / x) / 2; }
    return x;
}

/* Case-insensitive substring search (from H-Omega) */
static const char *my_strcasestr(const char *h, const char *n) {
    if (!n[0]) return h;
    for (; *h; h++) {
        const char *a = h, *b = n;
        while (*a && *b) {
            char ca = *a, cb = *b;
            if (ca >= 'A' && ca <= 'Z') ca += 32;
            if (cb >= 'A' && cb <= 'Z') cb += 32;
            if (ca != cb) break;
            a++; b++;
        }
        if (!*b) return h;
    }
    return NULL;
}

/* --- Behavioral EMA Anomaly Engine (from H-Omega) --- */
typedef struct { double ema; double var; } ema_stat_t;
typedef struct {
    char hostname[256];
    ema_stat_t ttft, mean_iti, p50_iti, p95_iti, burstiness, bpt;
    int count;
    volatile int lock;
} host_anomaly_t;

#define MAX_ANOMALY_HOSTS 64
static host_anomaly_t anomaly_hosts[MAX_ANOMALY_HOSTS];

static void update_ema(ema_stat_t *s, double val, const char *dim,
                       const char *host, int count) {
    if (count == 0) { s->ema = val; s->var = 0; return; }
    double diff = val - s->ema;
    double sd = fast_sqrt(s->var);
    if (count > 5 && sd > 0) {
        double sigma = diff / sd;
        if (sigma < 0) sigma = -sigma;
        if (sigma > 3.0) {
            char eh[512]; escape_json(host, eh, sizeof(eh));
            emit_log_event("behavioral_anomaly", getpid(), -999,
                ",\"hostname\":\"%s\",\"dimension\":\"%s\","
                "\"expected\":%.2f,\"observed\":%.2f,\"sigma\":%.2f",
                eh, dim, s->ema, val, sigma);
        }
    }
    s->ema = 0.9 * s->ema + 0.1 * val;
    s->var = 0.9 * s->var + 0.1 * (diff * diff);
}

static void feed_anomaly_engine(const char *hostname, double ttft,
    double mean_iti, double p50, double p95, double burst, double bpt) {
    unsigned h = 5381; const char *p = hostname;
    while (*p) h = ((h << 5) + h) + (unsigned char)*p++;
    int slot = (int)(h % MAX_ANOMALY_HOSTS);
    host_anomaly_t *a = &anomaly_hosts[slot];
    while (__sync_lock_test_and_set(&a->lock, 1)) {}
    if (a->hostname[0] && strcmp(a->hostname, hostname) != 0) {
        a->count = 0; /* collision — reset */
    }
    strncpy(a->hostname, hostname, 255); a->hostname[255] = '\0';
    update_ema(&a->ttft, ttft, "ttft_ns", hostname, a->count);
    update_ema(&a->mean_iti, mean_iti, "mean_iti_us", hostname, a->count);
    update_ema(&a->p50_iti, p50, "p50_iti_us", hostname, a->count);
    update_ema(&a->p95_iti, p95, "p95_iti_us", hostname, a->count);
    update_ema(&a->burstiness, burst, "burstiness", hostname, a->count);
    update_ema(&a->bpt, bpt, "bytes_per_token", hostname, a->count);
    a->count++;
    __sync_lock_release(&a->lock);
}

/* --- HTTP FSM: unified req/res state machine per FD --- */
typedef enum {
    HTTP_IDLE = 0, HTTP_REQ_HDR, HTTP_REQ_BODY,
    HTTP_WAIT_RES, HTTP_RES_HDR, HTTP_RES_BODY,
    HTTP_TRAILER  /* after final 0-chunk, parse trailer headers (from I-Genesis #60) */
} http_fsm_state_t;

typedef struct {
    http_fsm_state_t state;
    volatile int lock;

    /* Request metadata */
    char method[16];
    char path[512];
    int status;

    /* Model identity (from H-Omega headers + I-Genesis JSON scanner) */
    char model[128];        /* from response headers (x-model/openai-model) */
    char req_model[128];    /* from request body JSON "model" key */
    char res_model[128];    /* from response body JSON "model" key */
    int req_mscan;          /* req JSON model scanner state (0-11) */
    int req_midx;           /* req model string accumulation index */
    int res_mscan;          /* res JSON model scanner state (0-11) */
    int res_midx;           /* res model string accumulation index */

    /* Header parsing (line-at-a-time, cross-buffer) */
    char line_buf[512];
    size_t line_len;

    /* Body framing */
    uint64_t content_length;
    uint64_t body_bytes_read;
    uint64_t chunk_rem;
    int is_chunked;
    int is_sse;
    int in_chunk_ext;

    /* SSE canonicalization (from H-Omega: strips "data: " + [DONE]) */
    char sse_line[256];
    size_t sse_len;

    /* Three-context streaming SHA-256 (from H-Omega) */
    sha256_ctx_t req_ctx;   /* hash of request body only */
    sha256_ctx_t res_ctx;   /* hash of response body only */
    sha256_ctx_t receipt_ctx;/* hash of method||path||\n||req_body||\n||status||\n||res_body */

    /* Byte counters */
    uint64_t total_req_bytes;
    uint64_t total_res_bytes;

    /* R26: Per-direction transcript extraction (#110) */
    transcript_dfa_t req_tx;
    transcript_dfa_t res_tx;
} http_fsm_t;

static http_fsm_t http_fsm[MAX_TRACKED_FDS];

static inline void fsm_lock(int fd) { while (__sync_lock_test_and_set(&http_fsm[fd].lock, 1)) {} }
static inline void fsm_unlock(int fd) { __sync_lock_release(&http_fsm[fd].lock); }

/** Emit a content-addressable receipt with req/res/composite hashes. */
static void fsm_emit_receipt(int fd) {
    http_fsm_t *sm = &http_fsm[fd];
    if (sm->method[0] == '\0') return;

    /* R26 #116: Flush pending transcript events before receipt */
    tx_flush(fd, 0, &sm->req_tx);
    tx_flush(fd, 0, &sm->res_tx);

    /* Finalize all three hash contexts (snapshot, don't destroy) */
    uint8_t rq_h[32], rs_h[32], rc_h[32];
    sha256_ctx_t t;
    t = sm->req_ctx; sha256_final(&t, rq_h);
    t = sm->res_ctx; sha256_final(&t, rs_h);
    t = sm->receipt_ctx; sha256_final(&t, rc_h);

    char hex_rq[65], hex_rs[65], hex_rc[65];
    for (int k = 0; k < 32; k++) {
        snprintf(&hex_rq[k*2], 3, "%02x", rq_h[k]);
        snprintf(&hex_rs[k*2], 3, "%02x", rs_h[k]);
        snprintf(&hex_rc[k*2], 3, "%02x", rc_h[k]);
    }

    /* Model resolution: header > JSON body > "unknown" */
    const char *effective_model = sm->model[0] ? sm->model :
                                  sm->res_model[0] ? sm->res_model : "unknown";

    /* Model substitution detection (from I-Genesis #57):
     * compare claimed model (from request body) vs actual model (from response).
     * Orthogonal to timing-based detection — both can fire. */
    int model_substituted = 0;
    if (sm->req_model[0] && (sm->res_model[0] || sm->model[0])) {
        const char *actual = sm->model[0] ? sm->model : sm->res_model;
        if (strcmp(sm->req_model, actual) != 0) {
            model_substituted = 1;
            tl_event_fd = fd;
            char rm[256], am[256];
            escape_json(sm->req_model, rm, sizeof(rm));
            escape_json(actual, am, sizeof(am));
            emit_log_event("security_anomaly", getpid(), -999,
                ",\"fd\":%d,\"type\":\"model_substitution_structural\","
                "\"requested\":\"%s\",\"actual\":\"%s\"", fd, rm, am);
        }
    }

    char path_esc[1024], model_esc[256], req_m_esc[256];
    escape_json(sm->path, path_esc, sizeof(path_esc));
    escape_json(effective_model, model_esc, sizeof(model_esc));
    escape_json(sm->req_model, req_m_esc, sizeof(req_m_esc));

    tl_event_fd = fd;
    emit_log_event("llm_receipt", getpid(), -999,
        ",\"fd\":%d,\"receipt_hash\":\"%s\""
        ",\"method\":\"%s\",\"path\":\"%s\",\"status\":%d"
        ",\"req_bytes\":%llu,\"res_bytes\":%llu"
        ",\"req_body_sha256\":\"%s\",\"res_body_sha256\":\"%s\""
        ",\"model\":\"%s\",\"req_model\":\"%s\",\"model_substituted\":%d",
        fd, hex_rc,
        sm->method, path_esc, sm->status,
        (unsigned long long)sm->total_req_bytes,
        (unsigned long long)sm->total_res_bytes,
        hex_rq, hex_rs, model_esc, req_m_esc, model_substituted);

    sm->state = HTTP_IDLE;
    sm->method[0] = '\0';
}

/** Flush FSM on FD close — emit receipt for any in-progress exchange. */
static void fsm_flush(int fd) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS) return;
    http_fsm_t *sm = &http_fsm[fd];
    fsm_lock(fd);
    if (sm->state > HTTP_IDLE) fsm_emit_receipt(fd);
    fsm_unlock(fd);
}

/**
 * Byte-by-byte JSON "model" key scanner (from I-Genesis #56).
 * 12-state DFA: 0=idle, 1-6=matching "model", 7=post-quote ws,
 * 8=post-colon ws, 9=accumulating value, 10=done, 11=escape.
 * Scans streaming body without buffering entire JSON.
 */
static void json_model_scan(int *state, int *idx, char *model, size_t model_sz,
                            const uint8_t *data, size_t len) {
    static const char key[] = "model";
    for (size_t i = 0; i < len && *state < 10; i++) {
        uint8_t b = data[i];
        switch (*state) {
        case 0: if (b == '"') *state = 1; break;
        case 1: case 2: case 3: case 4: case 5:
            if (b == (uint8_t)key[*state - 1]) (*state)++;
            else *state = (b == '"') ? 1 : 0;
            break;
        case 6: if (b == '"') *state = 7; else *state = (b == '"') ? 1 : 0; break;
        case 7: if (b == ':') *state = 8;
                else if (b != ' ' && b != '\t') *state = 0; break;
        case 8: if (b == '"') { *state = 9; *idx = 0; }
                else if (b != ' ' && b != '\t') *state = 0; break;
        case 9:
            if (b == '"') { model[*idx] = '\0'; *state = 10; }
            else if (b == '\\') *state = 11;
            else if (*idx < (int)model_sz - 1) model[(*idx)++] = (char)b;
            break;
        case 11:
            if (*idx < (int)model_sz - 1) model[(*idx)++] = (char)b;
            *state = 9; break;
        }
    }
}

/** Append bytes to request body hash contexts + scan for model. */
static inline void fsm_hash_req(http_fsm_t *sm, const uint8_t *d, size_t n) {
    sha256_update(&sm->req_ctx, d, n);
    sha256_update(&sm->receipt_ctx, d, n);
    sm->total_req_bytes += n;
    json_model_scan(&sm->req_mscan, &sm->req_midx, sm->req_model,
                    sizeof(sm->req_model), d, n);
    /* R26 #111: Feed same bytes into transcript extraction */
    tx_feed_json(tl_event_fd, 0, &sm->req_tx, d, n);
}

/** Append bytes to response body hash contexts with SSE canonicalization + model scan. */
static void fsm_hash_res(int fd, http_fsm_t *sm, const uint8_t *data, size_t len) {
    /* JSON model scanner runs on raw bytes regardless of SSE mode */
    json_model_scan(&sm->res_mscan, &sm->res_midx, sm->res_model,
                    sizeof(sm->res_model), data, len);
    /* R26 #111: Feed same bytes into transcript extraction */
    tx_feed_json(fd, 0, &sm->res_tx, data, len);
    if (!sm->is_sse) {
        sha256_update(&sm->res_ctx, data, len);
        sha256_update(&sm->receipt_ctx, data, len);
        sm->total_res_bytes += len;
        return;
    }
    /* SSE: accumulate lines, strip "data: " prefix, skip [DONE] */
    for (size_t i = 0; i < len; i++) {
        char ch = (char)data[i];
        if (sm->sse_len < sizeof(sm->sse_line) - 1)
            sm->sse_line[sm->sse_len++] = ch;
        if (ch == '\n') {
            sm->sse_line[sm->sse_len] = '\0';
            if (strncmp(sm->sse_line, "data: ", 6) == 0) {
                size_t dlen = sm->sse_len - 6;
                if (dlen > 0 && sm->sse_line[6 + dlen - 1] == '\n') dlen--;
                if (dlen > 0 && sm->sse_line[6 + dlen - 1] == '\r') dlen--;
                /* Skip OpenAI [DONE] terminator (from H-Omega) */
                if (!(dlen == 6 && memcmp(sm->sse_line + 6, "[DONE]", 6) == 0)) {
                    sha256_update(&sm->res_ctx, (const uint8_t*)sm->sse_line + 6, dlen);
                    sha256_update(&sm->receipt_ctx, (const uint8_t*)sm->sse_line + 6, dlen);
                    sm->total_res_bytes += dlen;
                }
            }
            sm->sse_len = 0;
        }
    }
}

/** Scan body for prompt injection markers (case-insensitive). */
static void scan_body_anomalies(int fd, const uint8_t *buf, size_t len) {
    if (!buf || len < 15) return;
    for (size_t i = 0; i <= len - 15; i++) {
        if (buf[i] == 'i' || buf[i] == 'I') {
            const char *kw = "ignore previous";
            int match = 1;
            for (size_t j = 1; j < 15; j++) {
                char c = (char)buf[i + j];
                if (c >= 'A' && c <= 'Z') c += 32;
                if (c != kw[j]) { match = 0; break; }
            }
            if (match) {
                tl_event_fd = fd;
                emit_log_event("security_anomaly", getpid(), -999,
                    ",\"fd\":%d,\"type\":\"prompt_injection\","
                    "\"match\":\"ignore previous\"", fd);
                return;
            }
        }
    }
}

/**
 * Process raw SSL bytes through the HTTP FSM.
 * Handles both request (is_req=1) and response (is_req=0) directions.
 * Line-based header parsing with cross-buffer accumulation.
 * Chunked encoding with chunk extension support.
 * Receipt formula: SHA-256(method || " " || path || "\n" || req_body || "\n" || status || "\n" || res_body)
 */
static void fsm_feed(int fd, const uint8_t *data, size_t len, int is_req) {
    if (fd < 0 || fd >= MAX_TRACKED_FDS || !data || len == 0) return;
    http_fsm_t *sm = &http_fsm[fd];
    size_t i = 0;

    while (i < len) {
        /* --- State: IDLE → begin new request --- */
        if (sm->state == HTTP_IDLE) {
            if (!is_req) break; /* stray response data with no request */
            sm->state = HTTP_REQ_HDR;
            sm->line_len = 0; sm->method[0] = '\0'; sm->path[0] = '\0';
            sm->status = 0; sm->model[0] = '\0';
            sm->req_model[0] = '\0'; sm->res_model[0] = '\0';
            sm->req_mscan = 0; sm->req_midx = 0;
            sm->res_mscan = 0; sm->res_midx = 0;
            sm->total_req_bytes = 0; sm->total_res_bytes = 0;
            sm->content_length = 0; sm->body_bytes_read = 0;
            sm->is_chunked = 0; sm->is_sse = 0;
            sm->chunk_rem = 0; sm->in_chunk_ext = 0; sm->sse_len = 0;
            sha256_init(&sm->req_ctx);
            sha256_init(&sm->res_ctx);
            sha256_init(&sm->receipt_ctx);
            tx_init(&sm->req_tx);
            tx_init(&sm->res_tx);
        }

        /* --- States: REQ_HDR / RES_HDR — line-based header parsing --- */
        if (sm->state == HTTP_REQ_HDR || sm->state == HTTP_RES_HDR) {
            size_t start = i;
            while (i < len && data[i] != '\n') i++;
            if (i < len) {
                /* Complete line received */
                size_t cplen = i - start;
                if (cplen > 0 && data[i-1] == '\r') cplen--;
                if (sm->line_len + cplen < sizeof(sm->line_buf) - 1) {
                    memcpy(sm->line_buf + sm->line_len, data + start, cplen);
                    sm->line_len += cplen;
                }
                sm->line_buf[sm->line_len] = '\0';

                if (sm->line_len == 0) {
                    /* Empty line = end of headers → transition to body */
                    if (sm->state == HTTP_REQ_HDR) {
                        sm->state = HTTP_REQ_BODY;
                        if (!sm->is_chunked && sm->content_length == 0) {
                            /* No body → separator → wait for response */
                            sha256_update(&sm->receipt_ctx, (const uint8_t*)"\n", 1);
                            sm->state = HTTP_WAIT_RES;
                        }
                    } else {
                        /* HTTP 1xx informational: skip and re-parse next response
                         * (from I-Genesis #59). 100 Continue, 102 Processing, etc. */
                        if (sm->status >= 100 && sm->status < 200 && sm->status != 101) {
                            sm->status = 0; sm->state = HTTP_RES_HDR;
                            sm->content_length = 0; sm->is_chunked = 0;
                            sm->line_len = 0;
                            i++; continue;
                        }
                        sm->state = HTTP_RES_BODY;
                    }
                    sm->body_bytes_read = 0;
                    sm->chunk_rem = 0; sm->in_chunk_ext = 0;
                } else {
                    /* Parse header line */
                    if (sm->state == HTTP_REQ_HDR && sm->method[0] == '\0') {
                        sscanf(sm->line_buf, "%15s %511s", sm->method, sm->path);
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)sm->method, strlen(sm->method));
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)" ", 1);
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)sm->path, strlen(sm->path));
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)"\n", 1);
                    } else if (sm->state == HTTP_RES_HDR && sm->status == 0) {
                        int maj, min;
                        sscanf(sm->line_buf, "HTTP/%d.%d %d", &maj, &min, &sm->status);
                        char stat_str[32]; snprintf(stat_str, sizeof(stat_str), "%d\n", sm->status);
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)stat_str, strlen(stat_str));
                    } else {
                        /* Content-Length / Transfer-Encoding / Content-Type / Model */
                        if (my_strcasestr(sm->line_buf, "content-length:")) {
                            const char *v = strchr(sm->line_buf, ':');
                            if (v) { v++; while(*v == ' ') v++; sm->content_length = strtoull(v, NULL, 10); }
                        } else if (my_strcasestr(sm->line_buf, "transfer-encoding:") &&
                                   my_strcasestr(sm->line_buf, "chunked")) {
                            sm->is_chunked = 1;
                            sm->content_length = 0; /* RFC 9112: TE takes precedence */
                        } else if (my_strcasestr(sm->line_buf, "content-type:") &&
                                   my_strcasestr(sm->line_buf, "text/event-stream")) {
                            sm->is_sse = 1;
                        } else if (sm->state == HTTP_RES_HDR && sm->model[0] == '\0') {
                            if (my_strcasestr(sm->line_buf, "x-model:") ||
                                my_strcasestr(sm->line_buf, "x-model-id:") ||
                                my_strcasestr(sm->line_buf, "openai-model:")) {
                                const char *v = strchr(sm->line_buf, ':');
                                if (v) { v++; while(*v == ' ') v++;
                                    strncpy(sm->model, v, sizeof(sm->model)-1);
                                    sm->model[sizeof(sm->model)-1] = '\0';
                                }
                            }
                        }
                    }
                }
                sm->line_len = 0;
                i++; /* skip \n */
            } else {
                /* Partial line — accumulate for next buffer */
                size_t cplen = len - start;
                if (sm->line_len + cplen < sizeof(sm->line_buf) - 1) {
                    memcpy(sm->line_buf + sm->line_len, data + start, cplen);
                    sm->line_len += cplen;
                }
                break;
            }

        /* --- States: REQ_BODY / RES_BODY — payload + chunked --- */
        } else if (sm->state == HTTP_REQ_BODY || sm->state == HTTP_RES_BODY) {
            int is_state_req = (sm->state == HTTP_REQ_BODY);
            if (is_req != is_state_req) break; /* wrong direction */

            if (sm->is_chunked) {
                /* Chunked: parse hex size → data → CRLF → repeat */
                if (sm->chunk_rem == 0 && !sm->in_chunk_ext) {
                    /* Read chunk size line */
                    size_t start = i;
                    while (i < len && data[i] != '\n') i++;
                    if (i < len) {
                        size_t cplen = i - start;
                        if (cplen > 0 && data[i-1] == '\r') cplen--;
                        if (sm->line_len + cplen < sizeof(sm->line_buf) - 1) {
                            memcpy(sm->line_buf + sm->line_len, data + start, cplen);
                            sm->line_len += cplen;
                        }
                        sm->line_buf[sm->line_len] = '\0';
                        sm->chunk_rem = strtoull(sm->line_buf, NULL, 16);
                        sm->line_len = 0;
                        i++; /* skip \n */
                        if (sm->chunk_rem == 0) {
                            /* Final chunk → parse trailers (from I-Genesis #60) */
                            if (is_state_req) {
                                sha256_update(&sm->receipt_ctx, (const uint8_t*)"\n", 1);
                                sm->state = HTTP_WAIT_RES;
                            } else {
                                sm->state = HTTP_TRAILER;
                                sm->line_len = 0;
                            }
                            continue;
                        }
                    } else {
                        size_t cplen = len - start;
                        if (sm->line_len + cplen < sizeof(sm->line_buf) - 1) {
                            memcpy(sm->line_buf + sm->line_len, data + start, cplen);
                            sm->line_len += cplen;
                        }
                        break;
                    }
                } else if (sm->chunk_rem > 0) {
                    size_t avail = len - i;
                    size_t take = avail > sm->chunk_rem ? (size_t)sm->chunk_rem : avail;
                    if (is_state_req) fsm_hash_req(sm, data + i, take);
                    else { fsm_hash_res(fd, sm, data + i, take); scan_body_anomalies(fd, data + i, take); }
                    sm->chunk_rem -= take;
                    i += take;
                    if (sm->chunk_rem == 0) sm->in_chunk_ext = 1;
                } else if (sm->in_chunk_ext) {
                    /* Skip trailing CRLF after chunk data */
                    if (data[i] == '\n') { i++; sm->in_chunk_ext = 0; }
                    else i++;
                }
            } else {
                /* Identity body (Content-Length or until close) */
                size_t avail = len - i;
                size_t take = avail;
                if (sm->content_length > 0) {
                    size_t rem = (size_t)(sm->content_length - sm->body_bytes_read);
                    if (take > rem) take = rem;
                }
                if (is_state_req) fsm_hash_req(sm, data + i, take);
                else { fsm_hash_res(fd, sm, data + i, take); scan_body_anomalies(fd, data + i, take); }
                sm->body_bytes_read += take;
                i += take;
                if (sm->content_length > 0 && sm->body_bytes_read >= sm->content_length) {
                    if (is_state_req) {
                        sha256_update(&sm->receipt_ctx, (const uint8_t*)"\n", 1);
                        sm->state = HTTP_WAIT_RES;
                    } else {
                        fsm_emit_receipt(fd);
                    }
                }
            }

        /* --- State: TRAILER — after final 0-chunk (from I-Genesis #60) --- */
        } else if (sm->state == HTTP_TRAILER) {
            size_t start = i;
            while (i < len && data[i] != '\n') i++;
            if (i < len) {
                size_t cplen = i - start;
                if (cplen > 0 && data[i-1] == '\r') cplen--;
                if (cplen == 0) {
                    /* Empty line after trailers → receipt */
                    fsm_emit_receipt(fd);
                }
                /* Non-empty trailer lines are silently consumed */
                i++; /* skip \n */
            } else {
                break; /* wait for more data */
            }

        /* --- State: WAIT_RES — request done, waiting for response --- */
        } else if (sm->state == HTTP_WAIT_RES) {
            if (is_req) break; /* new request while waiting — shouldn't happen on LLM FDs */
            sm->state = HTTP_RES_HDR;
            sm->line_len = 0; sm->content_length = 0;
            sm->body_bytes_read = 0; sm->is_chunked = 0;
            sm->chunk_rem = 0; sm->in_chunk_ext = 0;
        } else {
            break;
        }
    }
}

/* ================================================================== */
/*   HTTP/2 Multiplexed FSM & HPACK Decoder (L-SelfVerify + K-Constr) */
/*   Zero-malloc binary frame parser with per-stream SHA-256 receipts, */
/*   full HPACK Huffman decoding (K #71), fd_to_h2 O(1) lookup (K #72),*/
/*   HPACK buffer accumulation + END_HEADERS gating (K #73), stream    */
/*   eviction (K #74), path-based LLM detection (K #75),               */
/*   end_stream_pending (K #76), per-stream timing_started (K #77),    */
/*   gRPC protobuf wire format parsing (R24 #81-#87): content-type     */
/*   detection, 5-byte LPM header, varint decoder, recursive protobuf  */
/*   model scanner with depth limit + UTF-8 validation.                */
/* ================================================================== */

#define MAX_H2_CONNS 64
#define MAX_H2_STREAMS 16

typedef struct {
    uint32_t stream_id;
    int active;
    char method[16];
    char path[512];
    int status;
    char content_type[64];
    char model[128], req_model[128], res_model[128];
    int req_mscan, req_midx, res_mscan, res_midx;
    sha256_ctx_t req_ctx, res_ctx, receipt_ctx;
    uint64_t total_req_bytes, total_res_bytes;
    int req_hdr_hashed, res_hdr_hashed;
    int is_sse;
    char sse_line[256];
    size_t sse_len;
    int timing_started; /* K #77: per-stream timing flag */
    /* R26: Per-direction transcript extraction (#110/#112) */
    transcript_dfa_t req_tx;
    transcript_dfa_t res_tx;
    /* R24 gRPC protobuf parsing state */
    int is_grpc;        /* set via content-type: application/grpc */
    int grpc_state;     /* 0=reading 5-byte hdr, 1=reading msg, 2=done (model found) */
    uint32_t grpc_msg_rem; /* bytes remaining in current LPM */
    uint8_t grpc_hdr[5];  /* 5-byte gRPC length-prefixed message header */
    uint8_t grpc_hdr_pos; /* bytes accumulated in grpc_hdr */
    uint8_t grpc_req_buf[2048]; /* first 2KB of request payload for model extraction */
    uint32_t grpc_req_pos;      /* bytes written to grpc_req_buf */
} h2_stream_t;

/* Directional parser state — separate TX/RX contexts with HPACK buffer
 * accumulation (K #73) and deferred END_STREAM (K #76). */
typedef struct {
    uint8_t hdr[9];
    uint32_t hdr_pos;
    uint32_t frame_len;
    uint8_t frame_type;
    uint8_t frame_flags;
    uint32_t stream_id;
    uint32_t payload_read;
    uint8_t pad_len;
    int in_frame;
    int end_stream_pending; /* K #76 */
    uint8_t hpack_buf[8192]; /* K #73: accumulate HPACK across CONTINUATIONs */
    uint32_t hpack_len;
} h2_parser_t;

typedef struct {
    volatile int fd;
    volatile int lock;
    h2_stream_t streams[MAX_H2_STREAMS];
    h2_parser_t rx, tx;
    int preface_read;
} h2_conn_t;

static h2_conn_t h2_conns[MAX_H2_CONNS];

/* Forward declarations for mutual dependencies */
static void h2_emit_receipt(int fd, h2_stream_t *sm);

/* ---- R24 gRPC Protobuf Wire Format Parsing ----
 * Schema-less protobuf parsing for model name extraction from gRPC streams.
 * Handles: varint (wire 0), 64-bit fixed (wire 1), length-delimited (wire 2),
 * 32-bit fixed (wire 5). Recursive descent with depth limit for nested msgs.
 * UTF-8 printability validation prevents binary noise false positives. */

/* R24 #84: Varint decoder with bounds checking and error flag */
static uint64_t pb_decode_varint(const uint8_t **p, const uint8_t *end, int *err) {
    uint64_t val = 0; int shift = 0; *err = 1;
    while (*p < end) {
        uint8_t b = *(*p)++;
        val |= (uint64_t)(b & 0x7F) << shift;
        if (!(b & 0x80)) { *err = 0; return val; }
        shift += 7;
        if (shift >= 64) break;
    }
    return val;
}

/* R24 #82/#85: Recursive protobuf model scanner with depth limit + UTF-8 check.
 * Scans length-delimited (wire type 2) fields for known LLM model prefixes.
 * Recursively descends into nested messages. Stops on first valid match. */
static void pb_scan_model(const uint8_t *data, size_t len, char *model_out,
                          size_t model_sz, int depth) {
    if (len == 0 || model_out[0] != '\0' || depth > 10) return;
    const uint8_t *p = data;
    const uint8_t *end = data + len;
    while (p < end && model_out[0] == '\0') {
        int err = 0;
        uint64_t tag_wire = pb_decode_varint(&p, end, &err);
        if (err) break;
        int wire = tag_wire & 7;
        if (wire == 0) {
            /* Varint — skip */
            pb_decode_varint(&p, end, &err);
            if (err) break;
        } else if (wire == 1) {
            /* 64-bit fixed — skip 8 bytes */
            if (end - p < 8) break;
            p += 8;
        } else if (wire == 5) {
            /* 32-bit fixed — skip 4 bytes */
            if (end - p < 4) break;
            p += 4;
        } else if (wire == 2) {
            /* Length-delimited: could be string, bytes, or nested message */
            uint64_t vlen = pb_decode_varint(&p, end, &err);
            if (err) break;
            size_t available = (size_t)(end - p);
            size_t scan_len = vlen < available ? (size_t)vlen : available;
            if (scan_len > 0) {
                /* Check for known LLM model name prefixes */
                if ((scan_len >= 7 && !memcmp(p, "gemini-", 7)) ||
                    (scan_len >= 4 && !memcmp(p, "gpt-", 4)) ||
                    (scan_len >= 7 && !memcmp(p, "claude-", 7)) ||
                    (scan_len >= 7 && !memcmp(p, "models/", 7))) {
                    /* R24 #81: UTF-8 printability validation */
                    size_t clen = scan_len < model_sz - 1 ? scan_len : model_sz - 1;
                    int is_print = 1;
                    for (size_t k = 0; k < clen; k++) {
                        if (p[k] < 32 || p[k] > 126) { is_print = 0; break; }
                    }
                    if (is_print) {
                        memcpy(model_out, p, clen);
                        model_out[clen] = '\0';
                        return;
                    }
                }
                /* Recurse into potential nested messages */
                pb_scan_model(p, scan_len, model_out, model_sz, depth + 1);
            }
            p += scan_len;
            if (vlen > available) break;
        } else {
            break; /* Unknown wire type — stop parsing */
        }
    }
}

/* R24 #83: gRPC Length-Prefixed Message (LPM) state machine.
 * Parses 5-byte gRPC header ([compressed:1][length:4]) then buffers up to
 * 2KB of request payload. Calls pb_scan_model when buffer fills or message
 * ends. State: 0=reading header, 1=reading message, 2=done (model found). */
static void grpc_feed(h2_stream_t *st, const uint8_t *data, size_t len) {
    if (st->grpc_state == 2) return; /* Already found model — skip */
    size_t i = 0;
    while (i < len) {
        if (st->grpc_state == 0) {
            /* Accumulate 5-byte LPM header */
            size_t take = 5 - st->grpc_hdr_pos;
            if (take > len - i) take = len - i;
            memcpy(st->grpc_hdr + st->grpc_hdr_pos, data + i, take);
            st->grpc_hdr_pos += (uint8_t)take;
            i += take;
            if (st->grpc_hdr_pos == 5) {
                st->grpc_msg_rem = ((uint32_t)st->grpc_hdr[1] << 24) |
                                   ((uint32_t)st->grpc_hdr[2] << 16) |
                                   ((uint32_t)st->grpc_hdr[3] << 8) |
                                    st->grpc_hdr[4];
                st->grpc_state = 1;
            }
        } else if (st->grpc_state == 1) {
            /* Buffer message payload (up to 2KB) */
            size_t take = st->grpc_msg_rem;
            if (take > len - i) take = len - i;
            size_t space = sizeof(st->grpc_req_buf) - st->grpc_req_pos;
            size_t copy = take < space ? take : space;
            if (copy > 0) {
                memcpy(st->grpc_req_buf + st->grpc_req_pos, data + i, copy);
                st->grpc_req_pos += (uint32_t)copy;
            }
            st->grpc_msg_rem -= (uint32_t)take;
            i += take;
            /* Buffer full — scan now and stop */
            if (st->grpc_req_pos == sizeof(st->grpc_req_buf)) {
                st->grpc_state = 2;
                pb_scan_model(st->grpc_req_buf, st->grpc_req_pos,
                              st->req_model, sizeof(st->req_model), 0);
                break;
            }
            /* End of LPM — reset header for next message in stream */
            if (st->grpc_msg_rem == 0) {
                st->grpc_state = 0;
                st->grpc_hdr_pos = 0;
            }
        }
    }
}

/* K #74: stream eviction — when all slots full, evict oldest stream_id
 * (lowest stream_id = oldest in HTTP/2's monotonic stream numbering). */
static h2_stream_t* h2_get_stream(h2_conn_t *conn, uint32_t stream_id) {
    if (stream_id == 0 || (stream_id % 2) == 0) return NULL;
    int free_idx = -1;
    uint32_t oldest_id = 0xFFFFFFFF;
    int oldest_idx = 0;
    for (int i = 0; i < MAX_H2_STREAMS; i++) {
        if (conn->streams[i].active && conn->streams[i].stream_id == stream_id)
            return &conn->streams[i];
        if (!conn->streams[i].active && free_idx == -1)
            free_idx = i;
        if (conn->streams[i].active && conn->streams[i].stream_id < oldest_id) {
            oldest_id = conn->streams[i].stream_id;
            oldest_idx = i;
        }
    }
    int idx = free_idx != -1 ? free_idx : oldest_idx;
    h2_stream_t *st = &conn->streams[idx];
    if (st->active) h2_emit_receipt(conn->fd, st);
    memset(st, 0, sizeof(h2_stream_t));
    st->active = 1;
    st->stream_id = stream_id;
    sha256_init(&st->req_ctx);
    sha256_init(&st->res_ctx);
    sha256_init(&st->receipt_ctx);
    tx_init(&st->req_tx);
    tx_init(&st->res_tx);
    return st;
}

/* Unified deferred header hashing (K's h2_check_hash_headers — cleaner than
 * separate h2_hash_req_hdr/h2_hash_res_hdr from L). Ensures receipt hash
 * order: method||" "||path||"\n"||req_body||"\n"||status||"\n"||res_body. */
static void h2_check_hash_headers(h2_stream_t *st) {
    if (!st->req_hdr_hashed && st->method[0]) {
        sha256_update(&st->receipt_ctx, (const uint8_t*)st->method, strlen(st->method));
        sha256_update(&st->receipt_ctx, (const uint8_t*)" ", 1);
        const char *p = st->path[0] ? st->path : "/";
        sha256_update(&st->receipt_ctx, (const uint8_t*)p, strlen(p));
        sha256_update(&st->receipt_ctx, (const uint8_t*)"\n", 1);
        st->req_hdr_hashed = 1;
    }
    if (!st->res_hdr_hashed && st->status != 0) {
        if (!st->req_hdr_hashed && st->method[0]) {
            sha256_update(&st->receipt_ctx, (const uint8_t*)st->method, strlen(st->method));
            sha256_update(&st->receipt_ctx, (const uint8_t*)" ", 1);
            const char *p = st->path[0] ? st->path : "/";
            sha256_update(&st->receipt_ctx, (const uint8_t*)p, strlen(p));
            sha256_update(&st->receipt_ctx, (const uint8_t*)"\n", 1);
            st->req_hdr_hashed = 1;
        }
        char stat_str[32]; snprintf(stat_str, sizeof(stat_str), "%d\n", st->status);
        sha256_update(&st->receipt_ctx, (const uint8_t*)stat_str, strlen(stat_str));
        st->res_hdr_hashed = 1;
    }
}

static void h2_emit_receipt(int fd, h2_stream_t *sm) {
    if (!sm->active || sm->method[0] == '\0') { sm->active = 0; return; }
    /* R26 #116: Flush pending transcript events before receipt */
    tx_flush(fd, sm->stream_id, &sm->req_tx);
    tx_flush(fd, sm->stream_id, &sm->res_tx);
    h2_check_hash_headers(sm);

    uint8_t rq_h[32], rs_h[32], rc_h[32]; sha256_ctx_t t;
    t = sm->req_ctx; sha256_final(&t, rq_h);
    t = sm->res_ctx; sha256_final(&t, rs_h);
    t = sm->receipt_ctx; sha256_final(&t, rc_h);

    char hex_rq[65], hex_rs[65], hex_rc[65];
    for (int k = 0; k < 32; k++) {
        snprintf(&hex_rq[k*2], 3, "%02x", rq_h[k]);
        snprintf(&hex_rs[k*2], 3, "%02x", rs_h[k]);
        snprintf(&hex_rc[k*2], 3, "%02x", rc_h[k]);
    }

    /* R24: Use req_model as primary for gRPC (model is always in request) */
    const char *effective_model = sm->req_model[0] ? sm->req_model :
                                  sm->model[0] ? sm->model :
                                  sm->res_model[0] ? sm->res_model : "unknown";
    int model_substituted = 0;
    if (sm->req_model[0] && (sm->res_model[0] || sm->model[0])) {
        const char *actual = sm->model[0] ? sm->model : sm->res_model;
        if (actual[0] && strcmp(sm->req_model, actual) != 0) {
            model_substituted = 1; tl_event_fd = fd;
            char rm[256], am[256]; escape_json(sm->req_model, rm, sizeof(rm)); escape_json(actual, am, sizeof(am));
            emit_log_event("security_anomaly", getpid(), -999,
                ",\"fd\":%d,\"type\":\"model_substitution_structural\","
                "\"requested\":\"%s\",\"actual\":\"%s\"", fd, rm, am);
        }
    }

    char path_esc[1024], model_esc[256], req_m_esc[256];
    escape_json(sm->path, path_esc, sizeof(path_esc));
    escape_json(effective_model, model_esc, sizeof(model_esc));
    escape_json(sm->req_model, req_m_esc, sizeof(req_m_esc));

    tl_event_fd = fd;
    if (sm->is_grpc) {
        /* R24 #87: Emit grpc_receipt for gRPC streams (compact format) */
        emit_log_event("grpc_receipt", getpid(), -999,
            ",\"fd\":%d,\"receipt_hash\":\"%s\""
            ",\"stream_id\":%u,\"path\":\"%s\""
            ",\"model\":\"%s\",\"req_model\":\"%s\",\"model_substituted\":%d"
            ",\"req_bytes\":%llu,\"res_bytes\":%llu",
            fd, hex_rc, sm->stream_id, path_esc,
            model_esc, req_m_esc, model_substituted,
            (unsigned long long)sm->total_req_bytes,
            (unsigned long long)sm->total_res_bytes);
    } else {
        emit_log_event("llm_receipt", getpid(), -999,
            ",\"fd\":%d,\"receipt_hash\":\"%s\""
            ",\"method\":\"%s\",\"path\":\"%s\",\"status\":%d"
            ",\"stream_id\":%u"
            ",\"req_bytes\":%llu,\"res_bytes\":%llu"
            ",\"req_body_sha256\":\"%s\",\"res_body_sha256\":\"%s\""
            ",\"model\":\"%s\",\"req_model\":\"%s\",\"model_substituted\":%d",
            fd, hex_rc,
            sm->method, path_esc, sm->status,
            sm->stream_id,
            (unsigned long long)sm->total_req_bytes,
            (unsigned long long)sm->total_res_bytes,
            hex_rq, hex_rs, model_esc, req_m_esc, model_substituted);
    }
    sm->active = 0;
}

/* Forward declarations for h2_get_stream (used by h2_emit_receipt via eviction) */
static void h2_flush(int fd);

/* CAS-based H2 connection allocation (K's h2_init_conn) */
static void h2_init_conn(int fd) {
    if (fd < 0 || fd >= 1024) return;
    if (fd_to_h2[fd] != -1) return;
    for (int i = 0; i < MAX_H2_CONNS; i++) {
        if (__sync_bool_compare_and_swap(&h2_conns[i].fd, -1, fd)) {
            h2_conn_t *conn = &h2_conns[i];
            conn->lock = 0;
            memset(&conn->rx, 0, sizeof(h2_parser_t));
            memset(&conn->tx, 0, sizeof(h2_parser_t));
            for (int j = 0; j < MAX_H2_STREAMS; j++) conn->streams[j].active = 0;
            conn->preface_read = 0;
            fd_to_h2[fd] = i;
            return;
        }
    }
}

/* K #71: Full HPACK static table (RFC 7541 Appendix A) — 62 entries */
static const char* const hpack_static_name[] = {
    "", ":authority", ":method", ":method", ":path", ":path", ":scheme", ":scheme",
    ":status", ":status", ":status", ":status", ":status", ":status", ":status",
    "accept-charset", "accept-encoding", "accept-language", "accept-ranges",
    "accept", "access-control-allow-origin", "age", "allow", "authorization",
    "cache-control", "content-disposition", "content-encoding", "content-language",
    "content-length", "content-location", "content-range", "content-type",
    "cookie", "date", "etag", "expect", "expires", "from", "host",
    "if-match", "if-modified-since", "if-none-match", "if-range",
    "if-unmodified-since", "last-modified", "link", "location",
    "max-forwards", "proxy-authenticate", "proxy-authorization",
    "range", "referer", "refresh", "retry-after", "server", "set-cookie",
    "strict-transport-security", "transfer-encoding", "user-agent",
    "vary", "via", "www-authenticate"
};

static const char* const hpack_static_val[] = {
    "", "", "GET", "POST", "/", "/index.html", "http", "https",
    "200", "204", "206", "304", "400", "404", "500",
    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
    "", "", "", "", "", "", "", "", ""
};

/* K #71: HPACK integer decode with configurable prefix bits (RFC 7541 §5.1) */
static uint32_t hpack_decode_int(const uint8_t **p, const uint8_t *end, int prefix_bits) {
    if (*p >= end) return 0;
    uint32_t mask = (1 << prefix_bits) - 1;
    uint32_t val = **p & mask;
    (*p)++;
    if (val < mask) return val;
    uint32_t m = 0;
    while (*p < end) {
        uint8_t b = **p; (*p)++;
        val += (b & 127) << m;
        m += 7;
        if (!(b & 128)) break;
    }
    return val;
}

/* K #71: Full 512-entry HPACK Huffman decoding tree (RFC 7541 Appendix B).
 * Values 0-255 = literal byte output, 256 = EOS, 257+ = internal tree node.
 * Each node has two children: tree[node*2] for bit=0, tree[node*2+1] for bit=1. */
static const uint16_t hpack_huff_tree[512] = {
    322,257,349,258,360,259,375,260,400,261,331,262,379,263,327,264,
    333,265,329,266,267,269,268,358,0,36,383,270,384,271,354,272,
    123,273,380,274,406,275,276,281,455,277,472,278,279,418,280,417,
    1,135,423,282,297,283,447,284,467,285,485,286,287,301,288,294,
    289,291,254,290,2,3,292,293,4,5,6,7,295,308,296,307,
    8,11,464,298,299,421,239,300,9,142,311,302,319,303,403,304,
    249,305,306,315,10,13,12,14,309,310,15,16,17,18,312,316,
    313,314,19,20,21,23,22,256,317,318,24,25,26,27,320,321,
    28,29,30,31,341,323,324,338,399,325,326,337,32,37,328,335,
    33,34,124,330,35,62,332,336,38,42,63,334,39,43,40,41,
    44,59,45,46,339,346,340,345,47,51,342,386,343,344,48,49,
    50,97,52,53,347,348,54,55,56,57,355,350,394,351,398,352,
    353,359,58,66,60,96,356,388,357,385,61,65,64,91,67,68,
    361,368,362,365,363,364,69,70,71,72,366,367,73,74,75,76,
    369,372,370,371,77,78,79,80,373,374,81,82,83,84,376,392,
    377,378,85,86,87,89,88,90,381,411,382,404,92,195,93,126,
    94,125,95,98,387,391,99,101,389,390,100,102,103,104,105,111,
    393,397,106,107,395,396,108,109,110,112,113,118,114,117,115,116,
    401,402,119,120,121,122,127,220,208,405,128,130,452,407,408,434,
    409,414,230,410,129,132,412,431,413,460,131,162,415,416,133,134,
    136,146,137,138,419,420,139,140,141,143,422,427,144,145,424,441,
    425,429,426,428,147,149,148,159,150,151,430,437,152,155,497,432,
    433,444,153,161,435,439,436,438,154,156,157,158,160,163,440,446,
    164,169,442,450,443,445,165,166,167,172,168,174,170,173,448,474,
    449,490,171,206,451,459,175,180,453,491,454,458,176,177,456,462,
    457,461,178,181,179,209,182,183,184,194,185,186,463,466,187,189,
    465,471,188,191,190,196,468,480,469,478,470,477,192,193,197,231,
    473,499,198,228,501,475,476,500,199,207,200,201,479,484,202,205,
    493,481,504,482,255,483,203,204,210,213,486,505,487,495,488,489,
    211,212,214,221,215,225,492,498,216,217,494,502,218,219,496,503,
    222,223,224,226,227,229,232,233,234,235,236,237,238,240,241,244,
    242,243,506,509,507,508,245,246,247,248,510,511,250,251,252,253
};

/* K #71: Decode HPACK string with full Huffman support */
static void hpack_decode_string(const uint8_t **p, const uint8_t *end, char *out, int out_sz) {
    if (*p >= end) { out[0] = 0; return; }
    int is_huff = (**p & 0x80);
    uint32_t len = hpack_decode_int(p, end, 7);
    if ((uint32_t)(end - *p) < len) len = (uint32_t)(end - *p);
    if (is_huff) {
        int state = 0, out_len = 0;
        for (uint32_t i = 0; i < len; i++) {
            uint8_t b = (*p)[i];
            for (int j = 7; j >= 0; j--) {
                uint16_t next = hpack_huff_tree[state * 2 + ((b >> j) & 1)];
                if (next == 256) { out[out_len] = '\0'; *p += len; return; }
                if (next < 256) {
                    if (out_len < out_sz - 1) out[out_len++] = (char)next;
                    state = 0;
                } else {
                    state = next - 256;
                }
            }
        }
        out[out_len] = '\0';
    } else {
        uint32_t cplen = len < (uint32_t)out_sz - 1 ? len : (uint32_t)out_sz - 1;
        memcpy(out, *p, cplen);
        out[cplen] = '\0';
    }
    *p += len;
}

/* Full HPACK header block parser using Huffman decoder + static table.
 * Handles indexed (0x80), literal with/without/never indexing, and
 * dynamic table size updates. Extracts :method, :path, :status,
 * content-type, x-model, openai-model into h2_stream_t fields. */
static void hpack_parse(h2_conn_t *c, h2_stream_t *st, const uint8_t *payload, size_t len, int is_req) {
    (void)c; (void)is_req;
    const uint8_t *p = payload;
    const uint8_t *end = payload + len;
    while (p < end) {
        uint8_t b = *p;
        if (b & 0x80) {
            uint32_t idx = hpack_decode_int(&p, end, 7);
            if (idx > 0 && idx <= 61) {
                const char *n = hpack_static_name[idx];
                const char *v = hpack_static_val[idx];
                if (!strcmp(n, ":method")) strncpy(st->method, v, sizeof(st->method)-1);
                else if (!strcmp(n, ":path")) strncpy(st->path, v, sizeof(st->path)-1);
                else if (!strcmp(n, ":status")) st->status = atoi(v);
            }
        } else if ((b & 0xC0) == 0x40 || (b & 0xF0) == 0x00 || (b & 0xF0) == 0x10) {
            int is_inc = ((b & 0xC0) == 0x40);
            int prefix = is_inc ? 6 : 4;
            uint32_t idx = hpack_decode_int(&p, end, prefix);
            char name[64] = {0}; char val[256] = {0};
            if (idx > 0 && idx <= 61) strncpy(name, hpack_static_name[idx], sizeof(name)-1);
            else if (idx == 0) hpack_decode_string(&p, end, name, sizeof(name));
            hpack_decode_string(&p, end, val, sizeof(val));
            if (!strcmp(name, ":method")) strncpy(st->method, val, sizeof(st->method)-1);
            else if (!strcmp(name, ":path")) strncpy(st->path, val, sizeof(st->path)-1);
            else if (!strcmp(name, ":status")) st->status = atoi(val);
            else if (!strcmp(name, "content-type")) {
                if (my_strcasestr(val, "text/event-stream")) st->is_sse = 1;
                /* R24 #87: Detect gRPC streams, disable JSON model scanning */
                if (my_strcasestr(val, "application/grpc")) {
                    st->is_grpc = 1;
                    st->req_mscan = 99; st->res_mscan = 99;
                }
            }
            if (my_strcasestr(name, "x-model") || my_strcasestr(name, "openai-model"))
                strncpy(st->model, val, sizeof(st->model)-1);
        } else if ((b & 0xE0) == 0x20) {
            hpack_decode_int(&p, end, 5);
        } else {
            break;
        }
    }
}

/* Factored response body hashing with SSE canonicalization (from K) */
static void h2_hash_res(int fd, h2_stream_t *sm, const uint8_t *data, size_t len) {
    json_model_scan(&sm->res_mscan, &sm->res_midx, sm->res_model, sizeof(sm->res_model), data, len);
    scan_body_anomalies(fd, data, len);
    /* R26 #111/#112: Feed response bytes into transcript (JSON or gRPC) */
    if (sm->is_grpc) tx_feed_grpc(fd, sm->stream_id, &sm->res_tx, data, len);
    else tx_feed_json(fd, sm->stream_id, &sm->res_tx, data, len);
    if (!sm->is_sse) {
        sha256_update(&sm->res_ctx, data, len);
        sha256_update(&sm->receipt_ctx, data, len);
        sm->total_res_bytes += len;
        return;
    }
    for (size_t i = 0; i < len; i++) {
        char ch = (char)data[i];
        if (sm->sse_len < sizeof(sm->sse_line) - 1)
            sm->sse_line[sm->sse_len++] = ch;
        if (ch == '\n') {
            sm->sse_line[sm->sse_len] = '\0';
            if (strncmp(sm->sse_line, "data: ", 6) == 0) {
                size_t dlen = sm->sse_len - 6;
                if (dlen > 0 && sm->sse_line[6 + dlen - 1] == '\n') dlen--;
                if (dlen > 0 && sm->sse_line[6 + dlen - 1] == '\r') dlen--;
                if (!(dlen == 6 && memcmp(sm->sse_line + 6, "[DONE]", 6) == 0)) {
                    sha256_update(&sm->res_ctx, (const uint8_t*)sm->sse_line + 6, dlen);
                    sha256_update(&sm->receipt_ctx, (const uint8_t*)sm->sse_line + 6, dlen);
                    sm->total_res_bytes += dlen;
                }
            }
            sm->sse_len = 0;
        }
    }
}

/* Flush all active H2 streams on FD close (standalone, uses fd_to_h2) */
static void h2_flush(int fd) {
    if (fd < 0 || fd >= 1024) return;
    int slot = fd_to_h2[fd];
    if (slot != -1) {
        h2_conn_t *conn = &h2_conns[slot];
        while (__sync_lock_test_and_set(&conn->lock, 1)) {}
        for (int i = 0; i < MAX_H2_STREAMS; i++) {
            if (conn->streams[i].active && conn->streams[i].method[0])
                h2_emit_receipt(fd, &conn->streams[i]);
        }
        conn->fd = -1;
        fd_to_h2[fd] = -1;
        __sync_lock_release(&conn->lock);
    }
}

/**
 * Process raw SSL bytes through the HTTP/2 frame parser.
 * Uses fd_to_h2 O(1) lookup (K #72), HPACK buffer accumulation with
 * END_HEADERS gating (K #73), end_stream_pending (K #76),
 * path-based LLM detection after HEADERS decode (K #75),
 * per-stream timing_started (K #77).
 */
static void h2_feed(int fd, const uint8_t *data, size_t len, int is_req) {
    int slot = fd >= 0 && fd < 1024 ? fd_to_h2[fd] : -1;
    if (slot == -1) return;
    h2_conn_t *c = &h2_conns[slot];

    while (__sync_lock_test_and_set(&c->lock, 1)) {}
    h2_parser_t *p = is_req ? &c->tx : &c->rx;
    size_t i = 0;

    /* Skip 24-byte connection preface on TX direction */
    if (is_req && c->preface_read < 24) {
        size_t take = 24 - c->preface_read;
        if (take > len) take = len;
        c->preface_read += (int)take;
        i += take;
    }

    while (i < len) {
        if (!p->in_frame) {
            /* Accumulate 9-byte frame header */
            size_t take = 9 - p->hdr_pos;
            if (take > len - i) take = len - i;
            memcpy(p->hdr + p->hdr_pos, data + i, take);
            p->hdr_pos += (uint32_t)take;
            i += take;

            if (p->hdr_pos == 9) {
                p->frame_len = ((uint32_t)p->hdr[0] << 16) | ((uint32_t)p->hdr[1] << 8) | p->hdr[2];
                p->frame_type = p->hdr[3];
                p->frame_flags = p->hdr[4];
                p->stream_id = ((uint32_t)(p->hdr[5] & 0x7F) << 24) | ((uint32_t)p->hdr[6] << 16) |
                               ((uint32_t)p->hdr[7] << 8) | p->hdr[8];
                p->payload_read = 0;
                p->pad_len = 0;
                p->in_frame = 1;
            }
        } else {
            size_t rem = p->frame_len - p->payload_read;
            size_t take = len - i;
            if (take > rem) take = rem;

            int is_client_stream = (p->stream_id > 0 && (p->stream_id % 2) != 0);
            h2_stream_t *st = NULL;
            if (is_client_stream) st = h2_get_stream(c, p->stream_id);

            if (take > 0 && st) {
                size_t p_offset = 0;
                size_t p_take = take;

                /* Skip PADDED (0x08) and PRIORITY (0x20) prefix bytes */
                int has_pad = (p->frame_flags & 0x08) && (p->frame_type == 0 || p->frame_type == 1);
                int pad_skip = has_pad ? 1 : 0;
                if (p->frame_type == 1 && (p->frame_flags & 0x20)) pad_skip += 5;

                if (p->payload_read < (uint32_t)pad_skip) {
                    size_t skip = (uint32_t)pad_skip - p->payload_read;
                    if (skip > p_take) skip = p_take;
                    if (has_pad && p->payload_read == 0 && skip > 0) p->pad_len = data[i];
                    p_offset += skip;
                    p_take -= skip;
                }

                size_t payload_end = p->frame_len > p->pad_len ? p->frame_len - p->pad_len : 0;
                size_t curr_pos = p->payload_read + p_offset;

                if (curr_pos < payload_end && p_take > 0) {
                    size_t data_bytes = p_take;
                    if (curr_pos + data_bytes > payload_end) data_bytes = payload_end - curr_pos;
                    if (data_bytes > 0) {
                        const uint8_t *valid_data = data + i + p_offset;
                        if (p->frame_type == 1 || p->frame_type == 9) {
                            /* K #73: Buffer HPACK data until END_HEADERS */
                            if (p->hpack_len + data_bytes <= sizeof(p->hpack_buf)) {
                                memcpy(p->hpack_buf + p->hpack_len, valid_data, data_bytes);
                                p->hpack_len += (uint32_t)data_bytes;
                            }
                        } else if (p->frame_type == 0) {
                            /* DATA frame → hash body */
                            h2_check_hash_headers(st);
                            if (is_req) {
                                sha256_update(&st->req_ctx, valid_data, data_bytes);
                                sha256_update(&st->receipt_ctx, valid_data, data_bytes);
                                st->total_req_bytes += data_bytes;
                                /* R24: gRPC streams use protobuf parsing, not JSON */
                                if (st->is_grpc) {
                                    grpc_feed(st, valid_data, data_bytes);
                                    tx_feed_grpc(fd, st->stream_id, &st->req_tx, valid_data, data_bytes);
                                } else {
                                    json_model_scan(&st->req_mscan, &st->req_midx, st->req_model,
                                                    sizeof(st->req_model), valid_data, data_bytes);
                                    tx_feed_json(fd, st->stream_id, &st->req_tx, valid_data, data_bytes);
                                }
                            } else {
                                h2_hash_res(fd, st, valid_data, data_bytes);
                            }
                        }
                    }
                }
            }

            p->payload_read += (uint32_t)take;
            i += take;

            if (p->payload_read == p->frame_len) {
                /* K #73: Decode accumulated HPACK on END_HEADERS (0x04) */
                if (st && (p->frame_type == 1 || p->frame_type == 9)) {
                    if (p->frame_flags & 0x04) {
                        hpack_parse(c, st, p->hpack_buf, p->hpack_len, is_req);
                        h2_check_hash_headers(st);
                        /* K #75: Path-based LLM detection after HEADERS decode */
                        if (is_req && st->method[0] != '\0' && !st->timing_started) {
                            if (!is_llm_fd(fd) && (my_strcasestr(st->path, "/v1/chat") ||
                                my_strcasestr(st->path, "/v1/compl") ||
                                my_strcasestr(st->path, "/api/gene") ||
                                my_strcasestr(st->path, "/v1/messa") ||
                                st->is_grpc)) { /* R24: gRPC streams are LLM traffic */
                                set_llm_fd(fd);
                            }
                            if (is_llm_fd(fd)) timing_start_req(fd);
                            st->timing_started = 1;
                        }
                        p->hpack_len = 0;
                    }
                }
                /* K #76: Track END_STREAM for deferred processing */
                if (st && (p->frame_flags & 0x01) && (p->frame_type == 0 || p->frame_type == 1)) {
                    p->end_stream_pending = 1;
                }
                if (st && p->end_stream_pending && p->hpack_len == 0) {
                    if (is_req) {
                        h2_check_hash_headers(st);
                        sha256_update(&st->receipt_ctx, (const uint8_t*)"\n", 1);
                        /* R24 #85: Parse remaining gRPC buffer on request end_stream */
                        if (st->is_grpc && st->grpc_req_pos > 0 && st->req_model[0] == '\0') {
                            pb_scan_model(st->grpc_req_buf, st->grpc_req_pos,
                                          st->req_model, sizeof(st->req_model), 0);
                        }
                    } else {
                        h2_check_hash_headers(st);
                        h2_emit_receipt(fd, st);
                    }
                    p->end_stream_pending = 0;
                }

                p->in_frame = 0;
                p->hdr_pos = 0;
            }
        }
    }
    __sync_lock_release(&c->lock);
}

/* ================================================================== */
/*                      Function Pointers                             */
/* ================================================================== */

typedef int (*open_func_t)(const char *, int, ...);
typedef int (*openat_func_t)(int, const char *, int, ...);
typedef int (*connect_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*bind_func_t)(int, const struct sockaddr *, socklen_t);
typedef int (*listen_func_t)(int, int);
typedef int (*accept_func_t)(int, struct sockaddr *restrict, socklen_t *restrict);
typedef int (*socket_func_t)(int, int, int);
typedef int (*socketpair_func_t)(int, int, int, int[2]);
typedef int (*pipe_func_t)(int[2]);
typedef int (*dup_func_t)(int);
typedef int (*dup2_func_t)(int, int);
typedef ssize_t (*sendto_func_t)(int, const void *, size_t, int, const struct sockaddr *, socklen_t);
typedef ssize_t (*send_func_t)(int, const void *, size_t, int);
typedef ssize_t (*sendmsg_func_t)(int, const struct msghdr *, int);
typedef ssize_t (*recv_func_t)(int, void *, size_t, int);
typedef ssize_t (*recvfrom_func_t)(int, void *restrict, size_t, int, struct sockaddr *restrict, socklen_t *restrict);
typedef ssize_t (*recvmsg_func_t)(int, struct msghdr *, int);
typedef int (*execve_func_t)(const char *, char *const[], char *const[]);
typedef int (*posix_spawn_func_t)(pid_t *restrict, const char *restrict, const posix_spawn_file_actions_t *, const posix_spawnattr_t *restrict, char *const[restrict], char *const[restrict]);
typedef pid_t (*fork_func_t)(void);
typedef int (*kill_func_t)(pid_t, int);
typedef int (*getaddrinfo_func_t)(const char *restrict, const char *restrict, const struct addrinfo *restrict, struct addrinfo **restrict);
typedef int (*getsockname_func_t)(int, struct sockaddr *restrict, socklen_t *restrict);
typedef int (*getpeername_func_t)(int, struct sockaddr *restrict, socklen_t *restrict);

static open_func_t real_open = NULL; static openat_func_t real_openat = NULL;
static connect_func_t real_connect = NULL; static bind_func_t real_bind = NULL;
static listen_func_t real_listen = NULL; static accept_func_t real_accept = NULL;
static socket_func_t real_socket = NULL; static socketpair_func_t real_socketpair = NULL;
static pipe_func_t real_pipe = NULL; static dup_func_t real_dup = NULL;
static dup2_func_t real_dup2 = NULL; static sendto_func_t real_sendto = NULL;
static send_func_t real_send = NULL; static sendmsg_func_t real_sendmsg = NULL;
static recv_func_t real_recv = NULL; static recvfrom_func_t real_recvfrom = NULL;
static recvmsg_func_t real_recvmsg = NULL; static execve_func_t real_execve = NULL;
static posix_spawn_func_t real_posix_spawn = NULL; static posix_spawn_func_t real_posix_spawnp = NULL;
static fork_func_t real_fork = NULL; static fork_func_t real_vfork = NULL;
static kill_func_t real_kill = NULL; static getaddrinfo_func_t real_getaddrinfo = NULL;
static getsockname_func_t real_getsockname = NULL; static getpeername_func_t real_getpeername = NULL;

/* --- SSL function pointers (from A-Zen stealable ideas #19-20) --- */
typedef void* (*ssl_new_t)(void*);
typedef int (*ssl_rw_t)(void*, void*, int);
typedef int (*ssl_write_t)(void*, const void*, int);
typedef void (*ssl_set_keylog_cb_t)(void*, void (*)(const void*, const char*));

static ssl_new_t real_SSL_new = NULL;
static ssl_rw_t real_SSL_read = NULL;
static ssl_write_t real_SSL_write = NULL;
static ssl_set_keylog_cb_t real_SSL_CTX_set_keylog_callback = NULL;
static void (*app_keylog_cb)(const void*, const char*) = NULL;

/* --- Apple Security.framework TLS (R27: covers Claude Code + native Mach-O) --- */
#ifdef __APPLE__
typedef int32_t OSStatus;
typedef const void *SSLContextRef;
typedef const void *SSLConnectionRef;
typedef OSStatus (*mac_ssl_read_t)(SSLContextRef, void*, size_t, size_t*);
typedef OSStatus (*mac_ssl_write_t)(SSLContextRef, const void*, size_t, size_t*);
typedef OSStatus (*mac_ssl_get_conn_t)(SSLContextRef, SSLConnectionRef*);
static mac_ssl_read_t real_SSLRead = NULL;
static mac_ssl_write_t real_SSLWrite = NULL;
static mac_ssl_get_conn_t real_SSLGetConnection = NULL;
#endif

#ifdef __linux__
typedef ssize_t (*write_func_t)(int, const void *, size_t);
typedef int (*close_func_t)(int);
typedef int (*open64_func_t)(const char *, int, ...);
typedef int (*openat64_func_t)(int, const char *, int, ...);
static write_func_t real_write = NULL; static close_func_t real_close = NULL;
static open64_func_t real_open64 = NULL; static openat64_func_t real_openat64 = NULL;
#endif

#define RESOLVE(name) if (!real_##name) { real_##name = (typeof(real_##name))dlsym(RTLD_NEXT, #name); }
/* R27: RTLD_DEFAULT fallback for SSL symbols — finds BoringSSL exported
 * for native addons when RTLD_NEXT skips the main executable. */
#define RESOLVE_SSL(name) if (!real_##name) { \
    real_##name = (typeof(real_##name))dlsym(RTLD_NEXT, #name); \
    if (!real_##name) real_##name = (typeof(real_##name))dlsym(RTLD_DEFAULT, #name); \
}

#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };
#define HOOK_NAME(name) clawsig_##name
#define CALL_REAL(name, ...) name(__VA_ARGS__)
#define REAL_FUNC(name) name
#else
#define HOOK_NAME(name) name
#define CALL_REAL(name, ...) real_##name(__VA_ARGS__)
#define REAL_FUNC(name) real_##name
#endif

/* --- macOS weak_import for SSL symbols (from A-Zen stealable idea #19) --- */
#ifdef __APPLE__
extern void* SSL_new(void*) __attribute__((weak_import));
extern int SSL_read(void*, void*, int) __attribute__((weak_import));
extern int SSL_write(void*, const void*, int) __attribute__((weak_import));
extern void SSL_CTX_set_keylog_callback(void*, void (*)(const void*, const char*)) __attribute__((weak_import));
/* R27: Apple SecureTransport — dynamically linked even when BoringSSL is static */
extern OSStatus SSLRead(SSLContextRef, void*, size_t, size_t*) __attribute__((weak_import));
extern OSStatus SSLWrite(SSLContextRef, const void*, size_t, size_t*) __attribute__((weak_import));
extern OSStatus SSLGetConnection(SSLContextRef, SSLConnectionRef*) __attribute__((weak_import));
#endif

/* ================================================================== */
/*       Incremental SHA-256 (env auditing + Merkle chain)            */
/*       Ported from E-Synthesis: proper init/update/final API        */
/* ================================================================== */

#define ROTR(a,b) (((a)>>(b))|((a)<<(32-(b))))
#define CH(x,y,z) (((x)&(y))^((~(x))&(z)))
#define MAJ(x,y,z) (((x)&(y))^((x)&(z))^((y)&(z)))
#define EP0(x) (ROTR(x,2)^ROTR(x,13)^ROTR(x,22))
#define EP1(x) (ROTR(x,6)^ROTR(x,11)^ROTR(x,25))
#define SIG0(x) (ROTR(x,7)^ROTR(x,18)^((x)>>3))
#define SIG1(x) (ROTR(x,17)^ROTR(x,19)^((x)>>10))

static const uint32_t sha256_k[64] = {
    0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,
    0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,
    0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,
    0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,
    0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,
    0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,
    0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,
    0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2
};

static void sha256_transform(uint32_t state[8], const uint8_t data[64]) {
    uint32_t a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];
    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = ((uint32_t)data[j] << 24) | ((uint32_t)data[j+1] << 16) |
               ((uint32_t)data[j+2] << 8) | (uint32_t)data[j+3];
    for (; i < 64; ++i) m[i] = SIG1(m[i-2]) + m[i-7] + SIG0(m[i-15]) + m[i-16];
    a=state[0]; b=state[1]; c=state[2]; d=state[3]; e=state[4]; f=state[5]; g=state[6]; h=state[7];
    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e,f,g) + sha256_k[i] + m[i];
        t2 = EP0(a) + MAJ(a,b,c);
        h=g; g=f; f=e; e=d+t1; d=c; c=b; b=a; a=t1+t2;
    }
    state[0]+=a; state[1]+=b; state[2]+=c; state[3]+=d; state[4]+=e; state[5]+=f; state[6]+=g; state[7]+=h;
}

/* sha256_ctx_t forward-declared above (DFA section). Implementations follow. */

static void sha256_init(sha256_ctx_t *ctx) {
    ctx->state[0] = 0x6a09e667; ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372; ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f; ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab; ctx->state[7] = 0x5be0cd19;
    ctx->count[0] = ctx->count[1] = 0;
}

static void sha256_update(sha256_ctx_t *ctx, const uint8_t *data, size_t len) {
    size_t i = 0;
    uint32_t j = (ctx->count[0] >> 3) & 63;
    if ((ctx->count[0] += (uint32_t)(len << 3)) < (len << 3)) ctx->count[1]++;
    ctx->count[1] += (uint32_t)(len >> 29);
    if ((j + len) > 63) {
        memcpy(&ctx->buffer[j], data, (i = 64 - j));
        sha256_transform(ctx->state, ctx->buffer);
        for (; i + 63 < len; i += 64) sha256_transform(ctx->state, &data[i]);
        j = 0;
    }
    memcpy(&ctx->buffer[j], &data[i], len - i);
}

static void sha256_final(sha256_ctx_t *ctx, uint8_t hash[32]) {
    uint8_t finalcount[8];
    for (int i = 0; i < 8; i++)
        finalcount[i] = (uint8_t)((ctx->count[(i >= 4 ? 0 : 1)] >> ((3 - (i & 3)) * 8)) & 255);
    uint8_t c = 0x80; sha256_update(ctx, &c, 1);
    while ((ctx->count[0] & 504) != 448) { c = 0x00; sha256_update(ctx, &c, 1); }
    sha256_update(ctx, finalcount, 8);
    for (int i = 0; i < 32; i++)
        hash[i] = (uint8_t)((ctx->state[i >> 2] >> (((3 - i) & 3) * 8)) & 255);
}

static void sha256_hash_string(const char *str, char out_hex[65]) {
    sha256_ctx_t ctx; sha256_init(&ctx);
    sha256_update(&ctx, (const uint8_t*)str, strlen(str));
    uint8_t hash[32]; sha256_final(&ctx, hash);
    for (int i = 0; i < 32; i++) snprintf(&out_hex[i * 2], 3, "%02x", hash[i]);
    out_hex[64] = '\0';
}

/** Global Merkle chain context — feeds event bytes incrementally. */
static sha256_ctx_t global_merkle_ctx;

/* ================================================================== */
/*                        Unified Event Emitter                       */
/* ================================================================== */

static void write_trace(const char *buf, size_t len) {
    if (trace_fd < 0) return;
#ifdef __linux__
    if (real_write) { real_write(trace_fd, buf, len); return; }
#endif
    write(trace_fd, buf, len);
}

static void emit_log_event(const char *syscall_name, int pid, int rc, const char *fmt, ...) {
    if (trace_fd < 0) return;
    char ts[64]; struct timeval tv; gettimeofday(&tv, NULL); struct tm *tm_info = gmtime(&tv.tv_sec);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
    snprintf(ts + strlen(ts), sizeof(ts) - strlen(ts), ".%06dZ", (int)tv.tv_usec);

    uint64_t ns = get_mono_ns(); uint64_t seq = next_seq();

    /* Causal DAG: capture cause_t (thread) and cause_f (fd) */
    uint64_t ct = tl_last_seq;
    int efd = tl_event_fd;
    uint64_t cf = (efd >= 0 && efd < MAX_TRACKED_FDS) ? fd_last_seq[efd] : 0;

    char buf[4096];
    int len = snprintf(buf, sizeof(buf),
        "{\"layer\":\"interpose\",\"seq\":%llu,\"ns\":%llu,\"ts\":\"%s\","
        "\"syscall\":\"%s\",\"pid\":%d,\"ct\":%llu,\"cf\":%llu",
        (unsigned long long)seq, (unsigned long long)ns, ts, syscall_name, pid,
        (unsigned long long)ct, (unsigned long long)cf);

    if (fmt && len > 0 && len < (int)sizeof(buf) - 64) {
        va_list args; va_start(args, fmt);
        len += vsnprintf(buf + len, sizeof(buf) - (size_t)len, fmt, args); va_end(args);
    }
    if (len > 0 && len < (int)sizeof(buf) - 100) {
        if (rc != -999) len += snprintf(buf + len, sizeof(buf) - (size_t)len, ",\"rc\":%d", rc);

        /* Merkle chain: feed event bytes (before chain_hash) into running context,
         * then embed the intermediate hash in the event itself.
         * This makes every single event independently verifiable. */
        merkle_acquire();
        sha256_update(&global_merkle_ctx, (const uint8_t*)buf, (size_t)len);
        merkle_count++;
        /* Snapshot the running hash without destroying the context */
        sha256_ctx_t snap = global_merkle_ctx;
        uint8_t intermediate[32];
        sha256_final(&snap, intermediate);
        for (int i = 0; i < 32; i++)
            snprintf(&current_merkle_hex[i * 2], 3, "%02x", intermediate[i]);
        int is_checkpoint = (merkle_count % 256 == 0);
        merkle_release();

        len += snprintf(buf + len, sizeof(buf) - (size_t)len,
            ",\"chain_hash\":\"%s\"}\n", current_merkle_hex);
        write_trace(buf, (size_t)len);

        /* Update causal DAG state */
        tl_last_seq = seq;
        if (efd >= 0 && efd < MAX_TRACKED_FDS) fd_last_seq[efd] = seq;
        tl_event_fd = -1;

        /* Emit checkpoint every 256 events (hashed into chain too) */
        if (is_checkpoint) {
            char ckpt[384];
            int ckpt_len = snprintf(ckpt, sizeof(ckpt),
                "{\"layer\":\"interpose\",\"syscall\":\"merkle_checkpoint\","
                "\"pid\":%d,\"count\":%llu,\"hash\":\"%s\"",
                pid, (unsigned long long)merkle_count, current_merkle_hex);

            merkle_acquire();
            sha256_update(&global_merkle_ctx, (const uint8_t*)ckpt, (size_t)ckpt_len);
            merkle_count++;
            sha256_ctx_t cp_snap = global_merkle_ctx;
            uint8_t cp_hash[32];
            sha256_final(&cp_snap, cp_hash);
            char cp_hex[65];
            for (int i = 0; i < 32; i++) snprintf(&cp_hex[i * 2], 3, "%02x", cp_hash[i]);
            memcpy(current_merkle_hex, cp_hex, 65);
            merkle_release();

            ckpt_len += snprintf(ckpt + ckpt_len, sizeof(ckpt) - (size_t)ckpt_len,
                ",\"chain_hash\":\"%s\"}\n", cp_hex);
            write_trace(ckpt, (size_t)ckpt_len);
        }
    }
}

/* ================================================================== */
/*                            Helpers                                 */
/* ================================================================== */

static void escape_json(const char *src, char *dest, size_t dest_len) {
    if (!src) { if (dest_len > 0) dest[0] = '\0'; return; }
    size_t i = 0, j = 0;
    while (src[i] && j < dest_len - 3) {
        switch (src[i]) {
            case '"':  dest[j++] = '\\'; dest[j++] = '"'; break; case '\\': dest[j++] = '\\'; dest[j++] = '\\'; break;
            case '\n': dest[j++] = '\\'; dest[j++] = 'n'; break; case '\r': dest[j++] = '\\'; dest[j++] = 'r'; break;
            case '\t': dest[j++] = '\\'; dest[j++] = 't'; break; default: if ((unsigned char)src[i] >= 0x20) dest[j++] = src[i]; break;
        } i++;
    } dest[j] = '\0';
}

static void format_argv(char *const arr[], char *out, size_t out_len) {
    if (!arr) { strncpy(out, "[]", out_len); return; }
    size_t j = 0; out[j++] = '[';
    for (int i = 0; arr[i] && j < out_len - 5; i++) {
        if (i > 0) out[j++] = ','; out[j++] = '"';
        char esc[512]; escape_json(arr[i], esc, sizeof(esc));
        size_t len = strlen(esc); if (j + len < out_len - 3) { strncpy(out + j, esc, len); j += len; } out[j++] = '"';
    } out[j++] = ']'; out[j] = '\0';
}

static void format_addr(const struct sockaddr *addr, char *ip, size_t ip_len, int *port, const char **family) {
    *port = 0; *family = "UNKNOWN"; ip[0] = '\0'; if (!addr) return;
    if (addr->sa_family == AF_INET) {
        inet_ntop(AF_INET, &((struct sockaddr_in *)addr)->sin_addr, ip, (socklen_t)ip_len);
        *port = ntohs(((struct sockaddr_in *)addr)->sin_port); *family = "AF_INET";
    } else if (addr->sa_family == AF_INET6) {
        inet_ntop(AF_INET6, &((struct sockaddr_in6 *)addr)->sin6_addr, ip, (socklen_t)ip_len);
        *port = ntohs(((struct sockaddr_in6 *)addr)->sin6_port); *family = "AF_INET6";
    } else if (addr->sa_family == AF_UNIX) {
        struct sockaddr_un *s = (struct sockaddr_un *)addr; *family = "AF_UNIX";
        if (s->sun_path[0]) { strncpy(ip, s->sun_path, ip_len - 1); ip[ip_len - 1] = '\0'; } else strncpy(ip, "unnamed_socket", ip_len);
    }
}

static const char* get_access_mode(int flags) {
    int mode = flags & O_ACCMODE; if (mode == O_RDONLY) return "O_RDONLY"; if (mode == O_WRONLY) return "O_WRONLY"; if (mode == O_RDWR) return "O_RDWR"; return "UNKNOWN";
}

static int is_write_access(int flags) {
    int mode = flags & O_ACCMODE;
    if (mode == O_WRONLY || mode == O_RDWR) return 1;
    if (flags & (O_CREAT | O_APPEND | O_TRUNC)) return 1;
    return 0;
}

/* ================================================================== */
/*                    Harness & Role Identification                   */
/* ================================================================== */

typedef struct {
    const char *harness;
    const char *role;
} proc_ident_t;

static proc_ident_t identify_process(const char *path, char *const argv[], char *const envp[]) {
    proc_ident_t id = {NULL, "unknown"};

    /* 1. Environment variable scanning for framework markers */
    if (envp) {
        for (int i = 0; envp[i]; i++) {
            if (strncmp(envp[i], "OPENCLAW_", 9) == 0) id.harness = "openclaw";
            else if (strncmp(envp[i], "AIDER_", 6) == 0) id.harness = "aider";
            else if (strncmp(envp[i], "CREWAI_", 7) == 0) id.harness = "crewai";
            else if (strncmp(envp[i], "AUTOGEN_", 8) == 0) id.harness = "autogen";
            else if (strncmp(envp[i], "LANGCHAIN_", 10) == 0) id.harness = "langchain";
        }
    }

    /* 2. Binary name classification */
    const char *base = path ? strrchr(path, '/') : NULL;
    base = base ? base + 1 : path;

    if (base) {
        if (strcmp(base, "bash") == 0 || strcmp(base, "sh") == 0 || strcmp(base, "zsh") == 0 ||
            strcmp(base, "dash") == 0 || strcmp(base, "fish") == 0)
            id.role = "shell";
        else if (strcmp(base, "git") == 0 || strcmp(base, "curl") == 0 || strcmp(base, "node") == 0 ||
                 strcmp(base, "python") == 0 || strcmp(base, "python3") == 0 || strcmp(base, "bun") == 0 ||
                 strcmp(base, "npm") == 0 || strcmp(base, "npx") == 0 || strcmp(base, "pip") == 0 ||
                 strcmp(base, "cat") == 0 || strcmp(base, "grep") == 0 || strcmp(base, "sed") == 0 ||
                 strcmp(base, "awk") == 0 || strcmp(base, "find") == 0 || strcmp(base, "ls") == 0 ||
                 strcmp(base, "mkdir") == 0 || strcmp(base, "rm") == 0 || strcmp(base, "cp") == 0 ||
                 strcmp(base, "mv") == 0 || strcmp(base, "chmod") == 0 || strcmp(base, "chown") == 0 ||
                 strcmp(base, "head") == 0 || strcmp(base, "tail") == 0 || strcmp(base, "wc") == 0 ||
                 strcmp(base, "sort") == 0 || strcmp(base, "uniq") == 0 || strcmp(base, "tr") == 0 ||
                 strcmp(base, "tee") == 0 || strcmp(base, "xargs") == 0 || strcmp(base, "env") == 0 ||
                 strcmp(base, "which") == 0 || strcmp(base, "whoami") == 0 || strcmp(base, "uname") == 0)
            id.role = "utility";
        else if (strstr(base, "chrome") || strstr(base, "chromium") || strstr(base, "firefox") ||
                 strstr(base, "safari") || strstr(base, "brave"))
            id.role = "browser";
        else if (strcmp(base, "pi") == 0) id.harness = "pi";
        else if (strcmp(base, "claude") == 0) id.harness = "claude_code";
        else if (strcmp(base, "codex") == 0) id.harness = "codex";
        else if (strcmp(base, "gemini") == 0) id.harness = "gemini_cli";
        else if (strcmp(base, "openclaw") == 0) id.harness = "openclaw";
        else if (strcmp(base, "aider") == 0) id.harness = "aider";
        else if (strcmp(base, "cline") == 0) id.harness = "cline";
        else if (strcmp(base, "cursor") == 0) id.harness = "cursor";
        else if (strcmp(base, "opencode") == 0) id.harness = "opencode";
        else if (strcmp(base, "devin") == 0) id.harness = "devin";
        else if (strcmp(base, "goose") == 0) id.harness = "goose";
        else if (strcmp(base, "sweep") == 0) id.harness = "sweep";
    }

    /* 3. argv scanning for MCP servers and harness packages */
    if (argv) {
        for (int i = 0; argv[i] && i < 15; i++) {
            if (strstr(argv[i], "@modelcontextprotocol/") || strstr(argv[i], "mcp-server") ||
                strstr(argv[i], "mcp_server")) {
                id.role = "mcp_server";
                if (strstr(argv[i], "browser-tools") || strstr(argv[i], "puppeteer") || strstr(argv[i], "playwright"))
                    id.harness = "mcp_browser";
                else if (strstr(argv[i], "git")) id.harness = "mcp_git";
                else if (strstr(argv[i], "filesystem")) id.harness = "mcp_filesystem";
                else if (strstr(argv[i], "sqlite")) id.harness = "mcp_sqlite";
                else if (strstr(argv[i], "postgres")) id.harness = "mcp_postgres";
                else if (!id.harness) id.harness = "mcp_custom";
            }
            if (!id.harness) {
                if (strstr(argv[i], "pi-coding-agent")) id.harness = "pi";
                else if (strstr(argv[i], "claude-code") || strstr(argv[i], "@anthropic/claude-code"))
                    id.harness = "claude_code";
                else if (strstr(argv[i], "openclaw")) id.harness = "openclaw";
                else if (strstr(argv[i], "litellm")) id.harness = "aider";
                else if (strstr(argv[i], "swe_agent") || strstr(argv[i], "swe-agent"))
                    id.harness = "swe_agent";
                else if (strstr(argv[i], "openhands") || strstr(argv[i], "opendevin"))
                    id.harness = "openhands";
            }
        }
        if (base && strcmp(base, "gh") == 0 && argv[1] && strcmp(argv[1], "copilot") == 0)
            id.harness = "copilot_cli";
    }

    /* 4. Path-based fallback detection */
    if (!id.harness && path) {
        if (strstr(path, "pi-coding-agent")) id.harness = "pi";
        else if (strstr(path, "claude-code") || strstr(path, "@anthropic/claude")) id.harness = "claude_code";
        else if (strstr(path, "swe-agent") || strstr(path, "swe_agent")) id.harness = "swe_agent";
        else if (strstr(path, "openhands") || strstr(path, "opendevin")) id.harness = "openhands";
        else if (strstr(path, "copilot-cli") || strstr(path, "github-copilot")) id.harness = "copilot_cli";
        else if (strstr(path, "crewai")) id.harness = "crewai";
        else if (strstr(path, "autogen")) id.harness = "autogen";
        else if (strstr(path, "langchain")) id.harness = "langchain";
    }

    /* 5. Infer role from harness */
    if (id.harness && strcmp(id.role, "unknown") == 0) {
        if (strncmp(id.harness, "mcp_", 4) == 0) id.role = "mcp_server";
        else id.role = "agent";
    }

    return id;
}

/* ================================================================== */
/*              Environment Auditing & Credential DLP                 */
/* ================================================================== */

static void audit_env(char *const envp[]) {
    if (!envp) return;
    for (int i = 0; envp[i]; i++) {
        if (strstr(envp[i], "API_KEY") || strstr(envp[i], "SECRET") ||
            strstr(envp[i], "TOKEN") || strstr(envp[i], "PASSWORD")) {
            char *eq = strchr(envp[i], '=');
            if (eq && *(eq + 1)) {
                int klen = (int)(eq - envp[i]); if (klen > 127) klen = 127;
                char key[128]; strncpy(key, envp[i], (size_t)klen); key[klen] = '\0';
                char hash[65]; sha256_hash_string(eq + 1, hash);
                emit_log_event("env_audit", getpid(), -999,
                    ",\"key\":\"%s\",\"value_sha256\":\"%s\"", key, hash);
            }
        }
    }
}

static void scan_credentials(int fd, const void *buf, size_t len) {
    if (!buf || len < 15) return;
    const unsigned char *p = (const unsigned char *)buf;
    size_t scan_len = len > 1024 ? 1024 : len;
    for (size_t i = 0; i <= scan_len - 10; i++) {
        if (p[i] == 'B' && i + 10 <= scan_len && memcmp(p + i, "Bearer sk-", 10) == 0) {
            tl_event_fd = fd;
            emit_log_event("cred_leak", getpid(), -999,
                ",\"fd\":%d,\"pattern\":\"Bearer sk-*\"", fd); return;
        }
        if (p[i] == 'x' && i + 10 <= scan_len && memcmp(p + i, "x-api-key:", 10) == 0) {
            tl_event_fd = fd;
            emit_log_event("cred_leak", getpid(), -999,
                ",\"fd\":%d,\"pattern\":\"x-api-key:*\"", fd); return;
        }
    }
}

/* ================================================================== */
/*                    DNS & TLS SNI Tracking                          */
/* ================================================================== */

static unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381; int c;
    while ((c = *ip++)) hash = ((hash << 5) + hash) + (unsigned int)c;
    return hash;
}

static void cache_dns(const char *ip, const char *hostname) {
    if (!ip || !hostname) return;
    int slot = (int)(hash_ip(ip) & (MAX_DNS_CACHE - 1));
    dns_cache[slot].in_use = 0; __sync_synchronize();
    strncpy(dns_cache[slot].ip, ip, INET6_ADDRSTRLEN - 1); dns_cache[slot].ip[INET6_ADDRSTRLEN - 1] = '\0';
    strncpy(dns_cache[slot].hostname, hostname, 255); dns_cache[slot].hostname[255] = '\0';
    __sync_synchronize(); dns_cache[slot].in_use = 1;
}

static int lookup_dns(const char *ip, char *hostname_out) {
    if (!ip) return 0;
    int slot = (int)(hash_ip(ip) & (MAX_DNS_CACHE - 1));
    if (dns_cache[slot].in_use && strcmp(dns_cache[slot].ip, ip) == 0) {
        strncpy(hostname_out, dns_cache[slot].hostname, 256); return 1;
    }
    return 0;
}

static void track_fd(int fd, const char *ip, int port) {
    if (fd < 0 || port != 443) return;
    int slot = fd & (MAX_TRACKED_FDS - 1);
    tracked_fds[slot].fd = -1; __sync_synchronize();
    strncpy(tracked_fds[slot].ip, ip, INET6_ADDRSTRLEN - 1);
    tracked_fds[slot].ip[INET6_ADDRSTRLEN - 1] = '\0';
    tracked_fds[slot].port = port; __sync_synchronize();
    tracked_fds[slot].fd = fd;
}

/** Destructive claim: atomically read and clear the tracked fd entry (for SNI parsing). */
static int claim_fd(int fd, char *ip_out, int *port_out) {
    if (fd < 0) return 0;
    int slot = fd & (MAX_TRACKED_FDS - 1);
    if (tracked_fds[slot].fd == fd) {
        if (__sync_bool_compare_and_swap(&tracked_fds[slot].fd, fd, -1)) {
            if (ip_out) strncpy(ip_out, tracked_fds[slot].ip, INET6_ADDRSTRLEN);
            if (port_out) *port_out = tracked_fds[slot].port;
            return 1;
        }
    }
    return 0;
}

/** Non-destructive peek: read tracked fd info without clearing (for SSL hooks). */
static int peek_fd(int fd, char *ip_out, int *port_out) {
    if (fd < 0) return 0;
    int slot = fd & (MAX_TRACKED_FDS - 1);
    if (tracked_fds[slot].fd == fd) {
        if (ip_out) strncpy(ip_out, tracked_fds[slot].ip, INET6_ADDRSTRLEN);
        if (port_out) *port_out = tracked_fds[slot].port;
        return 1;
    }
    return 0;
}

static void untrack_fd(int fd) {
    claim_fd(fd, NULL, NULL);
    if (fd >= 0 && fd < MAX_TRACKED_FDS) {
        if (is_llm_fd(fd) || is_h2_fd(fd)) emit_timing_fingerprint(fd);
        if (is_h2_fd(fd)) {
            h2_flush(fd);
        } else if (is_llm_fd(fd)) {
            fsm_flush(fd);
        }
    }
    clear_llm_fd(fd);
    clear_ssl_fd(fd);
    clear_h2_fd(fd);
}

static void check_tls_sni(int fd, const void *buf, size_t count) {
    if (fd < 0 || !buf || count < 5) return;
    const unsigned char *b = (const unsigned char *)buf;
    /* R27: Mark TLS-carrying FDs early to prevent ciphertext from poisoning
     * the plaintext HTTP FSM. Detects any TLS record (0x14-0x17, 0x03). */
    if (b[0] >= 0x14 && b[0] <= 0x17 && b[1] == 0x03) set_ssl_fd(fd);
    if (count < 47) return;
    int slot = fd & (MAX_TRACKED_FDS - 1);
    if (tracked_fds[slot].fd != fd) return;

    char ip[INET6_ADDRSTRLEN]; int port;
    if (!claim_fd(fd, ip, &port)) return;
    if (b[0] != 0x16 || b[1] != 0x03 || b[5] != 0x01) return;

    size_t pos = 43; if (pos >= count) return;
    pos += 1 + b[pos]; if (pos + 2 > count) return;
    pos += 2 + ((size_t)(b[pos] << 8) | b[pos+1]); if (pos + 1 > count) return;
    pos += 1 + b[pos]; if (pos + 2 > count) return;
    size_t ext_end = pos + 2 + ((size_t)(b[pos] << 8) | b[pos+1]);
    pos += 2; if (ext_end > count) ext_end = count;

    while (pos + 4 <= ext_end) {
        int ext_type = (b[pos] << 8) | b[pos+1];
        size_t ext_len = ((size_t)b[pos+2] << 8) | b[pos+3]; pos += 4;
        if (pos + ext_len > ext_end) break;
        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t name_len = ((size_t)b[pos+3] << 8) | b[pos+4];
            if (pos + 5 + name_len <= count && name_len < 256) {
                char sni[256]; memcpy(sni, b + pos + 5, name_len); sni[name_len] = '\0';
                char sni_esc[512]; escape_json(sni, sni_esc, sizeof(sni_esc));
                tl_event_fd = fd;
                emit_log_event("tls_sni", getpid(), -999,
                    ",\"fd\":%d,\"hostname\":\"%s\",\"addr\":\"%s\",\"port\":%d",
                    fd, sni_esc, ip, port);
                return;
            }
        }
        pos += ext_len;
    }
}

/* ================================================================== */
/*                SSLKEYLOGFILE Env Injection Helper                  */
/* ================================================================== */

/**
 * Build a hardened envp: inject SSLKEYLOGFILE, NODE_OPTIONS, and re-inject
 * CLAWSIG_TRACE_FILE + DYLD_INSERT_LIBRARIES/LD_PRELOAD even if the agent
 * stripped them. From B-Debate (SSLKEYLOG) + F-RedTeam (anti-stripping).
 *
 * Anti-stripping is critical: without it, a hostile agent can escape monitoring
 * by calling execve() with a clean envp that omits DYLD_INSERT_LIBRARIES.
 *
 * R25: Also injects CLAWSIG_PARENT_CHAIN for cross-process receipt correlation.
 */
#define MAX_INJECT_ENV 4096

static int build_injected_env(char *const envp[], char **out_envp,
    char *ssl_buf, size_t ssl_buf_sz, char *node_buf, size_t node_buf_sz,
    char *chain_buf) {
    if (!envp) return 0;
    if (!sslkeylog_path[0] && !saved_trace_env[0] && !saved_preload_env[0]
        && (!chain_buf || !chain_buf[0])) return 0;

    if (sslkeylog_path[0])
        snprintf(ssl_buf, ssl_buf_sz, "SSLKEYLOGFILE=%s", sslkeylog_path);

    int j = 0, has_ssl = 0, has_node = 0, has_trace = 0, has_preload = 0, has_chain = 0;
    for (int i = 0; envp[i] && j < MAX_INJECT_ENV - 6; i++) {
        if (sslkeylog_path[0] && strncmp(envp[i], "SSLKEYLOGFILE=", 14) == 0) {
            has_ssl = 1; out_envp[j++] = ssl_buf;
        } else if (sslkeylog_path[0] && strncmp(envp[i], "NODE_OPTIONS=", 13) == 0) {
            snprintf(node_buf, node_buf_sz, "%s --tls-keylog=%s", envp[i], sslkeylog_path);
            has_node = 1; out_envp[j++] = node_buf;
        } else if (saved_trace_env[0] && strncmp(envp[i], "CLAWSIG_TRACE_FILE=", 19) == 0) {
            has_trace = 1; out_envp[j++] = saved_trace_env;
#ifdef __linux__
        } else if (saved_preload_env[0] && strncmp(envp[i], "LD_PRELOAD=", 11) == 0) {
            has_preload = 1; out_envp[j++] = saved_preload_env;
#else
        } else if (saved_preload_env[0] && strncmp(envp[i], "DYLD_INSERT_LIBRARIES=", 22) == 0) {
            has_preload = 1; out_envp[j++] = saved_preload_env;
#endif
        } else if (chain_buf && chain_buf[0] && strncmp(envp[i], "CLAWSIG_PARENT_CHAIN=", 21) == 0) {
            has_chain = 1; out_envp[j++] = chain_buf;
        } else {
            out_envp[j++] = envp[i];
        }
    }
    /* Re-inject any that were stripped */
    if (sslkeylog_path[0] && !has_ssl && j < MAX_INJECT_ENV - 5)
        out_envp[j++] = ssl_buf;
    if (sslkeylog_path[0] && !has_node && j < MAX_INJECT_ENV - 4) {
        snprintf(node_buf, node_buf_sz, "NODE_OPTIONS=--tls-keylog=%s", sslkeylog_path);
        out_envp[j++] = node_buf;
    }
    if (saved_trace_env[0] && !has_trace && j < MAX_INJECT_ENV - 3)
        out_envp[j++] = saved_trace_env;
    if (saved_preload_env[0] && !has_preload && j < MAX_INJECT_ENV - 2)
        out_envp[j++] = saved_preload_env;
    if (chain_buf && chain_buf[0] && !has_chain && j < MAX_INJECT_ENV - 1)
        out_envp[j++] = chain_buf;
    out_envp[j] = NULL;
    return j;
}

/* ================================================================== */
/*                     THE HOOKS — TLS / OpenSSL                      */
/* ================================================================== */

static int get_ssl_fd(const void *ssl) {
    static int (*fn)(const void *) = NULL;
    if (!fn) fn = (int (*)(const void *))dlsym(RTLD_DEFAULT, "SSL_get_fd");
    return fn ? fn(ssl) : -1;
}

/**
 * Parse HTTP/1.1 content from SSL plaintext (from A-Zen stealable idea #20).
 * Detects requests (POST/GET/PUT), responses (HTTP/1.), SSE streams, raw JSON.
 * Only fires for LLM FDs to avoid noise.
 */
static void parse_http(int fd, const char *dir, const char *buf, int num) {
    if (num < 4 || !is_llm_fd(fd)) return;
    int is_req = !memcmp(buf, "POST", 4) || !memcmp(buf, "GET ", 4) || !memcmp(buf, "PUT ", 4);
    int is_res = num >= 8 && !memcmp(buf, "HTTP/1.", 7);
    if (!is_req && !is_res && (num < 6 || memcmp(buf, "data: ", 6) != 0) && buf[0] != '{' && buf[0] != '[') return;
    const char *body = buf; int blen = num;
    if (is_req || is_res) {
        blen = 0;
        for (int i = 0; i < num - 3; i++) if (buf[i] == '\r' && buf[i+1] == '\n' && buf[i+2] == '\r' && buf[i+3] == '\n') {
            body = buf + i + 4; blen = num - i - 4; break;
        }
    }
    if (blen > 0) {
        int to_esc = blen > 1024 ? 1024 : blen; char temp[1025], esc[2050];
        memcpy(temp, body, to_esc); temp[to_esc] = '\0'; escape_json(temp, esc, sizeof(esc));
        tl_event_fd = fd;
        emit_log_event(dir, getpid(), -999, ",\"fd\":%d,\"body\":\"%s\"", fd, esc);
    }
}

/**
 * Our keylog callback — chains the application's original callback.
 * From A-Zen stealable idea #19: captures TLS pre-master secrets.
 */
static void clawsig_keylog_cb(const void *ssl, const char *line) {
    if (in_hook || trace_fd < 0) return;
    in_hook = 1;
    int fd = get_ssl_fd(ssl);
    char host[256] = "", ip[INET6_ADDRSTRLEN] = "";
    if (peek_fd(fd, ip, NULL)) lookup_dns(ip, host);
    char esc_h[512], esc_l[512];
    escape_json(host, esc_h, sizeof(esc_h));
    escape_json(line, esc_l, sizeof(esc_l));
    tl_event_fd = fd;
    emit_log_event("tls_keylog", getpid(), -999,
        ",\"fd\":%d,\"hostname\":\"%s\",\"secret\":\"%s\"", fd, esc_h, esc_l);
    in_hook = 0;
    if (app_keylog_cb) app_keylog_cb(ssl, line);
}

void HOOK_NAME(SSL_CTX_set_keylog_callback)(void *ctx, void (*cb)(const void*, const char*)) {
    RESOLVE_SSL(SSL_CTX_set_keylog_callback);
    app_keylog_cb = cb;
    if (REAL_FUNC(SSL_CTX_set_keylog_callback))
        CALL_REAL(SSL_CTX_set_keylog_callback, ctx, clawsig_keylog_cb);
}

void* HOOK_NAME(SSL_new)(void *ctx) {
    RESOLVE_SSL(SSL_new);
    if (!REAL_FUNC(SSL_new)) return NULL;
    /* Inject our keylog callback on first SSL_new if app hasn't set one */
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1;
        RESOLVE_SSL(SSL_CTX_set_keylog_callback);
        if (REAL_FUNC(SSL_CTX_set_keylog_callback) && !app_keylog_cb)
            CALL_REAL(SSL_CTX_set_keylog_callback, ctx, clawsig_keylog_cb);
        in_hook = 0;
    }
    return CALL_REAL(SSL_new, ctx);
}

int HOOK_NAME(SSL_write)(void *ssl, const void *buf, int num) {
    RESOLVE_SSL(SSL_write);
    if (!REAL_FUNC(SSL_write)) return -1;
    if (!in_hook && trace_fd >= 0 && buf && num > 0) {
        in_hook = 1;
        int fd = get_ssl_fd(ssl);
        if (fd >= 0) set_ssl_fd(fd);

        /* H2 preface detection + h2_init_conn (K #72) */
        if (fd >= 0 && !is_h2_fd(fd) && num >= 24 &&
            !memcmp(buf, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)) {
            set_h2_fd(fd);
            h2_init_conn(fd);
        }

        /* Route to H2 parser (not gated behind is_llm_fd — K #75:
         * path-based detection sets llm_fd after HEADERS decode) */
        if (fd >= 0 && is_h2_fd(fd)) {
            h2_feed(fd, (const uint8_t *)buf, (size_t)num, 1);
            if (tl_causal_read_seq > 0) {
                tl_event_fd = fd;
                emit_log_event("https_write_causal", getpid(), num,
                    ",\"fd\":%d,\"causal_fd\":%d,\"causal_seq\":%llu",
                    fd, tl_causal_read_fd, (unsigned long long)tl_causal_read_seq);
            }
        } else if (fd >= 0 && is_llm_fd(fd)) {
            timing_start_req(fd);
            if (fd < MAX_TRACKED_FDS) {
                fsm_lock(fd);
                fsm_feed(fd, (const uint8_t *)buf, (size_t)num, 1);
                fsm_unlock(fd);
            }
            if (tl_causal_read_seq > 0) {
                tl_event_fd = fd;
                emit_log_event("https_write_causal", getpid(), num,
                    ",\"fd\":%d,\"causal_fd\":%d,\"causal_seq\":%llu",
                    fd, tl_causal_read_fd, (unsigned long long)tl_causal_read_seq);
            }
        }
        if (!is_h2_fd(fd)) parse_http(fd, "https_request", buf, num); /* M #78 */
        in_hook = 0;
    }
    return CALL_REAL(SSL_write, ssl, buf, num);
}

int HOOK_NAME(SSL_read)(void *ssl, void *buf, int num) {
    RESOLVE_SSL(SSL_read);
    if (!REAL_FUNC(SSL_read)) return -1;
    int rc = CALL_REAL(SSL_read, ssl, buf, num);
    if (!in_hook && trace_fd >= 0 && rc > 0 && buf) {
        in_hook = 1;
        int fd = get_ssl_fd(ssl);
        if (fd >= 0) set_ssl_fd(fd);
        /* H2: route directly, not gated behind is_llm_fd (K #75) */
        if (fd >= 0 && is_h2_fd(fd)) {
            if (is_llm_fd(fd)) timing_add_token(fd, (size_t)rc);
            h2_feed(fd, (const uint8_t *)buf, (size_t)rc, 0);
        } else if (fd >= 0 && is_llm_fd(fd)) {
            timing_add_token(fd, (size_t)rc);
            if (fd < MAX_TRACKED_FDS) {
                fsm_lock(fd);
                fsm_feed(fd, (const uint8_t *)buf, (size_t)rc, 0);
                fsm_unlock(fd);
            }
        }
        if (!is_h2_fd(fd)) parse_http(fd, "https_response", buf, rc); /* M #78 */
        tl_causal_read_fd = fd;
        tl_causal_read_seq = global_seq - 1;
        in_hook = 0;
    }
    return rc;
}

/* ================================================================== */
/*         R27: Apple Security.framework TLS Hooks                   */
/* ================================================================== */
#ifdef __APPLE__
static int get_mac_ssl_fd(SSLContextRef ctx) {
    RESOLVE_SSL(SSLGetConnection);
    if (REAL_FUNC(SSLGetConnection)) {
        SSLConnectionRef conn = NULL;
        if (CALL_REAL(SSLGetConnection, ctx, &conn) == 0)
            return (int)(intptr_t)conn;
    }
    return -1;
}

OSStatus HOOK_NAME(SSLWrite)(SSLContextRef ctx, const void *data,
                             size_t dataLength, size_t *processed) {
    RESOLVE_SSL(SSLWrite);
    if (!REAL_FUNC(SSLWrite)) return -1;
    if (!in_hook && trace_fd >= 0 && data && dataLength > 0) {
        in_hook = 1;
        int fd = get_mac_ssl_fd(ctx);
        if (fd >= 0) {
            set_ssl_fd(fd);
            /* H2 preface detection */
            if (!is_h2_fd(fd) && dataLength >= 24 &&
                !memcmp(data, "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", 24)) {
                set_h2_fd(fd);
                h2_init_conn(fd);
            }
            if (is_h2_fd(fd)) {
                h2_feed(fd, (const uint8_t *)data, dataLength, 1);
                if (tl_causal_read_seq > 0) {
                    tl_event_fd = fd;
                    emit_log_event("https_write_causal", getpid(), (int)dataLength,
                        ",\"fd\":%d,\"causal_fd\":%d,\"causal_seq\":%llu",
                        fd, tl_causal_read_fd, (unsigned long long)tl_causal_read_seq);
                }
            } else {
                sniff_and_set_llm_fd(fd, data, dataLength);
                if (is_llm_fd(fd)) {
                    timing_start_req(fd);
                    if (fd < MAX_TRACKED_FDS) {
                        fsm_lock(fd);
                        fsm_feed(fd, (const uint8_t *)data, dataLength, 1);
                        fsm_unlock(fd);
                    }
                    if (tl_causal_read_seq > 0) {
                        tl_event_fd = fd;
                        emit_log_event("https_write_causal", getpid(), (int)dataLength,
                            ",\"fd\":%d,\"causal_fd\":%d,\"causal_seq\":%llu",
                            fd, tl_causal_read_fd, (unsigned long long)tl_causal_read_seq);
                    }
                }
                if (!is_h2_fd(fd)) parse_http(fd, "https_request", data, (int)dataLength);
            }
        }
        in_hook = 0;
    }
    return CALL_REAL(SSLWrite, ctx, data, dataLength, processed);
}

OSStatus HOOK_NAME(SSLRead)(SSLContextRef ctx, void *data,
                            size_t dataLength, size_t *processed) {
    RESOLVE_SSL(SSLRead);
    if (!REAL_FUNC(SSLRead)) return -1;
    OSStatus rc = CALL_REAL(SSLRead, ctx, data, dataLength, processed);
    /* errSecSuccess=0, errSSLWouldBlock=-9806: both can yield valid bytes */
    if (!in_hook && trace_fd >= 0 && processed && *processed > 0 && data) {
        in_hook = 1;
        int fd = get_mac_ssl_fd(ctx);
        if (fd >= 0) {
            set_ssl_fd(fd);
            size_t num = *processed;
            if (is_h2_fd(fd)) {
                if (is_llm_fd(fd)) timing_add_token(fd, num);
                h2_feed(fd, (const uint8_t *)data, num, 0);
            } else if (is_llm_fd(fd)) {
                timing_add_token(fd, num);
                if (fd < MAX_TRACKED_FDS) {
                    fsm_lock(fd);
                    fsm_feed(fd, (const uint8_t *)data, num, 0);
                    fsm_unlock(fd);
                }
            }
            if (!is_h2_fd(fd)) parse_http(fd, "https_response", data, (int)num);
            tl_causal_read_fd = fd;
            tl_causal_read_seq = global_seq - 1;
        }
        in_hook = 0;
    }
    return rc;
}
#endif

/* ================================================================== */
/*                    Constructor & Destructor                        */
/* ================================================================== */

__attribute__((constructor))
static void clawsig_init(void) {
    in_hook = 1;
    cached_pid = getpid();
    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        tracked_fds[i].fd = -1; fd_last_seq[i] = 0;
        http_fsm[i].state = HTTP_IDLE; http_fsm[i].lock = 0;
        http_fsm[i].method[0] = '\0';
    }
    for (int i = 0; i < 1024; i++) fd_to_h2[i] = -1;
    for (int i = 0; i < MAX_H2_CONNS; i++) {
        h2_conns[i].fd = -1; h2_conns[i].lock = 0;
    }
    sha256_init(&global_merkle_ctx);
    memset(current_merkle_hex, '0', 64); current_merkle_hex[64] = '\0';

    RESOLVE(open); RESOLVE(openat); RESOLVE(connect); RESOLVE(bind);
    RESOLVE(listen); RESOLVE(accept); RESOLVE(socket); RESOLVE(socketpair);
    RESOLVE(pipe); RESOLVE(dup); RESOLVE(dup2); RESOLVE(sendto);
    RESOLVE(send); RESOLVE(sendmsg); RESOLVE(recv); RESOLVE(recvfrom);
    RESOLVE(recvmsg); RESOLVE(execve); RESOLVE(posix_spawn); RESOLVE(posix_spawnp);
    RESOLVE(fork); RESOLVE(vfork); RESOLVE(kill); RESOLVE(getaddrinfo);
    RESOLVE(getsockname); RESOLVE(getpeername);

    /* Resolve SSL functions — RESOLVE_SSL uses RTLD_DEFAULT fallback
     * to find BoringSSL symbols exported from the main executable. */
    RESOLVE_SSL(SSL_new); RESOLVE_SSL(SSL_read); RESOLVE_SSL(SSL_write);
    RESOLVE_SSL(SSL_CTX_set_keylog_callback);
#ifdef __APPLE__
    RESOLVE_SSL(SSLRead); RESOLVE_SSL(SSLWrite); RESOLVE_SSL(SSLGetConnection);
#endif

#ifdef __linux__
    RESOLVE(write); RESOLVE(close); RESOLVE(open64); RESOLVE(openat64);
#endif

    const char *trace_file = getenv("CLAWSIG_TRACE_FILE");
    if (trace_file && real_open) {
        trace_fd = real_open(trace_file, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);

        /* FD elevation: move trace_fd to 1023+ so agent can't accidentally
         * close or dup2 over it. From C-YOLO stealable idea #5.
         * Fallback to 255 if 1023 fails (from F-RedTeam). */
        if (trace_fd >= 0 && trace_fd < 1023) {
            int elevated = fcntl(trace_fd, F_DUPFD_CLOEXEC, 1023);
            if (elevated < 0) elevated = fcntl(trace_fd, F_DUPFD_CLOEXEC, 255);
            if (elevated >= 0) {
#ifdef __linux__
                if (real_close) real_close(trace_fd); else close(trace_fd);
#else
                close(trace_fd);
#endif
                trace_fd = elevated;
            }
        }

        /* Build SSLKEYLOGFILE path: <trace_file>.keys */
        snprintf(sslkeylog_path, sizeof(sslkeylog_path), "%s.keys", trace_file);

        /* R27: Inject TLS keylog into CURRENT process environment.
         * Constructor runs before main() — early enough for Node.js,
         * Go, Bun, Deno to pick up before their TLS stacks initialize. */
        setenv("SSLKEYLOGFILE", sslkeylog_path, 1);
        {
            const char *existing_node = getenv("NODE_OPTIONS");
            char node_inject[2048];
            if (existing_node && !strstr(existing_node, "--tls-keylog")) {
                snprintf(node_inject, sizeof(node_inject),
                    "%.1024s --tls-keylog=%s", existing_node, sslkeylog_path);
                setenv("NODE_OPTIONS", node_inject, 1);
            } else if (!existing_node) {
                snprintf(node_inject, sizeof(node_inject),
                    "--tls-keylog=%s", sslkeylog_path);
                setenv("NODE_OPTIONS", node_inject, 1);
            }
        }

        /* Anti-stripping: save env vars for re-injection in exec hooks.
         * From F-RedTeam: defeats sandbox escape via clean envp. */
        snprintf(saved_trace_env, sizeof(saved_trace_env),
            "CLAWSIG_TRACE_FILE=%s", trace_file);
#ifdef __linux__
        const char *preload = getenv("LD_PRELOAD");
        if (preload) snprintf(saved_preload_env, sizeof(saved_preload_env),
            "LD_PRELOAD=%s", preload);
#else
        const char *preload = getenv("DYLD_INSERT_LIBRARIES");
        if (preload) snprintf(saved_preload_env, sizeof(saved_preload_env),
            "DYLD_INSERT_LIBRARIES=%s", preload);
#endif

        char **argv = NULL; char **envp = NULL; const char *prog = "unknown";
#ifdef __APPLE__
        char ***argv_ptr = _NSGetArgv(); char ***envp_ptr = _NSGetEnviron();
        if (argv_ptr) argv = *argv_ptr;
        if (envp_ptr) envp = *envp_ptr;
        if (argv && argv[0]) prog = argv[0];
#elif defined(__linux__)
        extern char **environ;
        envp = environ;
        char cmd[1024] = {0};
        int fd = real_open("/proc/self/cmdline", O_RDONLY);
        if (fd >= 0) {
            ssize_t n = read(fd, cmd, sizeof(cmd)-1);
            if (n > 0) cmd[n] = '\0';
            if (real_close) real_close(fd); else close(fd);
            prog = cmd[0] ? cmd : "unknown";
        }
#endif
        proc_ident_t id = identify_process(prog, argv, envp);
        emit_log_event("agent_init", getpid(), 0,
            ",\"harness\":\"%s\",\"role\":\"%s\",\"trace_fd\":%d",
            id.harness ? id.harness : "unknown", id.role, trace_fd);

        /* R25: Chain inheritance — link this process to parent's Merkle chain.
         * Format: CLAWSIG_PARENT_CHAIN=pid:merkle_count:chain_hash */
        const char *parent_chain = getenv("CLAWSIG_PARENT_CHAIN");
        if (parent_chain) {
            int p_pid = 0; unsigned long long p_count = 0; char p_hash[128] = {0};
            if (sscanf(parent_chain, "%d:%llu:%64s", &p_pid, &p_count, p_hash) == 3) {
                /* Seed merkle with parent hash (from T2, confirmed by GPT-5.2 Pro) */
                sha256_update(&global_merkle_ctx, (const uint8_t *)p_hash, strlen(p_hash));
                merkle_count = 1;
                sha256_hash_string(p_hash, current_merkle_hex);
                emit_log_event("chain_inherit", getpid(), 0,
                    ",\"parent_pid\":%d,\"parent_merkle_count\":%llu,"
                    "\"parent_chain_hash\":\"%s\",\"reason\":\"exec\"",
                    p_pid, p_count, p_hash);
            }
        }
    }
    in_hook = 0;
}

/* ================================================================== */
/*            Post-Mortem Memory Forensics (from E-Synthesis)         */
/* ================================================================== */

static void scan_memory_block(const unsigned char *p, size_t len) {
    if (len < 15) return;
    const unsigned char *end = p + len - 10;
    /* memchr-based scanning: use SIMD-accelerated memchr to jump to
     * candidate 's' and 'B' positions. From D-Architect stealable idea #32.
     * 4-8x faster than linear byte-by-byte on large memory regions. */
    while (p <= end) {
        const unsigned char *s = (const unsigned char *)memchr(p, 's', (size_t)(end - p + 1));
        const unsigned char *b = (const unsigned char *)memchr(p, 'B', (size_t)(end - p + 1));
        if (!s && !b) break;
        /* Pick whichever candidate comes first */
        const unsigned char *next = s ? (b ? (s < b ? s : b) : s) : b;
        if (*next == 's' && next + 7 <= end + 10 && memcmp(next, "sk-ant-", 7) == 0) {
            emit_log_event("mem_forensics", getpid(), -999, ",\"pattern\":\"sk-ant-*\"");
            p = next + 30; continue;
        }
        if (*next == 's' && next + 8 <= end + 10 && memcmp(next, "sk-proj-", 8) == 0) {
            emit_log_event("mem_forensics", getpid(), -999, ",\"pattern\":\"sk-proj-*\"");
            p = next + 30; continue;
        }
        if (*next == 'B' && next + 10 <= end + 10 && memcmp(next, "Bearer sk-", 10) == 0) {
            emit_log_event("mem_forensics", getpid(), -999, ",\"pattern\":\"Bearer sk-*\"");
            p = next + 30; continue;
        }
        p = next + 1;
    }
}

static void safe_scan_memory(void) {
    int null_fd = open("/dev/null", O_WRONLY);
    if (null_fd < 0) return;
#ifdef __linux__
    int maps_fd = real_open ? real_open("/proc/self/maps", O_RDONLY) : open("/proc/self/maps", O_RDONLY);
    if (maps_fd >= 0) {
        char line[256]; int line_pos = 0; char rbuf[4096]; ssize_t n;
        while ((n = read(maps_fd, rbuf, sizeof(rbuf))) > 0) {
            for (ssize_t i = 0; i < n; i++) {
                if (rbuf[i] == '\n' || line_pos == (int)sizeof(line) - 1) {
                    line[line_pos] = '\0';
                    unsigned long start = 0, end = 0; char perms[8] = "";
                    if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
                        if (perms[0] == 'r' && perms[1] == 'w' && perms[3] == 'p') {
                            size_t sz = end - start;
                            if (sz <= 100 * 1024 * 1024) {
                                for (size_t off = 0; off < sz; off += 4096) {
                                    size_t c = (sz - off < 4096) ? sz - off : 4096;
                                    if (real_write ? (real_write(null_fd, (void*)(start + off), 1) == 1)
                                                   : (write(null_fd, (void*)(start + off), 1) == 1))
                                        scan_memory_block((const unsigned char*)(start + off), c);
                                }
                            }
                        }
                    }
                    line_pos = 0;
                } else { line[line_pos++] = rbuf[i]; }
            }
        }
        if (real_close) real_close(maps_fd); else close(maps_fd);
    }
#elif defined(__APPLE__)
    vm_address_t addr = 0; vm_size_t size = 0;
    while (1) {
        mach_msg_type_number_t count = VM_REGION_BASIC_INFO_COUNT_64;
        vm_region_basic_info_data_64_t info; mach_port_t object_name;
        kern_return_t kr = vm_region_64(mach_task_self(), &addr, &size,
            VM_REGION_BASIC_INFO_64, (vm_region_info_t)&info, &count, &object_name);
        if (kr != KERN_SUCCESS) break;
        if ((info.protection & VM_PROT_READ) && (info.protection & VM_PROT_WRITE)) {
            if (size <= 100 * 1024 * 1024) {
                for (size_t off = 0; off < size; off += 4096) {
                    size_t c = (size - off < 4096) ? size - off : 4096;
                    if (write(null_fd, (void*)(addr + off), 1) == 1)
                        scan_memory_block((const unsigned char*)(addr + off), c);
                }
            }
        }
        addr += size;
    }
#endif
    close(null_fd);
}

__attribute__((destructor))
static void clawsig_fini(void) {
    if (trace_fd < 0 || (cached_pid > 0 && getpid() != cached_pid)) return;
    in_hook = 1;

    /* Flush any pending timing fingerprints */
    for (int i = 0; i < MAX_TRACKED_FDS; i++)
        if (is_llm_fd(i)) emit_timing_fingerprint(i);

    /* Post-mortem memory forensics: scan RW pages for leaked credentials */
    safe_scan_memory();

    /* Emit final Merkle commitment — the chain_hash that commits to
     * the exact sequence of every event. Tamper one byte, hash breaks. */
    merkle_acquire();
    sha256_ctx_t final_snap = global_merkle_ctx;
    uint8_t final_hash[32];
    sha256_final(&final_snap, final_hash);
    char final_hex[65];
    for (int i = 0; i < 32; i++) snprintf(&final_hex[i * 2], 3, "%02x", final_hash[i]);
    merkle_release();

    char final_buf[384];
    int final_len = snprintf(final_buf, sizeof(final_buf),
        "{\"layer\":\"interpose\",\"syscall\":\"merkle_final\","
        "\"pid\":%d,\"count\":%llu,\"hash\":\"%s\"}\n",
        getpid(), (unsigned long long)merkle_count, final_hex);
    write_trace(final_buf, (size_t)final_len);
    in_hook = 0;
}

/* ================================================================== */
/*                  THE HOOKS — Process Lifecycle                     */
/* ================================================================== */

/**
 * R25: Cross-process receipt chain correlation.
 * Best-of-breed from 5 variants (Q/R/S/T/T2), all scored 7.8-8.6.
 *
 * Architecture (from S-Socratic):
 * - cached_pid detects fork/vfork children via getpid() mismatch
 * - vfork muting: child retains in_hook=1, silencing ALL hooks except execve
 * - fork child: full state reset (merkle, locks), emits chain_inherit
 * - exec/spawn: injects CLAWSIG_PARENT_CHAIN=pid:count:hash into envp
 * - constructor: parses CLAWSIG_PARENT_CHAIN, emits chain_inherit(reason=exec)
 *
 * 7 constraints addressed:
 * (1) fork BSS copy, (2) exec re-init, (3) fork-exec gap,
 * (4) vfork shared address space, (5) posix_spawn atomicity,
 * (6) signal safety, (7) concurrent trace writes
 */

pid_t HOOK_NAME(fork)(void) {
    RESOLVE(fork);
    if (in_hook || trace_fd < 0 || (cached_pid > 0 && getpid() != cached_pid))
        return CALL_REAL(fork);
    in_hook = 1;

    /* Snapshot parent's Merkle chain before fork */
    char parent_hash[65];
    merkle_acquire();
    memcpy(parent_hash, current_merkle_hex, 65);
    uint64_t p_count = merkle_count;
    merkle_release();
    parent_hash[64] = '\0';

    pid_t rc = CALL_REAL(fork);
    int saved_errno = errno;

    if (rc == 0) {
        /* Fork child: reset state so parent and child chains diverge.
         * From S(#96-S4): comprehensive lock reset prevents deadlocks
         * from locks held by parent threads at fork time. */
        pid_t parent_pid = cached_pid;
        cached_pid = getpid();
        merkle_lock = 0;
        for (int i = 0; i < MAX_TRACKED_FDS; i++) {
            http_fsm[i].lock = 0;
            llm_timings[i].lock = 0;
        }
        for (int i = 0; i < MAX_H2_CONNS; i++) h2_conns[i].lock = 0;
        for (int i = 0; i < MAX_ANOMALY_HOSTS; i++) anomaly_hosts[i].lock = 0;

        /* T2 insight (confirmed by GPT-5.2 Pro review): seed child merkle
         * with parent hash so the child chain is cryptographically rooted
         * in the parent, not starting from zeros. */
        sha256_init(&global_merkle_ctx);
        sha256_update(&global_merkle_ctx, (const uint8_t *)parent_hash, 64);
        merkle_count = 1;
        sha256_hash_string(parent_hash, current_merkle_hex);

        in_hook = 0;
        emit_log_event("chain_inherit", cached_pid, 0,
            ",\"parent_pid\":%d,\"parent_merkle_count\":%llu,"
            "\"parent_chain_hash\":\"%s\",\"reason\":\"fork\"",
            parent_pid, (unsigned long long)p_count, parent_hash);
        return 0;
    }

    if (rc > 0) emit_log_event("fork", getpid(), rc, ",\"child_pid\":%d", rc);
    in_hook = 0; errno = saved_errno; return rc;
}

pid_t HOOK_NAME(vfork)(void) {
    RESOLVE(vfork);
    if (in_hook || trace_fd < 0 || (cached_pid > 0 && getpid() != cached_pid))
        return CALL_REAL(vfork);
    in_hook = 1;
    /* S(#96-S1): vfork muting — leave in_hook=1 in child.
     * Since parent and child share address space until exec, setting in_hook=1
     * silences ALL hooks in the child with zero additional code. The child
     * will call execve which checks is_vfork_child explicitly. */
    pid_t rc = CALL_REAL(vfork);
    if (rc == 0) return 0; /* child: in_hook stays 1, all hooks muted */
    int saved_errno = errno;
    if (rc > 0) emit_log_event("vfork", getpid(), rc, ",\"child_pid\":%d", rc);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(execve)(const char *pathname, char *const argv[], char *const envp[]) {
    RESOLVE(execve);
    int is_vfork_child = (cached_pid > 0 && getpid() != cached_pid);

    if (trace_fd < 0 || (!is_vfork_child && in_hook))
        return CALL_REAL(execve, pathname, argv, envp);

    if (!is_vfork_child) in_hook = 1;

    char path_esc[1024] = {0}, argv_json[4096] = {0};
    if (!is_vfork_child) {
        escape_json(pathname, path_esc, sizeof(path_esc));
        format_argv(argv, argv_json, sizeof(argv_json));

        proc_ident_t id = identify_process(pathname, argv, envp);
        if (id.harness)
            emit_log_event("execve", getpid(), 0,
                ",\"path\":\"%s\",\"argv\":%s,\"role\":\"%s\",\"harness\":\"%s\"",
                path_esc, argv_json, id.role, id.harness);
        else
            emit_log_event("execve", getpid(), 0,
                ",\"path\":\"%s\",\"argv\":%s,\"role\":\"%s\"",
                path_esc, argv_json, id.role);
        audit_env(envp);
    }

    /* Inject parent chain + SSLKEYLOGFILE into child envp */
    char chain_buf[256] = {0};
    if (cached_pid > 0) {
        char parent_hash[65];
        /* Q(#98): unlocked read in vfork child avoids deadlock with
         * suspended parent threads holding merkle_lock */
        if (is_vfork_child) {
            for (int i = 0; i < 65; i++) parent_hash[i] = current_merkle_hex[i];
        } else {
            merkle_acquire();
            memcpy(parent_hash, current_merkle_hex, 65);
            merkle_release();
        }
        parent_hash[64] = '\0';
        snprintf(chain_buf, sizeof(chain_buf), "CLAWSIG_PARENT_CHAIN=%d:%llu:%s",
                 (int)cached_pid, (unsigned long long)merkle_count, parent_hash);
    }

    char *inj_envp[MAX_INJECT_ENV]; char ssl_buf[512], node_buf[1024];
    char *const *final_envp = envp;
    if (build_injected_env(envp, inj_envp, ssl_buf, sizeof(ssl_buf),
                           node_buf, sizeof(node_buf), chain_buf))
        final_envp = (char *const *)inj_envp;

    if (!is_vfork_child) in_hook = 0;
    int rc = CALL_REAL(execve, pathname, argv, final_envp);
    int saved_errno = errno;

    if (!is_vfork_child) {
        in_hook = 1;
        emit_log_event("execve_failed", getpid(), rc, ",\"path\":\"%s\"", path_esc);
        in_hook = 0;
    }
    errno = saved_errno; return rc;
}

int HOOK_NAME(posix_spawn)(pid_t *restrict pid, const char *restrict path,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
    char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawn);
    int is_vfork_child = (cached_pid > 0 && getpid() != cached_pid);
    if (trace_fd < 0 || (!is_vfork_child && in_hook))
        return CALL_REAL(posix_spawn, pid, path, fa, attr, argv, envp);

    if (!is_vfork_child) { in_hook = 1; audit_env(envp); }

    /* Inject parent chain */
    char chain_buf[256] = {0};
    if (cached_pid > 0) {
        char parent_hash[65];
        if (is_vfork_child) {
            for (int i = 0; i < 65; i++) parent_hash[i] = current_merkle_hex[i];
        } else {
            merkle_acquire(); memcpy(parent_hash, current_merkle_hex, 65); merkle_release();
        }
        parent_hash[64] = '\0';
        snprintf(chain_buf, sizeof(chain_buf), "CLAWSIG_PARENT_CHAIN=%d:%llu:%s",
                 (int)cached_pid, (unsigned long long)merkle_count, parent_hash);
    }

    char *inj_envp[MAX_INJECT_ENV]; char ssl_buf[512], node_buf[1024];
    char *const *final_envp = envp;
    if (build_injected_env(envp, inj_envp, ssl_buf, sizeof(ssl_buf),
                           node_buf, sizeof(node_buf), chain_buf))
        final_envp = (char *const *)inj_envp;

    int rc = CALL_REAL(posix_spawn, pid, path, fa, attr, argv, final_envp);
    int saved_errno = errno;

    if (!is_vfork_child) {
        char path_esc[1024], argv_json[4096];
        escape_json(path, path_esc, sizeof(path_esc));
        format_argv(argv, argv_json, sizeof(argv_json));

        proc_ident_t id = identify_process(path, argv, envp);
        if (id.harness)
            emit_log_event("posix_spawn", getpid(), rc,
                ",\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"role\":\"%s\",\"harness\":\"%s\"",
                path_esc, argv_json, (pid && rc == 0) ? *pid : -1, id.role, id.harness);
        else
            emit_log_event("posix_spawn", getpid(), rc,
                ",\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"role\":\"%s\"",
                path_esc, argv_json, (pid && rc == 0) ? *pid : -1, id.role);
        in_hook = 0;
    }
    errno = saved_errno; return rc;
}

int HOOK_NAME(posix_spawnp)(pid_t *restrict pid, const char *restrict file,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
    char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawnp);
    int is_vfork_child = (cached_pid > 0 && getpid() != cached_pid);
    if (trace_fd < 0 || (!is_vfork_child && in_hook))
        return CALL_REAL(posix_spawnp, pid, file, fa, attr, argv, envp);

    if (!is_vfork_child) { in_hook = 1; audit_env(envp); }

    char chain_buf[256] = {0};
    if (cached_pid > 0) {
        char parent_hash[65];
        if (is_vfork_child) {
            for (int i = 0; i < 65; i++) parent_hash[i] = current_merkle_hex[i];
        } else {
            merkle_acquire(); memcpy(parent_hash, current_merkle_hex, 65); merkle_release();
        }
        parent_hash[64] = '\0';
        snprintf(chain_buf, sizeof(chain_buf), "CLAWSIG_PARENT_CHAIN=%d:%llu:%s",
                 (int)cached_pid, (unsigned long long)merkle_count, parent_hash);
    }

    char *inj_envp[MAX_INJECT_ENV]; char ssl_buf[512], node_buf[1024];
    char *const *final_envp = envp;
    if (build_injected_env(envp, inj_envp, ssl_buf, sizeof(ssl_buf),
                           node_buf, sizeof(node_buf), chain_buf))
        final_envp = (char *const *)inj_envp;

    int rc = CALL_REAL(posix_spawnp, pid, file, fa, attr, argv, final_envp);
    int saved_errno = errno;

    if (!is_vfork_child) {
        char file_esc[1024], argv_json[4096];
        escape_json(file, file_esc, sizeof(file_esc));
        format_argv(argv, argv_json, sizeof(argv_json));

        proc_ident_t id = identify_process(file, argv, envp);
        if (id.harness)
            emit_log_event("posix_spawnp", getpid(), rc,
                ",\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"role\":\"%s\",\"harness\":\"%s\"",
                file_esc, argv_json, (pid && rc == 0) ? *pid : -1, id.role, id.harness);
        else
            emit_log_event("posix_spawnp", getpid(), rc,
                ",\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"role\":\"%s\"",
                file_esc, argv_json, (pid && rc == 0) ? *pid : -1, id.role);
        in_hook = 0;
    }
    errno = saved_errno; return rc;
}

int HOOK_NAME(kill)(pid_t pid, int sig) {
    RESOLVE(kill);
    if (in_hook || trace_fd < 0 || (cached_pid > 0 && getpid() != cached_pid))
        return CALL_REAL(kill, pid, sig);
    in_hook = 1; int rc = CALL_REAL(kill, pid, sig); int saved_errno = errno;
    emit_log_event("kill", getpid(), rc,
        ",\"target_pid\":%d,\"signal\":%d", pid, sig);
    in_hook = 0; errno = saved_errno; return rc;
}

/* ================================================================== */
/*                   THE HOOKS — Socket Lifecycle                     */
/* ================================================================== */

int HOOK_NAME(bind)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    RESOLVE(bind); if (in_hook || trace_fd < 0 || !addr) return CALL_REAL(bind, sockfd, addr, addrlen);
    in_hook = 1; int rc = CALL_REAL(bind, sockfd, addr, addrlen); int saved_errno = errno;
    char ip[INET6_ADDRSTRLEN]; int port; const char *family;
    format_addr(addr, ip, sizeof(ip), &port, &family);
    tl_event_fd = sockfd;
    emit_log_event("bind", getpid(), rc,
        ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"", sockfd, ip, port, family);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(listen)(int sockfd, int backlog) {
    RESOLVE(listen); if (in_hook || trace_fd < 0) return CALL_REAL(listen, sockfd, backlog);
    in_hook = 1; int rc = CALL_REAL(listen, sockfd, backlog); int saved_errno = errno;
    tl_event_fd = sockfd;
    emit_log_event("listen", getpid(), rc,
        ",\"fd\":%d,\"backlog\":%d", sockfd, backlog);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    RESOLVE(accept); if (in_hook || trace_fd < 0) return CALL_REAL(accept, sockfd, addr, addrlen);
    in_hook = 1; int rc = CALL_REAL(accept, sockfd, addr, addrlen); int saved_errno = errno;
    if (rc >= 0) {
        untrack_fd(rc);
        /* Causal lineage: client FD inherits server socket's causal sequence */
        if (sockfd >= 0 && sockfd < MAX_TRACKED_FDS && rc < MAX_TRACKED_FDS)
            fd_last_seq[rc] = fd_last_seq[sockfd];
    }
    char ip[INET6_ADDRSTRLEN] = ""; int port = 0; const char *family = "UNKNOWN";
    if (addr) format_addr(addr, ip, sizeof(ip), &port, &family);
    tl_event_fd = sockfd;
    emit_log_event("accept", getpid(), rc,
        ",\"server_fd\":%d,\"client_fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"",
        sockfd, rc, ip, port, family);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(socket)(int domain, int type, int protocol) {
    RESOLVE(socket); if (in_hook || trace_fd < 0) return CALL_REAL(socket, domain, type, protocol);
    in_hook = 1; int rc = CALL_REAL(socket, domain, type, protocol); int saved_errno = errno;
    if (rc >= 0) {
        tl_event_fd = rc;
        emit_log_event("socket", getpid(), rc,
            ",\"domain\":%d,\"type\":%d,\"protocol\":%d", domain, type, protocol);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(pipe)(int pipefd[2]) {
    RESOLVE(pipe); if (in_hook || trace_fd < 0) return CALL_REAL(pipe, pipefd);
    in_hook = 1; int rc = CALL_REAL(pipe, pipefd); int saved_errno = errno;
    if (rc == 0) {
        /* Causal lineage: write end inherits read end's causal sequence */
        if (pipefd[0] >= 0 && pipefd[0] < MAX_TRACKED_FDS &&
            pipefd[1] >= 0 && pipefd[1] < MAX_TRACKED_FDS)
            fd_last_seq[pipefd[1]] = fd_last_seq[pipefd[0]];
        emit_log_event("pipe", getpid(), rc,
            ",\"read_fd\":%d,\"write_fd\":%d", pipefd[0], pipefd[1]);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(socketpair)(int domain, int type, int protocol, int sv[2]) {
    RESOLVE(socketpair); if (in_hook || trace_fd < 0)
        return CALL_REAL(socketpair, domain, type, protocol, sv);
    in_hook = 1; int rc = CALL_REAL(socketpair, domain, type, protocol, sv);
    int saved_errno = errno;
    if (rc == 0) {
        /* Causal lineage: link both ends of socketpair */
        if (sv[0] >= 0 && sv[0] < MAX_TRACKED_FDS &&
            sv[1] >= 0 && sv[1] < MAX_TRACKED_FDS)
            fd_last_seq[sv[1]] = fd_last_seq[sv[0]];
        emit_log_event("socketpair", getpid(), rc,
            ",\"domain\":%d,\"type\":%d,\"fd0\":%d,\"fd1\":%d", domain, type, sv[0], sv[1]);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(dup)(int oldfd) {
    RESOLVE(dup); if (in_hook || trace_fd < 0) return CALL_REAL(dup, oldfd);
    in_hook = 1; int rc = CALL_REAL(dup, oldfd); int saved_errno = errno;
    if (rc >= 0) {
        /* Causal lineage: new FD inherits old FD's causal sequence */
        if (oldfd >= 0 && oldfd < MAX_TRACKED_FDS && rc < MAX_TRACKED_FDS)
            fd_last_seq[rc] = fd_last_seq[oldfd];
        tl_event_fd = oldfd;
        emit_log_event("dup", getpid(), rc, ",\"oldfd\":%d", oldfd);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(dup2)(int oldfd, int newfd) {
    RESOLVE(dup2);
    /* Trace FD protection: migrate trace_fd upward if dup2 targets it.
     * From D-Architect: resilient migration + tamper alert.
     * Survives hostile dup2 without losing trace capability. */
    if (newfd == trace_fd && trace_fd >= 0) {
        int moved_fd = fcntl(trace_fd, F_DUPFD_CLOEXEC, trace_fd + 1);
        if (moved_fd >= 0) {
            int old_trace = trace_fd;
            trace_fd = moved_fd;
#ifdef __linux__
            if (real_close) real_close(old_trace); else close(old_trace);
#else
            close(old_trace);
#endif
            if (!in_hook) {
                in_hook = 1;
                emit_log_event("trace_tamper", getpid(), -1,
                    ",\"action\":\"dup2_migrated\",\"oldfd\":%d,\"target_fd\":%d,\"new_trace_fd\":%d",
                    oldfd, newfd, moved_fd);
                in_hook = 0;
            }
        } else {
            /* Migration failed — fall back to blocking */
            errno = EBADF;
            if (!in_hook) {
                in_hook = 1;
                emit_log_event("trace_tamper", getpid(), -1,
                    ",\"action\":\"dup2_blocked\",\"oldfd\":%d,\"target_fd\":%d", oldfd, newfd);
                in_hook = 0;
            }
            return -1;
        }
    }
    if (in_hook || trace_fd < 0) return CALL_REAL(dup2, oldfd, newfd);
    in_hook = 1; int rc = CALL_REAL(dup2, oldfd, newfd); int saved_errno = errno;
    if (rc >= 0) {
        untrack_fd(newfd);
        /* Causal lineage: new FD inherits old FD's causal sequence */
        if (oldfd >= 0 && oldfd < MAX_TRACKED_FDS && newfd >= 0 && newfd < MAX_TRACKED_FDS)
            fd_last_seq[newfd] = fd_last_seq[oldfd];
    }
    tl_event_fd = oldfd;
    emit_log_event("dup2", getpid(), rc,
        ",\"oldfd\":%d,\"newfd\":%d", oldfd, newfd);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    RESOLVE(connect); if (in_hook || trace_fd < 0 || !addr)
        return CALL_REAL(connect, sockfd, addr, addrlen);
    in_hook = 1; untrack_fd(sockfd);
    int rc = CALL_REAL(connect, sockfd, addr, addrlen); int saved_errno = errno;
    char ip_str[INET6_ADDRSTRLEN] = "UNKNOWN"; int port; const char *family;
    format_addr(addr, ip_str, sizeof(ip_str), &port, &family);
    if (strcmp(family, "UNKNOWN") != 0) {
        if (port == 443) {
            char dns_hostname[256]; int emitted_sni = 0;
            if (lookup_dns(ip_str, dns_hostname)) {
                char sni_esc[512]; escape_json(dns_hostname, sni_esc, sizeof(sni_esc));
                tl_event_fd = sockfd;
                emit_log_event("tls_sni", getpid(), -999,
                    ",\"fd\":%d,\"hostname\":\"%s\",\"addr\":\"%s\",\"port\":%d",
                    sockfd, sni_esc, ip_str, port);
                emitted_sni = 1;
                if (strstr(dns_hostname, "openai") || strstr(dns_hostname, "anthropic") ||
                    strstr(dns_hostname, "googleapis") || strstr(dns_hostname, "cohere") ||
                    strstr(dns_hostname, "mistral") || strstr(dns_hostname, "deepseek") ||
                    strstr(dns_hostname, "groq") || strstr(dns_hostname, "together") ||
                    strstr(dns_hostname, "x.ai") || strstr(dns_hostname, "openrouter") ||
                    strstr(dns_hostname, "github")) {
                    set_llm_fd(sockfd);
                }
            }
            if (!emitted_sni && (rc == 0 || (rc == -1 && saved_errno == EINPROGRESS)))
                track_fd(sockfd, ip_str, port);
        }
        tl_event_fd = sockfd;
        emit_log_event("connect", getpid(), rc,
            ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"",
            sockfd, ip_str, port, family);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(getsockname)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    RESOLVE(getsockname); if (in_hook || trace_fd < 0 || !addr)
        return CALL_REAL(getsockname, sockfd, addr, addrlen);
    in_hook = 1; int rc = CALL_REAL(getsockname, sockfd, addr, addrlen);
    int saved_errno = errno;
    if (rc == 0) {
        char ip[INET6_ADDRSTRLEN]; int port; const char *fam;
        format_addr(addr, ip, sizeof(ip), &port, &fam);
        tl_event_fd = sockfd;
        emit_log_event("getsockname", getpid(), rc,
            ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"", sockfd, ip, port, fam);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(getpeername)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    RESOLVE(getpeername); if (in_hook || trace_fd < 0 || !addr)
        return CALL_REAL(getpeername, sockfd, addr, addrlen);
    in_hook = 1; int rc = CALL_REAL(getpeername, sockfd, addr, addrlen);
    int saved_errno = errno;
    if (rc == 0) {
        char ip[INET6_ADDRSTRLEN]; int port; const char *fam;
        format_addr(addr, ip, sizeof(ip), &port, &fam);
        tl_event_fd = sockfd;
        emit_log_event("getpeername", getpid(), rc,
            ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"", sockfd, ip, port, fam);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(getaddrinfo)(const char *restrict node, const char *restrict service,
    const struct addrinfo *restrict hints, struct addrinfo **restrict res) {
    RESOLVE(getaddrinfo);
    if (in_hook || trace_fd < 0 || !node)
        return CALL_REAL(getaddrinfo, node, service, hints, res);
    in_hook = 1;
    int rc = CALL_REAL(getaddrinfo, node, service, hints, res);
    if (rc == 0 && res && *res) {
        char ips_json[2048] = "["; int first = 1;
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            char ip_str[INET6_ADDRSTRLEN] = "";
            if (p->ai_family == AF_INET)
                inet_ntop(AF_INET, &((struct sockaddr_in *)p->ai_addr)->sin_addr,
                    ip_str, (socklen_t)sizeof(ip_str));
            else if (p->ai_family == AF_INET6)
                inet_ntop(AF_INET6, &((struct sockaddr_in6 *)p->ai_addr)->sin6_addr,
                    ip_str, (socklen_t)sizeof(ip_str));
            if (ip_str[0] != '\0') {
                cache_dns(ip_str, node);
                size_t cur_len = strlen(ips_json);
                if (cur_len < sizeof(ips_json) - INET6_ADDRSTRLEN - 5) {
                    if (!first) strncat(ips_json, ",", sizeof(ips_json) - cur_len - 1);
                    strncat(ips_json, "\"", sizeof(ips_json) - strlen(ips_json) - 1);
                    strncat(ips_json, ip_str, sizeof(ips_json) - strlen(ips_json) - 1);
                    strncat(ips_json, "\"", sizeof(ips_json) - strlen(ips_json) - 1);
                    first = 0;
                }
            }
        }
        strncat(ips_json, "]", sizeof(ips_json) - strlen(ips_json) - 1);
        char node_esc[256]; escape_json(node, node_esc, sizeof(node_esc));
        emit_log_event("getaddrinfo", getpid(), rc,
            ",\"hostname\":\"%s\",\"ips\":%s", node_esc, ips_json);
    }
    in_hook = 0; return rc;
}

/* ================================================================== */
/*                   THE HOOKS — Data Transfer                        */
/* ================================================================== */

ssize_t HOOK_NAME(send)(int sockfd, const void *buf, size_t len, int flags) {
    RESOLVE(send);
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1; check_tls_sni(sockfd, buf, len);
        scan_credentials(sockfd, buf, len);
        /* Plaintext HTTP DFA for non-SSL LLM FDs (from I-Genesis #58) */
        if (!is_ssl_fd(sockfd)) {
            sniff_and_set_llm_fd(sockfd, buf, len);
            if (is_llm_fd(sockfd) && sockfd >= 0 && sockfd < MAX_TRACKED_FDS) {
                timing_start_req(sockfd);
                fsm_lock(sockfd);
                fsm_feed(sockfd, (const uint8_t *)buf, len, 1);
                fsm_unlock(sockfd);
            }
        }
        in_hook = 0;
    }
    return CALL_REAL(send, sockfd, buf, len, flags);
}

ssize_t HOOK_NAME(sendmsg)(int sockfd, const struct msghdr *msg, int flags) {
    RESOLVE(sendmsg);
    if (!in_hook && trace_fd >= 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {
        in_hook = 1; int parsed = 0;
        for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
            if (msg->msg_iov[i].iov_base && msg->msg_iov[i].iov_len > 0) {
                check_tls_sni(sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                scan_credentials(sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                /* Plaintext HTTP DFA (from I-Genesis #58) */
                if (!is_ssl_fd(sockfd)) {
                    sniff_and_set_llm_fd(sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                    if (is_llm_fd(sockfd) && sockfd >= 0 && sockfd < MAX_TRACKED_FDS) {
                        if (i == 0) timing_start_req(sockfd);
                        fsm_lock(sockfd);
                        fsm_feed(sockfd, (const uint8_t *)msg->msg_iov[i].iov_base,
                                 msg->msg_iov[i].iov_len, 1);
                        fsm_unlock(sockfd);
                    }
                }
                parsed = 1;
            }
        }
        if (!parsed) untrack_fd(sockfd); in_hook = 0;
    }
    return CALL_REAL(sendmsg, sockfd, msg, flags);
}

ssize_t HOOK_NAME(sendto)(int sockfd, const void *buf, size_t len, int flags,
    const struct sockaddr *dest_addr, socklen_t addrlen) {
    RESOLVE(sendto);
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1; check_tls_sni(sockfd, buf, len);
        scan_credentials(sockfd, buf, len); in_hook = 0;
    }
    if (in_hook || trace_fd < 0 || !dest_addr)
        return CALL_REAL(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
    in_hook = 1;
    ssize_t rc = CALL_REAL(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
    int saved_errno = errno;
    char ip_str[INET6_ADDRSTRLEN] = {0}; int port; const char *family;
    format_addr(dest_addr, ip_str, sizeof(ip_str), &port, &family);
    if (ip_str[0] && strcmp(family, "UNKNOWN") != 0) {
        tl_event_fd = sockfd;
        emit_log_event("sendto", getpid(), -999,
            ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\",\"len\":%zu",
            sockfd, ip_str, port, family, len);
    }
    in_hook = 0; errno = saved_errno; return rc;
}

ssize_t HOOK_NAME(recv)(int sockfd, void *buf, size_t len, int flags) {
    RESOLVE(recv); ssize_t rc = CALL_REAL(recv, sockfd, buf, len, flags);
    if (!in_hook && trace_fd >= 0 && rc > 0 && is_llm_fd(sockfd)) {
        in_hook = 1;
        /* Plaintext HTTP DFA response parsing (from I-Genesis #58) */
        if (!is_ssl_fd(sockfd) && sockfd >= 0 && sockfd < MAX_TRACKED_FDS) {
            timing_add_token(sockfd, (size_t)rc);
            fsm_lock(sockfd);
            fsm_feed(sockfd, (const uint8_t *)buf, (size_t)rc, 0);
            fsm_unlock(sockfd);
        } else {
            timing_add_token(sockfd, (size_t)rc);
            int is_sse = (rc >= 6 && memcmp(buf, "data: ", 6) == 0) ? 1 : 0;
            tl_event_fd = sockfd;
            emit_log_event("recv_llm", getpid(), -999,
                ",\"fd\":%d,\"bytes\":%zd,\"sse\":%d", sockfd, rc, is_sse);
        }
        tl_causal_read_fd = sockfd;
        tl_causal_read_seq = global_seq - 1;
        in_hook = 0;
    }
    return rc;
}

ssize_t HOOK_NAME(recvfrom)(int sockfd, void *restrict buf, size_t len, int flags,
    struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    RESOLVE(recvfrom);
    ssize_t rc = CALL_REAL(recvfrom, sockfd, buf, len, flags, addr, addrlen);
    if (!in_hook && trace_fd >= 0 && rc > 0 && is_llm_fd(sockfd)) {
        in_hook = 1;
        if (!is_ssl_fd(sockfd) && sockfd >= 0 && sockfd < MAX_TRACKED_FDS) {
            timing_add_token(sockfd, (size_t)rc);
            fsm_lock(sockfd);
            fsm_feed(sockfd, (const uint8_t *)buf, (size_t)rc, 0);
            fsm_unlock(sockfd);
        }
        in_hook = 0;
    }
    return rc;
}

ssize_t HOOK_NAME(recvmsg)(int sockfd, struct msghdr *msg, int flags) {
    RESOLVE(recvmsg); ssize_t rc = CALL_REAL(recvmsg, sockfd, msg, flags);
    if (!in_hook && trace_fd >= 0 && rc > 0 && is_llm_fd(sockfd) &&
        msg && msg->msg_iovlen > 0 && msg->msg_iov[0].iov_base) {
        in_hook = 1;
        if (!is_ssl_fd(sockfd) && sockfd >= 0 && sockfd < MAX_TRACKED_FDS) {
            timing_add_token(sockfd, (size_t)rc);
            size_t remaining = (size_t)rc;
            fsm_lock(sockfd);
            for (size_t j = 0; j < (size_t)msg->msg_iovlen && remaining > 0; j++) {
                if (msg->msg_iov[j].iov_base && msg->msg_iov[j].iov_len > 0) {
                    size_t chunk = remaining < msg->msg_iov[j].iov_len ?
                                   remaining : msg->msg_iov[j].iov_len;
                    fsm_feed(sockfd, (const uint8_t *)msg->msg_iov[j].iov_base, chunk, 0);
                    remaining -= chunk;
                }
            }
            fsm_unlock(sockfd);
        }
        in_hook = 0;
    }
    return rc;
}

/* ================================================================== */
/*                      THE HOOKS — File I/O                          */
/* ================================================================== */

int HOOK_NAME(open)(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(open); if (in_hook || trace_fd < 0) return CALL_REAL(open, pathname, flags, mode);
    in_hook = 1; int rc = CALL_REAL(open, pathname, flags, mode);
    int saved_errno = errno; if (rc >= 0) untrack_fd(rc);
    char path_esc[1024]; escape_json(pathname, path_esc, sizeof(path_esc));
    tl_event_fd = rc;
    emit_log_event("open", getpid(), rc,
        ",\"path\":\"%s\",\"flags\":\"%s\",\"is_write\":%d",
        path_esc, get_access_mode(flags), is_write_access(flags));
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(openat)(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(openat); if (in_hook || trace_fd < 0) return CALL_REAL(openat, dirfd, pathname, flags, mode);
    in_hook = 1; int rc = CALL_REAL(openat, dirfd, pathname, flags, mode);
    int saved_errno = errno; if (rc >= 0) untrack_fd(rc);
    char path_esc[1024]; escape_json(pathname, path_esc, sizeof(path_esc));
    tl_event_fd = rc;
    emit_log_event("openat", getpid(), rc,
        ",\"dirfd\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"is_write\":%d",
        dirfd, path_esc, get_access_mode(flags), is_write_access(flags));
    in_hook = 0; errno = saved_errno; return rc;
}

/* ================================================================== */
/*                  Linux-only hooks (write/close/64)                 */
/* ================================================================== */

#ifdef __linux__
ssize_t write(int fd, const void *buf, size_t count) {
    RESOLVE(write);
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1; check_tls_sni(fd, buf, count);
        scan_credentials(fd, buf, count); in_hook = 0;
    }
    return real_write ? real_write(fd, buf, count) : -1;
}

int close(int fd) {
    RESOLVE(close);
    /* Trace FD protection on Linux too */
    if (fd == trace_fd && trace_fd >= 0) {
        errno = EBADF;
        return -1;
    }
    if (!in_hook && trace_fd >= 0) { in_hook = 1; untrack_fd(fd); in_hook = 0; }
    return real_close ? real_close(fd) : -1;
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(open64); if (in_hook || trace_fd < 0) return real_open64 ? real_open64(pathname, flags, mode) : -1;
    in_hook = 1; int rc = real_open64(pathname, flags, mode);
    int saved_errno = errno; if (rc >= 0) untrack_fd(rc);
    char path_esc[1024]; escape_json(pathname, path_esc, sizeof(path_esc));
    tl_event_fd = rc;
    emit_log_event("open64", getpid(), rc,
        ",\"path\":\"%s\",\"flags\":\"%s\",\"is_write\":%d",
        path_esc, get_access_mode(flags), is_write_access(flags));
    in_hook = 0; errno = saved_errno; return rc;
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags); mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(openat64); if (in_hook || trace_fd < 0) return real_openat64 ? real_openat64(dirfd, pathname, flags, mode) : -1;
    in_hook = 1; int rc = real_openat64(dirfd, pathname, flags, mode);
    int saved_errno = errno; if (rc >= 0) untrack_fd(rc);
    char path_esc[1024]; escape_json(pathname, path_esc, sizeof(path_esc));
    tl_event_fd = rc;
    emit_log_event("openat64", getpid(), rc,
        ",\"dirfd\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"is_write\":%d",
        dirfd, path_esc, get_access_mode(flags), is_write_access(flags));
    in_hook = 0; errno = saved_errno; return rc;
}
#endif /* __linux__ */

/* ================================================================== */
/*                   macOS DYLD_INTERPOSE Table                       */
/* ================================================================== */

#ifdef __APPLE__
DYLD_INTERPOSE(clawsig_connect, connect)
DYLD_INTERPOSE(clawsig_open, open)
DYLD_INTERPOSE(clawsig_openat, openat)
DYLD_INTERPOSE(clawsig_execve, execve)
DYLD_INTERPOSE(clawsig_posix_spawn, posix_spawn)
DYLD_INTERPOSE(clawsig_posix_spawnp, posix_spawnp)
DYLD_INTERPOSE(clawsig_sendto, sendto)
DYLD_INTERPOSE(clawsig_send, send)
DYLD_INTERPOSE(clawsig_sendmsg, sendmsg)
DYLD_INTERPOSE(clawsig_getaddrinfo, getaddrinfo)
DYLD_INTERPOSE(clawsig_fork, fork)
DYLD_INTERPOSE(clawsig_vfork, vfork)
DYLD_INTERPOSE(clawsig_bind, bind)
DYLD_INTERPOSE(clawsig_listen, listen)
DYLD_INTERPOSE(clawsig_accept, accept)
DYLD_INTERPOSE(clawsig_socket, socket)
DYLD_INTERPOSE(clawsig_pipe, pipe)
DYLD_INTERPOSE(clawsig_socketpair, socketpair)
DYLD_INTERPOSE(clawsig_dup, dup)
DYLD_INTERPOSE(clawsig_dup2, dup2)
DYLD_INTERPOSE(clawsig_kill, kill)
DYLD_INTERPOSE(clawsig_recv, recv)
DYLD_INTERPOSE(clawsig_recvfrom, recvfrom)
DYLD_INTERPOSE(clawsig_recvmsg, recvmsg)
DYLD_INTERPOSE(clawsig_getsockname, getsockname)
DYLD_INTERPOSE(clawsig_getpeername, getpeername)
/* SSL hooks — only fire if process dynamically links OpenSSL/BoringSSL/LibreSSL */
DYLD_INTERPOSE(clawsig_SSL_new, SSL_new)
DYLD_INTERPOSE(clawsig_SSL_read, SSL_read)
DYLD_INTERPOSE(clawsig_SSL_write, SSL_write)
DYLD_INTERPOSE(clawsig_SSL_CTX_set_keylog_callback, SSL_CTX_set_keylog_callback)
/* R27: Apple SecureTransport — dynamically linked, unlike BoringSSL */
DYLD_INTERPOSE(clawsig_SSLRead, SSLRead)
DYLD_INTERPOSE(clawsig_SSLWrite, SSLWrite)
#endif
