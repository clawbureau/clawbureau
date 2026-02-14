/**
 * Clawsig Interposition Library — God-Mode EDR Layer
 *
 * Implements: Perfect Process Genealogy, Server Socket Awareness,
 * Full IPC Lifecycle, Nanosecond Kinematics, Causal Sequence Numbers,
 * Stack-only SHA-256 Env Auditing, Credential DLP, LLM recv() Sampling,
 * and Semantic Harness/MCP Fingerprinting.
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

#ifdef __linux__
typedef ssize_t (*write_func_t)(int, const void *, size_t);
typedef int (*close_func_t)(int);
typedef int (*open64_func_t)(const char *, int, ...);
typedef int (*openat64_func_t)(int, const char *, int, ...);
static write_func_t real_write = NULL; static close_func_t real_close = NULL;
static open64_func_t real_open64 = NULL; static openat64_func_t real_openat64 = NULL;
#endif

#define RESOLVE(name) if (!real_##name) { real_##name = (typeof(real_##name))dlsym(RTLD_NEXT, #name); }

#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { const void* replacement; const void* replacee; } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { (const void*)(unsigned long)&_replacement, (const void*)(unsigned long)&_replacee };
#define HOOK_NAME(name) clawsig_##name
#define CALL_REAL(name, ...) name(__VA_ARGS__)
#else
#define HOOK_NAME(name) name
#define CALL_REAL(name, ...) real_##name(__VA_ARGS__)
#endif

/* ================================================================== */
/*                 Stack-only SHA-256 (env auditing)                  */
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

static void sha256_hash_string(const char *str, char out_hex[65]) {
    uint32_t state[8] = {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};
    uint8_t datalen = 0, data[64]; uint64_t bitlen = 0; size_t len = strlen(str);
    for (size_t i = 0; i < len; ++i) {
        data[datalen++] = (uint8_t)str[i];
        if (datalen == 64) { sha256_transform(state, data); bitlen += 512; datalen = 0; }
    }
    bitlen += datalen * 8; data[datalen++] = 0x80;
    if (datalen > 56) { while (datalen < 64) data[datalen++] = 0x00; sha256_transform(state, data); datalen = 0; }
    while (datalen < 56) data[datalen++] = 0x00;
    for (int i = 7; i >= 0; i--) data[56 + (7 - i)] = (uint8_t)((bitlen >> (i * 8)) & 0xFF);
    sha256_transform(state, data);
    for (int i = 0; i < 8; ++i) snprintf(out_hex + i * 8, 9, "%08x", state[i]);
}

/* ================================================================== */
/*                        Unified Event Emitter                       */
/* ================================================================== */

static void emit_log_event(const char *syscall_name, int pid, int rc, const char *fmt, ...) {
    if (trace_fd < 0) return;
    char ts[64]; struct timeval tv; gettimeofday(&tv, NULL); struct tm *tm_info = gmtime(&tv.tv_sec);
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
    snprintf(ts + strlen(ts), sizeof(ts) - strlen(ts), ".%06dZ", (int)tv.tv_usec);

    uint64_t ns = get_mono_ns(); uint64_t seq = next_seq(); char buf[4096];
    int len = snprintf(buf, sizeof(buf), "{\"layer\":\"interpose\",\"seq\":%llu,\"ns\":%llu,\"ts\":\"%s\",\"syscall\":\"%s\",\"pid\":%d",
        (unsigned long long)seq, (unsigned long long)ns, ts, syscall_name, pid);

    if (fmt && len > 0 && len < (int)sizeof(buf) - 64) {
        va_list args; va_start(args, fmt);
        len += vsnprintf(buf + len, sizeof(buf) - (size_t)len, fmt, args); va_end(args);
    }
    if (len > 0 && len < (int)sizeof(buf) - 20) {
        if (rc != -999) len += snprintf(buf + len, sizeof(buf) - (size_t)len, ",\"rc\":%d}\n", rc);
        else len += snprintf(buf + len, sizeof(buf) - (size_t)len, "}\n");
#ifdef __linux__
        if (real_write) { real_write(trace_fd, buf, (size_t)len); return; }
#endif
        write(trace_fd, buf, (size_t)len);
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
        /* Shells */
        if (strcmp(base, "bash") == 0 || strcmp(base, "sh") == 0 || strcmp(base, "zsh") == 0 ||
            strcmp(base, "dash") == 0 || strcmp(base, "fish") == 0) {
            id.role = "shell";
        }
        /* Common utilities */
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
                 strcmp(base, "which") == 0 || strcmp(base, "whoami") == 0 || strcmp(base, "uname") == 0) {
            id.role = "utility";
        }
        /* Browsers */
        else if (strstr(base, "chrome") || strstr(base, "chromium") || strstr(base, "firefox") ||
                 strstr(base, "safari") || strstr(base, "brave")) {
            id.role = "browser";
        }
        /* Agent harnesses — direct binary match */
        else if (strcmp(base, "pi") == 0) { id.harness = "pi"; }
        else if (strcmp(base, "claude") == 0) { id.harness = "claude_code"; }
        else if (strcmp(base, "codex") == 0) { id.harness = "codex"; }
        else if (strcmp(base, "gemini") == 0) { id.harness = "gemini_cli"; }
        else if (strcmp(base, "openclaw") == 0) { id.harness = "openclaw"; }
        else if (strcmp(base, "aider") == 0) { id.harness = "aider"; }
        else if (strcmp(base, "cline") == 0) { id.harness = "cline"; }
        else if (strcmp(base, "cursor") == 0) { id.harness = "cursor"; }
        else if (strcmp(base, "opencode") == 0) { id.harness = "opencode"; }
        else if (strcmp(base, "devin") == 0) { id.harness = "devin"; }
        else if (strcmp(base, "goose") == 0) { id.harness = "goose"; }
        else if (strcmp(base, "sweep") == 0) { id.harness = "sweep"; }
    }

    /* 3. argv scanning for MCP servers and harness packages */
    if (argv) {
        for (int i = 0; argv[i] && i < 15; i++) {
            /* MCP server detection */
            if (strstr(argv[i], "@modelcontextprotocol/") || strstr(argv[i], "mcp-server") ||
                strstr(argv[i], "mcp_server")) {
                id.role = "mcp_server";
                if (strstr(argv[i], "browser-tools") || strstr(argv[i], "puppeteer") || strstr(argv[i], "playwright"))
                    id.harness = "mcp_browser";
                else if (strstr(argv[i], "git"))
                    id.harness = "mcp_git";
                else if (strstr(argv[i], "filesystem"))
                    id.harness = "mcp_filesystem";
                else if (strstr(argv[i], "sqlite"))
                    id.harness = "mcp_sqlite";
                else if (strstr(argv[i], "postgres"))
                    id.harness = "mcp_postgres";
                else if (!id.harness)
                    id.harness = "mcp_custom";
            }
            /* Harness package paths in argv */
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
        /* Special: gh copilot (binary is gh, sub-command is copilot) */
        if (base && strcmp(base, "gh") == 0 && argv[1] && strcmp(argv[1], "copilot") == 0) {
            id.harness = "copilot_cli";
        }
    }

    /* 4. Path-based fallback detection */
    if (!id.harness && path) {
        if (strstr(path, "pi-coding-agent")) id.harness = "pi";
        else if (strstr(path, "claude-code") || strstr(path, "@anthropic/claude"))
            id.harness = "claude_code";
        else if (strstr(path, "swe-agent") || strstr(path, "swe_agent"))
            id.harness = "swe_agent";
        else if (strstr(path, "openhands") || strstr(path, "opendevin"))
            id.harness = "openhands";
        else if (strstr(path, "copilot-cli") || strstr(path, "github-copilot"))
            id.harness = "copilot_cli";
        else if (strstr(path, "crewai")) id.harness = "crewai";
        else if (strstr(path, "autogen")) id.harness = "autogen";
        else if (strstr(path, "langchain")) id.harness = "langchain";
    }

    /* 5. If harness identified but role is still unknown, infer role */
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
            emit_log_event("cred_leak", getpid(), -999,
                ",\"fd\":%d,\"pattern\":\"Bearer sk-*\"", fd); return;
        }
        if (p[i] == 'x' && i + 10 <= scan_len && memcmp(p + i, "x-api-key:", 10) == 0) {
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

static void untrack_fd(int fd) { claim_fd(fd, NULL, NULL); clear_llm_fd(fd); }

static void check_tls_sni(int fd, const void *buf, size_t count) {
    if (fd < 0 || !buf || count < 47) return;
    int slot = fd & (MAX_TRACKED_FDS - 1);
    if (tracked_fds[slot].fd != fd) return;

    char ip[INET6_ADDRSTRLEN]; int port;
    if (!claim_fd(fd, ip, &port)) return;
    const unsigned char *b = (const unsigned char *)buf;
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
/*                            Constructor                             */
/* ================================================================== */

__attribute__((constructor))
static void clawsig_init(void) {
    in_hook = 1;
    for (int i = 0; i < MAX_TRACKED_FDS; i++) tracked_fds[i].fd = -1;

    RESOLVE(open); RESOLVE(openat); RESOLVE(connect); RESOLVE(bind);
    RESOLVE(listen); RESOLVE(accept); RESOLVE(socket); RESOLVE(socketpair);
    RESOLVE(pipe); RESOLVE(dup); RESOLVE(dup2); RESOLVE(sendto);
    RESOLVE(send); RESOLVE(sendmsg); RESOLVE(recv); RESOLVE(recvfrom);
    RESOLVE(recvmsg); RESOLVE(execve); RESOLVE(posix_spawn); RESOLVE(posix_spawnp);
    RESOLVE(fork); RESOLVE(vfork); RESOLVE(kill); RESOLVE(getaddrinfo);
    RESOLVE(getsockname); RESOLVE(getpeername);
#ifdef __linux__
    RESOLVE(write); RESOLVE(close); RESOLVE(open64); RESOLVE(openat64);
#endif

    const char *trace_file = getenv("CLAWSIG_TRACE_FILE");
    if (trace_file && real_open) {
        trace_fd = real_open(trace_file, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);

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
            ",\"harness\":\"%s\",\"role\":\"%s\"",
            id.harness ? id.harness : "unknown", id.role);
    }
    in_hook = 0;
}

/* ================================================================== */
/*                  THE HOOKS — Process Lifecycle                     */
/* ================================================================== */

pid_t HOOK_NAME(fork)(void) {
    RESOLVE(fork); if (in_hook || trace_fd < 0) return CALL_REAL(fork);
    in_hook = 1; pid_t rc = CALL_REAL(fork); int saved_errno = errno;
    if (rc > 0) emit_log_event("fork", getpid(), rc, ",\"child_pid\":%d", rc);
    in_hook = 0; errno = saved_errno; return rc;
}

pid_t HOOK_NAME(vfork)(void) {
    RESOLVE(vfork); if (in_hook || trace_fd < 0) return CALL_REAL(vfork);
    in_hook = 1; pid_t rc = CALL_REAL(vfork); int saved_errno = errno;
    if (rc > 0) emit_log_event("vfork", getpid(), rc, ",\"child_pid\":%d", rc);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(execve)(const char *pathname, char *const argv[], char *const envp[]) {
    RESOLVE(execve); if (in_hook || trace_fd < 0) return CALL_REAL(execve, pathname, argv, envp);
    in_hook = 1;
    char path_esc[1024], argv_json[4096];
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

    audit_env(envp); in_hook = 0;
    int rc = CALL_REAL(execve, pathname, argv, envp); int saved_errno = errno;
    in_hook = 1;
    emit_log_event("execve_failed", getpid(), rc, ",\"path\":\"%s\"", path_esc);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(posix_spawn)(pid_t *restrict pid, const char *restrict path,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
    char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawn); if (in_hook || trace_fd < 0)
        return CALL_REAL(posix_spawn, pid, path, fa, attr, argv, envp);
    in_hook = 1; audit_env(envp);
    int rc = CALL_REAL(posix_spawn, pid, path, fa, attr, argv, envp);
    int saved_errno = errno;

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

    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(posix_spawnp)(pid_t *restrict pid, const char *restrict file,
    const posix_spawn_file_actions_t *fa, const posix_spawnattr_t *restrict attr,
    char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawnp); if (in_hook || trace_fd < 0)
        return CALL_REAL(posix_spawnp, pid, file, fa, attr, argv, envp);
    in_hook = 1; audit_env(envp);
    int rc = CALL_REAL(posix_spawnp, pid, file, fa, attr, argv, envp);
    int saved_errno = errno;

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

    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(kill)(pid_t pid, int sig) {
    RESOLVE(kill); if (in_hook || trace_fd < 0) return CALL_REAL(kill, pid, sig);
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
    emit_log_event("bind", getpid(), rc,
        ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"", sockfd, ip, port, family);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(listen)(int sockfd, int backlog) {
    RESOLVE(listen); if (in_hook || trace_fd < 0) return CALL_REAL(listen, sockfd, backlog);
    in_hook = 1; int rc = CALL_REAL(listen, sockfd, backlog); int saved_errno = errno;
    emit_log_event("listen", getpid(), rc,
        ",\"fd\":%d,\"backlog\":%d", sockfd, backlog);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(accept)(int sockfd, struct sockaddr *restrict addr, socklen_t *restrict addrlen) {
    RESOLVE(accept); if (in_hook || trace_fd < 0) return CALL_REAL(accept, sockfd, addr, addrlen);
    in_hook = 1; int rc = CALL_REAL(accept, sockfd, addr, addrlen); int saved_errno = errno;
    if (rc >= 0) untrack_fd(rc);
    char ip[INET6_ADDRSTRLEN] = ""; int port = 0; const char *family = "UNKNOWN";
    if (addr) format_addr(addr, ip, sizeof(ip), &port, &family);
    emit_log_event("accept", getpid(), rc,
        ",\"server_fd\":%d,\"client_fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\"",
        sockfd, rc, ip, port, family);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(socket)(int domain, int type, int protocol) {
    RESOLVE(socket); if (in_hook || trace_fd < 0) return CALL_REAL(socket, domain, type, protocol);
    in_hook = 1; int rc = CALL_REAL(socket, domain, type, protocol); int saved_errno = errno;
    if (rc >= 0) emit_log_event("socket", getpid(), rc,
        ",\"domain\":%d,\"type\":%d,\"protocol\":%d", domain, type, protocol);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(pipe)(int pipefd[2]) {
    RESOLVE(pipe); if (in_hook || trace_fd < 0) return CALL_REAL(pipe, pipefd);
    in_hook = 1; int rc = CALL_REAL(pipe, pipefd); int saved_errno = errno;
    if (rc == 0) emit_log_event("pipe", getpid(), rc,
        ",\"read_fd\":%d,\"write_fd\":%d", pipefd[0], pipefd[1]);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(socketpair)(int domain, int type, int protocol, int sv[2]) {
    RESOLVE(socketpair); if (in_hook || trace_fd < 0)
        return CALL_REAL(socketpair, domain, type, protocol, sv);
    in_hook = 1; int rc = CALL_REAL(socketpair, domain, type, protocol, sv);
    int saved_errno = errno;
    if (rc == 0) emit_log_event("socketpair", getpid(), rc,
        ",\"domain\":%d,\"type\":%d,\"fd0\":%d,\"fd1\":%d", domain, type, sv[0], sv[1]);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(dup)(int oldfd) {
    RESOLVE(dup); if (in_hook || trace_fd < 0) return CALL_REAL(dup, oldfd);
    in_hook = 1; int rc = CALL_REAL(dup, oldfd); int saved_errno = errno;
    if (rc >= 0) emit_log_event("dup", getpid(), rc, ",\"oldfd\":%d", oldfd);
    in_hook = 0; errno = saved_errno; return rc;
}

int HOOK_NAME(dup2)(int oldfd, int newfd) {
    RESOLVE(dup2); if (in_hook || trace_fd < 0) return CALL_REAL(dup2, oldfd, newfd);
    in_hook = 1; int rc = CALL_REAL(dup2, oldfd, newfd); int saved_errno = errno;
    if (rc >= 0) untrack_fd(newfd);
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
        scan_credentials(sockfd, buf, len); in_hook = 0;
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
                parsed = 1; break;
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
    if (ip_str[0] && strcmp(family, "UNKNOWN") != 0)
        emit_log_event("sendto", getpid(), -999,
            ",\"fd\":%d,\"addr\":\"%s\",\"port\":%d,\"family\":\"%s\",\"len\":%zu",
            sockfd, ip_str, port, family, len);
    in_hook = 0; errno = saved_errno; return rc;
}

ssize_t HOOK_NAME(recv)(int sockfd, void *buf, size_t len, int flags) {
    RESOLVE(recv); ssize_t rc = CALL_REAL(recv, sockfd, buf, len, flags);
    if (!in_hook && trace_fd >= 0 && rc > 0 && is_llm_fd(sockfd)) {
        in_hook = 1;
        int is_sse = (rc >= 6 && memcmp(buf, "data: ", 6) == 0) ? 1 : 0;
        emit_log_event("recv_llm", getpid(), -999,
            ",\"fd\":%d,\"bytes\":%zd,\"sse\":%d", sockfd, rc, is_sse);
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
        int is_sse = (rc >= 6 && memcmp(buf, "data: ", 6) == 0) ? 1 : 0;
        emit_log_event("recv_llm", getpid(), -999,
            ",\"fd\":%d,\"bytes\":%zd,\"sse\":%d", sockfd, rc, is_sse);
        in_hook = 0;
    }
    return rc;
}

ssize_t HOOK_NAME(recvmsg)(int sockfd, struct msghdr *msg, int flags) {
    RESOLVE(recvmsg); ssize_t rc = CALL_REAL(recvmsg, sockfd, msg, flags);
    if (!in_hook && trace_fd >= 0 && rc > 0 && is_llm_fd(sockfd) &&
        msg && msg->msg_iovlen > 0 && msg->msg_iov[0].iov_base) {
        in_hook = 1;
        int is_sse = (rc >= 6 && memcmp(msg->msg_iov[0].iov_base, "data: ", 6) == 0) ? 1 : 0;
        emit_log_event("recv_llm", getpid(), -999,
            ",\"fd\":%d,\"bytes\":%zd,\"sse\":%d", sockfd, rc, is_sse);
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
#endif
