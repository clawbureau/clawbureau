/**
 * Clawsig Interposition Library — Layer 6 Syscall Observability
 *
 * Hooks libc wrappers via LD_PRELOAD (Linux) / DYLD_INSERT_LIBRARIES (macOS)
 * to observe connect(), open(), openat(), execve(), posix_spawn(), sendto(),
 * and extract TLS ClientHello SNI via send(), sendmsg(), getaddrinfo() and write().
 *
 * Platform strategy:
 * - Linux: LD_PRELOAD symbol override (hooks use real function names)
 * - macOS: DYLD_INTERPOSE __DATA,__interpose section. Avoids hooking write()
 *   and close() which cause SIGABRT during dyld bootstrap on ARM64. Uses 
 *   getaddrinfo() as an SNI fallback for runtimes that bypass send().
 *
 * Design constraints:
 * - Zero malloc in hot path (all buffers on stack)
 * - Thread-safe lock-free FD tracking and DNS caching via atomic operations
 * - Hot path overhead < 5ns via direct power-of-two slot mapping
 * - POSIX guarantees write() < PIPE_BUF (4096) is atomic
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
#include <sys/uio.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <spawn.h>
#include <errno.h>

#ifndef O_TMPFILE
#define O_TMPFILE 0
#endif

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/* ---------- Thread-local reentrancy guard ---------- */
static __thread int in_hook = 0;

/* ---------- Pre-opened trace file descriptor ---------- */
static int trace_fd = -1;

/* ---------- Lock-free DNS Cache Table (macOS Fallback) ---------- */
#define MAX_DNS_CACHE 256

typedef struct {
    volatile int in_use;
    char ip[INET6_ADDRSTRLEN];
    char hostname[256];
} dns_cache_t;

static dns_cache_t dns_cache[MAX_DNS_CACHE];

/* ---------- Lock-free TLS FD Tracking Table ---------- */
#define MAX_TRACKED_FDS 1024

typedef struct {
    volatile int fd;
    int port;
    char ip[INET6_ADDRSTRLEN];
} tracked_fd_t;

/* Array sized by power-of-two for fast bitwise modulo mapping */
static tracked_fd_t tracked_fds[MAX_TRACKED_FDS];

/* ---------- Real libc function pointers ---------- */
typedef int (*open_func_t)(const char *, int, ...);
typedef int (*openat_func_t)(int, const char *, int, ...);
typedef int (*connect_func_t)(int, const struct sockaddr *, socklen_t);
typedef ssize_t (*sendto_func_t)(int, const void *, size_t, int,
                                  const struct sockaddr *, socklen_t);
typedef int (*execve_func_t)(const char *, char *const[], char *const[]);
typedef int (*posix_spawn_func_t)(pid_t *restrict, const char *restrict,
                                   const posix_spawn_file_actions_t *,
                                   const posix_spawnattr_t *restrict,
                                   char *const[restrict], char *const[restrict]);
typedef ssize_t (*send_func_t)(int, const void *, size_t, int);
typedef ssize_t (*sendmsg_func_t)(int, const struct msghdr *, int);
typedef int (*getaddrinfo_func_t)(const char *restrict, const char *restrict,
                                  const struct addrinfo *restrict,
                                  struct addrinfo **restrict);

static open_func_t        real_open         = NULL;
static openat_func_t      real_openat       = NULL;
static connect_func_t     real_connect      = NULL;
static sendto_func_t      real_sendto       = NULL;
static execve_func_t      real_execve       = NULL;
static posix_spawn_func_t real_posix_spawn  = NULL;
static posix_spawn_func_t real_posix_spawnp = NULL;
static send_func_t        real_send         = NULL;
static sendmsg_func_t     real_sendmsg      = NULL;
static getaddrinfo_func_t real_getaddrinfo  = NULL;

#ifdef __linux__
typedef ssize_t (*write_func_t)(int, const void *, size_t);
typedef int (*close_func_t)(int);
typedef int (*open64_func_t)(const char *, int, ...);
typedef int (*openat64_func_t)(int, const char *, int, ...);

static write_func_t    real_write    = NULL;
static close_func_t    real_close    = NULL;
static open64_func_t   real_open64   = NULL;
static openat64_func_t real_openat64 = NULL;
#endif

/* Lazy symbol resolution */
#define RESOLVE(name) \
    if (!real_##name) { \
        real_##name = (typeof(real_##name))dlsym(RTLD_NEXT, #name); \
    }

/* ---- macOS DYLD_INTERPOSE machinery ---- */
#ifdef __APPLE__
#define DYLD_INTERPOSE(_replacement, _replacee) \
    __attribute__((used)) static struct { \
        const void* replacement; \
        const void* replacee; \
    } _interpose_##_replacee \
    __attribute__((section("__DATA,__interpose"))) = { \
        (const void*)(unsigned long)&_replacement, \
        (const void*)(unsigned long)&_replacee \
    };

#define HOOK_NAME(name) clawsig_##name
#define CALL_REAL(name, ...) name(__VA_ARGS__)
#else
#define HOOK_NAME(name) name
#define CALL_REAL(name, ...) real_##name(__VA_ARGS__)
#endif

/* ---------- Constructor: init on library load ---------- */
__attribute__((constructor))
static void clawsig_init(void) {
    in_hook = 1;

    for (int i = 0; i < MAX_TRACKED_FDS; i++) {
        tracked_fds[i].fd = -1;
    }

    RESOLVE(open);
    RESOLVE(openat);
    RESOLVE(connect);
    RESOLVE(sendto);
    RESOLVE(execve);
    RESOLVE(posix_spawn);
    RESOLVE(posix_spawnp);
    RESOLVE(send);
    RESOLVE(sendmsg);
    RESOLVE(getaddrinfo);

#ifdef __linux__
    RESOLVE(write);
    RESOLVE(close);
    RESOLVE(open64);
    RESOLVE(openat64);
#endif

    const char *trace_file = getenv("CLAWSIG_TRACE_FILE");
    if (trace_file && real_open) {
        trace_fd = real_open(trace_file,
                             O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0666);
    }

    in_hook = 0;
}

/* ---------- Helpers ---------- */

static void get_timestamp(char *buf, size_t len) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    struct tm *tm_info = gmtime(&tv.tv_sec);
    char ts[32];
    strftime(ts, sizeof(ts), "%Y-%m-%dT%H:%M:%S", tm_info);
    snprintf(buf, len, "%s.%06dZ", ts, (int)tv.tv_usec);
}

static void escape_json(const char *src, char *dest, size_t dest_len) {
    if (!src) { if (dest_len > 0) dest[0] = '\0'; return; }
    size_t i = 0, j = 0;
    while (src[i] && j < dest_len - 3) {
        switch (src[i]) {
            case '"':  dest[j++] = '\\'; dest[j++] = '"'; break;
            case '\\': dest[j++] = '\\'; dest[j++] = '\\'; break;
            case '\n': dest[j++] = '\\'; dest[j++] = 'n'; break;
            case '\r': dest[j++] = '\\'; dest[j++] = 'r'; break;
            case '\t': dest[j++] = '\\'; dest[j++] = 't'; break;
            default:
                if ((unsigned char)src[i] >= 0x20) dest[j++] = src[i];
                break;
        }
        i++;
    }
    dest[j] = '\0';
}

static void format_argv(char *const arr[], char *out, size_t out_len) {
    if (!arr) { strncpy(out, "[]", out_len); return; }
    size_t j = 0;
    out[j++] = '[';
    for (int i = 0; arr[i] && j < out_len - 5; i++) {
        if (i > 0) out[j++] = ',';
        out[j++] = '"';
        char esc[512];
        escape_json(arr[i], esc, sizeof(esc));
        size_t len = strlen(esc);
        if (j + len < out_len - 3) { strncpy(out + j, esc, len); j += len; }
        out[j++] = '"';
    }
    out[j++] = ']';
    out[j] = '\0';
}

static void format_addr(const struct sockaddr *addr, char *ip, size_t ip_len,
                         int *port, const char **family) {
    *port = 0; *family = "UNKNOWN"; ip[0] = '\0';
    if (!addr) return;
    if (addr->sa_family == AF_INET) {
        struct sockaddr_in *s = (struct sockaddr_in *)addr;
        inet_ntop(AF_INET, &s->sin_addr, ip, (socklen_t)ip_len);
        *port = ntohs(s->sin_port);
        *family = "AF_INET";
    } else if (addr->sa_family == AF_INET6) {
        struct sockaddr_in6 *s = (struct sockaddr_in6 *)addr;
        inet_ntop(AF_INET6, &s->sin6_addr, ip, (socklen_t)ip_len);
        *port = ntohs(s->sin6_port);
        *family = "AF_INET6";
    } else if (addr->sa_family == AF_UNIX) {
        *family = "AF_UNIX";
        strncpy(ip, "local_socket", ip_len);
    }
}

static const char* get_access_mode(int flags) {
    int mode = flags & O_ACCMODE;
    if (mode == O_RDONLY) return "O_RDONLY";
    if (mode == O_WRONLY) return "O_WRONLY";
    if (mode == O_RDWR)   return "O_RDWR";
    return "UNKNOWN";
}

/* Single atomic write < PIPE_BUF — thread-safe, lock-free */
static void emit_log(const char *payload) {
    if (trace_fd >= 0) {
#ifdef __linux__
        if (real_write) {
            real_write(trace_fd, payload, strlen(payload));
            return;
        }
#endif
        write(trace_fd, payload, strlen(payload));
    }
}

/* ================================================================== */
/*                       DNS Hostname Tracking                        */
/* ================================================================== */

static unsigned int hash_ip(const char *ip) {
    unsigned int hash = 5381;
    int c;
    while ((c = *ip++))
        hash = ((hash << 5) + hash) + c;
    return hash;
}

static void cache_dns(const char *ip, const char *hostname) {
    if (!ip || !hostname) return;
    int slot = hash_ip(ip) & (MAX_DNS_CACHE - 1);

    dns_cache[slot].in_use = 0;
    __sync_synchronize();

    strncpy(dns_cache[slot].ip, ip, INET6_ADDRSTRLEN - 1);
    dns_cache[slot].ip[INET6_ADDRSTRLEN - 1] = '\0';
    strncpy(dns_cache[slot].hostname, hostname, 255);
    dns_cache[slot].hostname[255] = '\0';

    __sync_synchronize();
    dns_cache[slot].in_use = 1;
}

static int lookup_dns(const char *ip, char *hostname_out) {
    if (!ip) return 0;
    int slot = hash_ip(ip) & (MAX_DNS_CACHE - 1);

    if (dns_cache[slot].in_use && strcmp(dns_cache[slot].ip, ip) == 0) {
        strncpy(hostname_out, dns_cache[slot].hostname, 256);
        return 1;
    }
    return 0;
}

int HOOK_NAME(getaddrinfo)(const char *restrict node, const char *restrict service,
                           const struct addrinfo *restrict hints,
                           struct addrinfo **restrict res) {
    RESOLVE(getaddrinfo);
    if (in_hook || trace_fd < 0 || !node)
        return CALL_REAL(getaddrinfo, node, service, hints, res);

    in_hook = 1;
    int rc = CALL_REAL(getaddrinfo, node, service, hints, res);

    if (rc == 0 && res && *res) {
        for (struct addrinfo *p = *res; p != NULL; p = p->ai_next) {
            char ip_str[INET6_ADDRSTRLEN] = "";
            if (p->ai_family == AF_INET) {
                struct sockaddr_in *s = (struct sockaddr_in *)p->ai_addr;
                inet_ntop(AF_INET, &s->sin_addr, ip_str, (socklen_t)sizeof(ip_str));
            } else if (p->ai_family == AF_INET6) {
                struct sockaddr_in6 *s = (struct sockaddr_in6 *)p->ai_addr;
                inet_ntop(AF_INET6, &s->sin6_addr, ip_str, (socklen_t)sizeof(ip_str));
            }
            if (ip_str[0] != '\0') {
                cache_dns(ip_str, node);
            }
        }
    }
    in_hook = 0;
    return rc;
}

/* ================================================================== */
/*                    TLS SNI Extraction & Tracking                   */
/* ================================================================== */

static void track_fd(int fd, const char *ip, int port) {
    if (fd < 0 || port != 443) return;
    int slot = fd & (MAX_TRACKED_FDS - 1);

    tracked_fds[slot].fd = -1;
    __sync_synchronize();

    strncpy(tracked_fds[slot].ip, ip, INET6_ADDRSTRLEN - 1);
    tracked_fds[slot].ip[INET6_ADDRSTRLEN - 1] = '\0';
    tracked_fds[slot].port = port;

    __sync_synchronize();
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

static int extract_sni(const unsigned char *buf, size_t len, char *out_sni, size_t out_len) {
    if (!buf || len < 47) return 0;
    if (buf[0] != 0x16 || buf[1] != 0x03) return 0;
    if (buf[5] != 0x01) return 0;

    size_t pos = 5;
    pos += 4;
    pos += 2;
    pos += 32;

    if (pos >= len) return 0;
    size_t session_id_len = buf[pos];
    pos += 1 + session_id_len;

    if (pos + 2 > len) return 0;
    size_t cipher_suites_len = (buf[pos] << 8) | buf[pos+1];
    pos += 2 + cipher_suites_len;

    if (pos + 1 > len) return 0;
    size_t comp_methods_len = buf[pos];
    pos += 1 + comp_methods_len;

    if (pos + 2 > len) return 0;
    size_t ext_total_len = (buf[pos] << 8) | buf[pos+1];
    pos += 2;

    size_t ext_end = pos + ext_total_len;
    if (ext_end > len) ext_end = len;

    while (pos + 4 <= ext_end) {
        int ext_type = (buf[pos] << 8) | buf[pos+1];
        size_t ext_len = (buf[pos+2] << 8) | buf[pos+3];
        pos += 4;

        if (pos + ext_len > ext_end) break;

        if (ext_type == 0x0000 && ext_len >= 5) {
            size_t p = pos;
            /* size_t list_len = (buf[p] << 8) | buf[p+1]; */
            p += 2;
            while (p + 3 <= pos + ext_len) {
                int name_type = buf[p];
                size_t name_len = (buf[p+1] << 8) | buf[p+2];
                p += 3;

                if (p + name_len > pos + ext_len) break;

                if (name_type == 0) {
                    size_t copy_len = name_len < out_len - 1 ? name_len : out_len - 1;
                    memcpy(out_sni, buf + p, copy_len);
                    out_sni[copy_len] = '\0';
                    return 1;
                }
                p += name_len;
            }
        }
        pos += ext_len;
    }
    return 0;
}

static void check_tls_sni(int fd, const void *buf, size_t count) {
    if (fd < 0 || !buf || count == 0) return;

    int slot = fd & (MAX_TRACKED_FDS - 1);
    if (tracked_fds[slot].fd != fd) return;

    char ip[INET6_ADDRSTRLEN];
    int port;
    if (claim_fd(fd, ip, &port)) {
        char sni[256];
        if (extract_sni((const unsigned char *)buf, count, sni, sizeof(sni))) {
            char sni_esc[512];
            escape_json(sni, sni_esc, sizeof(sni_esc));
            char ts[64], log_buf[1024];
            get_timestamp(ts, sizeof(ts));
            snprintf(log_buf, sizeof(log_buf),
                "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"tls_sni\","
                "\"pid\":%d,\"fd\":%d,\"hostname\":\"%s\",\"addr\":\"%s\",\"port\":%d}\n",
                ts, getpid(), fd, sni_esc, ip, port);
            emit_log(log_buf);
        }
    }
}

/* ================================================================== */
/*                          THE HOOKS                                 */
/* ================================================================== */

int HOOK_NAME(connect)(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    RESOLVE(connect);
    if (in_hook || trace_fd < 0 || !addr)
        return CALL_REAL(connect, sockfd, addr, addrlen);

    in_hook = 1;

    claim_fd(sockfd, NULL, NULL);

    int rc = CALL_REAL(connect, sockfd, addr, addrlen);
    int saved_errno = errno;

    char ip_str[INET6_ADDRSTRLEN] = "UNKNOWN";
    int port; const char *family;
    format_addr(addr, ip_str, sizeof(ip_str), &port, &family);

    if (strcmp(family, "UNKNOWN") != 0 &&
        strncmp(ip_str, "127.", 4) != 0 &&
        strcmp(ip_str, "::1") != 0) {

        if (port == 443) {
            char dns_hostname[256];
            int emitted_sni = 0;

            if (lookup_dns(ip_str, dns_hostname)) {
                char sni_esc[512];
                escape_json(dns_hostname, sni_esc, sizeof(sni_esc));
                char ts_sni[64], sni_log[1024];
                get_timestamp(ts_sni, sizeof(ts_sni));
                snprintf(sni_log, sizeof(sni_log),
                    "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"tls_sni\","
                    "\"pid\":%d,\"fd\":%d,\"hostname\":\"%s\",\"addr\":\"%s\",\"port\":%d}\n",
                    ts_sni, getpid(), sockfd, sni_esc, ip_str, port);
                emit_log(sni_log);
                emitted_sni = 1;
            }

            if (!emitted_sni && (rc == 0 || (rc == -1 && saved_errno == EINPROGRESS))) {
                track_fd(sockfd, ip_str, port);
            }
        }

        char ts[64], log_buf[1024];
        get_timestamp(ts, sizeof(ts));
        snprintf(log_buf, sizeof(log_buf),
            "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"connect\","
            "\"pid\":%d,\"fd\":%d,\"addr\":\"%s\",\"port\":%d,"
            "\"family\":\"%s\",\"rc\":%d}\n",
            ts, getpid(), sockfd, ip_str, port, family, rc);
        emit_log(log_buf);
    }

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

ssize_t HOOK_NAME(send)(int sockfd, const void *buf, size_t len, int flags) {
    RESOLVE(send);
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1;
        check_tls_sni(sockfd, buf, len);
        in_hook = 0;
    }
    return CALL_REAL(send, sockfd, buf, len, flags);
}

ssize_t HOOK_NAME(sendmsg)(int sockfd, const struct msghdr *msg, int flags) {
    RESOLVE(sendmsg);
    if (!in_hook && trace_fd >= 0 && msg && msg->msg_iov && msg->msg_iovlen > 0) {
        in_hook = 1;
        int parsed = 0;
        for (size_t i = 0; i < (size_t)msg->msg_iovlen; i++) {
            if (msg->msg_iov[i].iov_base && msg->msg_iov[i].iov_len > 0) {
                check_tls_sni(sockfd, msg->msg_iov[i].iov_base, msg->msg_iov[i].iov_len);
                parsed = 1;
                break;
            }
        }
        if (!parsed) {
            claim_fd(sockfd, NULL, NULL);
        }
        in_hook = 0;
    }
    return CALL_REAL(sendmsg, sockfd, msg, flags);
}

ssize_t HOOK_NAME(sendto)(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    RESOLVE(sendto);

    if (!in_hook && trace_fd >= 0) {
        in_hook = 1;
        check_tls_sni(sockfd, buf, len);
        in_hook = 0;
    }

    if (in_hook || trace_fd < 0 || !dest_addr)
        return CALL_REAL(sendto, sockfd, buf, len, flags, dest_addr, addrlen);

    in_hook = 1;
    ssize_t rc = CALL_REAL(sendto, sockfd, buf, len, flags, dest_addr, addrlen);
    int saved_errno = errno;

    char ip_str[INET6_ADDRSTRLEN] = {0};
    int port; const char *family;
    format_addr(dest_addr, ip_str, sizeof(ip_str), &port, &family);

    if (ip_str[0] != '\0' && strcmp(family, "UNKNOWN") != 0 &&
        strncmp(ip_str, "127.", 4) != 0 && strcmp(ip_str, "::1") != 0) {
        char ts[64], log_buf[1024];
        get_timestamp(ts, sizeof(ts));
        snprintf(log_buf, sizeof(log_buf),
            "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"sendto\","
            "\"pid\":%d,\"fd\":%d,\"addr\":\"%s\",\"port\":%d,"
            "\"family\":\"%s\",\"len\":%zu,\"rc\":%zd}\n",
            ts, getpid(), sockfd, ip_str, port, family, len, rc);
        emit_log(log_buf);
    }

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

int HOOK_NAME(open)(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(open);
    if (in_hook || trace_fd < 0)
        return CALL_REAL(open, pathname, flags, mode);

    in_hook = 1;
    int rc = CALL_REAL(open, pathname, flags, mode);
    if (rc >= 0) claim_fd(rc, NULL, NULL);
    int saved_errno = errno;

    char ts[64], path_esc[1024], log_buf[2048];
    get_timestamp(ts, sizeof(ts));
    escape_json(pathname, path_esc, sizeof(path_esc));
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"open\","
        "\"pid\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"rc\":%d}\n",
        ts, getpid(), path_esc, get_access_mode(flags), rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

int HOOK_NAME(openat)(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(openat);
    if (in_hook || trace_fd < 0)
        return CALL_REAL(openat, dirfd, pathname, flags, mode);

    in_hook = 1;
    int rc = CALL_REAL(openat, dirfd, pathname, flags, mode);
    if (rc >= 0) claim_fd(rc, NULL, NULL);
    int saved_errno = errno;

    char ts[64], path_esc[1024], log_buf[2048];
    get_timestamp(ts, sizeof(ts));
    escape_json(pathname, path_esc, sizeof(path_esc));
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"openat\","
        "\"pid\":%d,\"dirfd\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"rc\":%d}\n",
        ts, getpid(), dirfd, path_esc, get_access_mode(flags), rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

int HOOK_NAME(execve)(const char *pathname, char *const argv[], char *const envp[]) {
    RESOLVE(execve);
    if (in_hook || trace_fd < 0)
        return CALL_REAL(execve, pathname, argv, envp);

    in_hook = 1;
    char ts[64], path_esc[1024], argv_json[4096], log_buf[6144];
    get_timestamp(ts, sizeof(ts));
    escape_json(pathname, path_esc, sizeof(path_esc));
    format_argv(argv, argv_json, sizeof(argv_json));

    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"execve\","
        "\"pid\":%d,\"path\":\"%s\",\"argv\":%s,\"rc\":0}\n",
        ts, getpid(), path_esc, argv_json);
    emit_log(log_buf);
    in_hook = 0;

    int rc = CALL_REAL(execve, pathname, argv, envp);
    int saved_errno = errno;

    in_hook = 1;
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"execve_failed\","
        "\"pid\":%d,\"path\":\"%s\",\"rc\":%d}\n",
        ts, getpid(), path_esc, rc);
    emit_log(log_buf);
    in_hook = 0;

    errno = saved_errno;
    return rc;
}

int HOOK_NAME(posix_spawn)(pid_t *restrict pid, const char *restrict path,
                const posix_spawn_file_actions_t *file_actions,
                const posix_spawnattr_t *restrict attrp,
                char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawn);
    if (in_hook || trace_fd < 0)
        return CALL_REAL(posix_spawn, pid, path, file_actions, attrp, argv, envp);

    in_hook = 1;
    char ts[64], path_esc[1024], argv_json[4096], log_buf[6144];
    get_timestamp(ts, sizeof(ts));
    escape_json(path, path_esc, sizeof(path_esc));
    format_argv(argv, argv_json, sizeof(argv_json));

    int rc = CALL_REAL(posix_spawn, pid, path, file_actions, attrp, argv, envp);
    int saved_errno = errno;

    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"posix_spawn\","
        "\"pid\":%d,\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"rc\":%d}\n",
        ts, getpid(), path_esc, argv_json, pid ? *pid : -1, rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

int HOOK_NAME(posix_spawnp)(pid_t *restrict pid, const char *restrict file,
                 const posix_spawn_file_actions_t *file_actions,
                 const posix_spawnattr_t *restrict attrp,
                 char *const argv[restrict], char *const envp[restrict]) {
    RESOLVE(posix_spawnp);
    if (in_hook || trace_fd < 0)
        return CALL_REAL(posix_spawnp, pid, file, file_actions, attrp, argv, envp);

    in_hook = 1;
    char ts[64], file_esc[1024], argv_json[4096], log_buf[6144];
    get_timestamp(ts, sizeof(ts));
    escape_json(file, file_esc, sizeof(file_esc));
    format_argv(argv, argv_json, sizeof(argv_json));

    int rc = CALL_REAL(posix_spawnp, pid, file, file_actions, attrp, argv, envp);
    int saved_errno = errno;

    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"posix_spawnp\","
        "\"pid\":%d,\"path\":\"%s\",\"argv\":%s,\"child_pid\":%d,\"rc\":%d}\n",
        ts, getpid(), file_esc, argv_json, pid ? *pid : -1, rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

/* ---------- Linux-specific write() and close() extensions ---------- */
#ifdef __linux__

ssize_t write(int fd, const void *buf, size_t count) {
    RESOLVE(write);
    if (!in_hook && trace_fd >= 0) {
        in_hook = 1;
        check_tls_sni(fd, buf, count);
        in_hook = 0;
    }
    return real_write ? real_write(fd, buf, count) : -1;
}

int close(int fd) {
    RESOLVE(close);
    if (!in_hook) {
        in_hook = 1;
        claim_fd(fd, NULL, NULL);
        in_hook = 0;
    }
    return real_close ? real_close(fd) : -1;
}

int open64(const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(open64);
    if (in_hook || trace_fd < 0)
        return real_open64 ? real_open64(pathname, flags, mode) : -1;

    in_hook = 1;
    int rc = real_open64(pathname, flags, mode);
    if (rc >= 0) claim_fd(rc, NULL, NULL);
    int saved_errno = errno;

    char ts[64], path_esc[1024], log_buf[2048];
    get_timestamp(ts, sizeof(ts));
    escape_json(pathname, path_esc, sizeof(path_esc));
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"open64\","
        "\"pid\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"rc\":%d}\n",
        ts, getpid(), path_esc, get_access_mode(flags), rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

int openat64(int dirfd, const char *pathname, int flags, ...) {
    mode_t mode = 0;
    if (flags & (O_CREAT | O_TMPFILE)) {
        va_list args; va_start(args, flags);
        mode = va_arg(args, int); va_end(args);
    }
    RESOLVE(openat64);
    if (in_hook || trace_fd < 0)
        return real_openat64 ? real_openat64(dirfd, pathname, flags, mode) : -1;

    in_hook = 1;
    int rc = real_openat64(dirfd, pathname, flags, mode);
    if (rc >= 0) claim_fd(rc, NULL, NULL);
    int saved_errno = errno;

    char ts[64], path_esc[1024], log_buf[2048];
    get_timestamp(ts, sizeof(ts));
    escape_json(pathname, path_esc, sizeof(path_esc));
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"openat64\","
        "\"pid\":%d,\"dirfd\":%d,\"path\":\"%s\",\"flags\":\"%s\",\"rc\":%d}\n",
        ts, getpid(), dirfd, path_esc, get_access_mode(flags), rc);
    emit_log(log_buf);

    in_hook = 0;
    errno = saved_errno;
    return rc;
}

#endif /* __linux__ */

/* ================================================================== */
/*        macOS DYLD_INTERPOSE registration (ARM64 compatible)        */
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
/* Deliberately excluding write() and close() — dyld bootstrap SIGABRT on ARM64 */
#endif
