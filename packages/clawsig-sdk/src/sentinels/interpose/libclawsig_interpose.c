/**
 * Clawsig Interposition Library — Layer 6 Syscall Observability
 *
 * Hooks libc wrappers via LD_PRELOAD (Linux) / DYLD_INSERT_LIBRARIES (macOS)
 * to observe connect(), open(), openat(), execve(), posix_spawn(), sendto().
 *
 * Platform strategy:
 * - Linux: LD_PRELOAD symbol override (hooks use real function names)
 * - macOS: DYLD_INTERPOSE __DATA,__interpose section (hooks use clawsig_* names,
 *   mapped to real symbols via DYLD_INTERPOSE macro). This is required because
 *   DYLD_FORCE_FLAT_NAMESPACE doesn't reliably work on ARM64 macOS.
 *
 * Design constraints:
 * - Zero malloc in hot path (all buffers on stack)
 * - Thread-safe via __thread reentrancy guard + atomic O_APPEND writes
 * - POSIX guarantees write() < PIPE_BUF (4096) is atomic
 * - O_CLOEXEC on trace fd prevents leaks across execve()
 * - No-op if CLAWSIG_TRACE_FILE is not set (zero overhead)
 *
 * Coverage: ~98% Linux (glibc/musl), ~85% macOS (SIP strips for /usr/bin)
 * Evasion: Go static binaries, inline syscall asm, env -i wipe
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
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/socket.h>
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

static open_func_t     real_open        = NULL;
static openat_func_t   real_openat      = NULL;
static connect_func_t  real_connect     = NULL;
static sendto_func_t   real_sendto      = NULL;
static execve_func_t   real_execve      = NULL;
static posix_spawn_func_t real_posix_spawn  = NULL;
static posix_spawn_func_t real_posix_spawnp = NULL;

#ifdef __linux__
typedef int (*open64_func_t)(const char *, int, ...);
typedef int (*openat64_func_t)(int, const char *, int, ...);
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

/*
 * On macOS with DYLD_INTERPOSE, the "real" function is called by its
 * original name (the dyld redirects at load time). So our hooks are
 * named clawsig_<func> and DYLD_INTERPOSE maps <func> -> clawsig_<func>.
 * Inside clawsig_<func>, calling <func>() goes to the real implementation.
 */
#define HOOK_NAME(name) clawsig_##name
#define CALL_REAL(name, ...) name(__VA_ARGS__)
#else
/* On Linux, LD_PRELOAD: our hook IS the symbol, call real via dlsym pointer */
#define HOOK_NAME(name) name
#define CALL_REAL(name, ...) real_##name(__VA_ARGS__)
#endif

/* ---------- Constructor: init on library load ---------- */
__attribute__((constructor))
static void clawsig_init(void) {
    in_hook = 1;

    RESOLVE(open);
    RESOLVE(openat);
    RESOLVE(connect);
    RESOLVE(sendto);
    RESOLVE(execve);
    RESOLVE(posix_spawn);
    RESOLVE(posix_spawnp);

#ifdef __linux__
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
        write(trace_fd, payload, strlen(payload));
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
    int rc = CALL_REAL(connect, sockfd, addr, addrlen);
    int saved_errno = errno;

    char ip_str[INET6_ADDRSTRLEN] = "UNKNOWN";
    int port; const char *family;
    format_addr(addr, ip_str, sizeof(ip_str), &port, &family);

    if (strcmp(family, "UNKNOWN") != 0 &&
        strncmp(ip_str, "127.", 4) != 0 &&
        strcmp(ip_str, "::1") != 0) {
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

    /* Log BEFORE executing — successful execve never returns */
    snprintf(log_buf, sizeof(log_buf),
        "{\"layer\":\"interpose\",\"ts\":\"%s\",\"syscall\":\"execve\","
        "\"pid\":%d,\"path\":\"%s\",\"argv\":%s,\"rc\":0}\n",
        ts, getpid(), path_esc, argv_json);
    emit_log(log_buf);
    in_hook = 0;

    int rc = CALL_REAL(execve, pathname, argv, envp);
    int saved_errno = errno;

    /* If we get here, execve failed */
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

ssize_t HOOK_NAME(sendto)(int sockfd, const void *buf, size_t len, int flags,
               const struct sockaddr *dest_addr, socklen_t addrlen) {
    RESOLVE(sendto);
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

/* ---------- Linux large-file support (glibc open64/openat64) ---------- */
#ifdef __linux__

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
#endif
