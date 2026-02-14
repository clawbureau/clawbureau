#if defined(__linux__) || defined(__APPLE__)
#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _DARWIN_C_SOURCE
#define _DARWIN_C_SOURCE
#endif
#endif

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <dlfcn.h>
#include <sys/socket.h>
#include <spawn.h>
#include <fcntl.h>

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

int diag_connect(int sockfd, const struct sockaddr *addr, socklen_t addrlen) {
    fprintf(stderr, "[diagnose_interpose] connect() hooked!\n");
    int (*real_connect)(int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "connect");
    return real_connect(sockfd, addr, addrlen);
}
DYLD_INTERPOSE(diag_connect, connect)

int diag_open(const char *path, int oflag, ...) {
    fprintf(stderr, "[diagnose_interpose] open() hooked!\n");
    int (*real_open)(const char *, int, ...) = dlsym(RTLD_NEXT, "open");
    return real_open(path, oflag);
}
DYLD_INTERPOSE(diag_open, open)

int diag_openat(int fd, const char *path, int oflag, ...) {
    fprintf(stderr, "[diagnose_interpose] openat() hooked!\n");
    int (*real_openat)(int, const char *, int, ...) = dlsym(RTLD_NEXT, "openat");
    return real_openat(fd, path, oflag);
}
DYLD_INTERPOSE(diag_openat, openat)

int diag_execve(const char *path, char *const argv[], char *const envp[]) {
    fprintf(stderr, "[diagnose_interpose] execve() hooked!\n");
    int (*real_execve)(const char *, char *const[], char *const[]) = dlsym(RTLD_NEXT, "execve");
    return real_execve(path, argv, envp);
}
DYLD_INTERPOSE(diag_execve, execve)

int diag_posix_spawn(pid_t *restrict pid, const char *restrict path,
                     const posix_spawn_file_actions_t *file_actions,
                     const posix_spawnattr_t *restrict attrp,
                     char *const argv[restrict], char *const envp[restrict]) {
    fprintf(stderr, "[diagnose_interpose] posix_spawn() hooked!\n");
    int (*real_posix_spawn)(pid_t *restrict, const char *restrict,
                            const posix_spawn_file_actions_t *,
                            const posix_spawnattr_t *restrict,
                            char *const[restrict], char *const[restrict]) = dlsym(RTLD_NEXT, "posix_spawn");
    return real_posix_spawn(pid, path, file_actions, attrp, argv, envp);
}
DYLD_INTERPOSE(diag_posix_spawn, posix_spawn)

ssize_t diag_sendto(int sockfd, const void *buf, size_t len, int flags,
                    const struct sockaddr *dest_addr, socklen_t addrlen) {
    fprintf(stderr, "[diagnose_interpose] sendto() hooked!\n");
    ssize_t (*real_sendto)(int, const void *, size_t, int, const struct sockaddr *, socklen_t) = dlsym(RTLD_NEXT, "sendto");
    return real_sendto(sockfd, buf, len, flags, dest_addr, addrlen);
}
DYLD_INTERPOSE(diag_sendto, sendto)

__attribute__((constructor))
static void diagnose_init(void) {
    fprintf(stderr, "========================================\n");
    fprintf(stderr, "[diagnose_interpose] INITIALIZING PID %d\n", getpid());

    void *real_connect = dlsym(RTLD_NEXT, "connect");
    void *real_open = dlsym(RTLD_NEXT, "open");
    void *real_openat = dlsym(RTLD_NEXT, "openat");
    void *real_execve = dlsym(RTLD_NEXT, "execve");
    void *real_posix_spawn = dlsym(RTLD_NEXT, "posix_spawn");
    void *real_sendto = dlsym(RTLD_NEXT, "sendto");
    void *def_connect = dlsym(RTLD_DEFAULT, "connect");

    fprintf(stderr, "  Hook addresses:\n");
    fprintf(stderr, "    connect     - hook: %p, real: %p, default: %p\n", (void*)diag_connect, real_connect, def_connect);
    fprintf(stderr, "    open        - hook: %p, real: %p\n", (void*)diag_open, real_open);
    fprintf(stderr, "    openat      - hook: %p, real: %p\n", (void*)diag_openat, real_openat);
    fprintf(stderr, "    execve      - hook: %p, real: %p\n", (void*)diag_execve, real_execve);
    fprintf(stderr, "    posix_spawn - hook: %p, real: %p\n", (void*)diag_posix_spawn, real_posix_spawn);
    fprintf(stderr, "    sendto      - hook: %p, real: %p\n", (void*)diag_sendto, real_sendto);

    if (def_connect == (void*)diag_connect) {
        fprintf(stderr, "  [+] Hooks are binding properly via DYLD_INTERPOSE.\n");
    } else {
        fprintf(stderr, "  [-] Hooks are NOT binding. SIP likely stripped DYLD_INSERT_LIBRARIES.\n");
    }
    fprintf(stderr, "========================================\n");
}
#endif
