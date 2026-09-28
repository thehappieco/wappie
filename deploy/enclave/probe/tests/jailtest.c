/* jailtest: one small static binary the A0 probe runs INSIDE the media-jail to
 * prove each escape is closed. Each sub-command attempts one dangerous thing and
 * prints a verdict with write(2) (never buffered stdio, so the line survives a
 * seccomp kill of the very next syscall). If seccomp KILLs the process, no
 * RESULT line is printed and the probe records the signal (SIGSYS) as the
 * denial. If the kernel/namespace denies it, a RESULT ... DENIED line is
 * printed. A RESULT ... OPENED/SURVIVED line means the sandbox FAILED.
 *
 *   jailtest nsm            open("/dev/nsm")            -> ENOENT (no device in the jail)
 *   jailtest socket-vsock   socket(AF_VSOCK)           -> seccomp kill (AF_UNIX only)
 *   jailtest socket-inet    socket(AF_INET)            -> seccomp kill
 *   jailtest socket-unix    socket(AF_UNIX)            -> allowed (shows the filter is precise)
 *   jailtest io-uring       io_uring_setup             -> ENOSYS (shim)
 *   jailtest userfaultfd    userfaultfd(2)             -> seccomp kill
 *   jailtest unshare-userns unshare(CLONE_NEWUSER)     -> seccomp kill
 *   jailtest proc-peek PID  open /proc/PID/{stat,mem}  -> ENOENT (other PID ns)
 *   jailtest memhog MB      touch MB MiB               -> OOM kill by memcg
 *   jailtest spin           sleep forever              -> wall timeout / cgroup.kill
 *
 * Built static musl in Dockerfile.probe; runs under the node-worker seccomp
 * profile, so its own startup and write()/openat() calls are all allowlisted.
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif

static void emit(const char *s) { (void)!write(1, s, strlen(s)); }

/* Append a signed decimal to a buffer; returns new length. */
static int put_long(char *b, int n, long v) {
    char t[24];
    int t_len = 0;
    unsigned long u = v < 0 ? (unsigned long)(-v) : (unsigned long)v;
    if (v < 0) b[n++] = '-';
    if (u == 0) t[t_len++] = '0';
    while (u) { t[t_len++] = (char)('0' + u % 10); u /= 10; }
    while (t_len) b[n++] = t[--t_len];
    return n;
}

/* RESULT <name> <status> ret=<r> errno=<e>\n */
static void result(const char *name, const char *status, long ret, int err) {
    char b[160];
    int n = 0;
    const char *p = "RESULT ";
    memcpy(b + n, p, 7); n += 7;
    int nl = (int)strlen(name); memcpy(b + n, name, nl); n += nl; b[n++] = ' ';
    int sl = (int)strlen(status); memcpy(b + n, status, sl); n += sl;
    memcpy(b + n, " ret=", 5); n += 5; n = put_long(b, n, ret);
    memcpy(b + n, " errno=", 7); n += 7; n = put_long(b, n, err);
    b[n++] = '\n';
    (void)!write(1, b, (size_t)n);
}

static void start(const char *name) {
    char b[64];
    int n = 0;
    memcpy(b + n, "START ", 6); n += 6;
    int nl = (int)strlen(name); memcpy(b + n, name, nl); n += nl; b[n++] = '\n';
    (void)!write(1, b, (size_t)n);
}

static int test_nsm(void) {
    start("nsm");
    int fd = open("/dev/nsm", O_RDWR);
    if (fd >= 0) { result("nsm", "OPENED", fd, 0); close(fd); return 1; }
    result("nsm", "DENIED", -1, errno);
    return 0;
}

static int test_socket(const char *name, int domain) {
    start(name);
    int fd = socket(domain, SOCK_STREAM, 0);
    if (fd >= 0) { result(name, "OPENED", fd, 0); close(fd); return 1; }
    result(name, "DENIED", -1, errno);
    return 0;
}

static int test_io_uring(void) {
    start("io-uring");
    /* io_uring_params is 120 bytes; a zeroed buffer of that size is enough. */
    unsigned char params[120];
    memset(params, 0, sizeof params);
    long r = syscall(SYS_io_uring_setup, 8, params);
    if (r >= 0) { result("io-uring", "OPENED", r, 0); return 1; }
    result("io-uring", "DENIED", r, errno);
    return 0;
}

static int test_userfaultfd(void) {
    start("userfaultfd");
    long r = syscall(SYS_userfaultfd, O_CLOEXEC);
    if (r >= 0) { result("userfaultfd", "OPENED", r, 0); return 1; }
    result("userfaultfd", "DENIED", r, errno);
    return 0;
}

static int test_unshare_userns(void) {
    start("unshare-userns");
    int r = unshare(CLONE_NEWUSER);
    if (r == 0) { result("unshare-userns", "SURVIVED", 0, 0); return 1; }
    result("unshare-userns", "DENIED", r, errno);
    return 0;
}

static int test_proc_peek(const char *pid) {
    start("proc-peek");
    char path[64];
    int visible = 0;
    const char *suf[] = {"stat", "maps", "mem"};
    for (int i = 0; i < 3; i++) {
        int n = 0;
        memcpy(path + n, "/proc/", 6); n += 6;
        int pl = (int)strlen(pid); memcpy(path + n, pid, pl); n += pl; path[n++] = '/';
        int sl = (int)strlen(suf[i]); memcpy(path + n, suf[i], sl); n += sl; path[n] = 0;
        int fd = open(path, O_RDONLY);
        if (fd >= 0) { visible = 1; close(fd); }
    }
    if (visible) { result("proc-peek", "VISIBLE", 0, 0); return 1; }
    result("proc-peek", "NOT-VISIBLE", -1, errno);
    return 0;
}

static int test_memhog(const char *mb_s) {
    start("memhog");
    long mb = atol(mb_s);
    size_t chunk = 8 * 1024 * 1024;
    long done = 0;
    for (long i = 0; i < mb; i += 8) {
        char *p = malloc(chunk);
        if (!p) { result("memhog", "MALLOC-FAILED", done, 0); return 2; }
        memset(p, 0x5a, chunk);
        done += 8;
    }
    result("memhog", "SURVIVED", done, 0);
    return 0;
}

/* Diagnostic: list the numeric PIDs the jail's /proc shows. In a fresh PID
 * namespace with its own /proc this is just {1}. */
static int test_lsproc(void) {
    start("lsproc");
    DIR *d = opendir("/proc");
    if (!d) { result("lsproc", "OPENDIR-FAILED", -1, errno); return 1; }
    char line[256];
    int n = 0;
    memcpy(line + n, "PROC-PIDS", 9); n += 9;
    struct dirent *e;
    int count = 0;
    while ((e = readdir(d)) != NULL) {
        if (e->d_name[0] < '0' || e->d_name[0] > '9') continue;
        count++;
        if (n < 200) { line[n++] = ' '; int l = (int)strlen(e->d_name); memcpy(line + n, e->d_name, l); n += l; }
    }
    closedir(d);
    line[n++] = '\n';
    (void)!write(1, line, (size_t)n);
    result("lsproc", "COUNT", count, 0);
    return 0;
}

static int test_spin(void) {
    start("spin");
    struct timespec ts = {0, 50 * 1000 * 1000};
    for (;;) nanosleep(&ts, 0);
    return 0;
}

int main(int argc, char **argv) {
    if (argc < 2) { emit("usage: jailtest <test> [arg]\n"); return 3; }
    const char *t = argv[1];
    if (!strcmp(t, "nsm")) return test_nsm();
    if (!strcmp(t, "socket-vsock")) return test_socket("socket-vsock", AF_VSOCK);
    if (!strcmp(t, "socket-inet")) return test_socket("socket-inet", AF_INET);
    if (!strcmp(t, "socket-unix")) return test_socket("socket-unix", AF_UNIX);
    if (!strcmp(t, "io-uring")) return test_io_uring();
    if (!strcmp(t, "userfaultfd")) return test_userfaultfd();
    if (!strcmp(t, "unshare-userns")) return test_unshare_userns();
    if (!strcmp(t, "proc-peek")) return test_proc_peek(argc > 2 ? argv[2] : "1");
    if (!strcmp(t, "memhog")) return test_memhog(argc > 2 ? argv[2] : "512");
    if (!strcmp(t, "lsproc")) return test_lsproc();
    if (!strcmp(t, "spin")) return test_spin();
    emit("unknown test\n");
    return 3;
}
