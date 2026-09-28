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
 *   jailtest connect-unix   socket(AF_UNIX) + connect  -> seccomp kill (connect)
 *   jailtest io-uring       io_uring_setup             -> ENOSYS (shim)
 *   jailtest userfaultfd    userfaultfd(2)             -> seccomp kill
 *   jailtest unshare-userns unshare(CLONE_NEWUSER)     -> seccomp kill
 *   jailtest clone-newns    clone(CLONE_NEWNS)         -> seccomp kill (flag filter)
 *   jailtest clone3         clone3(&args)              -> ENOSYS (shim)
 *   jailtest paths          stat the host-only paths   -> ENOENT for each
 *   jailtest proc-peek PID  open /proc/PID/{stat,mem}  -> ENOENT (other PID ns)
 *   jailtest memhog MB      touch MB MiB               -> OOM kill by memcg
 *   jailtest spin           sleep forever              -> wall timeout / external kill
 *   jailtest chroot         chroot("/tmp")             -> seccomp kill (never allowlisted)
 *   jailtest privs          /proc/self/status          -> every capability set empty,
 *                                                         NoNewPrivs 1, Seccomp 2
 *   jailtest mountinfo      /proc/self/mountinfo       -> the jail's mounts, one MOUNT line each
 *   jailtest pidfd-open     pidfd_open(getpid())       -> (unjailed only) ENOSYS before 5.3
 *
 * Built static musl in Dockerfile.probe; runs under the node-worker seccomp
 * profile, so its own startup and write()/openat() calls are all allowlisted.
 * The runner also runs io-uring, userfaultfd and unshare-userns UNJAILED, as
 * root, to record what the kernel itself supports (ENOSYS = not built in).
 */
#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <sched.h>
#include <stdlib.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <time.h>
#include <unistd.h>

#ifndef AF_VSOCK
#define AF_VSOCK 40
#endif
#ifndef SYS_clone3
#define SYS_clone3 435
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

static int test_connect_unix(void) {
    start("connect-unix");
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) { result("connect-unix", "SOCKET-FAILED", -1, errno); return 2; }
    struct sockaddr_un sa;
    memset(&sa, 0, sizeof sa);
    sa.sun_family = AF_UNIX;
    memcpy(sa.sun_path, "/tmp/jailtest.sock", 19);
    /* A missing path gives ENOENT if connect is allowed; the jail must kill
     * the process before the kernel ever looks at the path. */
    int r = connect(fd, (struct sockaddr *)&sa, sizeof sa);
    if (r == 0) { result("connect-unix", "OPENED", 0, 0); return 1; }
    result("connect-unix", "SURVIVED", r, errno);
    return 1;
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

static int test_clone_newns(void) {
    start("clone-newns");
    /* Raw clone, so libc cannot pick clone3 or add flags: arm64 argument order
     * is (flags, newsp, parent_tid, tls, child_tid); newsp 0 is fork-like. */
    long r = syscall(SYS_clone, (long)(CLONE_NEWNS | SIGCHLD), 0L, 0L, 0L, 0L);
    if (r == 0) _exit(0);
    if (r > 0) { result("clone-newns", "SURVIVED", r, 0); return 1; }
    result("clone-newns", "DENIED", r, errno);
    return 0;
}

static int test_clone3(void) {
    start("clone3");
    /* struct clone_args (v2, 88 bytes): only exit_signal set, a plain fork. */
    unsigned long long args[11];
    memset(args, 0, sizeof args);
    args[4] = SIGCHLD;
    long r = syscall(SYS_clone3, args, sizeof args);
    if (r == 0) _exit(0);
    if (r > 0) { result("clone3", "SURVIVED", r, 0); return 1; }
    result("clone3", "DENIED", r, errno);
    return 0;
}

/* The host-only paths §16.6 says are unreachable. Any answer but ENOENT
 * (including EACCES) means the path exists in the jail. */
static int test_paths(void) {
    start("paths");
    const char *paths[] = {"/run/wappie", "/run/cg2", "/sys", "/etc/hosts", "/dev/nsm"};
    int visible = 0;
    for (unsigned i = 0; i < sizeof paths / sizeof paths[0]; i++) {
        struct stat st;
        int r = stat(paths[i], &st);
        int e = r == 0 ? 0 : errno;
        char b[96];
        int n = 0;
        memcpy(b + n, "PATH ", 5); n += 5;
        int pl = (int)strlen(paths[i]); memcpy(b + n, paths[i], pl); n += pl;
        memcpy(b + n, " errno=", 7); n += 7; n = put_long(b, n, e);
        b[n++] = '\n';
        (void)!write(1, b, (size_t)n);
        if (e != ENOENT) visible = 1;
    }
    if (visible) { result("paths", "VISIBLE", 0, 0); return 1; }
    result("paths", "NOT-VISIBLE", -1, ENOENT);
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

/* chroot is never in the allowlist (profile.rs RESERVED), and the worker has
 * no CAP_SYS_CHROOT either: on the move+chroot root switch this is what keeps a
 * job from walking back out of its root. */
static int test_chroot(void) {
    start("chroot");
    int r = chroot("/tmp");
    if (r == 0) { result("chroot", "SURVIVED", 0, 0); return 1; }
    result("chroot", "DENIED", r, errno);
    return 0;
}

/* Read a small /proc file whole into buf (NUL-terminated); returns its length
 * or -1. */
static int read_small(const char *path, char *buf, int cap) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return -1;
    int n = 0;
    for (;;) {
        ssize_t r = read(fd, buf + n, (size_t)(cap - 1 - n));
        if (r <= 0) break;
        n += (int)r;
        if (n >= cap - 1) break;
    }
    close(fd);
    buf[n] = 0;
    return n;
}

/* The value after "<key>:\t" on its /proc/self/status line, or NULL. */
static const char *status_field(const char *text, const char *key, char *out, int cap) {
    int kl = (int)strlen(key);
    for (const char *p = text; p && *p; ) {
        const char *eol = strchr(p, '\n');
        if (!strncmp(p, key, (size_t)kl) && p[kl] == ':') {
            const char *v = p + kl + 1;
            while (*v == ' ' || *v == '\t') v++;
            int n = eol ? (int)(eol - v) : (int)strlen(v);
            if (n > cap - 1) n = cap - 1;
            memcpy(out, v, (size_t)n);
            out[n] = 0;
            return out;
        }
        p = eol ? eol + 1 : NULL;
    }
    return NULL;
}

/* What the jail left the worker: every capability set must be empty (hex all
 * zeros), NoNewPrivs 1 and Seccomp 2 (filter mode). The raw lines go out as
 * STATUS lines; the verdict is CLEARED or HELD. */
static int test_privs(void) {
    start("privs");
    char text[4096];
    if (read_small("/proc/self/status", text, sizeof text) < 0) {
        result("privs", "UNREADABLE", -1, errno);
        return 2;
    }
    const char *keys[] = {"Uid", "Gid", "Groups", "CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb",
                          "NoNewPrivs", "Seccomp", "Cpus_allowed_list"};
    int held = 0;
    for (unsigned i = 0; i < sizeof keys / sizeof keys[0]; i++) {
        char v[96];
        const char *got = status_field(text, keys[i], v, sizeof v);
        char b[160];
        int n = 0;
        memcpy(b + n, "STATUS ", 7); n += 7;
        int kl = (int)strlen(keys[i]); memcpy(b + n, keys[i], kl); n += kl;
        b[n++] = ' ';
        const char *shown = got ? got : "absent";
        int vl = (int)strlen(shown); memcpy(b + n, shown, vl); n += vl;
        b[n++] = '\n';
        (void)!write(1, b, (size_t)n);
        if (!strncmp(keys[i], "Cap", 3)) {
            /* CapAmb is absent before 4.3, which has no ambient set. */
            if (got && strspn(got, "0") != strlen(got)) held = 1;
        } else if (!strcmp(keys[i], "NoNewPrivs")) {
            if (!got || strcmp(got, "1")) held = 1;
        } else if (!strcmp(keys[i], "Seccomp")) {
            if (!got || strcmp(got, "2")) held = 1;
        }
    }
    if (held) { result("privs", "HELD", 0, 0); return 1; }
    result("privs", "CLEARED", 0, 0);
    return 0;
}

/* The jail's own view of its mounts, one MOUNT line each: a /proc/self/mountinfo
 * only shows mounts reachable from the process root, so this is exactly what
 * the worker can see. */
static int test_mountinfo(void) {
    start("mountinfo");
    char text[8192];
    if (read_small("/proc/self/mountinfo", text, sizeof text) < 0) {
        result("mountinfo", "UNREADABLE", -1, errno);
        return 2;
    }
    int count = 0;
    for (char *p = text; *p; ) {
        char *eol = strchr(p, '\n');
        int n = eol ? (int)(eol - p) : (int)strlen(p);
        (void)!write(1, "MOUNT ", 6);
        (void)!write(1, p, (size_t)n);
        (void)!write(1, "\n", 1);
        count++;
        if (!eol) break;
        p = eol + 1;
    }
    result("mountinfo", "COUNT", count, 0);
    return 0;
}

/* pidfd_open (5.3), run unjailed: what the kernel offers Node's kill path. */
static int test_pidfd_open(void) {
    start("pidfd-open");
    long r = syscall(434 /* SYS_pidfd_open on every arch */, (long)getpid(), 0L);
    if (r >= 0) { result("pidfd-open", "OPENED", r, 0); close((int)r); return 1; }
    result("pidfd-open", "DENIED", r, errno);
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
    if (!strcmp(t, "connect-unix")) return test_connect_unix();
    if (!strcmp(t, "io-uring")) return test_io_uring();
    if (!strcmp(t, "userfaultfd")) return test_userfaultfd();
    if (!strcmp(t, "unshare-userns")) return test_unshare_userns();
    if (!strcmp(t, "clone-newns")) return test_clone_newns();
    if (!strcmp(t, "clone3")) return test_clone3();
    if (!strcmp(t, "paths")) return test_paths();
    if (!strcmp(t, "proc-peek")) return test_proc_peek(argc > 2 ? argv[2] : "1");
    if (!strcmp(t, "memhog")) return test_memhog(argc > 2 ? argv[2] : "512");
    if (!strcmp(t, "lsproc")) return test_lsproc();
    if (!strcmp(t, "spin")) return test_spin();
    if (!strcmp(t, "chroot")) return test_chroot();
    if (!strcmp(t, "privs")) return test_privs();
    if (!strcmp(t, "mountinfo")) return test_mountinfo();
    if (!strcmp(t, "pidfd-open")) return test_pidfd_open();
    emit("unknown test\n");
    return 3;
}
