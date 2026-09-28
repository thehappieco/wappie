/* vsock-sink: the enclave side of the A0 vsock throughput probe. It listens on
 * an AF_VSOCK port, accepts N connections in turn, drains each to EOF while
 * timing it, and writes one JSON array of {label,bytes,ms,mbps} to a file. The
 * parent (probe.sh) is the sender: it connects to the enclave CID on this port
 * and streams 16 MiB, then 32 MiB. This runs UNJAILED in the enclave — the jail
 * forbids AF_VSOCK; measuring parent->enclave bandwidth is a legitimate enclave
 * capability, not something a parser may do.
 *
 *   vsock-sink <port> <out.json> <label1> [label2 …]
 *
 * One accept per label. Uses a fixed vsock port that does not collide with
 * production (5443-5445, 7000-7002, 8000-8002, 9000); the probe uses 9100.
 */
#define _GNU_SOURCE
#include <linux/vm_sockets.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    if (argc < 4) {
        fprintf(stderr, "usage: vsock-sink <port> <out.json> <label> [label …]\n");
        return 2;
    }
    unsigned int port = (unsigned int)strtoul(argv[1], NULL, 10);
    const char *out = argv[2];
    int nlabels = argc - 3;

    int ls = socket(AF_VSOCK, SOCK_STREAM, 0);
    if (ls < 0) { perror("socket"); return 1; }
    struct sockaddr_vm sa;
    memset(&sa, 0, sizeof sa);
    sa.svm_family = AF_VSOCK;
    sa.svm_cid = VMADDR_CID_ANY;
    sa.svm_port = port;
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) < 0) { perror("bind"); return 1; }
    if (listen(ls, 4) < 0) { perror("listen"); return 1; }

    FILE *f = fopen(out, "w");
    if (!f) { perror("fopen"); return 1; }
    fputc('[', f);

    char *buf = malloc(1 << 20);
    if (!buf) { fprintf(stderr, "oom\n"); return 1; }

    for (int i = 0; i < nlabels; i++) {
        int cs = accept(ls, NULL, NULL);
        if (cs < 0) { perror("accept"); return 1; }
        long start = now_ms();
        unsigned long long total = 0;
        for (;;) {
            ssize_t n = read(cs, buf, 1 << 20);
            if (n < 0) { perror("read"); break; }
            if (n == 0) break;
            total += (unsigned long long)n;
        }
        long ms = now_ms() - start;
        close(cs);
        double mbps = ms > 0 ? ((double)total / (1024.0 * 1024.0)) / ((double)ms / 1000.0) : 0.0;
        fprintf(f, "%s{\"label\":\"%s\",\"bytes\":%llu,\"ms\":%ld,\"mbps\":%.1f}",
                i ? "," : "", argv[3 + i], total, ms, mbps);
        fflush(f);
    }
    fputs("]\n", f);
    fclose(f);
    close(ls);
    return 0;
}
