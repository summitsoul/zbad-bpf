#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <signal.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "file_monitor.skel.h"

#define MAX_COMM_LEN 64

struct event {
    __u32 pid;
    char comm[MAX_COMM_LEN];
};

static volatile int keep_running = 1;

void handle_sigint(int sig) {
    keep_running = 0;
}

static int handle_event(void *ctx, void *data, size_t size) {
    struct event *e = data;
    printf("PID %u executed command: %s\n", e->pid, e->comm);
    return 0;
}

int main(int argc, char *argv[]) {
    struct file_monitor_bpf *skel;
    struct ring_buffer *rb = NULL;
    int err;

    // Open BPF application
    skel = file_monitor_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Load and verify BPF program
    err = file_monitor_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton: %s\n", strerror(errno));
        goto cleanup;
    }

    // Attach tracepoint handler
    err = file_monitor_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd(skel->maps.ringbuf), handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Failed to create ring buffer: %s\n", strerror(errno));
        err = -1;
        goto cleanup;
    }

    printf("Monitoring process executions. Press Ctrl+C to exit...\n");

    // Handle SIGINT to exit gracefully
    signal(SIGINT, handle_sigint);

    // Poll ring buffer
    while (keep_running) {
        err = ring_buffer__poll(rb, 100 /* timeout in ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %s\n", strerror(-err));
            break;
        }
    }

cleanup:
    ring_buffer__free(rb);
    file_monitor_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}