#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <linux/types.h>
#include <linux/sched.h>

// Define trace_event_raw_sys_enter structure explicitly
struct trace_event_raw_sys_enter {
    __u64 unused;
    long id;
    long args[6];
};

#define MAX_COMM_LEN 64

// Structure for ring buffer events
struct event {
    __u32 pid;
    char comm[MAX_COMM_LEN];
};

// Ring buffer for logging execve events
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 20); // 1MB ring buffer
} ringbuf SEC(".maps");

// Tracepoint for sys_enter_execve
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    struct event *e;
    __u32 pid = bpf_get_current_pid_tgid() >> 32;

    // Reserve space in ring buffer
    e = bpf_ringbuf_reserve(&ringbuf, sizeof(*e), 0);
    if (!e)
        return 0;

    // Fill event data
    e->pid = pid;
    if (bpf_probe_read_user_str(e->comm, sizeof(e->comm), (void *)ctx->args[0]) < 0) {
        bpf_ringbuf_discard(e, 0);
        return 0;
    }

    // Submit event to ring buffer
    bpf_ringbuf_submit(e, 0);
    return 0;
}

char _license[] SEC("license") = "GPL";