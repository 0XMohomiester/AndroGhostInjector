#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

enum event_type {
  EVENT_CAPTURE = 1,
  EVENT_COMPLETE = 2,
};

struct event_t {
  __u32 type;
  __u32 pid;
  __u32 uid;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} target_uid_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, __u32);
  __type(value, __u32);
} active_injection_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tracepoint/raw_syscalls/sys_enter")
int trace_sys_enter(struct trace_event_raw_sys_enter *ctx) {
  __u64 id_full = bpf_get_current_pid_tgid();
  __u32 pid = id_full >> 32;
  long syscall_id = ctx->id;

  // 1. Handle setresuid (147 on ARM64)
  if (syscall_id == 147) {
    __u32 ruid = (__u32)ctx->args[0];
    __u32 key = 0;
    __u32 *target_uid_ptr = bpf_map_lookup_elem(&target_uid_map, &key);

    if (target_uid_ptr && ruid == *target_uid_ptr) {
      char comm[16];
      bpf_get_current_comm(&comm, sizeof(comm));

      // Filter out 'su' and 'apd' to avoid hijacking the shell or helper tools
      if (comm[0] == 's' && comm[1] == 'u' && comm[2] == '\0')
        return 0;
      if (comm[0] == 'a' && comm[1] == 'p' && comm[2] == 'd' && comm[3] == '\0')
        return 0;

      // Pause process
      bpf_send_signal(19); // SIGSTOP

      // Add to active injections
      __u32 val = 1;
      bpf_map_update_elem(&active_injection_map, &pid, &val, BPF_ANY);

      // Notify User-space
      struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
      if (e) {
        e->type = EVENT_CAPTURE;
        e->pid = pid;
        e->uid = ruid;
        bpf_ringbuf_submit(e, 0);
      }
      bpf_printk("[eBPF] Capture: PID %u (%s), UID %u\n", pid, comm, ruid);
    }
  }

  // 2. Handle getpid (172 on ARM64)
  if (syscall_id == 172) {
    __u32 *active = bpf_map_lookup_elem(&active_injection_map, &pid);
    if (active) {
      bpf_send_signal(
          19); // SIGSTOP immediately to prevent user-space trap spinning
      struct event_t *e = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
      if (e) {
        e->type = EVENT_COMPLETE;
        e->pid = pid;
        e->uid = 0;
        bpf_ringbuf_submit(e, 0);
      }
      bpf_map_delete_elem(&active_injection_map, &pid);
      bpf_printk("[eBPF] Signal from PID %u\n", pid);
    }
  }

  return 0;
}

char LICENSE[] SEC("license") = "GPL";
