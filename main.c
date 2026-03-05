#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include "elf_parser.h"
#include "injector.skel.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/xattr.h>
#include <unistd.h>

#define MAX_CONCURRENT_INJECTIONS 64

enum event_type {
  EVENT_CAPTURE = 1,
  EVENT_COMPLETE = 2,
};

struct event_t {
  unsigned int type;
  unsigned int pid;
  unsigned int uid;
};

struct injection_ctx {
  int pid;
  unsigned long long ip;
  unsigned long long cave_addr;
  unsigned int orig_inst;
  char lib_path[256];
  int active;
};

static struct injection_ctx g_ctxs[MAX_CONCURRENT_INJECTIONS];

// Forward declarations for memory tools used by trampoline
ssize_t read_proc_mem(int pid, unsigned long long addr, void *buf, size_t len);
ssize_t write_proc_mem(int pid, unsigned long long addr, const void *buf,
                       size_t len);

static volatile int g_exit_injector = 0;

unsigned int encode_branch(unsigned long long pc, unsigned long long target) {
  long long offset = target - pc;
  int imm26 = (offset >> 2) & 0x03FFFFFF;
  return 0x14000000 | imm26;
}

unsigned long long find_executable_cave(int pid, unsigned long long ip) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  unsigned long long start = 0, end = 0;
  while (fgets(line, sizeof(line), f)) {
    if (strstr(line, "r-xp") && strstr(line, "libc.so")) {
      sscanf(line, "%llx-%llx", &start, &end);
      break;
    }
  }
  fclose(f);

  if (!start)
    return 0;

  size_t size = end - start;
  unsigned char *buf = malloc(size);
  if (!buf)
    return 0;

  if (read_proc_mem(pid, start, buf, size) != size) {
    free(buf);
    return 0;
  }

  unsigned long long cave_addr = 0;
  int zero_count = 0;
  for (size_t i = 0; i < size; i++) {
    if (buf[i] == 0) {
      zero_count++;
      if (zero_count == 128) {
        cave_addr = start + (i - 127);
        cave_addr = (cave_addr + 3) & ~3; // 4-byte align
        break;
      }
    } else {
      zero_count = 0;
    }
  }

  free(buf);
  return cave_addr;
}

// Retrieve or allocate a context for a specific PID
static struct injection_ctx *get_or_alloc_ctx(int pid) {
  for (int i = 0; i < MAX_CONCURRENT_INJECTIONS; i++) {
    if (g_ctxs[i].active && g_ctxs[i].pid == pid)
      return &g_ctxs[i];
  }
  for (int i = 0; i < MAX_CONCURRENT_INJECTIONS; i++) {
    if (!g_ctxs[i].active) {
      g_ctxs[i].pid = pid;
      g_ctxs[i].active = 1;
      return &g_ctxs[i];
    }
  }
  return NULL;
}

// Free context after injection
static void free_ctx(int pid) {
  for (int i = 0; i < MAX_CONCURRENT_INJECTIONS; i++) {
    if (g_ctxs[i].active && g_ctxs[i].pid == pid) {
      g_ctxs[i].active = 0;
      break;
    }
  }
}

ssize_t read_proc_mem(int pid, unsigned long long addr, void *buf, size_t len) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int fd = open(path, O_RDONLY);
  if (fd < 0)
    return -1;
  ssize_t n = pread(fd, buf, len, addr);
  close(fd);
  return n;
}

ssize_t write_proc_mem(int pid, unsigned long long addr, const void *buf,
                       size_t len) {
  char path[64];
  snprintf(path, sizeof(path), "/proc/%d/mem", pid);
  int fd = open(path, O_WRONLY);
  if (fd < 0)
    return -1;
  ssize_t n = pwrite(fd, buf, len, addr);
  close(fd);
  return n;
}

unsigned long long get_ip(int pid) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/syscall", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;
  if (!fgets(line, sizeof(line), f)) {
    fclose(f);
    return 0;
  }
  fclose(f);

  unsigned long long ip = 0;
  char *saveptr;
  char *line_copy = strdup(line);
  char *token = strtok_r(line_copy, " ", &saveptr);
  if (!token) {
    free(line_copy);
    return 0;
  }

  if (strcmp(token, "-1") == 0) {
    strtok_r(NULL, " ", &saveptr);
    token = strtok_r(NULL, " ", &saveptr);
  } else {
    for (int i = 1; i < 9 && token; i++)
      token = strtok_r(NULL, " ", &saveptr);
  }

  if (token)
    ip = strtoull(token, NULL, 16);
  free(line_copy);
  return ip;
}

unsigned long long resolve_dlopen(int pid) {
  char path[64], line[512];
  snprintf(path, sizeof(path), "/proc/%d/maps", pid);
  FILE *f = fopen(path, "r");
  if (!f)
    return 0;

  unsigned long long base = 0;
  char linker_path[256] = {0};

  while (fgets(line, sizeof(line), f)) {
    // The first mapping of the ELF is always the executable base
    if (strstr(line, "/linker64") || strstr(line, "/libdl.so")) {
      sscanf(line, "%llx-%*llx %*s %*s %*s %*s %255s", &base, linker_path);
      break;
    }
  }
  fclose(f);

  if (!base || strlen(linker_path) == 0)
    return 0;

  unsigned long long offset = get_symbol_offset(linker_path, "__loader_dlopen");
  if (!offset) {
    offset = get_symbol_offset(linker_path, "dlopen");
  }

  if (!offset) {
    printf("[-] Could not find dlopen symbol in %s\n", linker_path);
    return 0;
  }

  printf("[+] Dynamically resolved dlopen in %s at offset 0x%llx\n",
         linker_path, offset);
  return base + offset;
}

unsigned int resolve_package_uid(const char *pkg_name) {
  FILE *f = fopen("/data/system/packages.list", "r");
  if (!f)
    return 0;

  char line[1024];
  char current_pkg[256];
  unsigned int uid = 0;

  while (fgets(line, sizeof(line), f)) {
    if (sscanf(line, "%255s %u", current_pkg, &uid) == 2) {
      if (strcmp(current_pkg, pkg_name) == 0) {
        fclose(f);
        return uid;
      }
    }
  }
  fclose(f);
  return 0; // Not found
}

static int handle_event(void *ctx, void *data, size_t data_sz) {
  const struct event_t *e = data;

  if (e->type == EVENT_CAPTURE) {
    struct injection_ctx *t_ctx = get_or_alloc_ctx(e->pid);
    if (!t_ctx) {
      printf("[-] Max concurrent injections reached. Skipping PID %u\n",
             e->pid);
      return 0;
    }

    // Copy the target payload path into this session's context
    strncpy(t_ctx->lib_path, (char *)ctx, sizeof(t_ctx->lib_path) - 1);

    printf("[+] Target Captured: PID %u\n", e->pid);
    t_ctx->ip = get_ip(e->pid);
    if (!t_ctx->ip)
      return 0;

    unsigned long long dlopen_addr = resolve_dlopen(e->pid);
    if (!dlopen_addr) {
      printf("[-] Failed to resolve dlopen for PID %u\n", e->pid);
      return 0;
    }

    t_ctx->cave_addr = find_executable_cave(e->pid, t_ctx->ip);
    if (!t_ctx->cave_addr) {
      printf("[-] Failed to find executable cave for PID %u\n", e->pid);
      return 0;
    }

    size_t path_len = strlen(t_ctx->lib_path) + 1;

    // Backup EXACTLY the precise 4 bytes at IP
    if (read_proc_mem(e->pid, t_ctx->ip, &t_ctx->orig_inst, 4) != 4) {
      printf("[-] Failed to backup memory at 0x%llx (EFAULT).\n", t_ctx->ip);
      return 0;
    }

    unsigned int shellcode[] = {
        0xa9bf7bfd, // 0:  stp x29, x30, [sp, #-16]!
        0xa9bf07e0, // 1:  stp x0,  x1,  [sp, #-16]!
        0xa9bf23e2, // 2:  stp x2,  x8,  [sp, #-16]!
        0x100001e0, // 3:  adr x0, #60 (PC+60 = 72, index 18)
        0xd2800041, // 4:  mov x1, #2 (RTLD_NOW)
        0x58000163, // 5:  ldr x3, #44 (PC+44 = 64, index 16)
        0xaa0303e2, // 6:  mov x2, x3 (caller_addr = dlopen_addr spoof!)
        0xd63f0060, // 7:  blr x3
        0xa8c123e2, // 8:  ldp x2, x8, [sp], #16
        0xa8c107e0, // 9:  ldp x0, x1, [sp], #16
        0xa8c17bfd, // 10: ldp x29, x30, [sp], #16
        0xa9bf7fe8, // 11: stp x8, xzr, [sp, #-16]!
        0xd2801588, // 12: mov x8, #172 (getpid)
        0xd4000001, // 13: svc #0
        0xa8c17fe8, // 14: ldp x8, xzr, [sp], #16
        0x17ffffff, // 15: b .-4 (Infinite Trap)
        0x00000000, 0x00000000, // 16, 17: dlopen_addr placeholder
    };

    shellcode[16] = (unsigned int)(dlopen_addr & 0xFFFFFFFF);
    shellcode[17] = (unsigned int)(dlopen_addr >> 32);

    // Write shellcode to the executable cave
    write_proc_mem(e->pid, t_ctx->cave_addr, shellcode, sizeof(shellcode));

    // Write string path exactly at the end of the shellcode (offset 72)
    write_proc_mem(e->pid, t_ctx->cave_addr + 72, t_ctx->lib_path, path_len);

    // Overwrite the original instruction with a branch to the cave
    unsigned int branch_to_cave = encode_branch(t_ctx->ip, t_ctx->cave_addr);
    write_proc_mem(e->pid, t_ctx->ip, &branch_to_cave, 4);

    printf("[+] Hijacked IP 0x%llx to Cave 0x%llx. Waking app...\n", t_ctx->ip,
           t_ctx->cave_addr);
    kill(e->pid, SIGCONT);

  } else if (e->type == EVENT_COMPLETE) {
    struct injection_ctx *t_ctx = get_or_alloc_ctx(e->pid);
    if (!t_ctx || !t_ctx->ip)
      return 0;

    printf("[+] Injection complete signal from PID %u.\n", e->pid);

    // Stop the app from spinning in the `b .-4` loop
    kill(e->pid, SIGSTOP);

    // Restore ONLY the 4 bytes we hijacked at the original IP
    if (write_proc_mem(e->pid, t_ctx->ip, &t_ctx->orig_inst, 4) == 4) {
      printf("[+] Original instruction restored at 0x%llx.\n", t_ctx->ip);
    } else {
      printf("[-] FATAL: Failed to restore instruction. App will crash.\n");
    }

    // Overwrite the infinite trap (b .-4) in the cave with a branch BACK to the
    // original IP
    unsigned long long trap_addr = t_ctx->cave_addr + (15 * 4);
    unsigned int branch_back = encode_branch(trap_addr, t_ctx->ip);
    write_proc_mem(e->pid, trap_addr, &branch_back, 4);

    // Scrub the residual shellcode from memory (Zero-Out) to defeat scanners
    // We strictly preserve instructions 14 and 15 (offset 56 and 60) which
    // handle the flawless return
    unsigned char zeros[128] = {0};
    write_proc_mem(e->pid, t_ctx->cave_addr, zeros,
                   56); // Erase core instructions
    write_proc_mem(e->pid, t_ctx->cave_addr + 64, zeros,
                   128 - 64); // Erase dlopen_addr & lib_path string

    // Free the tracking context
    free_ctx(e->pid);

    printf("[*] Resuming target for seamless continuation. Cave scrubbed!\n");
    kill(e->pid, SIGCONT);

    g_exit_injector = 1; // Signal the active loop that injection is complete
  }
  return 0;
}

int main(int argc, char **argv) {
  if (argc < 3) {
    fprintf(stderr, "Usage: %s <package_name_or_uid> <lib_path>\n", argv[0]);
    return 1;
  }
  setlinebuf(stdout);

  unsigned int target_uid = 0;
  // If argument starts with a digit, assume it's a raw UID
  if (argv[1][0] >= '0' && argv[1][0] <= '9') {
    target_uid = atoi(argv[1]);
  } else {
    // Resolve Package Name to UID using Android native registry
    target_uid = resolve_package_uid(argv[1]);
    if (target_uid == 0) {
      fprintf(
          stderr,
          "[-] FATAL: Could not resolve UID for package %s. Is it installed?\n",
          argv[1]);
      return 1;
    }
  }

  // We allocate memory for the global path so we can pass it via ctx to
  // handle_event
  char *global_lib_path = strdup(argv[2]);

  printf("[*] eBPF /proc/mem Stealth Injector Started\n");
  if (argv[1][0] >= '0' && argv[1][0] <= '9') {
    printf("[*] Target UID: %u\n", target_uid);
  } else {
    printf("[*] Target App: %s (UID %u)\n", argv[1], target_uid);
  }
  printf("[*] Payload: %s\n", global_lib_path);

  // Apply Forge SELinux context
  if (access(global_lib_path, F_OK) == 0) {
    chmod(global_lib_path, 0755);
    const char *context = "u:object_r:system_file:s0";
    setxattr(global_lib_path, "security.selinux", context, strlen(context) + 1,
             0);
  }

  LIBBPF_OPTS(bpf_object_open_opts, open_opts,
              .btf_custom_path = "/sys/kernel/btf/vmlinux");
  struct injector_bpf *skel = injector_bpf__open_opts(&open_opts);
  if (!skel)
    return 1;
  if (injector_bpf__load(skel))
    return 1;

  int map_fd = bpf_map__fd(skel->maps.target_uid_map);
  unsigned int zero = 0;
  bpf_map_update_elem(map_fd, &zero, &target_uid, 0);

  if (injector_bpf__attach(skel))
    return 1;
  printf("[+] Attached. Waiting for target launch...\n");

  // Pass our global string as the ctx so `handle_event` can access the
  // requested library path
  struct ring_buffer *rb = ring_buffer__new(
      bpf_map__fd(skel->maps.rb), handle_event, global_lib_path, NULL);
  if (!rb)
    return 1;

  while (!g_exit_injector)
    ring_buffer__poll(rb, 100);

  printf("[*] Injection complete. Shutting down gracefully.\n");
  ring_buffer__free(rb);
  injector_bpf__destroy(skel);
  return 0;
}