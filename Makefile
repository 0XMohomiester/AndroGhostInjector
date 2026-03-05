# Makefile for Android standalone eBPF injector

# System tools
BPFTOOL ?= bpftool
CLANG ?= clang
CC ?= aarch64-linux-gnu-gcc

# Path to libbpf for cross-compilation (Override this if compiling outside of our Docker environment)
LIBBPF_PREFIX ?= /opt/libbpf-arm64/usr

# Compiler flags
CFLAGS = -g -O2 -Wall -I. -I$(LIBBPF_PREFIX)/include
LDFLAGS = -static -L$(LIBBPF_PREFIX)/lib64 -L$(LIBBPF_PREFIX)/lib -lbpf -lelf -lz

# Output binaries
TARGET = injector
BPF_OBJ = injector.bpf.o
BPF_SKEL = injector.skel.h
VMLINUX_H = vmlinux.h

all: check_vmlinux $(VMLINUX_H) $(TARGET)

check_vmlinux:
	@if [ ! -f ./vmlinux ]; then \
		echo "[-] Error: 'vmlinux' not found in current directory!"; \
		echo "    Please extract it from your target Android device (e.g. adb pull /sys/kernel/btf/vmlinux)"; \
		exit 1; \
	fi

$(VMLINUX_H): ./vmlinux
	$(BPFTOOL) btf dump file ./vmlinux format c > $@

$(BPF_OBJ): injector.bpf.c $(VMLINUX_H)
	$(CLANG) -g -O2 -target bpf -D__TARGET_ARCH_arm64 -I. -c $< -o $@

$(BPF_SKEL): $(BPF_OBJ)
	$(BPFTOOL) gen skeleton $< > $@

$(TARGET): main.c elf_parser.c $(BPF_SKEL)
	$(CC) $(CFLAGS) main.c elf_parser.c -o $@ $(LDFLAGS)

clean:
	rm -f $(TARGET) $(BPF_OBJ) $(BPF_SKEL) $(VMLINUX_H)
