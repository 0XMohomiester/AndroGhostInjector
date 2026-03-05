# AndroGhostInjector 👻🤖

An advanced, **ptrace-less** shared library injector for modern ARM64 Android systems (Android 10 - 15). 
This tool utilizes eBPF to precisely capture the Zygote fork specialization of an Android application, and seamlessly forces the process to load a custom Agent payload (`.so`) using an in-memory "Executable Cave Trampoline"—bypassing standard debugging and memory integrity SDKs.

## 🚀 Features
* **100% Ptrace-Free**: Never uses `ptrace` or the `TracerPid`. Undetectable by standard debugger checks.
* **Cave Scrubber**: Actively destroys the residual memory footprint of the injection payload after execution to defeat in-memory scanners.
* **Dynamic ELF Parsing**: Natively parses `libelf` on-device to defeat ASLR and Android OS versioning of the `dlopen` symbol. No hardcoded offsets.
* **App Context Support**: Instantly intercepts target package strings (e.g. `com.gemalto.eziomobilesampleapp`). No manual UID lookup required.

## 🛠 Compilation (Two Options)

The injector requires Android's `vmlinux` header and specifically targets the `aarch64` architecture. We provide two ways to compile it depending on your host OS.

### Prerequisites (for both options)
1. **vmlinux**: You must place your target Android device's `vmlinux` file (which contains the BTF info) in the root of this repository. Since `/sys/kernel/btf` is not directly accessible via standard adb, use this workaround:
   ```bash
   adb shell "su -c 'cat /sys/kernel/btf/vmlinux' > /data/local/tmp/vmlinux"
   adb pull /data/local/tmp/vmlinux .
   ```
2. **bpftool**: If building via Docker (Option B), the script expects a static `bpftool` binary for x86_64 in the root directory as `bpftool_bin`.
   ```bash
   # Download a static bpftool binary if you don't have one
   curl -L https://github.com/libbpf/bpftool/releases/download/v7.4.0/bpftool-v7.4.0-amd64.tar.gz | tar -xz && mv bpftool bpftool_bin
   ```

### Option A: Native Linux Build (Recommended)
If you are running Ubuntu/Debian natively, you can compile the project instantly without Docker.
1. Install dependencies: 
   `sudo apt install clang llvm gcc-aarch64-linux-gnu libc6-dev-arm64-cross libelf-dev zlib1g-dev libbpf-dev`
2. Run Make:
   `make`

### Option B: Cross-Platform Docker Build (macOS / Windows)
If you are on macOS or Windows and do not want to configure a cross-compilation toolchain, you can use our Docker wrapper. It automatically spins up an isolated Ubuntu container and runs the `Makefile` inside it.
1. Ensure Docker Desktop is running.
2. Execute the wrapper:
   `./build.sh`

---

> [!NOTE]
> **Agent Payloads**: A sample agent (`libstealth_agent.so`) is included in the `agent/` directory for testing purposes. If you already have your own shared library that you want to inject, there is no need to compile the sample agent.

## 🕹 Usage

1. Push the compiled injector and your custom agent payload (`.so`) to the device:
```bash
adb push injector /data/local/tmp/
adb push libstealth_agent.so /data/local/tmp/
adb shell "chmod +x /data/local/tmp/injector"
```

2. Run the injector as root, passing the target application package name and the payload path:
```bash
adb shell "su -c '/data/local/tmp/injector com.example.targetapp /data/local/tmp/libstealth_agent.so'"
```

3. Launch the target app on your phone. The eBPF kernel script will instantly catch the launch, inject the payload, scrub the memory, and the injector will securely terminate itself.
