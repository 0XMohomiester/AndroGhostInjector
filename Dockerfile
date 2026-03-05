FROM ubuntu:22.04
ENV DEBIAN_FRONTEND=noninteractive

# One-time install of all cross-compilation dependencies
RUN apt-get update && apt-get install -y \
      clang llvm \
      gcc-aarch64-linux-gnu libc6-dev-arm64-cross \
      curl tar make pkg-config \
      libelf-dev zlib1g-dev libbpf-dev \
      xz-utils && \
    rm -rf /var/lib/apt/lists/*

# Copy pre-downloaded bpftool binary from host
COPY bpftool_bin /usr/local/bin/bpftool
RUN chmod +x /usr/local/bin/bpftool && bpftool --version

# Build libbpf v1.5.0 from source for aarch64 cross-compilation
# Ubuntu 22.04's packaged libbpf (v0.5) is too old for proper BTF/CO-RE support on Android
RUN apt-get update && apt-get install -y git && rm -rf /var/lib/apt/lists/* && \
    git clone --branch v1.5.0 --depth 1 https://github.com/libbpf/libbpf.git /opt/libbpf && \
    cd /opt/libbpf/src && \
    CC=aarch64-linux-gnu-gcc BUILD_STATIC_ONLY=y DESTDIR=/opt/libbpf-arm64 \
    OBJDIR=/tmp/libbpf-build \
    make install && \
    ls -la /opt/libbpf-arm64/usr/lib64/libbpf.a

WORKDIR /work
