#!/bin/bash
set -e

# ==============================================================================
# eBPF Injector Docker Build Wrapper
# ==============================================================================
# This script is a convenience wrapper for user on macOS, Windows, or Linux distributions
# that do not have the native AArch64 cross-compilation toolchains installed.
# It spins up an isolated Docker container and executes the Makefile inside it.

IMAGE_NAME="ebpf-builder"

# 1. Verify Docker is installed
if ! command -v docker &> /dev/null; then
    echo "[-] Error: Docker is not installed or not in PATH."
    echo "    Please install Docker Desktop, or compile natively on Linux by running 'make'."
    exit 1
fi

# 2. Build the toolchain container if it doesn't exist locally
if ! docker image inspect "$IMAGE_NAME" > /dev/null 2>&1; then
    echo "[*] Docker image '$IMAGE_NAME' not found locally."
    echo "[*] Building the cross-compilation toolchain from Dockerfile (This may take a few minutes)..."
    docker build -t "$IMAGE_NAME" .
fi

# 3. Mount current directory and execute `make` inside the container
echo "[*] Container ready. Spinning up builder to compile injector..."
docker run --rm -v "$(pwd):/work" -w /work "$IMAGE_NAME" make

echo "[+] Compilation finished successfully! The static 'injector' binary is ready."
