#!/bin/bash
# AEGIS-OS Kernel Build Script
# Downloads, configures, and builds the hardened Linux kernel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
KERNEL_VERSION="${KERNEL_VERSION:-6.6.50}"  # LTS version
KERNEL_SRC="$PROJECT_ROOT/kernel/src"
KERNEL_BUILD="$PROJECT_ROOT/build/kernel"
KERNEL_CONFIG="$PROJECT_ROOT/kernel/configs/aegis_defconfig"

echo "========================================"
echo "AEGIS-OS Kernel Build"
echo "========================================"
echo "Kernel Version: $KERNEL_VERSION"
echo ""

# Load environment
if [ -f "$PROJECT_ROOT/build/env.sh" ]; then
    source "$PROJECT_ROOT/build/env.sh"
fi

# Check if kernel source exists, download if not
if [ ! -d "$KERNEL_SRC/linux-$KERNEL_VERSION" ]; then
    echo "Downloading Linux kernel $KERNEL_VERSION..."
    mkdir -p "$KERNEL_SRC"

    cd "$KERNEL_SRC"
    wget "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-$KERNEL_VERSION.tar.xz"

    echo "Extracting kernel source..."
    tar -xf "linux-$KERNEL_VERSION.tar.xz"
    rm "linux-$KERNEL_VERSION.tar.xz"

    echo "✓ Kernel source downloaded"
else
    echo "✓ Kernel source already exists"
fi

KERNEL_DIR="$KERNEL_SRC/linux-$KERNEL_VERSION"
cd "$KERNEL_DIR"

# Apply AEGIS-OS specific patches if they exist
PATCH_DIR="$PROJECT_ROOT/kernel/patches"
if [ -d "$PATCH_DIR" ] && [ "$(ls -A $PATCH_DIR/*.patch 2>/dev/null)" ]; then
    echo ""
    echo "Applying AEGIS-OS patches..."
    for patch in "$PATCH_DIR"/*.patch; do
        if [ -f "$patch" ]; then
            echo "  Applying $(basename "$patch")..."
            patch -p1 < "$patch" || echo "  ⚠ Patch failed: $(basename "$patch")"
        fi
    done
fi

# Create build directory
mkdir -p "$KERNEL_BUILD"

# Use existing config or create defconfig
echo ""
echo "Configuring kernel..."

if [ -f "$KERNEL_CONFIG" ]; then
    echo "Using AEGIS-OS defconfig..."
    cp "$KERNEL_CONFIG" "$KERNEL_DIR/.config"
else
    echo "Creating default configuration with security features..."
    make defconfig
    make kvm_guest.config 2>/dev/null || true

    # Enable security features
    ./scripts/config --enable SECURITY
    ./scripts/config --enable SECURITY_NETWORK
    ./scripts/config --enable SECURITY_PATH
    ./scripts/config --enable SECCOMP
    ./scripts/config --enable SECCOMP_FILTER
    ./scripts/config --enable SECURITY_LANDLOCK
    ./scripts/config --enable SECURITY_TOMOYO
    ./scripts/config --enable SECURITY_APPARMOR

    # Memory protection
    ./scripts/config --enable RANDOMIZE_BASE
    ./scripts/config --enable ASLR
    ./scripts/config --enable HARDENED_USERCOPY
    ./scripts/config --enable FORTIFY_SOURCE
    ./scripts/config --enable STACKPROTECTOR
    ./scripts/config --enable STACKPROTECTOR_STRONG
    ./scripts/config --enable CC_STACKPROTECTION
    ./scripts/config --enable RFENCE
    ./scripts/config --enable SLAB_HARDENED
    ./scripts/config --enable SLUB_DEBUG
    ./scripts/config --enable RANDOMIZE_MEMORY
    ./scripts/config --enable RANDOMIZE_KSTACK_OFFSET

    # Control Flow Integrity
    ./scripts/config --enable CC_HAVE_STACKPROTECTOR
    ./scripts/config --enable CC_HAVE_INLINE_YIELD
    ./scripts/config --enable MODULE_SIG
    ./scripts/config --enable MODULE_SIG_FORCE
    ./scripts/config --enable MODULE_SIG_ALL
    ./scripts/config --set-str MODULE_SIG_HASH sha256

    # IMA/EVM
    ./scripts/config --enable INTEGRITY
    ./scripts/config --enable IMA
    ./scripts/config --enable IMA_SYMLINK_MOD
    ./scripts/config --enable IMA_APPRAISE
    ./scripts/config --enable EVM

    # Auditing
    ./scripts/config --enable AUDIT
    ./scripts/config --enable AUDITSYSCALL

    # Network security
    ./scripts/config --enable NETFILTER
    ./scripts/config --enable NETFILTER_ADVANCED
    ./scripts/config --enable NF_CONNTRACK
    ./scripts/config --enable NETFILTER_XTABLES

    # Filesystems for ForensicFS
    ./scripts/config --enable OVERLAYFS
    ./scripts/config --enable SQUASHFS
    ./scripts/config --enable SQUASHFS_ZLIB
    ./scripts/config --enable SQUASHFS_LZ4
    ./scripts/config --enable SQUASHFS_XZ
    ./scripts/config --enable DM_VERITY
    ./scripts/config --enable DM_VERITY_FEC

    # Debugging
    ./scripts/config --enable DEBUG_KERNEL
    ./scripts/config --enable DEBUG_INFO
    ./scripts/config --enable KGDB
    ./scripts/config --enable KPROBES
    ./scripts/config --enable FTRACE

    # Save as AEGIS-OS defconfig
    mkdir -p "$PROJECT_ROOT/kernel/configs"
    cp .config "$KERNEL_CONFIG"
    echo "✓ Saved configuration to $KERNEL_CONFIG"
fi

# Olddefconfig to set new symbols to their default
echo ""
echo "Finalizing configuration..."
make olddefconfig

# Build kernel
echo ""
echo "Building kernel (this may take a while)..."
make -j"$(nproc)" bzImage modules

# Install to build directory
echo ""
echo "Installing kernel to build directory..."
INSTALL_MOD_PATH="$KERNEL_BUILD" make modules_install
INSTALL_PATH="$KERNEL_BUILD" make install

# Copy kernel image
cp arch/x86/boot/bzImage "$KERNEL_BUILD/vmlinuz-aegis"
cp System.map "$KERNEL_BUILD/System.map-aegis"
cp .config "$KERNEL_BUILD/config-aegis"

echo "✓ Kernel build complete!"
echo ""
echo "Build artifacts:"
echo "  Kernel:   $KERNEL_BUILD/vmlinuz-aegis"
echo "  Modules:  $KERNEL_BUILD/lib/modules/$KERNEL_VERSION"
echo "  Config:   $KERNEL_BUILD/config-aegis"
echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Build AI-Sentinel module: ./scripts/03-build-module.sh"
echo "  2. Test in QEMU: ./scripts/04-run-qemu.sh"
echo ""
