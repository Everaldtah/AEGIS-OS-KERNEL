#!/bin/bash
# AEGIS-OS Environment Setup Script
# Installs dependencies for kernel development and testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "AEGIS-OS Environment Setup"
echo "========================================"

# Detect OS
if [ -f /etc/os-release ]; then
    . /etc/os-release
    OS=$ID
else
    echo "ERROR: Cannot detect OS"
    exit 1
fi

echo "Detected OS: $OS"

install_debian_ubuntu() {
    echo "Installing dependencies for Debian/Ubuntu..."

    sudo apt-get update

    # Core build tools
    sudo apt-get install -y \
        build-essential \
        bc \
        bison \
        flex \
        libssl-dev \
        libelf-dev \
        pkg-config \
        gcc \
        make \
        ccache

    # Additional kernel build tools
    sudo apt-get install -y \
        git \
        quilt \
        wget \
        curl \
        rsync \
        kmod

    # QEMU/KVM for testing
    sudo apt-get install -y \
        qemu-system-x86 \
        qemu-kvm \
        qemu-utils \
        ovmf

    # Filesystem tools
    sudo apt-get install -y \
        e2fsprogs \
        squashfs-tools \
        erofs-utils \
        xfsprogs \
        btrfs-progs

    # Debugging tools
    sudo apt-get install -y \
        gdb \
        strace \
        ltrace

    # Python for testing
    sudo apt-get install -y \
        python3 \
        python3-pip

    echo "Dependencies installed successfully!"
}

install_fedora_rhel() {
    echo "Installing dependencies for Fedora/RHEL..."

    sudo dnf install -y \
        gcc \
        make \
        bc \
        bison \
        flex \
        openssl-devel \
        elfutils-libelf-devel \
        pkg-config \
        git \
        wget \
        curl \
        rsync \
        kmod \
        qemu-system-x86 \
        qemu-kvm \
        ovmf \
        e2fsprogs \
        squashfs-tools \
        xfsprogs \
        btrfs-progs \
        gdb \
        strace \
        ltrace \
        python3 \
        python3-pip

    echo "Dependencies installed successfully!"
}

install_arch() {
    echo "Installing dependencies for Arch Linux..."

    sudo pacman -S --needed \
        base-devel \
        bc \
        bison \
        flex \
        openssl \
        libelf \
        pkg-config \
        git \
        wget \
        curl \
        rsync \
        kmod \
        qemu-system-x86 \
        qemu-arch-extra \
        ovmf \
        e2fsprogs \
        squashfs-tools \
        xfsprogs \
        btrfs-progs \
        gdb \
        strace \
        ltrace \
        python \
        python-pip

    echo "Dependencies installed!"
}

# OS-specific installation
case "$OS" in
    ubuntu|debian)
        install_debian_ubuntu
        ;;
    fedora|rhel|centos|rocky|almalinux)
        install_fedora_rhel
        ;;
    arch|manjaro)
        install_arch
        ;;
    *)
        echo "WARNING: Unsupported OS: $OS"
        echo "Please install dependencies manually:"
        echo "  - build-essential, gcc, make, bc"
        echo "  - bison, flex, libssl-dev, libelf-dev"
        echo "  - qemu-kvm, ovmf"
        echo "  - e2fsprogs, squashfs-tools"
        exit 1
        ;;
esac

# Create build directories
echo ""
echo "Creating build directories..."
mkdir -p "$PROJECT_ROOT/build"
mkdir -p "$PROJECT_ROOT/build/kernel"
mkdir -p "$PROJECT_ROOT/build/modules"
mkdir -p "$PROJECT_ROOT/build/images"

# Verify QEMU/KVM support
echo ""
echo "Verifying QEMU/KVM support..."
if [ -e /dev/kvm ]; then
    echo "✓ KVM is available"
    if kvm-ok 2>/dev/null; then
        echo "✓ KVM is usable"
    else
        echo "⚠ KVM may not be properly configured"
    fi
else
    echo "⚠ KVM not found, QEMU will use software emulation (slower)"
fi

# Check compiler
echo ""
echo "Verifying compiler..."
gcc --version | head -n1

# Set environment variables for kernel building
echo ""
echo "Setting up environment..."
cat >> "$PROJECT_ROOT/build/env.sh" << 'EOF'
# AEGIS-OS Build Environment
export AEGIS_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export AEGIS_BUILD="$AEGIS_ROOT/build"
export AEGIS_KERNEL="$AEGIS_BUILD/kernel"
export AEGIS_MODULES="$AEGIS_BUILD/modules"

# Add build tools to PATH
export PATH="$AEGIS_BUILD/tools:$PATH"

# Kernel build optimization
export CONCURRENCY_LEVEL=$(nproc)
export MAKEFLAGS="-j$CONCURRENCY_LEVEL"
EOF

echo "✓ Environment configuration written to $PROJECT_ROOT/build/env.sh"

# Source the environment
source "$PROJECT_ROOT/build/env.sh"

echo ""
echo "========================================"
echo "Setup Complete!"
echo "========================================"
echo ""
echo "Next steps:"
echo "  1. Source the environment: source build/env.sh"
echo "  2. Run: ./scripts/02-build-kernel.sh"
echo ""
