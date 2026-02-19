#!/bin/bash
# AEGIS-OS AI-Sentinel Module Build Script

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODULE_DIR="$PROJECT_ROOT/modules/ai-sentinel"
KERNEL_BUILD="$PROJECT_ROOT/build/kernel"

echo "========================================"
echo "AEGIS-OS AI-Sentinel Module Build"
echo "========================================"
echo ""

# Load environment
if [ -f "$PROJECT_ROOT/build/env.sh" ]; then
    source "$PROJECT_ROOT/build/env.sh"
fi

# Check if kernel source is available
if [ ! -d "$KERNEL_BUILD/lib/modules" ]; then
    echo "ERROR: Kernel not built yet!"
    echo "Run ./scripts/02-build-kernel.sh first"
    exit 1
fi

# Find kernel version
KERNEL_VERSION=$(ls "$KERNEL_BUILD/lib/modules/" 2>/dev/null | head -n1)
if [ -z "$KERNEL_VERSION" ]; then
    echo "ERROR: Cannot find kernel version"
    exit 1
fi

echo "Kernel version: $KERNEL_VERSION"
echo ""

# Set kernel build directory
KERNEL_SRC_DIR="$KERNEL_SRC/linux-$KERNEL_VERSION"
if [ ! -d "$KERNEL_SRC_DIR" ]; then
    KERNEL_SRC_DIR="$PROJECT_ROOT/kernel/src/linux-$KERNEL_VERSION"
fi

if [ ! -d "$KERNEL_SRC_DIR" ]; then
    echo "ERROR: Kernel source not found at $KERNEL_SRC_DIR"
    exit 1
fi

# Build the module
echo "Building AI-Sentinel module..."
cd "$MODULE_DIR"

# Export kernel directory for make
export KERNEL_DIR="$KERNEL_SRC_DIR"

# Build
make clean
make -j"$(nproc)"

# Copy to build directory
echo ""
echo "Installing module to build directory..."
mkdir -p "$PROJECT_ROOT/build/modules"
cp ai_sentinel.ko "$PROJECT_ROOT/build/modules/"

echo "✓ Module build complete!"
echo ""
echo "Build artifacts:"
echo "  Module: $PROJECT_ROOT/build/modules/ai_sentinel.ko"
echo ""
echo "Module info:"
modinfo "$PROJECT_ROOT/build/modules/ai_sentinel.ko" 2>/dev/null || modinfo ai_sentinel.ko
echo ""
echo "========================================"
echo "Build Complete!"
echo "========================================"
echo ""
echo "To load the module:"
echo "  sudo insmod $PROJECT_ROOT/build/modules/ai_sentinel.ko"
echo ""
echo "To test the module:"
echo "  ./scripts/04-run-qemu.sh"
echo ""
