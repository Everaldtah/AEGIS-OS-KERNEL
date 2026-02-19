#!/bin/bash
# AEGIS-OS QEMU Test Script
# Boots the custom kernel in QEMU for testing

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="$PROJECT_ROOT/build"
KERNEL_IMAGE="$BUILD_DIR/kernel/vmlinuz-aegis"
MODULE_KO="$BUILD_DIR/modules/ai_sentinel.ko"

# QEMU configuration
QEMU_MEMORY="${QEMU_MEMORY:-2048}"
QEMU_SMP="${QEMU_SMP:-2}"
QEMU_DISPLAY="${QEMU_DISPLAY:-gtk}"  # gtk, sdl, none, vnc=:1

echo "========================================"
echo "AEGIS-OS QEMU Test"
echo "========================================"
echo ""

# Check if kernel exists
if [ ! -f "$KERNEL_IMAGE" ]; then
    echo "ERROR: Kernel not found at $KERNEL_IMAGE"
    echo "Run ./scripts/02-build-kernel.sh first"
    exit 1
fi

# Check if module exists
if [ ! -f "$MODULE_KO" ]; then
    echo "WARNING: AI-Sentinel module not found at $MODULE_KO"
    echo "Run ./scripts/03-build-module.sh to build the module"
    echo ""
fi

# Create initramfs if it doesn't exist
INITRAMFS="$BUILD_DIR/images/initramfs.cpio.gz"
if [ ! -f "$INITRAMFS" ]; then
    echo "Creating minimal initramfs..."
    mkdir -p "$BUILD_DIR/images/initramfs"
    cd "$BUILD_DIR/images/initramfs"

    # Create basic directory structure
    mkdir -p {bin,sbin,etc,proc,sys,dev,tmp,root,home,mnt,lib,lib64}

    # Create basic device nodes
    sudo mknod dev/null c 1 3
    sudo mknod dev/zero c 1 5
    sudo mknod dev/console c 5 1
    sudo mknod dev/tty c 5 0
    sudo mknod dev/random c 1 8
    sudo mknod dev/urandom c 1 9

    # Create init script
    cat > init << 'INIT_EOF'
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sysfs /sys
mount -t devtmpfs devtmpfs /dev

echo ""
echo "========================================"
echo "AEGIS-OS Kernel - Test Environment"
echo "========================================"
echo ""
echo "Kernel: $(uname -r)"
echo "Hostname: aegis-test"
echo ""

# Load AI-Sentinel module if available
if [ -f /lib/modules/ai_sentinel.ko ]; then
    echo "Loading AI-Sentinel LSM module..."
    insmod /lib/modules/ai_sentinel.ko
    if [ $? -eq 0 ]; then
        echo "AI-Sentinel module loaded successfully!"
        echo ""
        echo "Checking security modules..."
        cat /sys/kernel/security/lsm 2>/dev/null || echo "  LSM interface not available"
        echo ""
        echo "AI-Sentinel sysfs interface:"
        ls -la /sys/kernel/ai_sentinel/ 2>/dev/null || echo "  Not available"
    else
        echo "Failed to load AI-Sentinel module!"
    fi
else
    echo "AI-Sentinel module not found, starting shell..."
fi

echo ""
echo "Starting shell..."
echo "Type 'exit' to shut down."
echo ""
exec sh
INIT_EOF

    chmod +x init

    # Copy essential utilities (if using busybox)
    if command -v busybox &> /dev/null; then
        echo "Using busybox for initramfs..."
        # Create symlinks for busybox applets
        for applet in $(busybox --list); do
            ln -sf /bin/busybox bin/$applet 2>/dev/null || true
        done
        # Copy busybox
        cp $(which busybox) bin/
    else
        echo "WARNING: busybox not found, initramfs will be minimal"
    fi

    # Create initramfs
    find . | cpio -o -H newc | gzip > "$INITRAMFS"

    cd "$PROJECT_ROOT"
    echo "✓ Initramfs created"
fi

# Check KVM availability
KVM_AVAILABLE=false
if [ -e /dev/kvm ] && [ -r /dev/kvm ] && [ -w /dev/kvm ]; then
    KVM_AVAILABLE=true
    echo "✓ KVM is available"
else
    echo "⚠ KVM not available, using software emulation (slower)"
fi

# Prepare module loading command
MODULE_LOAD_CMD=""
if [ -f "$MODULE_KO" ]; then
    # We'll need to include the module in the initramfs or load it later
    echo "✓ AI-Sentinel module available"
fi

# Build QEMU command
QEMU_CMD="qemu-system-x86_64"

if [ "$KVM_AVAILABLE" = true ]; then
    QEMU_CMD+=" -enable-kvm -cpu host"
else
    QEMU_CMD+=" -cpu qemu64"
fi

QEMU_CMD+=" -m $QEMU_MEMORY"
QEMU_CMD+=" -smp $QEMU_SMP"
QEMU_CMD+=" -kernel $KERNEL_IMAGE"
QEMU_CMD+=" -initrd $INITRAMFS"
QEMU_CMD+=" -display $QEMU_DISPLAY"
QEMU_CMD+=" -serial mon:stdio"

# Add network for testing
QEMU_CMD+=" -netdev user,id=net0,hostfwd=tcp::2222-:22"
QEMU_CMD+=" -device virtio-net,netdev=net0"

# Additional options
QEMU_CMD+=" -no-reboot"
QEMU_CMD+=" -monitor stdio"

# Enable debug if requested
if [ "$AEGIS_DEBUG" = "1" ]; then
    QEMU_CMD+=" -d int,cpu_reset"
    QEMU_CMD+=" -D /tmp/aegis-qemu-debug.log"
fi

echo ""
echo "QEMU Configuration:"
echo "  Memory: ${QEMU_MEMORY}MB"
echo "  CPUs: $QEMU_SMP"
echo "  Display: $QEMU_DISPLAY"
echo "  KVM: $KVM_AVAILABLE"
echo ""

echo "Starting QEMU..."
echo "Press Ctrl-A, X to exit QEMU"
echo ""
echo "========================================"
echo ""

# Run QEMU
eval $QEMU_CMD

echo ""
echo "QEMU exited"
