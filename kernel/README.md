# AEGIS-OS Kernel

Custom hardened Linux kernel for AEGIS-OS with integrated security features.

## Overview

The AEGIS-OS kernel is based on Linux 6.x LTS with extensive security hardening and custom Linux Security Modules (LSMs) for AI-native behavioral analysis.

## Kernel Configuration

### Security Features Enabled

**Memory Protection:**
- KASLR (Kernel Address Space Layout Randomization)
- KASAN (Kernel Address Sanitizer)
- CFI (Control Flow Integrity)
- Stack protector (strong)
- Stack canaries
- Hardened usercopy
- Fortify source
- Read-only kernel data
- Write-only kernel data (where applicable)
- slab_hardened
- slub_debug

**Access Control:**
- LSM (Linux Security Modules) framework
- Landlock (sandboxing)
- AppArmor (optional)
- Tomoyo (optional)
- Yama (ptrace protection)

**Audit & Integrity:**
- Audit subsystem
- IMA (Integrity Measurement Architecture)
- EVM (Extended Verification Module)
- dm-verity (block device integrity)

**Process Isolation:**
- Seccomp (secure computing mode)
- User namespaces
- PID namespaces
- Network namespaces
- Mount namespaces
- Cgroup namespaces

**Filesystems:**
- OverlayFS (for layered filesystems)
- SquashFS (compressed read-only)
- dm-verity (block integrity)
- Btrfs (CoW filesystem)

## Building the Kernel

### Prerequisites

```bash
# Install dependencies
./scripts/01-setup-env.sh
```

### Build Process

```bash
# Download and configure kernel
./scripts/02-build-kernel.sh
```

This will:
1. Download Linux 6.x LTS source
2. Apply AEGIS-OS specific patches
3. Configure with security-focused settings
4. Build kernel and modules
5. Install to `build/kernel/`

### Build Output

```
build/kernel/
├── vmlinuz-aegis          # Kernel image
├── System.map-aegis       # Symbol table
├── config-aegis           # Configuration
└── lib/modules/6.x.x/     # Kernel modules
```

## Kernel Command Line Options

Add these to your bootloader configuration:

```
# Security
slab_nomerge
slub_debug=FZP
page_poison=1
page_alloc.shuffle=1
iommu=force

# IMA/EVM
ima_policy=appraise_tcb
ima_appraise=fix
evm=fix

# dm-verity root hash
dm-verity.dev=XXXXXXXXXXXX

# Debug (development only)
earlyprintk=serial,ttyS0,115200
debug
ignore_loglevel
```

## Custom Patches

Place patches in `kernel/patches/` - they will be applied automatically during build.

### Patch Naming Convention

- `0001-security-add-feature.patch`
- `0002-hardening-enable-option.patch`
- etc.

## Kernel Modules

### AI-Sentinel LSM

Custom Linux Security Module for behavioral analysis.

```bash
# Build module
./scripts/03-build-module.sh

# Load module
sudo insmod build/modules/ai_sentinel.ko

# Verify
cat /sys/kernel/security/lsm
cat /sys/kernel/ai_sentinel/version
```

### Module Configuration

Runtime configuration via sysfs:

```bash
# Enable/disable
echo 1 > /sys/kernel/ai_sentinel/enabled

# Set mode (0=monitor, 1=enforce)
echo 0 > /sys/kernel/ai_sentinel/enforce_mode

# Default trust score
echo 75 > /sys/kernel/ai_sentinel/default_trust_score

# View statistics
cat /sys/kernel/ai_sentinel/tracked_processes
cat /sys/kernel/ai_sentinel/process_list
```

## Debugging

### QEMU Testing

```bash
# Boot in QEMU
./scripts/04-run-qemu.sh
```

### Kernel Debugging

```bash
# View kernel messages
dmesg | tail -100

# Filter AI-Sentinel messages
dmesg | grep -i "ai-sentinel"

# Check loaded modules
lsmod | grep sentinel

# Check security hooks
cat /proc/keys
cat /sys/kernel/debug/tracing/trace
```

## Security Hardening Details

### Stack Protection

- **Stack protector strong**: Adds canaries to stack frames
- **Stack protector all**: Protects all functions (not just those with buffers)
- **VMAP stack**: Virtual mapped stack for guard pages

### Control Flow Integrity

- **KCFI (Kernel Control Flow Integrity)**: Validates indirect calls
- **Shadow call stack**: Protects return addresses

### Memory Safety

- **Hardened usercopy**: Validates copy_from_user/copy_to_user
- **Fortify source**: Compile-time buffer overflow detection
- **PAGE_POISON**: Detects use-after-free

### Randomization

- **KASLR**: Randomizes kernel base address
- **Randomize memory**: Randomizes page allocator
- **Randomize Kstack offset**: Randomizes kernel stack offset per syscall

## Performance Considerations

Security features have performance overhead:

| Feature | Overhead | Impact |
|---------|----------|--------|
| KASLR | Minimal | One-time boot cost |
| Stack protector | Low | Per-function prologue/epilogue |
| CFI | Medium | Indirect call validation |
| IMA | High | File measurement on access |
| AI-Sentinel | Low-Medium | Depends on event rate |

## Troubleshooting

### Kernel Won't Boot

1. Check kernel config: `cat build/kernel/config-aegis`
2. Enable early debugging in command line
3. Try minimal config: `make defconfig` first
4. Check dmesg from serial console

### Module Won't Load

1. Verify kernel version matches
2. Check `dmesg` for errors
3. Enable debug: `modprobe ai_sentinel dyndbg=+p`
4. Verify LSM framework: `cat /sys/kernel/security/lsm`

### Performance Issues

1. Disable debug features in production
2. Tune IMA policy
3. Adjust AI-Sentinel event rate limits
4. Monitor with `perf top`

## Security Certifications

The AEGIS-OS kernel aims to be compatible with:

- Common Criteria EAL 4+
- FIPS 140-2 Level 1 (cryptographic modules)
- NIAP Protection Profile

## Resources

- Linux Kernel Documentation: https://www.kernel.org/doc/html/latest/
- KSPP (Kernel Self Protection Project): https://kernsec.org/wiki/index.php/Kernel_Self_Protection_Project
- CLIP OS Kernel Hardening: https://github.com/clipos/kernel hardened

## License

GPLv2 - See kernel source for full license information.
