# AEGIS-OS Quick Start Guide

This guide will help you get started with AEGIS-OS development and testing.

## Prerequisites

- Linux host system (Ubuntu 22.04/24.04 recommended, or similar)
- At least 8GB RAM (16GB recommended for kernel builds)
- 20GB free disk space
- sudo/root access

## Initial Setup

### 1. Install Build Dependencies

```bash
cd ~/aegis-os
./scripts/01-setup-env.sh
```

This will install:
- GCC, make, and other build tools
- QEMU/KVM for testing
- Required libraries and utilities

### 2. Build the Kernel

```bash
./scripts/02-build-kernel.sh
```

This will:
- Download Linux 6.x LTS source
- Configure with security hardening
- Build kernel and modules (~30-60 minutes)

### 3. Build AI-Sentinel Module

```bash
./scripts/03-build-module.sh
```

This compiles the custom LSM module.

### 4. Test in QEMU

```bash
./scripts/04-run-qemu.sh
```

This boots your custom kernel in a virtual machine.

## Alternative: Build Everything

```bash
cd ~/aegis-os
make setup    # Install dependencies
make kernel   # Build kernel
make module   # Build AI-Sentinel module
make fs-tools # Build ForensicFS tools
```

## Building Individual Components

### Kernel Only

```bash
cd ~/aegis-os
make kernel
```

### AI-Sentinel Module Only

```bash
cd modules/ai-sentinel
make
```

### ForensicFS Tools Only

```bash
cd fs/tools
make
```

## Running Tests

```bash
# Run all tests
make test

# Or run individually
./testing/test-kernel.sh
./testing/test-module.sh
```

## First Boot in QEMU

When you first boot the kernel:

1. The system will start in QEMU
2. You'll see a minimal shell prompt
3. The AI-Sentinel module should load automatically
4. Check it's working:

```bash
# In QEMU:
cat /proc/version
cat /sys/kernel/security/lsm
cat /sys/kernel/ai_sentinel/version
```

## Testing AI-Sentinel

### Monitor System Activity

```bash
# In QEMU or on AEGIS-OS:

# Check tracked processes
cat /sys/kernel/ai_sentinel/process_list

# View statistics
cat /sys/kernel/ai_sentinel/tracked_processes
cat /sys/kernel/ai_sentinel/pending_events

# Generate some activity
ping -c 1 8.8.8.8
ls /root

# Check the process list again
cat /sys/kernel/ai_sentinel/process_list
```

### Test Enforce Mode

```bash
# Enable enforce mode
echo 1 > /sys/kernel/ai_sentinel/enforce_mode

# Try to run something (might be blocked if trust score is low)
# Disable again to return to monitor mode
echo 0 > /sys/kernel/ai_sentinel/enforce_mode
```

## Using ForensicFS Tools

### Snapshots

```bash
# Create a snapshot
aegis-snapshot --create "test-snapshot"

# List snapshots
aegis-snapshot --list

# Restore snapshot
aegis-snapshot --restore "test-snapshot"
```

### Integrity Verification

```bash
# Verify /ro filesystem
aegis-integrity --verify /ro

# Run full integrity check
aegis-integrity --check
```

### Evidence Collection

```bash
# Collect all evidence
aegis-evidence --collect --type all

# Collect network evidence for 60 seconds
aegis-evidence --collect --type network --duration 60

# List evidence collections
aegis-evidence --list

# Verify evidence
aegis-evidence --verify ev-1234567890
```

## Development Workflow

### Making Changes

1. Edit source files
2. Rebuild affected component
3. Test in QEMU
4. Run tests

Example:

```bash
# Edit AI-Sentinel source
vim modules/ai-sentinel/src/hooks.c

# Rebuild module
cd modules/ai-sentinel
make

# Test
cd ../..
./testing/test-module.sh
```

### Debugging

```bash
# Check kernel log
dmesg | tail -100

# Filter for AI-Sentinel messages
dmesg | grep -i sentinel

# Enable debug output
insmod ai_sentinel.ko dyndbg=+p

# View process activity
cat /sys/kernel/ai_sentinel/process_list
```

## Common Issues

### Build Fails

- Check dependencies: `./scripts/01-setup-env.sh`
- Check disk space: `df -h`
- Check memory: `free -h`

### Module Won't Load

```bash
# Check kernel version match
uname -r
modinfo ai_sentinel.ko | grep vermagic

# Check dmesg for errors
dmesg | tail -20
```

### QEMU Won't Start

```bash
# Check KVM is available
ls -l /dev/kvm

# Check QEMU installation
qemu-system-x86_64 --version

# Try without KVM
QEMU_DISPLAY=none ./scripts/04-run-qemu.sh
```

## Next Steps

1. **Explore the codebase**:
   - `kernel/README.md` - Kernel documentation
   - `modules/ai-sentinel/README.md` - LSM module documentation
   - `fs/README.md` - Filesystem documentation

2. **Customize**:
   - Modify kernel config: `kernel/configs/aegis_defconfig`
   - Adjust security features
   - Add custom LSM hooks

3. **Build Userspace**:
   - NEXUS AI runtime
   - SEMANTICSIEM log analysis
   - GUI components

## Getting Help

- Check documentation in component README.md files
- Review test scripts for usage examples
- Examine kernel log: `dmesg`
- Run tests: `make test`

## Project Structure

```
aegis-os/
├── kernel/              # Kernel sources and config
├── modules/             # Kernel modules
│   └── ai-sentinel/    # AI-Sentinel LSM
├── fs/                  # ForensicFS
│   └── tools/          # Evidence collection tools
├── scripts/             # Build scripts
├── testing/             # Test scripts
├── build/              # Build output (generated)
├── Makefile            # Top-level build
├── README.md           # Project overview
└── QUICKSTART.md       # This file
```

## Contributing

When making changes:
1. Follow the existing code style
2. Add tests for new features
3. Update documentation
4. Test thoroughly before committing

## License

AEGIS-OS components are licensed under GPLv2 unless otherwise noted.
