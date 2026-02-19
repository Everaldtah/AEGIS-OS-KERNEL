# AEGIS-OS Core Kernel

AI-native ethical cybersecurity operating system kernel layer.

## Overview

AEGIS-OS provides a hardened Linux kernel with custom security modules for real-time behavioral analysis and forensic capabilities.

### Key Components

- **Hardened Linux 6.x LTS Kernel** - Security-hardened base with KASLR, CFI, stack protection
- **AI-Sentinel LSM** - Custom Linux Security Module for syscall-level behavioral monitoring
- **ForensicFS** - Immutable filesystem with snapshots and evidence preservation
- **Process Containment** - Landlock/seccomp-based sandboxing for malware analysis

## Directory Structure

```
aegis-os/
├── kernel/                 # Kernel sources and patches
│   ├── src/               # Downloaded kernel source
│   ├── configs/           # Kernel configurations
│   └── patches/           # Security patches
├── modules/               # Custom kernel modules
│   └── ai-sentinel/      # AI-Sentinel LSM module
├── scripts/              # Build and setup scripts
├── fs/                   # ForensicFS userspace tools
├── build/               # Build artifacts
└── testing/             # Test scripts
```

## Quick Start

### Prerequisites

Linux build environment with:
- GCC/Clang with plugin support
- build-essential, bc, bison, flex, libssl-dev
- QEMU/KVM for testing
- e2fsprogs, squashfs-tools

### Setup

```bash
# Run initial setup (installs dependencies)
./scripts/01-setup-env.sh

# Download and configure kernel
./scripts/02-build-kernel.sh

# Build AI-Sentinel module
./scripts/03-build-module.sh

# Test in QEMU
./scripts/04-run-qemu.sh
```

## Components

### AI-Sentinel LSM

Custom Linux Security Module that:
- Hooks into syscall layer for behavioral monitoring
- Assigns trust scores (0-100) to processes
- Logs security-relevant events
- Communicates with userspace AI runtime via netlink

### ForensicFS

Forensic-by-default filesystem layout:
- `/ro` - Read-only base system (squashfs)
- `/rw` - User-writable overlay (upper layer)
- `/lab` - Isolated sandbox (ephemeral)
- `/evidence` - Append-only logging (WORM)

### Process Containment

Sandboxing capabilities:
- Landlock filesystem sandboxing
- Seccomp-BPF syscall filtering
- Network namespace isolation
- CLI tools for sandbox management

## Security Features

- **Memory Protection**: KASLR, PIE, stack protector, CFI
- **Access Control**: LSM hooks, capability-based
- **Process Isolation**: Namespaces, seccomp, landlock
- **Integrity**: dm-verity, IMA/EVM
- **Audit**: Comprehensive event logging

## Development

### Building the Kernel

```bash
cd kernel
# Download kernel source
# Configure with configs/aegis_defconfig
make -j$(nproc)
```

### Building the AI-Sentinel Module

```bash
cd modules/ai-sentinel
make
```

### Testing

```bash
# Unit tests
./testing/test-kernel.sh
./testing/test-module.sh

# Integration tests (run in QEMU)
./testing/integration-test.sh
```

## Architecture

```
┌─────────────────────────────────────────────────────┐
│              AEGIS-OS Kernel Layer                  │
├─────────────────────────────────────────────────────┤
│  Userspace AI Runtime (NEXUS)                       │
│  ├── Behavioral Analysis Engine                     │
│  └── Decision Module                                │
├─────────────────────────────────────────────────────┤
│  AI-Sentinel LSM                │
│  ├── Syscall Interception                            │
│  ├── Process Tracking                               │
│  └── Netlink Communication                          │
├─────────────────────────────────────────────────────┤
│  Linux Kernel 6.x LTS (Hardened)                    │
│  ├── Security Frameworks                            │
│  ├── Memory Protection                              │
│  └── Process Containment                            │
├─────────────────────────────────────────────────────┤
│  ForensicFS                                         │
│  ├── Immutable Base (squashfs + dm-verity)          │
│  ├── Overlay Mounts                                 │
│  └── Evidence Logging (append-only)                 │
└─────────────────────────────────────────────────────┘
```

## Project Status

- [x] Project structure created
- [ ] Phase 1: Build Environment Setup
- [ ] Phase 2: Kernel Base Configuration
- [ ] Phase 3: AI-Sentinel LSM Module
- [ ] Phase 4: ForensicFS Foundation
- [ ] Phase 5: Process Containment

## License

Proprietary - AEGIS-OS Project

## Documentation

- See `kernel/README.md` for kernel details
- See `modules/ai-sentinel/README.md` for LSM module details
- See `fs/README.md` for filesystem details
