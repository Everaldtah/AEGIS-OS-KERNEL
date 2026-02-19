# ForensicFS - Forensic-by-Default Filesystem

ForensicFS provides immutable system storage with built-in evidence preservation for AEGIS-OS.

## Architecture

```
/ro        - Read-only base system (squashfs + dm-verity)
/rw        - User-writable overlay (OverlayFS upper layer)
/lab       - Isolated sandbox (ephemeral tmpfs)
/evidence  - Append-only logging (WORM device)
```

## Components

1. **Immutable Base (/ro)**
   - SquashFS compressed read-only filesystem
   - dm-verity for integrity verification
   - Contains base OS and security tools

2. **Writable Overlay (/rw)**
   - OverlayFS upper layer
   - User data and configuration changes
   - Can be reset to clean state

3. **Analysis Lab (/lab)**
   - Ephemeral tmpfs for malware analysis
   - Isolated from base system
   - Automatically destroyed on shutdown

4. **Evidence Store (/evidence)**
   - Append-only logging
   - Tamper-evident storage
   - WORM (Write Once, Read Many) semantics

## Tools

- `aegis-snapshot` - Create/restore filesystem snapshots
- `aegis-integrity` - Verify filesystem integrity with dm-verity
- `aegis-evidence` - Collect and manage forensic evidence

## Usage

```bash
# Create snapshot of current state
aegis-snapshot create "before analysis"

# Restore snapshot
aegis-snapshot restore "before analysis"

# List snapshots
aegis-snapshot list

# Verify integrity
aegis-integrity verify /ro

# Collect evidence
aegis-evidence collect --type network --duration 300

# View evidence
aegis-evidence list
```

## Implementation Details

### dm-verity Configuration

The base system uses dm-verity for cryptographic integrity verification:

```
Root hash stored in kernel command line
Data blocks hashed in Merkle tree
Any modification detected at block level
System refuses to mount if verification fails
```

### Evidence Logging

All security events are logged to `/evidence` with:

- Cryptographic signing (HSM-backed keys)
- Append-only semantics (no modification/deletion)
- Automatic rotation and archival
- Chain of custody metadata

### Snapshot Mechanism

Snapshots use OverlayFS snapshot capabilities:

- Base layers remain immutable
- Upper layer changes captured
- Metadata includes timestamp, hash, creator
- Support for differential snapshots
