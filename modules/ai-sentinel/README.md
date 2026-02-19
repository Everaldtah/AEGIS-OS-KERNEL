# AI-Sentinel LSM Module

Linux Security Module for real-time behavioral analysis and anomaly detection in AEGIS-OS.

## Overview

AI-Sentinel is a custom Linux Security Module (LSM) that:

- Intercepts security-relevant system calls
- Tracks process behavior and assigns trust scores
- Communicates events to userspace AI runtime via netlink
- Supports real-time decision making (allow/block/quarantine)

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                   Userspace AI Runtime                  │
│                   (NEXUS)                               │
└────────────────────────────┬────────────────────────────┘
                             │ Netlink
┌────────────────────────────┴────────────────────────────┐
│              AI-Sentinel LSM Module                     │
│  ┌───────────┐  ┌──────────┐  ┌──────────┐            │
│  │   Hooks   │─→│  Tracker │─→│ Netlink  │            │
│  └───────────┘  └──────────┘  └──────────┘            │
│       │                                           │    │
│       └──→ Security Hook Callbacks                 │    │
│                                                  │    │
└──────────────────────────────────────────────────┴────┘
                 │
                 ▼
         ┌───────────────┐
         │ Linux Kernel  │
         │  Security     │
         │  Framework    │
         └───────────────┘
```

## Components

### 1. Security Hooks (`hooks.c`)

Implements LSM hooks for:
- `bprm_check_security` - Process execution
- `task_free` - Process exit
- `file_permission` - File access monitoring
- `socket_connect` - Outbound network connections
- `socket_bind` - Port binding
- `task_fix_setuid` - Privilege escalation
- `file_mmap` - Memory mapping (W+X detection)
- `ptrace_access_check` - Debugger detection

### 2. Process Tracker (`process_tracker.c`)

- Maintains list of tracked processes
- Assigns and updates trust scores (0-100)
- Records process metadata (PID, PPID, UID, executable path)
- Tracks statistics (syscalls, file ops, network ops)

### 3. Event System (`netlink.c`)

- Queues security events
- Batches events for efficient transmission
- Sends to userspace via netlink socket
- Receives decisions from AI runtime

### 4. Sysfs Interface (`sysfs.c`)

Runtime configuration at `/sys/kernel/ai_sentinel/`:
- `enabled` - Enable/disable monitoring
- `enforce_mode` - Switch between monitor/enforce
- `default_trust_score` - Initial score for new processes
- `version` - Module version
- `tracked_processes` - Number of tracked processes
- `process_list` - List all tracked processes
- `pending_events` - Events queued for transmission

## Event Types

| Type | Description | Default Severity |
|------|-------------|------------------|
| EXEC | Process execution | LOW |
| EXIT | Process exit | INFO |
| FORK | Process fork | INFO |
| FILE_OPEN | File opened | LOW-MEDIUM |
| FILE_WRITE | File written | MEDIUM-HIGH |
| SOCKET_CONNECT | Outbound connection | LOW-CRITICAL |
| SOCKET_BIND | Port binding | LOW |
| PRIV_ESCALATE | Privilege change | HIGH |
| MMAP_EXEC | Executable mapping | MEDIUM-HIGH |
| PTRACE | Debugger attached | MEDIUM |

## Severity Levels

Events are scored as:
- **INFO** - Normal operation
- **LOW** - Minor concern
- **MEDIUM** - Worthy of attention
- **HIGH** - Suspicious activity
- **CRITICAL** - Likely malicious

## Building

```bash
cd modules/ai-sentinel
make
```

Or from project root:
```bash
make module
```

## Loading the Module

```bash
# Load the module
sudo insmod build/modules/ai_sentinel.ko

# Verify it's loaded
lsmod | grep ai_sentinel
cat /sys/kernel/ai_sentinel/version
cat /sys/kernel/security/lsm
```

## Configuration

### Monitor Mode (Default)

Only logs events, doesn't block operations:
```bash
echo 0 > /sys/kernel/ai_sentinel/enforce_mode
```

### Enforce Mode

Blocks operations based on trust scores:
```bash
echo 1 > /sys/kernel/ai_sentinel/enforce_mode
```

In enforce mode:
- Trust score < 10: Process execution blocked
- Trust score < 30: File operations may be blocked
- Critical events automatically blocked

### Trust Scores

Default trust score for new processes:
```bash
echo 75 > /sys/kernel/ai_sentinel/default_trust_score
```

Score adjustments happen automatically:
- Privilege escalation: -20
- W+X memory mapping: -15
- Suspicious network connection: Variable

## Viewing Data

### Process List
```bash
cat /sys/kernel/ai_sentinel/process_list
```

Output:
```
PID   PPID  UID  Score  Command         Executable
1234  1000  0    75     sshd            /usr/sbin/sshd
5678  1234  1000 50     bash            /bin/bash
```

### Statistics
```bash
cat /sys/kernel/ai_sentinel/tracked_processes
cat /sys/kernel/ai_sentinel/pending_events
```

## Integration with Userspace AI

The module sends events to userspace via netlink. A userspace daemon should:

1. Create netlink socket (family 31)
2. Join multicast group 1
3. Parse events
4. Analyze behavior
5. Send decisions back

### Event Format

```c
struct ai_sentinel_event {
    type: enum ai_sentinel_event_type
    severity: enum ai_sentinel_severity
    pid: int
    uid: int
    comm: string (16 chars)
    timestamp: u64
    data: union {
        file: { path, flags, mode }
        socket: { family, protocol, sport, dport, addresses }
        privilege: { ruid, euid }
        mmap: { addr, size, prot }
    }
}
```

### Decision Format

Userspace can send decisions:
- **ALLOW** - Increase trust score (+5)
- **BLOCK** - Decrease trust score (-30)
- **QUARANTINE** - Strongly decrease score (-50)
- **KILL** - Set score to 0 and terminate process

## Troubleshooting

### Module Won't Load

```bash
# Check kernel log
dmesg | tail -20

# Verify kernel version match
uname -r
modinfo ai_sentinel.ko | grep vermagic

# Enable debug
insmod ai_sentinel.ko dyndbg=+p
```

### Events Not Being Sent

```bash
# Check if module is enabled
cat /sys/kernel/ai_sentinel/enabled

# Check pending events
cat /sys/kernel/ai_sentinel/pending_events

# Verify netlink socket
cat /proc/net/netlink | grep 31
```

### High Memory Usage

Process tracking list can grow large. Tune:
```bash
# Reduce tracked process limit in ai_sentinel.h
#define AI_SENTINEL_MAX_PROCS 2048  # Default: 4096
```

## Security Considerations

1. **Privilege Escalation**: Module runs in kernel space - bugs can compromise system
2. **DoS Potential**: High event rates can consume CPU/memory
3. **Information Leaks**: Event data may contain sensitive information
4. **Decision Latency**: Enforce mode decisions must be fast

## Performance

Typical overhead:
- Process fork: +0.5μs
- File operations: +1-2μs
- Network connections: +2-5μs

Tuning:
- Disable logging: `echo 0 > /sys/kernel/ai_sentinel/log_all_events`
- Reduce event frequency: Filter in hooks
- Batch events: Automatic (100ms flush)

## Future Enhancements

- [ ] eBPF-based filtering for lower overhead
- [ ] Machine learning model in kernel (via BPF)
- [ ] Integration with IMA/EVM
- [ ] Per-process resource limits based on trust
- [ ] Network-level isolation for low-trust processes
- [ ] Integration with Landlock for sandboxing

## License

GPLv2 - See source files for details.
