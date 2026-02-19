#!/bin/bash
# AEGIS-OS Kernel Tests
# Basic functionality tests for the custom kernel

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "AEGIS-OS Kernel Tests"
echo "========================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Test counters
PASSED=0
FAILED=0
SKIPPED=0

# Helper functions
test_result() {
    local test_name="$1"
    local result="$2"
    local message="$3"

    if [ "$result" = "PASS" ]; then
        echo -e "${GREEN}✓ PASS${NC} $test_name"
        ((PASSED++))
    elif [ "$result" = "FAIL" ]; then
        echo -e "${RED}✗ FAIL${NC} $test_name"
        if [ -n "$message" ]; then
            echo -e "  ${RED}$message${NC}"
        fi
        ((FAILED++))
    else
        echo -e "${YELLOW}⊘ SKIP${NC} $test_name"
        if [ -n "$message" ]; then
            echo -e "  ${YELLOW}$message${NC}"
        fi
        ((SKIPPED++))
    fi
}

# Check if running on AEGIS-OS kernel
check_kernel() {
    echo "[1/8] Checking kernel version..."
    if [ -f "/proc/version" ]; then
        local version=$(uname -r)
        echo "  Kernel version: $version"
        if [[ "$version" == *"aegis"* ]] || [ -f "/sys/kernel/ai_sentinel/version" ]; then
            test_result "Kernel identification" "PASS"
            return 0
        else
            test_result "Kernel identification" "SKIP" "Not running on AEGIS-OS kernel"
            return 1
        fi
    else
        test_result "Kernel identification" "FAIL" "Cannot read /proc/version"
        return 1
    fi
}

# Test LSM framework
test_lsm() {
    echo ""
    echo "[2/8] Testing LSM framework..."

    if [ ! -f "/sys/kernel/security/lsm" ]; then
        test_result "LSM framework" "SKIP" "LSM sysfs not available"
        return 0
    fi

    local lsm_list=$(cat /sys/kernel/security/lsm)
    echo "  Active LSMs: $lsm_list"

    if [[ "$lsm_list" == *"sentinel"* ]] || [[ "$lsm_list" == *"ai_sentinel"* ]]; then
        test_result "AI-Sentinel LSM loaded" "PASS"
    else
        test_result "AI-Sentinel LSM loaded" "FAIL" "AI-Sentinel not in LSM list"
    fi
}

# Test AI-Sentinel sysfs interface
test_ai_sentinel_sysfs() {
    echo ""
    echo "[3/8] Testing AI-Sentinel sysfs interface..."

    if [ ! -d "/sys/kernel/ai_sentinel" ]; then
        test_result "AI-Sentinel sysfs" "SKIP" "sysfs interface not available"
        return 0
    fi

    # Test enabled attribute
    if [ -f "/sys/kernel/ai_sentinel/enabled" ]; then
        local enabled=$(cat /sys/kernel/ai_sentinel/enabled)
        echo "  Enabled: $enabled"
        test_result "enabled attribute" "PASS"
    else
        test_result "enabled attribute" "FAIL"
    fi

    # Test version attribute
    if [ -f "/sys/kernel/ai_sentinel/version" ]; then
        local version=$(cat /sys/kernel/ai_sentinel/version)
        echo "  Version: $version"
        test_result "version attribute" "PASS"
    else
        test_result "version attribute" "FAIL"
    fi

    # Test enforce_mode attribute
    if [ -f "/sys/kernel/ai_sentinel/enforce_mode" ]; then
        local mode=$(cat /sys/kernel/ai_sentinel/enforce_mode)
        echo "  Mode: $mode"
        test_result "enforce_mode attribute" "PASS"
    else
        test_result "enforce_mode attribute" "FAIL"
    fi
}

# Test process tracking
test_process_tracking() {
    echo ""
    echo "[4/8] Testing process tracking..."

    if [ ! -f "/sys/kernel/ai_sentinel/tracked_processes" ]; then
        test_result "Process tracking" "SKIP" "tracked_processes not available"
        return 0
    fi

    local count=$(cat /sys/kernel/ai_sentinel/tracked_processes)
    echo "  Tracked processes: $count"
    test_result "Process tracking counter" "PASS"

    if [ -f "/sys/kernel/ai_sentinel/process_list" ]; then
        echo "  Process list:"
        head -5 /sys/kernel/ai_sentinel/process_list | sed 's/^/    /'
        test_result "Process list" "PASS"
    else
        test_result "Process list" "FAIL"
    fi
}

# Test security features
test_security_features() {
    echo ""
    echo "[5/8] Testing security features..."

    # Check KASLR
    if [ -f "/sys/kernel/debug/kaslr" ] || grep -q "Kernel page table isolation" /proc/cpuinfo; then
        test_result "KASLR" "PASS"
    else
        test_result "KASLR" "SKIP" "Cannot verify KASLR status"
    fi

    # Check stack protector
    if dmesg | grep -q "stack protector"; then
        test_result "Stack protector" "PASS"
    else
        test_result "Stack protector" "SKIP" "Cannot verify stack protector"
    fi

    # Check hardened usercopy
    if grep -q "Hardened user copy" /proc/cpuinfo 2>/dev/null; then
        test_result "Hardened usercopy" "PASS"
    else
        test_result "Hardened usercopy" "SKIP" "Cannot verify"
    fi
}

# Test seccomp
test_seccomp() {
    echo ""
    echo "[6/8] Testing seccomp..."

    if [ ! -f "/proc/sys/kernel/seccomp" ]; then
        test_result "Seccomp support" "SKIP" "Seccomp not available"
        return 0
    fi

    local seccomp=$(cat /proc/sys/kernel/seccomp)
    echo "  Actions available: $seccomp"

    # Test seccomp filter
    if [[ "$seccomp" == *"2"* ]]; then
        test_result "Seccomp filter mode" "PASS"
    else
        test_result "Seccomp filter mode" "FAIL"
    fi
}

# Test filesystems
test_filesystems() {
    echo ""
    echo "[7/8] Testing ForensicFS filesystems..."

    # Check for overlayfs
    if grep -q "overlay" /proc/filesystems; then
        test_result "OverlayFS support" "PASS"
    else
        test_result "OverlayFS support" "FAIL"
    fi

    # Check for squashfs
    if grep -q "squashfs" /proc/filesystems; then
        test_result "SquashFS support" "PASS"
    else
        test_result "SquashFS support" "FAIL"
    fi

    # Check mount points
    if mount | grep -q "overlay"; then
        test_result "Overlay mount active" "PASS"
    else
        test_result "Overlay mount active" "SKIP" "No overlay mount found"
    fi
}

# Test audit system
test_audit() {
    echo ""
    echo "[8/8] Testing audit system..."

    if [ ! -d "/proc/net/audit" ] && [ ! -d "/sys/kernel/audit" ]; then
        test_result "Audit subsystem" "SKIP" "Audit not available"
        return 0
    fi

    # Check if auditd is running
    if pgrep -x "auditd" > /dev/null; then
        test_result "Audit daemon" "PASS"
    else
        test_result "Audit daemon" "SKIP" "auditd not running"
    fi
}

# Run all tests
main() {
    check_kernel || true
    test_lsm
    test_ai_sentinel_sysfs
    test_process_tracking
    test_security_features
    test_seccomp
    test_filesystems
    test_audit

    echo ""
    echo "========================================"
    echo "Test Summary"
    echo "========================================"
    echo -e "  ${GREEN}Passed:${NC}   $PASSED"
    echo -e "  ${RED}Failed:${NC}   $FAILED"
    echo -e "  ${YELLOW}Skipped:${NC}  $SKIPPED"
    echo "  Total:    $((PASSED + FAILED + SKIPPED))"
    echo ""

    if [ $FAILED -gt 0 ]; then
        echo -e "${RED}Some tests failed!${NC}"
        exit 1
    else
        echo -e "${GREEN}All tests passed!${NC}"
        exit 0
    fi
}

main "$@"
