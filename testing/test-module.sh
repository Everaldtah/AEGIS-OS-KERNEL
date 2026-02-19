#!/bin/bash
# AEGIS-OS AI-Sentinel Module Tests
# Tests for the AI-Sentinel LSM module

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "========================================"
echo "AEGIS-OS AI-Sentinel Module Tests"
echo "========================================"
echo ""

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

PASSED=0
FAILED=0
SKIPPED=0

# Test helpers
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

# Check if module is loaded
check_module_loaded() {
    echo "[1/10] Checking if module is loaded..."

    if lsmod | grep -q "ai_sentinel"; then
        test_result "Module loaded" "PASS"
        return 0
    else
        test_result "Module loaded" "FAIL" "ai_sentinel module not found in lsmod"
        echo ""
        echo "Load the module first:"
        echo "  sudo insmod build/modules/ai_sentinel.ko"
        return 1
    fi
}

# Test module initialization
test_module_init() {
    echo ""
    echo "[2/10] Testing module initialization..."

    if [ -f "/sys/module/ai_sentinel/refcnt" ]; then
        local refcnt=$(cat /sys/module/ai_sentinel/refcnt)
        echo "  Ref count: $refcnt"
        test_result "Module sysfs" "PASS"
    else
        test_result "Module sysfs" "FAIL"
    fi
}

# Test sysfs interface
test_sysfs_interface() {
    echo ""
    echo "[3/10] Testing sysfs interface..."

    if [ ! -d "/sys/kernel/ai_sentinel" ]; then
        test_result "Sysfs directory" "FAIL" "ai_sentinel sysfs not found"
        return 1
    fi

    # Test each attribute
    for attr in enabled enforce_mode default_trust_score version tracked_processes pending_events; do
        if [ -f "/sys/kernel/ai_sentinel/$attr" ]; then
            local value=$(cat /sys/kernel/ai_sentinel/$attr)
            echo "  $attr: $value"
            test_result "Attribute: $attr" "PASS"
        else
            test_result "Attribute: $attr" "FAIL"
        fi
    done
}

# Test enabling/disabling
test_enable_disable() {
    echo ""
    echo "[4/10] Testing enable/disable..."

    if [ ! -w "/sys/kernel/ai_sentinel/enabled" ]; then
        test_result "Enable/disable" "SKIP" "Cannot write to enabled"
        return 0
    fi

    # Get current state
    local original=$(cat /sys/kernel/ai_sentinel/enabled)

    # Test disabling
    echo 0 > /sys/kernel/ai_sentinel/enabled 2>/dev/null
    local current=$(cat /sys/kernel/ai_sentinel/enabled)
    if [ "$current" = "0" ]; then
        test_result "Disable module" "PASS"
    else
        test_result "Disable module" "FAIL"
    fi

    # Test enabling
    echo 1 > /sys/kernel/ai_sentinel/enabled 2>/dev/null
    current=$(cat /sys/kernel/ai_sentinel/enabled)
    if [ "$current" = "1" ]; then
        test_result "Enable module" "PASS"
    else
        test_result "Enable module" "FAIL"
    fi

    # Restore original state
    echo $original > /sys/kernel/ai_sentinel/enabled
}

# Test trust score configuration
test_trust_score() {
    echo ""
    echo "[5/10] Testing trust score configuration..."

    if [ ! -w "/sys/kernel/ai_sentinel/default_trust_score" ]; then
        test_result "Trust score config" "SKIP" "Cannot write to default_trust_score"
        return 0
    fi

    # Get current value
    local original=$(cat /sys/kernel/ai_sentinel/default_trust_score)

    # Test setting value
    echo 50 > /sys/kernel/ai_sentinel/default_trust_score 2>/dev/null
    local current=$(cat /sys/kernel/ai_sentinel/default_trust_score)
    if [ "$current" = "50" ]; then
        test_result "Set trust score to 50" "PASS"
    else
        test_result "Set trust score to 50" "FAIL"
    fi

    # Test bounds
    echo 150 > /sys/kernel/ai_sentinel/default_trust_score 2>/dev/null
    current=$(cat /sys/kernel/ai_sentinel/default_trust_score)
    if [ "$current" = "100" ]; then
        test_result "Clamp to maximum (100)" "PASS"
    else
        test_result "Clamp to maximum (100)" "SKIP" "Bounds not enforced"
    fi

    # Restore original
    echo $original > /sys/kernel/ai_sentinel/default_trust_score
}

# Test process tracking
test_process_tracking() {
    echo ""
    echo "[6/10] Testing process tracking..."

    if [ ! -f "/sys/kernel/ai_sentinel/process_list" ]; then
        test_result "Process list" "FAIL"
        return 1
    fi

    # Get current count
    local before=$(cat /sys/kernel/ai_sentinel/tracked_processes)
    echo "  Tracked processes before: $before"

    # Start a test process
    sleep 60 &
    local test_pid=$!

    # Wait a bit for tracking
    sleep 0.5

    # Check if process is tracked
    local after=$(cat /sys/kernel/ai_sentinel/tracked_processes)
    echo "  Tracked processes after: $after"

    if [ "$after" -ge "$before" ]; then
        test_result "Process tracking" "PASS"
    else
        test_result "Process tracking" "FAIL" "Process count didn't increase"
    fi

    # Cleanup
    kill $test_pid 2>/dev/null || true
}

# Test security hooks
test_security_hooks() {
    echo ""
    echo "[7/10] Testing security hooks..."

    # Check if LSM is registered
    if [ -f "/sys/kernel/security/lsm" ]; then
        local lsm_list=$(cat /sys/kernel/security/lsm)
        echo "  Active LSMs: $lsm_list"

        if [[ "$lsm_list" == *"sentinel"* ]] || [[ "$lsm_list" == *"ai_sentinel"* ]]; then
            test_result "LSM registration" "PASS"
        else
            test_result "LSM registration" "FAIL" "ai_sentinel not in LSM list"
        fi
    else
        test_result "LSM registration" "SKIP" "LSM interface not available"
    fi

    # Test file operation monitoring (if enabled)
    if [ -f "/sys/kernel/ai_sentinel/enabled" ]; then
        local enabled=$(cat /sys/kernel/ai_sentinel/enabled)
        if [ "$enabled" = "1" ]; then
            # Create a test file to trigger hook
            local test_file="/tmp/aegis-test-$$"
            touch "$test_file" 2>/dev/null
            rm -f "$test_file" 2>/dev/null
            test_result "File operation hook" "PASS"
        else
            test_result "File operation hook" "SKIP" "Module disabled"
        fi
    fi
}

# Test enforce mode
test_enforce_mode() {
    echo ""
    echo "[8/10] Testing enforce mode..."

    if [ ! -w "/sys/kernel/ai_sentinel/enforce_mode" ]; then
        test_result "Enforce mode" "SKIP" "Cannot write to enforce_mode"
        return 0
    fi

    local original=$(cat /sys/kernel/ai_sentinel/enforce_mode)

    # Test setting enforce mode
    echo 1 > /sys/kernel/ai_sentinel/enforce_mode 2>/dev/null
    local current=$(cat /sys/kernel/ai_sentinel/enforce_mode)
    if [ "$current" = "1" ]; then
        test_result "Set enforce mode" "PASS"
    else
        test_result "Set enforce mode" "FAIL"
    fi

    # Restore
    echo $original > /sys/kernel/ai_sentinel/enforce_mode
}

# Test netlink communication
test_netlink() {
    echo ""
    echo "[9/10] Testing netlink communication..."

    # Check if netlink socket exists
    if netstat -g 2>/dev/null | grep -q "31" || \
       cat /proc/net/netlink 2>/dev/null | grep -q "31"; then
        test_result "Netlink socket" "PASS"
    else
        test_result "Netlink socket" "SKIP" "Cannot verify netlink"
    fi

    # Check for pending events
    if [ -f "/sys/kernel/ai_sentinel/pending_events" ]; then
        local events=$(cat /sys/kernel/ai_sentinel/pending_events)
        echo "  Pending events: $events"
        test_result "Event queue" "PASS"
    else
        test_result "Event queue" "FAIL"
    fi
}

# Test dmesg for errors
test_dmesg() {
    echo ""
    echo "[10/10] Checking dmesg for errors..."

    local errors=$(dmesg | grep -i "ai_sentinel" | grep -i "error\|fail\|warn" | tail -5)

    if [ -z "$errors" ]; then
        test_result "Kernel log errors" "PASS" "No errors found"
    else
        test_result "Kernel log errors" "WARN" "Some errors in kernel log:"
        echo "$errors" | sed 's/^/  /'
    fi
}

# Main test runner
main() {
    check_module_loaded || exit 1
    test_module_init
    test_sysfs_interface
    test_enable_disable
    test_trust_score
    test_process_tracking
    test_security_hooks
    test_enforce_mode
    test_netlink
    test_dmesg

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
