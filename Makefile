# SPDX-License-Identifier: GPL-2.0
# AEGIS-OS Top-Level Makefile

.PHONY: all clean help install test kernel module fs-tools

# Default target
all: kernel module fs-tools

help:
	@echo "AEGIS-OS Build System"
	@echo ""
	@echo "Available targets:"
	@echo "  all        - Build everything (kernel, module, tools)"
	@echo "  kernel     - Build the hardened kernel"
	@echo "  module     - Build the AI-Sentinel LSM module"
	@echo "  fs-tools   - Build ForensicFS tools"
	@echo "  clean      - Clean all build artifacts"
	@echo "  install    - Install all components"
	@echo "  test       - Run tests"
	@echo "  help       - Show this message"
	@echo ""
	@echo "Quick start:"
	@echo "  1. make setup     # Install dependencies"
	@echo "  2. make kernel    # Build kernel"
	@echo "  3. make module    # Build AI-Sentinel module"
	@echo "  4. make test      # Run tests"

setup:
	@echo "Installing dependencies..."
	@./scripts/01-setup-env.sh

kernel:
	@echo "Building kernel..."
	@./scripts/02-build-kernel.sh

module:
	@echo "Building AI-Sentinel module..."
	@./scripts/03-build-module.sh

fs-tools:
	@echo "Building ForensicFS tools..."
	@$(MAKE) -C fs/tools

clean:
	@echo "Cleaning build artifacts..."
	@rm -rf build/*
	@$(MAKE) -C fs/tools clean
	@$(MAKE) -C modules/ai-sentinel clean 2>/dev/null || true

install: all
	@echo "Installing AEGIS-OS..."
	@echo "NOTE: Installation requires root privileges"
	@sudo $(MAKE) -C fs/tools install
	@# Kernel installation is manual - see documentation

test:
	@echo "Running tests..."
	@./testing/test-kernel.sh
	@./testing/test-module.sh

qemu:
	@echo "Starting QEMU..."
	@./scripts/04-run-qemu.sh

# Show project status
status:
	@echo "AEGIS-OS Build Status"
	@echo "===================="
	@echo ""
	@echo "Kernel:"
	@if [ -f build/kernel/vmlinuz-aegis ]; then \
		echo "  ✓ Built"; \
		ls -lh build/kernel/vmlinuz-aegis | awk '{print "    Size: " $$5}'; \
	else \
		echo "  ✗ Not built"; \
	fi
	@echo ""
	@echo "AI-Sentinel Module:"
	@if [ -f build/modules/ai_sentinel.ko ]; then \
		echo "  ✓ Built"; \
		ls -lh build/modules/ai_sentinel.ko | awk '{print "    Size: " $$5}'; \
	else \
		echo "  ✗ Not built"; \
	fi
	@echo ""
	@echo "ForensicFS Tools:"
	@if [ -f fs/tools/aegis-snapshot ]; then \
		echo "  ✓ Built"; \
	else \
		echo "  ✗ Not built"; \
	fi
