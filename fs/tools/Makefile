# SPDX-License-Identifier: GPL-2.0
# ForensicFS Tools Makefile

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra -O2 -std=gnu99
LDFLAGS :=

# Installation directories
PREFIX := /usr/local
BINDIR := $(PREFIX)/bin
MANDIR := $(PREFIX)/share/man

# Targets
TARGETS := aegis-snapshot aegis-integrity aegis-evidence

# Default target
all: $(TARGETS)

# Build aegis-snapshot
aegis-snapshot: aegis-snapshot.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build aegis-integrity
aegis-integrity: aegis-integrity.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Build aegis-evidence
aegis-evidence: aegis-evidence.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# Clean
clean:
	rm -f $(TARGETS) *.o

# Install
install: all
	install -d $(BINDIR)
	install -m 755 $(TARGETS) $(BINDIR)

# Uninstall
uninstall:
	for t in $(TARGETS); do rm -f $(BINDIR)/$$t; done

# Help
help:
	@echo "ForensicFS Tools - Available targets:"
	@echo "  all       - Build all tools (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  install   - Install to $(BINDIR)"
	@echo "  uninstall - Remove installed tools"
	@echo "  help      - Show this help message"

.PHONY: all clean install uninstall help
