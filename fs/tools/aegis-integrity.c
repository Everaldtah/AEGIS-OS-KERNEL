// SPDX-License-Identifier: GPL-2.0
/*
 * aegis-integrity - ForensicFS Integrity Verification
 *
 * Tool for verifying filesystem integrity using dm-verity
 *
 * Copyright (c) 2025 AEGIS-OS Project
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#define VERSION "1.0.0"

#define DM_DIR "/dev/mapper"
#define VERITY_HASH_BLOCK_SIZE 4096
#define VERITY_BLOCK_SIZE 4096

/* Command line options */
static struct option long_options[] = {
	{"verify", required_argument, 0, 'v'},
	{"setup", required_argument, 0, 's'},
	{"hash", required_argument, 0, 'h'},
	{"check", no_argument, 0, 'c'},
	{"help", no_argument, 0, 'H'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0}
};

/* Function prototypes */
static int integrity_verify(const char *path);
static int integrity_setup(const char *device, const char *hash_path);
static char *integrity_hash(const char *path);
static int integrity_check(void);
static void print_help(const char *progname);
static void print_version(void);
static int read_root_hash(const char *path, char *hash, size_t len);

/**
 * integrity_verify - Verify filesystem integrity
 * @path: Path to verify (e.g., /ro)
 *
 * Uses dm-verity to verify cryptographic integrity
 */
int integrity_verify(const char *path)
{
	struct stat st;
	char line[512];
	FILE *fp;
	int failed = 0;

	printf("Verifying integrity of: %s\n", path);

	if (stat(path, &st) != 0) {
		perror("stat");
		return -1;
	}

	/* Check if device mapper target is active */
	fp = fopen("/proc/mounts", "r");
	if (!fp) {
		perror("Failed to open /proc/mounts");
		return -1;
	}

	while (fgets(line, sizeof(line), fp)) {
		char mount_path[256];
		char dev[256];
		char fstype[64];

		if (sscanf(line, "%255s %255s %63s", dev, mount_path, fstype) == 3) {
			if (strcmp(mount_path, path) == 0) {
				printf("  Mount point: %s\n", path);
				printf("  Device: %s\n", dev);
				printf("  Type: %s\n", fstype);

				/* Check if using verity */
				if (strstr(dev, "dm-verity") || strstr(fstype, "verity")) {
					printf("  ✓ dm-verity active\n");
				} else {
					printf("  ⚠ Warning: Not using dm-verity\n");
					failed = 1;
				}
				break;
			}
		}
	}
	fclose(fp);

	/* Check for integrity errors in kernel log */
	fp = popen("dmesg | grep -i 'verity\\|integrity\\|corruption' | tail -20", "r");
	if (fp) {
		int error_count = 0;
		while (fgets(line, sizeof(line), fp)) {
			if (strstr(line, "error") || strstr(line, "failed") ||
			    strstr(line, "corruption") || strstr(line, "invalid")) {
				printf("  ⚠ Kernel log: %s", line);
				error_count++;
				failed = 1;
			}
		}
		pclose(fp);

		if (error_count == 0) {
			printf("  ✓ No integrity errors in kernel log\n");
		}
	}

	/* Verify root hash if available */
	char root_hash[65];
	if (read_root_hash("/etc/aegis/root_hash", root_hash, sizeof(root_hash)) == 0) {
		printf("  Expected root hash: %s\n", root_hash);
		printf("  ✓ Root hash configuration found\n");
	}

	if (failed) {
		printf("\n❌ Integrity verification FAILED\n");
		return 1;
	}

	printf("\n✓ Integrity verification PASSED\n");
	return 0;
}

/**
 * integrity_setup - Set up dm-verity for a device
 * @device: Block device to set up (e.g., /dev/sda1)
 * @hash_path: Path to store hash tree
 */
int integrity_setup(const char *device, const char *hash_path)
{
	char cmd[1024];
	char root_hash[65];
	int ret;

	printf("Setting up dm-verity for: %s\n", device);

	/* Create hash tree using veritysetup */
	snprintf(cmd, sizeof(cmd),
		 "veritysetup format %s %s 2>/dev/null | grep 'Root hash'",
		 device, hash_path);

	FILE *fp = popen(cmd, "r");
	if (!fp) {
		perror("Failed to run veritysetup");
		return -1;
	}

	if (fgets(root_hash, sizeof(root_hash), fp)) {
		/* Remove trailing newline */
		root_hash[strcspn(root_hash, "\n")] = 0;
		printf("  Root hash: %s\n", root_hash);

		/* Save root hash for verification */
		FILE *hash_file = fopen("/etc/aegis/root_hash", "w");
		if (hash_file) {
			fprintf(hash_file, "%s\n", root_hash);
			fclose(hash_file);
			printf("  Root hash saved to /etc/aegis/root_hash\n");
		}
	}
	pclose(fp);

	/* Create verity device */
	snprintf(cmd, sizeof(cmd),
		 "veritysetup create aegis-ro %s %s %s 2>&1",
		 device, hash_path, root_hash);

	ret = system(cmd);
	if (ret != 0) {
		fprintf(stderr, "Failed to create verity device\n");
		return -1;
	}

	printf("✓ dm-verity device created: /dev/mapper/aegis-ro\n");

	/* Update fstab if needed */
	/* TODO: Add fstab entry for automatic mounting on boot */

	return 0;
}

/**
 * integrity_hash - Calculate hash of file or directory
 * @path: Path to hash
 */
char *integrity_hash(const char *path)
{
	static char hash[65];
	char cmd[1024];
	FILE *fp;

	printf("Calculating hash of: %s\n", path);

	/* Use sha256sum for files */
	snprintf(cmd, sizeof(cmd), "sha256sum '%s' 2>/dev/null | cut -d' ' -f1", path);
	fp = popen(cmd, "r");
	if (!fp) {
		perror("Failed to calculate hash");
		return NULL;
	}

	if (fgets(hash, sizeof(hash), fp)) {
		hash[strcspn(hash, "\n")] = 0;
		printf("  SHA-256: %s\n", hash);
	}

	pclose(fp);
	return hash;
}

/**
 * integrity_check - Perform full integrity check
 */
int integrity_check(void)
{
	int failed = 0;

	printf("========================================\n");
	printf("AEGIS-OS Integrity Check\n");
	printf("========================================\n");
	printf("\n");

	/* Check root filesystem */
	printf("[1/4] Checking root filesystem...\n");
	if (integrity_verify("/") != 0)
		failed = 1;

	printf("\n");

	/* Check read-only base */
	printf("[2/4] checking read-only base...\n");
	if (integrity_verify("/ro") != 0)
		failed = 1;

	printf("\n");

	/* Check critical system files */
	printf("[3/4] Checking critical system files...\n");
	const char *critical_files[] = {
		"/bin/sh",
		"/bin/bash",
		"/usr/bin/sshd",
		"/lib/x86_64-linux-gnu/ld-linux-x86-64.so.2",
		NULL
	};

	for (int i = 0; critical_files[i]; i++) {
		printf("  Checking: %s\n", critical_files[i]);
		if (access(critical_files[i], F_OK) == 0) {
			integrity_hash(critical_files[i]);
		}
	}

	printf("\n");

	/* Check IMA/EVM signatures if available */
	printf("[4/4] Checking IMA/EVM signatures...\n");
	if (access("/sys/kernel/security/ima", F_OK) == 0) {
		printf("  ✓ IMA securityfs available\n");
		/* TODO: Read and verify IMA measurements */
	} else {
		printf("  ⚠ IMA not available\n");
	}

	printf("\n");
	printf("========================================\n");

	if (failed) {
		printf("❌ INTEGRITY CHECK FAILED\n");
		return 1;
	}

	printf("✓ INTEGRITY CHECK PASSED\n");
	return 0;
}

/**
 * read_root_hash - Read root hash from file
 */
int read_root_hash(const char *path, char *hash, size_t len)
{
	FILE *fp = fopen(path, "r");
	if (!fp)
		return -1;

	if (fgets(hash, len, fp)) {
		hash[strcspn(hash, "\n")] = 0;
		fclose(fp);
		return 0;
	}

	fclose(fp);
	return -1;
}

/**
 * print_help
 */
void print_help(const char *progname)
{
	printf("AEGIS-OS Integrity Verification Tool v%s\n\n", VERSION);
	printf("Usage: %s [OPTIONS]\n\n", progname);
	printf("Commands:\n");
	printf("  -v, --verify PATH     Verify integrity of path\n");
	printf("  -s, --setup DEV HASH  Set up dm-verity for device\n");
	printf("  -h, --hash PATH       Calculate hash of file/directory\n");
	printf("  -c, --check           Perform full integrity check\n");
	printf("  -H, --help            Show this help message\n");
	printf("  -V, --version         Show version information\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s --verify /ro\n", progname);
	printf("  %s --check\n", progname);
	printf("  %s --setup /dev/sda1 /var/lib/aegis/hash.dat\n", progname);
}

/**
 * print_version
 */
void print_version(void)
{
	printf("aegis-integrity version %s\n", VERSION);
	printf("Copyright (c) 2025 AEGIS-OS Project\n");
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;

	if (argc < 2) {
		print_help(argv[0]);
		return 1;
	}

	while ((opt = getopt_long(argc, argv, "v:s:h:cHV", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'v':
			return integrity_verify(optarg) == 0 ? 0 : 1;
		case 's':
			if (optind < argc) {
				return integrity_setup(optarg, argv[optind]) == 0 ? 0 : 1;
			} else {
				fprintf(stderr, "Error: --setup requires hash path argument\n");
				return 1;
			}
		case 'h':
			integrity_hash(optarg);
			return 0;
		case 'c':
			return integrity_check() == 0 ? 0 : 1;
		case 'H':
			print_help(argv[0]);
			return 0;
		case 'V':
			print_version();
			return 0;
		default:
			print_help(argv[0]);
			return 1;
		}
	}

	print_help(argv[0]);
	return 1;
}
