// SPDX-License-Identifier: GPL-2.0
/*
 * aegis-snapshot - ForensicFS Snapshot Management
 *
 * Tool for creating and restoring filesystem snapshots
 * using OverlayFS and device-mapper.
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
#include <sys/mount.h>
#include <sys/wait.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>
#include <limits.h>
#include <dirent.h>
#include <linux/loop.h>

#define VERSION "1.0.0"

/* Paths */
#define RO_BASE "/ro"
#define RW_BASE "/rw"
#define LAB_BASE "/lab"
#define EVIDENCE_BASE "/evidence"
#define SNAPSHOT_DIR "/var/lib/aegis/snapshots"
#define OVERLAY_WORK "/var/lib/aegis/overlay/work"
#define OVERLAY_UPPER "/var/lib/aegis/overlay/upper"

/* Snapshot metadata */
struct snapshot_meta {
	char name[256];
	char description[512];
	time_t created;
	unsigned long size;
	char hash[65];  /* SHA-256 hex */
};

/* Command line options */
static struct option long_options[] = {
	{"create", required_argument, 0, 'c'},
	{"restore", required_argument, 0, 'r'},
	{"list", no_argument, 0, 'l'},
	{"delete", required_argument, 0, 'd'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0}
};

/* Function prototypes */
static int snapshot_create(const char *name, const char *description);
static int snapshot_restore(const char *name);
static int snapshot_list(void);
static int snapshot_delete(const char *name);
static void print_help(const char *progname);
static void print_version(void);
static int ensure_directories(void);
static char *calculate_hash(const char *path);
static int mount_overlay(void);
static int umount_overlay(void);

/**
 * snapshot_create - Create a new snapshot
 * @name: Snapshot name
 * @description: Optional description
 */
int snapshot_create(const char *name, const char *description)
{
	struct snapshot_meta meta;
	char snap_dir[PATH_MAX];
	char upper_copy[PATH_MAX];
	FILE *meta_file;
	time_t now;

	printf("Creating snapshot: %s\n", name);

	/* Ensure directories exist */
	if (ensure_directories() < 0) {
		fprintf(stderr, "Failed to create directories\n");
		return -1;
	}

	/* Validate snapshot name */
	if (name[0] == '.' || strchr(name, '/') != NULL) {
		fprintf(stderr, "Invalid snapshot name\n");
		return -1;
	}

	/* Check if snapshot already exists */
	snprintf(snap_dir, sizeof(snap_dir), "%s/%s", SNAPSHOT_DIR, name);
	if (access(snap_dir, F_OK) == 0) {
		fprintf(stderr, "Snapshot '%s' already exists\n", name);
		return -1;
	}

	/* Create snapshot directory */
	if (mkdir(snap_dir, 0755) < 0) {
		perror("Failed to create snapshot directory");
		return -1;
	}

	/* Copy upper layer to snapshot */
	snprintf(upper_copy, sizeof(upper_copy), "%s/upper", snap_dir);
	if (mkdir(upper_copy, 0755) < 0) {
		perror("Failed to create upper copy");
		rmdir(snap_dir);
		return -1;
	}

	/* Use rsync to copy current upper layer */
	char upper_copy_src[PATH_MAX + 2];
	char upper_copy_dst[PATH_MAX + 2];
	snprintf(upper_copy_src, sizeof(upper_copy_src), "%s/", OVERLAY_UPPER);
	snprintf(upper_copy_dst, sizeof(upper_copy_dst), "%s/", upper_copy);
	pid_t pid = fork();
	if (pid == 0) {
		/* Child process */
		execlp("rsync", "rsync", "-aAX", upper_copy_src, upper_copy_dst, NULL);
		exit(1);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "Failed to copy upper layer\n");
			return -1;
		}
	} else {
		perror("Failed to fork for rsync");
		return -1;
	}

	/* Calculate hash of upper layer */
	char *hash = calculate_hash(upper_copy);
	if (!hash) {
		fprintf(stderr, "Warning: Failed to calculate hash\n");
		strncpy(meta.hash, "unknown", sizeof(meta.hash));
	} else {
		strncpy(meta.hash, hash, sizeof(meta.hash));
		free(hash);
	}

	/* Create metadata */
	memset(&meta, 0, sizeof(meta));
	strncpy(meta.name, name, sizeof(meta.name) - 1);
	if (description)
		strncpy(meta.description, description, sizeof(meta.description) - 1);
	time(&meta.created);

	/* Calculate size (rough estimate) */
	struct stat st;
	if (stat(upper_copy, &st) == 0) {
		meta.size = 0;  /* TODO: Implement recursive size calculation */
	}

	/* Write metadata file */
	char meta_path[PATH_MAX];
	snprintf(meta_path, sizeof(meta_path), "%s/meta.txt", snap_dir);

	meta_file = fopen(meta_path, "w");
	if (!meta_file) {
		perror("Failed to create metadata file");
		return -1;
	}

	fprintf(meta_file, "name=%s\n", meta.name);
	fprintf(meta_file, "description=%s\n", meta.description);
	fprintf(meta_file, "created=%ld\n", meta.created);
	fprintf(meta_file, "hash=%s\n", meta.hash);
	fprintf(meta_file, "size=%lu\n", meta.size);

	fclose(meta_file);

	printf("Snapshot '%s' created successfully\n", name);
	printf("  Hash: %s\n", meta.hash);
	printf("  Location: %s\n", snap_dir);

	return 0;
}

/**
 * snapshot_restore - Restore a snapshot
 * @name: Snapshot name
 */
int snapshot_restore(const char *name)
{
	char snap_dir[PATH_MAX];
	char upper_copy[PATH_MAX];
	struct stat st;

	printf("Restoring snapshot: %s\n", name);

	snprintf(snap_dir, sizeof(snap_dir), "%s/%s", SNAPSHOT_DIR, name);
	if (access(snap_dir, F_OK) != 0) {
		fprintf(stderr, "Snapshot '%s' not found\n", name);
		return -1;
	}

	snprintf(upper_copy, sizeof(upper_copy), "%s/upper", snap_dir);
	if (access(upper_copy, F_OK) != 0) {
		fprintf(stderr, "Snapshot data not found\n");
		return -1;
	}

	/* Unmount overlay if mounted */
	umount_overlay();

	/* Clear current upper layer */
	pid_t pid = fork();
	if (pid == 0) {
		execlp("rm", "rm", "-rf", OVERLAY_UPPER "/*", NULL);
		exit(1);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "Warning: Failed to clear upper layer\n");
		}
	} else {
		perror("Failed to fork for rm");
		return -1;
	}

	/* Copy snapshot to upper layer */
	char restore_src[PATH_MAX + 2];
	char restore_dst[PATH_MAX + 2];
	snprintf(restore_src, sizeof(restore_src), "%s/", upper_copy);
	snprintf(restore_dst, sizeof(restore_dst), "%s/", OVERLAY_UPPER);
	pid = fork();
	if (pid == 0) {
		execlp("rsync", "rsync", "-aAX", "--delete",
		       restore_src, restore_dst, NULL);
		exit(1);
	} else if (pid > 0) {
		int status;
		waitpid(pid, &status, 0);
		if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
			fprintf(stderr, "Failed to restore upper layer\n");
			return -1;
		}
	} else {
		perror("Failed to fork for rsync");
		return -1;
	}

	/* Remount overlay */
	mount_overlay();

	printf("Snapshot '%s' restored successfully\n", name);
	return 0;
}

/**
 * snapshot_list - List all snapshots
 */
int snapshot_list(void)
{
	DIR *dir;
	struct dirent *entry;
	time_t now;
	char time_buf[64];

	printf("Available snapshots:\n");
	printf("---------------------\n");

	dir = opendir(SNAPSHOT_DIR);
	if (!dir) {
		perror("Failed to open snapshots directory");
		return -1;
	}

	time(&now);

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		char meta_path[PATH_MAX];
		FILE *meta_file;
		char line[512];
		char name[256] = "";
		char hash[65] = "";
		time_t created = 0;

		snprintf(meta_path, sizeof(meta_path), "%s/%s/meta.txt",
			 SNAPSHOT_DIR, entry->d_name);

		meta_file = fopen(meta_path, "r");
		if (meta_file) {
			while (fgets(line, sizeof(line), meta_file)) {
				if (strncmp(line, "name=", 5) == 0)
					sscanf(line, "name=%255s", name);
				else if (strncmp(line, "hash=", 5) == 0)
					sscanf(line, "hash=%64s", hash);
				else if (strncmp(line, "created=", 8) == 0)
					sscanf(line, "created=%ld", &created);
			}
			fclose(meta_file);
		}

		if (name[0]) {
			struct tm *tm = localtime(&created);
			strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", tm);

			printf("  %-20s  %s  %s\n", name, time_buf, hash);
		}
	}

	closedir(dir);
	return 0;
}

/**
 * snapshot_delete - Delete a snapshot
 * @name: Snapshot name
 */
int snapshot_delete(const char *name)
{
	char snap_dir[PATH_MAX];
	char cmd[PATH_MAX];

	printf("Deleting snapshot: %s\n", name);

	snprintf(snap_dir, sizeof(snap_dir), "%s/%s", SNAPSHOT_DIR, name);
	if (access(snap_dir, F_OK) != 0) {
		fprintf(stderr, "Snapshot '%s' not found\n", name);
		return -1;
	}

	snprintf(cmd, sizeof(cmd), "rm -rf '%s'", snap_dir);
	if (system(cmd) != 0) {
		fprintf(stderr, "Failed to delete snapshot\n");
		return -1;
	}

	printf("Snapshot '%s' deleted\n", name);
	return 0;
}

/**
 * ensure_directories - Create required directories
 */
int ensure_directories(void)
{
	const char *dirs[] = {
		SNAPSHOT_DIR,
		OVERLAY_UPPER,
		OVERLAY_WORK,
		NULL
	};

	for (int i = 0; dirs[i]; i++) {
		struct stat st;
		if (stat(dirs[i], &st) != 0) {
			if (mkdir(dirs[i], 0755) < 0 && errno != EEXIST) {
				perror(dirs[i]);
				return -1;
			}
		}
	}

	return 0;
}

/**
 * mount_overlay - Mount overlay filesystem
 */
int mount_overlay(void)
{
	/* Unmount first if already mounted */
	umount("/ro");

	/* Mount overlay */
	char options[PATH_MAX * 2];
	snprintf(options, sizeof(options),
		 "lowerdir=%s,upperdir=%s,workdir=%s",
		 RO_BASE, OVERLAY_UPPER, OVERLAY_WORK);

	if (mount("overlay", "/ro", "overlay", 0, options) < 0) {
		perror("Failed to mount overlay");
		return -1;
	}

	return 0;
}

/**
 * umount_overlay - Unmount overlay filesystem
 */
int umount_overlay(void)
{
	if (umount("/ro") < 0 && errno != EINVAL) {
		perror("Failed to unmount overlay");
		return -1;
	}
	return 0;
}

/**
 * calculate_hash - Calculate SHA-256 hash of directory
 * Note: Simplified implementation - full version would walk directory tree
 */
char *calculate_hash(const char *path)
{
	static char hash[65];
	/* Placeholder - actual implementation would use openssl */
	strcpy(hash, "sha256_placeholder_hash");
	return hash;
}

/**
 * print_help - Print usage information
 */
void print_help(const char *progname)
{
	printf("AEGIS-OS Snapshot Manager v%s\n\n", VERSION);
	printf("Usage: %s [OPTIONS] [COMMAND]\n\n", progname);
	printf("Commands:\n");
	printf("  -c, --create NAME     Create a new snapshot\n");
	printf("  -r, --restore NAME    Restore a snapshot\n");
	printf("  -l, --list            List all snapshots\n");
	printf("  -d, --delete NAME     Delete a snapshot\n");
	printf("  -h, --help            Show this help message\n");
	printf("  -V, --version         Show version information\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s --create \"before-analysis\"\n", progname);
	printf("  %s --restore \"before-analysis\"\n", progname);
	printf("  %s --list\n", progname);
}

/**
 * print_version - Print version information
 */
void print_version(void)
{
	printf("aegis-snapshot version %s\n", VERSION);
	printf("Copyright (c) 2025 AEGIS-OS Project\n");
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	char *command = NULL;
	char *argument = NULL;

	if (argc < 2) {
		print_help(argv[0]);
		return 1;
	}

	while ((opt = getopt_long(argc, argv, "c:r:ld:hV", long_options, &option_index)) != -1) {
		switch (opt) {
		case 'c':
			return snapshot_create(optarg, NULL) == 0 ? 0 : 1;
		case 'r':
			return snapshot_restore(optarg) == 0 ? 0 : 1;
		case 'l':
			return snapshot_list() == 0 ? 0 : 1;
		case 'd':
			return snapshot_delete(optarg) == 0 ? 0 : 1;
		case 'h':
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
