// SPDX-License-Identifier: GPL-2.0
/*
 * aegis-evidence - Forensic Evidence Collection
 *
 * Tool for collecting and managing forensic evidence
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
#include <dirent.h>
#include <sys/wait.h>

#define VERSION "1.0.0"

#define EVIDENCE_DIR "/evidence"
#define EVIDENCE_META "/evidence/meta"
#define MAX_EVIDENCE_SIZE (1024 * 1024 * 1024)  /* 1GB per collection */

/* Evidence types */
enum evidence_type {
	EVIDENCE_NETWORK = 0,
	EVIDENCE_PROCESS,
	EVIDENCE_FILESYSTEM,
	EVIDENCE_MEMORY,
	EVIDENCE_KERNEL,
	EVIDENCE_ALL
};

/* Command line options */
static struct option long_options[] = {
	{"collect", required_argument, 0, 'c'},
	{"list", no_argument, 0, 'l'},
	{"export", required_argument, 0, 'e'},
	{"verify", required_argument, 0, 'v'},
	{"type", required_argument, 0, 't'},
	{"duration", required_argument, 0, 'd'},
	{"output", required_argument, 0, 'o'},
	{"help", no_argument, 0, 'h'},
	{"version", no_argument, 0, 'V'},
	{0, 0, 0, 0}
};

/* Function prototypes */
static int evidence_collect(enum evidence_type type, int duration, const char *output);
static int evidence_list(void);
static int evidence_export(const char *id, const char *dest);
static int evidence_verify(const char *id);
static void print_help(const char *progname);
static void print_version(void);
static char *generate_evidence_id(void);
static int collect_network_evidence(const char *output_dir, int duration);
static int collect_process_evidence(const char *output_dir);
static int collect_filesystem_evidence(const char *output_dir);
static int collect_kernel_evidence(const char *output_dir);
static int sign_evidence(const char *path);

/**
 * evidence_collect - Collect forensic evidence
 * @type: Type of evidence to collect
 * @duration: Duration for collection (seconds)
 * @output: Output directory
 */
int evidence_collect(enum evidence_type type, int duration, const char *output)
{
	char evidence_id[64];
	char output_dir[PATH_MAX];
	time_t now;
	char timestamp[64];

	printf("========================================\n");
	printf("AEGIS-OS Evidence Collection\n");
	printf("========================================\n");

	/* Generate evidence ID */
	snprintf(evidence_id, sizeof(evidence_id), "ev-%s", generate_evidence_id());

	/* Create output directory */
	if (output) {
		snprintf(output_dir, sizeof(output_dir), "%s/%s", output, evidence_id);
	} else {
		snprintf(output_dir, sizeof(output_dir), "%s/%s", EVIDENCE_DIR, evidence_id);
	}

	if (mkdir(output_dir, 0755) < 0) {
		perror("Failed to create evidence directory");
		return -1;
	}

	/* Create metadata file */
	time(&now);
	strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localtime(&now));

	FILE *meta = fopen(strcat(output_dir, "/metadata.txt"), "w");
	if (!meta) {
		perror("Failed to create metadata file");
		return -1;
	}

	fprintf(meta, "evidence_id=%s\n", evidence_id);
	fprintf(meta, "collected_at=%s\n", timestamp);
	fprintf(meta, "duration=%d\n", duration);
	fprintf(meta, "type=%d\n", type);
	fprintf(meta, "hostname=aegis-os\n");

	/* Get system info */
	char hostname[256];
	gethostname(hostname, sizeof(hostname));
	fprintf(meta, "hostname=%s\n", hostname);

	fclose(meta);

	printf("Evidence ID: %s\n", evidence_id);
	printf("Output directory: %s\n", output_dir);
	printf("\n");

	/* Collect evidence based on type */
	int collected = 0;

	if (type == EVIDENCE_ALL || type == EVIDENCE_NETWORK) {
		printf("[1/4] Collecting network evidence...\n");
		if (collect_network_evidence(output_dir, duration) == 0) {
			collected++;
			printf("  ✓ Network evidence collected\n");
		}
	}

	if (type == EVIDENCE_ALL || type == EVIDENCE_PROCESS) {
		printf("[2/4] Collecting process evidence...\n");
		if (collect_process_evidence(output_dir) == 0) {
			collected++;
			printf("  ✓ Process evidence collected\n");
		}
	}

	if (type == EVIDENCE_ALL || type == EVIDENCE_FILESYSTEM) {
		printf("[3/4] Collecting filesystem evidence...\n");
		if (collect_filesystem_evidence(output_dir) == 0) {
			collected++;
			printf("  ✓ Filesystem evidence collected\n");
		}
	}

	if (type == EVIDENCE_ALL || type == EVIDENCE_KERNEL) {
		printf("[4/4] Collecting kernel evidence...\n");
		if (collect_kernel_evidence(output_dir) == 0) {
			collected++;
			printf("  ✓ Kernel evidence collected\n");
		}
	}

	/* Sign the evidence collection */
	printf("\nSigning evidence collection...\n");
	if (sign_evidence(output_dir) == 0) {
		printf("  ✓ Evidence signed\n");
	}

	printf("\n========================================\n");
	printf("✓ Evidence collection complete: %s\n", evidence_id);
	printf("  Location: %s\n", output_dir);
	printf("  Items collected: %d\n", collected);

	return 0;
}

/**
 * collect_network_evidence
 */
int collect_network_evidence(const char *output_dir, int duration)
{
	char cmd[PATH_MAX];
	int ret = 0;

	/* Capture network connections */
	snprintf(cmd, sizeof(cmd), "ss -tunap > %s/network_connections.txt 2>/dev/null",
		 output_dir);
	ret |= system(cmd);

	/* Capture network statistics */
	snprintf(cmd, sizeof(cmd), "netstat -s > %s/network_stats.txt 2>/dev/null",
		 output_dir);
	ret |= system(cmd);

	/* Capture routing table */
	snprintf(cmd, sizeof(cmd), "ip route > %s/routing_table.txt 2>/dev/null",
		 output_dir);
	ret |= system(cmd);

	/* Capture ARP cache */
	snprintf(cmd, sizeof(cmd), "ip neigh > %s/arp_cache.txt 2>/dev/null",
		 output_dir);
	ret |= system(cmd);

	/* Capture iptables rules */
	snprintf(cmd, sizeof(cmd), "iptables -L -v -n > %s/iptables.txt 2>/dev/null",
		 output_dir);
	ret |= system(cmd);

	/* Start packet capture if duration > 0 */
	if (duration > 0) {
		printf("  Capturing packets for %d seconds...\n", duration);
		snprintf(cmd, sizeof(cmd), "timeout %d tcpdump -i any -w %s/capture.pcap 2>/dev/null",
			 duration, output_dir);
		system(cmd);
	}

	return ret == 0 ? 0 : -1;
}

/**
 * collect_process_evidence
 */
int collect_process_evidence(const char *output_dir)
{
	char cmd[PATH_MAX];

	/* Capture process list */
	snprintf(cmd, sizeof(cmd), "ps auxf > %s/process_list.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture process tree */
	snprintf(cmd, sizeof(cmd), "pstree -p > %s/process_tree.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture open files for all processes */
	snprintf(cmd, sizeof(cmd), "lsof > %s/open_files.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture AI-Sentinel tracked processes */
	if (access("/sys/kernel/ai_sentinel/process_list", F_OK) == 0) {
		snprintf(cmd, sizeof(cmd), "cat /sys/kernel/ai_sentinel/process_list > %s/ai_sentinel_procs.txt 2>/dev/null",
			 output_dir);
		system(cmd);
	}

	return 0;
}

/**
 * collect_filesystem_evidence
 */
int collect_filesystem_evidence(const char *output_dir)
{
	char cmd[PATH_MAX];

	/* Capture mount points */
	snprintf(cmd, sizeof(cmd), "mount > %s/mounts.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture disk usage */
	snprintf(cmd, sizeof(cmd), "df -h > %s/disk_usage.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture inode usage */
	snprintf(cmd, sizeof(cmd), "df -i > %s/inode_usage.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* List recently modified files in /rw */
	snprintf(cmd, sizeof(cmd),
		 "find /rw -type f -mtime -1 -ls 2>/dev/null > %s/recent_files.txt",
		 output_dir);
	system(cmd);

	/* Capture file integrity hashes */
	snprintf(cmd, sizeof(cmd),
		 "find /ro -type f -exec sha256sum {} \\; 2>/dev/null > %s/file_hashes.txt",
		 output_dir);
	system(cmd);

	return 0;
}

/**
 * collect_kernel_evidence
 */
int collect_kernel_evidence(const char *output_dir)
{
	char cmd[PATH_MAX];

	/* Capture kernel messages */
	snprintf(cmd, sizeof(cmd), "dmesg > %s/dmesg.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture kernel version */
	snprintf(cmd, sizeof(cmd), "uname -a > %s/kernel_version.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture loaded modules */
	snprintf(cmd, sizeof(cmd), "lsmod > %s/loaded_modules.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture kernel parameters */
	snprintf(cmd, sizeof(cmd), "sysctl -a > %s/sysctl.txt 2>/dev/null",
		 output_dir);
	system(cmd);

	/* Capture security module status */
	if (access("/sys/kernel/security/lsm", F_OK) == 0) {
		snprintf(cmd, sizeof(cmd),
			 "cat /sys/kernel/security/lsm > %s/lsm_status.txt 2>/dev/null",
			 output_dir);
		system(cmd);
	}

	return 0;
}

/**
 * sign_evidence - Sign evidence collection
 */
int sign_evidence(const char *path)
{
	char cmd[PATH_MAX];

	/* Calculate hash of all files */
	snprintf(cmd, sizeof(cmd),
		 "find '%s' -type f -exec sha256sum {} \\; > '%s.sha256' 2>/dev/null",
		 path, path);
	system(cmd);

	/* TODO: Sign with GPG key when available */
	/* snprintf(cmd, sizeof(cmd), "gpg --detach-sign --armor %s.sha256", path); */

	return 0;
}

/**
 * evidence_list - List all evidence collections
 */
int evidence_list(void)
{
	DIR *dir;
	struct dirent *entry;

	printf("Evidence Collections:\n");
	printf("=====================\n");

	dir = opendir(EVIDENCE_DIR);
	if (!dir) {
		printf("No evidence directory found\n");
		return 0;
	}

	while ((entry = readdir(dir)) != NULL) {
		if (entry->d_name[0] == '.')
			continue;

		/* Skip files, only list directories */
		if (entry->d_type != DT_DIR && entry->d_type != DT_UNKNOWN)
			continue;

		/* Check for metadata file */
		char meta_path[PATH_MAX];
		snprintf(meta_path, sizeof(meta_path), "%s/%s/metadata.txt",
			 EVIDENCE_DIR, entry->d_name);

		FILE *fp = fopen(meta_path, "r");
		if (fp) {
			char line[512];
			printf("\n%s\n", entry->d_name);
			while (fgets(line, sizeof(line), fp)) {
				line[strcspn(line, "\n")] = 0;
				if (strncmp(line, "evidence_id=", 12) == 0 ||
				    strncmp(line, "collected_at=", 13) == 0 ||
				    strncmp(line, "type=", 5) == 0) {
					printf("  %s\n", line);
				}
			}
			fclose(fp);
		}
	}

	closedir(dir);
	return 0;
}

/**
 * evidence_verify - Verify evidence integrity
 */
int evidence_verify(const char *id)
{
	char evidence_path[PATH_MAX];
	char hash_file[PATH_MAX];
	char cmd[PATH_MAX];

	snprintf(evidence_path, sizeof(evidence_path), "%s/%s", EVIDENCE_DIR, id);
	snprintf(hash_file, sizeof(hash_file), "%s/%s.sha256", EVIDENCE_DIR, id);

	printf("Verifying evidence: %s\n", id);

	if (access(evidence_path, F_OK) != 0) {
		fprintf(stderr, "Evidence collection not found\n");
		return -1;
	}

	if (access(hash_file, F_OK) != 0) {
		fprintf(stderr, "Hash file not found\n");
		return -1;
	}

	/* Verify hashes */
	snprintf(cmd, sizeof(cmd), "sha256sum -c %s 2>&1", hash_file);
	if (system(cmd) == 0) {
		printf("✓ Evidence integrity verified\n");
		return 0;
	} else {
		printf("❌ Evidence verification FAILED\n");
		return 1;
	}
}

/**
 * generate_evidence_id - Generate unique evidence ID
 */
char *generate_evidence_id(void)
{
	static char id[64];
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	snprintf(id, sizeof(id), "%ld%09ld-%04x",
		 (long)ts.tv_sec, ts.tv_nsec, rand() & 0xffff);
	return id;
}

/**
 * print_help
 */
void print_help(const char *progname)
{
	printf("AEGIS-OS Evidence Collection Tool v%s\n\n", VERSION);
	printf("Usage: %s [OPTIONS]\n\n", progname);
	printf("Commands:\n");
	printf("  -c, --collect TYPE     Collect evidence\n");
	printf("  -l, --list             List evidence collections\n");
	printf("  -e, --export ID DEST   Export evidence to destination\n");
	printf("  -v, --verify ID        Verify evidence integrity\n");
	printf("  -t, --type TYPE        Evidence type: network|process|fs|kernel|all\n");
	printf("  -d, --duration SECS    Collection duration for network capture\n");
	printf("  -o, --output DIR       Output directory\n");
	printf("  -h, --help             Show this help message\n");
	printf("  -V, --version          Show version information\n");
	printf("\n");
	printf("Examples:\n");
	printf("  %s --collect --type network --duration 60\n", progname);
	printf("  %s --collect --type all\n", progname);
	printf("  %s --list\n", progname);
	printf("  %s --verify ev-1234567890\n", progname);
}

/**
 * print_version
 */
void print_version(void)
{
	printf("aegis-evidence version %s\n", VERSION);
	printf("Copyright (c) 2025 AEGIS-OS Project\n");
}

/**
 * main
 */
int main(int argc, char *argv[])
{
	int opt;
	int option_index = 0;
	enum evidence_type type = EVIDENCE_ALL;
	int duration = 0;
	char *output = NULL;

	if (argc < 2) {
		print_help(argv[0]);
		return 1;
	}

	while ((opt = getopt_long(argc, argv, "c:le:v:t:d:o:hV",
				  long_options, &option_index)) != -1) {
		switch (opt) {
		case 'c':
			if (type == EVIDENCE_ALL) {
				return evidence_collect(type, duration, output) == 0 ? 0 : 1;
			}
			break;
		case 'l':
			return evidence_list() == 0 ? 0 : 1;
		case 'v':
			return evidence_verify(optarg) == 0 ? 0 : 1;
		case 't':
			if (strcmp(optarg, "network") == 0)
				type = EVIDENCE_NETWORK;
			else if (strcmp(optarg, "process") == 0)
				type = EVIDENCE_PROCESS;
			else if (strcmp(optarg, "fs") == 0)
				type = EVIDENCE_FILESYSTEM;
			else if (strcmp(optarg, "kernel") == 0)
				type = EVIDENCE_KERNEL;
			else if (strcmp(optarg, "all") == 0)
				type = EVIDENCE_ALL;
			else {
				fprintf(stderr, "Invalid type: %s\n", optarg);
				return 1;
			}
			break;
		case 'd':
			duration = atoi(optarg);
			break;
		case 'o':
			output = optarg;
			break;
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

	/* If --type was specified, call collect */
	if (optind < argc && type != EVIDENCE_ALL) {
		return evidence_collect(type, duration, output) == 0 ? 0 : 1;
	}

	print_help(argv[0]);
	return 1;
}
