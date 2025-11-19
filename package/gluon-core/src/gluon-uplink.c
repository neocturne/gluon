// SPDX-License-Identifier: GPL-2.0-or-later

#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <net/if.h>
#include <sys/syscall.h>

#include <linux/bpf.h>

#define VRF "vrf-uplink"
#define TIMEOUT 300 // seconds

#define ARRAY_SIZE(x) (sizeof(x) / sizeof(*(x)))

// BPF / cgroup handling code imported from iproute2 v6.17.0 with some cleanup

#define CGRP_PROC_FILE  "/cgroup.procs"

/* get base path for controller-less cgroup for a process.
 * path returned does not include /vrf/NAME if it exists
 */
static int vrf_path(char *vpath, size_t len)
{
	char path[PATH_MAX];
	char buf[4096];
	char *vrf;
	FILE *fp;

	snprintf(path, sizeof(path), "/proc/%d/cgroup", getpid());
	fp = fopen(path, "r");
	if (!fp)
		return -1;

	vpath[0] = '\0';

	while (fgets(buf, sizeof(buf), fp)) {
		char *start, *nl;

		start = strstr(buf, "::/");
		if (!start)
			continue;

		/* advance past '::' */
		start += 2;

		nl = strchr(start, '\n');
		if (nl)
			*nl = '\0';

		vrf = strstr(start, "/vrf");
		if (vrf)
			*vrf = '\0';

		strlcpy(vpath, start, len);

		/* if vrf path is just / then return nothing */
		if (!strcmp(vpath, "/"))
			vpath[0] = '\0';

		break;
	}

	fclose(fp);

	return 0;
}

static int make_path(const char *path, mode_t mode)
{
	char *dir, *delim;
	int rc = -1;

	delim = dir = strdup(path);
	if (dir == NULL) {
		fprintf(stderr, "strdup failed copying path");
		return -1;
	}

	/* skip '/' -- it had better exist */
	if (*delim == '/')
		delim++;

	while (1) {
		delim = strchr(delim, '/');
		if (delim)
			*delim = '\0';

		rc = mkdir(dir, mode);
		if (rc && errno != EEXIST) {
			fprintf(stderr, "mkdir failed for %s: %m\n", dir);
			goto out;
		}

		if (delim == NULL)
			break;

		*delim = '/';
		delim++;
		if (*delim == '\0')
			break;
	}
	rc = 0;
out:
	free(dir);

	return rc;
}

static int bpf(int cmd, union bpf_attr *attr, unsigned int size)
{
	return syscall(__NR_bpf, cmd, attr, size);
}

static inline uint64_t bpf_ptr_to_u64(const void *ptr)
{
	return (uint64_t)(unsigned long)ptr;
}

/* Short form of mov, dst_reg = src_reg */
#define BPF_MOV64_REG(DST, SRC) \
	((struct bpf_insn) { \
		.code = BPF_ALU64 | BPF_MOV | BPF_X, \
		.dst_reg = DST, \
		.src_reg = SRC, \
		.off = 0, \
		.imm = 0 })

/* Short form of mov, dst_reg = imm32 */

#define BPF_MOV64_IMM(DST, IMM) \
	((struct bpf_insn) { \
		.code = BPF_ALU64 | BPF_MOV | BPF_K, \
		.dst_reg = DST, \
		.src_reg = 0, \
		.off = 0, \
		.imm = IMM })

/* Memory store, *(uint *) (dst_reg + off16) = src_reg */

#define BPF_STX_MEM(SIZE, DST, SRC, OFF) \
	((struct bpf_insn) { \
		.code = BPF_STX | BPF_SIZE(SIZE) | BPF_MEM, \
		.dst_reg = DST, \
		.src_reg = SRC, \
		.off = OFF, \
		.imm = 0 })

/* Program exit */
#define BPF_EXIT_INSN() \
	((struct bpf_insn) { \
		.code = BPF_JMP | BPF_EXIT, \
		.dst_reg = 0, \
		.src_reg = 0, \
		.off = 0, \
		.imm = 0 })

static int prog_load(int idx)
{
	const struct bpf_insn prog[] = {
		BPF_MOV64_REG(BPF_REG_6, BPF_REG_1),
		BPF_MOV64_IMM(BPF_REG_3, idx),
		BPF_MOV64_IMM(BPF_REG_2, offsetof(struct bpf_sock, bound_dev_if)),
		BPF_STX_MEM(BPF_W, BPF_REG_1, BPF_REG_3, offsetof(struct bpf_sock, bound_dev_if)),
		BPF_MOV64_IMM(BPF_REG_0, 1), /* r0 = verdict */
		BPF_EXIT_INSN(),
	};

	union bpf_attr attr = {};

	attr.prog_type = BPF_PROG_TYPE_CGROUP_SOCK;
	attr.insns = bpf_ptr_to_u64(prog);
	attr.insn_cnt = ARRAY_SIZE(prog);
	attr.license = bpf_ptr_to_u64("GPL");

	return bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
}

static int prog_attach(int prog_fd, int target_fd, enum bpf_attach_type type)
{
	union bpf_attr attr = {};

	attr.target_fd = target_fd;
	attr.attach_bpf_fd = prog_fd;
	attr.attach_type = type;

	return bpf(BPF_PROG_ATTACH, &attr, sizeof(attr));
}

static int vrf_configure_cgroup(const char *path, int ifindex)
{
	int rc = -1, cg_fd, prog_fd = -1;

	cg_fd = open(path, O_DIRECTORY | O_RDONLY);
	if (cg_fd < 0) {
		fprintf(stderr, "Failed to open cgroup path: %m\n");
		goto out;
	}

	/*
	 * Load bpf program into kernel and attach to cgroup to affect
	 * socket creates
	 */
	prog_fd = prog_load(ifindex);
	if (prog_fd < 0) {
		fprintf(stderr, "Failed to load BPF prog: %m\n");
		goto out;
	}

	if (prog_attach(prog_fd, cg_fd, BPF_CGROUP_INET_SOCK_CREATE)) {
		fprintf(stderr, "Failed to attach prog to cgroup: %m\n");
		goto out;
	}

	rc = 0;
out:
	close(cg_fd);
	close(prog_fd);

	return rc;
}


static int vrf_switch(unsigned ifindex)
{
	const char *mnt = "/sys/fs/cgroup";
	char path[PATH_MAX], vpath[PATH_MAX], pid[16];
	int rc = -1, len, fd = -1;

	if (vrf_path(vpath, sizeof(vpath)) < 0) {
		fprintf(stderr, "Failed to get base cgroup path: %m\n");
		goto out;
	}

	/* path to cgroup; make sure buffer has room to cat "/cgroup.procs"
	 * to the end of the path
	 */
	len = snprintf(path, sizeof(path) - sizeof(CGRP_PROC_FILE),
		"%s%s/vrf/%s", mnt, vpath, VRF);
	if (len > sizeof(path) - sizeof(CGRP_PROC_FILE)) {
		fprintf(stderr, "Invalid path to cgroup2 mount\n");
		goto out;
	}

	if (make_path(path, 0755)) {
		fprintf(stderr, "Failed to setup vrf cgroup2 directory\n");
		goto out;
	}

	if (vrf_configure_cgroup(path, ifindex))
		goto out;

	/*
	 * write pid to cgroup.procs making process part of cgroup
	 */
	strlcat(path, CGRP_PROC_FILE, sizeof(path));
	fd = open(path, O_RDWR | O_APPEND);
	if (fd < 0) {
		fprintf(stderr, "Failed to open cgroups.procs file: %m\n");
		goto out;
	}

	snprintf(pid, sizeof(pid), "%d", getpid());
	if (write(fd, pid, strlen(pid)) < 0) {
		fprintf(stderr, "Failed to join cgroup\n");
		goto out;
	}

	rc = 0;
out:
	close(fd);

	return rc;
}

// End of imported code

int main(int argc, char *argv[]) {
	if (argc < 2) {
		fprintf(stderr, "Usage: %s command...\n", program_invocation_short_name);
		return 1;
	}

	unsigned ifindex = 0;

	// netifd may take a while to set up interfaces, especially on first boot
	for (unsigned try = 0; try < TIMEOUT; try++) {
		ifindex = if_nametoindex(VRF);
		if (ifindex)
			break;

		if (try == 0)
			fprintf(stderr, "Waiting for interface '%s'...\n", VRF);

		sleep(1);
	}

	if (!ifindex) {
		fprintf(stderr, "Timed out waiting for interface '%s'\n", VRF);
		return 1;
	}

	if (vrf_switch(ifindex))
		return 1;

	execvp(argv[1], argv + 1);

	// Not reached on success
	fprintf(stderr, "exec: %m\n");
}
