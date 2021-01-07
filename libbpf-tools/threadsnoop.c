// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
//
// Based on threadsnoop(8) from BCC by Brendan Gregg and others.
// ??-???-2021   Arivu Alamari   Created this.
#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "threadsnoop.h"
#include "threadsnoop.skel.h"
#include "trace_helpers.h"


const char *argp_program_version = "threadsnoop 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"List new thread creation. Ctrl-C to end.\n"
"\n"
"USAGE: threadsnoop  [-help] \n"
"\n";

static const struct argp_option opts[] = {
	{},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	return ARGP_ERR_UNKNOWN;
}


static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 1,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;

	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}

	return 0;
}

int libbpf_print_fn(enum libbpf_print_level level,
		    const char *format, va_list args)
{
	if (level == LIBBPF_DEBUG && !env.verbose)
		return 0;
	return vfprintf(stderr, format, args);
}

static void sig_handler(int sig)
{
}

static void print_linear_hists(struct bpf_map *hists,
			struct threadsnoop_bpf__bss *bss)
{
	struct hkey lookup_key = {}, next_key;
	int err, fd = bpf_map__fd(hists);
	struct hist hist;

	while (!bpf_map_get_next_key(fd, &lookup_key, &next_key)) {
		err = bpf_map_lookup_elem(fd, &next_key, &hist);
		if (err < 0) {
			fprintf(stderr, "failed to lookup hist: %d\n", err);
			return;
		}
		print_linear_hist(hist.slots, MAX_SLOTS, 0, 200, next_key.comm);
		printf("\n");
		lookup_key = next_key;
	}

	printf("\n");
	print_linear_hist(bss->syswide.slots, MAX_SLOTS, 0, 200, "syswide");
}

int main(int argc, char **argv)
{
	static const struct argp argp = {
		.options = opts,
		.parser = parse_arg,
		.doc = argp_program_doc,
	};
	struct bpf_link **links = NULL;
	struct threadsnoop_bpf *obj;
	int err, i;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;

	libbpf_set_print(libbpf_print_fn);

	err = bump_memlock_rlimit();
	if (err) {
		fprintf(stderr, "failed to increase rlimit: %d\n", err);
		return 1;
	}


	obj = threadsnoop_bpf__open_and_load();
	if (!obj) {
		fprintf(stderr, "failed to open and/or load BPF object\n");
		return 1;
	}


