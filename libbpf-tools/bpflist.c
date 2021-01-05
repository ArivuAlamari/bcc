#include <argp.h>
#include <stdio.h>
#include <unistd.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include "bpflist.h"
#include "bpflist.skel.h"
#include "trace_helpers.h"


const char *argp_program_version = "bpflist 0.1";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";
const char argp_program_doc[] =
"Display processes currently using BPF programs and maps. Ctrl-C to end.\n"
"\n"
"USAGE: cpufreq [--help] [-v Verbose]\n"
"\n";

static const struct argp_option opts[] = {
	{ "verbose", 'v', NULL, 0, "Verbose debug output" },
	{},
};


