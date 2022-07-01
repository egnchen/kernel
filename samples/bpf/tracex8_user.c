#define _GNU_SOURCE

#include <stdio.h>
#include <unistd.h>
#include <syscall.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include "tracex89_common.h"

// the arguments you want to rewrite
const struct {
	char name[KEY_LEN];
	struct arg_rewrite_rule rule;
} rules[] = {
	{
		.name = "ksys_write",
		.rule = {
			// redirect stdout to stderr
			.rewrite[0] = REWRITE_ARBITRARY, .val[0] = 2,
			// truncate anything longer than 32
			.rewrite[2] = REWRITE_UPPER_BOUND, .val[2] = 16,
		},
	}
};

char buf[1024] = {0};

int main(int argc, char **argv)
{
	struct bpf_link *link = NULL;
	struct bpf_program *prog;
	struct bpf_object *obj;
	int map_fd;
	char filename[256];
	char command[256];
	FILE *f;
	
	int ret = 0;

	snprintf(filename, sizeof(filename), "%s_kern.o", argv[0]);
	obj = bpf_object__open_file(filename, NULL);
	if (libbpf_get_error(obj)) {
		fprintf(stderr, "ERROR: opening BPF object file failed\n");
		return 0;
	}

	prog = bpf_object__find_program_by_name(obj, "bpf_prog1");
	if (!prog) {
		fprintf(stderr, "ERROR: finding a prog in obj file failed\n");
		goto cleanup;
	}

	/* load BPF program */
	if (bpf_object__load(obj)) {
		fprintf(stderr, "ERROR: loading BPF object file failed\n");
		goto cleanup;
	}

	link = bpf_program__attach(prog);
	if (libbpf_get_error(link)) {
		fprintf(stderr, "ERROR: bpf_program__attach failed\n");
		link = NULL;
		goto cleanup;
	}

	map_fd = bpf_object__find_map_fd_by_name(obj, "arg_rewrite_map");
	if(map_fd < 0) {
		fprintf(stderr, "ERROR: finding a map in obj file failed.\n");
		goto cleanup;
	}

	// inject argument rewrite rules to ebpf map
	for(int i = 0; i < sizeof(rules) / sizeof(rules[0]); i++) {
		bpf_map_update_elem(map_fd, rules[i].name, &rules[i].rule, BPF_ANY);
	}

	const char *content = "123456\n";
	// this should be redirected to stderr
	write(1, content, strlen(content));
	
	for(int i = 0; i < 128; i++) buf[i] = 'a';
	buf[128] = '\0';
	// this should be truncated to 16 bytes
	write(1, buf, strlen(buf));

cleanup:
	bpf_link__destroy(link);
	bpf_object__close(obj);
	return ret ? 0 : 1;
}