#include <uapi/linux/ptrace.h>
#include <uapi/linux/bpf.h>
#include <linux/version.h>
#include <bpf/bpf_helpers.h>

#include "tracex89_common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(key_size, KEY_LEN);
	__uint(value_size, VALUE_LEN);
	__uint(max_entries, MAX_ENTRIES);
} arg_rewrite_map SEC(".maps");

SEC("kprobe/ksys_write")
int bpf_prog1(struct pt_regs *ctx)
{
    char name[KEY_LEN] = "ksys_write";
    const struct arg_rewrite_rule *r = bpf_map_lookup_elem(&arg_rewrite_map, name);
    if(!r) {
        return 0;
    }
    bpf_printk("Intercepted ksys_write, arguments:\n");
    for(int i = 0; i < NR_ARGUMENTS; i++) {
        bpf_printk("#%d:\t0x%x\n", i, bpf_get_argument(ctx, i));
        switch(r->rewrite[i]) {
            case 0: break;
            case REWRITE_ARBITRARY: {
                bpf_printk("\tRewriting this to 0x%x\n", r->val[i]);
                if(bpf_override_argument(ctx, i, r->val[i]) < 0) {
                    bpf_printk("\tFailed\n");
                }
                break;
            }
            case REWRITE_UPPER_BOUND: {
                if(bpf_get_argument(ctx, i) > r->val[i]) {
                    bpf_printk("\tRewriting this to %d(upper bound)\n", r->val[i]);
                    if(bpf_override_argument(ctx, i, r->val[i]) < 0) {
                        bpf_printk("\tFailed\n");
                    }
                }
                break;
            }
        }
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
u32 _version SEC("version") = LINUX_VERSION_CODE;
