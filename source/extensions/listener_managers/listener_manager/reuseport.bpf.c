// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) 2023 Intel */

#include <stdlib.h>
#include <linux/bpf.h>
#include <linux/types.h>
#include <bpf/bpf_helpers.h>
#include "reuseport_ebpf.h"

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif

#define dbg(fmt, ...)                   \
    ({                                  \
        bpf_printk(fmt, ##__VA_ARGS__); \
    })

typedef struct {
	__u32 idx;
	struct bpf_spin_lock lock;	
} index_t;

struct {
	__uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
	__uint(max_entries, 65535);
	__type(key, __u32);
	__type(value, __u32);
} reuseport_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, index_t);
} index_map SEC(".maps");


#define GOTO_DONE(_result) ({	\
	result = (_result);			\
	goto done;					\
})

__u32 idx = 0;

// define global const inside one rodata struct, so that userspace could
// properly re-initialize the data before load objects
// Here is somehow tricky, const will confuse the compiler.
// No initial value here, otherwise compiler will optimized the val to an 
// immediate value. 
const volatile global_rodata_t rodata = {
	.total_sockets = 0,
};


SEC("sk_reuseport")
int select_sock(struct sk_reuseport_md *reuse_md)
{
	index_t *idx;
	__u32 index = 0;
	__u32 index_zero = 0;
	__u32 flags = 0;
	enum result result;
	int err;

	idx = bpf_map_lookup_elem(&index_map, &index_zero);
	if (!idx) {
		GOTO_DONE(DROP_MISC); 
	}
	
	bpf_spin_lock(&idx->lock);
	index = ++(idx->idx);
	bpf_spin_unlock(&idx->lock);

	// atmoic does not work with kernel 5.4 (20.04), but OK with 5.15 (22.04)
	// index = __sync_fetch_and_add(&idx, 1);
	// index = __sync_add_and_fetch(&idx, 1);

	index = index % rodata.total_sockets;
	dbg("assign to thread %d/%d\n", index, rodata.total_sockets);
	err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, &index,
				      flags);
	if (!err)
		GOTO_DONE(PASS);

	GOTO_DONE(PASS_ERR_SK_SELECT_REUSEPORT);

done:
	return result < PASS ? SK_DROP : SK_PASS; // if SK_DROP, will fallback to kern selection
}

char LICENSE[] SEC("license") = "GPL";
