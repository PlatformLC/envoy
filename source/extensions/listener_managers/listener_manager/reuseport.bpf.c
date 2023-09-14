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

#define err(fmt, ...)                   \
    ({                                  \
        bpf_printk(fmt, ##__VA_ARGS__); \
    })

// #define dbg(fmt, ...)                   \
//     ({                                  \
//         bpf_printk(fmt, ##__VA_ARGS__); \
//     })

#define dbg(fmt, ...)   ({})

typedef struct {
    __u32 idx;
    struct bpf_spin_lock lock;
} index_t;

struct {
    __uint(type, BPF_MAP_TYPE_REUSEPORT_SOCKARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    // either __u32/__u64 works for value, but __u64 is friendly with bpftool
    // to dump/debug if the element exists, the actual value is not fd, but
    // sock pointer in os.
    __type(value, __u64);
} reuseport_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    // __type(value, index_t);
    __type(value, __u32);
} index_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __u32);
} index_map_per_cpu SEC(".maps");
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} connection_cnts SEC(".maps");

#define GOTO_DONE(_result) ({	\
    result = (_result);			\
    goto done;					\
})

// define global const inside one rodata struct, so that userspace could
// properly re-initialize the data before load objects
// Here is somehow tricky, const will confuse the compiler.
// No initial value here, otherwise compiler will optimized the val to an
// immediate value.
const volatile global_rodata_t rodata = {
    .total_sockets = 0,
};

typedef struct {
    __u32 connections;
    __u32 index;
} connections_info_t;

static __u64
check_handler_connections(struct bpf_map *map, __u32 *key, __u32 *val, connections_info_t *data)
{
    if (*key >= rodata.total_sockets)
        return 1; /* stop the iteration */
    if (*val < data->connections) {
        data->connections = *val;
        data->index = *key;
    }
    return 0;
}

SEC("sk_reuseport")
int select_sock_lc(struct sk_reuseport_md *reuse_md)
{
    __u32 index = 0;
    __u32 flags = 0;
    enum result result;
    int err;
    __u32 i, *conn;
    connections_info_t data;

    i = 0;
    conn = bpf_map_lookup_elem(&connection_cnts, &i);
    if (!conn) {
        err("bpf_map_lookup_elem error");
        GOTO_DONE(DROP_MISC);
    }
    data.connections = *conn;
    data.index = 0;
    i = bpf_for_each_map_elem(&connection_cnts, check_handler_connections, &data, 0);
    dbg("bpf_for_each_map_elem interates connection_cnts map %d times", i);
    index = data.index;
// assign:
    err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, &index,
                      flags);
    if (!err) {
        dbg("assign to thread %d/%d\n", index, rodata.total_sockets);
        GOTO_DONE(PASS);
    }

    err("bpf_sk_select_reuseport error: %d", err);

    GOTO_DONE(PASS_ERR_SK_SELECT_REUSEPORT);

done:
    return result < PASS ? SK_DROP : SK_PASS; // if SK_DROP, will fallback to kern selection
}


SEC("sk_reuseport")
int rr_atomic_idx(struct sk_reuseport_md *reuse_md)
{
    // index_t *idx;
    __u32 *idx;
    __u32 index = 0;
    __u32 index_zero = 0;
    __u32 flags = 0;
    enum result result;
    int err;

    idx = bpf_map_lookup_elem(&index_map, &index_zero);
    if (!idx) {
        err("bpf_map_lookup_elem error");
        GOTO_DONE(DROP_MISC);
    }

    // bpf_spin_lock(&idx->lock);
    // index = ++(idx->idx);
    // bpf_spin_unlock(&idx->lock);

    // atmoic does not work with kernel 5.4 (20.04), but OK with 5.15 (22.04)
    index = __sync_fetch_and_add(idx, 1);

    index = index % rodata.total_sockets;

    err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, &index,
                      flags);
    if (!err) {
        dbg("assign to thread %d/%d\n", index, rodata.total_sockets);
        GOTO_DONE(PASS);
    }

    err("bpf_sk_select_reuseport error: %d", err);

    GOTO_DONE(PASS_ERR_SK_SELECT_REUSEPORT);

done:
    return result < PASS ? SK_DROP : SK_PASS; // if SK_DROP, will fallback to kern selection
}

SEC("sk_reuseport")
int rr_per_cpu(struct sk_reuseport_md *reuse_md)
{
    __u32 *idx;
    __u32 index_zero = 0;
    __u32 flags = 0;
    enum result result;
    int err;

    idx = bpf_map_lookup_elem(&index_map_per_cpu, &index_zero);
    if (!idx) {
        err("bpf_map_lookup_elem error");
        GOTO_DONE(DROP_MISC);
    }
    (*idx)++;
    *idx = *idx % rodata.total_sockets;
    err = bpf_sk_select_reuseport(reuse_md, &reuseport_map, idx,
                      flags);
    if (!err) {
        dbg("assign to thread %d/%d\n", index, rodata.total_sockets);
        GOTO_DONE(PASS);
    }

    err("bpf_sk_select_reuseport error: %d", err);

    GOTO_DONE(PASS_ERR_SK_SELECT_REUSEPORT);

done:
    return result < PASS ? SK_DROP : SK_PASS; // if SK_DROP, will fallback to kern selection
}
char LICENSE[] SEC("license") = "GPL";
