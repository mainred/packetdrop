// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 mainred */
#include "drop.h"
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/* BPF ringbuf map */
struct {
  // All available bpf map types are enumerated by bpf_map_type:
  // https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h#L880
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024 /* 256 KB */);
} rb SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
  __uint(max_entries, 1);
  __type(key, int);
  __type(value, struct event_t);
} heap SEC(".maps");

// Section macro tell libbpf where to place the BPF program.
// The breakdown on the different types you can attach bpf programs to is
// provided in  bpf_prog_type:
// https://elixir.bootlin.com/linux/v5.19.17/source/include/uapi/linux/bpf.h#L922
// Q: How can I get the context to each progream type?
// A: https://blogs.oracle.com/linux/post/bpf-a-tour-of-program-types
// Q: Is there a name convention to the program?
// A: No.
// For tracepoint context, we can get the format from
// `/sys/kernel/debug/tracing/events/skb/kfree_skb/format`, and a detailed
// definition can be found in vmlinux.h, which may vary among linux
// releases/version.
SEC("tracepoint/skb/kfree_skb")
int tracepoint__skb__kfree_skb(struct trace_event_raw_kfree_skb *ctx) {
  if (ctx->reason == SKB_DROP_REASON_NOT_SPECIFIED) {
    return 0;
  }

  struct event_t *event;
  int zero = 0;

  // pre-allocate buff for event
  // an alternative is to use bpf_ringbuf_reserve + bpf_ringbuf_commit to
  // replace bpf_map_lookup_elem + bpf_ringbuf_output the later does not
  // requires us to allocate extra buff for event sample.
  event = bpf_map_lookup_elem(&heap, &zero);
  if (!event) /* can't happen */
    return 0;

  struct sk_buff *skb = (struct sk_buff *)ctx->skbaddr;

  // The invalid mem access 'inv' error can happen if you try to dereference
  // memory without first using bpf_probe_read() to copy it to the BPF stack.
  struct sock *sk;
  bpf_probe_read(&sk, sizeof(sk), &(skb->sk));

  unsigned char state;
  bpf_probe_read(&state, sizeof(state), &(sk->__sk_common.skc_state));

  // Reference of the code to extrac packet properties on different levels.
  // https://github.com/cilium/pwru/blob/main/bpf/kprobe_pwru.c
  u16 sport = 0, dport = 0, l4_proto;
  unsigned char *skb_head = BPF_CORE_READ(skb, head);
  u16 l3_off = BPF_CORE_READ(skb, network_header);
  u16 l4_off = BPF_CORE_READ(skb, transport_header);
  struct iphdr *tmp = (struct iphdr *)(skb_head + l3_off);
  struct tcphdr *tcp = (struct tcphdr *)(skb_head + l4_off);

  u8 tcpflags = ((u_int8_t *)tcp)[13];
  u8 iphdr_first_byte, ip_vsn;
  bpf_probe_read(&iphdr_first_byte, 1, tmp);
  ip_vsn = iphdr_first_byte >> 4;

  if (ip_vsn == 4) {
    struct iphdr ip4;
    bpf_probe_read(&ip4, sizeof(ip4), tmp);
    bpf_probe_read(&event->daddr, sizeof(event->daddr), &ip4.daddr);
    bpf_probe_read(&event->saddr, sizeof(event->saddr), &ip4.saddr);

    // As a BPF debugging helper function, pf_printk() will redirect the output
    // to /sys/kernel/debug/tracing/trace_pipe file
    // ref: https://github.com/libbpf/libbpf-bootstrap/blob/master/README.md
    bpf_printk("saddr %d", ip4.saddr);

    event->state = state;
    l4_proto = ip4.protocol;
  } else if (ip_vsn == 6) {
    struct ipv6hdr ip6;
    bpf_probe_read(&ip6, sizeof(ip6), tmp);
    // TODO(mainred): Change event_t daddr and saddr to be compatible with ipv6
    // addresses.
    l4_proto = ip6.nexthdr;
  }

  if (l4_proto == IPPROTO_TCP) {
    struct tcphdr *tmp = (struct tcphdr *)(skb_head + l4_off);
    struct tcphdr tcp;

    bpf_probe_read(&tcp, sizeof(tcp), tmp);
    event->sport = bpf_ntohs(tcp.source);
    event->dport = bpf_ntohs(tcp.dest);
    // event->tcpflags = tcpflags;
  } else if (l4_proto == IPPROTO_UDP) {
    struct udphdr *tmp = (struct udphdr *)(skb_head + l4_off);
    struct udphdr udp;

    bpf_probe_read(&udp, sizeof(udp), tmp);
    event->sport = bpf_ntohs(udp.source);
    event->dport = bpf_ntohs(udp.dest);
  }

  event->state = state;

  event->start_ns = bpf_ktime_get_ns();

  event->reason = ctx->reason;
  // BPF perfbuf and BPF ringbuf allows BPF programs to communite with
  // user-space programs in a stream-like manner. BPF perfbuf will
  // allocate a separate buff for each CPU in advance and reording events
  // from different CPUs may make these events out of order. BPF ringbuf
  // achievents the similar functionalities but with better performance
  // ref: https://nakryiko.com/posts/bpf-ringbuf/
  bpf_ringbuf_output(&rb, event, sizeof(*event), 0);

  return 0;
}
