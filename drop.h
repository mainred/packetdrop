// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2022 mainred */

#ifndef __DROP_H
#define __DROP_H

// reference of the struct definitino and skb structure analysis
// https://github.com/Asphaltt/skbtracer/blob/main/ebpf/headers/skbtracer.h

#define ETH_P_IP 0x0800   /* Internet Protocol packet */
#define ETH_P_IPV6 0x86DD /* IPv6 over bluebook       */

#define AF_INET 2
#define AF_INET6 10
// See https://github.com/torvalds/linux/blob/master/include/net/tcp_states.h
char *tcp_states[] = {
    "ESTABLISHED", "SYN_SENT",  "SYN_RECV", "FIN_WAIT1",
    "FIN_WAIT2",   "TIME_WAIT", "CLOSE",    "CLOSE_WAIT",
    "LAST_ACK",    "LISTEN",    "CLOSING",  "NEW_SYN_RECV",
};

char *packet_drop_reason[] = {
    "SKB_DROP_REASON_NOT_SPECIFIED",
    "SKB_DROP_REASON_NO_SOCKET",
    "SKB_DROP_REASON_PKT_TOO_SMALL",
    "SKB_DROP_REASON_TCP_CSUM",
    "SKB_DROP_REASON_SOCKET_FILTER",
    "SKB_DROP_REASON_UDP_CSUM",
    "SKB_DROP_REASON_NETFILTER_DROP",
    "SKB_DROP_REASON_OTHERHOST",
    "SKB_DROP_REASON_IP_CSUM",
    "SKB_DROP_REASON_IP_INHDR",
    "SKB_DROP_REASON_IP_RPFILTER",
    "SKB_DROP_REASON_UNICAST_IN_L2_MULTICAST",
    "SKB_DROP_REASON_MAX",
};

/* definition of a sample sent to user-space from BPF program */
struct event_t {
  long long unsigned int start_ns;

  unsigned int daddr, saddr;
  short unsigned int sport, dport;
  short unsigned int tcpflags;

  unsigned char state;

  unsigned int reason;
};

#endif /* __DROP_H */
