// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2022 mainred */
// reference: https://github.com/libbpf/libbpf-bootstrap
#include "drop.h"
#include "drop.skel.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/in.h>
#include <signal.h>
#include <stdio.h>
#include <sys/resource.h>
#include <time.h>

static volatile bool exiting = false;

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args) {
  return vfprintf(stderr, format, args);
}

static void sig_handler(int sig) { exiting = true; }

int handle_event(void *ctx, void *data, unsigned int data_sz) {
  struct event_t *e = data;
  // arpa/inet.h is required to use `inet_ntoa` otherwise `Segmentation fault`
  // will be raised.
  printf("%s:%d(src) -> %s:%d(dst) %s %s\n",
         inet_ntoa((struct in_addr){e->saddr}), e->sport,
         inet_ntoa((struct in_addr){e->daddr}), e->dport, tcp_states[e->state],
         packet_drop_reason[e->reason]);
  return 0;
}

int main(int argc, char **argv) {
  struct drop_bpf *skel;
  struct ring_buffer *rb = NULL;
  int err;

  libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
  /* Set up libbpf logging callback */
  libbpf_set_print(libbpf_print_fn);

  /* Clean handling of Ctrl-C */
  signal(SIGINT, sig_handler);
  signal(SIGTERM, sig_handler);

  /* Open BPF application */
  skel = drop_bpf__open();
  if (!skel) {
    fprintf(stderr, "Failed to open BPF skeleton\n");
    return 1;
  }

  /* Load & verify BPF programs */
  err = drop_bpf__load(skel);
  if (err) {
    fprintf(stderr, "Failed to load and verify BPF skeleton\n");
    goto cleanup;
  }

  /* Attach tracepoint handler */
  err = drop_bpf__attach(skel);
  if (err) {
    fprintf(stderr, "Failed to attach BPF skeleton\n");
    goto cleanup;
  }

  /* Set up ring buffer polling */
  rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
  if (!rb) {
    err = -1;
    fprintf(stderr, "Failed to create ring buffer\n");
    goto cleanup;
  }

  while (!exiting) {
    err = ring_buffer__poll(rb, 100 /* timeout, ms */);
    /* Ctrl-C will cause -EINTR */
    if (err == -EINTR) {
      err = 0;
      break;
    }
    if (err < 0) {
      printf("Error polling perf buffer: %d\n", err);
      break;
    }
  }

cleanup:
  ring_buffer__free(rb);
  drop_bpf__destroy(skel);
  return -err;
}
