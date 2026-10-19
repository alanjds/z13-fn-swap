/* SPDX-License-Identifier: GPL-2.0-only */
/* Host stand-ins for the BPF and kernel API the program uses; test_z13.c implements the kfuncs. */
#ifndef Z13_HOST_SHIM_H
#define Z13_HOST_SHIM_H

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

typedef uint8_t __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef int32_t __s32;
typedef uint64_t __u64;

enum hid_report_type { HID_INPUT_REPORT, HID_OUTPUT_REPORT, HID_FEATURE_REPORT };

struct hid_bpf_ctx {
	__u32 allocated_size;
	__s32 size;
	__u8 *data;	/* host only: the device buffer */
	int dev;	/* host only */
};

struct hid_bpf_ops {
	void *hid_device_event, *hid_rdesc_fixup;
};

#define SEC(name)
#ifndef __always_inline
#define __always_inline inline __attribute__((always_inline))
#endif
#define BPF_PROG(name, ...) name(__VA_ARGS__)
#define HID_BPF_CONFIG(...) extern int z13_host_config
#define HID_MAX_DESCRIPTOR_SIZE 4096

__u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, size_t sz);
int hid_bpf_try_input_report(struct hid_bpf_ctx *ctx, enum hid_report_type type, __u8 *buf,
			     size_t sz);

#endif
