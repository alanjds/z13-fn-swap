// SPDX-License-Identifier: GPL-2.0-only
/* Fn <-> corner Ctrl swap for the ASUS ROG Flow Z13 (GZ302) folio keyboard.
 * Behavior: README.md. Report formats and raw captures: NOTES.md. */

#ifdef Z13_HOST_TEST
#include "host_shim.h"
#else
#include "vmlinux.h"
#include "hid_bpf_helpers.h"
#include <bpf/bpf_tracing.h>
#endif
#include "hid_bpf.h"

#define VID_ASUS	0x0B05
#define PID_Z13_FOLIO	0x1A30

HID_BPF_CONFIG(
	HID_DEVICE(BUS_USB, HID_GROUP_GENERIC, VID_ASUS, PID_Z13_FOLIO)
);

/* Only two interfaces are ours, told apart by descriptor: ASUS vendor and keyboard */
#define VENDOR_RDESC_SIZE	192
#define KBD_RDESC_SIZE		83

#define RID_KBD		0x01	/* keyboard interface */
#define RID_CONSUMER	0x02	/* vendor interface, from here on */
#define RID_RADIO	0x03
#define RID_FNCTRL	0x10	/* added by z13_rdesc_fixup */
#define RID_VENDOR	0x5a
#define RID_MATRIX	0x5d

#define MATRIX_SUBTYPE	0x0a
#define MATRIX_MODS	17
#define MATRIX_FN	0x80
#define MATRIX_CORNER	0x40

#define KBD_KEYS	3
#define KBD_NKEYS	6
#define FNCTRL_SIZE	3

#define MOD_LCTRL	0x01
#define MOD_LSHIFT	0x02
#define MOD_LGUI	0x08

/* Keyboard page usages */
#define K_C		0x06
#define K_P		0x13
#define K_S		0x16
#define K_V		0x19
#define K_ENTER		0x28
#define K_ESC		0x29
#define K_BACKSPACE	0x2a
#define K_SPACE		0x2c
#define K_LBRACKET	0x2f
#define K_RBRACKET	0x30
#define K_F(n)		(0x39 + (n))
#define K_INSERT	0x49
#define K_HOME		0x4a
#define K_PAGEUP	0x4b
#define K_DELETE	0x4c
#define K_END		0x4d
#define K_PAGEDOWN	0x4e
#define K_RIGHT		0x4f
#define K_LEFT		0x50
#define K_DOWN		0x51
#define K_UP		0x52

/* Report 10: LeftCtrl from the physical Fn, plus the plain key behind a firmware Fn-layer one */
static const __u8 fnctrl_rdesc[] = {
	0x05, 0x01,		/* Usage Page (Generic Desktop) */
	0x09, 0x06,		/* Usage (Keyboard) */
	0xa1, 0x01,		/* Collection (Application) */
	0x85, RID_FNCTRL,	/*  Report ID */
	0x05, 0x07,		/*  Usage Page (Keyboard) */
	0x19, 0xe0,		/*  Usage Minimum (LeftControl) */
	0x29, 0xe7,		/*  Usage Maximum (Right GUI) */
	0x15, 0x00,		/*  Logical Minimum (0) */
	0x25, 0x01,		/*  Logical Maximum (1) */
	0x75, 0x01,		/*  Report Size (1) */
	0x95, 0x08,		/*  Report Count (8) */
	0x81, 0x02,		/*  Input (Data,Var,Abs) */
	0x19, 0x00,		/*  Usage Minimum (0) */
	0x2a, 0xff, 0x00,	/*  Usage Maximum (255) */
	0x15, 0x00,		/*  Logical Minimum (0) */
	0x26, 0xff, 0x00,	/*  Logical Maximum (255) */
	0x75, 0x08,		/*  Report Size (8) */
	0x95, 0x01,		/*  Report Count (1) */
	0x81, 0x00,		/*  Input (Data,Arr,Abs) */
	0xc0,			/* End Collection */
};

/* Corner + key replays Fn + key: matrix bit and report (F6, F9 are macros: corner_layer) */
static const struct {
	__u8 byte, mask, rid, key;
	__u16 code;
} func[] = {
	{ 4, 0x80, RID_CONSUMER, K_F(1),  0x00e2 },	/* mute */
	{ 5, 0x01, RID_CONSUMER, K_F(2),  0x00ea },	/* volume down */
	{ 5, 0x02, RID_CONSUMER, K_F(3),  0x00e9 },	/* volume up */
	{ 5, 0x04, RID_VENDOR,   K_F(4),  0x7c },	/* mic mute */
	{ 5, 0x10, RID_VENDOR,   K_F(5),  0xae },	/* fan profile, via asus-wmi */
	{ 5, 0x40, RID_VENDOR,   K_F(7),  0x10 },	/* brightness down */
	{ 5, 0x80, RID_VENDOR,   K_F(8),  0x20 },	/* brightness up */
	{ 6, 0x02, RID_VENDOR,   K_F(10), 0x6b },	/* touchpad toggle */
	{ 6, 0x04, RID_VENDOR,   K_F(11), 0xc7 },	/* keyboard backlight */
	{ 6, 0x08, RID_VENDOR,   K_F(12), 0x88 },	/* airplane; firmware's own 03 88 is a no-op */
	{ 18, 0x08, RID_VENDOR,  K_SPACE, 0x38 },	/* ROG key */
};
#define NFUNC	(sizeof(func) / sizeof(func[0]))

/* Fn-layer reports turned back into the plain key; the corner doesn't replay these */
static const struct {
	__u8 rid, key;
	__u16 code;
} fw_keys[] = {
	{ RID_CONSUMER, K_ENTER, 0x0192 },	/* AL Calculator */
	{ RID_VENDOR,   K_ESC,   0x4e },
	{ RID_VENDOR,   K_C,     0x9e },	/* 9e and 8a: hid-asus drops them as spurious */
	{ RID_VENDOR,   K_V,     0x8a },
};
#define NFWKEYS	(sizeof(fw_keys) / sizeof(fw_keys[0]))

/* Fn + these sends no report at all: only the matrix echo shows them */
static const struct {
	__u8 byte, mask, key;
} fw_mute[] = {
	{ 11, 0x04, K_LBRACKET },
	{ 11, 0x08, K_RBRACKET },
};
#define NMUTE		(sizeof(fw_mute) / sizeof(fw_mute[0]))
#define RID_MUTE(k)	(0xf0 + (k))	/* fn_key_rid of a key from fw_mute[k] */

/* Each interface loads its own copy; all-zero is idle */
static struct z13_state {
	__u8 fn_down, corner_down;	/* vendor: from the last matrix echo */
	__u8 fn_key, fn_key_rid;	/* vendor: Fn-layer key held, sent as its plain key */
	__u8 func_rid;			/* vendor: report ID of the injected key, for its release */
	__u16 func_active;		/* vendor: func[] bit being injected, 0 if none */
	__u16 func_held;		/* vendor: func[] keys down in the last echo */
	__u8 mute_held;			/* vendor: fw_mute[] keys down in the last echo */
	__u8 prev_keys[KBD_NKEYS];	/* keyboard: last raw key array */
	__u8 corner_keys[32];		/* keyboard: bitset, usage went down with the corner held */
} st;

/* The firmware's Fn layer on the keyboard interface, back to the plain key */
static __always_inline __u8 fw_fn_undo(__u8 u)
{
	switch (u) {
	case K_PAGEUP:		return K_UP;
	case K_PAGEDOWN:	return K_DOWN;
	case K_HOME:		return K_LEFT;
	case K_END:		return K_RIGHT;
	case K_INSERT:		return K_DELETE;
	}
	return u;
}

/* Apple-style Fn layer for the corner key; extra modifiers go to *mods */
static __always_inline __u8 corner_layer(__u8 u, __u8 *mods)
{
	switch (u) {
	case K_UP:		return K_PAGEUP;
	case K_DOWN:		return K_PAGEDOWN;
	case K_LEFT:		return K_HOME;
	case K_RIGHT:		return K_END;
	case K_ENTER:
	case K_DELETE:		return K_INSERT;
	case K_BACKSPACE:	return K_DELETE;
	case K_F(6):		*mods |= MOD_LGUI | MOD_LSHIFT; return K_S;	/* firmware macros */
	case K_F(9):		*mods |= MOD_LGUI; return K_P;
	case K_F(1) ... K_F(5):
	case K_F(7) ... K_F(8):
	case K_F(10) ... K_F(12):
	case K_SPACE:
		return 0;	/* injected on the vendor interface instead: matrix_event */
	}
	return u;
}

static __always_inline int emit_fnctrl(__u8 *data)
{
	data[0] = RID_FNCTRL;
	data[1] = st.fn_down ? MOD_LCTRL : 0;
	data[2] = st.fn_key;
	return FNCTRL_SIZE;
}

/* Plain key behind a firmware Fn-layer report; 0 if not one we translate */
static __always_inline __u8 fw_key(__u8 rid, __u16 code)
{
	for (int k = 0; k < NFWKEYS; k++)
		if (fw_keys[k].rid == rid && fw_keys[k].code == code)
			return fw_keys[k].key;
	for (int k = 0; k < NFUNC; k++)
		if (func[k].rid == rid && func[k].code == code)
			return func[k].key;
	return 0;
}

/* Physical Fn + key: the plain key goes in report 10, through the corner layer if held too */
static __always_inline bool fn_key_press(__u8 rid, __u8 key)
{
	__u8 mods = 0;

	if (st.corner_down)
		key = corner_layer(key, &mods);	/* F-keys give 0: the firmware's report stays */
	if (!key || !st.fn_down)
		return false;
	st.fn_key = key;
	st.fn_key_rid = rid;
	return true;
}

/* Physical Fn is Ctrl now: turn the firmware's Fn-layer reports back into plain keys */
static __always_inline int fw_fn_layer(__u8 *data, __s32 size)
{
	__u8 rid = data[0];
	__u16 code;
	bool release;

	if (rid == RID_CONSUMER) {
		if (size < 5)
			return 0;
		code = data[1] | data[2] << 8;
		release = !(code | data[3] | data[4]);
	} else {
		if (size < 2)
			return 0;
		code = data[1];
		release = rid == RID_VENDOR && !code;
		rid = RID_VENDOR;	/* Fn+F12 comes as 03 88 and goes as 5a 00 */
	}

	if (release) {
		if (!st.fn_key || st.fn_key_rid != rid)
			return 0;
		st.fn_key = 0;
		return emit_fnctrl(data);
	}
	return fn_key_press(rid, fw_key(rid, code)) ? emit_fnctrl(data) : 0;
}

/* Fn + a key the firmware swallows (fw_mute[]): the echo says when it goes down and up */
static __always_inline void mute_keys(__u8 now)
{
	for (int k = 0; k < NMUTE; k++) {
		__u8 bit = 1 << k;

		if (now & bit & ~st.mute_held)
			fn_key_press(RID_MUTE(k), fw_mute[k].key);
		else if (bit & st.mute_held & ~now && st.fn_key_rid == RID_MUTE(k))
			st.fn_key = 0;
	}
	st.mute_held = now;
}

static __always_inline void inject(struct hid_bpf_ctx *hctx, __u8 rid, __u16 code)
{
	__u8 buf[5] = { rid, code & 0xff, code >> 8 };

	hid_bpf_try_input_report(hctx, HID_INPUT_REPORT, buf, sizeof(buf));
}

/* Matrix echo (hid-asus drops it): physical Fn drives LeftCtrl, and corner + F-key
 * injects the report the firmware sends for Fn + F-key */
static __always_inline int matrix_event(struct hid_bpf_ctx *hctx, __u8 *data)
{
	__u16 now = 0, rising, active = st.func_active;
	__u8 fn, corner, mute = 0;

	if (data[1] != MATRIX_SUBTYPE)
		return 0;
	fn = data[MATRIX_MODS] & MATRIX_FN;
	corner = data[MATRIX_MODS] & MATRIX_CORNER;
	for (int k = 0; k < NFUNC; k++)
		if (data[func[k].byte & 0x1f] & func[k].mask)
			now |= 1 << k;
	for (int k = 0; k < NMUTE; k++)
		if (data[fw_mute[k].byte & 0x1f] & fw_mute[k].mask)
			mute |= 1 << k;
	rising = now & ~st.func_held;

	/* Injecting reuses this buffer, so our own reply is written last */
	if (active && !(now & active)) {
		inject(hctx, st.func_rid, 0);
		active = 0;
	}
	if (!active && corner && !fn) {
		for (int k = 0; k < NFUNC; k++) {
			if (rising & 1 << k) {
				inject(hctx, func[k].rid, func[k].code);
				st.func_rid = func[k].rid;
				active = 1 << k;
				break;
			}
		}
	}
	st.func_active = active;
	st.func_held = now;
	st.fn_down = !!fn;
	st.corner_down = !!corner;
	mute_keys(mute);
	return emit_fnctrl(data);
}

static __always_inline bool was_down(__u8 u)
{
	for (int i = 0; i < KBD_NKEYS; i++)
		if (st.prev_keys[i] == u)
			return true;
	return false;
}

/* The corner's LeftCtrl becomes the corner layer, decided per key at press time */
static __always_inline int kbd_event(__u8 *data)
{
	__u8 corner = data[1] & MOD_LCTRL, mods = 0, raw[KBD_NKEYS];

	data[1] &= ~MOD_LCTRL;
	for (int i = 0; i < KBD_NKEYS; i++) {
		__u8 u = data[KBD_KEYS + i], bit = 1 << (u & 7), v;

		raw[i] = u;
		if (!u)
			continue;
		if (!was_down(u)) {
			if (corner)
				st.corner_keys[u >> 3] |= bit;
			else
				st.corner_keys[u >> 3] &= ~bit;
		}
		v = fw_fn_undo(u);
		if (st.corner_keys[u >> 3] & bit)
			v = corner_layer(v, &mods);
		data[KBD_KEYS + i] = v;
	}
	__builtin_memcpy(st.prev_keys, raw, KBD_NKEYS);
	data[1] |= mods;
	return 0;
}

SEC(HID_BPF_DEVICE_EVENT)
int BPF_PROG(z13_event, struct hid_bpf_ctx *hctx, enum hid_report_type type, __u64 source)
{
	__u8 *data;

	if (type != HID_INPUT_REPORT || source)
		return 0;	/* source is set on the reports we inject */
	data = hid_bpf_get_data(hctx, 0, 64);
	if (!data)
		return 0;

	switch (data[0]) {
	case RID_KBD:
		return hctx->size < KBD_KEYS + KBD_NKEYS ? 0 : kbd_event(data);
	case RID_MATRIX:
		return hctx->size <= MATRIX_MODS ? 0 : matrix_event(hctx, data);
	case RID_CONSUMER:
	case RID_VENDOR:
	case RID_RADIO:
		return fw_fn_layer(data, hctx->size);
	}
	return 0;
}

static __always_inline bool is_vendor_rdesc(const __u8 *d)
{
	return d[0] == 0x06 && d[1] == 0x31 && d[2] == 0xff && d[3] == 0x09 && d[4] == 0x76;
}

SEC(HID_BPF_RDESC_FIXUP)
int BPF_PROG(z13_rdesc_fixup, struct hid_bpf_ctx *hctx)
{
	__u8 *data = hid_bpf_get_data(hctx, 0, HID_MAX_DESCRIPTOR_SIZE);

	if (!data || hctx->size != VENDOR_RDESC_SIZE || !is_vendor_rdesc(data))
		return 0;
	__builtin_memcpy(data + VENDOR_RDESC_SIZE, fnctrl_rdesc, sizeof(fnctrl_rdesc));
	return VENDOR_RDESC_SIZE + sizeof(fnctrl_rdesc);
}

SEC("syscall")
int probe(struct hid_bpf_probe_args *ctx)
{
	unsigned int n = ctx->rdesc_size;
	bool vendor = (n == VENDOR_RDESC_SIZE || n == VENDOR_RDESC_SIZE + sizeof(fnctrl_rdesc)) &&
		      is_vendor_rdesc(ctx->rdesc);
	bool kbd = n == KBD_RDESC_SIZE && ctx->rdesc[0] == 0x05 && ctx->rdesc[1] == 0x01 &&
		   ctx->rdesc[2] == 0x09 && ctx->rdesc[3] == 0x06;

	ctx->retval = vendor || kbd ? 0 : -EINVAL;
	return 0;
}

HID_BPF_OPS(asus_z13_folio) = {
	.hid_device_event = (void *)z13_event,
	.hid_rdesc_fixup = (void *)z13_rdesc_fixup,
};

char _license[] SEC("license") = "GPL";
