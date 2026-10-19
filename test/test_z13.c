// SPDX-License-Identifier: GPL-2.0-only
/* Feeds reports through the program the way hid-core does and checks the key events that
 * hid-asus and hid-input would emit. Captures and descriptors are read from NOTES.md. */
#define Z13_HOST_TEST
#include "ASUS__ROG-Flow-Z13-Folio.bpf.c"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

enum { VEND, KBD, NDEV };	/* the .0012 and .0014 interfaces of the captures */

static struct sim {
	__u8 buf[64];			/* hdev->bpf.device_data */
	struct z13_state st;
	unsigned mods, keys[KBD_NKEYS], fnmods, fnkey, cons[2], vend, radio;
	const char *down[32];		/* input core key state */
	int ndown;
} sim[NDEV];

static int depth, failures;
static char evlog[4096], injlog[1024];

static void append(char *log, size_t size, const char *fmt, ...)
{
	size_t n = strlen(log);
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(log + n, size - n, fmt, ap);
	va_end(ap);
}

/* Input core: only a change of state becomes an event */
static void key(struct sim *s, int down, const char *name)
{
	int i;

	if (!name)
		return;
	for (i = 0; i < s->ndown && strcmp(s->down[i], name); i++)
		;
	if (down == (i < s->ndown))
		return;
	if (down)
		s->down[s->ndown++] = name;
	else
		s->down[i] = s->down[--s->ndown];
	append(evlog, sizeof(evlog), " %c%s", down ? '+' : '-', name);
}

static const char *const mod_names[8] = {
	"LCTRL", "LSHIFT", "LALT", "LMETA", "RCTRL", "RSHIFT", "RALT", "RMETA",
};

static const char *kbd_name(unsigned u)
{
	static const char *const named[256] = {
		[0x28] = "ENTER", [0x29] = "ESC", [0x2a] = "BACKSPACE", [0x2b] = "TAB",
		[0x2c] = "SPACE", [0x2f] = "LEFTBRACE", [0x30] = "RIGHTBRACE", [0x46] = "SYSRQ",
		[0x49] = "INSERT", [0x4a] = "HOME", [0x4b] = "PAGEUP", [0x4c] = "DELETE",
		[0x4d] = "END", [0x4e] = "PAGEDOWN", [0x4f] = "RIGHT", [0x50] = "LEFT",
		[0x51] = "DOWN", [0x52] = "UP", [0x65] = "COMPOSE",
	};
	static char pool[256][8];
	char *p = pool[u & 0xff];

	if (!u)
		return NULL;
	if (named[u & 0xff])
		return named[u & 0xff];
	if (!*p) {
		if (u >= 0x04 && u <= 0x1d)
			snprintf(p, sizeof(pool[0]), "%c", 'A' + u - 0x04);
		else if (u >= 0x3a && u <= 0x45)
			snprintf(p, sizeof(pool[0]), "F%u", u - 0x39);
		else if (u >= 0x68 && u <= 0x73)
			snprintf(p, sizeof(pool[0]), "F%u", u - 0x68 + 13);
		else
			snprintf(p, sizeof(pool[0]), "K%02X", u & 0xff);
	}
	return p;
}

static const char *cons_name(unsigned u)
{
	static char pool[0x400][8];

	switch (u) {
	case 0:		return NULL;
	case 0x0e2:	return "MUTE";
	case 0x0e9:	return "VOLUMEUP";
	case 0x0ea:	return "VOLUMEDOWN";
	case 0x192:	return "CALC";
	}
	u &= 0x3ff;
	if (!*pool[u])
		snprintf(pool[u], sizeof(pool[0]), "C%03X", u);
	return pool[u];
}

/* hid-asus input_mapping; it ignores the rest of the vendor page */
static const char *vendor_name(unsigned u)
{
	switch (u) {
	case 0x10:	return "BRIGHTNESSDOWN";
	case 0x20:	return "BRIGHTNESSUP";
	case 0x38:	return "PROG1";
	case 0x4e:	return "FN_ESC";
	case 0x5c:	return "PROG3";
	case 0x6b:	return "F21";
	case 0x7c:	return "MICMUTE";
	case 0x88:	return "RFKILL";
	case 0xae:	return "PROG4";	/* asus-wmi takes it first when present */
	case 0xc7:	return "KBDILLUMTOGGLE";
	}
	return NULL;
}

static const char *radio_name(unsigned u)
{
	return u ? "RFKILL" : NULL;
}

static void set_mods(struct sim *s, unsigned *old, unsigned now)
{
	for (int j = 0; j < 8; j++)
		if ((*old ^ now) & 1 << j)
			key(s, now >> j & 1, mod_names[j]);
	*old = now;
}

static bool has(const unsigned *v, int n, unsigned x)
{
	for (int i = 0; i < n; i++)
		if (v[i] == x)
			return true;
	return false;
}

/* hid_input_array_field() order: per slot, release the old value, then press the new one */
static void set_array(struct sim *s, unsigned *old, const unsigned *now, int n,
		      const char *(*name)(unsigned))
{
	for (int i = 0; i < n; i++) {
		if (old[i] && !has(now, n, old[i]))
			key(s, 0, name(old[i]));
		if (now[i] && !has(old, n, now[i]))
			key(s, 1, name(now[i]));
	}
	memcpy(old, now, n * sizeof(*old));
}

static const __u8 spurious[] = { 0xea, 0xec, 0x02, 0x8a, 0x9e };	/* hid-asus drops 5a xx */

/* What hid-asus and hid-input make of a report that left the program */
static void process(int dev, const __u8 *b, int len)
{
	struct sim *s = &sim[dev];
	unsigned v[KBD_NKEYS];

	if (dev == KBD) {
		if (b[0] != RID_KBD || len < KBD_KEYS + KBD_NKEYS)
			return;
		set_mods(s, &s->mods, b[1]);
		for (int i = 0; i < KBD_NKEYS; i++)
			v[i] = b[KBD_KEYS + i];
		set_array(s, s->keys, v, KBD_NKEYS, kbd_name);
		return;
	}
	switch (b[0]) {
	case RID_FNCTRL:
		set_mods(s, &s->fnmods, b[1]);
		v[0] = b[2];
		set_array(s, &s->fnkey, v, 1, kbd_name);
		break;
	case RID_CONSUMER:
		v[0] = b[1] | b[2] << 8;
		v[1] = b[3] | b[4] << 8;
		set_array(s, s->cons, v, 2, cons_name);
		break;
	case RID_RADIO:
		v[0] = b[1] & 1;
		set_array(s, &s->radio, v, 1, radio_name);
		break;
	case RID_VENDOR:
		if (memchr(spurious, b[1], sizeof(spurious)))
			break;
		v[0] = b[1];
		set_array(s, &s->vend, v, 1, vendor_name);
		break;
	}	/* 5d and 5e: hid-asus drops them */
}

/* One report through hid-core: the BPF program first, then hid-asus and hid-input */
static int deliver(int dev, const __u8 *bytes, int n, __u64 source)
{
	struct sim *s = &sim[dev];
	struct hid_bpf_ctx ctx = {
		.allocated_size = sizeof(s->buf), .size = n, .data = s->buf, .dev = dev,
	};
	int ret;

	memset(s->buf, 0, sizeof(s->buf));
	memcpy(s->buf, bytes, n);
	if (!depth)
		st = s->st;
	ret = z13_event(&ctx, HID_INPUT_REPORT, source);
	if (!depth)
		s->st = st;
	if (ret >= 0)
		process(dev, s->buf, ret ? ret : n);
	return ret;
}

__u8 *hid_bpf_get_data(struct hid_bpf_ctx *ctx, unsigned int offset, size_t sz)
{
	return offset + sz <= ctx->allocated_size ? ctx->data + offset : NULL;
}

/* Declared input report lengths, report ID included, after z13_rdesc_fixup */
static int report_len(int dev, __u8 rid)
{
	if (dev == KBD)
		return rid == RID_KBD ? 33 : -1;
	switch (rid) {
	case RID_VENDOR:	return 2;
	case RID_CONSUMER:	return 5;
	case RID_RADIO:		return 2;
	case RID_FNCTRL:	return FNCTRL_SIZE;
	case RID_MATRIX:	return 32;
	case 0x5e:		return 6;
	}
	return -1;
}

/* Like the kernel: truncate to the report length, then run the report through hid-core
 * synchronously, in the same device buffer the caller is still holding */
int hid_bpf_try_input_report(struct hid_bpf_ctx *ctx, enum hid_report_type type, __u8 *buf,
			     size_t sz)
{
	int n = report_len(ctx->dev, buf[0]);

	if (type != HID_INPUT_REPORT || n < 0 || !sz)
		return -EINVAL;
	if (depth)
		return -EDEADLOCK;
	if (sz < (size_t)n)
		n = sz;
	append(injlog, sizeof(injlog), " [");
	for (int i = 0; i < n; i++)
		append(injlog, sizeof(injlog), i ? " %02x" : "%02x", buf[i]);
	append(injlog, sizeof(injlog), "]");
	depth++;
	deliver(ctx->dev, buf, n, (__u64)(uintptr_t)ctx);
	depth--;
	return 0;
}

static int parse_hex(const char *s, __u8 *out, int max)
{
	unsigned v;
	int n = 0, used;

	while (n < max && sscanf(s, " %2x%n", &v, &used) == 1) {
		out[n++] = v;
		s += used;
	}
	return n;
}

#define M(byte, mask)	((byte) << 8 | (mask))
#define M_FN		M(MATRIX_MODS, MATRIX_FN)
#define M_CORNER	M(MATRIX_MODS, MATRIX_CORNER)
#define M_ESC		M(4, 0x20)
#define M_F2		M(5, 0x01)
#define M_F4		M(5, 0x04)
#define M_F5		M(5, 0x10)
#define M_F6		M(5, 0x20)
#define M_F9		M(6, 0x01)
#define M_F12		M(6, 0x08)
#define M_LBRACE	M(11, 0x04)
#define M_RBRACE	M(11, 0x08)
#define M_C		M(15, 0x20)
#define M_V		M(15, 0x40)
#define M_SPACE		M(18, 0x08)
#define M_UP		M(19, 0x08)

/* Matrix echo with these keys down; the list ends with 0 */
static void echo(int pos, ...)
{
	__u8 b[32] = { RID_MATRIX, MATRIX_SUBTYPE };
	va_list ap;

	va_start(ap, pos);
	for (; pos; pos = va_arg(ap, int))
		b[pos >> 8] |= pos & 0xff;
	va_end(ap);
	deliver(VEND, b, sizeof(b), 0);
}

/* Keyboard report: modifier byte, then the keys down; the list ends with 0 */
static void kbd(int mods, ...)
{
	__u8 b[33] = { RID_KBD, mods };
	va_list ap;
	int k, i = KBD_KEYS;

	va_start(ap, mods);
	while ((k = va_arg(ap, int)) && i < KBD_KEYS + KBD_NKEYS)
		b[i++] = k;
	va_end(ap);
	deliver(KBD, b, sizeof(b), 0);
}

static void vend(const char *hex)
{
	__u8 b[64];
	int n = parse_hex(hex, b, sizeof(b));

	deliver(VEND, b, n, 0);
}

static void reset(void)
{
	memset(sim, 0, sizeof(sim));
	memset(&st, 0, sizeof(st));
	evlog[0] = injlog[0] = 0;
}

static void check(const char *what, const char *got, const char *want)
{
	if (*got == ' ')
		got++;
	if (!strcmp(got, want)) {
		printf("ok    %s\n", what);
		return;
	}
	printf("FAIL  %s\n      got:  %s\n      want: %s\n", what, got, want);
	failures++;
}

/* Body of the first ``` block after the line `heading` */
static const char *block(const char *notes, const char *heading, const char **end)
{
	char pat[160];
	const char *p;

	snprintf(pat, sizeof(pat), "\n%s\n", heading);
	p = strstr(notes, pat);
	if (!p || !(p = strstr(p + strlen(pat), "```")) || !(p = strchr(p, '\n')))
		return NULL;
	*end = strstr(++p, "```");
	return *end ? p : NULL;
}

/* Replays one capture of NOTES.md, in order, and checks the resulting key events */
static void replay(const char *notes, const char *heading, const char *want)
{
	const char *end, *p = block(notes, heading, &end);
	char line[512];

	reset();
	if (!p) {
		check(heading, "(section missing from NOTES.md)", want);
		return;
	}
	for (; p < end; p = strchr(p, '\n') + 1) {
		const char *id;
		__u8 b[64];
		int dev, n;

		snprintf(line, sizeof(line), "%.*s", (int)strcspn(p, "\n"), p);
		id = strstr(line, "0003:0B05:1A30.");
		if (!id)
			continue;
		dev = !strncmp(id + 15, "0012", 4) ? VEND : !strncmp(id + 15, "0014", 4) ? KBD : -1;
		n = parse_hex(id + 19, b, sizeof(b));
		if (dev >= 0 && n)
			deliver(dev, b, n, 0);
	}
	check(heading + 4, evlog, want);
}

static void replay_tests(const char *notes)
{
	replay(notes, "### S, then Fn alone three times",
	       "+S -S +LCTRL -LCTRL +LCTRL -LCTRL +LCTRL -LCTRL");
	replay(notes, "### Backlight off: Fn alone", "+LCTRL -LCTRL +LCTRL -LCTRL +LCTRL -LCTRL");
	replay(notes, "### Turning the backlight on (Fn+F11)", "+LCTRL +F11 -F11 -LCTRL");
	replay(notes, "### Backlight on: Fn alone", "+LCTRL -LCTRL +LCTRL -LCTRL +LCTRL -LCTRL");
	/* Fn+F6 and Fn+F9 stay firmware macros: README.md, "Limitations" */
	replay(notes, "### Fn + each of F1–F12",
	       "+LCTRL +F1 -F1 +F2 -F2 +F3 -F3 +F4 -F4 +F5 -F5 +LMETA +LSHIFT +S -S +F7 -F7 "
	       "+F8 -F8 +P -P +F10 -F10 +F11 -F11 +F12 -F12 -LCTRL -LMETA -LSHIFT");
	replay(notes, "### Fn + arrows, Del, Enter",
	       "+LCTRL +UP -UP +DOWN -DOWN +LEFT -LEFT +RIGHT -RIGHT +DELETE -DELETE "
	       "+ENTER -ENTER -LCTRL");
	replay(notes, "### Fn + Ctrl, Shift, Alt, Backspace",
	       "+LCTRL +LSHIFT -LSHIFT +LALT -LALT +BACKSPACE -BACKSPACE -LCTRL");
	replay(notes, "### Copilot alone", "+LMETA +LSHIFT +F23 -F23 -LSHIFT -LMETA");
	replay(notes, "### Fn + Copilot", "+LCTRL +COMPOSE -COMPOSE -LCTRL");
	replay(notes,
	       "### Corner key + C three times, corner key + Shift + ↑ three times (program unloaded)",
	       "+C -C +C -C +C -C +LSHIFT +PAGEUP -PAGEUP +PAGEUP -PAGEUP +PAGEUP -PAGEUP -LSHIFT");
	/* Every key comes out plain, Esc [ ] Enter C V Space included */
	replay(notes, "### Fn + each key, row by row (program unloaded)",
	       "+LCTRL +ESC -ESC +ESC -ESC +K35 -K35 +K1E -K1E +K1F -K1F +K20 -K20 +K21 -K21 "
	       "+K22 -K22 +K23 -K23 +K24 -K24 +K25 -K25 +K26 -K26 +K27 -K27 +K2D -K2D +K2E -K2E "
	       "+BACKSPACE -BACKSPACE +TAB -TAB +Q -Q +W -W +E -E +R -R +T -T +Y -Y +U -U +I -I "
	       "+O -O +P -P +LEFTBRACE -LEFTBRACE +RIGHTBRACE -RIGHTBRACE +K31 -K31 +K39 -K39 "
	       "+A -A +S -S +D -D +F -F +G -G +H -H +J -J +K -K +L -L +K33 -K33 +K34 -K34 "
	       "+ENTER -ENTER +LSHIFT -LSHIFT +Z -Z +X -X +C -C +V -V +B -B +N -N +M -M "
	       "+K36 -K36 +K37 -K37 +K38 -K38 +RSHIFT -RSHIFT +SPACE -SPACE -LCTRL");
}

static void physical_fn_tests(void)
{
	reset();
	echo(M_FN, 0);
	kbd(0, 0x06, 0);
	kbd(0, 0);
	echo(0);
	check("Fn+C = Ctrl+C", evlog, "+LCTRL +C -C -LCTRL");

	reset();
	echo(M_FN, 0);
	echo(M_FN, M_F2, 0);
	vend("02 ea 00 00 00");
	echo(M_F2, 0);
	vend("02 00 00 00 00");
	echo(0);
	check("Fn released before F2", evlog, "+LCTRL +F2 -LCTRL -F2");

	reset();
	echo(M_FN, 0);
	vend("5a 5c 00 00 00 00");
	vend("5a 00 00 00 00 00");
	echo(0);
	check("Fn + a vendor code we don't translate passes", evlog, "+LCTRL +PROG3 -PROG3 -LCTRL");

	reset();
	echo(M_FN, 0);
	echo(M_FN, M_F4, 0);
	vend("5a 7c 00 00 00 00");
	vend("5a ec 02 00 00 00 00 00 00 00 00 00 00 00 00 00 "
	     "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00");
	echo(M_FN, 0);
	vend("5a 00 00 00 00 00");
	echo(0);
	check("Fn+F4 survives the 5a ec heartbeat", evlog, "+LCTRL +F4 -F4 -LCTRL");

	reset();
	echo(M_FN, 0);
	kbd(MOD_LCTRL, 0);
	echo(M_FN, M_CORNER, 0);
	echo(M_FN, M_CORNER, M_F2, 0);
	vend("02 ea 00 00 00");
	echo(M_FN, M_CORNER, 0);
	vend("02 00 00 00 00");
	kbd(0, 0);
	echo(M_FN, 0);
	echo(0);
	check("Fn+corner+F2 = Ctrl+VolumeDown", evlog, "+LCTRL +VOLUMEDOWN -VOLUMEDOWN -LCTRL");
	check("Fn+corner+F2 injects nothing", injlog, "");

	reset();
	echo(M_FN, 0);
	kbd(MOD_LCTRL, 0);
	echo(M_FN, M_CORNER, 0);
	kbd(MOD_LCTRL, K_PAGEUP, 0);
	kbd(MOD_LCTRL, 0);
	kbd(0, 0);
	echo(0);
	check("Fn+corner+Up = Ctrl+PageUp", evlog, "+LCTRL +PAGEUP -PAGEUP -LCTRL");

	reset();
	echo(M_FN, 0);
	kbd(MOD_LCTRL, 0);
	echo(M_FN, M_CORNER, 0);
	vend("02 92 01 00 00");
	vend("02 00 00 00 00");
	kbd(0, 0);
	echo(M_FN, 0);
	echo(0);
	check("Fn+corner+Enter = Ctrl+Insert", evlog, "+LCTRL +INSERT -INSERT -LCTRL");

	reset();
	echo(M_FN, 0);
	echo(M_FN, M_C, 0);
	vend("5a 9e 00 00 00 00");
	echo(M_FN, 0);
	vend("5a 00 00 00 00 00");
	echo(M_FN, M_V, 0);
	vend("5a 8a 00 00 00 00");
	echo(M_FN, 0);
	vend("5a 00 00 00 00 00");
	echo(0);
	check("Fn+C, Fn+V = Ctrl+C, Ctrl+V", evlog, "+LCTRL +C -C +V -V -LCTRL");

	reset();
	echo(M_FN, 0);
	echo(M_FN, M_SPACE, 0);
	vend("5a 38 00 00 00 00");
	echo(M_FN, 0);
	vend("5a 00 00 00 00 00");
	echo(M_FN, M_ESC, 0);
	vend("5a 4e 00 00 00 00");
	echo(M_FN, 0);
	vend("5a 00 00 00 00 00");
	echo(0);
	check("Fn+Space, Fn+Esc = Ctrl+Space, Ctrl+Esc", evlog,
	      "+LCTRL +SPACE -SPACE +ESC -ESC -LCTRL");

	/* The firmware sends nothing for Fn+[ and Fn+]: the echo is all there is */
	reset();
	echo(M_FN, 0);
	echo(M_FN, M_LBRACE, 0);
	echo(M_FN, 0);
	echo(M_FN, M_RBRACE, 0);
	echo(M_FN, 0);
	echo(0);
	check("Fn+[, Fn+] = Ctrl+[, Ctrl+]", evlog,
	      "+LCTRL +LEFTBRACE -LEFTBRACE +RIGHTBRACE -RIGHTBRACE -LCTRL");

	reset();
	echo(M_FN, 0);
	echo(M_FN, M_LBRACE, 0);
	echo(M_LBRACE, 0);
	echo(0);
	check("Fn released before [", evlog, "+LCTRL +LEFTBRACE -LCTRL -LEFTBRACE");

	reset();
	echo(M_LBRACE, 0);
	echo(0);
	check("[ alone: nothing from the vendor interface", evlog, "");

	reset();
	echo(M_FN, 0);
	kbd(MOD_LCTRL, 0);
	echo(M_FN, M_CORNER, 0);
	echo(M_FN, M_CORNER, M_C, 0);
	vend("5a 9e 00 00 00 00");
	echo(M_FN, M_CORNER, 0);
	vend("5a 00 00 00 00 00");
	kbd(0, 0);
	echo(M_FN, 0);
	echo(0);
	check("Fn+corner+C = Ctrl+C", evlog, "+LCTRL +C -C -LCTRL");
}

static void corner_tests(void)
{
	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, 0);
	echo(M_CORNER, M_UP, 0);
	kbd(MOD_LCTRL, K_UP, 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+Up = PageUp", evlog, "+PAGEUP -PAGEUP");

	reset();
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_DOWN, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_LEFT, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_RIGHT, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_ENTER, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_BACKSPACE, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_DELETE, 0);
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, 0x06, 0);
	kbd(MOD_LCTRL, 0);
	kbd(0, 0);
	check("corner + Down, Left, Right, Enter, Backspace, Del, C", evlog,
	      "+PAGEDOWN -PAGEDOWN +HOME -HOME +END -END +INSERT -INSERT +DELETE -DELETE "
	      "+INSERT -INSERT +C -C");

	reset();
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_DOWN, 0);
	kbd(0, K_DOWN, 0);
	kbd(0, 0);
	check("corner released first: Down stays PageDown", evlog, "+PAGEDOWN -PAGEDOWN");

	reset();
	kbd(0, K_DOWN, 0);
	kbd(MOD_LCTRL, K_DOWN, 0);
	kbd(MOD_LCTRL, 0);
	kbd(0, 0);
	check("corner pressed after Down: stays Down", evlog, "+DOWN -DOWN");

	reset();
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL | MOD_LSHIFT, 0);
	kbd(MOD_LCTRL | MOD_LSHIFT, K_UP, 0);
	kbd(MOD_LCTRL | MOD_LSHIFT, 0);
	kbd(MOD_LCTRL, 0);
	kbd(0, 0);
	check("corner+Shift+Up = Shift+PageUp", evlog, "+LSHIFT +PAGEUP -PAGEUP -LSHIFT");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, 0);
	echo(M_CORNER, M_F2, 0);
	kbd(MOD_LCTRL, K_F(2), 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+F2 = VolumeDown", evlog, "+VOLUMEDOWN -VOLUMEDOWN");
	check("corner+F2 injects press and release", injlog, "[02 ea 00 00 00] [02 00 00 00 00]");

	reset();
	kbd(MOD_LCTRL, 0);
	kbd(MOD_LCTRL, K_F(2), 0);
	echo(M_CORNER, M_F2, 0);
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, 0);
	kbd(0, 0);
	echo(0);
	check("corner+F2, keyboard interface first", evlog, "+VOLUMEDOWN -VOLUMEDOWN");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, M_F2, 0);
	kbd(MOD_LCTRL, K_F(2), 0);
	echo(M_F2, 0);
	kbd(0, K_F(2), 0);
	echo(0);
	kbd(0, 0);
	check("corner released before F2", evlog, "+VOLUMEDOWN -VOLUMEDOWN");

	/* One echo both injects and releases Ctrl: the reply must survive the injection */
	reset();
	echo(M_FN, 0);
	echo(M_FN, M_CORNER, 0);
	echo(M_CORNER, M_F2, 0);
	echo(M_CORNER, 0);
	echo(0);
	check("Fn up in the same echo as corner+F2 down", evlog,
	      "+LCTRL +VOLUMEDOWN -LCTRL -VOLUMEDOWN");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, M_F5, 0);
	kbd(MOD_LCTRL, K_F(5), 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+F5 = fan profile key", evlog, "+PROG4 -PROG4");
	check("corner+F5 injects 5a ae, 5a 00", injlog, "[5a ae] [5a 00]");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, M_F12, 0);
	kbd(MOD_LCTRL, K_F(12), 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+F12 = RFKILL", evlog, "+RFKILL -RFKILL");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, 0);
	echo(M_CORNER, M_SPACE, 0);
	kbd(MOD_LCTRL, K_SPACE, 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+Space = ROG key", evlog, "+PROG1 -PROG1");
	check("corner+Space injects 5a 38, 5a 00", injlog, "[5a 38] [5a 00]");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, M_F6, 0);
	kbd(MOD_LCTRL, K_F(6), 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+F6 = Meta+Shift+S", evlog, "+LSHIFT +LMETA +S -LSHIFT -LMETA -S");
	check("corner+F6 injects nothing", injlog, "");

	reset();
	kbd(MOD_LCTRL, 0);
	echo(M_CORNER, M_F9, 0);
	kbd(MOD_LCTRL, K_F(9), 0);
	echo(M_CORNER, 0);
	kbd(MOD_LCTRL, 0);
	echo(0);
	kbd(0, 0);
	check("corner+F9 = Meta+P", evlog, "+LMETA +P -LMETA -P");

	reset();
	kbd(MOD_LSHIFT, 0x04, 0);
	kbd(0, 0);
	check("Shift+A untouched", evlog, "+LSHIFT +A -LSHIFT -A");
}

static int rdesc(const char *notes, const char *iface, __u8 *out)
{
	const char *end, *p = block(notes, "## Raw descriptors (hex)", &end);
	char hdr[40], line[256];
	int n = 0;

	snprintf(hdr, sizeof(hdr), "== 0003:0B05:1A30.%s\n", iface);
	if (!p || !(p = strstr(p, hdr)) || p > end)
		return -1;
	for (p += strlen(hdr); p < end && *p != '='; p = strchr(p, '\n') + 1) {
		snprintf(line, sizeof(line), "%.*s", (int)strcspn(p, "\n"), p);
		n += parse_hex(line, out + n, HID_MAX_DESCRIPTOR_SIZE - n);
	}
	return n;
}

static void probe_one(const char *what, const __u8 *d, int n, int want)
{
	static struct hid_bpf_probe_args args;
	char got[16], exp[16];

	args.rdesc_size = n;
	memcpy(args.rdesc, d, n);
	args.retval = 1;
	probe(&args);
	snprintf(got, sizeof(got), "%d", args.retval);
	snprintf(exp, sizeof(exp), "%d", want);
	check(what, got, exp);
}

static void descriptor_tests(const char *notes)
{
	static const struct { const char *iface; int size, ours; } ifaces[] = {
		{ "0012", 192, 1 }, { "0013", 77, 0 }, { "0014", 83, 1 },
		{ "0015", 752, 0 }, { "0016", 328, 0 },
	};
	static __u8 d[HID_MAX_DESCRIPTOR_SIZE], raw[HID_MAX_DESCRIPTOR_SIZE];
	struct hid_bpf_ctx ctx = { .allocated_size = sizeof(d), .data = d };
	char what[64], got[64], exp[64];
	int n;

	for (int i = 0; i < 5; i++) {
		n = rdesc(notes, ifaces[i].iface, d);
		snprintf(what, sizeof(what), "descriptor .%s from NOTES.md", ifaces[i].iface);
		snprintf(got, sizeof(got), "%d bytes", n);
		snprintf(exp, sizeof(exp), "%d bytes", ifaces[i].size);
		check(what, got, exp);
		snprintf(what, sizeof(what), "probe %s .%s", ifaces[i].ours ? "takes" : "skips",
			 ifaces[i].iface);
		probe_one(what, d, n, ifaces[i].ours ? 0 : -EINVAL);
	}

	/* sysfs shows 95 01 at 21: hid-asus rewrites the device's 95 05 after BPF has run */
	n = rdesc(notes, "0012", raw);
	check("sysfs .0012 has hid-asus's 95 01 at 21", raw[21] == 0x95 && raw[22] == 0x01 ?
	      "yes" : "no", "yes");
	raw[22] = 0x05;
	memcpy(d, raw, n);
	ctx.size = n;
	n = z13_rdesc_fixup(&ctx);
	snprintf(got, sizeof(got), "%d %s %s", n, memcmp(d, raw, VENDOR_RDESC_SIZE) ? "changed" :
		 "kept", memcmp(d + VENDOR_RDESC_SIZE, fnctrl_rdesc, sizeof(fnctrl_rdesc)) ?
		 "wrong" : "appended");
	check("rdesc fixup appends report 10 to .0012", got, "233 kept appended");
	probe_one("probe takes .0012 once fixed up", d, n, 0);

	n = rdesc(notes, "0014", raw);
	memcpy(d, raw, n);
	ctx.size = n;
	snprintf(got, sizeof(got), "%d %s", z13_rdesc_fixup(&ctx),
		 memcmp(d, raw, n) ? "changed" : "kept");
	check("rdesc fixup leaves .0014 alone", got, "0 kept");
}

static void misc_tests(void)
{
	__u8 b[64] = { RID_MATRIX, MATRIX_SUBTYPE, [MATRIX_MODS] = MATRIX_FN }, copy[64];
	struct hid_bpf_ctx ctx = { .allocated_size = sizeof(b), .size = 32, .data = b };
	char got[32];
	int feature, injected;

	reset();
	memcpy(copy, b, sizeof(b));
	feature = z13_event(&ctx, HID_FEATURE_REPORT, 0);
	injected = z13_event(&ctx, HID_INPUT_REPORT, 1);
	snprintf(got, sizeof(got), "%d %d %s", feature, injected,
		 memcmp(b, copy, sizeof(b)) ? "changed" : "kept");
	check("feature reports and our own injections pass untouched", got, "0 0 kept");
}

int main(int argc, char **argv)
{
	static char notes[1 << 20];
	const char *path = argc > 1 ? argv[1] : "NOTES.md";
	FILE *f = fopen(path, "r");
	size_t n;

	if (!f) {
		perror(path);
		return 2;
	}
	n = fread(notes, 1, sizeof(notes) - 1, f);
	fclose(f);
	notes[n] = 0;

	replay_tests(notes);
	physical_fn_tests();
	corner_tests();
	descriptor_tests(notes);
	misc_tests();

	if (failures) {
		printf("\n%d FAILED\n", failures);
		return 1;
	}
	printf("\nall passed\n");
	return 0;
}
