# Fn ↔ Ctrl on the ROG Flow Z13 keyboard

A HID-BPF program that gives the folio keyboard of the ROG Flow Z13 (GZ302, USB `0b05:1a30`) the
layout of Apple's Magic Keyboard: the corner key (the bottom-left key, labeled Ctrl) becomes Fn, and
the Fn key becomes Ctrl. It runs inside the kernel, with no daemon. `udev-hid-bpf` loads the program
when the keyboard is connected.

## What changes

| You press | You get |
|---|---|
| Fn | Left Ctrl |
| Fn + any key | Ctrl + that key (Ctrl+C, Ctrl+V, Ctrl+↑, Ctrl+F2, Ctrl+Enter, …) |
| Corner key + ↑ / ↓ | PgUp / PgDn |
| Corner key + ← / → | Home / End |
| Corner key + Enter or Del | Insert |
| Corner key + Backspace | Del (forward delete), like Fn + delete on a Mac |
| Corner key + F1…F12 | the function printed on the key: mute, volume, microphone, fan, screenshot, brightness, display switch, touchpad, keyboard backlight, airplane mode |
| Corner key + Space | the ROG key (`KEY_PROG1`), as Fn + Space on the stock keyboard |
| Corner key + any other key | the key alone |
| Corner key + Fn + key | Ctrl + the corner key's result (Ctrl+PgUp, Ctrl+Insert, Ctrl+Volume, …) |

Each key keeps the meaning it had when it was pressed: releasing the corner key while still holding
↓ does not turn PgDn into ↓ midway.

## How it works

Two of the keyboard's interfaces matter. The report formats and the captures are in
[NOTES.md](NOTES.md).

- **Keyboard** (83-byte descriptor): the program removes the corner key's Ctrl and applies the
  corner key's layer. It also undoes the firmware's Fn layer (PgUp → ↑, Insert → Del, …), which now
  only shows up when the physical Fn key, which became Ctrl, is pressed.
- **ASUS vendor** (192-byte descriptor): on every key change the firmware sends a matrix echo
  there, with all the physical keys pressed, Fn included. The hid-asus driver discards that echo.
  The program:
  - appends a keyboard report (ID `0x10`) to the descriptor, which grows to 233 bytes;
  - replaces each echo with that report, carrying Left Ctrl when the physical Fn key is pressed;
  - turns what the firmware sends in the Fn layer over this interface back into the original key:
    F1…F12 (mute, volume, …), Enter, Esc, Space, C and V;
  - takes `[` and `]`, which the firmware swallows when Fn is pressed, from the echo;
  - on corner key + F1…F12 or Space, injects the report the firmware would send for Fn + that key.

## Requirements

A kernel with `CONFIG_HID_BPF` (the 7.0 kernel in Ubuntu 26.04 has it) and these packages:

```bash
sudo apt install udev-hid-bpf clang libbpf-dev bpftool make
```

## Build and test

```bash
make        # generates vmlinux.h from the running kernel and builds the .bpf.o
make test   # tests on the host, using the captures in NOTES.md
```

## Try it without installing

```bash
make load     # lasts until the keyboard is reconnected
make unload
```

`make load` runs `udev-hid-bpf add` on every interface of the keyboard, and the program itself
refuses the ones that aren't its own. To check, run
`wc -c /sys/bus/hid/devices/0003:0B05:1A30.*/report_descriptor`: the 192-byte interface now has
233 bytes.

## Install

```bash
make install
```

This copies the program to `/etc/udev-hid-bpf/` and creates
`/etc/udev/rules.d/99-hid-bpf-ASUS__ROG-Flow-Z13-Folio.rules`, which loads it every time the
keyboard is connected. It takes effect from the next connection, or right away with `make load`.

## Uninstall

```bash
make uninstall
```

## Limitations

- Fn + F6 and Fn + F9: the firmware sends the macros Meta+Shift+S and Meta+P over the keyboard
  interface, where there is no way to tell whether Fn is pressed. Ctrl+Meta+Shift+S and
  Ctrl+Meta+P come out instead of Ctrl+F6 and Ctrl+F9.
- Fn + Copilot comes out as Ctrl+Menu, because the firmware sends Menu for that combination.
- The Copilot key stays as it is (Meta+Shift+F23). To remap it, its position in the matrix is given
  in NOTES.md.
- Starting with the 7th key pressed at the same time, the keyboard uses a bitmap that the program
  does not translate.
- Corner key + two F keys at the same time: only the first one counts.
- The firmware's function on Fn + Esc (`KEY_FN_ESC`) is gone: that combination is now Ctrl+Esc,
  and corner key + Esc is a plain Esc. On this keyboard hid-asus doesn't use `KEY_FN_ESC` as an
  Fn Lock, and desktops don't bind it by default.
- Meta and the other keys on the bottom row were not captured with Fn.

## If something goes wrong

- `make unload`, or reconnecting the keyboard, puts everything back to normal. Without
  `make install`, nothing is reloaded on reconnection.
- `sudo python3 tools/hid-capture.py` shows the reports after the program has processed them: the
  `5d 0a` echo appears as `10 …`.
- `sudo udev-hid-bpf --debug add <device> <.bpf.o file>` shows why a load failed.
