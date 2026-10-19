#!/usr/bin/env python3
"""Print the HID reports of the Z13 folio keyboard (0b05:1a30) from debugfs.

Run as root, over SSH, so the Z13 keyboard does not type into this terminal.
debugfs shows each report after HID-BPF and before the driver (hid-asus).
Consecutive identical reports from the same interface are shown once.
"""
import glob
import os
import select
import time

paths = glob.glob("/sys/kernel/debug/hid/0003:0B05:1A30.*/events")
if not paths:
    raise SystemExit("no 0B05:1A30 device in /sys/kernel/debug/hid (run as root)")
fds = {os.open(p, os.O_RDONLY | os.O_NONBLOCK): p.split("/")[-2] for p in paths}
print("reading", *sorted(fds.values()), "- Ctrl+C to exit", flush=True)
t0, buf, last = time.monotonic(), dict.fromkeys(fds, ""), {}
try:
    while True:
        for fd in select.select(list(fds), [], [])[0]:
            try:
                buf[fd] += os.read(fd, 65536).decode(errors="replace")
            except BlockingIOError:
                continue
            *lines, buf[fd] = buf[fd].split("\n")
            for line in lines:
                if line.startswith("report") and last.get(fd) != line:
                    last[fd] = line
                    data = line.split("=", 1)[1].strip()
                    print(f"{time.monotonic() - t0:6.1f}s {fds[fd]}  {data}", flush=True)
except KeyboardInterrupt:
    pass
