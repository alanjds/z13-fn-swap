# Fn <-> corner Ctrl swap for the ASUS ROG Flow Z13 folio keyboard: see README.md
NAME     := ASUS__ROG-Flow-Z13-Folio
CLANG    ?= clang
HOSTCC   ?= $(CLANG)
BPFTOOL  ?= bpftool
ARCH_INC := /usr/include/$(shell uname -m)-linux-gnu
DEVICES  := $(wildcard /sys/bus/hid/devices/0003:0B05:1A30.*)
INSTALLED := /etc/udev-hid-bpf/$(NAME).bpf.o /etc/udev/rules.d/99-hid-bpf-$(NAME).rules

all: $(NAME).bpf.o

vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@.tmp
	mv $@.tmp $@

$(NAME).bpf.o: $(NAME).bpf.c hid_bpf.h hid_bpf_helpers.h vmlinux.h
	$(CLANG) -g -O2 --target=bpf -Wall -Werror -I. -I$(ARCH_INC) \
		-Wno-microsoft-anon-tag -fms-extensions -c $< -o $@

test/test_z13: test/test_z13.c test/host_shim.h $(NAME).bpf.c hid_bpf.h
	$(HOSTCC) -g -O1 -Wall -Werror -I. -Itest -o $@ $<

test: test/test_z13 NOTES.md
	./test/test_z13 NOTES.md

# Until the keyboard is reconnected; probe skips the interfaces that aren't ours
load: $(NAME).bpf.o
	for d in $(DEVICES); do sudo udev-hid-bpf add --replace $$d $(CURDIR)/$<; done

unload:
	sudo udev-hid-bpf remove $(DEVICES)

install: $(NAME).bpf.o
	sudo udev-hid-bpf install --force $<

uninstall: unload
	sudo rm -f $(INSTALLED)
	sudo udevadm control --reload

clean:
	rm -f $(NAME).bpf.o vmlinux.h vmlinux.h.tmp test/test_z13

.PHONY: all test load unload install uninstall clean
