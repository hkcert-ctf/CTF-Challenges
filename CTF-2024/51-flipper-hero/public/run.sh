#!/bin/bash
cd "$(dirname "$0")"
[[ -e /tmp/qemu.lock ]] && kill -9 $(lsof -t /tmp/qemu.lock) 2>/dev/null

flock /tmp/qemu.lock qemu-system-x86_64 \
    -m 128M \
    -nographic \
    -kernel ./bzImage \
    -append "console=ttyS0 quiet oops=panic panic=1 pti=on nokaslr" \
    -no-reboot \
    -cpu kvm64,+smap,+smep \
    -monitor /dev/null \
    -initrd ./rootfs.cpio <&0 >&1 &
