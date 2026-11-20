#!/bin/busybox sh
echo "=== 1. bootin.elf ==="
busybox ls -l /usr/bin/bootin.elf 2>&1
echo "=== 2. change_mode.sh ==="
busybox ls -l /usr/bin/change_mode.sh 2>&1
echo "=== 3. setting/mode dir ==="
busybox ls -la /setting/mode 2>&1
echo "=== 4. setting mount ==="
busybox cat /proc/mounts | busybox grep nflasha2
echo "=== 5. im.elf mappings (ld) ==="
busybox cat /proc/155/maps | busybox grep -E 'ld-linux|im.elf' | busybox head -6
echo "=== 6. glibc ==="
busybox ls -l /lib/libc-*.so 2>&1
echo "=== 7. bootin strings ==="
busybox strings /usr/bin/bootin.elf 2>/dev/null | busybox grep -E 'LD_PRELOAD|setting/mode' | busybox head -6
echo "=== 8. change_mode.sh content head ==="
busybox sed -n '1,25p' /usr/bin/change_mode.sh 2>&1
echo "DONE"
