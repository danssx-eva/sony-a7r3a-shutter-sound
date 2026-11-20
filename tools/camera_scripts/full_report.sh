#!/bin/busybox sh
echo "=== A. SYSTEM ==="
busybox cat /proc/uptime
echo "--- mem ---"
busybox cat /proc/meminfo | busybox grep -E 'MemTotal|MemFree|MemAvailable'
echo "--- load ---"
busybox cat /proc/loadavg
echo ""
echo "=== B. FLASH PATCH ==="
busybox sha256sum /usr/lib/libObj.so 2>&1
echo "--- hook bytes file 0xA31226 ---"
busybox dd if=/usr/lib/libObj.so bs=1 skip=10687014 count=8 2>/dev/null | busybox xxd -p
echo "--- payload bytes file 0x1948D8 ---"
busybox dd if=/usr/lib/libObj.so bs=1 skip=1657048 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== C. MEMORY HOOK ==="
busybox dd if=/proc/155/mem bs=1 skip=109031974 count=8 2>/dev/null | busybox xxd -p
echo ""
echo "=== D. SOUND FILES ==="
busybox md5sum /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
busybox ls -l /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
echo ""
echo "=== E. SETTINGS ==="
busybox ls -la /tmp/beeplist.txt 2>&1
busybox ls -la /setting/mode 2>&1
echo ""
echo "=== F. PROCESSES ==="
busybox ps 2>/dev/null | busybox tail -12
echo ""
echo "=== G. MOUNTS (rw only) ==="
busybox cat /proc/mounts | busybox grep ' rw'
echo ""
echo "=== H. DMESG errors ==="
busybox dmesg 2>/dev/null | busybox grep -icE 'panic|oops|BUG:|error' 2>&1
echo "DONE"
