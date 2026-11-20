#!/bin/busybox sh
echo "=== Caution.bin md5 ==="
busybox md5sum /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
echo "=== 大小 ==="
busybox ls -l /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
echo "=== 前 8 字节 ==="
busybox dd if=/usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin bs=1 count=8 2>/dev/null | busybox xxd -p
echo "=== uptime ==="
busybox cat /proc/uptime
echo "DONE"
