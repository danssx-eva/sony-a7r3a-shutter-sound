#!/bin/busybox sh
echo "=== 1. shan cun libObj.so SHA ==="
busybox sha256sum /usr/lib/libObj.so 2>&1
echo ""
echo "=== 2. hook bytes at 0xA31226 (expect 63f7579b) ==="
busybox dd if=/usr/lib/libObj.so bs=1 skip=10687014 count=4 2>/dev/null | busybox xxd -p
echo ""
echo "=== 3. Caution.bin md5 (expect afc76363...) ==="
busybox md5sum /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin 2>&1
echo ""
echo "=== 4. uptime ==="
busybox cat /proc/uptime
echo "DONE"
