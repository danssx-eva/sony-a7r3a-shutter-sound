#!/bin/busybox sh
echo "=== 1. libObj.so 整体 SHA（应为原厂 f1351204...）==="
busybox sha256sum /usr/lib/libObj.so 2>&1
echo ""
echo "=== 2. 块 0xA31000（1024 字节，含钩点 0xA31226）==="
busybox dd if=/usr/lib/libObj.so bs=1 skip=10686464 count=1024 2>/dev/null | busybox xxd -p
echo ""
echo "=== 3. 块 0x194800（1024 字节，含载荷 0x1948D8）==="
busybox dd if=/usr/lib/libObj.so bs=1 skip=1656832 count=1024 2>/dev/null | busybox xxd -p
echo ""
echo "=== 4. 钩点原字节 0xA31226 ==="
busybox dd if=/usr/lib/libObj.so bs=1 skip=10687014 count=8 2>/dev/null | busybox xxd -p
echo ""
echo "=== 5. 载荷区原字节 0x1948D8 ==="
busybox dd if=/usr/lib/libObj.so bs=1 skip=1657048 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "BACKUP_DONE"
