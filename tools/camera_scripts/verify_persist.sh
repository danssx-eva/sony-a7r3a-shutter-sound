#!/bin/busybox sh
echo "=== 1. uptime（应该很小，证明重启了）==="
busybox cat /proc/uptime 2>&1

echo ""
echo "=== 2. 闪存文件 SHA（应仍为 d45ca8d7...）==="
busybox sha256sum /usr/lib/libObj.so 2>&1

echo ""
echo "=== 3. 内存里的钩点 0x067FB226（应从闪存加载，应为 63f7579b）==="
busybox dd if=/proc/155/mem bs=1 skip=0x067FB226 count=8 2>/dev/null | busybox xxd -p

echo ""
echo "=== 4. 内存里的载荷 0x05F5E8D8（应从闪存加载，应为 2de9ff51...）==="
busybox dd if=/proc/155/mem bs=1 skip=0x05F5E8D8 count=16 2>/dev/null | busybox xxd -p

echo ""
echo "=== 5. libObj 运行期基址（确认还是 0x05DCA000）==="
busybox cat /proc/155/maps 2>/dev/null | busybox grep libObj

echo ""
echo "=== 6. im.elf 进程号（应为 155）==="
busybox ps 2>/dev/null | busybox grep -E 'im\.elf|launch' | busybox head -3

echo ""
echo "VERIFY_DONE"
