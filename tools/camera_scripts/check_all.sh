#!/bin/busybox sh
echo "=== 1. uptime（判断是否重启）==="
busybox cat /proc/uptime
echo ""
echo "=== 2. Bkup_Write 钩点（应为 edf3f09d）==="
busybox dd if=/proc/155/mem bs=1 skip=0x061D02AC count=4 2>/dev/null | busybox xxd -p
echo ""
echo "=== 3. 载荷 0x06DBDE90（应为 2de9ff51...）==="
busybox dd if=/proc/155/mem bs=1 skip=0x06DBDE90 count=8 2>/dev/null | busybox xxd -p
echo ""
echo "=== 4. 记录区 0x0405EFE0（32 字节）==="
busybox dd if=/proc/155/mem bs=1 skip=0x0405EFE0 count=32 2>/dev/null | busybox xxd -p
echo ""
echo "=== 5. 菜单补丁（音频信号根 0x1651F428，应为 subNodes=0x1651F798 count=3）==="
busybox dd if=/proc/155/mem bs=1 skip=0x1651F428 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== 6. 连拍钩子（应为 63f7579b）==="
busybox dd if=/proc/155/mem bs=1 skip=0x067FB226 count=4 2>/dev/null | busybox xxd -p
echo "DONE"
