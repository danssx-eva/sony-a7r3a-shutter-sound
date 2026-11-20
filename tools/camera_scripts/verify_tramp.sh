#!/bin/busybox sh
echo "=== 1. viewUnified2 基址 ==="
busybox cat /proc/155/maps | busybox grep viewUnified2
echo ""
echo "=== 2. 钩点 0x15393EE4 运行时字节（应为 adf22aba）==="
busybox dd if=/proc/155/mem bs=1 skip=0x15393EE4 count=8 2>/dev/null | busybox xxd -p
echo ""
echo "=== 3. veneer 0x1564133C 运行时字节（应为 dff800c087dedb066047）==="
busybox dd if=/proc/155/mem bs=1 skip=0x1564133C count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== 4. handler 0x06DBDE86 运行时字节（应为 b0b582b0dff800c0e93e39156047）==="
busybox dd if=/proc/155/mem bs=1 skip=0x06DBDE86 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== 5. libObj 基址 ==="
busybox cat /proc/155/maps | busybox grep libObj | busybox head -1
echo ""
echo "=== 6. uptime（判断是否重启过）==="
busybox cat /proc/uptime
echo "DONE"
