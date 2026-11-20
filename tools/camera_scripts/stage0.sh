#!/bin/busybox sh
echo "=== Stage0-1: setValueToModel 正确入口 0x15394004 ==="
busybox dd if=/proc/155/mem bs=1 skip=356073476 count=16 2>/dev/null | busybox xxd -p
echo "  期望: b0b582b0044600af0025c0687d603d60"
echo ""
echo "=== Stage0-2: 错误的旧地址 0x15393EE4（应看到跨指令）==="
busybox dd if=/proc/155/mem bs=1 skip=356073188 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== Stage0-3: RemoteCtrlRoot props group 0x164FD790 ==="
busybox dd if=/proc/155/mem bs=1 skip=374331280 count=8 2>/dev/null | busybox xxd -p
echo "  期望: 3c87291606000000  (table=0x1629873C, count=6)"
echo ""
echo "=== Stage0-4: 空闲区 0x1651F798（256 字节应全零）==="
busybox dd if=/proc/155/mem bs=1 skip=374470552 count=256 2>/dev/null | busybox xxd -p
echo ""
echo "=== Stage0-5: RemoteCtrlRoot 行节点 0x1651EA28（+0x18=selidx @0x1651EA40）==="
busybox dd if=/proc/155/mem bs=1 skip=374467112 count=40 2>/dev/null | busybox xxd -p
echo ""
echo "=== Stage0-6: 音频信号根 0x1651F428（对照）==="
busybox dd if=/proc/155/mem bs=1 skip=374469672 count=16 2>/dev/null | busybox xxd -p
echo ""
echo "=== Stage0-7: uptime ==="
busybox cat /proc/uptime
echo "DONE"
