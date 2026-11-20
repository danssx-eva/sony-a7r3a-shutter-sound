#!/bin/busybox sh
TARGET=/usr/lib/libObj.so
echo "=== 0. 写前 ==="
busybox sha256sum $TARGET 2>&1
echo "=== 1. mount rw ==="
busybox mount -o remount,rw /usr 2>&1
echo "rc=$?"
echo "=== 2. 写块 0x194800（新载荷 soundId=7）==="
/log/w/pw $TARGET 0x194800 /log/w/blkB.bin 2>&1
echo "rc=$?"
echo "=== 3. 落盘 ==="
busybox sync
busybox fsync /dev/nflasha15 2>&1
echo "fsync rc=$?"
busybox sync
echo "=== 4. mount ro ==="
busybox mount -o remount,ro /usr 2>&1
echo "rc=$?"
echo "=== 5. 整体 SHA ==="
busybox sha256sum $TARGET 2>&1
echo "=== 6. 载荷前 8 字节（应为 2de9ff51adf1300d）==="
busybox dd if=$TARGET bs=1 skip=1657048 count=8 2>/dev/null | busybox xxd -p
echo "=== 7. 钩点（应为 63f7579b）==="
busybox dd if=$TARGET bs=1 skip=10687014 count=4 2>/dev/null | busybox xxd -p
echo "DONE"
