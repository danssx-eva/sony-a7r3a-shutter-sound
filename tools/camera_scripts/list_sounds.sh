#!/bin/busybox sh
echo "=== /usr/share/avsystemsound/ 全部文件 ==="
busybox ls -la /usr/share/avsystemsound/ 2>&1
echo ""
echo "=== 每个文件的 md5 ==="
busybox md5sum /usr/share/avsystemsound/*.bin 2>&1
echo ""
echo "=== /etc 内容 ==="
busybox ls -la /etc/ 2>&1
echo ""
echo "=== /etc 下的文件（递归一层）==="
for f in /etc/*; do
  if [ -f "$f" ]; then
    echo "FILE: $f"
    busybox ls -l "$f" 2>&1
  fi
done
echo ""
echo "=== /system 内容 ==="
busybox ls -la /system/ 2>&1
echo ""
echo "=== beeplist 前 15 行 ==="
busybox sed -n '1,15p' /tmp/beeplist.txt 2>&1
echo ""
echo "=== beeplist 总行数 ==="
busybox wc -l /tmp/beeplist.txt 2>&1
