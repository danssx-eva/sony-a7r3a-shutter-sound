#!/bin/busybox sh
echo "=== 1. 自定义音效文件 ==="
for f in Dslr_Emnt_High_Caution Menu_Open WPS_PBC T_Select; do
  p="/usr/share/avsystemsound/$f.bin"
  if [ -f "$p" ]; then
    busybox md5sum "$p" 2>&1
    busybox ls -l "$p" 2>&1 | busybox sed 's/  */ /g'
  else
    echo "MISSING: $p"
  fi
done
echo ""
echo "=== 2. /tmp/beeplist.txt ==="
if [ -f /tmp/beeplist.txt ]; then
  busybox md5sum /tmp/beeplist.txt 2>&1
  busybox wc -l /tmp/beeplist.txt 2>&1
else
  echo "MISSING: /tmp/beeplist.txt"
fi
echo ""
echo "=== 3. /etc 内容（可写分区，可能有启动脚本）==="
busybox ls -la /etc 2>&1 | busybox head -30
echo ""
echo "=== 4. /system 内容 ==="
busybox ls -la /system 2>&1 | busybox head -20
echo ""
echo "=== 5. 启动脚本候选 ==="
for d in /etc /system /setting; do
  busybox find $d -maxdepth 2 -name "*.sh" 2>/dev/null | busybox head -10
  busybox find $d -maxdepth 2 -name "rc*" 2>/dev/null | busybox head -5
  busybox find $d -maxdepth 2 -name "init*" 2>/dev/null | busybox head -5
done
echo ""
echo "=== 6. init 脚本路径 ==="
busybox cat /proc/1/cmdline 2>/dev/null
echo ""
busybox ls -la /sbin/init /etc/init.d /etc/rc.d 2>&1 | busybox head -20
echo ""
echo "=== 7. 当前 /usr 空间 ==="
busybox df 2>/dev/null || echo "df 不可用"
busybox cat /proc/mounts | busybox grep -E 'nflasha15|nflasha10'
