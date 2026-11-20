#!/bin/busybox sh
echo "=== 1. loadavg 趋势（10 秒内 5 次采样）==="
i=0
while [ $i -lt 5 ]; do
  busybox cat /proc/loadavg
  sleep 2
  i=$((i+1))
done
echo ""
echo "=== 2. CPU 时间总量 ==="
busybox cat /proc/stat | busybox head -1
echo ""
echo "=== 3. im.elf (pid 155) CPU 时间 ==="
if [ -r /proc/155/stat ]; then
  busybox cat /proc/155/stat
fi
echo ""
echo "=== 4. 线程数 ==="
if [ -d /proc/155/task ]; then
  busybox ls /proc/155/task | busybox wc -l
fi
echo ""
echo "=== 5. 各线程 CPU 时间（前 10 名）==="
if [ -d /proc/155/task ]; then
  for t in $(busybox ls /proc/155/task 2>/dev/null); do
    if [ -r /proc/155/task/$t/stat ]; then
      busybox cat /proc/155/task/$t/stat 2>/dev/null
    fi
  done | busybox head -30
fi
echo ""
echo "=== 6. 全系统进程 CPU（ps）==="
busybox ps 2>/dev/null | busybox head -20
echo ""
echo "=== 7. 中断统计 ==="
busybox cat /proc/interrupts 2>/dev/null | busybox head -12
echo "DONE"
