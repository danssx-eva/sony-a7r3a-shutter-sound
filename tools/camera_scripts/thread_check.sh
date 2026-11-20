#!/bin/busybox sh
echo "=== 1. 线程状态统计（/proc/155/task/*/stat 第 3 字段）==="
R=0; S=0; D=0; Z=0; OTHER=0
if [ -d /proc/155/task ]; then
  for t in $(busybox ls /proc/155/task 2>/dev/null); do
    st=$(busybox cut -d' ' -f3 /proc/155/task/$t/stat 2>/dev/null)
    case "$st" in
      R) R=$((R+1)) ;;
      S) S=$((S+1)) ;;
      D) D=$((D+1)) ;;
      Z) Z=$((Z+1)) ;;
      *) OTHER=$((OTHER+1)) ;;
    esac
  done
fi
echo "  R (running)     = $R"
echo "  S (sleeping)    = $S"
echo "  D (uninterrupt) = $D"
echo "  Z (zombie)      = $Z"
echo "  其他            = $OTHER"
echo ""
echo "=== 2. RT 线程统计 ==="
RT=0
if [ -d /proc/155/task ]; then
  for t in $(busybox ls /proc/155/task 2>/dev/null); do
    pol=$(busybox cut -d' ' -f41 /proc/155/task/$t/stat 2>/dev/null)
    if [ "$pol" = "1" ] || [ "$pol" = "2" ] || [ "$pol" = "3" ] || [ "$pol" = "4" ] || [ "$pol" = "5" ]; then
      RT=$((RT+1))
    fi
  done
fi
echo "  RT 线程数 = $RT"
echo ""
echo "=== 3. CPU 时间快照（用于计算增量）==="
busybox cat /proc/stat | busybox head -1
busybox cut -d' ' -f14,15 /proc/155/stat
echo ""
echo "=== 4. 5 秒后再采样 ==="
sleep 5
busybox cat /proc/stat | busybox head -1
busybox cut -d' ' -f14,15 /proc/155/stat
echo ""
echo "=== 5. 系统总线程数 ==="
busybox ls /proc/*/task 2>/dev/null | busybox wc -l
echo "DONE"
