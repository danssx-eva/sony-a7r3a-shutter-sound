#!/bin/busybox sh
echo "=== 重测: dd 带 seek 写文件是否截断 ==="

# 用 echo 建源文件（2 字节）
busybox rm -f /tmp/src.bin /tmp/dst.bin
busybox echo -n "XY" > /tmp/src.bin
echo "源文件大小: $(busybox wc -c < /tmp/src.bin)  md5: $(busybox md5sum /tmp/src.bin | busybox cut -d' ' -f1)"

# 建 100 字节目标文件（全零）
busybox dd if=/dev/zero of=/tmp/dst.bin bs=1 count=100 2>/dev/null
echo "目标原始大小: $(busybox wc -c < /tmp/dst.bin)"

# 带 seek 写 2 字节
busybox dd if=/tmp/src.bin of=/tmp/dst.bin bs=1 seek=50 count=2 2>&1
SZ=$(busybox wc -c < /tmp/dst.bin)
echo "写入后大小: $SZ"
if [ "$SZ" = "100" ]; then
  echo ">>> ✅ dd 不截断！可以原地打补丁！"
  echo ">>> 验证第 50 字节: $(busybox xxd -s 48 -l 8 -p /tmp/dst.bin)"
elif [ "$SZ" = "2" ]; then
  echo ">>> ❌ dd 截断了（文件变成 2 字节）"
else
  echo ">>> ? 意外结果 size=$SZ"
fi

echo ""
echo "=== 测试 sed 能否处理二进制（用来改单字节）==="
busybox rm -f /tmp/b.bin
busybox dd if=/dev/zero of=/tmp/b.bin bs=1 count=16 2>/dev/null
busybox xxd -p /tmp/b.bin
# 用 sed 替换（二进制里 sed 会把 0x00 也当内容处理，不安全）
busybox echo "sed 对二进制不可靠，跳过"

echo ""
echo "=== 检查 /usr 剩余空间 ==="
busybox cat /proc/mounts | busybox grep nflasha15
# 尝试 statfs: 用 dd 写大文件测试
busybox dd if=/dev/zero of=/tmp/space.bin bs=1024 count=64 2>/dev/null
echo "/tmp 写 64KB: $(busybox wc -c < /tmp/space.bin)"
busybox rm -f /tmp/space.bin

echo ""
echo "=== 关键: /usr 里能不能写一个 500 字节的文件 ==="
busybox mount -o remount,rw /usr 2>&1
busybox dd if=/dev/zero of=/usr/_t.bin bs=1 count=500 2>&1
echo "写入结果: $(busybox wc -c < /usr/_t.bin 2>/dev/null)"
busybox rm -f /usr/_t.bin
busybox mount -o remount,ro /usr 2>&1
echo "done"

echo ""
echo "=== 清理 ==="
busybox rm -f /tmp/src.bin /tmp/dst.bin /tmp/b.bin
