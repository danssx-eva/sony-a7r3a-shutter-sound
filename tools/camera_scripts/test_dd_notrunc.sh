#!/bin/busybox sh
echo "=== 测试 busybox dd 是否支持 conv=notrunc ==="
busybox rm -f /tmp/t1.bin /tmp/t2.bin
# 建一个 100 字节的文件，全 0xAA
busybox dd if=/dev/zero bs=1 count=100 2>/dev/null | busybox tr '\000' '\252' > /tmp/t1.bin 2>/dev/null
if [ ! -s /tmp/t1.bin ]; then
  # tr 可能不存在，用别的方法
  busybox dd if=/dev/zero of=/tmp/t1.bin bs=1 count=100 2>/dev/null
fi
echo "原始大小: $(busybox wc -c < /tmp/t1.bin 2>/dev/null)"
echo "原始 md5: $(busybox md5sum /tmp/t1.bin 2>/dev/null)"

echo ""
echo "--- 测试 A: dd 不带 conv=notrunc ---"
busybox printf 'XX' > /tmp/t2.bin
busybox dd if=/tmp/t2.bin of=/tmp/t1.bin bs=1 seek=50 count=2 2>&1
echo "结果大小: $(busybox wc -c < /tmp/t1.bin 2>/dev/null)  （如果是 2 = 被截断了！）"

echo ""
echo "--- 重建测试文件 ---"
busybox rm -f /tmp/t1.bin
busybox dd if=/dev/zero of=/tmp/t1.bin bs=1 count=100 2>/dev/null
echo "大小: $(busybox wc -c < /tmp/t1.bin 2>/dev/null)"

echo ""
echo "--- 测试 B: dd 带 conv=notrunc ---"
busybox dd if=/tmp/t2.bin of=/tmp/t1.bin bs=1 seek=50 count=2 conv=notrunc 2>&1
echo "结果大小: $(busybox wc -c < /tmp/t1.bin 2>/dev/null)  （如果是 100 = 支持 notrunc！）"

echo ""
echo "=== 检查可用的替代工具 ==="
for t in sed patch perl python awk tr od xxd printf; do
  if busybox $t --help >/dev/null 2>&1; then
    echo "  busybox $t: 可用"
  else
    echo "  busybox $t: 不可用"
  fi
done

echo ""
echo "=== sed 是否支持 -i ==="
busybox echo "hello" > /tmp/t3.bin
busybox sed -i 's/hello/world/' /tmp/t3.bin 2>&1
echo "sed -i 结果: $(busybox cat /tmp/t3.bin 2>/dev/null)"

echo ""
echo "=== 清理 ==="
busybox rm -f /tmp/t1.bin /tmp/t2.bin /tmp/t3.bin
echo "done"
