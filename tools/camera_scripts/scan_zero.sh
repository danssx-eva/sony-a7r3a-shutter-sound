#!/bin/busybox sh
# 扫描可写区域，找出全零的 1KB 块
# 期望：全零 1KB 的 MD5 = 0f343b0931126a20f133d67c2b018a3b
ZERO=0f343b0931126a20f133d67c2b018a3b

scan_range() {
  LO=$1   # 起始字节地址
  N=$2    # 块数（1KB 块）
  NAME=$3
  echo "=== $NAME 起始 0x$(busybox printf '%x' $LO 2>/dev/null || echo $LO) 共 $N 块 ==="
  i=0
  while [ $i -lt $N ]; do
    SKIP=$((LO / 1024 + i))
    H=$(busybox dd if=/proc/155/mem bs=1024 skip=$SKIP count=1 2>/dev/null | busybox md5sum | busybox cut -d' ' -f1)
    if [ "$H" = "$ZERO" ]; then
      echo "ZERO 0x$(busybox printf '%x' $((LO + i*1024)) 2>/dev/null)"
    fi
    i=$((i + 1))
  done
  echo "--- $NAME 完成 ---"
}

# libObj rw 段: 0x06F77000 .. 0x07067000 = 1MB = 1024 块
# 只扫前半部分（前 512 块），找零区足够用
scan_range 116785152 512 "libObj_rw"

# CautionConfig rw: 0x163B2000 .. 0x1646E000 = 768KB = 768 块
scan_range 373260288 768 "CautionConfig_rw"

echo "SCAN_DONE"
