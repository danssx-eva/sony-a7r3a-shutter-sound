#!/bin/busybox sh
# 逐块写入 libObj.so 补丁。
# 规则：上一块没验证通过，绝不写下一块。任一关键步骤失败都以非零退出。
TARGET=/usr/lib/libObj.so
PW=/log/w/pw
BLKB=/log/w/blkB.bin
BLKA=/log/w/blkA.bin

fail() {
    echo ""
    echo "FAILED: $1"
    busybox mount -o remount,ro /usr 2>/dev/null
    exit 1
}

is_md5() {
    [ ${#1} -eq 32 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1;; esac
    return 0
}

is_sha256() {
    [ ${#1} -eq 64 ] || return 1
    case "$1" in *[!0-9a-f]*) return 1;; esac
    return 0
}

EXPECT=${1:-}
[ -n "$EXPECT" ] || fail "用法: $0 <预期整文件 SHA256>"
is_sha256 "$EXPECT" || fail "第一个参数不是 64 位十六进制 SHA256"

echo "=== 0. 前置检查 ==="
busybox test -f $PW  || fail "找不到写入器 $PW"
busybox test -f $BLKB || fail "找不到 $BLKB"
busybox test -f $BLKA || fail "找不到 $BLKA"
busybox chmod 755 $PW 2>/dev/null
echo "  三个文件都在"

echo ""
echo "=== 1. 写前状态 ==="
busybox sha256sum $TARGET 2>&1
busybox cat /proc/uptime 2>&1

echo ""
echo "=== 2. 挂载可写 ==="
busybox mount -o remount,rw /usr 2>&1
RC=$?
echo "  rc=$RC"
[ $RC -eq 0 ] || fail "挂写失败"

echo ""
echo "=== 3. 写块 B（载荷 0x194800）==="
$PW $TARGET 0x194800 $BLKB 2>&1 || fail "写块 B 失败"

echo ""
echo "=== 4. 验证块 B（整块 1024 字节）==="
GOT_B=$(busybox dd if=$TARGET bs=1 skip=0x194800 count=1024 2>/dev/null | busybox md5sum | busybox cut -d' ' -f1)
WANT_B=$(busybox md5sum $BLKB | busybox cut -d' ' -f1)
echo "  相机 $GOT_B"
echo "  源   $WANT_B"
is_md5 "$GOT_B" && is_md5 "$WANT_B" || fail "块 B 的 md5 读不到"
[ "$GOT_B" = "$WANT_B" ] || fail "块 B 内容与源文件不一致，不写块 A"

echo ""
echo "=== 5. 写块 A（钩点 0xA31000）==="
$PW $TARGET 0xA31000 $BLKA 2>&1 || fail "写块 A 失败"

echo ""
echo "=== 6. 验证块 A（整块 1024 字节）==="
GOT_A=$(busybox dd if=$TARGET bs=1 skip=0xA31000 count=1024 2>/dev/null | busybox md5sum | busybox cut -d' ' -f1)
WANT_A=$(busybox md5sum $BLKA | busybox cut -d' ' -f1)
echo "  相机 $GOT_A"
echo "  源   $WANT_A"
is_md5 "$GOT_A" && is_md5 "$WANT_A" || fail "块 A 的 md5 读不到"
[ "$GOT_A" = "$WANT_A" ] || fail "块 A 内容与源文件不一致"

echo ""
echo "=== 7. 落盘 ==="
busybox sync
busybox fsync /dev/nflasha15 2>&1
RC=$?
echo "  fsync rc=$RC"
[ $RC -eq 0 ] || fail "fsync 失败"
busybox sync

echo ""
echo "=== 8. 挂回只读 ==="
busybox mount -o remount,ro /usr 2>&1
RC=$?
[ $RC -eq 0 ] || fail "挂回只读失败"

echo ""
echo "=== 9. 整体 SHA（应等于生成时给出的值）==="
FINAL=$(busybox sha256sum $TARGET 2>/dev/null | busybox cut -d' ' -f1)
echo "  $FINAL"
echo ""
is_sha256 "$FINAL" || fail "整文件 SHA 读不到"
[ "$FINAL" = "$EXPECT" ] || fail "整文件 SHA 不等于预期（$FINAL != $EXPECT）"
echo "  与预期一致。"

echo ""
echo "WRITE_DONE"
