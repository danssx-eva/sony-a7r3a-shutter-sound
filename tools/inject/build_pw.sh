#!/bin/sh
# 编译 pw —— 一个不依赖 libc 的原地写文件工具。
#
# 为什么需要它：相机上只有 busybox，它的 dd 用 O_TRUNC 打开目标文件，
# 往 19 MB 的 libObj.so 中间写 1 KB 会把文件截断。busybox dd 没有
# conv=notrunc。所以得自己写一个用 O_WRONLY（不带 O_TRUNC）的。
#
# 用法：
#   sh tools/inject/build_pw.sh
#   产物：tools/inject/pw
#
# 需要 ARM 交叉编译器。构建环境：Ubuntu arm-linux-gnueabi-gcc 15.2.0。
# 其他 ARM 交叉工具链也行，只要支持 -nostdlib -static。
#
# 不同工具链产出的二进制不会逐字节相同。仓库里附了编好的 pw：
#   tools/inject/pw   2,656 字节
#   sha256 fc9a3788aa997ce1f66d8ecda625adaf...

set -e

HERE=$(cd "$(dirname "$0")" && pwd)
OUT="$HERE/pw"

# 挑一个能用的交叉编译器
CC=""
for candidate in arm-linux-gnueabi-gcc arm-linux-gnueabihf-gcc \
                 arm-none-linux-gnueabi-gcc arm-none-eabi-gcc; do
    if command -v "$candidate" >/dev/null 2>&1; then
        CC="$candidate"
        break
    fi
done

if [ -z "$CC" ]; then
    echo "找不到 ARM 交叉编译器。" >&2
    echo "" >&2
    echo "装一个：" >&2
    echo "  Ubuntu/Debian:  sudo apt install gcc-arm-linux-gnueabi" >&2
    echo "  macOS:          brew install arm-linux-gnueabi-gcc" >&2
    echo "" >&2
    echo "或者直接用仓库里附的 pw（不用编译）。" >&2
    exit 1
fi

echo "用 $CC 编译"

# -nostdlib   不链 libc，只留纯系统调用
# -static     静态链接，相机上没有动态加载器可用
# -Os         体积优先（目标只有几 KB）
# -mthumb     相机 im.elf 是 Thumb 环境，统一指令集减少意外
# -Ttext      固定加载地址，避免依赖动态重定位
"$CC" \
    -nostdlib -static -Os -mthumb -march=armv7-a \
    -fno-stack-protector -fno-builtin \
    -Wl,--build-id=none \
    -o "$OUT" \
    "$HERE/pw_nolibc.c" "$HERE/pw_start.S"

echo "产物：$OUT"
ls -l "$OUT"
if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$OUT"
fi

cat <<'EOF'

下一步：传到相机上验证能跑。
相机端执行（不带参数应该打印用法并退出）：

    /log/w/pw

正常输出类似：

    usage: pw <file> <offset> <datafile>
      <offset> 支持 0x 前缀十六进制

EOF
