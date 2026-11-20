"""读取连拍探针计数器（载荷里的 base+0x194A18）

用法:
    python tools/read_probe.py            # 读一次并显示
    python tools/read_probe.py --reset    # 清零（会写内存，不是只读）
    python tools/read_probe.py --wait 30  # 等 30 秒后读（方便你在这期间连拍）
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
import threading
import time
import pathlib

LAB = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))

COUNTER_OFF = 0x194A18


class Shell:
    def __init__(self, s):
        self.s = s

    def _flush(self, quiet=0.3, maxt=2.0):
        end = time.time() + maxt
        last = time.time()
        while time.time() < end:
            try:
                ch = self.s.recv(65536)
                if not ch:
                    return
                last = time.time()
            except socket.timeout:
                if time.time() - last > quiet:
                    return

    def run(self, cmd, t=60.0):
        self._flush()
        self.s.sendall((cmd + "; echo Z9X$?\n").encode("latin1", "replace"))
        buf = b""
        end = time.time() + t
        while time.time() < end:
            try:
                ch = self.s.recv(65536)
            except socket.timeout:
                continue
            if not ch:
                break
            buf += ch
            if re.search(rb"Z9X\d", buf):
                break
        return buf.decode("latin1", "replace")


def find_libobj_base(sh: Shell) -> int | None:
    o = sh.run("busybox cat /proc/155/maps", 60)
    for line in o.splitlines():
        if "libObj.so" in line and line.split()[0].count("-") == 1:
            try:
                return int(line.split("-")[0], 16)
            except ValueError:
                pass
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--reset", action="store_true",
                    help="把计数器清零。注意这**会写内存**，不是只读操作")
    ap.add_argument("--wait", type=int, default=0, help="读之前等多少秒")
    a = ap.parse_args()

    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend

    result = {}

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.5)
        s1.settimeout(0.3)
        sh = Shell(s1)

        base = find_libobj_base(sh)
        if base is None:
            print("❌ 找不到 libObj.so 基址")
            return False
        addr = base + COUNTER_OFF
        result["base"] = base
        result["addr"] = addr
        print(f"libObj 基址 0x{base:08x}")
        print(f"计数器地址 0x{addr:08x}")

        if a.reset:
            print("（--reset 会往相机内存写 4 个零字节，不是只读操作）")
            # /dev/zero 比 printf 可靠；/proc/<pid>/mem 不是普通文件，不需要 conv=notrunc
            o = sh.run(
                f"busybox dd if=/dev/zero of=/proc/155/mem bs=1 count=4 "
                f"seek={addr} 2>&1", 40)
            print("  清零:", o.strip()[-80:] or "已发送")
        if a.wait:
            print(f"  等待 {a.wait} 秒（现在去连拍）...")
            time.sleep(a.wait)

        # 读 4 字节：用 dd 从 /proc/155/mem 读
        o = sh.run(
            f"busybox dd if=/proc/155/mem bs=1 skip={addr} count=4 2>/dev/null | busybox xxd -p", 40)
        hexs = None
        for line in o.splitlines():
            ls = line.strip()
            if re.fullmatch(r"[0-9a-f]{8}", ls):
                hexs = ls
                break
        if hexs:
            val = int.from_bytes(bytes.fromhex(hexs), "little")
            result["count"] = val
            print(f"  计数器 = {val}")
        else:
            print("  ❌ 读取失败，原始输出:", o[:300])
        for s in (s1, s2):
            try:
                s.close()
            except OSError:
                pass
        return True

    try:
        senserShellCommand(complete=work)
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return 1

    if "count" in result:
        print()
        print("═" * 56)
        print(f" 命中了 {result['count']} 次")
        print("═" * 56)
        if result["count"] <= 1:
            print(" ⇒ 触发点只响应一次按键（H1 成立）")
            print("    需要找「每帧拍摄」的触发点")
        else:
            print(" ⇒ 触发点每帧都在响应（H1 否定）")
            print("    声音被挡是【发声资源被占用】（H2 成立）")
            print("    ⇒ 缩短音效时长到 < 每帧间隔 即可")
    return 0


if __name__ == "__main__":
    sys.exit(main())
