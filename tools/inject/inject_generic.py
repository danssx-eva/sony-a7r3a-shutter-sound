r"""通用注入器：上传载荷与钩子到相机运行期内存，读回校验。

用法：
    python tools/inject/inject_generic.py --so <打好的 libObj.so>
    python tools/inject/inject_generic.py --read 0x0405EFE0 --len 4

--so 必须是用 tools/build_payload/build_burst_only.py 生成的那份完整 .so
（19,484,036 字节）。传 pay.bin 之类的小文件会被拒绝。
"""
from __future__ import annotations

import argparse
import io
import pathlib
import re
import struct
import sys
import threading
import time

LAB = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "tools"))
sys.path.insert(0, str(LAB / "tools" / "camera"))
sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))

import a7r3a_shell as A

LIBOBJ_BASE = 0x05DCA000
WORK = "/log/w"


EXPECTED_SIZE = 19_484_036
EXPECTED_HOOK = bytes.fromhex("63f7579b")
EXPECTED_PAY = bytes.fromhex("2de9ff51")


def check_so(path: pathlib.Path) -> str | None:
    """确认传进来的是打好的完整 .so，不是 pay.bin 之类的小文件。

    这个工具按固定 fileVA 切片，传错文件不会报错，只会静默写进垃圾数据。
    所以先做三项粗检：
      · 大小必须是完整的 libObj.so
      · 钩点处 4 字节必须是 b.w 指令
      · 载荷处前 4 字节必须是 push.w 序言
    """
    try:
        size = path.stat().st_size
    except OSError as exc:
        return f"读不到文件：{exc}"
    if size != EXPECTED_SIZE:
        hint = ""
        if size < 1024:
            hint = "（这看起来是 pay.bin 之类的小文件，--so 要的是完整的 .so）"
        return (f"文件大小 {size:,} 字节，不是完整的 libObj.so（应为 {EXPECTED_SIZE:,}）{hint}")
    data = path.read_bytes()
    hook = data[0xA31226:0xA31226 + 4]
    pay = data[0x1948D8:0x1948D8 + 4]
    if hook != EXPECTED_HOOK:
        return (f"钩点 0xA31226 处是 {hook.hex()}，不是打好的钩子 {EXPECTED_HOOK.hex()}。"
                f"这个 .so 没打补丁，或者钩点地址不对。")
    if pay != EXPECTED_PAY:
        return (f"载荷 0x1948D8 处是 {pay.hex()}，不是载荷序言 {EXPECTED_PAY.hex()}。"
                f"这个 .so 里没写载荷。")
    return None


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", type=pathlib.Path)
    ap.add_argument("--hook-va", type=lambda x: int(x, 0), default=0xA31226,
                    help="钩点 fileVA，默认 0xA31226（CP 收包循环）。单拍方案是 0x3C039E")
    ap.add_argument("--pay-va", type=lambda x: int(x, 0), default=0x1948D8)
    ap.add_argument("--pay-len", type=int, default=240)
    ap.add_argument("--hook-from-so", action="store_true",
                    help="钩子字节从 .so 的 hook-va 处取（默认）")
    ap.add_argument("--read", type=lambda x: int(x, 0))
    ap.add_argument("--len", type=int, default=4)
    ap.add_argument("--zero", type=lambda x: int(x, 0),
                    help="注入前把该地址 4 字节清零（用于计数器）")
    # ---- 双钩模式（推荐）：一切参数来自 build_dual_hook.py 的产物清单 ----
    ap.add_argument("--manifest", type=pathlib.Path,
                    help="双钩清单 .json：自动安装 1~2 个钩点 + 一整块载荷")
    ap.add_argument("--dry-run", action="store_true",
                    help="只打印将要写入的运行期地址/字节，不接相机")
    a = ap.parse_args()

    if a.manifest:
        import json
        man = json.loads(a.manifest.read_text(encoding="utf-8"))
        so_path = pathlib.Path(man["out_path"])
        so = so_path.read_bytes()
        slot = man["slot"]["fileVA"]
        used = man["slot"]["used"]
        pay = so[slot:slot + used]
        pay_addr = LIBOBJ_BASE + slot
        jobs = [(LIBOBJ_BASE + h["fileVA"], bytes.fromhex(h["patch"]), h["name"])
                for h in man["hooks"]]
        guard = man.get("guard", {})
        print(f"清单      {a.manifest}")
        print(f"产物      {so_path.name}  sha256={man['out_sha256'][:16]}…")
        print(f"载荷      {len(pay)}B → 运行期 0x{pay_addr:08X}")
        for addr, data, name in jobs:
            print(f"钩点[{name}] 0x{addr:08X} ← {data.hex()}")
        if guard.get("enabled"):
            print(f"guard 标志 0x{guard['flag_addr']:08X}（注入前清零 4 字节）")
        if a.dry_run:
            print("\n（--dry-run：未连接相机）")
            return 0

        def work(cam: A.Cam):
            def put(name: str, data: bytes) -> bool:
                for _ in range(10):
                    try:
                        cam.camera.writeFile(f"{WORK}/{name}", data)
                        return True
                    except Exception:
                        time.sleep(2.5)
                return False

            cam.shell.run(f"busybox rm -rf {WORK}", 20)
            cam.shell.run(f"busybox mkdir -p {WORK}", 20)
            time.sleep(0.4)
            if not put("pay.bin", pay):
                print("❌ 载荷上传失败")
                return False
            lines = ["#!/bin/busybox sh"]
            if guard.get("enabled"):
                lines.append(f"busybox dd if=/dev/zero of=/proc/155/mem bs=1 "
                             f"seek={guard['flag_addr']} count=4 2>/dev/null")
            lines.append(f"busybox dd if={WORK}/pay.bin of=/proc/155/mem bs=1 "
                         f"seek={pay_addr} count={len(pay)} 2>/dev/null")
            checks = [("pay", pay_addr, pay)]
            for i, (addr, data, name) in enumerate(jobs):
                fn = f"h{i}.bin"
                if not put(fn, data):
                    print(f"❌ 钩点位图上传失败 {name}")
                    return False
                lines.append(f"busybox dd if={WORK}/{fn} of=/proc/155/mem bs=1 "
                             f"seek={addr} count=4 2>/dev/null")
                checks.append((f"h{i}", addr, data))
            for i, (_, addr, _) in enumerate(checks):
                lines.append(f"busybox dd if=/proc/155/mem bs=1 skip={addr} count=4 "
                             f"2>/dev/null > {WORK}/v{i}.bin")
            lines.append("echo WROTE")
            if not put("run.sh", ("\n".join(lines) + "\n").encode()):
                print("❌ 脚本上传失败")
                return False
            cam.shell.run(f"busybox sh {WORK}/run.sh", 180)
            cam.shell.run("busybox sync", 60)
            time.sleep(0.5)

            ok = True
            for i, (name, addr, want) in enumerate(checks):
                want4 = want[:4]
                got = None
                for _ in range(12):
                    buf = io.BytesIO()
                    try:
                        cam.camera.readFile(f"{WORK}/v{i}.bin", buf)
                        got = buf.getvalue()
                        break
                    except Exception:
                        time.sleep(1.3)
                if got is None:
                    print(f"  {name} 0x{addr:08X}: ❌ 读回失败")
                    ok = False
                else:
                    same = got == want4
                    print(f"  {name} 0x{addr:08X}: {got.hex()} vs {want4.hex()} "
                          f"{'✅' if same else '❌'}")
                    ok = ok and same
            cam.shell.run(f"busybox rm -rf {WORK}", 20)
            return ok

        try:
            r = A.run_on_camera(work)
        except Exception as e:
            print(f"❌ {e}")
            return 1
        print("\n✅ 注入成功" if r else "\n❌ 未成功")
        return 0 if r else 2

    if a.read is not None:
        if a.dry_run:
            print("\n（--dry-run：将读取 0x%08x %d 字节，未连接相机）" % (a.read, a.len))
            return 0

        def work(cam: A.Cam):
            data = cam.read_mem(a.read, a.len)
            print(f"0x{a.read:08x}: {data.hex()}")
            if a.len == 4:
                print(f"  值 = {struct.unpack('<I', data)[0]}")
            return True
        try:
            A.run_on_camera(work)
        except Exception as e:
            print(f"❌ {e}")
            return 1
        return 0

    if a.so is None:
        print("需要 --so 或 --read")
        return 1

    err = check_so(a.so)
    if err:
        print(f"--so 有问题：{err}")
        return 2

    so = a.so.read_bytes()
    pay = so[a.pay_va:a.pay_va + a.pay_len]
    hook = so[a.hook_va:a.hook_va + 4]
    hook_addr = LIBOBJ_BASE + a.hook_va
    pay_addr = LIBOBJ_BASE + a.pay_va
    print(f"载荷 {len(pay)}B → 0x{pay_addr:08x}")
    print(f"钩子 {hook.hex()} → 0x{hook_addr:08x}")

    if a.dry_run:
        print(f"\n（--dry-run：载荷 {len(pay)}B、钩子 {hook.hex()} 通过校验，未连接相机）")
        return 0

    def work(cam: A.Cam):
        def put(name: str, data: bytes) -> bool:
            for _ in range(10):
                try:
                    cam.camera.writeFile(f"{WORK}/{name}", data)
                    return True
                except Exception:
                    time.sleep(2.5)
            return False

        cam.shell.run(f"busybox rm -rf {WORK}", 20)
        cam.shell.run(f"busybox mkdir -p {WORK}", 20)
        time.sleep(0.4)

        if not (put("pay.bin", pay) and put("hok.bin", hook)):
            print("❌ 上传失败")
            return False

        lines = ["#!/bin/busybox sh", "set -e"]
        if a.zero is not None:
            lines.append(f"busybox dd if=/dev/zero of=/proc/155/mem bs=1 seek={a.zero} count=4 2>/dev/null")
        lines += [
            f"busybox dd if={WORK}/pay.bin of=/proc/155/mem bs=1 seek={pay_addr} count={len(pay)} 2>/dev/null",
            f"busybox dd if={WORK}/hok.bin of=/proc/155/mem bs=1 seek={hook_addr} count=4 2>/dev/null",
            f"busybox dd if=/proc/155/mem bs=1 skip={hook_addr} count=4 2>/dev/null > {WORK}/h.bin",
            f"busybox dd if=/proc/155/mem bs=1 skip={pay_addr} count={len(pay)} 2>/dev/null > {WORK}/p.bin",
            "echo WROTE",
        ]
        if not put("run.sh", ("\n".join(lines) + "\n").encode()):
            print("❌ 脚本上传失败")
            return False
        cam.shell.run(f"busybox sh {WORK}/run.sh", 180)
        cam.shell.run("busybox sync", 60)
        time.sleep(0.5)

        ok = True
        for name, want in (("h.bin", hook), ("p.bin", pay)):
            got = None
            for _ in range(12):
                buf = io.BytesIO()
                try:
                    cam.camera.readFile(f"{WORK}/{name}", buf)
                    got = buf.getvalue()
                    break
                except Exception:
                    time.sleep(1.3)
            if got is None:
                print(f"  {name}: ❌ 读取失败")
                ok = False
            else:
                same = got == want
                print(f"  {name}: {got.hex()} vs {want.hex()}  {'✅' if same else '❌'}")
                ok = ok and same
        cam.shell.run(f"busybox rm -rf {WORK}", 20)
        return ok

    try:
        r = A.run_on_camera(work)
    except Exception as e:
        print(f"❌ {e}")
        return 1
    print("\n✅ 注入成功" if r else "\n❌ 未成功")
    return 0 if r else 2


if __name__ == "__main__":
    sys.exit(main())
