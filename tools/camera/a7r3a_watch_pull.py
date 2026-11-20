"""后台守候：相机一插上就自动拉文件。

用法：
    python a7r3a_watch_pull.py --pmca <PMCA目录> --out logs/watch [--rounds 8]

逻辑：
  1. 每 0.5 秒轮询 USB，见到 054C 就开始
  2. 调用 PMCA 的 serviceshell 路径（自动切服务模式 / 认证）
  3. 逐个拉文件，已拉成功的跳过
  4. 一轮结束相机掉线也没关系，等它再出现就继续
"""
from __future__ import annotations
import argparse, pathlib
import hashlib
import json
import sys
import time
from datetime import datetime
from pathlib import Path

DEFAULT_PATHS = [
    "/usr/share/app/area_check_data.dat",
    "/usr/share/app/master_camera.uxc",
    "/usr/share/app/string_english.uxc",
    "/usr/bin/scenario.elf",
    "/usr/bin/sen.elf",
    "/usr/lib/libviewUnified2.so",
    "/usr/lib/libObj.so",
]


def sony_present() -> bool:
    try:
        import libusb_package
        import usb.backend.libusb1 as lb
        import usb.core
        dll = libusb_package.get_library_path()
        be = lb.get_backend(find_library=lambda n: dll)
        return any(d.idVendor == 0x054C for d in usb.core.find(find_all=True, backend=be))
    except Exception:
        return False


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default=str(pathlib.Path(__file__).resolve().parents[2] / "vendor" / "Sony-PMCA-RE"))
    ap.add_argument("--out", default="logs/watch")
    ap.add_argument("--rounds", type=int, default=8)
    ap.add_argument("--timeout", type=int, default=1800)
    args = ap.parse_args()

    sys.path.insert(0, str(Path(args.pmca).resolve()))
    from pmca.commands.usb import senserShellCommand  # noqa: E402

    outdir = Path(args.out)
    outdir.mkdir(parents=True, exist_ok=True)
    log = open(outdir / "watch.log", "a", encoding="utf-8", buffering=1)

    def say(msg):
        line = f"[{datetime.now():%H:%M:%S}] {msg}"
        print(line, flush=True)
        log.write(line + "\n")

    pending = list(DEFAULT_PATHS)
    started = time.time()

    for rnd in range(1, args.rounds + 1):
        if time.time() - started > args.timeout:
            say("超时退出")
            break
        if not pending:
            say("全部文件已拿到，退出")
            break

        say(f"第 {rnd} 轮：等相机…")
        while not sony_present():
            if time.time() - started > args.timeout:
                say("等相机超时")
                return 1
            time.sleep(0.5)
        say("检测到相机，开始")
        time.sleep(1.5)  # 等枚举稳定

        got = []

        def run(camera):
            camera.readHasp()
            say(f"认证成功，待拉 {len(pending)} 个文件")
            for path in list(pending):
                name = path.strip("/").replace("/", "_")
                dst = outdir / name
                if dst.exists() and dst.stat().st_size > 0:
                    pending.remove(path)
                    continue
                try:
                    with open(dst, "wb") as f:
                        camera.readFile(path, f)
                    size = dst.stat().st_size
                    if size == 0:
                        dst.unlink()
                        say(f"  {path}: 0 字节，跳过")
                        continue
                    sha = hashlib.sha256(dst.read_bytes()).hexdigest() if size <= 64 << 20 else ""
                    say(f"  {path}: {size} bytes {sha[:16]}")
                    got.append(path)
                    pending.remove(path)
                except Exception as exc:
                    if dst.exists():
                        dst.unlink()
                    say(f"  {path}: 失败 {exc}")

        try:
            senserShellCommand(complete=run)
        except Exception as exc:
            say(f"会话异常：{exc}")

        say(f"本轮拿到 {len(got)} 个，剩余 {len(pending)}")
        time.sleep(2)

    say("结束")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
