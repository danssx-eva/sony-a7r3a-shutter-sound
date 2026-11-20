"""从相机 dump 大块内存：先在相机上 dd 成文件，再通过 USB 传回（快）

用法:
    python tools/cam_memdump_file.py --addr 0x04050000 --len 0x6000 --out work/cam_libosal_full.bin
"""
from __future__ import annotations

import argparse
import io
import re
import socket
import sys
import threading
import time
import pathlib

LAB = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))

DUMP = "/log/w/dump.bin"


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

    def run(self, cmd, t=180.0):
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


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--len", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--out", type=pathlib.Path, required=True)
    a = ap.parse_args()

    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend

    result = {"data": None}

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.5)
        s1.settimeout(0.3)
        sh = Shell(s1)

        sh.run("busybox rm -rf /log/w", 20)
        sh.run("busybox mkdir -p /log/w", 20)
        time.sleep(0.3)
        print(f"相机上 dd: 0x{a.addr:x} .. 0x{a.addr+a.len:x} ({a.len} 字节)")
        sh.run(f"busybox dd if=/proc/155/mem of={DUMP} bs=1 skip={a.addr} "
               f"count={a.len} 2>&1 | busybox tail -1", 180)
        o = sh.run(f"busybox wc -c {DUMP}", 30)
        print("  文件大小:", o.strip().splitlines()[:2])
        sh.run("busybox sync", 60)
        time.sleep(0.4)

        for attempt in range(12):
            buf = io.BytesIO()
            try:
                camera.readFile(DUMP, buf)
                d = buf.getvalue()
                if len(d) == a.len:
                    result["data"] = d
                    print(f"  ✓ 下载成功 {len(d)} 字节")
                    break
                else:
                    print(f"  ? 大小不符 {len(d)}，重试")
            except Exception as e:
                if attempt == 11:
                    print(f"  ❌ 下载失败: {e}")
            time.sleep(1.5)

        sh.run(f"busybox rm -f {DUMP}", 20)
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

    if result["data"]:
        a.out.parent.mkdir(parents=True, exist_ok=True)
        a.out.write_bytes(result["data"])
        import hashlib
        print(f"已保存 {a.out}  ({len(result['data'])} 字节)")
        print(f"SHA256: {hashlib.sha256(result['data']).hexdigest()}")
        return 0
    print("❌ 未取到数据")
    return 2


if __name__ == "__main__":
    sys.exit(main())
