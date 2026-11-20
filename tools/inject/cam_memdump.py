"""从相机读取任意内存区域（只读，安全）

用法:
    python tools/cam_memdump.py --addr 0x04053ED0 --len 128
    python tools/cam_memdump.py --addr 0x04053ED0 --len 128 --save work/dump.bin
"""
from __future__ import annotations

import argparse
import re
import socket
import sys
import time
import pathlib

LAB = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))


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

    def run(self, cmd, t=90.0):
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

    def read_mem(self, addr: int, length: int, chunk: int = 512) -> bytes | None:
        out = bytearray()
        off = 0
        while off < length:
            n = min(chunk, length - off)
            o = self.run(
                f"busybox dd if=/proc/155/mem bs=1 skip={addr+off} count={n} "
                f"2>/dev/null | busybox xxd -p", 90)
            hexs = "".join(l.strip() for l in o.splitlines()
                           if re.fullmatch(r"[0-9a-f]+", l.strip()))
            if len(hexs) < n * 2:
                return None
            out += bytes.fromhex(hexs[:n * 2])
            off += n
        return bytes(out)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--len", type=lambda x: int(x, 0), default=128)
    ap.add_argument("--save", type=pathlib.Path)
    a = ap.parse_args()

    from pmca.commands.usb import senserShellCommand
    from pmca.platform.backend.senser import SenserPlatformBackend

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.5)
        s1.settimeout(0.3)
        sh = Shell(s1)
        data = sh.read_mem(a.addr, a.len)
        if data is None:
            print("❌ 读取失败")
        else:
            print(f"0x{a.addr:08x} .. 0x{a.addr+a.len:08x}  ({len(data)} 字节)")
            for i in range(0, len(data), 16):
                row = data[i:i+16]
                hexs = " ".join(f"{x:02x}" for x in row)
                asci = "".join(chr(x) if 32 <= x < 127 else "." for x in row)
                print(f"  {a.addr+i:08x}  {hexs:<48}  {asci}")
            if a.save:
                a.save.parent.mkdir(parents=True, exist_ok=True)
                a.save.write_bytes(data)
                print(f"已保存 {a.save}")
        for s in (s1, s2):
            try:
                s.close()
            except OSError:
                pass
        return True

    import threading
    try:
        senserShellCommand(complete=work)
    except Exception as e:
        print(f"❌ 连接失败: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
