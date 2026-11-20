"""只读状态检查：库 SHA、磁盘/内存钩子字节、uptime、/log、分区表、ext2 超级块。

不写任何东西。用于每次接手/实验后确认相机真实状态。
"""
from __future__ import annotations
import argparse, re, socket, struct, sys, threading, time
from pathlib import Path

HOOKS = [0x3e0eb8, 0x3e0ef0, 0x1948d8, 0xc8a238, 0xa3628c]
TARGET = "/usr/lib/libObj.so"


class Shell:
    def __init__(self, sock): self.sock = sock

    def _flush(self, quiet=0.3, max_wait=3.0):
        end = time.time() + max_wait; last = time.time()
        while time.time() < end:
            try:
                ch = self.sock.recv(65536)
                if not ch: return
                last = time.time()
            except socket.timeout:
                if time.time() - last > quiet: return

    def run(self, cmd, timeout=180.0):
        self._flush()
        self.sock.sendall((cmd + "; echo Z9X$?\n").encode("latin1", "replace"))
        buf = b""; end = time.time() + timeout
        while time.time() < end:
            try: ch = self.sock.recv(65536)
            except socket.timeout: continue
            if not ch: break
            buf += ch
            if re.search(rb"Z9X\d", buf):
                break
        return buf.decode("latin1", "replace")


def hexlines(out: str, width: int) -> list[str]:
    pat = r"[0-9a-f]{%d}" % width
    return [l.strip() for l in out.splitlines() if re.fullmatch(pat, l.strip())]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default="vendor/Sony-PMCA-RE")
    ap.add_argument("--maps", action="store_true",
                    help="只打印 /proc/<pid>/maps 后退出")
    a = ap.parse_args()
    sys.path.insert(0, str(Path(a.pmca).resolve()))
    from pmca.commands.usb import senserShellCommand  # noqa
    from pmca.platform.backend.senser import SenserPlatformBackend  # noqa

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.2); s1.settimeout(0.3)
        sh = Shell(s1)

        # --maps：只打印映射表就退出
        if a.maps:
            o = sh.run("busybox ps | busybox grep im.elf | busybox grep -v grep")
            mm = re.search(r"^\s*(\d+)", o, re.M)
            pid = int(mm.group(1)) if mm else 155
            print(f"# /proc/{pid}/maps")
            print(sh.run(f"busybox cat /proc/{pid}/maps", 120))
            for x in (s1, s2):
                try: x.close()
                except OSError: pass
            return True

        o = sh.run(f"busybox sha256sum {TARGET}")
        m = re.findall(r"[0-9a-f]{64}", o)
        print("磁盘 SHA :", m[-1] if m else "?")

        o = sh.run(f"busybox wc -c {TARGET}")
        sizes = re.findall(r"\b(\d{6,})\b", o)
        print("文件大小 :", sizes[-1] if sizes else "?")

        for h in HOOKS:
            o = sh.run(f"busybox dd if={TARGET} bs=1 skip={h} count=8 2>/dev/null | busybox xxd -p")
            v = hexlines(o, 16)
            print(f"磁盘 0x{h:x}:", v[-1] if v else "?")

        o = sh.run("busybox cat /proc/uptime")
        v = [l.strip() for l in o.splitlines() if re.fullmatch(r"[0-9.]+ [0-9.]+", l.strip())]
        print("uptime   :", v[-1] if v else "?")

        o = sh.run("busybox cat /proc/partitions")
        print("--- /proc/partitions ---")
        for l in o.splitlines():
            if re.search(r"nflasha|major", l):
                print("   ", l.strip()[:100])

        o = sh.run("busybox dd if=/dev/nflasha15 bs=1024 skip=1 count=1 2>/dev/null | busybox xxd -p")
        hx = "".join(hexlines(o, 32))
        if len(hx) >= 0xC0 * 2:
            sb = bytes.fromhex(hx[:1024 * 2])
            u32 = lambda off: struct.unpack_from("<I", sb, off)[0]
            u16 = lambda off: struct.unpack_from("<H", sb, off)[0]
            print("--- ext2 超级块 ---")
            print("    magic/state   :", hex(u16(0x38)), "/", u16(0x3A), "(1=clean)")
            print("    free/total blk:", u32(0x0C), "/", u32(0x04))
            print("    free inodes   :", u32(0x10), "/", u32(0x00))
            print("    mnt_count     :", u16(0x34))
            print("    wtime         :", u32(0x30), " lastcheck:", u32(0x40))
            print("    error_count   :", u32(0x194))
        else:
            print("--- ext2 超级块: 读取失败 ---")

        o = sh.run("busybox ls -l /log")
        print("--- /log ---")
        for l in o.splitlines():
            if re.search(r"[a-z0-9_.-]+$", l.strip()) and " " in l:
                print("   ", l.strip()[:100])

        o = sh.run("busybox cat /proc/155/maps | busybox grep libObj")
        m = re.search(r"([0-9a-f]{8})-[0-9a-f]{8}\s+r-xp", o)
        if m:
            base = int(m.group(1), 16)
            print("im.elf 基址:", hex(base))
            o = sh.run(f"busybox dd if=/proc/155/mem bs=1 skip={base + 0x3e0eb8} count=8 2>/dev/null | busybox xxd -p")
            v = hexlines(o, 16)
            print("内存 0x3e0eb8:", v[-1] if v else "?")
        else:
            print("im.elf 基址: ? (maps 里没找到 libObj)")
        for s in (s1, s2):
            try: s.close()
            except OSError: pass
        return True

    senserShellCommand(complete=work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
