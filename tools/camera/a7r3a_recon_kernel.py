"""只读侦察：内核模块、驱动参数、dmesg、块设备、工具清单。

目的：找 mumin FTL 写回缓存的运行期状态与是否有用户态刷写接口。
"""
from __future__ import annotations
import argparse, re, socket, sys, threading, time
from pathlib import Path


class Shell:
    def __init__(self, sock): self.sock = sock

    def _flush(self, quiet=0.25, max_wait=3.0):
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


def show(sh: Shell, cmd: str, title: str, keep: str | None = None, limit: int = 40):
    o = sh.run(cmd)
    print(f"\n##### {title}  [{cmd[:80]}]")
    lines = [l.rstrip() for l in o.splitlines()]
    lines = [l for l in lines if l.strip() and "job control" not in l and not re.fullmatch(r"Z9X\d", l.strip())]
    if keep:
        lines = [l for l in lines if re.search(keep, l, re.I)]
    for l in lines[:limit]:
        print("   ", l[:170])
    if len(lines) > limit:
        print(f"    … 共 {len(lines)} 行")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default="vendor/Sony-PMCA-RE")
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

        show(sh, "busybox cat /proc/modules", "已加载内核模块", limit=60)
        show(sh, "busybox ls /sys/module", "sys/module 列表", limit=80)
        for mod in ["nand", "mumindrv", "muminblk", "emmc", "ldec", "devno"]:
            show(sh, f"busybox ls /sys/module/{mod}/parameters 2>&1", f"{mod} 参数", limit=30)
            show(sh, f"busybox cat /sys/module/{mod}/parameters/* 2>&1", f"{mod} 参数值", limit=30)
        show(sh, "busybox cat /proc/devices", "字符/块设备", keep=r"nflasha|nand|emmc|mumin|Name|Block|Character", limit=40)
        show(sh, "busybox cat /proc/diskstats", "diskstats", limit=40)
        show(sh, "busybox dmesg", "dmesg: 错误/闪存相关",
             keep=r"error|fail|nand|mumin|emmc|read-only|readonly|bad|cache|flush|write", limit=60)
        show(sh, "busybox ls -l /dev | busybox grep -i 'nflasha\\|nand\\|dnfl'", "/dev 设备节点", limit=40)
        show(sh, "busybox mount", "当前挂载", limit=30)
        for d in ["/usr/bin", "/usr/sbin", "/usr/local/bin", "/sbin", "/bin"]:
            show(sh, f"busybox ls {d} 2>&1", f"{d} 内容", limit=60)
        for s in (s1, s2):
            try: s.close()
            except OSError: pass
        return True

    senserShellCommand(complete=work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
