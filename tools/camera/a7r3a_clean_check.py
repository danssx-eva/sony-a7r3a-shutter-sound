"""干净检查：库 SHA、内存钩子、hits.bin、uptime。用标记行避免回显污染。"""
from __future__ import annotations
import argparse, re, socket, sys, threading, time
from pathlib import Path


class Shell:
    def __init__(self, sock): self.sock = sock
    def _flush(self, quiet=0.3, max_wait=2.0):
        end = time.time() + max_wait; last = time.time()
        while time.time() < end:
            try:
                ch = self.sock.recv(65536)
                if not ch: return
                last = time.time()
            except socket.timeout:
                if time.time() - last > quiet: return
    def run(self, cmd, timeout=240.0):
        self._flush()
        self.sock.sendall((cmd + "\n").encode("latin1", "replace"))
        buf = b""; end = time.time() + timeout
        while time.time() < end:
            try: ch = self.sock.recv(65536)
            except socket.timeout: continue
            if not ch: break
            buf += ch
            text = buf.decode("latin1", "replace")
            if "ZZDONEZ" in text:
                return text
        return buf.decode("latin1", "replace")


def grab(text: str, tag: str, pat: str):
    m = re.search(rf"ZZ{tag}Z(.*?)ZZ", text, re.S)
    if not m:
        return None
    m2 = re.search(pat, m.group(1))
    return m2.group(0) if m2 else m.group(1).strip()


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default="vendor/Sony-PMCA-RE")
    ap.add_argument("--hook", default="0xa3628c")
    a = ap.parse_args()
    hook = int(a.hook, 0)
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

        sh.run("busybox echo ZZSHAZ; busybox sha256sum /usr/lib/libObj.so; busybox echo ZZ")
        sh.run(f"busybox echo ZZDISKZ; busybox dd if=/usr/lib/libObj.so bs=1 skip={hook} count=4 2>/dev/null | busybox xxd -p; busybox echo ZZ")
        sh.run("busybox echo ZZHITZ; busybox ls -l /log/hits.bin 2>&1; busybox echo ZZ")
        sh.run("busybox echo ZZUPZ; busybox cat /proc/uptime; busybox echo ZZ")
        sh.run("busybox echo ZZMAPZ; busybox cat /proc/155/maps | busybox grep libObj; busybox echo ZZ")
        out = sh.run("busybox echo ZZDONEZ")
        print("SHA   :", grab(out, "SHA", r"[0-9a-f]{64}"))
        print("磁盘钩子头:", grab(out, "DISK", r"[0-9a-f]{8}"))
        print("hits  :", grab(out, "HIT", r".{0,60}"))
        print("uptime:", grab(out, "UP", r"[0-9.]+ [0-9.]+"))
        mp = grab(out, "MAP", r"([0-9a-f]{8})-[0-9a-f]{8}\s+r-xp")
        base = int(mp, 16) if mp else None
        print("base  :", hex(base) if base else "?")
        if base:
            mem = sh.run(f"busybox echo ZZMHZ; busybox dd if=/proc/155/mem bs=1 skip={base + hook} count=4 2>/dev/null | busybox xxd -p; busybox echo ZZ")
            out2 = sh.run("busybox echo ZZDONEZ")
            print("内存钩子头:", grab(out2, "MH", r"[0-9a-f]{8}"))
        for s in (s1, s2):
            try: s.close()
            except OSError: pass
        return True

    senserShellCommand(complete=work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
