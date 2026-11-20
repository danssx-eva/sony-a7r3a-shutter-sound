"""把中文语言包里「静音拍摄」改成「静音测试」（等长替换，原地写）。"""
from __future__ import annotations
import argparse, hashlib, re, socket, sys, threading, time
from pathlib import Path

TARGET = "/usr/share/app/string_simplifiedchinese.uxc"
NEW = Path("work/zh_test.uxc")
PW = Path("tools/inject/pw")
ORIG_SHA = "478d704515b6f240"  # 前 16 位，仅打印用


class Shell:
    def __init__(self, sock): self.sock = sock
    def _flush(self, quiet=0.25, max_wait=2.0):
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
        self.sock.sendall((cmd + "; echo __RC=$?\n").encode("latin1", "replace"))
        buf = b""; end = time.time() + timeout
        while time.time() < end:
            try: ch = self.sock.recv(65536)
            except socket.timeout: continue
            if not ch: break
            buf += ch
            text = buf.decode("latin1", "replace")
            i = text.rfind("__RC=")
            if i >= 0:
                d = ""
                for c in text[i+5:i+12]:
                    if c.isdigit(): d += c
                    else: break
                if d: return int(d), text
        raise TimeoutError(cmd)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default="vendor/Sony-PMCA-RE")
    ap.add_argument("--restore", default="")
    a = ap.parse_args()
    payload = Path(a.restore).read_bytes() if a.restore else NEW.read_bytes()
    pw = PW.read_bytes()
    print(f"目标 {TARGET}  写入 {len(payload)} 字节  SHA {hashlib.sha256(payload).hexdigest()[:16]}")

    sys.path.insert(0, str(Path(a.pmca).resolve()))
    from pmca.commands.usb import senserShellCommand  # noqa
    from pmca.platform.backend.senser import SenserPlatformBackend  # noqa

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.2); s1.settimeout(0.5)
        sh = Shell(s1)

        def rc(cmd, t=180.0, show=False):
            c, o = sh.run(cmd, t)
            if show:
                for line in o.splitlines():
                    s = line.strip()
                    if s and "job control" not in s and "__RC=" not in s:
                        print("   ", s[:150])
            return c, o

        def sha():
            c, o = rc(f"busybox sha256sum {TARGET}")
            m = re.findall(r"([0-9a-f]{64})", o)
            return m[-1] if m else "?"

        print("改前 SHA:", sha())
        rc("busybox mkdir -p /log/zw")
        camera.writeFile("/log/zw/pw", pw)
        camera.writeFile("/log/zw/new.uxc", payload)
        rc("busybox chmod 755 /log/zw/pw")
        rc("busybox sync")
        rc("busybox sha256sum /log/zw/new.uxc", show=True)
        rc("mount -o remount,rw /usr")
        rc(f"/log/zw/pw {TARGET} 0 /log/zw/new.uxc", show=True)
        rc("busybox sync")
        got = sha()
        print("改后 SHA:", got)
        rc("mount -o remount,ro /usr")
        rc(f"busybox ls -l {TARGET}", show=True)
        for s in (s1, s2):
            try: s.close()
            except OSError: pass
        return True

    senserShellCommand(complete=work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
