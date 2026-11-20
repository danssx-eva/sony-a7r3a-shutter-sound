"""LD_PRELOAD 部署/回滚工具（A7R3A）。

安全设计：
  · 默认 dry-run，必须 --go 才真的写
  · 部署前本地校验 .so：ELF32 / ARM / EABI5 / soft-float / 有 INIT_ARRAY / 无 DT_NEEDED
  · 上传到 /setting/mode/（vfat 持久分区，不掉电丢失）
  · 用索尼官方 change_mode.sh 激活
  · 随时可用 rollback() 清理

用法：
  python ldpreload_deploy.py --check                       # 只查本机 .so 是否合规
  python ldpreload_deploy.py --deploy --so <路径>           # dry-run，看会做什么
  python ldpreload_deploy.py --deploy --so <路径> --go      # 真的部署
  python ldpreload_deploy.py --rollback --go               # 回滚
  python ldpreload_deploy.py --status                      # 查相机当前状态
"""
from __future__ import annotations
import argparse, re, socket, struct, sys, threading, time
from pathlib import Path

PMCA_DEFAULT = "vendor/Sony-PMCA-RE"
MODE_DIR = "/setting/mode"
SO_NAME = "hook.so"
SO_PATH = f"{MODE_DIR}/{SO_NAME}"
DMODE = f"{MODE_DIR}/dmode"
PRELOAD = f"{MODE_DIR}/preload"
HOOK_LOG = "/log/hook.log"


# ---------------- 本地 .so 校验 ----------------
def check_so(path: Path) -> bool:
    if not path.exists():
        print(f"  ✗ 文件不存在: {path}")
        return False
    d = path.read_bytes()
    ok = True
    if d[:4] != b"\x7fELF":
        print("  ✗ 不是 ELF"); return False
    if d[4] != 1:
        print(f"  ✗ 不是 ELF32 (class={d[4]})"); ok = False
    if d[5] != 1:
        print(f"  ✗ 不是小端 (data={d[5]})"); ok = False
    e_machine = struct.unpack_from("<H", d, 0x12)[0]
    if e_machine != 40:
        print(f"  ✗ 不是 ARM (machine={e_machine})"); ok = False
    e_flags = struct.unpack_from("<I", d, 0x24)[0]
    eabi = (e_flags >> 24) & 0xFF      # ARM: EABI 版本在 bit 24-31
    if eabi != 5:
        print(f"  ✗ EABI 版本不是 5 (={eabi}, flags=0x{e_flags:08x})"); ok = False
    # EF_ARM_ABI_FLOAT_SOFT = 0x200 / EF_ARM_ABI_FLOAT_HARD = 0x400
    soft = bool(e_flags & 0x200)
    hard = bool(e_flags & 0x400)
    print(f"  ABI: EABI{eabi}  (flags=0x{e_flags:08x})  soft-float={soft}  hard-float={hard}")
    if not soft:
        print("  ✗ 不是 soft-float！相机是 ld-linux.so.3（soft-float）"); ok = False
    if hard:
        print("  ✗ 标了 hard-float！"); ok = False
    # 动态段：找 INIT_ARRAY / DT_NEEDED
    phoff = struct.unpack_from("<I", d, 0x1C)[0]
    phentsize = struct.unpack_from("<H", d, 0x2A)[0]
    phnum = struct.unpack_from("<H", d, 0x2C)[0]
    dyn = None
    for i in range(phnum):
        p = struct.unpack_from("<8I", d, phoff + i * phentsize)
        if p[0] == 2:  # PT_DYNAMIC
            dyn = (p[1], p[4])
    has_init_array = False
    needed = []
    if dyn:
        off, size = dyn
        for j in range(0, size, 8):
            tag, val = struct.unpack_from("<II", d, off + j)
            if tag == 0:
                break
            if tag == 0x19:      # DT_INIT_ARRAY
                has_init_array = True
            if tag == 1:         # DT_NEEDED
                needed.append(val)
    print(f"  INIT_ARRAY（构造函数）: {'有 ✓' if has_init_array else '无 ✗'}")
    if not has_init_array:
        print("  ✗ 没有 INIT_ARRAY → 构造函数不会被调用"); ok = False
    print(f"  DT_NEEDED 依赖数: {len(needed)}  {'✓ 自包含' if not needed else '⚠ 有依赖（相机上需存在）'}")
    print(f"  大小: {len(d)} 字节")
    return ok


# ---------------- 相机 shell ----------------
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

    def run(self, cmd, timeout=120.0):
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


def body_of(out: str) -> list[str]:
    return [l.strip() for l in out.splitlines()
            if l.strip() and "job control" not in l and not re.fullmatch(r"Z9X\d", l.strip())]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default=PMCA_DEFAULT)
    ap.add_argument("--check", action="store_true", help="只校验本地 .so")
    ap.add_argument("--so", help="本地 .so 路径")
    ap.add_argument("--deploy", action="store_true")
    ap.add_argument("--rollback", action="store_true")
    ap.add_argument("--status", action="store_true")
    ap.add_argument("--go", action="store_true", help="真的执行（否则 dry-run）")
    a = ap.parse_args()

    if a.check:
        if not a.so:
            print("需要 --so"); return 1
        print(f"校验 {a.so}")
        ok = check_so(Path(a.so))
        print("\n=> " + ("✅ 合规，可以部署" if ok else "❌ 不合规，禁止部署"))
        return 0 if ok else 1

    sys.path.insert(0, str(Path(a.pmca).resolve()))
    from pmca.commands.usb import senserShellCommand  # noqa
    from pmca.platform.backend.senser import SenserPlatformBackend  # noqa

    payload = None
    if a.deploy:
        if not a.so:
            print("--deploy 需要 --so"); return 1
        print(f"部署前校验 {a.so}")
        if not check_so(Path(a.so)):
            print("\n=> ❌ 校验失败，中止（不会写任何东西）"); return 1
        payload = Path(a.so).read_bytes()
        print()

    def work(camera):
        camera.readHasp()
        b = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=b.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(1.2); s1.settimeout(0.3)
        sh = Shell(s1)

        def put(path, data, tries=6):
            for i in range(tries):
                try:
                    camera.writeFile(path, data); return True
                except Exception as e:
                    print(f"      put 重试 {i+1}: {e}"); time.sleep(2)
            return False

        if a.status:
            print("=== 相机当前 LD_PRELOAD 状态 ===")
            for cmd, label in [
                (f"busybox ls -l {MODE_DIR} 2>&1", f"{MODE_DIR} 内容"),
                (f"busybox cat {DMODE} 2>&1", "dmode"),
                (f"busybox cat {PRELOAD} 2>&1", "preload"),
                (f"busybox ls -l {HOOK_LOG} 2>&1", "hook.log"),
                ("busybox cat /proc/uptime", "uptime"),
            ]:
                o = sh.run("echo BGN; " + cmd + "; echo END")
                lines = body_of(o.split("BGN")[-1].split("END")[0])
                print(f"  --- {label} ---")
                for l in lines[:6]:
                    print("     ", l[:110])

        if a.rollback:
            print("=== 回滚 LD_PRELOAD ===")
            cmds = [
                "busybox sync",
                f"busybox rm -f {PRELOAD}",
                f"busybox rm -f {SO_PATH}",
                f"sh {MODE_DIR}/../..//usr/bin/change_mode.sh 3 2>&1 || echo change_mode_missing",
            ]
            for c in cmds:
                if a.go:
                    o = sh.run(c)
                    print(f"  $ {c[:70]}")
                    for l in body_of(o)[:3]: print("     ", l[:100])
                else:
                    print(f"  (dry-run) $ {c[:70]}")
            o = sh.run(f"busybox cat {DMODE} 2>&1")
            print("  回滚后 dmode:", body_of(o)[:2])
            print("  → 完成。断电重启后即不再加载。")

        if a.deploy:
            print("=== 部署 LD_PRELOAD ===")
            steps = [
                (f"busybox mkdir -p {MODE_DIR} 2>&1; busybox sync", "建目录"),
                ("busybox mount | busybox grep setting", "确认 /setting 可写"),
            ]
            for c, label in steps:
                o = sh.run(c)
                print(f"  [{label}]")
                for l in body_of(o)[:3]:
                    print("     ", l[:110])

            if not a.go:
                print(f"  (dry-run) 会写入:")
                print(f"     {SO_PATH}   ({len(payload)} 字节)")
                print(f"  然后执行: /usr/bin/change_mode.sh p {SO_PATH}")
                print(f"  它会写: echo 3p > {DMODE} ; echo -n {SO_PATH} > {PRELOAD}")
                print("\n  ⚠ 这是 dry-run。确认无误后加 --go 才能真正部署。")
            else:
                print(f"  上传 .so ({len(payload)} 字节)…")
                if not put(SO_PATH, payload):
                    print("  ✗ 上传失败"); return False
                sh.run(f"busybox chmod 777 {SO_PATH}")
                sh.run("busybox sync")
                o = sh.run(f"busybox ls -l {SO_PATH}")
                print("  ", body_of(o)[:2])
                # 激活（用官方脚本）
                o = sh.run(f"/usr/bin/change_mode.sh p {SO_PATH} 2>&1")
                print("  change_mode.sh 输出:", body_of(o)[:3])
                sh.run("busybox sync")
                for f in (DMODE, PRELOAD):
                    o = sh.run(f"busybox cat {f} 2>&1")
                    print(f"  {f} = {body_of(o)[:1]}")
                print("\n  ✅ 部署完成。请【拔电池冷启动】，然后看 /log/hook.log 是否出现内容。")

        for s in (s1, s2):
            try: s.close()
            except OSError: pass
        return True

    senserShellCommand(complete=work)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
