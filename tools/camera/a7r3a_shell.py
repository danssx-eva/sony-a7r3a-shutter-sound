"""A7R3 相机 shell 访问 + /proc/<pid>/mem 读写（被 read_msglog / inject_msglog 复用）

只做三件事：
  · 通过 PMCA 的 senser shell 在相机上执行 busybox 命令
  · 读 /proc/<pid>/mem（dd + xxd -p）
  · 写 /proc/<pid>/mem（上传文件 + dd）

⚠ 本模块不会主动连接相机；调用方必须显式调用 run_on_camera()。
"""
from __future__ import annotations

import pathlib
import re
import socket
import sys
import threading
import time

LAB = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_PID = 155
WORKDIR = "/log/w"


# --------------------------------------------------------------------------
class Shell:
    """PMCA 交互式 shell 的薄封装（沿用 tools/inject_payload.py 的成熟实现）"""

    MARK = "Z9X"

    def __init__(self, s: socket.socket):
        self.s = s

    def _flush(self, quiet: float = 0.3, maxt: float = 2.0) -> None:
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

    _seq = 0

    def run(self, cmd: str, t: float = 120.0) -> str:
        # 唯一标记：避免和缓冲区里旧命令残留的标记撞车
        Shell._seq += 1
        mark = f"{self.MARK}{Shell._seq}"
        self._flush(quiet=0.25, maxt=2.0)
        # 先发一个同步点，把残留输出吃掉
        self.s.sendall(f"echo {mark}PRE\n".encode("latin1", "replace"))
        pre = b""
        pre_end = time.time() + 10.0
        while time.time() < pre_end:
            try:
                ch = self.s.recv(65536)
            except socket.timeout:
                continue
            if not ch:
                break
            pre += ch
            if f"{mark}PRE".encode() in pre:
                break
        # 标记必须能被"运行时拼出来"，否则串口回显的命令行里就会出现它，
        # 读取循环会在真正的输出到达之前就退出。用 shell 变量拼接可以达到这个效果：
        #   命令原文：cmd; R=$?; M=<mark>; echo ${M}END${R}
        #   回显内容：... echo ${M}END${R}      （不含 <mark>END 字面量）
        #   实际输出：<mark>END<exitcode>
        self.s.sendall((cmd + f"; R=$?; M={mark}; echo ${{M}}END${{R}}\n")
                       .encode("latin1", "replace"))
        buf = b""
        end = time.time() + t
        marker = f"{mark}END".encode()
        while time.time() < end:
            try:
                ch = self.s.recv(65536)
            except socket.timeout:
                continue
            if not ch:
                break
            buf += ch
            if marker in buf:
                break
        text = buf.decode("latin1", "replace")
        # 切掉命令回显。注意必须用 find（第一个提示符），不能用 rfind：
        # 命令执行完之后还会再打印一个新提示符，rfind 会切到那之后，把输出全部丢掉。
        idx = text.find("# ")
        if idx >= 0:
            nl = text.find("\n", idx)
            if nl >= 0:
                text = text[nl + 1:]
        # 去掉尾部的标记与退出码
        text = re.sub(rf"{mark}END\d+\s*$", "", text)
        return text


# --------------------------------------------------------------------------
class Mapping:
    __slots__ = ("lo", "hi", "perm", "off", "path")

    def __init__(self, lo: int, hi: int, perm: str, off: int, path: str):
        self.lo, self.hi, self.perm, self.off, self.path = lo, hi, perm, off, path

    def __repr__(self) -> str:
        return f"{self.lo:#010x}-{self.hi:#010x} {self.perm} {self.path}"


def parse_maps(text: str) -> list[Mapping]:
    out = []
    for line in text.splitlines():
        m = re.match(r"([0-9a-f]+)-([0-9a-f]+)\s+(\S{4})\s+([0-9a-f]+)\s+\S+\s+\S+\s*(.*)",
                     line)
        if m:
            out.append(Mapping(int(m.group(1), 16), int(m.group(2), 16),
                               m.group(3), int(m.group(4), 16), m.group(5).strip()))
    return out


class Cam:
    """相机上的文件/内存操作"""

    def __init__(self, camera, shell: Shell, pid: int = DEFAULT_PID):
        self.camera = camera
        self.shell = shell
        self.pid = pid
        self._mem = pathlib.Path(WORKDIR)
        self._prepared = False

    # ---- 基础 ----
    def sh(self, cmd: str, t: float = 120.0) -> str:
        return self.shell.run(cmd, t)

    def prepare(self) -> None:
        if self._prepared:
            return
        self.sh(f"busybox rm -rf {WORKDIR}", 20)
        self.sh(f"busybox mkdir -p {WORKDIR}", 20)
        self._prepared = True

    def cleanup(self) -> None:
        self.sh(f"busybox rm -rf {WORKDIR}", 20)
        self._prepared = False

    def upload(self, name: str, data: bytes, tries: int = 6) -> bool:
        self.prepare()
        path = f"{WORKDIR}/{name}"
        for _ in range(tries):
            try:
                self.camera.writeFile(path, data)
                return True
            except Exception:                                # noqa: BLE001
                time.sleep(2.0)
        return False

    # ---- 内存 ----
    def read_mem(self, addr: int, n: int, t: float = 180.0) -> bytes:
        cmd = (f"busybox dd if=/proc/{self.pid}/mem bs=1 skip={addr} count={n} "
               f"2>/dev/null | busybox xxd -p")
        out = self.sh(cmd, t)
        # 只接受"整行都是纯十六进制"的行，避免 shell 提示符/日志掺入
        lines = [ln.strip() for ln in out.splitlines()]
        hex_lines = [ln for ln in lines if ln and re.fullmatch(r"[0-9a-fA-F]+", ln)]
        hexs = "".join(hex_lines)
        if len(hexs) < n * 2:
            raise IOError(f"读 0x{addr:x}({n}B) 只拿到 {len(hexs)//2}B；输出={out[:200]!r}")
        return bytes.fromhex(hexs[:n * 2])

    def write_mem_file(self, addr: int, name: str, n: int, word_aligned: bool = False,
                       t: float = 180.0) -> bool:
        """把已上传的 name 写到 addr。word_aligned=True 时用 bs=4 单次写入（原子性更好）"""
        self.prepare()
        src = f"{WORKDIR}/{name}"
        if word_aligned:
            if addr % 4 or n % 4:
                raise ValueError(f"bs=4 写入要求 4 字节对齐/长度: addr={addr:#x} n={n}")
            cmd = (f"busybox dd if={src} of=/proc/{self.pid}/mem bs=4 "
                   f"seek={addr // 4} count={n // 4} 2>/dev/null")
        else:
            cmd = (f"busybox dd if={src} of=/proc/{self.pid}/mem bs=1 "
                   f"seek={addr} count={n} 2>/dev/null")
        out = self.sh(cmd, t)
        return len(out.strip()) == 0 or "error" not in out.lower()

    def write_mem(self, addr: int, data: bytes, name: str, word_aligned: bool = False) -> bool:
        if not self.upload(name, data):
            raise IOError(f"上传 {name} 失败")
        return self.write_mem_file(addr, name, len(data), word_aligned=word_aligned)

    def maps(self) -> list[Mapping]:
        return parse_maps(self.sh(f"busybox cat /proc/{self.pid}/maps", 60))

    def pid_of(self, pattern: str) -> list[int]:
        out = self.sh(f"busybox ps | busybox grep -F '{pattern}' | busybox grep -v grep", 40)
        pids = []
        for line in out.splitlines():
            m = re.match(r"\s*(\d+)", line)
            if m:
                pids.append(int(m.group(1)))
        return pids


# --------------------------------------------------------------------------
def find_base(mappings: list[Mapping], soname: str) -> int | None:
    """取某个 .so 的最低位映射起点作为基址（对 libosal 这类 p_vaddr=0 的对象成立）。

    必须按文件名精确匹配，不能用 endswith：这台机器上同时存在
    CautionConfig.so 和 ModelCautionConfig.so，而
    "ModelCautionConfig.so".endswith("CautionConfig.so") 是 True，
    会把基址取到错误的模块上。
    """
    for m in mappings:
        if m.path.rsplit("/", 1)[-1] == soname:
            return m.lo
    return None


def mapping_at(mappings: list[Mapping], addr: int) -> Mapping | None:
    for m in mappings:
        if m.lo <= addr < m.hi:
            return m
    return None


# --------------------------------------------------------------------------
def run_on_camera(work, ready_wait: float = 1.5, cleanup: bool = True):
    """连上相机 → 起一个 shell → 调 work(Cam) → 返回 work 的返回值。

    cleanup=True 时退出前会删掉 /log/w 整个目录。上传文件给别人用的时候要传 False，
    否则刚传上去的文件在会话结束时就被清掉了。

    注意：这是唯一会接触相机的入口，工具里的 --dry-run 必须绕过它。
    """
    sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))
    from pmca.commands.usb import senserShellCommand          # noqa: PLC0415
    from pmca.platform.backend.senser import SenserPlatformBackend  # noqa: PLC0415

    box: dict = {}

    def _work(camera):
        camera.readHasp()
        backend = SenserPlatformBackend(camera)
        s1, s2 = socket.socketpair()
        threading.Thread(target=backend.interactiveShell, args=(s2,), daemon=True).start()
        time.sleep(ready_wait)
        s1.settimeout(0.3)
        cam = Cam(camera, Shell(s1))
        box["cam"] = cam
        try:
            box["result"] = work(cam)
        finally:
            if cleanup:
                try:
                    cam.cleanup()
                except Exception:                            # noqa: BLE001
                    pass
        return box.get("result")

    senserShellCommand(complete=_work)
    if "result" not in box and "cam" not in box:
        raise RuntimeError("无法建立相机 shell（senserShellCommand 未回调）")
    return box.get("result")
