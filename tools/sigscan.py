#!/usr/bin/env python3
"""sigscan —— 特征码扫描脚手架（让补丁跨固件版本可用）

思路借用 **Magic Lantern 的 `constable`**：
不要硬编码地址，而是记录"目标函数附近的**短字节模式**"（签名），
运行时在**你自己的固件文件**里扫一遍，就能算出本次固件的实际地址。

为什么必须自己扫
----------------
本项目实测过：同一机型的"相机副本"和"固件包副本"不是同一个构建
（`viewUnified2.so` 差 0x120；`libObj.so` 在 A7R3 3.10 与 A7R3A 1.00 之间
同偏移相同率 8.08%，见 `docs/01-固件介绍.md`）。
别人文档里的地址对你不成立；**只有你自己扫出来的才算数**。

三种用法
--------
1) 从你自己的固件生成签名（推荐工作流）::

       python tools/sigscan.py make --file my_libObj.so --va 0x3C039E --len 16

2) 用内置示例签名定位（本机 A7R3A 1.00 的已知锚点）::

       python tools/sigscan.py locate --file my_libObj.so --base 0x05DCA000
       python tools/sigscan.py scan   --file my_libObj.so --name createEvent

3) 手工扫任意模式（`??` 是通配符，适配寄存器/立即数差异）::

       python tools/sigscan.py scan --file my_libObj.so \\
           --pattern "f8 b5 10 20 ?? af 0e 46 15 46"

输出里所有地址都是 **fileVA**（模块内虚拟地址）。
本机 libObj.so 第一个 PT_LOAD 的 vaddr == 文件偏移，所以前半段两者相同；
第二个段差 0x8000，脚本会自动换算。
给了 `--base` 会额外算出运行期地址（`base + fileVA`）。

注意
----
- 签名越短越容易误命中：默认取 16 字节，扫完会显示命中数（>1 就要加长）。
- 内置签名取自**本机固件**，只用于对照；换固件后应 `make` 出你自己的签名。
- 本工具只读文件，不连接相机。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path


# ---------------------------------------------------------------------------
# 内置示例签名
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Sig:
    module: str          # libObj / viewUnified2
    name: str
    file_va: int         # 本机固件上的文件偏移（仅作对照）
    pattern: str         # "f8 b5 10 20 ?? af ..."
    note: str


SIGS: tuple[Sig, ...] = (
    # ---- libObj.so ---------------------------------------------------------
    Sig(
        "libObj", "createEvent_hook", 0x3C039E,
        "f8 b5 10 20 00 af 0e 46 15 46 3c f5 58 ef 31 46",
        "单拍钩点：InputService::createEvent 入口（原厂 4 字节 f8 b5 10 20）",
    ),
    Sig(
        "libObj", "cp_recv_loop_hook", 0xA31226,
        "7c 69 23 78 ff 2b 08 d1 e2 78 a3 78 43 ea 02 22",
        "连拍钩点：CP 收包循环内、类型分发之前（原厂 4 字节 7c 69 23 78）",
    ),
    Sig(
        "libObj", "plt_ObjMsg_ctor", 0x0FF7B8,
        "11 c6 8f e2 1b ca 8c e2 5c fd bc e5 11 c6 8f e2",
        "PLT：ObjMsg 构造函数（ARM 存根，blx 目标不要置 Thumb 位）",
    ),
    Sig(
        "libObj", "plt_ParamStd_ctor", 0x102B34,
        "11 c6 8f e2 19 ca 8c e2 28 fa bc e5 11 c6 8f e2",
        "PLT：ParamStd<uint,Type8> 构造",
    ),
    Sig(
        "libObj", "plt_AddParam", 0x1027E4,
        "11 c6 8f e2 19 ca 8c e2 68 fc bc e5 11 c6 8f e2",
        "PLT：AddParam",
    ),
    Sig(
        "libObj", "plt_IssueCommandAsync", 0x0FD2A0,
        "11 c6 8f e2 1d ca 8c e2 b4 f6 bc e5 11 c6 8f e2",
        "PLT：ObjIf::IssueCommandAsync（必须用异步的，同步会死锁）",
    ),
    Sig(
        "libObj", "Get_id", 0x34D840,
        "80 b5 00 af bd e8 80 40 f9 f7 e6 bd",
        "Get(id) 组件实例获取",
    ),
    # ---- viewUnified2.so ---------------------------------------------------
    Sig(
        "viewUnified2", "setValueToModel_cam", 0x38C004,
        "b0 b5 82 b0 04 46 00 af 00 25 c0 68 7d 60 3d 60",
        "★★ 相机副本的 setValueToModel 入口；固件包副本在 0x38BEE4（差 0x120，别用）",
    ),
    Sig(
        "viewUnified2", "setCursorOnItemChange", 0x38BEB0,
        "f0 b5 8b b0 05 46 00 af 00 24 c0 68 07 f1 28 01",
        "光标移动处理（热函数；曾把它的中段 0x38BEE4 误当 setValueToModel 而必崩）",
    ),
)


# ---------------------------------------------------------------------------
# 模式编译与扫描
# ---------------------------------------------------------------------------
def compile_pattern(pattern: str) -> tuple[re.Pattern[bytes], int, int]:
    """把 "f8 b5 ?? 20" 编译成 bytes 正则。返回 (regex, 固定字节数, 总长)。"""
    tokens = pattern.replace(",", " ").split()
    if not tokens:
        raise SystemExit("空模式")
    parts: list[bytes] = []
    fixed = 0
    for tok in tokens:
        tok = tok.strip()
        if tok in {"??", "**", "?"}:
            parts.append(b".")
            continue
        if tok.startswith("0x"):
            tok = tok[2:]
        if len(tok) != 2 or not re.fullmatch(r"[0-9a-fA-F]{2}", tok):
            raise SystemExit(f"非法字节: {tok!r}（应为 2 位十六进制或 ??）")
        parts.append(re.escape(bytes([int(tok, 16)])))
        fixed += 1
    return re.compile(b"".join(parts), re.DOTALL), fixed, len(tokens)


def scan_bytes(data: bytes, pattern: str) -> list[int]:
    rx, _, _ = compile_pattern(pattern)
    return [m.start() for m in rx.finditer(data)]


def parse_pattern_text(pattern: str) -> bytes:
    """模式里的固定字节（用于展示/生成）。"""
    out = bytearray()
    for tok in pattern.split():
        if tok in {"??", "**", "?"}:
            out.append(0)
        else:
            out.append(int(tok[2:] if tok.startswith("0x") else tok, 16))
    return bytes(out)


# ---------------------------------------------------------------------------
# 子命令
# ---------------------------------------------------------------------------
def cmd_list(args: argparse.Namespace) -> int:
    rows = [s for s in SIGS if args.module in ("all", s.module)]
    if args.json:
        print(json.dumps([s.__dict__ for s in rows], ensure_ascii=False, indent=2))
        return 0
    print(f"{'module':14s} {'name':24s} {'fileVA':>10s}  说明")
    for s in rows:
        print(f"{s.module:14s} {s.name:24s} 0x{s.file_va:08X}  {s.note}")
    print("\n注：fileVA 是本机（ILCE-7RM3A / 1.00）的实测值，仅作对照；")
    print("    换固件请用 `make` 从你自己的 .so 重新生成签名。")
    return 0


def va_to_offset(data: bytes, va: int) -> int | None:
    """fileVA -> 文件偏移，找不到返回 None。"""
    import struct
    try:
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    except struct.error:
        return None
    for i in range(phnum):
        b = phoff + i * phentsize
        try:
            p_type = struct.unpack_from("<I", data, b)[0]
            p_offset = struct.unpack_from("<I", data, b + 4)[0]
            p_vaddr = struct.unpack_from("<I", data, b + 8)[0]
            p_filesz = struct.unpack_from("<I", data, b + 16)[0]
        except struct.error:
            continue
        if p_type != 1:
            continue
        if p_vaddr <= va < p_vaddr + p_filesz:
            return p_offset + (va - p_vaddr)
    return None


def offset_to_va(data: bytes, off: int) -> int:
    """文件偏移 -> fileVA。

    本机 libObj.so 第一个 PT_LOAD 的 p_offset == p_vaddr == 0，所以前半段两者相等；
    第二个 PT_LOAD 有 +0x8000 的差（p_offset=0x11A50E4, p_vaddr=0x11AD0E4）。
    直接把文件偏移当 fileVA 会在这之后全部算错。
    """
    import struct
    try:
        phoff = struct.unpack_from("<I", data, 0x1C)[0]
        phentsize, phnum = struct.unpack_from("<HH", data, 0x2A)
    except struct.error:
        return off
    for i in range(phnum):
        b = phoff + i * phentsize
        try:
            p_type = struct.unpack_from("<I", data, b)[0]
            p_offset = struct.unpack_from("<I", data, b + 4)[0]
            p_vaddr = struct.unpack_from("<I", data, b + 8)[0]
            p_filesz = struct.unpack_from("<I", data, b + 16)[0]
        except struct.error:
            continue
        if p_type != 1:
            continue
        if p_offset <= off < p_offset + p_filesz:
            return p_vaddr + (off - p_offset)
    return off



def _load(path: Path) -> bytes:
    if not path.is_file():
        raise SystemExit(f"文件不存在: {path}")
    return path.read_bytes()


def cmd_scan(args: argparse.Namespace) -> int:
    data = _load(args.file)
    if args.name:
        matches = [s for s in SIGS if s.name == args.name]
        if not matches:
            raise SystemExit(f"没有名为 {args.name} 的内置签名（用 list 查看）")
        sig = matches[0]
        pattern = sig.pattern
        print(f"# 使用内置签名 {sig.module}/{sig.name}")
    elif args.pattern:
        pattern = args.pattern
    else:
        raise SystemExit("需要 --name 或 --pattern")

    hits = scan_bytes(data, pattern)
    if not hits:
        print("[X] 未命中（固件版本不同？请用 make 重新生成签名）")
        return 1
    shown = hits if args.all else hits[:1]
    for off in shown:
        va = offset_to_va(data, off)
        line = f"命中 fileVA 0x{va:08X}（文件偏移 0x{off:X}）"
        if args.base is not None:
            line += f"  运行期 0x{args.base + va:08X}"
        line += f"  前 8 字节 {data[off:off+8].hex(' ')}"
        print(line)
    if len(hits) > 1:
        print(f"[!] 共 {len(hits)} 处命中 —— 签名可能太短，建议加长")
    if args.json:
        print(json.dumps({"pattern": pattern, "hits": hits,
                          "hit_vas": [offset_to_va(data, x) for x in hits]},
                         ensure_ascii=False, indent=2))
    return 0


def _guess_module(filename: str) -> str | None:
    """从文件名猜模块。猜不出返回 None。"""
    low = filename.lower()
    for name in ("libObj", "viewUnified2", "CautionConfig"):
        if name.lower() in low:
            return name
    return None


def cmd_locate(args: argparse.Namespace) -> int:
    data = _load(args.file)

    # --module all 时，若文件名能看出是什么模块，就只看该模块的签名。
    # 否则会拿 viewUnified2 的签名去扫 libObj，把「扫错文件」误报成「固件不同」。
    module = args.module
    other = 0
    if module == "all":
        guessed = _guess_module(args.file.name)
        if guessed:
            module = guessed
            other = sum(1 for s in SIGS if s.module != guessed)

    rows = [s for s in SIGS if module in ("all", s.module)]
    if not rows:
        print(f"内置签名里没有模块 {module} 的条目。")
        return 2

    print(f"文件 {args.file.name}  {len(data):,} 字节"
          + (f"  基址 0x{args.base:08X}" if args.base is not None else ""))
    print(f"{'name':24s} {'期望 fileVA':>12s} {'实际 fileVA':>12s} {'Δ':>8s}  运行期")
    missing: list[str] = []
    multi: list[str] = []
    shifted: list[str] = []
    exact: list[str] = []

    for sg in rows:
        hits = scan_bytes(data, sg.pattern)
        if not hits:
            print(f"{sg.name:24s} 0x{sg.file_va:08X} {'-':>12s} {'-':>8s}  [X] 未命中")
            missing.append(sg.name)
            continue
        va = offset_to_va(data, hits[0])
        delta = va - sg.file_va
        rt = f"0x{args.base + va:08X}" if args.base is not None else "（需 --base）"
        if len(hits) > 1:
            flag = f"  [!]多重命中 {len(hits)} 处"
            multi.append(sg.name)
        elif delta == 0:
            flag = ""
            exact.append(sg.name)
        else:
            flag = "  [!]位移"
            shifted.append(sg.name)
        print(f"{sg.name:24s} 0x{sg.file_va:08X} 0x{va:08X} {delta:+8d}  {rt}{flag}")

    if other:
        print(f"\n（另有 {other} 个签名属于其他模块，已跳过；用 --module all 可强制全扫）")

    print()
    if missing:
        print(f"未命中 {len(missing)}/{len(rows)}：{', '.join(missing)}")
    if multi:
        print(f"多重命中 {len(multi)}/{len(rows)}：{', '.join(multi)}")
        print("  这些签名太短，不能用来定位。")
    if shifted:
        print(f"有位移 {len(shifted)}/{len(rows)}：{', '.join(shifted)}")

    # 注意：other 只是「跳过别的模块的签名」，不算失败条件
    if not missing and not multi and not shifted:
        print("全部命中、唯一、Δ 均为 0 —— 签名锚点与本项目对照一致。")
        print("  这只说明地址锚点吻合，不是整文件同一个构建；"
              "构建身份用整文件 SHA256 确认。")
        return 0

    if missing or multi:
        print()
        print("结论：不能只靠这次扫描认定这是哪个构建。")
        print("  缺失或多重命中时，用整文件 SHA256 确认身份（见 docs/01-固件介绍.md）。")
        return 1 if missing else 3

    print()
    print("结论：签名都能唯一定位，但有位移。按 Δ 列调整地址，或在本文件上重新 make 签名。")
    return 4


def cmd_make(args: argparse.Namespace) -> int:
    data = _load(args.file)
    off = va_to_offset(data, args.va)
    if off is None:
        raise SystemExit(f"--va 0x{args.va:X} 不在任何 PT_LOAD 段内")
    chunk = data[off:off + args.len]
    if len(chunk) < args.len:
        raise SystemExit("文件尾不足，减小 --len")

    # 可选：把某些字节标成通配符（例如 RIP/PC 相对位移、寄存器编码）
    wild = set()
    for spec in args.wildcard:
        for part in spec.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                a, b = part.split("-", 1)
                wild.update(range(int(a, 0), int(b, 0) + 1))
            else:
                wild.add(int(part, 0))
    tokens = ["??" if i in wild else f"{b:02x}" for i, b in enumerate(chunk)]
    pattern = " ".join(tokens)

    print(f"# 从 {args.file.name} fileVA 0x{args.va:08X}（文件偏移 0x{off:X}）"
          f"起 {args.len} 字节生成签名")
    print(pattern)
    hits = scan_bytes(data, pattern)
    if len(hits) == 1:
        print(f"# [OK] 在本文件中唯一命中 @ 0x{hits[0]:08X}")
    else:
        print(f"# [!] 在本文件中命中 {len(hits)} 处 —— 建议加长 --len 或减少通配符")
    if args.json:
        print(json.dumps({"va": args.va, "offset": off, "len": args.len,
                          "pattern": pattern, "hits": hits,
                          "hit_vas": [offset_to_va(data, x) for x in hits]}, indent=2))
    return 0


def main() -> int:
    # Windows 控制台默认 GBK，打印中文/符号会炸；这里尽量切 UTF-8
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="特征码扫描脚手架（跨固件版本定位地址）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_list = sub.add_parser("list", help="列出内置示例签名")
    p_list.add_argument("--module", default="all", choices=["all", "libObj", "viewUnified2"])
    p_list.add_argument("--json", action="store_true")
    p_list.set_defaults(func=cmd_list)

    p_scan = sub.add_parser("scan", help="扫一个文件")
    p_scan.add_argument("--file", type=Path, required=True)
    p_scan.add_argument("--name", help="用内置签名名（见 list）")
    p_scan.add_argument("--pattern", help='形如 "f8 b5 10 20 ?? af"')
    p_scan.add_argument("--base", type=lambda x: int(x, 0), help="模块运行期基址，用于换算")
    p_scan.add_argument("--all", action="store_true", help="显示全部命中（默认只显示第一个）")
    p_scan.add_argument("--json", action="store_true")
    p_scan.set_defaults(func=cmd_scan)

    p_loc = sub.add_parser("locate", help="用全部内置签名逐个核对（换版本后第一件事）")
    p_loc.add_argument("--file", type=Path, required=True)
    p_loc.add_argument("--module", default="all", choices=["all", "libObj", "viewUnified2"])
    p_loc.add_argument("--base", type=lambda x: int(x, 0))
    p_loc.set_defaults(func=cmd_locate)

    p_make = sub.add_parser("make", help="从你自己的固件生成签名")
    p_make.add_argument("--file", type=Path, required=True)
    p_make.add_argument("--va", type=lambda x: int(x, 0), required=True)
    p_make.add_argument("--len", type=int, default=16)
    p_make.add_argument(
        "--wildcard", action="append", default=[],
        help="把这些【字节序号】变成 ??，可多次给；支持 0-3 区间，如 --wildcard 4-7",
    )
    p_make.add_argument("--json", action="store_true")
    p_make.set_defaults(func=cmd_make)

    args = ap.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
