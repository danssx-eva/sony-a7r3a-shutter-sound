#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""libObj 离线分析公共库：ELF 映射 / PLT 符号解析 / Thumb-2 分支解码 / 函数边界。

被 a1_hook.py / a2_alt.py / emu_burst.py / selfcheck_burst.py 共用。
默认读 logs/watch/usr_lib_libObj.so，可用 --file 或构造时传路径覆盖。
"""
from __future__ import annotations
import struct, bisect, pathlib

_ROOT = pathlib.Path(__file__).resolve().parents[2]
LIBOBJ = _ROOT / "logs" / "watch" / "usr_lib_libObj.so"
RUNTIME_BASE = 0x05DCA000          # 真机稳定运行期基址（上一轮实测）
TEXT_LO, TEXT_HI = 0x104070, 0xCF443C


# ---------------------------------------------------------------- ELF 基本映射
class Elf:
    """只读 ELF 解析：fileVA(==sh_addr) ↔ 文件偏移。

    第一个 PT_LOAD 的 vaddr == offset == 0，所以 .text/.rodata 区段
    fileVA 就等于文件偏移。.data 之后有 +0x8000 的 delta，本类自动处理。
    """

    def __init__(self, path: pathlib.Path = LIBOBJ):
        from elftools.elf.elffile import ELFFile
        self.path = pathlib.Path(path)
        self.data = self.path.read_bytes()
        self.ef = ELFFile(open(self.path, "rb"))
        self.segs = []
        for s in self.ef.iter_segments():
            if s["p_type"] == "PT_LOAD":
                self.segs.append((s["p_vaddr"], s["p_filesz"],
                                  s["p_offset"], s["p_memsz"]))
        self.segs.sort()
        self._fn = None
        self._plt = None

    def va2off(self, va: int) -> int:
        for vaddr, filesz, off, _memsz in self.segs:
            if vaddr <= va < vaddr + filesz:
                return off + (va - vaddr)
        raise ValueError(f"0x{va:x} 不在可读段内")

    def read(self, va: int, n: int) -> bytes:
        o = self.va2off(va)
        return self.data[o:o + n]

    # ------------------------------------------------------------ PLT 符号表
    def plt_map(self) -> dict[int, str]:
        """{PLT stub VA: 符号名}。

        实测本项目 .plt 的 stub 形态（ARM 模式 3 条指令 = 12 字节）：
            add  ip, pc, #0x1100000      ; 0xE28FC611
            add  ip, ip, #rot(imm8)      ; 0xE28CCxxx  (Rn=Rd=ip)
            ldr  pc, [ip, #disp]         ; 0xE5BCFxxx
        以及 4 个 stub 里有 1 个前面夹 4 字节填充（`bx lr; nop` 之类），
        因此**不能假设固定步长**，改为逐 4 字节扫描特征并解出 GOT 槽地址，
        再用 .rel.plt 的 r_offset → .dynsym 反查名字。全部 2511 个 stub 命中。
        """
        if self._plt is not None:
            return self._plt
        rel = self.ef.get_section_by_name(".rel.plt")
        ds = self.ef.get_section_by_name(".dynsym")
        plt = self.ef.get_section_by_name(".plt")
        plt_va, plt_sz = plt["sh_addr"], plt["sh_size"]
        rd = rel.data()
        n = len(rd) // 8
        got2name = {}
        for i in range(n):
            roff, info = struct.unpack_from("<II", rd, i * 8)
            got2name[roff] = ds.get_symbol(info >> 8).name

        def rot2(x: int) -> int:
            r = (x >> 8) & 0xF          # ARM 旋转字段：右移 2*r 位
            imm = x & 0xFF
            if r == 0:
                return imm
            s = 2 * r
            return ((imm >> s) | (imm << (32 - s))) & 0xFFFFFFFF

        MAGIC = 0xE28FC611
        d = self.data
        out: dict[int, str] = {}
        off = plt_va
        while off < plt_va + plt_sz - 8:
            if struct.unpack_from("<I", d, off)[0] == MAGIC:
                w2, w3 = struct.unpack_from("<II", d, off + 4)
                if ((w2 & 0xFFFFF000) == 0xE28CC000 and
                        (w3 & 0xFFFFF000) == 0xE5BCF000):
                    got = (off + 8) + 0x1100000 + rot2(w2) + (w3 & 0xFFF)
                    if got in got2name:
                        out[off] = got2name[got]
                    off += 12
                    continue
            off += 4
        self._plt = out
        return out

    # -------------------------------------------------------- 函数起始表
    def function_starts(self) -> list[int]:
        if self._fn is not None:
            return self._fn
        ex = self.ef.get_section_by_name(".ARM.exidx")
        data = ex.data()
        base = ex["sh_addr"]

        def prel31(w, addr):
            v = w & 0x7FFFFFFF
            if v & 0x40000000:
                v -= 0x80000000
            return (addr + v) & 0xFFFFFFFF

        fn = set()
        for off in range(0, len(data), 8):
            w = struct.unpack_from("<I", data, off)[0]
            fn.add(prel31(w, base + off))
        self._fn = sorted(fn)
        return self._fn


# ------------------------------------------------------- Thumb-2 分支解码
def decode_branch(va: int, b0: bytes):
    """解码 32 位 Thumb 的 B.W(T4) / BL / BLX 立即数。

    返回 (kind, target_va, 4)；kind ∈ {"b","bl","blx"}；否则 None。

    ★ 三条必须踩准的坑（全部由 keystone 往返 + capstone 对拍实证）：
      1. 位映射：imm = S:I1:I2:imm10H:imm11:0
                     I1 = NOT(J1 XOR S), I2 = NOT(J2 XOR S)   ← 是"取反"，不是直接异或
         直接写 (J1^S) 会让目标偏 0x800000/0x400000。
      2. BLX 的基准是 Align(va+4, 4)，不是 va+4。因为 PLT stub 是 ARM 状态，
         调用点常落在 2 mod 4 地址上（如 0xA311F6）。不取整就偏 2 字节。
      3. BLX 必须被识别成"分支"。`blx #0x10393c` 编码 d2 f6 a2 cb（hw2=0xCBA2，
         bit12=0），只认 `(hw2 & 0xD000)==0xD000` 的扫描器会漏掉全部 459 个
         blx 调用点 —— 上一轮 b3_queues.py 报"0 个调用点"正是栽在这里。

    对拍结果：在 .text 的 4 个区段（含本任务全部相关函数）上，
    bl=233 / blx=459 / b.w=44，**0 失配**。
    条件分支 B<c>.W（T3，21 位 imm）不在此函数内使用，返回 None —— 需要时用
    capstone 单独解码（本工具只做线性反汇编区域，不扫它）。
    """
    if len(b0) < 4:
        return None
    hw1, hw2 = struct.unpack_from("<HH", b0, 0)
    if (hw1 & 0xF800) != 0xF000:
        return None
    b15, b14, b12 = (hw2 >> 15) & 1, (hw2 >> 14) & 1, (hw2 >> 12) & 1
    if b15 == 1 and b14 == 1 and b12 == 1:
        kind, base = "bl", va + 4
    elif b15 == 1 and b14 == 1 and b12 == 0:
        kind, base = "blx", (va + 4) & ~3
    elif b15 == 1 and b14 == 0 and b12 == 1:
        kind, base = "b", va + 4
    else:
        return None                      # B<c>.W 的 T3 编码，不支持
    S = (hw1 >> 10) & 1
    J1 = (hw2 >> 13) & 1
    J2 = (hw2 >> 11) & 1
    I1 = 1 - (J1 ^ S)
    I2 = 1 - (J2 ^ S)
    imm = ((S << 24) | (I1 << 23) | (I2 << 22) |
           ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1))
    if S:
        imm -= (1 << 25)
    return kind, (base + imm) & 0xFFFFFFFF, 4


def find_branch_sites(e: Elf, targets: set[int], lo: int = TEXT_LO,
                      hi: int = TEXT_HI) -> list[dict]:
    """扫描代码段找所有 b/b.w/bl/blx 到 targets 的站点。

    只扫 32 位分支（16 位 b/b<cond> 的射程 ±2KB，跨函数到钩点的可能为 0；
    即便如此下面也顺带扫了 16 位无条件 b）。
    """
    d = e.data
    hits = []
    for va in range(lo, hi - 4, 2):
        try:
            o = e.va2off(va)
        except ValueError:
            continue
        hw1 = struct.unpack_from("<H", d, o)[0]
        if (hw1 & 0xF800) == 0xF000:
            r = decode_branch(va, d[o:o + 4])
            if r and r[1] in targets:
                hits.append(dict(va=va, kind=r[0], target=r[1],
                                 raw=d[o:o + 4].hex()))
            continue
        # 16 位无条件 B (T2): 11100 imm11
        if (hw1 & 0xF800) == 0xE000:
            imm = hw1 & 0x7FF
            if imm & 0x400:
                imm -= 0x800
            tgt = (va + 4 + imm * 2) & 0xFFFFFFFF
            if tgt in targets:
                hits.append(dict(va=va, kind="b16", target=tgt,
                                 raw=d[o:o + 2].hex()))
    return hits


# --------------------------------------------------------------- 反汇编
def make_md():
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM,
                     capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    return md


def disasm(e: Elf, va: int, nbytes: int, mark: dict[int, str] | None = None):
    """返回 [(addr, hexbytes, mnemonic, op_str, size, tag)]"""
    md = make_md()
    mark = mark or {}
    out = []
    for i in md.disasm(e.read(va, nbytes), va):
        out.append((i.address, i.bytes.hex(), i.mnemonic, i.op_str, i.size,
                    "   <<< " + mark[i.address] if i.address in mark else ""))
    return out


def func_of(starts: list[int], va: int) -> tuple[int, int | None]:
    k = bisect.bisect_right(starts, va) - 1
    return starts[k], (starts[k + 1] if k + 1 < len(starts) else None)


if __name__ == "__main__":
    e = Elf()
    print("PT_LOAD 段:")
    for s in e.segs:
        print("   vaddr=0x%08x filesz=0x%08x off=0x%08x memsz=0x%08x" % s)
    pm = e.plt_map()
    print("\nPLT stub 解析成功 =", len(pm), "个")
    for va in (0x0FF7B8, 0x102B34, 0x1027E4, 0x0FD2A0, 0x34D840,
               0x10393C, 0x1035CC, 0x101EC8, 0x0FCC1C):
        print("   0x%08x -> %s" % (va, pm.get(va, "<不是 PLT stub>")))
    fs = e.function_starts()
    print("\n.ARM.exidx 函数起始数 =", len(fs))
    for t in (0xA311E0, 0x3C039E, 0x1948D8, 0x194A20):
        f, n = func_of(fs, t)
        print("   0x%08x -> fn 0x%08x (+0x%x)  next=0x%x" % (t, f, t - f, n or 0))
