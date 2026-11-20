"""最小 ELF32/ARM 读取 + 反汇编工具（给相机固件用）。"""
from __future__ import annotations
import struct
from pathlib import Path

from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_THUMB

SHT_SYMTAB, SHT_DYNSYM, SHT_STRTAB = 2, 11, 3


class Elf:
    def __init__(self, path: str | Path):
        self.path = Path(path)
        self.data = self.path.read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 1:
            raise ValueError("不是 ELF32")
        self.machine = struct.unpack_from("<H", d, 18)[0]
        e_shoff = struct.unpack_from("<I", d, 0x20)[0]
        e_shentsize = struct.unpack_from("<H", d, 0x2E)[0]
        e_shnum = struct.unpack_from("<H", d, 0x30)[0]
        e_shstrndx = struct.unpack_from("<H", d, 0x32)[0]
        self.sections = []
        for i in range(e_shnum):
            name, typ, flags, addr, off, size, link, info, align, entsize = struct.unpack_from(
                "<IIIIIIIIII", d, e_shoff + i * e_shentsize)
            self.sections.append(dict(name_off=name, type=typ, addr=addr, off=off,
                                      size=size, link=link, entsize=entsize))
        shstr = self.sections[e_shstrndx]
        for s in self.sections:
            p = shstr["off"] + s["name_off"]
            end = self.data.index(b"\x00", p)
            s["name"] = self.data[p:end].decode("ascii", "replace")

        self.symbols: dict[str, tuple[int, int]] = {}
        for s in self.sections:
            if s["type"] not in (SHT_SYMTAB, SHT_DYNSYM):
                continue
            strtab = self.sections[s["link"]]
            n = s["size"] // 16
            for i in range(n):
                name_off, value, size, info, other, shndx = struct.unpack_from(
                    "<IIIBBH", self.data, s["off"] + i * 16)
                if not name_off:
                    continue
                p = strtab["off"] + name_off
                end = self.data.index(b"\x00", p)
                name = self.data[p:end].decode("ascii", "replace")
                self.symbols.setdefault(name, (value, size))

    # --- 地址映射 ---
    def offset(self, vaddr: int) -> int:
        for s in self.sections:
            if s["addr"] and s["addr"] <= vaddr < s["addr"] + s["size"] and s["type"] != 8:
                return s["off"] + (vaddr - s["addr"])
        return vaddr  # 多数段 addr == off

    def read(self, vaddr: int, size: int) -> bytes:
        off = self.offset(vaddr)
        return self.data[off:off + size]

    # --- 符号 ---
    def sym(self, name: str) -> tuple[int, int]:
        if name not in self.symbols:
            cands = [k for k in self.symbols if name in k]
            raise KeyError(f"没有符号 {name!r}；相近：{cands[:5]}")
        return self.symbols[name]

    def text_range(self):
        for s in self.sections:
            if s["name"] == ".text":
                return s["addr"], s["size"]

    # --- 反汇编 ---
    def disasm(self, vaddr: int, size: int | None = None, count: int = 40, thumb: bool = True):
        md = Cs(CS_ARCH_ARM, CS_MODE_THUMB if thumb else CS_MODE_ARM)
        md.detail = True
        if size is None:
            size = count * 4
        code = self.read(vaddr, size)
        return list(md.disasm(code, vaddr))

    def disasm_function(self, name: str, extra: int = 16):
        value, size = self.sym(name)
        thumb = bool(value & 1)
        addr = value & ~1
        return self.disasm(addr, max(size + extra, 16), thumb=thumb) if size else \
            self.disasm(addr, 64, thumb=thumb)

    # --- 调用点 ---
    def bl_calls(self, target: int, thumb: bool = True):
        """扫描 .text，返回所有 BL/BLX/B.W 到 target 的位置。"""
        base, size = self.text_range()
        buf = self.read(base, size)
        out = []
        want = target & ~1
        for i in range(0, len(buf) - 4, 2):
            hw1 = struct.unpack_from("<H", buf, i)[0]
            if (hw1 & 0xF800) != 0xF000:
                continue
            hw2 = struct.unpack_from("<H", buf, i + 2)[0]
            kind = hw2 & 0xD000
            if kind == 0xD000:
                ins = "BL"
            elif kind == 0xC000:
                ins = "BLX"
            elif kind == 0x9000:
                ins = "B.W"
            else:
                continue
            S = (hw1 >> 10) & 1
            imm10 = hw1 & 0x3FF
            J1 = (hw2 >> 13) & 1
            J2 = (hw2 >> 11) & 1
            imm11 = hw2 & 0x7FF
            I1 = 1 - (J1 ^ S)
            I2 = 1 - (J2 ^ S)
            imm = (S << 24) | (I1 << 23) | (I2 << 22) | (imm10 << 12) | (imm11 << 1)
            if S:
                imm -= (1 << 25)
            pc = base + i + 4
            if ((pc + imm) & ~1) == want:
                out.append((base + i, ins))
        return out
