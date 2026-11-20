"""Resolve ARM PLT stubs to dynamic symbols through their actual GOT relocations."""
from __future__ import annotations

import struct
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fwlab.arm import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_IP, ARM_REG_PC

PATH = Path("logs/watch/usr_lib_libObj.so")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=PATH,
                    help=f"要分析的 ELF（默认 {PATH}）")
    ap.add_argument("addresses", nargs="*", help="只输出这些 PLT 地址；留空输出全部")
    args = ap.parse_args()
    if not args.file.exists():
        ap.error(f"文件不存在：{args.file}\n先用 教程/01-读取固件 把 libObj.so 拉到本地")
    elf = Elf(args.file)
    data = elf.data
    dynsym = next(s for s in elf.sections if s["type"] == 11)
    dynstr = elf.sections[dynsym["link"]]
    symbols = []
    for index in range(dynsym["size"] // 16):
        name_off, value, size, info, other, shndx = struct.unpack_from(
            "<IIIBBH", data, dynsym["off"] + index * 16)
        start = dynstr["off"] + name_off
        end = data.find(b"\0", start)
        symbols.append(data[start:end].decode("ascii", "replace"))
    relplt = next(s for s in elf.sections if s["name"] == ".rel.plt")
    got_symbol = {}
    for off in range(relplt["off"], relplt["off"] + relplt["size"], 8):
        got, info = struct.unpack_from("<II", data, off)
        got_symbol[got] = symbols[info >> 8]

    plt = next(s for s in elf.sections if s["name"] == ".plt")
    md = Cs(CS_ARCH_ARM, CS_MODE_ARM | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    instructions = list(md.disasm(data[plt["off"]:plt["off"] + plt["size"]], plt["addr"]))
    resolved = {}
    for i in range(len(instructions) - 2):
        a, b, c = instructions[i:i + 3]
        if not (a.mnemonic == "add" and b.mnemonic == "add" and c.mnemonic.startswith("ldr")):
            continue
        if len(a.operands) < 3 or len(b.operands) < 3 or len(c.operands) < 2:
            continue
        if not (a.operands[0].type == ARM_OP_REG and a.operands[0].reg == ARM_REG_IP
                and a.operands[1].type == ARM_OP_REG and a.operands[1].reg == ARM_REG_PC
                and a.operands[2].type == ARM_OP_IMM
                and b.operands[0].type == ARM_OP_REG and b.operands[0].reg == ARM_REG_IP
                and b.operands[1].type == ARM_OP_REG and b.operands[1].reg == ARM_REG_IP
                and b.operands[2].type == ARM_OP_IMM
                and c.operands[1].type == ARM_OP_MEM and c.operands[1].mem.base == ARM_REG_IP):
            continue
        got = (a.address + 8 + a.operands[2].imm + b.operands[2].imm + c.operands[1].mem.disp) & 0xffffffff
        if got in got_symbol:
            resolved[a.address] = (got, got_symbol[got])
    requested = {int(arg, 0) for arg in sys.argv[1:]}
    print(f"plt_stubs={len(resolved)} requested={len(requested)}")
    for address, (got, name) in sorted(resolved.items()):
        if not requested or address in requested:
            print(f"0x{address:08x} GOT=0x{got:08x} {name}")
    missing = requested - set(resolved)
    if missing:
        print("unresolved:", ", ".join(hex(x) for x in sorted(missing)))
        raise SystemExit(1)


if __name__ == "__main__":
    main()
