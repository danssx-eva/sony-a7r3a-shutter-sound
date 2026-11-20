"""Find Thumb code references to arbitrary link-time virtual addresses."""
from __future__ import annotations

import struct
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from fwlab.arm import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_OP_IMM, ARM_OP_MEM, ARM_OP_REG, ARM_REG_PC

PATH = Path("logs/watch/usr_lib_libObj.so")


def main() -> None:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=PATH,
                    help=f"要分析的 ELF（默认 {PATH}）")
    ap.add_argument("addresses", nargs="*", type=lambda x: int(x, 0),
                    help="要找引用点的地址，例如 0x0FF7B8")
    args = ap.parse_args()
    targets = set(args.addresses)
    if not targets:
        ap.error("至少给一个地址，例如 0x0FF7B8")
    if not args.file.exists():
        ap.error(f"文件不存在：{args.file}\n先用 教程/01-读取固件 把 libObj.so 拉到本地")
    elf = Elf(args.file)
    text = next(s for s in elf.sections if s["name"] == ".text")
    base = text["addr"]
    blob = elf.data[text["off"]:text["off"] + text["size"]]
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    recent = defaultdict(list)
    last_movw = {}
    hits = []
    for ins in md.disasm(blob, base):
        if ins.id == 0:
            continue
        ops = ins.operands
        mn = ins.mnemonic.lower()
        if mn.startswith("adr") and len(ops) >= 2 and ops[1].type == ARM_OP_IMM and ops[1].imm in targets:
            hits.append((ins.address, ops[1].imm, "adr", f"{ins.mnemonic} {ins.op_str}"))
        if mn.startswith("ldr") and len(ops) >= 2 and ops[1].type == ARM_OP_MEM and ops[1].mem.base == ARM_REG_PC:
            lit = ((ins.address + 4) - ((ins.address + 4) % 4) + ops[1].mem.disp) & 0xffffffff
            rel = lit - base
            if 0 <= rel <= len(blob) - 4:
                value = struct.unpack_from("<I", blob, rel)[0]
                if value in targets:
                    hits.append((ins.address, value, "ldr-literal", f"{ins.mnemonic} {ins.op_str}"))
                if ops[0].type == ARM_OP_REG:
                    recent[ops[0].reg].append((ins.address, value))
        if mn.startswith("movw") and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            last_movw[ops[0].reg] = (ops[1].imm, ins.address)
        elif mn.startswith("movt") and len(ops) >= 2 and ops[1].type == ARM_OP_IMM:
            prev = last_movw.pop(ops[0].reg, None)
            if prev:
                value = ((ops[1].imm << 16) | prev[0]) & 0xffffffff
                if value in targets:
                    hits.append((ins.address, value, f"movw@0x{prev[1]:x}/movt", f"{ins.mnemonic} {ins.op_str}"))
        if mn.startswith("add") and ops and ops[0].type == ARM_OP_REG:
            if any(op.type == ARM_OP_REG and op.reg == ARM_REG_PC for op in ops[1:]):
                for ldr_addr, value in reversed(recent[ops[0].reg]):
                    if ins.address - ldr_addr > 24:
                        break
                    target = (value + ins.address + 4) & 0xffffffff
                    if target in targets:
                        hits.append((ins.address, target, f"pic-ldr@0x{ldr_addr:x}+add", f"{ins.mnemonic} {ins.op_str}"))
    print(f"targets={[hex(t) for t in sorted(targets)]} hits={len(hits)}")
    for hit in hits:
        print(f"0x{hit[0]:08x} target=0x{hit[1]:x} {hit[2]:24s} {hit[3]}")


if __name__ == "__main__":
    main()
