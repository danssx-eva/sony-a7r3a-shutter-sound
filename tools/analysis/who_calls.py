"""找指定地址的调用点（BL / B.W / BLX）和字面量引用，并给出所属函数。"""
from __future__ import annotations
import bisect, struct, sys
from pathlib import Path
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
from capstone.arm import ARM_INS_BL, ARM_INS_BLX, ARM_INS_B

PATH = "logs/watch/usr_lib_libObj.so"
TARGETS = {
    0xa360e4: "SequenceStillCaptureStart ctor",
    0xc19b00: "SequenceEEStart ctor",
    0xa35d20: "StillCaptureStart 执行体候选",
    0xc19b3a: "EEStart 执行体候选",
    0x120d530: "StillCaptureStart vtable",
    0x120fb60: "EEStart vtable",
}


def exidx_ranges(d: bytes):
    shoff = struct.unpack_from("<I", d, 0x20)[0]
    shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x2e)
    shstr = struct.unpack_from("<I", d, shoff + shstrndx * shentsize + 0x10)[0]
    secs = {}
    for i in range(shnum):
        b = shoff + i * shentsize
        no = struct.unpack_from("<I", d, b)[0]
        secs[d[shstr + no:d.index(b"\0", shstr + no)].decode()] = b
    # PT_LOAD 映射（off→va）
    phoff = struct.unpack_from("<I", d, 0x1c)[0]
    segs = []
    for i in range(struct.unpack_from("<H", d, 0x2c)[0]):
        p = struct.unpack_from("<8I", d, phoff + 32 * i)
        if p[0] == 1:
            segs.append((p[1], p[2], p[4]))
    def o2v(o):
        for fo, va, fs in segs:
            if fo <= o < fo + fs:
                return va + (o - fo)
        return o
    off, size = struct.unpack_from("<II", d, secs[".ARM.exidx"] + 0x10)[:2]
    starts = []
    for i in range(size // 8):
        w, _ = struct.unpack_from("<II", d, off + 8 * i)
        if w >= (1 << 31):
            w -= (1 << 32)
        starts.append(o2v(off + 8 * i) + w)
    starts = sorted(set(x - x % 2 for x in starts))
    return starts


def main() -> int:
    import argparse
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", type=Path, default=Path(PATH),
                    help=f"要分析的 ELF（默认 {PATH}）")
    ap.add_argument("--target", type=lambda x: int(x, 0), action="append",
                    help="额外关注的地址，可重复")
    args = ap.parse_args()
    if not args.file.exists():
        ap.error(f"文件不存在：{args.file}\n先用 教程/01-读取固件 把 libObj.so 拉到本地")
    d = args.file.read_bytes()
    if args.target:
        for t in args.target:
            TARGETS.setdefault(t, "自定义目标")
    starts = exidx_ranges(d)
    def owner(a):
        i = bisect.bisect_right(starts, a) - 1
        return starts[i], (starts[i + 1] if i + 1 < len(starts) else a)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True
    md.skipdata = True
    calls = {t: [] for t in TARGETS}
    literals = {t: [] for t in TARGETS}
    for ins in md.disasm(d, 0):
        if ins.address > 0x11a6000:
            break
        if ins.id in (ARM_INS_BL, ARM_INS_BLX, ARM_INS_B):
            for op in ins.operands:
                if op.type == 2 and op.imm in calls:  # ARM_OP_IMM
                    calls[op.imm].append(ins.address)
        if ins.mnemonic.startswith("ldr") and "pc" in ins.op_str:
            for op in ins.operands:
                if op.type == 3:  # MEM
                    base = op.mem.base
                    from capstone.arm import ARM_REG_PC
                    if base == ARM_REG_PC:
                        pool = (ins.address + 4) - ((ins.address + 4) % 4) + op.mem.disp
                        if 0 <= pool <= len(d) - 4:
                            v = struct.unpack_from("<I", d, pool)[0]
                            if v in literals:
                                literals[v].append((ins.address, pool))
    for t, name in TARGETS.items():
        print(f"=== 0x{t:x} {name}")
        print(f"    调用点 {len(calls[t])}: {[hex(a) for a in calls[t][:10]]}")
        for a in calls[t][:6]:
            s, e = owner(a)
            print(f"      0x{a:x} → 函数 0x{s:x}..0x{e:x}")
        print(f"    字面量引用 {len(literals[t])}: {[(hex(a), hex(p)) for a, p in literals[t][:10]]}")
        for a, p in literals[t][:6]:
            s, e = owner(a)
            print(f"      pool 0x{p:x} 被 0x{a:x} 引用 → 函数 0x{s:x}..0x{e:x}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
