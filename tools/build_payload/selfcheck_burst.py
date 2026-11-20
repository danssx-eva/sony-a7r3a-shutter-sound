#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""连拍补丁的独立自检（可反复跑，不依赖构建器内部状态）。

它只读两个文件：原厂 libObj 与构建出来的 .so，逐项核对：
  A. 差异面：.so 相对原厂只应改「钩点 4 字节 + 载荷死区 [+ 补零]」
  B. 载荷尺寸 ≤ 328 字节，且不越出 .ARM.exidx 认证的函数边界
  C. 载荷里所有 32 位 b/b.w/bl/blx 的偏移都在 ±16MB 内，且目标语义正确
  D. 载荷里没有任何写内存指令（str/strh/strb/strd/stm/...），push/pop 除外
  E. 重放 4 字节 == 原厂在钩点的原始字节
  F. 回跳 b.w 的目标 == 钩点 + 4
  G. 钩点机器码 == b.w 载荷槽
  H. 钩点处是 2 字节对齐的完整指令边界；无跨函数跳入
  I. ELF 结构完整（段/节未被破坏）
  J. 可选：跑一遍 Unicorn 端到端仿真（--emu）

用法：
    python tools/selfcheck_burst.py work/re-burst2/libObj.burst_nid1001s04.json
    python tools/selfcheck_burst.py --latest
    python tools/selfcheck_burst.py --latest --emu
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, struct, sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

ORIG = ROOT / "logs" / "watch" / "usr_lib_libObj.so"   # 默认；可用 --so 覆盖
OUTDIR = pathlib.Path(__file__).resolve().parent / "out"

STORE_MN = {"str", "strh", "strb", "strd", "strt", "stm", "stmdb", "stmia",
            "str.w", "strh.w", "strb.w", "stm.w", "vst1.8", "vst1.16",
            "vst1.32", "vst1.64"}


class Chk:
    def __init__(self):
        self.items = []

    def add(self, name, ok, detail=""):
        self.items.append((name, bool(ok), detail))

    @property
    def ok(self):
        return all(i[1] for i in self.items)

    def report(self):
        w = max((len(n) for n, _, _ in self.items), default=10)
        for n, ok, d in self.items:
            print(f"  [{'PASS' if ok else 'FAIL'}] {n:<{w}}  {d}")
        npass = sum(1 for i in self.items if i[1])
        print(f"\n  合计 {len(self.items)} 项，通过 {npass}，失败 {len(self.items) - npass}")


def se(v, bits):
    return v - (1 << bits) if v & (1 << (bits - 1)) else v


def thumb_branch_target(va: int, b: bytes):
    """独立实现的 Thumb-2 分支解码（与 armlib 交叉验证用）。

    I1/I2 = NOT(J1/J2 XOR S)；BLX 基准 = Align(va+4,4)。
    """
    if len(b) < 4:
        return None
    hw1, hw2 = struct.unpack_from("<HH", b, 0)
    if (hw1 & 0xF800) != 0xF000:
        return None
    b15, b14, b12 = (hw2 >> 15) & 1, (hw2 >> 14) & 1, (hw2 >> 12) & 1
    if b15 and b14 and b12:
        kind, base = "bl", va + 4
    elif b15 and b14 and not b12:
        kind, base = "blx", (va + 4) & ~3
    elif b15 and not b14 and b12:
        kind, base = "b.w", va + 4
    else:
        return None
    S = (hw1 >> 10) & 1
    I1 = 1 - (((hw2 >> 13) & 1) ^ S)
    I2 = 1 - (((hw2 >> 11) & 1) ^ S)
    imm = ((S << 24) | (I1 << 23) | (I2 << 22) |
           ((hw1 & 0x3FF) << 12) | ((hw2 & 0x7FF) << 1))
    if S:
        imm -= 1 << 25
    return kind, (base + imm) & 0xFFFFFFFF


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest", nargs="?")
    ap.add_argument("--latest", action="store_true")
    ap.add_argument("--emu", action="store_true", help="追加 Unicorn 端到端仿真")
    ap.add_argument("--so", type=pathlib.Path,
                    help=f"原厂 libObj.so 路径（默认 {ORIG}）")
    a = ap.parse_args()

    orig_path = a.so or ORIG
    if not orig_path.exists():
        rel = orig_path.relative_to(ROOT) if orig_path.is_absolute() and str(orig_path).startswith(str(ROOT)) else orig_path
        print(f"找不到原厂 libObj.so：{rel}")
        print("  先用 tools/camera/a7r3a_backup.py 备份，或用 --so 指定")
        return 2
    OUTDIR.mkdir(parents=True, exist_ok=True)

    man_path = pathlib.Path(a.manifest) if a.manifest else None
    if a.latest or man_path is None:
        cands = sorted(OUTDIR.glob("libObj.burst_*.json"),
                       key=lambda p: p.stat().st_mtime)
        if not cands:
            raise SystemExit("找不到任何 libObj.burst_*.json，先跑 build_burst_only.py")
        man_path = cands[-1]
    man = json.loads(man_path.read_text(encoding="utf-8"))
    so_path = pathlib.Path(man["out_path"])
    so = so_path.read_bytes()
    orig = orig_path.read_bytes()

    HOOK = man["hook"]["fileVA"]
    SLOT = man["payload"]["fileVA"]
    CODE_LEN = man["payload"]["code_len"]
    REPLAY = bytes.fromhex(man["hook"]["orig_hex"])
    PATCH = bytes.fromhex(man["hook"]["patch_hex"])
    TAIL = bytes.fromhex(man["payload"]["tail_hex"])
    LEN = man["payload"]["length"]
    RESUME = man["hook"]["back"]
    LIMIT = man["payload"]["limit"]

    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    md.detail = True

    print("=" * 96)
    print(f"自检目标  {so_path.name}")
    print(f"清单      {man_path}")
    print("=" * 96)
    c = Chk()

    # ---------- A. 差异面 ----------
    if len(so) != len(orig):
        c.add("A1 文件大小不变", False, f"{len(orig)} -> {len(so)}")
    else:
        c.add("A1 文件大小不变", True, f"{len(so)} 字节")
        diffs = [i for i in range(len(orig)) if orig[i] != so[i]]
        seg_hook = [i for i in diffs if HOOK <= i < HOOK + 4]
        seg_pay = [i for i in diffs if SLOT <= i < SLOT + LEN]
        other = [i for i in diffs if i not in set(seg_hook) | set(seg_pay)]
        c.add("A2 只有钩点 4 字节被改", len(seg_hook) == 4, f"{len(seg_hook)} 字节")
        c.add("A3 只有载荷槽被改", not other,
              f"越界改动 {len(other)} 字节 {[hex(x) for x in other[:8]]}")

    # ---------- B. 尺寸 ----------
    c.add("B1 载荷总长 ≤ 328", LEN <= 328, f"{LEN} 字节（余 {328 - LEN}）")
    c.add("B2 载荷不越死区上界", SLOT + LEN <= LIMIT,
          f"0x{SLOT + LEN:08x} ≤ 0x{LIMIT:08x}")

    # ---------- C. 分支偏移 ----------
    code = orig[SLOT:SLOT + CODE_LEN]
    # 注意：用构建后的 .so 取载荷（含补零前的正文），正文在 .so 里同址
    code = so[SLOT:SLOT + CODE_LEN]
    bad_rng, brs = [], []
    for i in md.disasm(code, SLOT):
        if i.size != 4:
            continue
        r = thumb_branch_target(i.address, i.bytes)
        if not r:
            continue
        kind, tgt = r
        brs.append((i.address, kind, tgt, i.op_str))
        # 目标必须在模块 VA 空间内（±16MB 由编码本身保证；这里校验落点合理）
        if not (0 <= tgt < 0x2000000):
            bad_rng.append((i.address, kind, tgt))
    c.add("C1 载荷内 32 位分支落点都在模块地址空间内",
          not bad_rng, f"{len(brs)} 条分支；异常 {bad_rng}")
    # 关键分支语义
    bl_targets = {t for _, k, t, _ in brs if k == "bl"}
    c.add("C2 Get(7) 的 bl 目标 = 0x34D840", 0x34D840 in bl_targets,
          f"bl 目标 = {sorted(hex(x) for x in bl_targets)}")

    # C3：PLT 是 ARM 代码，载荷用 `movw/movt 常量 + add 模块基址 + blx 寄存器` 调它，
    #     所以**不会**出现立即数形式的 blx。改为校验 movw/movt 物化出的常量集合。
    def materialized_consts(blob, base):
        out = {}
        last_movw = {}
        for ins in md.disasm(blob, base):
            if ins.mnemonic == "movw":
                try:
                    rd = ins.op_str.split(",")[0].strip()
                    v = int(ins.op_str.split("#")[1], 0)
                except Exception:
                    continue
                last_movw[rd] = (v, ins.address)
                continue
            if ins.mnemonic == "movt":
                try:
                    rd = ins.op_str.split(",")[0].strip()
                    hi = int(ins.op_str.split("#")[1], 0)
                except Exception:
                    continue
                if rd in last_movw:
                    lo, addr = last_movw.pop(rd)
                    out[(hi << 16) | lo] = (addr, rd)
        return out

    consts = materialized_consts(code, SLOT)
    need = {0x0FF7B8: "ObjMsg ctor", 0x102B34: "ParamStd ctor",
            0x1027E4: "AddParam", 0x0FD2A0: "IssueCommandAsync"}
    missing = [f"0x{k:06X}({v})" for k, v in need.items() if k not in consts]
    c.add("C3 四个 PLT 偏移都已 movw/movt 物化",
          not missing, f"缺少 {missing}" if missing else
          " ".join(f"{v}=0x{k:06X}" for k, v in need.items()))
    # 每个 PLT 常量后面必须紧跟 add rX, r4（加模块基址）
    add_ok = True
    add_detail = []
    for off, nm in need.items():
        addr, rd = consts[off]
        seq = [i for i in md.disasm(so[addr:addr + 16], addr)]
        found = any(i.mnemonic == "add" and i.op_str.replace(" ", "") ==
                    f"{rd},r4" for i in seq[:4])
        add_detail.append(f"{nm}:{'OK' if found else '缺 add'}")
        add_ok = add_ok and found
    c.add("C4 每个 PLT 常量都紧跟 add rX,r4（PIC 基址相加）", add_ok,
          " ".join(add_detail))
    # 分支偏移 |delta| < 16MB
    worst = max([abs(tgt - (addr + 4)) for addr, kind, tgt, _ in brs] or [0])
    c.add("C5 所有分支 |delta| < 16MB", worst < 16 * 1024 * 1024,
          f"最大 |delta| = 0x{worst:x}")
    # adr 偏置自洽：bias == Align(adr地址+4, 4)，且 movw/movt 物化的就是它
    adr_ins = next((i for i in md.disasm(code, SLOT) if i.mnemonic == "adr"), None)
    bias_want = ((adr_ins.address + 4) & ~3) if adr_ins else None
    man_bias = man["payload"]["bias"]
    c.add("C6 adr 偏置与清单一致且自洽",
          adr_ins is not None and man_bias == bias_want and man_bias in consts,
          f"adr@0x{adr_ins.address:08x} bias=0x{man_bias:x} 期望 0x{bias_want:x}")

    # ---------- D. 无写内存 ----------
    stores = []
    for i in md.disasm(code, SLOT):
        m = i.mnemonic
        if m in STORE_MN or m.startswith("str") or m.startswith("stm") \
                or m.startswith("vst"):
            stores.append((i.address, m, i.op_str))
    c.add("D1 载荷里没有任何 store 指令", not stores,
          "零 store（只有 push/pop 用 SP 相对寻址）" if not stores
          else f"{len(stores)} 条: {stores[:6]}")
    # 交叉：载荷里不得出现绝对地址立即数形式的写目标
    c.add("D2 载荷里没有出现已知的可写段地址常量",
          not any(x in code for x in
                  (struct.pack("<I", 0x070A6000), struct.pack("<I", 0x0405EFE8),
                   struct.pack("<I", 0x01223EA8))),
          "无 libObj .bss / libosal .bss / libObj .data 常量")

    # ---------- E/F/G. 重放与回跳 ----------
    replay_in_so = so[SLOT + CODE_LEN:SLOT + CODE_LEN + 4]
    c.add("E1 重放字节 == 原厂钩点原始 4 字节", replay_in_so == REPLAY,
          f".so 内 {replay_in_so.hex()} vs 原厂 {REPLAY.hex()}")
    tail_in_so = so[SLOT + CODE_LEN + 4:SLOT + CODE_LEN + 8]
    r = thumb_branch_target(SLOT + CODE_LEN + 4, tail_in_so)
    c.add("F1 回跳 b.w 目标 == 钩点+4", r and r[0] == "b.w" and r[1] == RESUME,
          f"解码出 {r}，期望 ('b.w', 0x{RESUME:08x})")
    hook_in_so = so[HOOK:HOOK + 4]
    r2 = thumb_branch_target(HOOK, hook_in_so)
    c.add("G1 钩点机器码 == b.w 载荷槽", hook_in_so == PATCH and r2 and r2[1] == SLOT,
          f"{hook_in_so.hex()} -> {r2}")

    # ---------- H. 钩点位置合法性 ----------
    base_bytes = orig[HOOK:HOOK + 4]
    ins = list(md.disasm(base_bytes, HOOK))
    c.add("H1 钩点 2 字节对齐", HOOK % 2 == 0, f"0x{HOOK:08x} % 2 = {HOOK % 2}")
    c.add("H2 覆盖的 4 字节恰好是 2 条 2 字节指令（无 32 位指令被切一半）",
          len(ins) == 2 and all(i.size == 2 for i in ins),
          " + ".join(f"{i.mnemonic} {i.op_str}" for i in ins))
    # .ARM.exidx 函数边界
    try:
        from armlib import Elf, func_of
        e = Elf()
        fs = e.function_starts()
        f_hook, n_hook = func_of(fs, HOOK)
        f_slot, n_slot = func_of(fs, SLOT)
        c.add("H3 载荷槽是 .ARM.exidx 的独立函数起点",
              f_slot == SLOT, f"fn 0x{f_slot:08x}，下一个函数 0x{n_slot:08x}")
        c.add("H4 载荷不越入下一个函数", SLOT + LEN <= (n_slot or 0xFFFFFFFF),
              f"0x{SLOT + LEN:08x} ≤ 0x{n_slot:08x}")
        c.add("H5 钩点落在 CP 收包循环 FUN_00A311E0 内",
              f_hook == 0xA311E0, f"fn 0x{f_hook:08x}（期望 0x00a311e0）")
    except Exception as ex:
        c.add("H3-H5 .ARM.exidx 校验", False, f"异常 {ex}")

    # ---------- I. ELF 完整 ----------
    try:
        from elftools.elf.elffile import ELFFile
        ef = ELFFile(open(so_path, "rb"))
        ok = True
        for s in ef.iter_segments():
            if s["p_type"] == "PT_LOAD" and s["p_offset"] + s["p_filesz"] > len(so):
                ok = False
        c.add("I1 ELF 可解析且所有 PT_LOAD 在文件范围内", ok, "OK" if ok else "段越界")
        names = [s.name for s in ef.iter_sections()]
        c.add("I2 关键节仍在（.text/.rel.dyn/.dynsym）",
              all(n in names for n in (".text", ".rel.dyn", ".dynsym")),
              f"{len(names)} 个节")
    except Exception as ex:
        c.add("I1/I2 ELF 校验", False, f"异常 {ex}")
    c.add("I3 SHA256 与清单一致",
          hashlib.sha256(so).hexdigest() == man["out_sha256"],
          hashlib.sha256(so).hexdigest()[:24] + "…")

    # ---------- 输出 ----------
    c.report()

    # 打印载荷反汇编（人眼复核）
    print()
    print("载荷反汇编（capstone 逐条复核）：")
    for i in md.disasm(code, SLOT):
        print(f"  0x{i.address:08x}  {i.bytes.hex():<10} {i.mnemonic:<9} {i.op_str}")
    print(f"  0x{SLOT + CODE_LEN:08x}  {replay_in_so.hex():<10} （重放原厂 4 字节）")
    for i in md.disasm(tail_in_so, SLOT + CODE_LEN + 4):
        print(f"  0x{i.address:08x}  {i.bytes.hex():<10} {i.mnemonic:<9} {i.op_str}")

    rc = 0 if c.ok else 1
    if a.emu:
        print()
        import emu_burst
        snd = man["sound"]
        b = dict(out_path=str(so_path), code_len=CODE_LEN,
                 nid=man.get("nid", man["hook"].get("filter_nid", 0x1001)),
                 check_type=man["hook"].get("check_type", True),
                 sound=snd["id"], p1=snd["p1001"], p2=snd["p1002"])
        rc = 0 if (c.ok and emu_burst.run_all(b)) else 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
