"""在 libObj.so 里找字符串的引用点（ADR / LDR literal 两种寻址）。"""
import sys, struct, pathlib
sys.path.insert(0, ".")
from fwlab.arm import Elf
from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN

PATH = r"logs/watch/usr_lib_libObj.so"
DEFAULT_TARGETS = {
    0xfbb117: "NID_END_EXPOSURE_NOTIFY",
    0xf370ab: "TYPE_CAP_NOTIFY",
    0xfd3043: "MID_ACQUIRE_RELEASE_RIGHT",
    0xd50e24: "ExecCommandSetShutterMute",
    0xf3bff0: "SeqEEStart",
}
import argparse
import re

_ap = argparse.ArgumentParser(description=__doc__,
                             formatter_class=argparse.RawDescriptionHelpFormatter)
_ap.add_argument("--file", type=pathlib.Path, default=pathlib.Path(PATH),
                 help=f"要分析的 ELF（默认 {PATH}）")
_args = _ap.parse_args()
if not _args.file.exists():
    _ap.error(f"文件不存在：{_args.file}\n先用 教程/01-读取固件 把 libObj.so 拉到本地")

TARGETS = dict(DEFAULT_TARGETS)
# 附加：所有含 END_EXPOSURE / CAP_NOTIFY 的字符串地址
data = _args.file.read_bytes()
for m in re.finditer(rb"(NID_[A-Z_]*END_EXPOSURE[A-Z_]*|TYPE_CAP_NOTIFY|MID_[A-Z_]*END_EXPOSURE[A-Z_]*)", data):
    TARGETS.setdefault(m.start(), m.group().decode())

e = Elf(_args.file)
text = [s for s in e.sections if s["name"] == ".text"][0]
blob = data[text["off"]:text["off"] + text["size"]]
base = text["addr"]

md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
md.skipdata = True
hits = []
for ins in md.disasm(blob, base):
    mn = ins.mnemonic
    try:
        if mn.startswith("adr") and len(ins.operands) == 2 and ins.operands[1].type == 2:
            tgt = ins.operands[1].imm
            if tgt in TARGETS:
                hits.append((ins.address, TARGETS[tgt], "adr", ins.op_str))
        elif mn.startswith("add") and len(ins.operands) >= 3 and "pc" in ins.op_str:
            ops = ins.op_str.split(", ")
            if len(ops) >= 3 and ops[1] == "pc":
                imm = int(ops[2].lstrip("#"), 0)
                tgt = (ins.address + 4) + imm
                if tgt in TARGETS:
                    hits.append((ins.address, TARGETS[tgt], "add-pc", ins.op_str))
        elif mn.startswith("ldr") and "[pc" in ins.op_str:
            imm = int(ins.op_str.split("#")[1].split("]")[0], 0)
            lit = (ins.address + 4 - ((ins.address + 4) % 4)) + imm
            voff = lit - base
            if 0 <= voff < len(blob) - 4:
                v = struct.unpack_from("<I", blob, voff)[0]
                if v in TARGETS:
                    hits.append((ins.address, TARGETS[v], "ldr-lit", ins.op_str))
    except Exception:
        pass

print("TARGETS", len(TARGETS), "命中", len(hits))
for a, name, kind, op in hits:
    print(f"  0x{a:06x}  {kind:8s} {name:28s} {op}")
