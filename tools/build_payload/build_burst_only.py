#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""连拍"每帧响一次"载荷构建器（只做连拍，不含单拍钩子）。

## 设计要点
钩点   libObj fileVA 0xA31226（CP 收包循环 FUN_00A311E0 内部，类型分发之前）
       原始 4 字节 = 7c 69 23 78 = `ldr r4,[r7,#0x14]` + `ldrb r3,[r4]`
       进入时 msg 指针 = *(u32*)(r7 + 0x14)（r7 是函数帧指针，全程有效）
载荷   libObj fileVA 0x1948D8..0x194A20（328 字节，.ARM.exidx 认证的独立函数边界）

判断    msg != NULL && *(u16*)(msg+2) == 0x1001   → 发 ObjSystemSound
        0x1001 = START_EXPOSURE，实测单拍 ×1 / 连拍 8 张 ×8

## 约束
1. 单块连续函数，**不跨段 bl**（除了 blx PLT 与 bl Get(7)，两者都是"会正常返回"的调用，
   与单拍载荷完全同构）
2. **绝不写任何内存地址**：全载荷零 str/strh/strb，只有 push/pop 用 SP 相对寻址
3. 长度 ≤ 328 字节
4. 重放原始字节走"文件里直接拷"，不用 keystone 的 .inst.w（keystone 会静默丢弃）
5. 所有 b/b.w 偏移必须 ±16MB 内

用法：
    python tools/build_burst_only.py                 # 构建 + 自检 + 仿真
    python tools/build_burst_only.py --nid 0x1002    # 换触发 NID
    python tools/build_burst_only.py --sound 0x04
"""
from __future__ import annotations
import argparse, hashlib, json, pathlib, sys

HERE = pathlib.Path(__file__).resolve().parent
ROOT = HERE.parent.parent
sys.path.insert(0, str(HERE))

ORIG = ROOT / "logs" / "watch" / "usr_lib_libObj.so"   # 默认；可用 --so 覆盖
OUTDIR = pathlib.Path(__file__).resolve().parent / "out"

# ---------------------------------------------------------------- 常量
HOOK = 0xA31226          # 钩点（CP 收包循环，类型分发之前）
RESUME = HOOK + 4        # 重放后回跳
SLOT = 0x1948D8          # 载荷槽（死区函数起点）
LIMIT = 0x194A20         # 死区上界（下一个函数起点）
RUNTIME_BASE = 0x05DCA000

# 单拍载荷已验证的 PLT（本构建器用同一组）
OBJMSG_CTOR = 0x0FF7B8     # MWF::ObjMsg::ObjMsg(unsigned,unsigned)
PARAM_CTOR = 0x102B34      # MWF::ParamStd_Template<unsigned,(MWF::Param::Type)8>::ctor
ADDPARAM = 0x1027E4        # MWF::ObjMsg::AddParam(unsigned, Param const*)
ISSUE_ASYNC = 0x0FD2A0     # MWF::ObjIf::IssueCommandAsync(void*, ObjMsg*)
GET_COMP = 0x34D840        # 内部函数，Thumb，同模块可直接 bl

CATE = 0x3410
MSGID = 0x1120
PID_SOUND = 0x1000
PID_1 = 0x1001
PID_2 = 0x1002
COMP_SOUND = 7


def pltset(reg: str, off: int) -> list[str]:
    """reg = BASE + off（BASE 在 r4）"""
    return [f"movw {reg}, #{off & 0xFFFF:#06x}",
            f"movt {reg}, #{(off >> 16) & 0xFFFF:#06x}",
            f"add {reg}, {reg}, r4"]


def build_code(nid: int, sound: int, bias: int, p1: int = 1, p2: int = 0,
               dryrun: bool = False, check_type: bool = True,
               check_null: bool = True) -> list[str]:
    a: list[str] = []

    # ---- 序：保存全部会被破坏的寄存器（与单拍载荷同构）----
    a += ["push.w {r0-r3, r4-r8, r12, lr}",
          "sub.w sp, sp, #0x30"]

    # ---- 取 msg 指针并过滤 ----
    # r7 此时尚未被破坏（刚 push 过，值还是调用者的帧指针）
    # CpMsg 布局（21 个构造器 + 4 个 handler 双向确证；本轮另有 0xA32488 发送方复证）：
    #   +0 u8 type | +1 u8 unk | +2 u16 nid | +4 u32 unk2 | +8 payload
    a += ["ldr.w r8, [r7, #0x14]",        # r8 = msg
          ]
    if check_null:
        a += ["cmp r8, #0",
              "beq done"]                 # NULL 保护
    a += ["mov r6, r8"]                   # ldrb/ldrh 的基址必须是 r0-r7
    if check_type:
        a += ["ldrb r3, [r6]",            # r3 = type
              "cmp r3, #4",               # 实测 0x1000..0x1007 全部是 type==4
              "bne done"]
    a += ["ldrh r6, [r6, #2]",            # r6 = nid
          f"movw r3, #{nid & 0xFFFF:#06x}",   # MOVW 会把高 16 位清零，无需 movt
          "cmp r6, r3",
          "bne done"]

    # ---- 算模块基址：r4 = BASE ----
    a += ["adr r4, #0",
          f"movw r5, #{bias & 0xFFFF:#06x}",
          f"movt r5, #{(bias >> 16) & 0xFFFF:#06x}",
          "sub.w r4, r4, r5"]

    # ---- 帧布局：sp+0x00=p2  sp+0x08=p1  sp+0x10=p0  sp+0x18=ObjMsg ----
    # ObjMsg(0x3410, 0x1120)
    a += ["add r0, sp, #0x18",
          f"movw r1, #{CATE:#06x}",
          "movt r1, #0",
          f"movw r2, #{MSGID:#06x}",
          "movt r2, #0"]
    a += pltset("r6", OBJMSG_CTOR)
    a += ["blx r6"]

    # 3× ParamStd<uint,Type8>
    a += ["add r0, sp, #0x10", f"movs r1, #{sound:#04x}"]
    a += pltset("r6", PARAM_CTOR) + ["blx r6"]
    a += ["add r0, sp, #0x08", f"movs r1, #{p1:#04x}"]
    a += pltset("r6", PARAM_CTOR) + ["blx r6"]
    a += ["add r0, sp, #0x00", f"movs r1, #{p2:#04x}"]
    a += pltset("r6", PARAM_CTOR) + ["blx r6"]

    # 3× AddParam(pid, &param)
    for pid, frame in ((PID_SOUND, 0x10), (PID_1, 0x08), (PID_2, 0x00)):
        a += ["add r0, sp, #0x18", f"movw r1, #{pid:#06x}",
              ("add r2, sp, #0x00" if frame == 0 else f"add r2, sp, #{frame:#04x}")]
        a += pltset("r6", ADDPARAM) + ["blx r6"]

    # Get(7) → ObjSystemSound 组件
    a += ["movs r0, #7",
          f"bl #{GET_COMP:#x}",
          "mov r6, r0",
          "cmp r0, #0",
          "beq done"]

    # IssueCommandAsync(comp, &msg)
    a += ["mov r0, r6",
          "add r1, sp, #0x18"]
    if dryrun:
        a += ["nop", "nop"]
    else:
        a += pltset("r12", ISSUE_ASYNC) + ["blx r12"]

    # ---- 收尾 ----
    a += ["done:",
          "add.w sp, sp, #0x30",
          "pop.w {r0-r3, r4-r8, r12, lr}"]
    return a


def build(nid: int, sound: int, p1: int, p2: int, dryrun: bool,
          check_type: bool = True, check_null: bool = True,
          orig_path: pathlib.Path | None = None) -> dict:
    import keystone as K
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    ks = K.Ks(K.KS_ARCH_ARM, K.KS_MODE_THUMB)
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)

    orig = (orig_path or ORIG).read_bytes()

    def assemble(bias: int) -> bytes:
        src = "\n".join(build_code(nid, sound, bias, p1, p2, dryrun,
                                    check_type, check_null))
        enc, _ = ks.asm(src, SLOT)
        if enc is None:
            raise SystemExit("keystone 汇编失败")
        return bytes(enc)

    e1 = assemble(0)
    adr = next((i for i in md.disasm(e1, SLOT) if i.mnemonic == "adr"), None)
    if adr is None:
        raise SystemExit("载荷里找不到 adr")
    bias = (adr.address + 4) & ~3
    e2 = assemble(bias)
    if len(e2) != len(e1):
        raise SystemExit(f"bias 迭代后长度不稳定：{len(e1)} vs {len(e2)}")
    # 二次核对：bias 是否收敛
    adr2 = next((i for i in md.disasm(e2, SLOT) if i.mnemonic == "adr"), None)
    if ((adr2.address + 4) & ~3) != bias:
        raise SystemExit("bias 未收敛")
    code = e2

    replay = orig[HOOK:HOOK + 4]                       # ★ 直接拷原文，不用 .inst.w
    tail_va = SLOT + len(code) + len(replay)
    tail, _ = ks.asm(f"b.w #{RESUME:#x}", tail_va)
    br, _ = ks.asm(f"b.w #{SLOT:#x}", HOOK)
    if tail is None or br is None or len(tail) != 4 or len(br) != 4:
        raise SystemExit("b.w 汇编失败或长度不为 4")

    body = code + replay + bytes(tail) + b"\0" * 8
    end = SLOT + len(body)
    if end > LIMIT:
        raise SystemExit(f"载荷越界：0x{end:x} > 0x{LIMIT:x}（超 {end - LIMIT} 字节）")

    out = bytearray(orig)
    out[SLOT:end] = body
    out[HOOK:HOOK + 4] = bytes(br)

    return dict(nid=nid, sound=sound, p1=p1, p2=p2, dryrun=dryrun,
                check_type=check_type, check_null=check_null,
                code=code, replay=replay, tail=bytes(tail), hook=bytes(br),
                body=body, out=bytes(out), orig=orig,
                bias=bias, code_len=len(code), total=len(body), end=end,
                hook_va=HOOK, slot_va=SLOT, resume_va=RESUME)


def disasm_listing(b: dict) -> list[str]:
    from capstone import Cs, CS_ARCH_ARM, CS_MODE_THUMB, CS_MODE_LITTLE_ENDIAN
    md = Cs(CS_ARCH_ARM, CS_MODE_THUMB | CS_MODE_LITTLE_ENDIAN)
    lines = []
    lines.append("; ===== 钩点子程序 0x%08x (fileVA) 原始 4 字节 %s ====="
                 % (b["hook_va"], b["replay"].hex()))
    lines.append("; 钩子机器码 %s   = b.w 0x%08x" % (b["hook"].hex(), b["slot_va"]))
    lines.append("; 运行期 钩子=0x%08x 载荷=0x%08x"
                 % (RUNTIME_BASE + b["hook_va"], RUNTIME_BASE + b["slot_va"]))
    lines.append("")
    lines.append("; ===== 载荷正文（%d 字节）=====" % b["code_len"])
    for i in md.disasm(b["code"], b["slot_va"]):
        lines.append("  %08x  %-10s %-9s %s" % (i.address, i.bytes.hex(),
                                                i.mnemonic, i.op_str))
    lines.append("")
    lines.append("; ===== 重放原始 4 字节（从 .so 原文直接拷贝）=====")
    rv = b["slot_va"] + b["code_len"]
    for i in md.disasm(b["replay"], rv):
        lines.append("  %08x  %-10s %-9s %s   ; 原文重放" % (i.address, i.bytes.hex(),
                                                          i.mnemonic, i.op_str))
    lines.append("")
    lines.append("; ===== 回跳 =====")
    for i in md.disasm(b["tail"], rv + 4):
        lines.append("  %08x  %-10s %-9s %s   ; → 0x%08x"
                     % (i.address, i.bytes.hex(), i.mnemonic, i.op_str, b["resume_va"]))
    return lines


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--nid", type=lambda x: int(x, 0), default=0x1001,
                    help="触发 NID（默认 0x1001 = START_EXPOSURE，逐帧一次）")
    ap.add_argument("--sound", type=lambda x: int(x, 0), default=0x04)
    ap.add_argument("--p1", type=lambda x: int(x, 0), default=1)
    ap.add_argument("--p2", type=lambda x: int(x, 0), default=0)
    ap.add_argument("--dryrun", action="store_true", help="不真发 IssueCommandAsync")
    ap.add_argument("--no-type-check", dest="type_check", action="store_false",
                    help="关闭 type==4 校验（只在确认 NID 跨 type 复用时用）")
    ap.add_argument("--no-null-check", dest="null_check", action="store_false",
                    help="关闭 msg!=NULL 保护")
    ap.add_argument("--no-emu", action="store_true")
    ap.add_argument("--so", type=pathlib.Path,
                    help=f"原厂 libObj.so 路径（默认 {ORIG}）")
    a = ap.parse_args()

    orig_path = a.so or ORIG
    if not orig_path.exists():
        rel = orig_path.relative_to(ROOT) if orig_path.is_absolute() and str(orig_path).startswith(str(ROOT)) else orig_path
        print(f"找不到原厂 libObj.so：{rel}")
        print()
        print("这个文件从你自己相机的备份里来：")
        print("  python tools/camera/a7r3a_backup.py")
        print("  cp backup/<时间戳>/usr_lib_libObj.so logs/watch/usr_lib_libObj.so")
        print()
        print("或者用 --so 直接指定：")
        print("  python tools/build_payload/build_burst_only.py --so <你的 libObj.so>")
        return 2

    OUTDIR.mkdir(parents=True, exist_ok=True)

    b = build(a.nid, a.sound, a.p1, a.p2, a.dryrun, a.type_check, a.null_check,
              orig_path)

    tag = (f"nid{b['nid']:04x}s{b['sound']:02x}"
           + ("" if a.type_check else "_notype")
           + ("_dry" if a.dryrun else ""))
    stem = f"libObj.burst_{tag}"
    so_path = OUTDIR / f"{stem}.so"
    so_path.write_bytes(b["out"])
    b["out_path"] = str(so_path)

    listing = disasm_listing(b)
    lst_path = OUTDIR / f"{stem}.asm.txt"
    lst_path.write_text("\n".join(listing), encoding="utf-8")

    # ---- 上机用小文件（busybox dd 直接吃）----
    bin_dir = OUTDIR / f"{stem}.bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "pay.bin").write_bytes(b["body"])
    (bin_dir / "hok.bin").write_bytes(b["hook"])
    (bin_dir / "orig_hook.bin").write_bytes(b["replay"])
    (bin_dir / "orig_pay.bin").write_bytes(b["orig"][SLOT:LIMIT])

    # 差异块（注入器要按 1024 对齐块刷写）
    orig, out = b["orig"], b["out"]
    diffs = sorted({i - i % 1024 for i in range(len(orig)) if orig[i] != out[i]})

    man = dict(
        generator="tools/build_burst_only.py",
        scheme="burst-only (CP recv loop NID filter)",
        orig_path=str(ORIG),
        orig_size=len(orig),
        orig_sha256=hashlib.sha256(orig).hexdigest(),
        out_path=str(so_path),
        out_size=len(out),
        out_sha256=hashlib.sha256(out).hexdigest(),
        libobj_runtime_base=RUNTIME_BASE,
        hook=dict(fileVA=b["hook_va"], runtime=RUNTIME_BASE + b["hook_va"],
                  orig_hex=b["replay"].hex(), patch_hex=b["hook"].hex(),
                  target=b["slot_va"], back=b["resume_va"],
                  function="FUN_00A311E0 CP recv loop", filter_nid=b["nid"],
                  check_type=b["check_type"], check_null=b["check_null"]),
        payload=dict(fileVA=b["slot_va"], runtime=RUNTIME_BASE + b["slot_va"],
                     end_fileVA=b["end"], length=b["total"], code_len=b["code_len"],
                     limit=LIMIT, free=LIMIT - b["end"], bias=b["bias"],
                     replay_hex=b["replay"].hex(), tail_hex=b["tail"].hex(),
                     body_hex=b["body"].hex()),
        sound=dict(id=b["sound"], p1000=b["sound"], p1001=b["p1"], p1002=b["p2"],
                   cate=CATE, msgid=MSGID, comp=COMP_SOUND),
        diff_blocks_1k=[hex(x) for x in diffs],
        nid=b["nid"],
        files=dict(pay_bin=str(bin_dir / "pay.bin"),
                   hook_bin=str(bin_dir / "hok.bin"),
                   restore_hook_bin=str(bin_dir / "orig_hook.bin"),
                   restore_payload_bin=str(bin_dir / "orig_pay.bin")),
        oncam=dict(
            pay_dd=(f"busybox dd if=pay.bin of=/proc/155/mem bs=1 "
                    f"seek={RUNTIME_BASE + b['slot_va']} count={b['total']}"),
            hook_dd=(f"busybox dd if=hok.bin of=/proc/155/mem bs=1 "
                     f"seek={RUNTIME_BASE + b['hook_va']} count=4"),
            rollback_hook_dd=(f"busybox dd if=orig_hook.bin of=/proc/155/mem bs=1 "
                              f"seek={RUNTIME_BASE + b['hook_va']} count=4"),
            verify_hook_dd=(f"busybox dd if=/proc/155/mem bs=1 "
                            f"skip={RUNTIME_BASE + b['hook_va']} count=4"),
            verify_payload_dd=(f"busybox dd if=/proc/155/mem bs=1 "
                               f"skip={RUNTIME_BASE + b['slot_va']} "
                               f"count={b['total']}"),
        ),
    )
    man_path = OUTDIR / f"{stem}.json"
    man_path.write_text(json.dumps(man, indent=2, ensure_ascii=False), encoding="utf-8")

    print("=" * 84)
    print("连拍载荷构建结果")
    print("=" * 84)
    print(f"  钩点            0x{b['hook_va']:08x}  (运行期 0x{RUNTIME_BASE + b['hook_va']:08x})")
    print(f"  钩点原始 4 字节  {b['replay'].hex()}")
    print(f"  钩子机器码       {b['hook'].hex()}   = b.w 0x{b['slot_va']:08x}")
    print(f"  载荷            0x{b['slot_va']:08x}..0x{b['end']:08x}"
          f"  正文 {b['code_len']}B + 重放 4B + 回跳 4B + pad = {b['total']}B")
    print(f"  死区容量        {LIMIT - SLOT}B，占用 {b['total']}B，剩余 {LIMIT - b['end']}B")
    print(f"  过滤条件        type==4" + ("" if b["check_type"] else "（已关闭）")
          + f" && nid==0x{b['nid']:04x}"
          + (" && msg!=NULL" if b["check_null"] else ""))
    print(f"  音效            0x{b['sound']:02x}  (cate 0x{CATE:04x} msgid 0x{MSGID:04x} comp {COMP_SOUND})")
    print(f"  adr 偏置        0x{b['bias']:x}")
    print(f"  差异块(1K)      {[hex(x) for x in diffs]}")
    print(f"  输出            {so_path}")
    print(f"  反汇编          {lst_path}")
    print(f"  清单            {man_path}")
    print(f"  上机 bin 目录   {bin_dir}")
    print(f"  SHA256          {man['out_sha256']}")
    rc = 0
    if not a.no_emu:
        print()
        import emu_burst
        rc = 0 if emu_burst.run_all(b) else 1
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
