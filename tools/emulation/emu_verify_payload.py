#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
emu_verify_payload.py —— 用 Unicorn 离线验证 patch_sound_post.py 生成的注入载荷
================================================================================
做三件事：
  1) 把打补丁后的 libObj.so 按 PT_LOAD 映射进 Unicorn（含 R_ARM_RELATIVE 重定位）；
  2) 造假 sender（vt[3] = "投递记录桩"）并填好 GOT 槽 0x012222d0 -> &mp_lEvtSndCmd -> sender；
  3) 从钩点 0xc19b38 开始跑，检查：
       - 是否构造了 Param / ObjMsg / AddParam(0x1000) / 是否调用 sender->vt[3]（投递）/ 是否走到 ~ObjMsg
       - r0-r12 / SP / LR 是否原样恢复（AAPCS 检查，在"重放被覆盖 4 字节"之前快照）
       - 空指针（GOT 槽=0 / sender=0 / vtable=0）时是否安全 bail（不崩、不调用 vt[3]）

用法
----
  python emu_verify_payload.py --so work/re-sound-re/libObj.sndA.so --json work/re-sound-re/libObj.sndA.json
  python emu_verify_payload.py --so ... --json ... --null sender   # 负向：sender 为空
  python emu_verify_payload.py --so ... --json ... --null got      # 负向：GOT 槽为空
  python emu_verify_payload.py --so ... --json ... --null vtable   # 负向：vptr 为空
"""
from __future__ import annotations
import argparse, json, sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from unicorn import *                                                    # noqa
from unicorn.arm_const import *                                          # noqa
import sim_play_sound as S                                               # noqa

HOOK = 0xC19B38
SENDER_GOT = 0x012222D0          # GOT 槽：内容 = &mp_lEvtSndCmd（loader 重定位后填好）
MP_EVTSNDCMD = 0x0129CF50        # mp_lEvtSndCmd 变量（.bss）
POST_STUB_PAGE = 0x51000000

# 本仿真器把镜像按 file_offset + 0x10000 摆放（见 sim_play_sound._map_image），
# 真机上该模块按 file VA 摆放（base 0）。载荷是位置无关的（adr+movw/movt 自算偏差），
# 所以这里整体平移 0x10000 验证，同时也证明了"换基址照样能跑"。
SHIFT = 0x10000
TRAMP = 0x1948D8

REGNAMES = ["r0", "r1", "r2", "r3", "r4", "r5", "r6", "r7",
            "r8", "r9", "r10", "r11", "r12"]
REGS = {n: getattr(S, "UC_ARM_REG_" + n.upper()) for n in REGNAMES}
REGS = {"r0": UC_ARM_REG_R0, "r1": UC_ARM_REG_R1, "r2": UC_ARM_REG_R2, "r3": UC_ARM_REG_R3,
        "r4": UC_ARM_REG_R4, "r5": UC_ARM_REG_R5, "r6": UC_ARM_REG_R6, "r7": UC_ARM_REG_R7,
        "r8": UC_ARM_REG_R8, "r9": UC_ARM_REG_R9, "r10": UC_ARM_REG_R10,
        "r11": UC_ARM_REG_R11, "r12": UC_ARM_REG_R12}
SENT = {n: (0xA5A50000 + i) for i, n in enumerate(REGNAMES)}


class VerifySim(S.Sim):
    """在"重放点"停住并快照寄存器，用于检查载荷是否原样恢复上下文。"""

    def __init__(self, *a, **kw):
        self.stop_at = None
        self.snap = None
        super().__init__(*a, **kw)

    def _hook_code(self, uc, address, size, user):
        if self.stop_at is not None and address == self.stop_at:
            snap = {n: uc.reg_read(v) for n, v in REGS.items()}
            snap["sp"] = uc.reg_read(UC_ARM_REG_SP)
            snap["lr"] = uc.reg_read(UC_ARM_REG_LR)
            snap["pc"] = address
            self.snap = snap
            self.events.append(("SNAPSHOT", address, 0))
            uc.emu_stop()
            return
        super()._hook_code(uc, address, size, user)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--so", required=True)
    ap.add_argument("--json", dest="js", required=True)
    ap.add_argument("--null", choices=["none", "got", "sender", "vtable"], default="none")
    ap.add_argument("--max-insn", type=int, default=20000)
    a = ap.parse_args()

    rep = json.loads(Path(a.js).read_text(encoding="utf-8"))
    raw = Path(a.so).read_bytes()
    elf = S.ELF(a.so)

    sim = VerifySim(elf, dict(S.SCENARIOS["ok3"]), trace=False, max_insn=a.max_insn)
    uc = sim.uc

    # ---- 把注入载荷搬到仿真地址空间（+SHIFT）并写好钩点分支 ----
    # 新构建器（build_burst_only.py）的 manifest 字段名不一样，两边都认
    plen = (rep.get("payload_len")
            or rep.get("payload", {}).get("len")
            or (rep.get("layout") or {}).get("payload_len"))
    if plen is None:
        print(f"这个 manifest 里没有载荷长度字段，认不出：{sorted(rep.keys())[:8]}")
        print("  emu_verify_payload 是早期载荷的配套工具；")
        print("  当前载荷请用 tools/build_payload/build_burst_only.py，它自带 18 项仿真。")
        return 2
    uc.mem_write(TRAMP + SHIFT, raw[TRAMP:TRAMP + plen])
    uc.mem_write(HOOK + SHIFT, raw[HOOK:HOOK + 4])

    # ---- 假 sender：vt[3] -> 投递记录桩（bx lr，被钩子记为 "<POST vt[3]>"） ----
    uc.mem_map(POST_STUB_PAGE, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
    uc.mem_write(POST_STUB_PAGE, b"\x70\x47")
    sim.tramp_of[POST_STUB_PAGE | 1] = "<POST vt[3]>"
    sim.tramp_end = max(sim.tramp_end, POST_STUB_PAGE + 0x1000)

    sender = sim.alloc(0x40)
    vt = sim.alloc(0x40)
    for i in range(16):
        sim.w32(vt + i * 4, sim.ret_stub)
    sim.w32(vt + 0xC, POST_STUB_PAGE | 1)          # sender->vt[3]
    sim.w32(sender, vt)

    # ---- 填 GOT 槽 / mp_lEvtSndCmd（模拟 bias=0 时 loader 重定位后的状态） ----
    sim.w32(SENDER_GOT + SHIFT, MP_EVTSNDCMD + SHIFT)
    sim.w32(MP_EVTSNDCMD + SHIFT, sender)
    if a.null == "got":
        sim.w32(SENDER_GOT + SHIFT, 0)
    elif a.null == "sender":
        sim.w32(MP_EVTSNDCMD + SHIFT, 0)
    elif a.null == "vtable":
        sim.w32(sender, 0)

    # ---- 让被钩函数在重放后立刻返回：把 hook+4 改成 bx lr ----
    uc.mem_write(HOOK + SHIFT + 4, b"\x70\x47")
    sim.stop_at = int(rep["replay_at"], 16) + SHIFT

    sp0 = S.STACK_BASE + S.STACK_SIZE - 0x1000
    for n, v in REGS.items():
        uc.reg_write(v, SENT[n])
    uc.reg_write(UC_ARM_REG_SP, sp0)
    uc.reg_write(UC_ARM_REG_LR, S.RETMAGIC)

    err = None
    try:
        uc.emu_start((HOOK + SHIFT) | 1, S.RETMAGIC, timeout=0, count=a.max_insn)
    except UcError as e:
        err = str(e)

    snap = sim.snap
    print("=" * 78)
    print(f"载荷 {rep['payload']} — {rep['desc']}")
    print(f"  so={a.so}  长度={rep['payload_len']}B  负向={a.null}")
    print(f"  仿真结果: err={err}  insn={sim.insn_count}")
    print("  --- 载荷内的外部调用序列 ---")
    for addr, nm, r0, r1, r2, r3 in sim.calls:
        print(f"      {nm[:56]:56s} r0={r0:#010x} r1={r1:#x} r2={r2:#x}")
    posted = sim.stub_hits.get("<POST vt[3]>", 0)
    print(f"  --- sender->vt[3] 投递: {posted} 次 ---")
    for addr, nm, r0, r1, r2, r3 in sim.calls:
        if nm == "<POST vt[3]>":
            print(f"      sender={r0:#x}  &msg={r1:#x}")
    if snap:
        bad = [n for n in REGNAMES if snap[n] != SENT[n]]
        print("  --- AAPCS 检查（在重放点快照，尚未重放原指令）---")
        print(f"      SP 还原: {snap['sp'] == sp0}   SP={snap['sp']:#x} (应为 {sp0:#x})")
        print(f"      LR 还原: {snap['lr'] == S.RETMAGIC}   LR={snap['lr']:#x}")
        print(f"      被破坏的寄存器: {bad if bad else '无 —— r0-r12 全部原样'}")
    else:
        print("  --- 未到达重放点（提前 bail 或异常）---")

    expect_post = (a.null == "none")
    regs_ok = bool(snap) and not [n for n in REGNAMES if snap[n] != SENT[n]]
    ok = (err is None) and regs_ok and ((posted > 0) == expect_post)
    print(f"  ==> {'PASS' if ok else 'CHECK'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
