"""构建 osal_rcv_msg_tmo「环形缓冲日志载荷」——本地离线，不连接相机。

设计摘要（详细推导见 work/trampoline-设计.md）
================================================
钩点（函数唯一出口前 4 字节）
    libosal_uipc.so fileVA 0x3EF8
      0x3EF8: bde8 f083   pop.w {r4,r5,r6,r7,r8,sb,pc}
    运行期 = base + 0x3EF8 = 0x04053EF8
    把这条 4 字节指令换成 b.w <载荷>；载荷末尾原样重放它 → 直接返回调用者。

载荷（可执行、可写、距钩点 0x1D8C，b.w 够得着）
    fileVA 0x5C84..0x6000 = 892 字节零（PT_LOAD#0 的 p_filesz=0x5C84 之后、
    页内剩余部分，内核按页映射 → 可执行；全零；无任何引用）
    运行期 = 0x04055C84

粘滞状态（唯一需要的静态可写内存，可证明空闲）
    fileVA 0xEFE0  （__bss_end__ = 0xEFD4，页内余量 0xEFD4..0xF000 = 44 字节）
    { u32 buf_ptr ; u32 calls }
    运行期 = 0x0405EFE0

环形缓冲（运行期动态获得）
    text 与 data 段之间的装载空隙 fileVA 0x6000..0xE000 = 32KB `---p`，
    载荷首次调包时 mmap 成私有匿名 RW（内核保证全零）。
    { u32 cursor ; u32 count ; u32 magic ; +0x10 records[1024] }  = 0x2010 字节

为什么缓冲不能放 libObj 的 20974 字节零区
    /proc/155/maps 显示 libObj 第一个 PT_LOAD 是 r-xp（只读可执行），
    那 20974 字节零区其实是 .rodata。载荷运行时 `str` 到只读页 → 权限异常。
    它能放「代码」，不能放「数据」。

用法
    python tools/build_msglog_payload.py                       # 默认：构建 + Unicorn 验证
    python tools/build_msglog_payload.py --scheme entry-count    # 备选：只在入口计数
    python tools/build_msglog_payload.py --no-verify
"""
from __future__ import annotations
import os

import argparse
import json
import pathlib
import struct
import sys

LAB = pathlib.Path(os.environ.get("LAB_ROOT", "."))
LIBOSAL = (LAB / "work" / "unpack" / "firmware.tar_unpacked" / "0700_part_image"
           / "dev" / "nflasha15_unpacked" / "lib" / "libosal_uipc.so")
OUTDIR = LAB / "work" / "msglog"

# ---- 定死的 ELF 布局常量（已离线核实）----
TEXT_FILESZ = 0x5C84          # PT_LOAD#0 p_filesz
TEXT_VAMAX = 0x6000           # PT_LOAD#0 所在页结束（内核按页映射 → 0x5C84..0x6000 在映射内）
DATA_VADDR = 0xE000           # PT_LOAD#1 p_vaddr
BSS_END = 0xEFD4              # __bss_end__ / _end / __end__
GLUE_END = 0xF000             # 数据段页结束

DEFAULT_LIBOSAL_BASE = 0x04050000

# ---- 三个关键地址（fileVA）----
HOOK_OFF = 0x3EF8             # 出口 pop.w
PAY_OFF = 0x5C84              # 892 字节零区起点
G_OFF = 0xEFE0                # .bss 之后的页内余量（44 字节里取 8）
HOLE_OFF = 0x6000             # text/data 之间的 32KB `---p` 空隙

REPLAY_LEN_EPILOGUE = 4
ENTRY_OFF = 0x3ED8            # 函数入口（备选 scheme 用）
ENTRY_REPLAY_LEN = 8
ENTRY_RESUME_OFF = 0x3EE0

RECORDS = 1024                # 环形缓冲条数
RECORD_BYTES = 8
MAGIC = 0x4D53474C            # "MSGL"
BUF_HDR = 0x10
BUF_SIZE = BUF_HDR + RECORDS * RECORD_BYTES      # 0x2010
BUF_MAP_LEN = 0x8000          # 映射整个空隙

# 粘滞区布局
G_BUF = 0                     # u32 buf_ptr
G_CALLS = 4                   # u32 calls
G_SIZE = 8

NR_MMAP2 = 192                # ARM EABI __NR_mmap2
PROT_RW = 3                   # PROT_READ|PROT_WRITE
MAP_PRIVATE_ANON = 0x22       # MAP_PRIVATE|MAP_ANONYMOUS


def _ks():
    import keystone as K
    return K.Ks(K.KS_ARCH_ARM, K.KS_MODE_THUMB | K.KS_MODE_LITTLE_ENDIAN)


def _cs_detail():
    import capstone
    md = capstone.Cs(capstone.CS_ARCH_ARM,
                     capstone.CS_MODE_THUMB | capstone.CS_MODE_LITTLE_ENDIAN)
    md.detail = False
    return md


def asm_lines(scheme: str, base: int, records: int = RECORDS) -> list[str]:
    """返回载荷汇编源码（便于逐行定位汇编错误）。"""
    pay_va = base + PAY_OFF
    g_va = base + G_OFF
    hole_va = base + HOLE_OFF
    log_msg = (scheme == "epilogue")

    a: list[str] = []
    a.append("mlog:")
    a.append("push {r0, r1, r2, r3}")
    if log_msg:
        a.append(f"movw r8, #{g_va & 0xFFFF:#06x}")
        a.append(f"movt r8, #{(g_va >> 16) & 0xFFFF:#06x}")
        a.append("ldr.w r2, [r8, #4]")          # calls
        a.append("adds r2, r2, #1")
        a.append("str.w r2, [r8, #4]")          # calls++
        a.append("cmp r0, #0")                  # 返回值 0 == 成功收包
        a.append("bne mlog_done")
        a.append("ldr r6, [r4]")                # msg = *(void**)arg1
        a.append("cmp r6, #0")
        a.append("beq mlog_done")
        a.append("tst r6, #3")                  # 指针对齐兜底
        a.append("bne mlog_done")
        # ---- 只看 type == 0x04 (CAP_NOTIFY) 的消息，过滤掉海量噪声 ----
        a.append("ldrb r0, [r6]")               # msg->type
        a.append("cmp r0, #0x04")
        a.append("bne mlog_done")
        a.append("ldr r1, [r8]")                # buf
        a.append("cmp r1, #0")
        a.append("bne mlog_ready")
        # ---- 首次：mmap(hole, 0x8000, RW, PRIVATE|ANON, -1, 0) ----
        a.append(f"movw r0, #{hole_va & 0xFFFF:#06x}")
        a.append(f"movt r0, #{(hole_va >> 16) & 0xFFFF:#06x}")
        a.append(f"movw r1, #{BUF_MAP_LEN & 0xFFFF:#06x}")
        a.append("movt r1, #0")
        a.append(f"movs r2, #{PROT_RW}")
        a.append(f"movs r3, #{MAP_PRIVATE_ANON:#04x}")
        a.append("mvn r4, #0")                  # fd = -1（r4 已读完）
        a.append("movs r5, #0")                 # offset = 0
        a.append(f"movs r7, #{NR_MMAP2}")
        a.append("svc #0")
        a.append("cmp r0, #0")
        a.append("blt mlog_done")               # mmap 失败 → 只留计数
        a.append("str r0, [r8]")                # 粘滞保存
        a.append("mov r1, r0")
        a.append("movw r2, #0x474c")            # magic "MSGL" 低半
        a.append("movt r2, #0x4d53")            # 高半
        a.append("str.w r2, [r1, #8]")
        a.append("mlog_ready:")
        a.append("ldr r3, [r6]")                # hdr0
        a.append("ldr r7, [r6, #4]")            # hdr1
        a.append("ldr r2, [r1]")                # cursor
        a.append("add r2, r2, r1")              # &records[cursor/8]
        a.append(f"str r3, [r2, #{BUF_HDR:#04x}]")
        a.append(f"str r7, [r2, #{BUF_HDR + 4:#04x}]")
        a.append("ldr r2, [r1]")
        a.append("adds r2, r2, #8")
        a.append(f"movw r3, #{records * RECORD_BYTES - 1:#06x}")
        a.append("and.w r2, r2, r3")            # 环形回卷
        a.append("str r2, [r1]")                # cursor = next
        a.append("ldr r2, [r1, #4]")            # count
        a.append("adds r2, r2, #1")
        a.append("str r2, [r1, #4]")            # count++
    else:
        # 只计数：只用 r0-r3 / r12，不碰任何 callee-saved
        a.append(f"movw r12, #{g_va & 0xFFFF:#06x}")
        a.append(f"movt r12, #{(g_va >> 16) & 0xFFFF:#06x}")
        a.append("ldr.w r2, [r12, #4]")
        a.append("adds r2, r2, #1")
        a.append("str.w r2, [r12, #4]")
    a.append("mlog_done:")
    a.append("pop {r0, r1, r2, r3}")
    return a


def build(scheme: str, base: int, records: int = RECORDS) -> dict:
    """生成载荷。返回 dict：payload / hook / replay / 地址表 / 反汇编清单。"""
    orig = LIBOSAL.read_bytes()
    ks = _ks()
    md = _cs_detail()

    if scheme == "epilogue":
        hook_off, replay_len, resume_off = HOOK_OFF, REPLAY_LEN_EPILOGUE, None
    elif scheme == "entry-count":
        hook_off, replay_len, resume_off = ENTRY_OFF, ENTRY_REPLAY_LEN, ENTRY_RESUME_OFF
    else:
        raise SystemExit(f"未知 scheme: {scheme}")

    replay = orig[hook_off:hook_off + replay_len]
    pay_va = base + PAY_OFF
    g_va = base + G_OFF
    hole_va = base + HOLE_OFF
    log_msg = (scheme == "epilogue")
    a = asm_lines(scheme, base, records)

    src = "\n".join(a)
    enc, cnt = ks.asm(src, pay_va)
    if enc is None:
        raise SystemExit(f"keystone 汇编失败:\n{src}")
    code = bytes(enc)

    # 载荷 = 代码 + 原样重放 + （可选）回跳
    body = code + replay
    if resume_off is not None:
        resume_va = base + resume_off
        tail, _ = ks.asm(f"b.w #{resume_va:#x}", pay_va + len(body))
        if tail is None:
            raise SystemExit("回跳汇编失败")
        body += bytes(tail)

    if len(body) > TEXT_VAMAX - PAY_OFF:
        raise SystemExit(f"载荷 {len(body)} 字节超出零区 {TEXT_VAMAX - PAY_OFF}")

    # 钩子 4 字节
    hook, _ = ks.asm(f"b.w #{pay_va:#x}", base + hook_off)
    if hook is None:
        raise SystemExit("钩子汇编失败")
    hook = bytes(hook)
    if len(hook) != 4:
        raise SystemExit(f"钩子不是 4 字节而是 {len(hook)}: {hook.hex()}")

    return dict(scheme=scheme, base=base, pay_va=pay_va, g_va=g_va, hole_va=hole_va,
                hook_va=base + hook_off, hook_off=hook_off,
                payload=body, code=code, replay=replay, hook=hook,
                src=a, records=records, log_msg=log_msg,
                disasm=[f"0x{i.address:08x}: {i.bytes.hex():<10} {i.mnemonic:<9} {i.op_str}"
                        for i in md.disasm(body, pay_va)])


# --------------------------------------------------------------------------
# Unicorn 离线验证
# --------------------------------------------------------------------------
def verify(b: dict, verbose: bool = True) -> bool:
    from unicorn import (Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN,
                         UC_HOOK_INTR, UC_HOOK_CODE, UC_PROT_ALL)
    from unicorn.arm_const import (UC_ARM_REG_R0, UC_ARM_REG_R1, UC_ARM_REG_R2,
                                   UC_ARM_REG_R3, UC_ARM_REG_R4, UC_ARM_REG_R5,
                                   UC_ARM_REG_R6, UC_ARM_REG_R7, UC_ARM_REG_R8,
                                   UC_ARM_REG_R9, UC_ARM_REG_R10, UC_ARM_REG_R11,
                                   UC_ARM_REG_R12, UC_ARM_REG_SP, UC_ARM_REG_PC,
                                   UC_ARM_REG_LR)

    base = b["base"]
    pay_va = b["pay_va"]
    g_va = b["g_va"]
    hole_va = b["hole_va"]
    hook_va = b["hook_va"]
    records = b["records"]

    LIBLO, LIBSZ = base, 0x10000            # 覆盖 text + 空隙 + data 页
    STKLO, STKSZ = 0x00100000, 0x00020000
    DBLO, DBSZ = 0x00200000, 0x00020000     # 「堆」：out 槽 + 消息
    SENT = 0x00300000                       # 调用者返回哨兵（必须映射，放 b .）
    RET = SENT | 1
    OUT_SLOT = DBLO + 0x1000
    MSG = DBLO + 0x2000
    MMAPED = hole_va                        # 假 mmap 返回值

    orig_file = LIBOSAL.read_bytes()

    def mk(emu_ret: int = 0):
        uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        uc.mem_map(LIBLO, LIBSZ, UC_PROT_ALL)
        uc.mem_write(LIBLO, orig_file[:min(len(orig_file), LIBSZ)] + b"\x00" * max(0, LIBSZ - len(orig_file)))
        uc.mem_map(STKLO, STKSZ, UC_PROT_ALL)
        uc.mem_map(DBLO, DBSZ, UC_PROT_ALL)
        uc.mem_write(DBLO, b"\x00" * 0x20000)
        uc.mem_map(SENT, 0x1000, UC_PROT_ALL)
        uc.mem_write(SENT, bytes.fromhex("fee7"))         # b .  （哨兵死循环）
        # 写入载荷与钩子
        uc.mem_write(pay_va, b["payload"])
        uc.mem_write(hook_va, b["hook"])
        state = {"n_svc": 0, "mmap_ret": emu_ret, "ret": False}

        def on_intr(uc_, intno, user_data):
            state["n_svc"] += 1
            # 直接当成 mmap2 的返回：内核 mmap 匿名页 → 全零
            ret = state["mmap_ret"]
            if ret & 0x80000000 == 0:
                try:
                    uc_.mem_write(ret, b"\x00" * BUF_MAP_LEN)
                except Exception:                                # noqa: BLE001
                    pass
            uc_.reg_write(UC_ARM_REG_R0, ret & 0xFFFFFFFF)
            # 实测：Unicorn 的 intr 钩子里 PC 已越过 svc，不能再 +2
            # （写 PC 也不必；如要写，Thumb 位必须保留）
            _ = intno

        def on_code(uc_, addr, size, user_data):
            if (addr & ~1) == SENT:
                state["ret"] = True
                uc_.emu_stop()

        uc.hook_add(UC_HOOK_INTR, on_intr)
        uc.hook_add(UC_HOOK_CODE, on_code)
        return uc, state

    def setup_frame(uc, ret_val=0, msg=MSG, out_slot=OUT_SLOT):
        """模拟「刚执行完 mov sp,r7」的函数栈帧状态。"""
        sp = STKLO + STKSZ - 0x400
        frame = struct.pack("<7I",
                            0xA4A4A4A4, 0xA5A5A5A5, 0xA6A6A6A6, 0xA7A7A7A7,
                            0xA8A8A8A8, 0xABABABAB, RET)
        uc.mem_write(sp, frame)
        if out_slot is not None:
            uc.mem_write(out_slot, struct.pack("<I", msg if msg is not None else 0))
        regs = {UC_ARM_REG_R0: ret_val, UC_ARM_REG_R1: 0x11111111,
                UC_ARM_REG_R2: 0x22222222, UC_ARM_REG_R3: 0x33333333,
                UC_ARM_REG_R4: out_slot if out_slot is not None else 0x44444444,
                UC_ARM_REG_R5: 0, UC_ARM_REG_R6: 0, UC_ARM_REG_R7: 0,
                UC_ARM_REG_R8: 0, UC_ARM_REG_R9: 0, UC_ARM_REG_R10: 0,
                UC_ARM_REG_R11: 0, UC_ARM_REG_R12: 0,
                UC_ARM_REG_SP: sp, UC_ARM_REG_LR: 0x0000ABCD}
        for r, v in regs.items():
            uc.reg_write(r, v)
        return sp

    ok = True

    def fail(msg):
        nonlocal ok
        ok = False
        print(f"  [FAIL] {msg}")

    def chk(cond, msg):
        if not cond:
            fail(msg)

    def run(uc, begin, count=2000):
        try:
            uc.emu_start(begin, 0, count=count)
            return True
        except Exception as e:                              # noqa: BLE001
            fail(f"仿真异常 begin=0x{begin:x}: {e}")
            return False

    # ================= 入口计数方案（备选）：独立验证 =================
    if not b["log_msg"]:
        from unicorn.arm_const import UC_ARM_REG_R9 as _R9
        entry = base + ENTRY_OFF
        resume = base + ENTRY_RESUME_OFF
        # 把 resume 处改成 b . 并作为停止点
        uc, st = mk(0)
        uc.mem_write(resume, bytes.fromhex("fee7"))
        stopped = {"at": None}

        def on_code2(uc_, addr, size, ud):
            if (addr & ~1) == resume:
                stopped["at"] = addr
                uc_.emu_stop()

        uc.hook_add(UC_HOOK_CODE, on_code2)
        sp0 = STKLO + STKSZ - 0x400
        uc.reg_write(UC_ARM_REG_R0, 0x00008005)
        uc.reg_write(UC_ARM_REG_R1, 0x12345678)
        uc.reg_write(UC_ARM_REG_R2, 0x000003E8)
        uc.reg_write(UC_ARM_REG_R3, 0xCAFEBABE)
        uc.reg_write(UC_ARM_REG_SP, sp0)
        run(uc, entry | 1)
        chk(stopped["at"] is not None, "入口计数：没有回到 resume 点")
        chk(struct.unpack("<I", bytes(uc.mem_read(g_va + G_CALLS, 4)))[0] == 1,
            "入口计数：calls 不是 1")
        chk(uc.reg_read(UC_ARM_REG_R0) == 0x00008005, "入口计数：r0 被破坏")
        chk(uc.reg_read(UC_ARM_REG_R1) == 0x12345678, "入口计数：r1 被破坏")
        chk(uc.reg_read(UC_ARM_REG_R2) == 0x000003E8, "入口计数：r2 被破坏")
        chk(uc.reg_read(UC_ARM_REG_R3) == 0xCAFEBABE, "入口计数：r3 被破坏")
        chk(uc.reg_read(UC_ARM_REG_SP) == sp0 - 28, "入口计数：push.w 重放后 SP 不对")
        chk(uc.reg_read(_R9) == 0, "入口计数：r9 被破坏")
        # 钩子跳转
        uc2, st2 = mk(0)
        uc2.reg_write(UC_ARM_REG_SP, sp0)
        run(uc2, entry | 1, count=1)
        chk(uc2.reg_read(UC_ARM_REG_PC) == pay_va,
            f"入口计数：钩子跳到 0x{uc2.reg_read(UC_ARM_REG_PC):x} 期望 0x{pay_va:x}")
        if verbose:
            print(f"  入口计数用例: 6 组  →  {'全部通过' if ok else '存在失败'}")
        return ok



    # ---------- 用例 1：单次正常收包 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc, ret_val=0, msg=MSG)
    uc.mem_write(MSG, struct.pack("<2I", 0x00000004, 0x1120))
    try:
        run(uc, hook_va | 1)
    except Exception as e:                                    # noqa: BLE001
        fail(f"用例1 仿真异常: {e}")
    chk(st["ret"], "用例1 未返回到哨兵（pop.w 未正确返回）")
    chk(st["n_svc"] == 1, f"用例1 应发生 1 次 svc，实际 {st['n_svc']}")
    chk(uc.reg_read(UC_ARM_REG_R0) == 0, f"用例1 r0(返回值) 被破坏: {uc.reg_read(UC_ARM_REG_R0)}")
    chk(uc.reg_read(UC_ARM_REG_SP) == sp + 28, f"用例1 SP={uc.reg_read(UC_ARM_REG_SP):#x} 期望 {sp+28:#x}")
    chk(uc.reg_read(UC_ARM_REG_R4) == 0xA4A4A4A4, "用例1 r4 未由 pop.w 复原")
    chk(uc.reg_read(UC_ARM_REG_R8) == 0xA8A8A8A8, "用例1 r8 未由 pop.w 复原")
    chk(uc.reg_read(UC_ARM_REG_R9) == 0xABABABAB, "用例1 r9/sb 未复原")
    g_buf, g_calls = struct.unpack("<2I", uc.mem_read(g_va, 8))
    chk(g_buf == MMAPED, f"用例1 粘滞 buf=0x{g_buf:x} 期望 0x{MMAPED:x}")
    chk(g_calls == 1, f"用例1 calls={g_calls} 期望 1")
    hdr = struct.unpack("<4I", uc.mem_read(MMAPED, 16))
    chk(hdr[0] == 8, f"用例1 cursor={hdr[0]} 期望 8")
    chk(hdr[1] == 1, f"用例1 count={hdr[1]} 期望 1")
    chk(hdr[2] == MAGIC, f"用例1 magic=0x{hdr[2]:x} 期望 0x{MAGIC:x}")
    rec = struct.unpack("<2I", uc.mem_read(MMAPED + BUF_HDR, 8))
    chk(rec == (0x00000004, 0x1120), f"用例1 记录={rec} 期望 (0x4,0x1120)")

    # ---------- 用例 2：连续 5 条不同消息，验证追加 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc)
    for i in range(5):
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_R4, OUT_SLOT)
        uc.reg_write(UC_ARM_REG_R8, 0)
        uc.mem_write(MSG, struct.pack("<2I", 0x04 | (i << 8), 0x2000 + i))
        # 每次重设栈帧（模拟每次调用都是新的）
        uc.mem_write(sp, struct.pack("<7I", 0xA4A4A4A4, 0xA5A5A5A5, 0xA6A6A6A6,
                                     0xA7A7A7A7, 0xA8A8A8A8, 0xABABABAB, RET))
        uc.reg_write(UC_ARM_REG_SP, sp)
        run(uc, hook_va | 1)
    hdr = struct.unpack("<4I", uc.mem_read(MMAPED, 16))
    chk(hdr[1] == 5, f"用例2 count={hdr[1]} 期望 5")
    chk(hdr[0] == 40, f"用例2 cursor={hdr[0]} 期望 40")
    chk(struct.unpack("<2I", uc.mem_read(MMAPED + BUF_HDR + 32, 8)) == (0x404, 0x2004),
        "用例2 第 5 条记录内容不对")
    chk(st["n_svc"] == 1, f"用例2 svc 应只 1 次（缓冲复用），实际 {st['n_svc']}")

    # ---------- 用例 3：回卷（跑 records+3 次，只跑后半段省时） ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc)
    n = records + 3
    for i in range(n):
        uc.reg_write(UC_ARM_REG_R0, 0)
        uc.reg_write(UC_ARM_REG_R4, OUT_SLOT)
        uc.reg_write(UC_ARM_REG_R8, 0)
        uc.mem_write(MSG, struct.pack("<2I", 0x04 | (i << 8), i ^ 0xFFFF))
        uc.mem_write(sp, struct.pack("<7I", 0, 0, 0, 0, 0, 0, RET))
        uc.reg_write(UC_ARM_REG_SP, sp)
        run(uc, hook_va | 1)
    hdr = struct.unpack("<4I", uc.mem_read(MMAPED, 16))
    chk(hdr[1] == n, f"用例3 count={hdr[1]} 期望 {n}")
    exp_cursor = (n * 8) % (records * 8)
    chk(hdr[0] == exp_cursor, f"用例3 cursor={hdr[0]} 期望 {exp_cursor}")
    last_idx = (n * 8) % (records * 8)      # 最后一条写到 records[(n-1)%records]
    slot = ((n - 1) % records) * 8
    got = struct.unpack("<2I", uc.mem_read(MMAPED + BUF_HDR + slot, 8))
    chk(got == (0x04 | ((n - 1) << 8), (n - 1) ^ 0xFFFF), f"用例3 回卷后最后一条={got} 期望 {(0x04 | ((n-1)<<8), (n-1)^0xFFFF)}")
    chk(st["n_svc"] == 1, f"用例3 svc 次数 {st['n_svc']}")

    # ---------- 用例 4：返回值非 0 → 只计数 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc, ret_val=0xFFFFFC02)
    uc.mem_write(MSG, struct.pack("<2I", 0x000400AD, 0xBEEF))
    run(uc, hook_va | 1)
    g_buf, g_calls = struct.unpack("<2I", uc.mem_read(g_va, 8))
    chk(g_calls == 1, f"用例4 calls={g_calls} 期望 1")
    chk(g_buf == 0, f"用例4 不应分配缓冲，buf=0x{g_buf:x}")
    chk(uc.reg_read(UC_ARM_REG_R0) == 0xFFFFFC02, "用例4 错误返回值被破坏")
    chk(uc.reg_read(UC_ARM_REG_SP) == sp + 28, "用例4 SP 未复原")

    # ---------- 用例 5：out 槽为 NULL → 只计数 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc, msg=None)
    run(uc, hook_va | 1)
    g_buf, g_calls = struct.unpack("<2I", uc.mem_read(g_va, 8))
    chk(g_calls == 1 and g_buf == 0, f"用例5 calls={g_calls} buf=0x{g_buf:x}")

    # ---------- 用例 6：指针对齐异常 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc, msg=MSG + 2)
    run(uc, hook_va | 1)
    g_buf, g_calls = struct.unpack("<2I", uc.mem_read(g_va, 8))
    chk(g_calls == 1 and g_buf == 0, f"用例6 calls={g_calls} buf=0x{g_buf:x}")

    # ---------- 用例 7：mmap 失败（负返回）----------
    uc, st = mk(0xFFFFFFF4)                 # -12 ENOMEM
    sp = setup_frame(uc)
    run(uc, hook_va | 1)
    g_buf, g_calls = struct.unpack("<2I", uc.mem_read(g_va, 8))
    chk(g_calls == 1, f"用例7 calls={g_calls} 期望 1")
    chk(g_buf == 0, f"用例7 mmap 失败后 buf 应保持 0，实际 0x{g_buf:x}")
    chk(st["ret"], "用例7 未正常返回")
    chk(uc.reg_read(UC_ARM_REG_R0) == 0, "用例7 r0(返回值) 被破坏")

    # ---------- 用例 8：钩子本身跳转正确 ----------
    uc, st = mk(MMAPED)
    setup_frame(uc)
    run(uc, hook_va | 1, count=1)     # 只执行钩子那一条
    chk(uc.reg_read(UC_ARM_REG_PC) == (pay_va | 0) or uc.reg_read(UC_ARM_REG_PC) == pay_va,
        f"用例8 钩子跳到 0x{uc.reg_read(UC_ARM_REG_PC):x} 期望 0x{pay_va:x}")

    # ---------- 用例 9：载荷未污染 libosal 其它区域 ----------
    uc, st = mk(MMAPED)
    sp = setup_frame(uc)
    uc.mem_write(MSG, struct.pack("<2I", 0x00000004, 0x1120))
    before = bytes(uc.mem_read(base, 0x6000))
    run(uc, hook_va | 1)
    after = bytes(uc.mem_read(base, 0x6000))
    diff = [i for i in range(len(before)) if before[i] != after[i]]
    pay_end = PAY_OFF + len(b["payload"])
    bad = [d for d in diff if not (PAY_OFF <= d < pay_end or HOOK_OFF <= d < HOOK_OFF + 4)]
    chk(not bad, f"用例9 意外改写了 {len(bad)} 处" + (f" 例如 0x{bad[0]:x}" if bad else ""))

    if verbose:
        print(f"  用例矩阵: 9 组  →  {'全部通过' if ok else '存在失败'}")
    return ok


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--scheme", choices=["epilogue", "entry-count"], default="epilogue")
    ap.add_argument("--libosal-base", type=lambda x: int(x, 0), default=DEFAULT_LIBOSAL_BASE)
    ap.add_argument("--no-verify", action="store_true")
    ap.add_argument("--out", type=pathlib.Path, default=None)
    a = ap.parse_args()

    print("=" * 78)
    print("环形缓冲日志载荷构建（osal_rcv_msg_tmo）")
    print("=" * 78)
    b = build(a.scheme, a.libosal_base)

    print(f"  scheme          {b['scheme']}")
    print(f"  libosal 基址    0x{b['base']:08x}")
    print(f"  钩点            0x{b['hook_va']:08x}   (fileVA 0x{b['hook_off']:04x})")
    print(f"  载荷            0x{b['pay_va']:08x}   {len(b['payload'])} 字节"
          f"（代码 {len(b['code'])} + 重放 {len(b['replay'])}"
          f"{' + 回跳 4' if b['scheme'] == 'entry-count' else ''}）")
    print(f"  载荷上限        {TEXT_VAMAX - PAY_OFF} 字节，占用率 "
          f"{100 * len(b['payload']) / (TEXT_VAMAX - PAY_OFF):.1f}%")
    print(f"  粘滞状态        0x{b['g_va']:08x}   {{buf_ptr, calls}}")
    if b["log_msg"]:
        print(f"  缓冲提示地址    0x{b['hole_va']:08x}   （首次调用 mmap 32KB 匿名 RW）")
    print()
    print("  钩子机器码      " + b["hook"].hex() + "   b.w 0x%08x" % b["pay_va"])
    print("  重放机器码      " + b["replay"].hex())
    print()
    print("  载荷反汇编:")
    for line in b["disasm"]:
        print("    " + line)

    ok = True
    if not a.no_verify:
        print()
        print("=" * 78)
        print("Unicorn 离线验证")
        print("=" * 78)
        ok = verify(b)

    outdir = a.out.parent if a.out else OUTDIR
    outdir.mkdir(parents=True, exist_ok=True)
    stem = f"payload_{b['scheme']}"
    payload_path = outdir / f"{stem}.bin"
    payload_path.write_bytes(b["payload"])
    hook_path = outdir / f"{stem}.hook.bin"
    hook_path.write_bytes(b["hook"])
    man = dict(scheme=b["scheme"], libosal_base=b["base"], hook_va=b["hook_va"],
               hook_off=b["hook_off"], pay_va=b["pay_va"], pay_off=PAY_OFF,
               g_va=b["g_va"], hole_va=b["hole_va"], payload_len=len(b["payload"]),
               payload_hex=b["payload"].hex(), hook_hex=b["hook"].hex(),
               replay_hex=b["replay"].hex(), records=b["records"], magic=MAGIC,
               buf_hdr=BUF_HDR, buf_size=BUF_SIZE, verified=ok,
               asm=b["src"], disasm=b["disasm"])
    man_path = outdir / f"{stem}.json"
    man_path.write_text(json.dumps(man, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print(f"  载荷文件  {payload_path}")
    print(f"  钩子文件  {hook_path}")
    print(f"  清单文件  {man_path}")
    print()
    print("  ✅ 构建完成" if ok else "  ❌ 验证未通过")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
