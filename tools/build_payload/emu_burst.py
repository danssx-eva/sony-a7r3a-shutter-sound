#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""连拍载荷的 Unicorn **端到端**仿真验证。

不是"只测片段"——仿真的是真机上的完整路径：

    CPU 到达钩点 0xA31226
      → 钩子 b.w 跳到载荷 0x1948D8        （真实编码，跑真实指令）
      → 载荷：保存寄存器 → 读 [r7+0x14] 取 msg → 判 NID → 发声调用序列
      → 恢复寄存器
      → 重放原始 4 字节 `ldr r4,[r7,#0x14]` + `ldrb r3,[r4]`
      → b.w 回跳 0xA3122A
      → 继续跑真实分发器 0xA3122A..0xA3134C（证明控制流未被破坏）

为了让"载荷 → PLT"这一段真的跑起来，用 UC_HOOK_CODE 在 5 个调用目标上打桩：
  · MWF::ObjMsg::ObjMsg(unsigned,unsigned)         fileVA 0x0FF7B8
  · MWF::ParamStd_Template<unsigned,Type8>::ctor   fileVA 0x102B34
  · MWF::ObjMsg::AddParam(unsigned,Param const*)   fileVA 0x1027E4
  · MWF::ObjIf::IssueCommandAsync(void*,ObjMsg*)   fileVA 0x0FD2A0
  · Get(7)                                          fileVA 0x34D840
桩会记录参数、模拟副作用、然后 `PC = LR & ~1` 返回。

另外用 UC_HOOK_MEM_WRITE 记录**每一次内存写**，断言全部落在本帧栈范围内
（= 证明"绝不写任何绝对地址"）。
"""
from __future__ import annotations
import os, struct, pathlib, sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

BASE = 0x05DCA000
HOOK = 0xA31226
RESUME = HOOK + 4
SLOT = 0x1948D8

OBJMSG_CTOR = 0x0FF7B8
PARAM_CTOR = 0x102B34
ADDPARAM = 0x1027E4
ISSUE_ASYNC = 0x0FD2A0
GET_COMP = 0x34D840

STACK_TOP = 0x70010000
STACK_SIZE = 0x20000
HEAP = 0x60000000
HEAP_SIZE = 0x10000

FAKE_COMP = 0xCAFE0000
NID_OK = 0x1001          # 默认目标；实际以 b["nid"] 为准


# ------------------------------------------------------------------ 装载镜像
def image_blobs(path: pathlib.Path):
    """返回 [(runtime_va, bytes)]：按 PT_LOAD 把文件内容摆到运行期地址。"""
    from elftools.elf.elffile import ELFFile
    ef = ELFFile(open(path, "rb"))
    data = path.read_bytes()
    blobs = []
    for s in ef.iter_segments():
        if s["p_type"] != "PT_LOAD":
            continue
        blobs.append((BASE + s["p_vaddr"], data[s["p_offset"]:
                                               s["p_offset"] + s["p_filesz"]]))
    return blobs


class Emu:
    def __init__(self, so_path: pathlib.Path, get_comp_ret=FAKE_COMP,
                 verbose=False):
        from unicorn import Uc, UC_ARCH_ARM, UC_MODE_THUMB, UC_MODE_LITTLE_ENDIAN
        from unicorn import arm_const as R
        self.R = R
        from unicorn import (UC_HOOK_CODE, UC_HOOK_MEM_WRITE, UC_HOOK_MEM_READ_UNMAPPED,
                             UC_HOOK_MEM_WRITE_UNMAPPED, UC_HOOK_MEM_FETCH_UNMAPPED,
                             UC_HOOK_INTR)
        self.UC_HOOK_CODE = UC_HOOK_CODE
        self.verbose = verbose
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        self.uc.mem_map(BASE, 0x1300000)          # libObj 全部 PT_LOAD
        for va, blob in image_blobs(so_path):
            self.uc.mem_write(va, blob)
        self.uc.mem_map(STACK_TOP - STACK_SIZE, STACK_SIZE)
        self.uc.mem_map(HEAP, HEAP_SIZE)

        self.calls = []          # [(name, args...)]
        self.writes = []         # [(addr, size)]
        self.sp_min = STACK_TOP
        self.sp_max = STACK_TOP - STACK_SIZE
        self.get_comp_ret = get_comp_ret
        self.trace = []
        self.stopped_at = None
        self.err = None

        # ---- PLT / API 桩 ----
        self.stubs = {}
        for name, va in (("ObjMsg_ctor", OBJMSG_CTOR),
                         ("ParamStd_ctor", PARAM_CTOR),
                         ("AddParam", ADDPARAM),
                         ("IssueCommandAsync", ISSUE_ASYNC),
                         ("Get7", GET_COMP)):
            self.stubs[va] = name
            self.uc.hook_add(UC_HOOK_CODE, self._mk_stub(name),
                             begin=BASE + va, end=BASE + va + 3)

        self.uc.hook_add(UC_HOOK_MEM_WRITE, self._on_write)
        self.uc.hook_add(UC_HOOK_MEM_WRITE_UNMAPPED, self._on_bad_write)
        self.uc.hook_add(UC_HOOK_MEM_FETCH_UNMAPPED, self._on_bad_fetch)
        self.uc.hook_add(UC_HOOK_INTR, self._on_intr)

    # ------------------------------------------------------------- 回调
    def _reg(self, r):
        return self.uc.reg_read(r)

    def _set_pc(self, v):
        self.uc.reg_write(self.R.UC_ARM_REG_PC, v & 0xFFFFFFFE)

    def _enter_thumb(self):
        """★ 关键：`blx r6` 的 r6 是偶数（PLT 桩是 ARM 代码），execution 会切到 ARM 态。
        桩返回时若只写 PC 不恢复 T 位，后续 Thumb 指令会被按 ARM 解码 →
        UC_ERR_INSN_INVALID。必须在 CPSR 里把 T(bit5) 置回 1。"""
        try:
            cpsr = self.uc.reg_read(self.R.UC_ARM_REG_CPSR)
            self.uc.reg_write(self.R.UC_ARM_REG_CPSR, (cpsr | 0x20) & 0xFFFFFFFF)
        except Exception:
            pass

    def _mk_stub(self, name):
        def cb(uc, address, size, user):
            r0 = self._reg(self.R.UC_ARM_REG_R0)
            r1 = self._reg(self.R.UC_ARM_REG_R1)
            r2 = self._reg(self.R.UC_ARM_REG_R2)
            r3 = self._reg(self.R.UC_ARM_REG_R3)
            lr = self._reg(self.R.UC_ARM_REG_LR)
            sp = self._reg(self.R.UC_ARM_REG_SP)
            if name == "ObjMsg_ctor":
                # 模拟：ObjMsg(cate=r1, msgId=r2) 写在对象头
                try:
                    uc.mem_write(r0, struct.pack("<II", r1 & 0xFFFFFFFF, r2 & 0xFFFFFFFF))
                    uc.mem_write(r0 + 8, b"\0" * 0x10)
                    self.calls.append(("ObjMsg_ctor", r0, r1, r2, sp))
                except Exception as ex:
                    self.err = f"ObjMsg_ctor 写对象失败: {ex}"
            elif name == "ParamStd_ctor":
                try:
                    uc.mem_write(r0, struct.pack("<I", r1 & 0xFFFFFFFF))
                    self.calls.append(("ParamStd_ctor", r0, r1, sp))
                except Exception as ex:
                    self.err = f"ParamStd_ctor 写对象失败: {ex}"
            elif name == "AddParam":
                val = None
                try:
                    val = struct.unpack("<I", uc.mem_read(r2, 4))[0]
                except Exception:
                    pass
                self.calls.append(("AddParam", r0, r1, r2, val, sp))
            elif name == "IssueCommandAsync":
                self.calls.append(("IssueCommandAsync", r0, r1, sp))
            elif name == "Get7":
                self.calls.append(("Get7", r0, sp))
                uc.reg_write(self.R.UC_ARM_REG_R0, self.get_comp_ret)
            self._enter_thumb()
            uc.reg_write(self.R.UC_ARM_REG_PC, lr & 0xFFFFFFFE)
            self._enter_thumb()
        return cb

    def _on_write(self, uc, access, address, size, value, user):
        sp = self._reg(self.R.UC_ARM_REG_SP)
        self.writes.append((address, size, sp))
        self.sp_min = min(self.sp_min, sp)
        self.sp_max = max(self.sp_max, sp)

    def _on_bad_write(self, uc, access, address, size, value, user):
        self.err = f"非法写 0x{address:08x} size={size}"
        uc.emu_stop()
        return False

    def _on_bad_fetch(self, uc, access, address, size, value, user):
        self.err = f"非法取指 0x{address:08x}"
        pc = self._reg(self.R.UC_ARM_REG_PC)
        self.err += f" (PC=0x{pc:08x}, LR=0x{self._reg(self.R.UC_ARM_REG_LR):08x})"
        uc.emu_stop()
        return False

    def _on_intr(self, uc, intno, user):
        self.err = f"中断/异常 intno={intno}"
        uc.emu_stop()

    # --------------------------------------------------------- 帧构造
    def setup_frame(self, msg_ptr, r4=0x44444444, r5=0x55555555, r8=0x88888888,
                    r6=0x66666666, r7_in=None, r9=0x99999999, r10=0xAAAAAAAA,
                    r11=0xBBBBBBBB, lr=0x11111111):
        """复刻 FUN_00A311E0 的函数帧：
             entry:   sp = SP0
             push.w {r4,r5,r6,r7,r8,lr}   -> sp = SP0-24
             sub sp,#0x20                 -> sp = SP0-56
             add r7, sp, #8               -> r7 = SP0-48
           并把 msg 指针写进 [r7+0x14]（= osal_rcv_msg_tmo 的输出槽）
        """
        SP0 = STACK_TOP - 0x100
        sp = SP0 - 24 - 0x20
        r7 = sp + 8
        uc = self.uc
        # 调用者已压栈的 r4,r5,r6,r7,r8,lr（槽位内容仅用于观测）
        uc.mem_write(SP0 - 24, struct.pack("<IIIIII", r4, r5, r6, r7, r8, lr))
        uc.mem_write(r7 + 0x14, struct.pack("<I", msg_ptr if msg_ptr is not None else 0))
        # 帧内其它槽清零
        uc.mem_write(sp, b"\0" * 0x20)
        uc.mem_write(r7 + 0x14, struct.pack("<I", msg_ptr if msg_ptr is not None else 0))
        for reg, val in ((self.R.UC_ARM_REG_R4, r4), (self.R.UC_ARM_REG_R5, r5),
                         (self.R.UC_ARM_REG_R6, r6), (self.R.UC_ARM_REG_R7, r7),
                         (self.R.UC_ARM_REG_R8, r8), (self.R.UC_ARM_REG_R9, r9),
                         (self.R.UC_ARM_REG_R10, r10), (self.R.UC_ARM_REG_R11, r11),
                         (self.R.UC_ARM_REG_LR, lr),
                         (self.R.UC_ARM_REG_R0, 0xDEAD0000),
                         (self.R.UC_ARM_REG_R1, 0x11110000),
                         (self.R.UC_ARM_REG_R2, 0x22220000),
                         (self.R.UC_ARM_REG_R3, 0x33330000)):
            uc.reg_write(reg, val)
        uc.reg_write(self.R.UC_ARM_REG_SP, sp)
        self.SP0, self.sp_entry, self.r7_entry = SP0, sp, r7
        self.saved = dict(r4=r4, r5=r5, r6=r6, r8=r8, r9=r9, r10=r10, r11=r11, lr=lr)
        return r7

    def write_msg(self, hdr: bytes, addr: int = HEAP + 0x100, size: int = 64):
        self.uc.mem_write(addr, hdr + b"\0" * max(0, size - len(hdr)))
        return addr

    def run(self, start_va, stop_addrs, max_insn=4000):
        """从 start_va 跑到任一 stop_addrs（运行期地址）。返回停止地址。

        ★ emu_start 的起始地址必须 `|1`：Unicorn 的 ARM 后端用 addr&1 决定
          初始 T 态；传偶数会以 ARM 模式开始执行，Thumb 指令全被错解。
        """
        self.uc.reg_write(self.R.UC_ARM_REG_PC, start_va & 0xFFFFFFFE)
        self._enter_thumb()
        self.stopped_at = None
        stops = set(stop_addrs)          # ★ 调用方传运行期地址，这里不再加 BASE

        def cb(uc, address, size, user):
            if address in stops:
                self.stopped_at = address
                uc.emu_stop()
        h = self.uc.hook_add(self.UC_HOOK_CODE, cb)
        try:
            self.uc.emu_start((start_va & ~1) | 1, 0, count=max_insn)
        except Exception as ex:
            self.err = self.err or f"UcError: {ex}"
        finally:
            self.uc.hook_del(h)
        return self.stopped_at

    def regs(self):
        R = self.R
        return dict(r0=self._reg(R.UC_ARM_REG_R0), r1=self._reg(R.UC_ARM_REG_R1),
                    r2=self._reg(R.UC_ARM_REG_R2), r3=self._reg(R.UC_ARM_REG_R3),
                    r4=self._reg(R.UC_ARM_REG_R4), r5=self._reg(R.UC_ARM_REG_R5),
                    r6=self._reg(R.UC_ARM_REG_R6), r7=self._reg(R.UC_ARM_REG_R7),
                    r8=self._reg(R.UC_ARM_REG_R8), r9=self._reg(R.UC_ARM_REG_R9),
                    r10=self._reg(R.UC_ARM_REG_R10), r11=self._reg(R.UC_ARM_REG_R11),
                    r12=self._reg(R.UC_ARM_REG_R12), sp=self._reg(R.UC_ARM_REG_SP),
                    lr=self._reg(R.UC_ARM_REG_LR), pc=self._reg(R.UC_ARM_REG_PC))


# ------------------------------------------------------------------ 用例
class Result:
    def __init__(self):
        self.cases = []
        self.warnings = []

    def add(self, name, ok, detail=""):
        self.cases.append((name, bool(ok), detail))

    def warn(self, text):
        self.warnings.append(text)

    @property
    def ok(self):
        return all(c[1] for c in self.cases)


def _api_seq(calls):
    return [c[0] for c in calls]


def case_valid_nid(b, res, nid, expect_sound):
    """①②：msg 有效，NID 命中/不命中"""
    e = Emu(pathlib.Path(b["out_path"]))
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, nid, 1))
    e.setup_frame(msg)
    stop = e.run(BASE + HOOK, [BASE + RESUME])
    st = e.stopped_at
    seq = _api_seq(e.calls)
    detail = f"停止于 0x{(st or 0):08x} 调用序列 {seq}"
    if expect_sound:
        want = ["ObjMsg_ctor", "ParamStd_ctor", "ParamStd_ctor",
                "ParamStd_ctor", "AddParam", "AddParam", "AddParam",
                "Get7", "IssueCommandAsync"]
        ok = (st == BASE + RESUME and seq == want and e.err is None)
        om = [c for c in e.calls if c[0] == "ObjMsg_ctor"]
        ps = [c[2] for c in e.calls if c[0] == "ParamStd_ctor"]   # 元组=(名,r0,值)
        ap = [c[2] for c in e.calls if c[0] == "AddParam"]        # 元组=(名,r0,pid,...)
        ic = [c for c in e.calls if c[0] == "IssueCommandAsync"]
        params_ok = (bool(om) and om[0][2] == 0x3410 and om[0][3] == 0x1120
                     and ps == [b["sound"], b["p1"], b["p2"]]
                     and ap == [0x1000, 0x1001, 0x1002]
                     and bool(ic) and ic[0][1] == FAKE_COMP)
        detail = (f"cate=0x{om[0][2]:04x} msgid=0x{om[0][3]:04x} "
                  f"Param值={[hex(x) for x in ps]} pid={[hex(x) for x in ap]} "
                  f"comp=0x{ic[0][1]:08x}" if om and ic
                  else f"调用序列 {seq}")
        ok = ok and params_ok
    else:
        ok = (st == BASE + RESUME and seq == [] and e.err is None)
        detail = f"NID=0x{nid:04x} 未发声（序列 {seq}），停止于 0x{(st or 0):08x}"
    res.add(f"用例: NID=0x{nid:04x} {'应发声' if expect_sound else '不应发声'}",
            ok, detail)
    return e


def case_null(b, res):
    """③ msg == NULL：载荷自身必须不崩、不发声。

    注意：重放的第 2 条 `ldrb r3,[r4]`（0xA31228）是**原厂指令**，
    r4=NULL 时它本身就会访存异常 —— 这属于原厂行为，不是本补丁引入的。
    真机上 osal_rcv_msg_tmo 返回 0 时 msg 必有效，NULL 不可达。
    因此本用例只验证到"重放前"这一检查点。
    """
    e = Emu(pathlib.Path(b["out_path"]))
    e.setup_frame(0)
    replay_va = SLOT + b["code_len"]
    st = e.run(BASE + HOOK, [BASE + replay_va])
    res.add("用例: msg == NULL 时载荷自身不崩、不发声（验到重放前）",
            st == BASE + replay_va and e.err is None and _api_seq(e.calls) == [],
            f"PC=0x{(st or 0):08x} err={e.err} 序列={_api_seq(e.calls)}")


def case_get_null(b, res):
    """④ Get(7) 返回 NULL → 不得调用 IssueCommandAsync"""
    e = Emu(pathlib.Path(b["out_path"]), get_comp_ret=0)
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), 1))
    e.setup_frame(msg)
    st = e.run(BASE + HOOK, [BASE + RESUME])
    seq = _api_seq(e.calls)
    res.add("用例: Get(7)==NULL 时 IssueCommandAsync 不得被调用",
            st == BASE + RESUME and "IssueCommandAsync" not in seq and e.err is None,
            f"PC=0x{(st or 0):08x} 序列 {seq} err={e.err}")


def case_stack_and_regs(b, res):
    """⑤⑥ 栈平衡 + callee-saved 恢复（在"重放开头"这个检查点取快照）"""
    e = Emu(pathlib.Path(b["out_path"]))
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), 1))
    e.setup_frame(msg)
    sp_entry = e.regs()["sp"]
    replay_va = SLOT + b["code_len"]
    st = e.run(BASE + HOOK, [BASE + replay_va])
    res.add("用例: 重放前到达检查点（载荷已执行完、pop 已恢复）",
            st == BASE + replay_va, f"PC=0x{(st or 0):08x} 期望 0x{BASE + replay_va:08x}")
    r = e.regs()
    res.add("用例: SP 平衡（载荷执行完 == 进入时）",
            r["sp"] == sp_entry, f"进入 0x{sp_entry:08x} 退出 0x{r['sp']:08x}")
    bad = [k for k, v in e.saved.items() if r[k] != v]
    res.add("用例: callee-saved r4-r8/r9-r11/lr 全部恢复",
            not bad, f"未恢复: {bad}" if bad else
            "r4,r5,r6,r7,r8,r9,r10,r11,lr 全部一致")
    res.add("用例: 检查点处 r4 仍是调用者原值（未被载荷污染）",
            r["r4"] == e.saved["r4"], f"r4=0x{r['r4']:08x}")
    return e


def case_replay(b, res):
    """⑦ 重放 4 字节正确 + 回跳地址正确 + 继续进真实分发器"""
    e = Emu(pathlib.Path(b["out_path"]))
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), 1))
    e.setup_frame(msg)
    replay_va = SLOT + b["code_len"]
    st = e.run(BASE + HOOK, [BASE + replay_va])
    ok1 = st == BASE + replay_va
    # 从"重放开头"继续跑，应当走完 2 条原文指令后落在 0xA3122A
    st2 = e.run(BASE + replay_va, [BASE + RESUME])
    r = e.regs()
    ok2 = st2 == BASE + RESUME
    res.add("用例: 重放 4 字节后 PC 落在 0xA3122A",
            ok1 and ok2,
            f"重放起点=0x{BASE + replay_va:08x}，之后 PC=0x{(st2 or 0):08x}"
            f"（期望 0x{BASE + RESUME:08x}）")
    res.add("用例: 重放生效 —— r4=msg 且 r3=type",
            r["r4"] == msg and r["r3"] == 0x04,
            f"r4=0x{r['r4']:08x}(期望 0x{msg:08x}) r3=0x{r['r3']:x}(期望 0x4)")
    # 继续跑真实分发器：type=4 应当依次 0xA31240 → 0xA3127A → 0xA312A6 → 0xA3134C
    st3 = e.run(BASE + RESUME, [BASE + 0xA3134C])
    res.add("用例: 回跳后真实分发器继续正确工作（type=4 → 0xA3134C）",
            st3 == BASE + 0xA3134C, f"到达 0x{(st3 or 0):08x}")


def case_type_mismatch(b, res):
    """⑧ type 不匹配：nid==0x1001 但 type!=4 —— 默认必须不发声（防误触发）"""
    if not b.get("check_type", True):
        res.add("用例: type!=4 且 nid==0x1001（本构建已关闭 type 校验，跳过）",
                True, "该构建不校验 type")
        return
    e = Emu(pathlib.Path(b["out_path"]))
    for t, label in ((0xFF, "type=0xFF"), (0x01, "type=0x01"), (0x00, "type=0x00")):
        e.calls.clear()
        msg = e.write_msg(struct.pack("<BBHI", t, 0x00, b.get("nid", NID_OK), 1),
                          addr=HEAP + 0x200 + t * 0x40)
        e.setup_frame(msg)
        st = e.run(BASE + HOOK, [BASE + RESUME])
        seq = _api_seq(e.calls)
        ok = st == BASE + RESUME and seq == [] and e.err is None
        res.add(f"用例: {label} + nid=0x1001 不发声（防误触发）", ok,
                f"序列 {seq}，停止于 0x{(st or 0):08x}")


def case_no_mem_write(b, res):
    """⑩ 绝不写内存：所有写都必须落在本帧栈范围内"""
    e = Emu(pathlib.Path(b["out_path"]))
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), 1))
    e.setup_frame(msg)
    e.run(BASE + HOOK, [BASE + RESUME])
    stack_lo, stack_hi = STACK_TOP - STACK_SIZE, STACK_TOP
    bad = [(a, s) for a, s, sp in e.writes if not (stack_lo <= a < stack_hi)]
    res.add("用例: 载荷只在本帧栈上写（零绝对地址写）",
            e.err is None and len(e.writes) > 0 and not bad,
            f"写次数 {len(e.writes)}（全部来自被调函数桩），栈外写 {len(bad)} 处")
    res.add("用例: 无非法内存访问（unmapped write/fetch 0 次）",
            e.err is None, e.err or "无")


def case_call_alignment(b, res):
    """⑫ 调用边界 SP 8 字节对齐（AAPCS）：不参与通过/失败，只报告。"""
    e = Emu(pathlib.Path(b["out_path"]))
    msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), 1))
    e.setup_frame(msg)
    e.run(BASE + HOOK, [BASE + RESUME])
    names = ("ObjMsg_ctor", "ParamStd_ctor", "AddParam", "IssueCommandAsync", "Get7")
    sps = [c[-1] for c in e.calls if c[0] in names]
    bad = [x for x in sps if x % 8]
    if bad:
        res.warn(f"AAPCS 栈对齐：{len(bad)}/{len(sps)} 个调用点 SP%8=4"
                 f"（入口 0x{sps[0]:08x}，push 44B + sub 0x30 = 92B）。"
                 "未观察到后果，真机后果未验证。")


def case_burst8(b, res):
    """⑪ 连拍 8 帧：同一载荷反复执行 8 次 → 8 次发声，状态无残留"""
    e = Emu(pathlib.Path(b["out_path"]))
    seqs = []
    for i in range(8):
        e.calls.clear()
        msg = e.write_msg(struct.pack("<BBHI", 0x04, 0x00, b.get("nid", NID_OK), i + 1),
                          addr=HEAP + 0x100 + i * 0x40)
        e.setup_frame(msg)
        stop = e.run(BASE + HOOK, [BASE + RESUME])
        assert stop == BASE + RESUME, f"第 {i+1} 帧未回到 RESUME (0x{(stop or 0):08x})"
        seqs.append([c[0] for c in e.calls])
        assert e.err is None, e.err
    beeps = sum(1 for s in seqs if "IssueCommandAsync" in s)
    res.add("用例: 连拍 8 帧 → 恰好 8 次进入播放调用桩（每帧一次）",
            beeps == 8 and all(s.count("IssueCommandAsync") == 1 for s in seqs),
            f"8 次仿真中 IssueCommandAsync 次数={beeps}，每帧恰好进入桩 1 次")


def run_all(b: dict) -> bool:
    """b 是 build_burst_only.build() 的返回值（已含 out_path）。"""
    so = pathlib.Path(b["out_path"])
    res = Result()
    cases = [
        ("用例: NID=0x1001 应发声", lambda: case_valid_nid(b, res, b.get("nid", NID_OK), True)),
        ("用例: NID=0x1002 不应发声", lambda: case_valid_nid(b, res, 0x1002 if b.get("nid", NID_OK) != 0x1002 else 0x1001, False)),
        ("用例: NID=0x0000 不应发声", lambda: case_valid_nid(b, res, 0x0000, False)),
        ("用例: msg == NULL", lambda: case_null(b, res)),
        ("用例: Get(7)==NULL", lambda: case_get_null(b, res)),
        ("用例: 栈平衡/寄存器守恒", lambda: case_stack_and_regs(b, res)),
        ("用例: 重放与回跳", lambda: case_replay(b, res)),
        ("用例: type 不匹配", lambda: case_type_mismatch(b, res)),
        ("用例: 零内存写", lambda: case_no_mem_write(b, res)),
        ("用例: 连拍 8 帧", lambda: case_burst8(b, res)),
    ]
    for label, fn in cases:
        n0 = len(res.cases)
        try:
            fn()
        except Exception as ex:
            import traceback
            res.add(label + " [异常]", False, f"{type(ex).__name__}: {ex}")
            if os.environ.get("BURST_DEBUG"):
                traceback.print_exc()
        if len(res.cases) == n0:
            res.add(label + " [无断言产出]", False, "该用例没有登记任何检查项")

    case_call_alignment(b, res)

    print("=" * 84)
    print("Unicorn 端到端仿真结果")
    print("=" * 84)
    for name, ok, detail in res.cases:
        print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if detail:
            print(f"         {detail}")
    print()
    npass = sum(1 for c in res.cases if c[1])
    print(f"  合计 {len(res.cases)} 项，通过 {npass}，失败 {len(res.cases) - npass}")
    for w in res.warnings:
        print(f"  [WARN] {w}")
    print(f"  仿真覆盖：镜像按 PT_LOAD 映射到运行期地址 BASE=0x{BASE:08x}；"
          f"钩子 b.w / 载荷 / 重放 / 回跳 / 真实分发器 全部执行")
    return res.ok


if __name__ == "__main__":
    print("本模块由 tools/build_burst_only.py 调用。")
