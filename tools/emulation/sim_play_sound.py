#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sim_play_sound.py —— 用 Unicorn 离线仿真 libObj.so 的「请求播放 soundId」路径
================================================================================
只做静态/离线：不连相机、不改相机、不写 /usr。

用法
----
  python sim_play_sound.py                 # 跑全部场景
  python sim_play_sound.py --scenario ok3  # 只跑某个场景
  python sim_play_sound.py --trace         # 打开逐指令/函数级 trace（很啰嗦）
  python sim_play_sound.py --max-insn 200000

环境
----
  unicorn (>=2.1)  —— 用系统 python： python

被仿真的东西 / 被桩掉的东西
--------------------------
  真的执行：libObj.so 里的机器码（Thumb-2），包括
      FUN_002a3b74 (ObjSystemSound vt[9]，msgId==0x1120 处理)
      FUN_002a1308 (GetParameter<uint32>)
      FUN_002a353c (AcquiredRsrcBeforeBeepPlay)
      FUN_002a2ef8 (GetParameter<int32>)
      FUN_002a6114 (ExecCmdFactoryComponent::GetCommand)
      FUN_002a5720 / FUN_002a1b24 / ...
  做桩：所有 PLT 导入（MWF/框架层，实现在别的 .so 里）—— ObjMsg 的构造/析构/
        GetMessageId/GetParam/AddParam/SetCateIdMsgId、Param 的 GetType/GetValue、
        BizRsrcAcsr::Acquire、GlobalAccessor::SendAppEvent、operator new/delete、
        memset/memcpy、BizPrintf 等。桩会记录调用序列。

注意：ObjMsg / Param 的**内存布局属于框架模块**（不在 libObj 里），所以本仿真用
      "逻辑消息"（本项目自己定义布局）+ 拦截访问器的方式；libObj 侧的校验逻辑
      （类型检查、soundId 上限、资源返回值分支）都是真码在跑。
"""
import os, sys, struct, argparse

try:
    from unicorn import *
    from unicorn.arm_const import *
except ImportError:
    sys.stderr.write("需要 unicorn：用系统 python 运行本脚本\n")
    raise

# ----------------------------------------------------------------------------- 常量
SO = os.path.join(os.environ.get("LAB_ROOT", "."), "work", "pw-test", "libObj.so")
BASE = 0x10000                       # Ghidra imageBase：Ghidra 地址 = 文件 VA + 0x10000

STACK_BASE = 0x70000000
STACK_SIZE = 0x00200000
HEAP_BASE = 0x60000000
HEAP_SIZE = 0x00400000
TRAMP_BASE = 0x50000000
RETMAGIC = 0x5EED0000                # 仿真返回哨兵地址

# 关键函数（Ghidra 地址）
A_VT9 = 0x2a3b74                     # ObjSystemSound vt[9]  (VA 0x1a3b74)
A_GETPARAM_U32 = 0x2a1308            # FUN_002a1308
A_ACQ_BEFORE_BEEP = 0x2a353c         # AcquiredRsrcBeforeBeepPlay
A_READSOUNDFILE = 0x2a53bc           # SystemSoundData::ReadSoundFile
A_BEGINSOUND = 0x2a5838
A_GETCOMMAND = 0x2a6114              # ExecCmdFactoryComponent::GetCommand
A_SYS_DATA_QUERY = 0x2a5720
A_EVTLOG = 0x2a1b24

# libObj 内部的日志/遥测助手：只用于"是否打印"，对控制流无影响 —— 桩掉
#   0x1145ac: `ldr r3,[pc]; add r3,pc; ldr r3,[r3,r2]; ldr r0,[r3]` = **(TU_base+off)
#             = 取"调试打印等级"全局；真实运行时非空，本仿真里是 0 -> 会空指针
#   0x2a1b24: 事件日志（AvbbcBaseClassLog）；真实运行时全局非空
INTERNAL_STUBS = {
    0x1145ac: ('DebugPrintLevel', 0),
    0x2a1b24: ('EventLog', 1),
}

# 场景
SCENARIOS = {
    # name            msgId    param       acq_ret_17d  acq_ret_195  note
    "ok3":        dict(msgId=0x1120, pid=0x1000, ptype=8, pval=3,    acq1=0,      acq2=0),
    "ok3_9003":   dict(msgId=0x1120, pid=0x1000, ptype=8, pval=3,    acq1=0x9003, acq2=0x9003),
    "bad_id":     dict(msgId=0x1120, pid=0x1000, ptype=8, pval=0x40, acq1=0,      acq2=0),
    "no_param":   dict(msgId=0x1120, pid=0x1000, ptype=None, pval=0, acq1=0,      acq2=0),
    "bad_type":   dict(msgId=0x1120, pid=0x1000, ptype=7, pval=3,    acq1=0,      acq2=0),
    "other_mid":  dict(msgId=0x1121, pid=0x1000, ptype=8, pval=3,    acq1=0,      acq2=0),
    "acq_fail":   dict(msgId=0x1120, pid=0x1000, ptype=8, pval=3,    acq1=0x9001, acq2=0),
    "acq2_fail":  dict(msgId=0x1120, pid=0x1000, ptype=8, pval=3,    acq1=0,      acq2=0x9001),
}


# ----------------------------------------------------------------------------- ELF
class ELF:
    def __init__(self, path):
        self.d = open(path, 'rb').read()
        d = self.d
        assert d[:4] == b'\x7fELF' and d[4] == 1 and d[5] == 1, "需要 ELF32 LE"
        e_phoff, = struct.unpack_from('<I', d, 0x1c)
        e_shoff, = struct.unpack_from('<I', d, 0x20)
        e_phentsize, e_phnum = struct.unpack_from('<HH', d, 0x2a)
        e_shentsize, e_shnum, e_shstrndx = struct.unpack_from('<HHH', d, 0x2e)
        self.segs = []
        for i in range(e_phnum):
            o = e_phoff + i * e_phentsize
            t, off, va, pa, fsz, msz, fl, al = struct.unpack_from('<8I', d, o)
            if t == 1:
                self.segs.append(dict(off=off, va=va, fsz=fsz, msz=msz, fl=fl))
        self.sh = []
        for i in range(e_shnum):
            o = e_shoff + i * e_shentsize
            nm, ty, fl, ad, of, sz, lk, inf, al, es = struct.unpack_from('<10I', d, o)
            self.sh.append(dict(name=nm, addr=ad, off=of, size=sz, link=lk, entsize=es))
        stro = self.sh[e_shstrndx]['off']
        strsz = self.sh[e_shstrndx]['size']
        shstr = d[stro:stro+strsz]
        for s in self.sh:
            e = shstr.find(b'\0', s['name'])
            s['sname'] = shstr[s['name']:e].decode('latin1')

    def sec(self, n):
        for s in self.sh:
            if s['sname'] == n:
                return s
        return None

    def dynsym_name(self, idx):
        sym = self.sec('.dynsym'); st = self.sec('.dynstr')
        o = sym['off'] + idx * 16
        st_name, = struct.unpack_from('<I', self.d, o)
        e = self.d.find(b'\0', st['off'] + st_name)
        return self.d[st['off']+st_name:e].decode('latin1')

    def imports(self):
        """返回 [(got_va, mangled_name)]，来自 .rel.plt（JUMP_SLOT）——不依赖 PLT 反汇编"""
        rel = self.sec('.rel.plt')
        rels = []
        for i in range(rel['size'] // 8):
            r_off, r_info = struct.unpack_from('<II', self.d, rel['off'] + i*8)
            rels.append((r_off, self.dynsym_name(r_info >> 8)))
        return rels

    def relocs(self):
        """返回 [(va, type, symbol_or_None)]，.rel.dyn"""
        rel = self.sec('.rel.dyn')
        out = []
        for i in range(rel['size'] // 8):
            r_off, r_info = struct.unpack_from('<II', self.d, rel['off'] + i*8)
            t = r_info & 0xff
            sym = (r_info >> 8)
            out.append((r_off, t, sym))
        return out


# ----------------------------------------------------------------------------- 仿真器
class Sim:
    def __init__(self, elf, scenario, trace=False, max_insn=400000, verbose=True):
        self.elf = elf
        self.sc = scenario
        self.trace = trace
        self.max_insn = max_insn
        self.verbose = verbose
        self.uc = Uc(UC_ARCH_ARM, UC_MODE_THUMB | UC_MODE_LITTLE_ENDIAN)
        self.rel_plt = elf.imports()          # [(got_va, name)]
        self.heap_ptr = HEAP_BASE + 0x1000
        self.calls = []
        self.events = []
        self.stub_hits = {}
        self.acquire_args = []
        self.insn_count = 0
        self.last_pcs = []
        self._map_image()
        self._install_trampolines()
        self._install_hooks()
        self._prepare_state()

    # ---------- 内存 ----------
    def _map_image(self):
        PAGE = 0x1000
        for s in self.elf.segs:
            start = BASE + s['va']
            lo = start & ~(PAGE-1)
            hi = (start + s['msz'] + PAGE - 1) & ~(PAGE-1)
            perms = UC_PROT_READ
            if s['fl'] & 2:
                perms |= UC_PROT_WRITE
            if s['fl'] & 1:
                perms |= UC_PROT_EXEC
            self.uc.mem_map(lo, hi - lo, perms)
            self.uc.mem_write(start, self.elf.d[s['off']:s['off']+s['fsz']])
        # 栈 / 堆 / 哨兵
        self.uc.mem_map(STACK_BASE, STACK_SIZE, UC_PROT_READ | UC_PROT_WRITE)
        self.uc.mem_map(HEAP_BASE, HEAP_SIZE, UC_PROT_READ | UC_PROT_WRITE | UC_PROT_EXEC)
        self.uc.mem_map(RETMAGIC, 0x1000, UC_PROT_READ | UC_PROT_EXEC)
        self.uc.mem_write(RETMAGIC, b'\x70\x47' * 8)          # bx lr
        self.uc.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)
        # 应用重定位（R_ARM_RELATIVE=23 / R_ARM_ABS32=2）：值 += BASE
        nrel = 0
        for va, t, sym in self.elf.relocs():
            if t in (2, 23):
                g = va + BASE
                try:
                    v = struct.unpack('<I', self.uc.mem_read(g, 4))[0]
                except UcError:
                    continue
                self.w32(g, (v + BASE) & 0xffffffff)
                nrel += 1
        self.reloc_count = nrel

    # ---------- GOT -> 蹦床（彻底避开 PLT 解析） ----------
    def _install_trampolines(self):
        self.tramp_base = TRAMP_BASE
        n = len(self.rel_plt)
        size = ((n * 8) + 0xfff) & ~0xfff
        self.uc.mem_map(TRAMP_BASE, size, UC_PROT_READ | UC_PROT_EXEC)
        self.tramp_of = {}          # trampoline addr -> import name
        self.got_of = {}            # name -> got va
        for i, (got_va, name) in enumerate(self.rel_plt):
            t = TRAMP_BASE + i * 8
            self.uc.mem_write(t, b'\x70\x47')            # bx lr (Thumb)
            self.tramp_of[t | 1] = name
            self.got_of.setdefault(name, got_va)
            self.w32(got_va + BASE, t | 1)               # GOT 槽 -> 蹦床
        self.tramp_end = TRAMP_BASE + size

    def alloc(self, size, align=8):
        p = (self.heap_ptr + align - 1) & ~(align-1)
        self.heap_ptr = p + size + 0x40
        if self.heap_ptr >= HEAP_BASE + HEAP_SIZE:
            raise RuntimeError("fake heap exhausted")
        return p

    def w32(self, a, v): self.uc.mem_write(a, struct.pack('<I', v & 0xffffffff))
    def r32(self, a): return struct.unpack('<I', self.uc.mem_read(a, 4))[0]
    def wbytes(self, a, b): self.uc.mem_write(a, b)

    # ---------- 桩 ----------
    def _mk_ret_stub(self):
        """在堆里造一个 'bx lr' 的假函数，用于假虚表项"""
        a = self.alloc(8, 4)
        self.wbytes(a, b'\x70\x47')
        return a | 1

    def _prepare_state(self):
        self.ret_stub = self._mk_ret_stub()
        # 假 EventSender / 假对象统一用"vt = 全 ret_stub"的假表
        self.fake_vt = self.alloc(0x40, 4)
        for i in range(16):
            self.w32(self.fake_vt + i*4, self.ret_stub)
        # ---- 假 Param 对象 ----
        # 真实布局线索：FUN_00126a00 (Ghidra 0x126a00) = `ldr r3,[r0,#4]; ldr r0,[r3]`
        #   => param+4 是"描述符/虚表"指针，其 [0] = 类型号。
        # 这里照此摆放，让 libObj 的类型校验是真码在跑。
        self.param_of = {}     # pid -> (addr, type, value)
        sc = self.sc
        if sc['ptype'] is not None:
            p = self.alloc(0x10)
            desc = self.alloc(0x10)
            self.w32(desc + 0, sc['ptype'])
            self.w32(p + 4, desc)
            self.param_of[sc['pid']] = (p, sc['ptype'], sc['pval'])
        # ---- 假 ObjMsg ----
        self.msg = self.alloc(0x80)
        self.msg_id = sc['msgId']
        # ---- 假 ObjSystemSound 对象 ----
        self.obj = self.alloc(0x400)
        self.w32(self.obj + 0x00, self.fake_vt)             # 对象自身虚表（不会被本仿真用）
        self.sender = self.alloc(0x20)                       # 假 EventSender (+0x18)
        self.w32(self.sender, self.fake_vt)
        self.w32(self.obj + 0x18, self.sender)
        # 注意：+0x78 (GlobalAccessor) 与 +0x204 (ExecCmdFactoryComponent) 是**内嵌子对象**——
        # 调用方传的是 this+0x78 / this+0x204 这个"地址"，所以该地址上要放虚表指针。
        self.w32(self.obj + 0x78, self.fake_vt)
        self.w32(self.obj + 0x204, self.fake_vt)
        self.obj_220 = self.alloc(0x2600)                    # 假 SystemSoundData（对象）
        self.w32(self.obj + 0x220, self.obj_220)
        self.obj_224 = self.alloc(0x20); self.w32(self.obj_224, self.fake_vt)
        self.w32(self.obj + 0x224, self.obj_224)
        self.obj_234 = self.alloc(0x30); self.w32(self.obj_234, self.fake_vt)
        self.w32(self.obj + 0x234, self.obj_234)             # 假 BizRsrcAcsr(0x17d)
        self.obj_238 = self.alloc(0x30); self.w32(self.obj_238, self.fake_vt)
        self.w32(self.obj + 0x238, self.obj_238)             # 假 BizRsrcAcsr(0x195)
        self.acq_seq = []

    def log(self, *a):
        if self.verbose:
            print(*a)

    def func_of_sym(self, pc):
        """把 PC 归到最近的已知符号/观测点/蹦床"""
        pcm = pc & ~1
        if self.tramp_base <= pcm < self.tramp_end:
            return '<import ' + (self.tramp_of.get(pc) or self.tramp_of.get(pcm) or '?') + '>'
        if pcm in INTERNAL_STUBS:
            return '<int-stub ' + INTERNAL_STUBS[pcm][0] + '>'
        if pcm in self.watch:
            return self.watch[pcm]
        return ''

    # ---------- 钩子 ----------
    def _install_hooks(self):
        uc = self.uc
        self.watch = {
            A_VT9: 'FUN_002a3b74  ObjSystemSound vt[9]',
            A_GETPARAM_U32: 'FUN_002a1308  GetParameter<uint32>',
            A_ACQ_BEFORE_BEEP: 'FUN_002a353c  AcquiredRsrcBeforeBeepPlay',
            A_READSOUNDFILE: 'FUN_002a53bc  SystemSoundData::ReadSoundFile',
            A_BEGINSOUND: 'FUN_002a5838  SystemSoundData::BeginSound',
            A_GETCOMMAND: 'FUN_002a6114  ExecCmdFactory::GetCommand',
            A_SYS_DATA_QUERY: 'FUN_002a5720  SysSndData query(soundId)',
            A_EVTLOG: 'FUN_002a1b24  eventlog',
        }
        uc.hook_add(UC_HOOK_CODE, self._hook_code)
        uc.hook_add(UC_HOOK_MEM_READ_UNMAPPED | UC_HOOK_MEM_WRITE_UNMAPPED |
                    UC_HOOK_MEM_FETCH_UNMAPPED, self._hook_badmem)

    def _hook_badmem(self, uc, access, address, size, value, user):
        self.log("[BADMEM] access=%d addr=0x%x size=%d pc=0x%x" %
                 (access, address, size, uc.reg_read(UC_ARM_REG_PC)))
        self.events.append(("BADMEM", address, uc.reg_read(UC_ARM_REG_PC)))
        uc.emu_stop()

    def _hook_code(self, uc, address, size, user):
        self.insn_count += 1
        if self.insn_count > self.max_insn:
            self.events.append(("MAXINSN", address, 0))
            uc.emu_stop()
            return
        pcm = address & ~1
        self.last_pcs.append(address)
        if len(self.last_pcs) > 64:
            self.last_pcs.pop(0)

        # 返回哨兵
        if address == RETMAGIC:
            self.events.append(("RET", uc.reg_read(UC_ARM_REG_R0), 0))
            uc.emu_stop()
            return

        # 观测点
        if pcm in self.watch:
            self.events.append(("ENTER", pcm, uc.reg_read(UC_ARM_REG_R0)))
            if self.trace:
                self.log("  -> enter 0x%06x  %s  (r0=0x%x r1=0x%x)" %
                         (pcm, self.watch[pcm], uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1)))

        # 导入蹦床
        if self.tramp_base <= pcm < self.tramp_end:
            nm = self.tramp_of.get(address) or self.tramp_of.get(pcm) or self.tramp_of.get(pcm | 1)
            self._do_import(uc, address, nm or '?')
            return

        # libObj 内部的"日志/遥测"小函数：只影响打印，不影响控制流 -> 强制返回
        if pcm in INTERNAL_STUBS:
            name, rv = INTERNAL_STUBS[pcm]
            self.stub_hits['<int>' + name] = self.stub_hits.get('<int>' + name, 0) + 1
            uc.reg_write(UC_ARM_REG_R0, rv)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))
            return

    # ---------- 各导入桩 ----------
    def _do_import(self, uc, addr, nm):
        self.stub_hits[nm] = self.stub_hits.get(nm, 0) + 1
        r0, r1, r2, r3 = (uc.reg_read(UC_ARM_REG_R0), uc.reg_read(UC_ARM_REG_R1),
                          uc.reg_read(UC_ARM_REG_R2), uc.reg_read(UC_ARM_REG_R3))
        n = nm
        self.calls.append((addr, n, r0, r1, r2, r3))
        if self.trace:
            self.log("     [stub] %-70s r0=0x%x r1=0x%x r2=0x%x r3=0x%x" % (n, r0, r1, r2, r3))

        def ret(v=0):
            uc.reg_write(UC_ARM_REG_R0, v)
            uc.reg_write(UC_ARM_REG_PC, uc.reg_read(UC_ARM_REG_LR))

        if 'ObjMsgC1Ejj' in n or 'ObjMsgC1Ev' in n or 'ObjMsgD1Ev' in n or 'ObjMsgD2Ev' in n:
            return ret(r0)
        if 'ObjMsg14SetCateIdMsgId' in n:
            self.msg_id = r2
            self.events.append(("SetCateIdMsgId", r1, r2))
            if self.trace: self.log("        SetCateIdMsgId(0x%x, 0x%x)" % (r1, r2))
            return ret(r0)
        if 'ObjMsg8AddParam' in n:
            self.events.append(("AddParam", r1, r2))
            if self.trace: self.log("        AddParam(pid=0x%x, param=0x%x)" % (r1, r2))
            return ret(r0)
        if 'ObjMsg8GetParam' in n:
            # GetParam(pid) -> Param* 或 0
            hit = self.param_of.get(r1)
            return ret(hit[0] if hit else 0)
        if 'ObjMsg12GetMessageId' in n or 'GetMessageId' in n:
            return ret(self.msg_id)
        if 'Param11GetType' in n or 'Param7GetType' in n:
            for pid, (pa, ty, val) in self.param_of.items():
                if pa == r0:
                    return ret(ty)
            return ret(0)
        if 'GetValue' in n:
            for pid, (pa, ty, val) in self.param_of.items():
                if pa == r0:
                    return ret(val)
            return ret(0)
        if 'BizPrintf' in n:
            return ret(0)
        if 'Acquire' in n:
            self.acquire_args.append((r0, r1, r2, r3))
            idx = len(self.acquire_args) - 1
            v = self.sc['acq1'] if idx == 0 else self.sc['acq2']
            self.events.append(("Acquire", idx, v))
            return ret(v)
        if 'SendAppEvent' in n:
            self.events.append(("SendAppEvent", r0, r1))
            return ret(0)
        if '_Znwj' in n or 'operator_new' in n or n.endswith('_Znwj'):
            return ret(self.alloc(max(r0, 0x10)))
        if '_Znaj' in n:
            return ret(self.alloc(max(r0, 0x10)))
        if '_ZdlPv' in n or '_ZdaPv' in n:
            return ret(0)
        if 'memset' in n:
            self.wbytes(r0, b'\0' * r2)
            return ret(r0)
        # 外部模块里定义的"基类构造器"：真实实现会把 vptr 设成该模块里的基类虚表。
        # 本仿真里给它一个"全 bx lr"的假虚表，保证不空指针；随后 libObj 自己的派生构造器
        # 会用本模块 .data.rel.ro 里的真虚表覆盖它。
        if ('C1E' in n or 'C2E' in n or n.endswith('C1Ev') or n.endswith('C2Ev')) and 'ObjMsg' not in n:
            if r0:
                self.w32(r0, self.fake_vt)
            self.events.append(("EXT_BASE_CTOR", r0, 0))
            return ret(r0)
        if 'memcpy' in n:
            self.wbytes(r0, bytes(self.uc.mem_read(r1, r2)))
            return ret(r0)
        if 'strlen' in n:
            b = bytes(self.uc.mem_read(r0, 4096))
            return ret(b.find(b'\0'))
        if 'snprintf' in n:
            return ret(0)
        if 'startThread' in n or 'Thread' in n or 'thread' in n:
            return ret(0)
        # 未分类：记录并返回 0（不中断，保持仿真继续，最后统一汇报）
        self.events.append(("UNSTUBBED", addr, r0))
        return ret(0)

    # ---------- 运行 ----------
    def run(self, entry, r0, r1=0, label=''):
        uc = self.uc
        self.insn_count = 0
        lr = RETMAGIC | 1
        uc.reg_write(UC_ARM_REG_R0, r0)
        uc.reg_write(UC_ARM_REG_R1, r1)
        uc.reg_write(UC_ARM_REG_LR, lr)
        uc.reg_write(UC_ARM_REG_SP, STACK_BASE + STACK_SIZE - 0x1000)
        try:
            uc.emu_start(entry | 1, RETMAGIC, timeout=0, count=self.max_insn)
            ok = True
            err = None
        except UcError as e:
            ok = False
            err = str(e)
        r0v = uc.reg_read(UC_ARM_REG_R0)
        pcv = uc.reg_read(UC_ARM_REG_PC)
        return dict(label=label, ok=ok, err=err, r0=r0v, pc=pcv,
                    insn=self.insn_count, events=list(self.events),
                    pcs=list(self.last_pcs), last_calls=list(self.calls[-12:]))


# ----------------------------------------------------------------------------- 主流程
def summarize(res, sim):
    ev = res['events']
    acquire = [e for e in ev if e[0] == 'Acquire']
    enters = [e[1] for e in ev if e[0] == 'ENTER']
    names = []
    for a in enters:
        if not names or names[-1] != a:
            names.append(a)
    def nm(a):
        return sim.watch.get(a, hex(a))
    seq = ' -> '.join(nm(a).split()[0] for a in names)
    print("   结果: ok=%s err=%s r0=0x%x insn=%d" % (res['ok'], res['err'], res['r0'] & 0xffffffff, res['insn']))
    print("   进入过的函数: " + seq)
    print("   Acquire 调用: " + ('; '.join('#%d -> ret=0x%x' % (a[1], a[2]) for a in acquire) or '无'))
    if res.get('last_calls'):
        print("   最后 12 个外部调用:")
        for a, n, r0, r1, r2, r3 in res['last_calls']:
            print("        %-62s r0=0x%x r1=0x%x r2=0x%x r3=0x%x" % (n[:62], r0, r1, r2, r3))
    if not res['ok'] and res.get('pcs'):
        print("   崩溃前最后 16 条指令 PC:")
        for p in res['pcs'][-16:]:
            f = sim.func_of_sym(p)
            print("        0x%08x  %s" % (p, f))
    for k in ('SetCateIdMsgId', 'AddParam', 'SendAppEvent', 'BADMEM', 'MAXINSN', 'RET'):
        got = [e for e in ev if e[0] == k]
        if got:
            print("   %s: %d 次%s" % (k, len(got), ('  例: ' + str(got[:4])) if k in ('BADMEM', 'MAXINSN') else ''))
    return res


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--so', default=SO)
    ap.add_argument('--scenario', default=None)
    ap.add_argument('--trace', action='store_true')
    ap.add_argument('--max-insn', type=int, default=400000)
    ap.add_argument('--mode', default='inline', choices=['inline', 'post'],
                    help='inline = 直接调 vt[9]（同步）；post = 只调 *(obj+0x18)->vt[3]（异步投递）')
    args = ap.parse_args()

    elf = ELF(args.so)
    print("libObj: %d bytes, %d PT_LOAD" % (len(elf.d), len(elf.segs)))

    todo = [args.scenario] if args.scenario else list(SCENARIOS)
    for name in todo:
        sc = dict(SCENARIOS[name])
        print("\n================ 场景 %s : msgId=0x%x param(0x%x)=type%s val=%d acq1=%s acq2=%s ================" %
              (name, sc['msgId'], sc['pid'], sc['ptype'], sc['pval'], hex(sc['acq1']), hex(sc['acq2'])))
        sim = Sim(elf, sc, trace=args.trace, max_insn=args.max_insn)
        if args.mode == 'inline':
            res = sim.run(A_VT9, sim.obj, sim.msg, label='vt9')
        else:
            # 异步投递：把消息交给假 EventSender 的 vt[3]（真实实现在框架模块里，这里只能验证"转发发生了"）
            vt = sim.r32(sim.sender)
            f = sim.r32(vt + 0xc)
            print("   EventSender@0x%x vt[3]=0x%x（本仿真里是 ret 桩）" % (sim.sender, f))
            res = sim.run(f, sim.sender, sim.msg, label='post')
        summarize(res, sim)


if __name__ == '__main__':
    main()


