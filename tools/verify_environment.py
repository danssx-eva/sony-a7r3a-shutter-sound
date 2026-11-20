#!/usr/bin/env python3
"""verify_environment —— 在**你自己的相机上**验证本项目记录的数据是否适用。

**这个工具只做只读操作。** 它不写内存、不写文件、不改任何设置。
它的存在理由只有一个：本项目的所有地址/字节值**只在一台设备上验证过**
（ILCE-7RM3A，fw 1.00，非国行）。换一台机器、换一个区域版本、
甚至只是不同批次的板子，这些数字都可能不成立。

**先验证，再操作。** 不匹配就不要应用补丁。

用法
----
    python tools/verify_environment.py --check-all
    python tools/verify_environment.py --check cp_recv
    python tools/verify_environment.py --dump-info
    python tools/verify_environment.py --list
    python tools/verify_environment.py --check-all --json
    python tools/verify_environment.py --check-all --no-backup   # 跳过需要二次认证的检查

前置
----
    · 相机 USB 连接 → 菜单选「海量存储器」
    · Sony-PMCA-RE 已 clone 到 vendor/Sony-PMCA-RE（或设 PMCA_DIR）
    · 音频检查不需要相机也可单独跑：--check sound_format --file <某个 .bin>

输出示例
--------
    [1/6] 相机连接 ................ [OK]   im.elf pid=155，模块基址已读取
    [2/6] libObj.so 指纹 ........... [OK]   原厂 f1351204…
    [3/6] CP 收包循环钩点 ......... [OK]   原厂 7c692378（与记录一致）
    [4/6] 音频信号属性表 .......... [!!]   不匹配（你的固件可能不同）
    [5/6] 音效文件格式 ............ [OK]   Caution.bin 8640B，可解析
    [6/6] Backup 属性 .............. [OK]   soundId 0x07 音量=7

    结论：5/6 匹配。1 项不匹配 → 不建议应用本项目补丁。

退出码：0 = 全部匹配；1 = 有项目不匹配；2 = 环境/连接问题（未完成验证）。
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE / "camera"))

# ---------------------------------------------------------------------------
# 本项目记录的"期望值"（全部来自对同一台设备的观察）
# 这些不是固件规范，只是一次观察记录，换个设备就可能是别的数字。
# ---------------------------------------------------------------------------
RECORDED = {
    "device": "ILCE-7RM3A / fw 1.00 / 非国行",
    "pid": 155,
    "libobj_base": 0x05DCA000,
    "libobj_sha_orig": "f1351204d2dd1c4033d427e09e7848fbbff0dd577abb205e00ef97bb4e6b81ed",
    # 本项目可能得到过的补丁后状态。载荷里 soundId 不同，整文件 SHA 就不同。
    "libobj_sha_patched": {
        "d45ca8d7821b7a771555faab179ec268316d75acb4cb1a0ee8bae70453730e6a":
            "soundId 0x04 FORCUSLOCK 载荷（第一版）",
        "d80aa1e00b84f5f719eb5e427bf760a06b81b6401a7550edada355d8f2d4a960":
            "soundId 0x07 CAUTION 载荷（当前版本，自定义咔嚓声）",
    },
    # CP 收包循环钩点（fileVA 0xA31226）：原厂 4 字节 / 本项目补丁后的 4 字节
    "cp_hook_va": 0xA31226,
    "cp_hook_orig": "7c 69 23 78",
    "cp_hook_patched": "63 f7 57 9b",
    # 单拍钩点（fileVA 0x3C039E）
    "single_hook_va": 0x3C039E,
    "single_hook_orig": "f8 b5 10 20",
    # 「音频信号」属性表：相机侧运行期地址 = CautionConfig 基址 + 0x8139F8
    "caution_base": 0x15AC0000,
    "audio_props_off": 0x8139F8,
    "audio_props_propids": [0x00, 0x06, 0x0B, 0x0C, 0x0E, 0x14],
    "audio_proc_id": 0xA8,
    # 音效文件
    "sound_dir": "/usr/share/avsystemsound",
    "sound_files": {
        "ka": ("Dslr_Emnt_High_Shutter_Ka.bin", 256),
        "sha": ("Dslr_Emnt_High_Shutter_Sha.bin", 2944),
        "kasha": ("Dslr_Emnt_High_10FPS_Kasha.bin", 2944),
        "focuslock": ("Dslr_Emnt_High_FocusLock.bin", 3712),
        "caution": ("Dslr_Emnt_High_Caution.bin", 8640),
        "select": ("Dslr_Emnt_High_T_Select.bin", 2496),
    },
    # Backup 属性
    "bkid_volume_snd7": 0x002B0020,     # soundId 0x07 CAUTION 主通道音量，0..7
    "bkid_audio_signal": 0x01070026,    # 1=开 2=关
}


# ---------------------------------------------------------------------------
# 结果收集
# ---------------------------------------------------------------------------
class Report:
    def __init__(self) -> None:
        self.items: list[dict] = []

    def add(self, key: str, title: str, state: str, detail: str) -> None:
        # state: ok / mismatch / skip / error
        self.items.append({"key": key, "title": title, "state": state, "detail": detail})

    def print_all(self) -> None:
        mark = {"ok": "[OK]", "mismatch": "[!!]", "skip": "[--]", "error": "[EE]"}
        total = len(self.items)
        for i, it in enumerate(self.items, 1):
            print(f"[{i}/{total}] {it['title']:26s} {mark[it['state']]:6s} {it['detail']}")
        bad = [it for it in self.items if it["state"] in {"mismatch", "error"}]
        print()
        if bad:
            if all(it["key"] == "link" for it in bad):
                print(f"结论：无法连接相机（{bad[0]['detail']}）。")
                print("  其余检查没有执行，不能据此判断固件版本或地址。")
            else:
                print(f"结论：{total - len(bad)}/{total} 匹配。{len(bad)} 项不匹配 → "
                      "**不建议应用本项目补丁**，请先用 tools/sigscan.py 重新定位。")
        else:
            ok = [it for it in self.items if it["state"] == "ok"]
            if ok:
                print(f"结论：{len(ok)}/{total} 通过。仍请逐项阅读上面的细节，"
                      "并先做完整备份、写好回滚预案（docs/教程/06-持久化到闪存.md）后再说。")
            else:
                print("结论：没有拿到任何结论（检查被跳过或失败）。")

    def to_json(self) -> str:
        return json.dumps({"recorded": RECORDED, "items": self.items},
                          ensure_ascii=False, indent=2)


# ---------------------------------------------------------------------------
# 纯本地检查（不需要相机）
# ---------------------------------------------------------------------------
def check_sound_format(args: argparse.Namespace, rep: Report) -> None:
    """音效文件格式：大小必须是 32 的倍数，且首块能按预测器规则解出合理幅度。"""
    if args.file:
        files = [args.file]
        names = [args.file.name]
    else:
        files, names = [], []

    if not files:
        rep.add("sound_format", "音效文件格式", "skip",
                "未给 --file，且需要相机才能读（用 --check sound_format --file xxx.bin）")
        return

    for path, name in zip(files, names):
        data = path.read_bytes()
        if len(data) % 32:
            rep.add("sound_format", "音效文件格式", "mismatch",
                    f"{name}: {len(data)} 字节不是 32 的倍数 → 不是相机格式")
            continue
        # 解码首块，看控制字节与幅度是否合理
        control = data[0]
        steps = 1 << (control & 0x0F)
        predictor = bool(control & 0x10)
        last, vals = 0.0, []
        for b in data[1:32]:
            r = b if b < 128 else b - 256
            last = r * steps + (60 / 64 * last if predictor else 0.0)
            vals.append(round(last))
        ok = (max(abs(v) for v in vals) < 40000) and (0 <= control & 0x0F <= 9)
        detail = (f"{name}: {len(data)} 字节 = {len(data)//32} 块，"
                  f"首块控制字节 0x{control:02X}（指数 {control & 0x0F}，"
                  f"预测器 {'开' if predictor else '关'}）")
        rep.add("sound_format", "音效文件格式", "ok" if ok else "mismatch", detail)


# ---------------------------------------------------------------------------
# 相机侧检查（只读）
# ---------------------------------------------------------------------------
def _need_cam():
    try:
        import a7r3a_shell as A  # noqa: F401
    except Exception as exc:  # pragma: no cover
        raise SystemExit(f"无法导入 a7r3a_shell（{exc}）。请确认 tools/camera/ 完整。")
    return A


def camera_checks(args: argparse.Namespace, rep: Report) -> bool:
    """返回 True 表示连接成功（后面还能继续做相机侧检查）。"""
    A = _need_cam()

    state: dict[str, object] = {}

    def work(cam) -> None:
        pid = RECORDED["pid"]
        # 如果记录里的 pid 不在，试着按进程名找
        try:
            found = cam.pid_of("im.elf")
            if found:
                pid = found[0]
        except Exception:
            pass
        state["pid"] = pid
        try:
            maps = cam.maps()
        except Exception as exc:
            state["error"] = f"读 /proc/{pid}/maps 失败: {exc}"
            return
        state["maps"] = maps
        for soname, key in (
            ("libObj.so", "libobj_base"),
            ("CautionConfig.so", "caution_base"),
            ("viewUnified2.so", "viewUnified2_base"),
        ):
            state[key] = A.find_base(maps, soname)

        # ---- libObj 指纹 ----
        if state.get("libobj_base"):
            try:
                out = cam.sh("busybox sha256sum /usr/lib/libObj.so")
                m = re.search(r"([0-9a-f]{64})", out)
                state["libobj_sha"] = m.group(1) if m else None
            except Exception as exc:
                state["libobj_sha_err"] = str(exc)

            base = int(state["libobj_base"])
            try:
                state["cp_hook"] = cam.read_mem(base + RECORDED["cp_hook_va"], 4)
            except Exception as exc:
                state["cp_hook_err"] = str(exc)
            try:
                state["single_hook"] = cam.read_mem(base + RECORDED["single_hook_va"], 4)
            except Exception as exc:
                state["single_hook_err"] = str(exc)

        # ---- 音频信号属性表（结构指纹，比地址更抗版本差异）----
        base_c = state.get("caution_base")
        if base_c:
            try:
                raw = cam.read_mem(int(base_c) + RECORDED["audio_props_off"], 72)
                state["audio_props"] = raw
            except Exception as exc:
                state["audio_props_err"] = str(exc)

        # ---- 音效文件 ----
        try:
            ls = cam.sh(f"busybox ls -l {RECORDED['sound_dir']}")
            state["sound_ls"] = ls
            fname = RECORDED["sound_files"]["caution"][0]
            head = cam.sh(
                f"busybox dd if={RECORDED['sound_dir']}/{fname} bs=32 count=1 2>/dev/null "
                f"| busybox xxd -p"
            )
            state["sound_head"] = head
        except Exception as exc:
            state["sound_err"] = str(exc)

    try:
        A.run_on_camera(work)
    except SystemExit:
        raise
    except Exception as exc:
        rep.add("link", "相机连接", "error", f"连接/会话失败：{exc}")
        return False

    if state.get("error"):
        rep.add("link", "相机连接", "error", str(state["error"]))
        return False

    pid = state.get("pid")
    maps = state.get("maps") or []
    rep.add("link", "相机连接", "ok",
            f"im.elf pid={pid}，/proc/{pid}/maps {len(maps)} 段")

    # 基址与记录对照
    libobj_base = state.get("libobj_base")
    if not libobj_base:
        rep.add("libobj", "libObj.so 指纹", "mismatch", "没找到 libObj.so 的映射")
    else:
        same_base = int(libobj_base) == RECORDED["libobj_base"]
        sha = state.get("libobj_sha")
        if sha == RECORDED["libobj_sha_orig"]:
            rep.add("libobj", "libObj.so 指纹", "ok" if same_base else "mismatch",
                    f"原厂 SHA（与记录一致）"
                    + ("" if same_base else f"；但基址 0x{int(libobj_base):08X} ≠ 记录 "
                                             f"0x{RECORDED['libobj_base']:08X}"))
        elif sha in RECORDED["libobj_sha_patched"]:
            desc = RECORDED["libobj_sha_patched"][sha]
            rep.add("libobj", "libObj.so 指纹", "ok" if same_base else "mismatch",
                    f"已是本项目补丁后的 SHA（{sha[:8]}…，{desc}）"
                    + ("" if same_base else f"；但基址 0x{int(libobj_base):08X} ≠ 记录 "
                                             f"0x{RECORDED['libobj_base']:08X}"))
        elif sha:
            rep.add("libobj", "libObj.so 指纹", "mismatch",
                    f"SHA 与记录不符（{sha[:16]}…）→ 这是**不同的构建**，"
                    "所有地址都要重新定位")
        else:
            rep.add("libobj", "libObj.so 指纹", "mismatch",
                    f"读不到 SHA（{state.get('libobj_sha_err', '未知错误')}）")

    # CP 收包循环钩点 4 字节
    cp_hook = state.get("cp_hook")
    if cp_hook is None:
        rep.add("cp_recv", "CP 收包循环钩点", "error", state.get("cp_hook_err", "读内存失败"))
    else:
        got = " ".join(f"{b:02x}" for b in cp_hook)
        if got == RECORDED["cp_hook_orig"]:
            rep.add("cp_recv", "CP 收包循环钩点", "ok",
                    f"原厂 {got.replace(' ', '')}（与记录一致）")
        elif got == RECORDED["cp_hook_patched"]:
            rep.add("cp_recv", "CP 收包循环钩点", "ok",
                    f"已是本项目补丁 {got.replace(' ', '')}")
        else:
            rep.add("cp_recv", "CP 收包循环钩点", "mismatch",
                    f"读到 {got.replace(' ', '')}，与记录的 "
                    f"{RECORDED['cp_hook_orig'].replace(' ', '')} 不同 → 地址不适用")

    # 磁盘 SHA 与内存钩点必须是同一种状态，不能一半原厂一半补丁
    if sha and cp_hook is not None:
        sha_orig = sha == RECORDED["libobj_sha_orig"]
        sha_patched = sha in RECORDED["libobj_sha_patched"]
        hook_orig = got == RECORDED["cp_hook_orig"]
        hook_patched = got == RECORDED["cp_hook_patched"]
        if (sha_orig and hook_patched) or (sha_patched and hook_orig):
            rep.add("state", "整体状态", "mismatch",
                    "磁盘 SHA 是" + ("原厂" if sha_orig else "补丁")
                    + "，内存钩点是" + ("补丁" if hook_patched else "原厂")
                    + "（混合状态，地址/写入结果不可信）")

    # 音频信号属性表结构指纹
    props = state.get("audio_props")
    if props is None:
        rep.add("audio_node", "音频信号属性表", "error",
                state.get("audio_props_err", "读内存失败"))
    else:
        propids = [int.from_bytes(props[i:i + 4], "little") for i in range(0, 72, 12)]
        # 第 [4] 条属性：propId 0x0E（procId），value = 0xA8（音频信号）
        propid_4 = int.from_bytes(props[48:52], "little")
        proc_id = int.from_bytes(props[56:60], "little")
        ok = (propids == RECORDED["audio_props_propids"]
              and propid_4 == 0x0E and proc_id == RECORDED["audio_proc_id"])
        rep.add("audio_node", "音频信号属性表", "ok" if ok else "mismatch",
                "propId 序列 "
                + " ".join(f"{p:02X}" for p in propids)
                + f"，[4]=0x{propid_4:02X}→0x{proc_id:X}"
                + ("" if ok else f"（记录为 0x0E→0x{RECORDED['audio_proc_id']:X}）"))

    # 音效文件格式（相机上的真文件）
    head = state.get("sound_head")
    if not head:
        rep.add("sound_file", "音效文件格式", "error", state.get("sound_err", "读文件失败"))
    else:
        hexstr = re.sub(r"[^0-9a-fA-F]", "", head)
        raw = bytes.fromhex(hexstr[:64])
        if len(raw) < 32:
            rep.add("sound_file", "音效文件格式", "mismatch", f"首块读数异常：{head[:60]}")
        else:
            control = raw[0]
            exp = control & 0x0F
            unused = control & 0xE0
            ok = unused == 0 and exp <= 9
            rep.add("sound_file", "音效文件格式", "ok" if ok else "mismatch",
                    f"Caution.bin 首块 0x{control:02X}"
                    f"（指数 {exp}，预测器 {'开' if control & 0x10 else '关'}，"
                    f"未用位 0x{unused:02X}）"
                    + (" → 可解析" if ok else " → 控制字节不符合格式"))
    return True


def backup_check(args: argparse.Namespace, rep: Report) -> None:
    """Backup 属性读取（独立连接，因为要二次认证）。"""
    if args.no_backup:
        rep.add("backup", "Backup 属性", "skip", "--no-backup，已跳过")
        return
    try:
        import a7r3a_prop as P
    except Exception as exc:
        rep.add("backup", "Backup 属性", "skip", f"无法导入 a7r3a_prop（{exc}）")
        return
    try:
        cam = P.connect()
    except Exception as exc:
        rep.add("backup", "Backup 属性", "error", f"连接失败：{exc}")
        return
    try:
        vol = cam.readBackup(RECORDED["bkid_volume_snd7"])
        sig = cam.readBackup(RECORDED["bkid_audio_signal"])
        v = vol[0] if vol else None
        s = sig[0] if sig else None
        ok = (v is not None and 0 <= v <= 7) and (s in (1, 2))
        rep.add("backup", "Backup 属性", "ok" if ok else "mismatch",
                f"soundId 0x07 音量={v}（0..7）；音频信号={s}（1=开 2=关）")
    except Exception as exc:
        rep.add("backup", "Backup 属性", "error", f"读属性失败：{exc}")
    finally:
        try:
            cam.close()
        except Exception:
            pass


def dump_info(args: argparse.Namespace, rep: Report) -> None:
    A = _need_cam()
    state: dict[str, object] = {}

    def work(cam) -> None:
        pid = RECORDED["pid"]
        try:
            found = cam.pid_of("im.elf")
            if found:
                pid = found[0]
        except Exception:
            pass
        state["pid"] = pid
        state["maps"] = cam.maps()
        for soname, key in (
            ("libObj.so", "libObj"), ("CautionConfig.so", "CautionConfig"),
            ("viewUnified2.so", "viewUnified2"), ("libosal_uipc.so", "libosal_uipc"),
            ("libMWF.so", "libMWF"), ("libmpr.so", "libmpr"),
            ("libBizFw.so", "libBizFw"),
        ):
            state[key] = A.find_base(state["maps"], soname)

    A.run_on_camera(work)
    pid = state.get("pid")
    print(f"im.elf pid = {pid}")
    print(f"{'模块':24s} {'运行期基址':>12s}")
    for key in ("libObj", "CautionConfig", "viewUnified2", "libosal_uipc",
                "libMWF", "libmpr", "libBizFw"):
        base = state.get(key)
        print(f"{key + '.so':24s} "
              + (f"0x{int(base):08X}" if base else "（未找到）"))
    print("\n对照记录：")
    print(f"  libObj.so 记录值 0x{RECORDED['libobj_base']:08X}；"
          f"CautionConfig 记录值 0x{RECORDED['caution_base']:08X}")
    print("  基址不同不一定错（重定位/ASLR），但所有 fileVA 相关的地址都要重新核对。")


# ---------------------------------------------------------------------------
def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="只读地验证本项目记录的数据是否适用于你的相机",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    ap.add_argument("--check-all", action="store_true", help="跑全部只读检查")
    ap.add_argument("--check", action="append", default=[],
                    choices=["link", "libobj", "cp_recv", "audio_node",
                             "sound_file", "sound_format", "backup", "all"],
                    help="只跑某一项（可多次）")
    ap.add_argument("--dump-info", action="store_true", help="只打印模块基址（不判断）")
    ap.add_argument("--file", type=Path, help="--check sound_format 时分析的 .bin")
    ap.add_argument("--no-backup", action="store_true", help="跳过 Backup 检查（需要二次认证）")
    ap.add_argument("--json", action="store_true", help="输出 JSON")
    ap.add_argument("--list", action="store_true", help="列出所有检查项的含义")
    args = ap.parse_args()

    if args.list:
        print("检查项：")
        print("  link         相机连接（找 im.elf 的 pid 与 /proc/<pid>/maps）")
        print("  libobj       libObj.so 的 SHA256 是否等于记录值（原厂/已补丁）")
        print("  cp_recv      CP 收包循环钩点(fileVA 0xA31226) 的 4 字节是否与记录一致")
        print("  audio_node   「音频信号」属性表的结构指纹（propId 序列 + procId 0xA8）")
        print("  sound_file   相机上的 Caution.bin 首块是否符合音效格式")
        print("  sound_format 本地 .bin 文件是否符合音效格式（需 --file）")
        print("  backup       Backup 属性：soundId 0x07 音量 / 音频信号开关")
        return 0

    # 纯本地检查：不需要相机
    if args.check == ["sound_format"] or (
        "sound_format" in args.check and not (args.check_all or len(args.check) > 1)
    ):
        rep = Report()
        check_sound_format(args, rep)
        rep.print_all()
        return 0 if all(i["state"] == "ok" for i in rep.items) else 1

    if not any([args.check_all, args.check, args.dump_info]):
        ap.print_help()
        return 2

    if args.dump_info:
        rep = Report()
        dump_info(args, rep)
        return 0

    wanted = set(args.check)
    if args.check_all or "all" in wanted:
        wanted = {"link", "libobj", "cp_recv", "audio_node", "sound_file", "backup"}

    rep = Report()
    need_camera = bool(wanted - {"sound_format"})
    connected = True
    if need_camera:
        connected = camera_checks(args, rep)
    if "sound_format" in wanted:
        check_sound_format(args, rep)
    if "backup" in wanted and connected:
        backup_check(args, rep)

    # 只显示被请求的项
    wanted_titles = {
        "link": "相机连接", "libobj": "libObj.so 指纹", "cp_recv": "CP 收包循环钩点",
        "audio_node": "音频信号属性表", "sound_file": "音效文件格式",
        "sound_format": "音效文件格式", "backup": "Backup 属性",
    }
    if not (args.check_all or "all" in wanted):
        rep.items = [it for it in rep.items if it["title"] in wanted_titles.values()]

    if args.json:
        print(rep.to_json())
    else:
        print("=" * 78)
        print(f"verify_environment —— 只读检查（记录设备：{RECORDED['device']}）")
        print("=" * 78)
        rep.print_all()

    bad = [it for it in rep.items if it["state"] in {"mismatch", "error"}]
    return 1 if bad else (0 if rep.items else 2)


if __name__ == "__main__":
    raise SystemExit(main())
