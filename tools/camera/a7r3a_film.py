"""A7R3A 胶片配方写入器（基于 Bigrabbit 的字段定义 + 本项目自己的属性 API）。

关键（来自 Bigrabbit core.py 的精确编码，已核对）：
  · contrast / saturation / sharpness 是 **有符号字节**：-3..+3 → 0xFD..0x03
    （不是 0..6！之前如果按 0..6 解释会写错值）
  · style 是枚举：1标准 2生动 3中性 4肖像 5风景 6黑白 7清澈 8深色
                  9浅色 10黄昏 11夜景 12红叶 14棕褐色
  · **保存值和当前生效值 是两份数据**，激活槽位时必须同时写，否则菜单会把旧值写回槽
  · 黑白/棕褐色：原厂行为把 saturation 强制 0（但槽里保存值保留）
  · AWB：a=A/B*1000, c=-G/M*1000；整数部分 1 字节有符号，余数 2 字节有符号
        同时写「当前」和「记忆」两处

用法：
  python a7r3a_film.py --list                    # 列出配方库
  python a7r3a_film.py --show                    # 读相机当前六槽（只读）
  python a7r3a_film.py --plan e100 reala c200 gold provia hp5     # 预览写入计划
  python a7r3a_film.py --write e100 reala c200 gold provia hp5 --go
"""
from __future__ import annotations
import argparse, json, math, sys, os
from pathlib import Path

PMCA = Path(os.environ.get("PMCA_DIR", "vendor/Sony-PMCA-RE"))
LIBUSB_DIR = os.environ.get("LIBUSB_PACKAGE_DIR", "")
RECIPES = Path(os.environ.get("LAB_ROOT", ".")) / "logs" / "re-filter" / "_dl" / "bigrabbit" / "assets_recipes.json"

STYLES = {"Standard": (1, "标准"), "Vivid": (2, "生动"), "Neutral": (3, "中性"),
          "Portrait": (4, "肖像"), "Landscape": (5, "风景"), "Black & White": (6, "黑白"),
          "Clear": (7, "清澈"), "Deep": (8, "深色"), "Light": (9, "浅色"),
          "Sunset": (10, "黄昏"), "Night": (11, "夜景"), "Autumn": (12, "红叶"),
          "Sepia": (14, "棕褐色")}
STYLE_BY_ID = {v[0]: k for k, v in STYLES.items()}
MONO = ("Black & White", "Sepia")

BASES = {"style": 0x0107075C, "contrast": 0x01070A0F,
         "saturation": 0x01070A15, "sharpness": 0x01070A1B}
CURRENT_STYLE = {"style": 0x01070175, "contrast": 0x01070178,
                 "saturation": 0x01070187, "sharpness": 0x0107018A}
WB_MODE = 0x01070019
WB_CURRENT = [0x01070017, 0x01070016, 0x010714B6, 0x010714B5]
WB_MEMORY = [0x0107067F, 0x0107067E, 0x010714DD, 0x010714DC]
SELECTED_SLOT = 0x01070762
PP_OFF = 0x0107031C


# ---------------- 连接（双认证 + 重试，已实测可用） ----------------
def _find(pid):
    import usb.core
    for d in usb.core.find(find_all=True, idVendor=0x054C):
        if d.idProduct == pid:
            return d
    return None


def _once():
    from pmca.usb.driver.generic.libusb import UsbBackend  # noqa
    from pmca.usb.driver.generic import GenericUsbDriver  # noqa
    from pmca.usb.sony import SonySenserDevice, SonySenserCamera, SonySenserAuthDevice  # noqa

    def mkd(dev):
        b = UsbBackend(dev)
        b.reset()
        return GenericUsbDriver(b)

    d = _find(0x0D99)
    if d is not None:
        a = SonySenserAuthDevice(mkd(d))
        a.start(); a.authenticate()
        import time
        for _ in range(25):
            time.sleep(1.0)
            if _find(0x0336) is not None:
                break
        else:
            raise RuntimeError("切换服务模式超时")
    d = _find(0x0336)
    if d is None:
        raise RuntimeError("未找到服务模式设备")
    a2 = SonySenserAuthDevice(mkd(d))
    a2.start(); a2.authenticate()
    return SonySenserCamera(SonySenserDevice(mkd(d))), a2


class Cam:
    def __init__(self, c, a):
        self._c = c; self._a = a

    def r(self, pid):
        return self._c.readBackup(pid)

    def w(self, pid, data):
        self._c.writeBackup(pid, data)

    def sync(self):
        self._c.saveBackup(0)

    def close(self):
        try:
            self._a.stop()
        except Exception:
            pass


def connect(retries: int = 5) -> Cam:
    sys.path.insert(0, str(PMCA))
    import os, time
    if LIBUSB_DIR not in os.environ.get("PATH", ""):
        os.environ["PATH"] = LIBUSB_DIR + os.pathsep + os.environ.get("PATH", "")
    last = None
    for i in range(retries):
        try:
            c, a = _once()
            return Cam(c, a)
        except Exception as e:
            last = e
            print(f"  连接 {i+1}/{retries} 失败: {type(e).__name__}: {str(e)[:50]}")
            for _ in range(15):
                time.sleep(1.0)
                if _find(0x0D99) is not None:
                    break
            time.sleep(2)
    raise SystemExit(f"连接失败: {last}")


# ---------------- 编码 ----------------
def sb(v: int) -> bytes:
    """有符号字节"""
    return int(v).to_bytes(1, "little", signed=True)


def encode_wb(wb: dict) -> dict[int, bytes]:
    """AWB 编码：a=ab*1000, c=-gm*1000，整数 1B 有符号 + 余数 2B 有符号"""
    a = round(wb["ab"] * 1000)
    c = round(-wb["gm"] * 1000)
    ai = math.trunc(a / 1000)
    ci = math.trunc(c / 1000)
    vs = [ai.to_bytes(1, "little", signed=True),
          ci.to_bytes(1, "little", signed=True),
          (a - ai * 1000).to_bytes(2, "little", signed=True),
          (c - ci * 1000).to_bytes(2, "little", signed=True)]
    out = {WB_MODE: b"\x01"}
    for pid, v in zip(WB_CURRENT, vs):
        out[pid] = v
    for pid, v in zip(WB_MEMORY, vs):
        out[pid] = v
    return out


def load_recipes() -> dict[str, dict]:
    data = json.loads(RECIPES.read_text(encoding="utf-8"))
    return {r["id"]: r for r in data["recipes"]}


# ---------------- 读写 ----------------
def read_slots(cam: Cam):
    print(f"{'槽':<4}{'风格':<12}{'对比':>5}{'饱和':>5}{'锐度':>5}")
    print("-" * 34)
    for i in range(6):
        st = cam.r(BASES["style"] + i)[0]
        c = cam.r(BASES["contrast"] + i)[0]
        s = cam.r(BASES["saturation"] + i)[0]
        h = cam.r(BASES["sharpness"] + i)[0]
        c = c - 256 if c >= 128 else c
        s = s - 256 if s >= 128 else s
        h = h - 256 if h >= 128 else h
        name = STYLE_BY_ID.get(st, f"?{st}")
        print(f"槽{i:<3}{name:<12}{c:>+5}{s:>+5}{h:>+5}")
    print("-" * 34)
    try:
        print("当前生效：", end="")
        st = cam.r(CURRENT_STYLE["style"])[0]
        c = cam.r(CURRENT_STYLE["contrast"])[0]
        s = cam.r(CURRENT_STYLE["saturation"])[0]
        h = cam.r(CURRENT_STYLE["sharpness"])[0]
        c = c - 256 if c >= 128 else c
        s = s - 256 if s >= 128 else s
        h = h - 256 if h >= 128 else h
        print(f"{STYLE_BY_ID.get(st, st)}  C{c:+d} S{s:+d} SH{h:+d}")
    except Exception as e:
        print(f"读取失败 {e}")
    try:
        sel = cam.r(SELECTED_SLOT)[0]
        print(f"选中槽号 = 0x{sel:02x}" + ("（未选中）" if sel == 0xFF else f"（槽{sel}）"))
    except Exception:
        pass


def build_plan(recipes: list[dict]) -> list[tuple[int, bytes, str]]:
    """生成完整写入计划：(pid, data, 说明)"""
    if len(recipes) != 6:
        raise SystemExit("必须正好 6 个配方")
    plan = []
    for slot, r in enumerate(recipes):
        style_name = r["style"]
        if style_name not in STYLES:
            raise SystemExit(f"配方 {r['id']} 的风格 {style_name!r} 不支持")
        style_id = STYLES[style_name][0]
        c, s, h = int(r["contrast"]), int(r["saturation"]), int(r["sharpness"])
        for v, k in ((c, "contrast"), (s, "saturation"), (h, "sharpness")):
            if not -3 <= v <= 3:
                raise SystemExit(f"配方 {r['id']} 的 {k}={v} 超范围 -3..+3")

        # ① 槽保存值
        plan.append((BASES["style"] + slot, sb(style_id), f"槽{slot} style={style_name}"))
        plan.append((BASES["contrast"] + slot, sb(c), f"槽{slot} contrast={c:+d}"))
        plan.append((BASES["saturation"] + slot, sb(s), f"槽{slot} saturation={s:+d}"))
        plan.append((BASES["sharpness"] + slot, sb(h), f"槽{slot} sharpness={h:+d}"))


    # ② 当前生效值 = 槽0 的配方（激活它，否则画面不变）
    r0 = recipes[0]
    style0 = STYLES[r0["style"]][0]
    c0, s0, h0 = int(r0["contrast"]), int(r0["saturation"]), int(r0["sharpness"])
    if r0["style"] in MONO:
        s0 = 0
    plan.append((CURRENT_STYLE["style"], sb(style0), f"当前 style={r0['style']}"))
    plan.append((CURRENT_STYLE["contrast"], sb(c0), f"当前 contrast={c0:+d}"))
    plan.append((CURRENT_STYLE["saturation"], sb(s0), f"当前 saturation={s0:+d}"))
    plan.append((CURRENT_STYLE["sharpness"], sb(h0), f"当前 sharpness={h0:+d}"))

    # ③ AWB 只写一次（全局设置，不是每槽一份）
    for pid, data in encode_wb(r0["wb"]).items():
        plan.append((pid, data, f"AWB(槽0) 0x{pid:08x}"))

    # ④ 选中槽号 = 1（第一个槽）
    plan.append((SELECTED_SLOT, b"\x01", "选中槽号=1"))
    # ⑤ 关 PP（否则 PP 会覆盖创意风格）
    plan.append((PP_OFF, b"\x00", "关闭 Picture Profile"))
    return plan


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--list", action="store_true")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--plan", nargs=6, metavar="ID")
    ap.add_argument("--write", nargs=6, metavar="ID")
    ap.add_argument("--go", action="store_true")
    ap.add_argument("--no-save", action="store_true")
    a = ap.parse_args()

    lib = load_recipes()

    if a.list:
        print(f"配方库共 {len(lib)} 条\n")
        print(f"{'ID':<36}{'名称':<26}{'风格':<16}{'C':>3}{'S':>4}{'SH':>4}  {'WB':<14}")
        print("-" * 112)
        for rid, r in lib.items():
            wb = f"{r['wb']['ab']:+.1f}/{r['wb']['gm']:+.2f}"
            print(f"{rid:<36}{r['name'][:24]:<26}{r['style'][:14]:<16}"
                  f"{r['contrast']:>+3}{r['saturation']:>+4}{r['sharpness']:>+4}  {wb:<14}")
        return 0

    ids = a.plan or a.write
    if ids:
        unknown = [i for i in ids if i not in lib]
        if unknown:
            raise SystemExit(f"不认识的配方 ID: {unknown}（用 --list 查看）")
        recipes = [lib[i] for i in ids]
        plan = build_plan(recipes)

        print("=== 六个槽 ===")
        for i, r in enumerate(recipes):
            print(f"  槽{i}: {r['name']:<24} {r['style']:<16} "
                  f"C{r['contrast']:+d} S{r['saturation']:+d} SH{r['sharpness']:+d}  "
                  f"WB A/B{r['wb']['ab']:+.1f} G/M{r['wb']['gm']:+.2f}")
        print(f"\n=== 将写 {len(plan)} 个属性 ===")
        for pid, data, note in plan:
            print(f"  0x{pid:08x}  {data.hex(' '):<8}  {note}")

        if not a.write:
            print("\n（dry-run）加 --write ... --go 执行")
            return 0
        if not a.go:
            print("\n⚠ 需要 --go 才会真的写")
            return 1

        cam = connect()
        try:
            print("\n=== 写入 ===")
            bad = 0
            for pid, data, note in plan:
                try:
                    cam.w(pid, data)
                    got = cam.r(pid)
                    ok = got == data
                    if not ok:
                        print(f"  ✗ 0x{pid:08x} {note}  写 {data.hex()} 回读 {got.hex()}")
                        bad += 1
                except Exception as e:
                    print(f"  ✗ 0x{pid:08x} {note}  {type(e).__name__}")
                    bad += 1
            print(f"\n{'✅ 全部写入成功' if bad == 0 else f'⚠️ {bad} 处失败'}")
            if bad == 0 and not a.no_save:
                cam.sync()
                print("已 saveBackup(0) 持久化")
                print("→ 拔 USB，在相机菜单确认")
            print("\n=== 写完回读六槽 ===")
            read_slots(cam)
        finally:
            cam.close()
        return 0

    if a.show:
        cam = connect()
        try:
            read_slots(cam)
        finally:
            cam.close()
        return 0

    ap.print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
