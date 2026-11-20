"""A7R3A Backup 属性读写工具（走 PMCA 原生 API，不碰文件）。

关键约束（踩坑得来）：
  · **认证只能在一个进程里做一次**，重复认证会让设备报 "Pipe error"
  · 流程：找 MSC 设备 → 认证 → 切服务模式 → 找 0336 设备 → 读/写属性
  · 写完必须 syncBackup() 才持久化

用法：
  python a7r3a_prop.py --read                     # 读全部滤镜属性
  python a7r3a_prop.py --read --id 0x01070175     # 读单个
  python a7r3a_prop.py --write 0x0107075C 0b      # 写（危险，需 --go）
  python a7r3a_prop.py --read --no-service        # 不切服务模式，用普通模式 BKRD（大概率失败）
"""
from __future__ import annotations
import argparse, sys, time, os
from pathlib import Path

PMCA = Path(os.environ.get("PMCA_DIR", "vendor/Sony-PMCA-RE"))
LIBUSB_DIR = os.environ.get("LIBUSB_PACKAGE_DIR", "")

STYLE = {1: "标准", 2: "生动", 3: "中性", 4: "人像", 5: "风景", 6: "黑白",
         7: "清澈", 8: "深色", 9: "浅色", 10: "黄昏", 11: "夜景", 12: "红叶",
         13: "?", 14: "棕褐"}

PROPS = [
    (0x01070175, "style当前", "0..14"),
    (0x01070178, "contrast当前", "0..6 = -3..+3"),
    (0x01070187, "saturation当前", "0..6"),
    (0x0107018A, "sharpness当前", "0..6"),
    (0x0107075C, "style槽0", "0..14"),
    (0x0107075D, "style槽1", ""),
    (0x0107075E, "style槽2", ""),
    (0x0107075F, "style槽3", ""),
    (0x01070760, "style槽4", ""),
    (0x01070761, "style槽5", ""),
    (0x01070A0F, "contrast槽0", ""),
    (0x01070A10, "contrast槽1", ""),
    (0x01070A11, "contrast槽2", ""),
    (0x01070A12, "contrast槽3", ""),
    (0x01070A13, "contrast槽4", ""),
    (0x01070A14, "contrast槽5", ""),
    (0x01070A15, "sat槽0", ""),
    (0x01070A16, "sat槽1", ""),
    (0x01070A17, "sat槽2", ""),
    (0x01070A18, "sat槽3", ""),
    (0x01070A19, "sat槽4", ""),
    (0x01070A1A, "sat槽5", ""),
    (0x01070A1B, "sharp槽0", ""),
    (0x01070A1C, "sharp槽1", ""),
    (0x01070A1D, "sharp槽2", ""),
    (0x01070A1E, "sharp槽3", ""),
    (0x01070A1F, "sharp槽4", ""),
    (0x01070A20, "sharp槽5", ""),
    (0x01070762, "选中槽号", "0xFF=未选中"),
    (0x0107031C, "关PP", ""),
    (0x01070019, "AWB标志", ""),
    (0x01070017, "A/B整数", ""),
    (0x01070016, "G/M整数", ""),
    (0x010714B6, "A/B余", ""),
    (0x010714B5, "G/M余", ""),
    (0x01070B2C, "SILENT_SHUTTER", ""),
    (0x010713F2, "SHUTTER_TYPE", ""),
]


def find_camera(pid_want: int | None = None):
    import usb.core
    for d in usb.core.find(find_all=True, idVendor=0x054C):
        if pid_want is None or d.idProduct == pid_want:
            return d
    return None


def _try_connect_once():
    import usb.core  # noqa
    from pmca.usb.driver.generic.libusb import UsbBackend  # noqa
    from pmca.usb.driver.generic import GenericUsbDriver  # noqa
    from pmca.usb.sony import (SonySenserDevice, SonySenserCamera,  # noqa
                               SonySenserAuthDevice)

    def mkd(dev):
        backend = UsbBackend(dev)
        backend.reset()
        return GenericUsbDriver(backend)

    dev = find_camera(0x0D99)
    if dev is not None:
        d1 = mkd(dev)
        a1 = SonySenserAuthDevice(d1)
        a1.start()
        a1.authenticate()
        for _ in range(25):
            time.sleep(1.0)
            if find_camera(0x0336) is not None:
                break
        else:
            raise RuntimeError("切换服务模式超时")

    dev = find_camera(0x0336)
    if dev is None:
        raise RuntimeError("未找到服务模式设备 0x0336")
    d2 = mkd(dev)
    a2 = SonySenserAuthDevice(d2)
    a2.start()
    a2.authenticate()
    return SonySenserCamera(SonySenserDevice(d2)), a2


def connect(skip_service: bool = False, retries: int = 4):
    """带重试的连接。认证握手对时序敏感，连续调用容易失败，需等待后重试。"""
    sys.path.insert(0, str(PMCA))
    import os
    if LIBUSB_DIR not in os.environ.get("PATH", ""):
        os.environ["PATH"] = LIBUSB_DIR + os.pathsep + os.environ.get("PATH", "")
    last = None
    for i in range(retries):
        try:
            cam, auth = _try_connect_once()
            print(f"  连接成功（第 {i+1} 次尝试）")
            return SonyWrap(cam, auth)
        except Exception as e:
            last = e
            print(f"  第 {i+1} 次连接失败: {type(e).__name__}: {str(e)[:60]}")
            # 等相机从服务模式退回普通模式
            for _ in range(15):
                time.sleep(1.0)
                if find_camera(0x0D99) is not None:
                    break
            time.sleep(2)
    raise SystemExit(f"连接失败（重试 {retries} 次）: {last}")


class SonyWrap:
    """包一层，保证结束时调用 auth.stop() 释放相机。"""
    def __init__(self, cam, auth):
        self.cam = cam
        self.auth = auth

    def __getattr__(self, name):
        return getattr(self.cam, name)

    def close(self):
        try:
            self.auth.stop()
        except Exception:
            pass

def fmt(v, signed=False):
    if v is None:
        return "✗"
    x = v[0]
    if signed and x >= 128:
        x -= 256
    return f"{x:>3}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--read", action="store_true")
    ap.add_argument("--id", help="只读这一个属性")
    ap.add_argument("--write", nargs=2, metavar=("ID", "HEX"), help="写属性（需 --go）")
    ap.add_argument("--go", action="store_true", help="真的写")
    ap.add_argument("--no-save", action="store_true", help="只写内存不持久化（重启恢复）")
    ap.add_argument("--no-service", action="store_true")
    a = ap.parse_args()

    cam = connect(a.no_service)

    if a.write:
        pid = int(a.write[0], 16)
        data = bytes.fromhex(a.write[1])
        cur = cam.readBackup(pid)
        print(f"0x{pid:08x} 当前 = {cur.hex(' ')} ({len(cur)} 字节)")
        if len(data) != len(cur):
            print(f"✗ 长度不符：给 {len(data)} 字节，属性是 {len(cur)} 字节")
            return 1
        if not a.go:
            print(f"（dry-run）将写入 {data.hex(' ')}  → 加 --go 执行")
            return 0
        cam.writeBackup(pid, data)
        print(f"已写入，回读 = {cam.readBackup(pid).hex(' ')}")
        if a.no_save:
            print("（--no-save）未持久化，断电/重启即恢复")
        else:
            cam.saveBackup(0)
            print("已 saveBackup(0) 持久化")
        return 0

    if a.id:
        pid = int(a.id, 16)
        try:
            d = cam.readBackup(pid)
            print(f"0x{pid:08x} = {d.hex(' ')}  ({len(d)} 字节)")
        except Exception as e:
            print(f"0x{pid:08x} ✗ {type(e).__name__}: {e}")
        return 0

    # 全量读
    print(f"{'属性ID':>12}  {'名称':<16} {'值':<10} 说明")
    print("-" * 74)
    slots_ok = 0
    for pid, name, note in PROPS:
        try:
            d = cam.readBackup(pid)
        except Exception as e:
            print(f"0x{pid:08x}  {name:<16} ✗ {type(e).__name__}")
            continue
        hexs = d.hex(" ")
        extra = ""
        if len(d) == 1:
            v = d[0]
            if "style" in name:
                extra = STYLE.get(v, "?")
            elif any(k in name for k in ("contrast", "sat", "sharp")) and v <= 6:
                extra = f"{v-3:+d}"
            if "槽" in name:
                slots_ok += 1
        print(f"0x{pid:08x}  {name:<16} {hexs:<10} {extra} {note}")
    print()
    print(f"槽位相关属性读取成功: {slots_ok}/28")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
