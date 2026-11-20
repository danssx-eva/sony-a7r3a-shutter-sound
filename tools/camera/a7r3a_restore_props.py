"""把相机上被改过的 Backup 属性恢复成原厂值。

基准 = 最早从相机拉下来的原厂 /setting/Backup.bin（logs/backup/Backup.bin）。
只写「本项目曾经改过的」那些属性，不动别的。
"""
from __future__ import annotations
import os
import sys
from pathlib import Path

PMCA = Path(os.environ.get("PMCA_DIR", "vendor/Sony-PMCA-RE"))
BASE = Path(os.environ.get("LAB_ROOT", ".")) / "logs" / "backup" / "Backup.bin"

# 可能被改过的属性
TOUCHED = [
    0x01070175, 0x01070178, 0x01070187, 0x0107018A,      # 当前生效
    0x0107075C, 0x0107075D, 0x0107075E, 0x0107075F,      # style 槽
    0x01070760, 0x01070761,
    0x01070A0F, 0x01070A10, 0x01070A11, 0x01070A12,      # contrast 槽
    0x01070A13, 0x01070A14,
    0x01070A15, 0x01070A16, 0x01070A17, 0x01070A18,      # saturation 槽
    0x01070A19, 0x01070A1A,
    0x01070A1B, 0x01070A1C, 0x01070A1D, 0x01070A1E,      # sharpness 槽
    0x01070A1F, 0x01070A20,
    0x01070762,                                          # 选中槽号
    0x0107031C,                                          # 关 PP
    0x01070019, 0x01070017, 0x01070016,                  # AWB
    0x010714B6, 0x010714B5,
    0x0107067F, 0x0107067E, 0x010714DD, 0x010714DC,      # AWB 记忆
]


def main() -> int:
    sys.path.insert(0, str(PMCA))
    from pmca.backup import BackupFile
    from a7r3a_film import connect

    # ① 从原厂 Backup.bin 读出每个属性的原值
    f = open(BASE, "rb")
    bf = BackupFile(f)
    orig = {}
    for pid in TOUCHED:
        try:
            orig[pid] = bf.getProperty(pid).data
        except Exception as e:
            print(f"  ! 原厂文件里读不到 0x{pid:08x}: {e}")
    print(f"从原厂 Backup.bin 取到 {len(orig)} 个属性的原值\n")

    # ② 连相机，对比 + 恢复
    cam = connect()
    try:
        need = []
        print(f"{'属性':>12}  {'当前':<12}{'原厂':<12} 动作")
        print("-" * 56)
        for pid in TOUCHED:
            if pid not in orig:
                continue
            try:
                cur = cam.r(pid)
            except Exception as e:
                print(f"  0x{pid:08x}  读取失败 {type(e).__name__}")
                continue
            want = orig[pid]
            same = cur == want
            print(f"  0x{pid:08x}  {cur.hex(' '):<12}{want.hex(' '):<12} "
                  f"{'✓ 一致' if same else '← 恢复'}")
            if not same:
                need.append((pid, cur, want))

        if not need:
            print("\n全部已是原厂值，无需恢复。")
            return 0

        print(f"\n需要恢复 {len(need)} 项，开始写入…")
        bad = 0
        for pid, cur, want in need:
            try:
                cam.w(pid, want)
                got = cam.r(pid)
                if got != want:
                    print(f"  ✗ 0x{pid:08x} 写 {want.hex(' ')} 回读 {got.hex(' ')}")
                    bad += 1
            except Exception as e:
                print(f"  ✗ 0x{pid:08x} {type(e).__name__}")
                bad += 1
        print(f"\n{'✅ 全部恢复' if bad == 0 else f'⚠️ {bad} 项失败'}")
        if bad == 0:
            cam.sync()
            print("已 saveBackup(0) 持久化")
            print("\n=== 恢复后复查 ===")
            ok = 0
            for pid in TOUCHED:
                if pid not in orig:
                    continue
                try:
                    if cam.r(pid) == orig[pid]:
                        ok += 1
                except Exception:
                    pass
            print(f"  {ok}/{len(orig)} 项与原厂一致")
        return 0 if bad == 0 else 1
    finally:
        cam.close()


if __name__ == "__main__":
    raise SystemExit(main())
