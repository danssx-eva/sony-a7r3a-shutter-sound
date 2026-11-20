"""往相机进程内存写任意字节（危险操作，慎用）

用法:
    python tools/cam_mempoke.py --addr 0x0405EFE0 --hex 0000000000000000
"""
from __future__ import annotations

import argparse
import pathlib
import sys
import threading
import time

LAB = pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0, str(LAB / "tools"))
sys.path.insert(0, str(LAB / "vendor/Sony-PMCA-RE"))

import a7r3a_shell as A


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--addr", type=lambda x: int(x, 0), required=True)
    ap.add_argument("--hex", required=True)
    ap.add_argument("--verify", action="store_true")
    a = ap.parse_args()

    data = bytes.fromhex(a.hex)
    print(f"写入 0x{a.addr:x}  {len(data)} 字节: {data.hex()}")

    def work(cam: A.Cam):
        ok = cam.write_mem(a.addr, data, "poke.bin")
        print(f"  写入返回: {ok}")
        time.sleep(0.3)
        back = cam.read_mem(a.addr, len(data))
        print(f"  读回: {back.hex()}")
        print(f"  {'✅ 一致' if back == data else '❌ 不一致'}")
        return True

    try:
        A.run_on_camera(work)
    except Exception as e:
        print(f"❌ 失败: {e}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
