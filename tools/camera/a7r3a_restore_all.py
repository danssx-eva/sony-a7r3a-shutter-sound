"""把相机上的 libObj.so 恢复到原厂。

改过的两处都要还原，顺序是**先撤钩子（块 A），再还原载荷（块 B）**。
反过来的话，两次写之间钩子还指着 0x1948D8，可那里已经变回原厂代码了——这时按快门
会跳进原厂函数中间，崩。

用法：
    python tools/camera/a7r3a_restore_all.py --so backup/<时间戳>/usr_lib_libObj.so
    python tools/camera/a7r3a_restore_all.py --so <原厂.so> --pwname pw

--so 必须是**原厂**的 libObj.so（SHA256 = f1351204…）。脚本会先校验，不对就拒绝。

只写 /usr 的两个 1 KB 块，以及 /log/w/ 下的临时文件；不碰其他分区。
会先把当前两个块按 A、B 顺序拼成 /log/w/before_rollback.bin（2048 B），
回滚中断时可以拿它反悔。前 1024 B 是块 A，后 1024 B 是块 B；要退回补丁状态，按 A→B 顺序
用 pw 写回 0xA31000 / 0x194800。工具不清理 /log/w，这个文件会留在相机上；下次运行会先清空
/log/w，需要长期保留就先拉回电脑。
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import re
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_PMCA = ROOT / "vendor" / "Sony-PMCA-RE"

TARGET = "/usr/lib/libObj.so"
SHA_FACTORY = "f1351204d2dd1c4033d427e09e7848fbbff0dd577abb205e00ef97bb4e6b81ed"
BLOCK_SIZE = 1024

# 顺序：先 A（钩子）后 B（载荷）
BLOCKS = [
    ("A", 0xA31000, "钩点"),
    ("B", 0x194800, "载荷"),
]

WORK = "/log/w"


def sha256_of_bytes(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def sh_rc(cam, cmd: str, t: float = 60.0) -> tuple[str, int | None]:
    """跑一条命令并取回真实退出码。cam.sh 只返回输出，不返回状态。"""
    out = cam.sh(f"{cmd}; echo __RC=$?", t)
    m = re.search("__RC=([0-9]+)", out)
    if not m:
        return out, None
    return out[:m.start()], int(m.group(1))


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pmca", type=pathlib.Path, default=DEFAULT_PMCA,
                    help=f"Sony-PMCA-RE 目录（默认 {DEFAULT_PMCA.relative_to(ROOT)}）")
    ap.add_argument("--so", type=pathlib.Path, required=True,
                    help="原厂 libObj.so（SHA256 必须等于 f1351204…）")
    ap.add_argument("--pwname", default="pw",
                    help="相机 /log/w/ 下写入器的文件名（默认 pw）")
    ap.add_argument("--yes", action="store_true", help="跳过确认")
    args = ap.parse_args()

    if not args.so.exists():
        print(f"找不到 {args.so}")
        return 2
    orig = args.so.read_bytes()
    sha = sha256_of_bytes(orig)
    print(f"输入 .so  {len(orig):,} 字节")
    print(f"  SHA256 {sha}")
    if sha != SHA_FACTORY:
        print()
        print("这不是原厂文件，不能用来回滚。")
        print(f"  原厂 SHA256 应为 {SHA_FACTORY}")
        print("  你给的是已打补丁的版本，或者别的构建。")
        return 1
    print("  = 原厂 ✓")

    if not args.yes:
        print()
        print("将要执行：")
        print(f"  · 备份当前 {TARGET} 的这两个块到 {WORK}/before_rollback.bin")
        print(f"  · 把 {WORK}/{args.pwname} 和两个原厂块传到相机")
        print(f"  · 按顺序写回块 A 0xA31000 → 块 B 0x194800")
        print(f"  · 刷盘后校验整文件 SHA256 回到 {SHA_FACTORY[:16]}…")
        print()
        ans = input("继续？输入 yes：").strip().lower()
        if ans != "yes":
            print("已取消。")
            return 1

    if not args.pmca.exists():
        print(f"找不到 Sony-PMCA-RE：{args.pmca}")
        return 2

    sys.path.insert(0, str(ROOT / "tools" / "camera"))
    try:
        import a7r3a_shell as A
    except ImportError as exc:
        print(f"导入 a7r3a_shell 失败：{exc}")
        return 2

    pw_path = ROOT / "tools" / "inject" / "pw"
    if not pw_path.exists():
        print(f"找不到写入器 {pw_path}")
        print("  用 sh tools/inject/build_pw.sh 编译，或者从仓库里取")
        return 2

    blocks = {name: orig[off:off + BLOCK_SIZE] for name, off, _ in BLOCKS}
    for name, off, what in BLOCKS:
        print(f"  块 {name} 0x{off:X}（{what}） {len(blocks[name])} B  "
              f"md5 {hashlib.md5(blocks[name]).hexdigest()}")

    result = {"ok": False}

    def work(cam) -> bool:
        # 1. 把当前状态备份下来（反悔用）：按文件偏移读两个块，A 在前 B 在后
        cur = bytearray()
        for name, off, _ in BLOCKS:
            hexs = cam.sh(f"busybox dd if={TARGET} bs=1 skip=0x{off:X} count={BLOCK_SIZE} "
                          f"2>/dev/null | busybox xxd -p", 180)
            hexs = "".join(ln.strip() for ln in hexs.splitlines()
                           if ln.strip() and re.fullmatch(r"[0-9a-fA-F]+", ln.strip()))
            if len(hexs) < BLOCK_SIZE * 2:
                print(f"  读当前块 {name} 失败（只拿到 {len(hexs) // 2} B）")
                return False
            cur += bytes.fromhex(hexs[:BLOCK_SIZE * 2])
        if not cam.upload("before_rollback.bin", bytes(cur)):
            print("  上传 before_rollback.bin 失败")
            return False
        print(f"  已备份当前状态到 {WORK}/before_rollback.bin（{len(cur)} B，A+B）")

        # 2. 上传写入器和两个原厂块
        for name, off, _ in BLOCKS:
            if not cam.upload(f"blk{name}_orig.bin", blocks[name]):
                print(f"  上传块 {name} 失败")
                return False
        print(f"  已上传两个原厂块")

        if not cam.upload(args.pwname, pw_path.read_bytes()):
            print(f"  上传 {args.pwname} 失败")
            return False
        print(f"  已上传 {args.pwname}")

        # 3. 确认它们真的在（前面的上传可能会被 prepare 清掉）
        o = cam.sh(f"busybox ls {WORK}", 30)
        have = o
        for needed in [args.pwname, "blkA_orig.bin", "blkB_orig.bin", "before_rollback.bin"]:
            if needed not in have:
                print(f"  相机上找不到 {needed}，上传没生效")
                return False
        print("  已确认四个文件都在相机上")

        cam.sh(f"busybox chmod 755 {WORK}/{args.pwname}", 30)

        # 4. 挂写 → 按顺序写块 → 刷盘 → 挂回只读
        print(f"  挂写 {TARGET} 所在分区")
        _, rc = sh_rc(cam, "busybox mount -o remount,rw /usr", 60)
        if rc != 0:
            print(f"    挂写失败（rc={rc}）")
            return False

        for name, off, what in BLOCKS:
            cmd = f"{WORK}/{args.pwname} {TARGET} 0x{off:X} {WORK}/blk{name}_orig.bin"
            o = cam.sh(cmd, 180)
            print(f"  写块 {name}（{what}）: {o.strip()[-120:] or '无输出'}")

            # 该块必须与源文件逐字节一致才继续
            chk = cam.sh(f"busybox dd if={TARGET} bs=1 skip=0x{off:X} count={BLOCK_SIZE} "
                         f"2>/dev/null | busybox md5sum", 120)
            got = re.findall(r"[0-9a-f]{32}", chk)
            want = hashlib.md5(blocks[name]).hexdigest()
            if not got:
                print(f"    块 {name} 读回失败")
                cam.sh("busybox mount -o remount,ro /usr", 60)
                return False
            if got[-1] != want:
                print(f"    块 {name} 内容不对：相机 {got[-1][:12]} 期望 {want[:12]}")
                print("    停止，不继续写下一块。")
                cam.sh("busybox mount -o remount,ro /usr", 60)
                return False
            print(f"    md5 {want}  ✓")

        print("  刷盘")
        for cmd in ("busybox sync", "busybox fsync /dev/nflasha15", "busybox sync"):
            _, rc = sh_rc(cam, cmd, 300)
            if rc != 0:
                print(f"    {cmd} 失败（rc={rc}），不认为已经落盘")
                result["ok"] = False
                return False
        _, rc = sh_rc(cam, "busybox mount -o remount,ro /usr", 60)
        if rc != 0:
            print(f"    挂回只读失败（rc={rc}）")
            result["ok"] = False
            return False
        print("  已挂回只读")

        # 5. 整文件校验
        o = cam.sh(f"busybox sha256sum {TARGET}", 600)
        got = re.findall(r"[0-9a-f]{64}", o)
        if not got:
            # 19MB 哈希偶尔读不到，重试一次
            time.sleep(2)
            o = cam.sh(f"busybox sha256sum {TARGET}", 600)
            got = re.findall(r"[0-9a-f]{64}", o)
        print(f"  整文件 SHA256: {got[-1] if got else '读不到'}")
        result["ok"] = bool(got) and got[-1] == SHA_FACTORY
        return result["ok"]

    try:
        A.run_on_camera(work, cleanup=False)
    except Exception as exc:
        print(f"\n失败：{exc}")
        return 1

    print()
    if result["ok"]:
        print("回滚完成。整文件 SHA256 已回到原厂值。")
        print()
        print("最后一步：拔电池冷启动，再跑一次 verify_environment.py 确认。")
        return 0

    print("回滚未确认成功。整文件 SHA256 不是原厂值。")
    print("  可能原因：块写进去了但没落盘、或者还有别的地方被改过。")
    print("  先拔电池冷启动，再看 SHA256。仍然不对就重跑一次本脚本。")
    return 1


if __name__ == "__main__":
    sys.exit(main())
