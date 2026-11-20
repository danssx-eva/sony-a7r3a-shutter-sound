"""把本地文件传到相机的 /log/w/ 目录，并校验。

持久化那一步需要在相机上执行 `/log/w/pw`，所以得先把 pw 和两个 1 KB 块送上去。
手边只有 PMCA 的库，没有现成的命令行入口，所以有了这个工具。

用法：
    python tools/camera/push_files.py --file tools/inject/pw
    python tools/camera/push_files.py --dir work/blocks
    python tools/camera/push_files.py --list                 只列相机上现有的文件
    python tools/camera/push_files.py --clean                清空 /log/w/

每个文件传完都会读回算 md5 比对，不一致会重试。

相机上执行：
    busybox chmod 755 /log/w/pw
    /log/w/pw            # 不带参数应该打印用法
"""

from __future__ import annotations

import argparse
import hashlib
import pathlib
import sys
import time

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_PMCA = ROOT / "vendor" / "Sony-PMCA-RE"

WORK = "/log/w"
# camera.writeFile 一次超过约 4 KB 容易失败
CHUNK = 2048


def md5_bytes(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pmca", type=pathlib.Path, default=DEFAULT_PMCA,
                    help=f"Sony-PMCA-RE 目录（默认 {DEFAULT_PMCA.relative_to(ROOT)}）")
    ap.add_argument("--file", type=pathlib.Path, action="append", default=[],
                    help="要传的文件，可重复")
    ap.add_argument("--dir", type=pathlib.Path, action="append", default=[],
                    help="要传的目录（传里面所有文件），可重复")
    ap.add_argument("--list", action="store_true", help="只列相机上 /log/w/ 的内容")
    ap.add_argument("--clean", action="store_true", help="清空 /log/w/")
    args = ap.parse_args()

    if not args.pmca.exists():
        print(f"找不到 Sony-PMCA-RE：{args.pmca}")
        return 2

    files: list[pathlib.Path] = []
    for f in args.file:
        if not f.exists():
            print(f"文件不存在：{f}")
            return 2
        files.append(f)
    for d in args.dir:
        if not d.is_dir():
            print(f"目录不存在：{d}")
            return 2
        files.extend(sorted(x for x in d.iterdir() if x.is_file()))

    if not (args.list or args.clean or files):
        ap.error("没有指定 --file / --dir / --list / --clean")

    sys.path.insert(0, str(ROOT / "tools" / "camera"))
    try:
        import a7r3a_shell as A
    except ImportError as exc:
        print(f"导入 a7r3a_shell 失败：{exc}")
        return 2

    results: list[tuple[str, bool, str]] = []
    listing: dict[str, str] = {}

    def work(cam) -> bool:
        if args.clean:
            cam.sh(f"busybox rm -rf {WORK}", 60)
            print(f"  已清空 {WORK}")

        cam.sh(f"busybox mkdir -p {WORK}", 30)

        if args.list:
            o = cam.sh(f"busybox ls -l {WORK}", 60)
            print(f"  {WORK}:")
            for line in o.splitlines():
                if line.strip() and not line.strip().startswith("/"):
                    print(f"    {line.strip()}")
            return True

        for local in files:
            data = local.read_bytes()
            remote = f"{WORK}/{local.name}"
            print(f"  [push] {local.name}  {len(data):,} B", end="", flush=True)

            # 分段上传
            ok = False
            for attempt in range(4):
                try:
                    if len(data) <= 28 * 1024:
                        cam.camera.writeFile(remote, data)
                    else:
                        # 大文件分段落盘再拼
                        parts = [data[i:i + 4096] for i in range(0, len(data), 4096)]
                        names = []
                        for i, part in enumerate(parts, 1):
                            pn = f"{WORK}/.__part{i}"
                            cam.camera.writeFile(pn, part)
                            names.append(pn)
                        cam.sh(f"busybox cat {' '.join(names)} > {remote}", 120)
                        cam.sh(f"busybox rm -f {' '.join(names)}", 60)
                    ok = True
                    break
                except Exception:
                    time.sleep(2.5)
            if not ok:
                print("  上传失败")
                results.append((local.name, False, "上传失败"))
                continue

            # 读回校验
            got = ""
            for _ in range(3):
                o = cam.sh(f"busybox md5sum {remote}", 120)
                import re
                m = re.findall(r"\b([0-9a-f]{32})\b", o)
                if m:
                    got = m[-1]
                    break
                time.sleep(1.5)

            want = md5_bytes(data)
            if not got:
                print("  [无法校验]")
                results.append((local.name, False, "相机端 md5 读不到"))
            elif got != want:
                print(f"  [不一致] 相机 {got[:12]} 本地 {want[:12]}")
                results.append((local.name, False, "内容不一致"))
            else:
                print("  ok")
                results.append((local.name, True, ""))

        # 可执行文件给上 +x
        cam.sh(f"busybox chmod 755 {WORK}/* 2>/dev/null", 30)
        ok_all = bool(results) and all(r[1] for r in results)
        if ok_all:
            listing["text"] = cam.sh(f"busybox ls -l {WORK}", 60)
        return ok_all

    print(f"目标目录 {WORK}")
    print("（这是唯一会写相机的操作：只写 /log/ 分区，不碰 /usr）")
    print("（传完不会清理这个目录，下一会话可以直接用）")
    print()
    try:
        ok_run = A.run_on_camera(work, cleanup=False)
    except Exception as exc:
        print(f"\n失败：{exc}")
        print("USB 不稳时重试。见 docs/附录/踩过的坑.md")
        return 1

    if results:
        bad = [r for r in results if not r[1]]
        print()
        print(f"完成 {len(results) - len(bad)}/{len(results)}")
        if bad:
            for name, _, why in bad:
                print(f"  失败 {name}：{why}")
            return 1
        if not ok_run:
            print("  上传结果未通过会话校验")
            return 1
        print()
        print("已确认留在相机上（本次会话结束不会清理）：")
        for line in listing.get("text", "").splitlines():
            if line.strip() and not line.strip().startswith("/"):
                print(f"  {line.strip()}")
        print()
        print("下一步（在相机上）：")
        print(f"  busybox ls -l {WORK}")
        print(f"  busybox chmod 755 {WORK}/pw")
        print(f"  {WORK}/pw")
    return 0


if __name__ == "__main__":
    sys.exit(main())
