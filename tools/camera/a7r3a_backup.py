"""在改动相机之前，把需要恢复的全部内容备份到本地。

这是本项目的第一步。没有这个备份，任何一步改动都可能不可逆。

用法：
    python tools/camera/a7r3a_backup.py
    python tools/camera/a7r3a_backup.py --out my-backup
    python tools/camera/a7r3a_backup.py --no-libobj
    python tools/camera/a7r3a_backup.py --verify backup/20261119-004512

备份内容：
    /usr/lib/libObj.so                  19 MB，补丁改的就是它
    /usr/share/avsystemsound/*.bin      30 个音效文件
    /usr/share/avsystemsound/beeplist.txt
    /proc/<pid>/maps                    地址对照

每个文件拉下来之后，会再让相机自己算一遍 md5 做交叉校验。只比本地哈希是不够的：
那只能证明文件没被改坏，不能证明它和相机上的一致。

整个操作只读。不写文件、不写内存、不改设置、不重启。
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import re
import sys
import time
from datetime import datetime

ROOT = pathlib.Path(__file__).resolve().parents[2]
DEFAULT_PMCA = ROOT / "vendor" / "Sony-PMCA-RE"

SOUND_DIR = "/usr/share/avsystemsound"
LIBOBJ = "/usr/lib/libObj.so"

# libObj.so 的已知状态。备份时必须告诉用户他备份的是哪一种。
KNOWN_LIBOBJ = {
    "f1351204d2dd1c4033d427e09e7848fbbff0dd577abb205e00ef97bb4e6b81ed":
        ("原厂", "未修改的原始文件，回滚就靠它"),
    "d80aa1e00b84f5f719eb5e427bf760a06b81b6401a7550edada355d8f2d4a960":
        ("已打补丁（soundId 0x07 CAUTION）", "打完补丁的状态，不能用来回滚到原厂"),
    "d45ca8d7821b7a771555faab179ec268316d75acb4cb1a0ee8bae70453730e6a":
        ("已打补丁（soundId 0x04 FOCUSLOCK）", "打完补丁的状态，不能用来回滚到原厂"),
}


def sha256_of(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_of(path: pathlib.Path) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def do_verify(dirpath: pathlib.Path) -> int:
    """离线校验一个已有备份目录。"""
    man = dirpath / "manifest.json"
    if not man.exists():
        print(f"没有 {man}，这不是一个备份目录。")
        return 2
    data = json.loads(man.read_text(encoding="utf-8"))
    bad = 0
    print(f"校验 {dirpath}")
    for item in data["files"]:
        p = dirpath / item["file"]
        if not p.exists():
            print(f"  缺失  {item['file']}")
            bad += 1
            continue
        got = sha256_of(p)
        if got != item["sha256"]:
            print(f"  损坏  {item['file']}")
            print(f"        期望 {item['sha256'][:16]}  实际 {got[:16]}")
            bad += 1
        else:
            print(f"  OK    {item['file']}")

    files = data["files"]
    n = len(files)
    xs = [f.get("cross_verified", "unknown") for f in files]
    ok_n = xs.count("ok")

    # 备份齐不齐，要用「应该有哪些」判，不能拿清单里已有几条当分母。
    # 否则残缺备份也会显示 N/N 全过。
    remotes = [f.get("remote", "") for f in files]
    dup = sorted({r for r in remotes if r and remotes.count(r) > 1})
    has_libobj = LIBOBJ in remotes
    sound_items = [r for r in remotes if r.startswith(SOUND_DIR + "/")]
    sound_names = [r.rsplit("/", 1)[-1] for r in sound_items]
    n_sound = len(sound_items)
    n_bin = sum(1 for x in sound_names if x.endswith(".bin"))
    has_beeplist = "beeplist.txt" in sound_names
    manifest_errors = data.get("errors") or []
    expect_sound = 31          # 30 个 .bin + beeplist.txt

    # 状态不能信清单，必须复算本地 libObj.so 的 SHA256。
    sha_factory = next(k for k, v in KNOWN_LIBOBJ.items() if v[0] == "原厂")
    libobj_item = next((f for f in files if f.get("remote") == LIBOBJ), None)
    libobj_sha = ""
    if libobj_item:
        p = dirpath / libobj_item["file"]
        if p.exists():
            libobj_sha = sha256_of(p)
    if libobj_sha == sha_factory:
        libobj_state = "原厂"
    elif libobj_sha in KNOWN_LIBOBJ:
        libobj_state = KNOWN_LIBOBJ[libobj_sha][0]
    elif libobj_sha:
        libobj_state = "未知构建"
    else:
        libobj_state = "缺失"

    problems = []
    if not has_libobj:
        problems.append("缺 libObj.so —— 补丁改的就是这个文件，没有它无法回滚")
    elif libobj_sha != sha_factory:
        problems.append(f"libObj.so 复算 SHA 不是原厂（{libobj_state}），不能用来回滚")
    if n_sound != expect_sound or n_bin != 30 or not has_beeplist:
        problems.append(f"音效目录是 {n_sound} 个（.bin {n_bin} + beeplist "
                        f"{'有' if has_beeplist else '缺'}），应为 30 个 .bin + beeplist.txt")
    if dup:
        problems.append(f"清单里有重复路径：{', '.join(dup[:3])}")
    if manifest_errors:
        problems.append(f"备份时记录了 {len(manifest_errors)} 个错误："
                        + "；".join(str(e) for e in manifest_errors[:3]))
    if ok_n < n:
        problems.append(f"{n - ok_n} 个文件备份时没拿到相机端 md5，无法确认与相机一致")
    st = data.get("libobj_state", "")
    if st and libobj_state != "缺失" and st != libobj_state:
        problems.append(f"清单写的是「{st}」，复算结果是「{libobj_state}」")

    print()
    print(f"清单 {n} 个文件    本地完整性 {n - bad} 通过    交叉校验 {ok_n}/{n}")
    print(f"libObj.so {libobj_state}    音效 {n_sound}/{expect_sound}")

    if problems:
        print()
        print("这份备份有问题：")
        for x in problems:
            print(f"  · {x}")

    print()
    ok = (bad == 0) and not problems
    print("备份完整。" if ok else "备份不完整，重新备份。")
    return 0 if ok else 1


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--pmca", type=pathlib.Path, default=DEFAULT_PMCA,
                    help=f"Sony-PMCA-RE 目录（默认 {DEFAULT_PMCA.relative_to(ROOT)}）")
    ap.add_argument("--out", type=pathlib.Path, help="备份目录（默认 backup/<时间戳>）")
    ap.add_argument("--no-libobj", action="store_true",
                    help="跳过 19 MB 的 libObj.so（不推荐）")
    ap.add_argument("--verify", type=pathlib.Path, help="只校验已有备份目录，不连相机")
    args = ap.parse_args()

    if args.verify:
        return do_verify(args.verify)

    # ---- 导入 PHCA 和已经调好的 shell 封装 ----
    if not args.pmca.exists():
        print(f"找不到 Sony-PMCA-RE：{args.pmca}")
        print("  用 --pmca 指向它的位置，或者 git clone 到 vendor/Sony-PMCA-RE")
        return 2
    sys.path.insert(0, str(ROOT / "tools" / "camera"))
    try:
        import a7r3a_shell as A
    except ImportError as exc:
        print(f"导入 a7r3a_shell 失败：{exc}")
        print("  确认 tools/camera/ 完整")
        return 2

    outdir = args.out or (ROOT / "backup" / datetime.now().strftime("%Y%m%d-%H%M%S"))
    outdir.mkdir(parents=True, exist_ok=True)

    files: list[dict] = []
    errors: list[str] = []

    def camera_hash(cam, remote: str, tries: int = 4) -> tuple[str, str]:
        """让相机算一个文件的哈希。返回 (算法, 值)，失败返回 ("", "")。

        19 MB 的 libObj.so 上 shell 通道容易失步：命令发出去了，回来的却是
        一串重复的登录横幅。实测先读一段大输出（maps）把 PTY 冲干净再试就成。
        """
        for i in range(tries):
            for algo, n in (("md5sum", 32), ("sha256sum", 64)):
                o = cam.sh(f"busybox {algo} {remote}", 300)
                mm = re.findall(rf"\b([0-9a-f]{{{n}}})\b", o)
                if mm:
                    return algo, mm[-1]
            # 排水：读一段大输出，把通道冲干净
            cam.sh("busybox cat /proc/version", 30)
            cam.sh(f"busybox cat /proc/{cam.pid}/maps", 120)
            time.sleep(1.5)
        return "", ""

    def work(cam) -> bool:
        pid = cam.pid
        print(f"  相机 pid={pid}")

        # 热身：先跑两条命令把 shell 通道稳定下来。
        # 实测直接对 19 MB 文件跑哈希会失步，先读一次 maps（大输出）就正常。
        try:
            cam.pid_of("im.elf")
        except Exception:
            pass

        # maps
        maps_text = cam.sh(f"busybox cat /proc/{pid}/maps", 120)
        (outdir / "maps.txt").write_text(maps_text, encoding="utf-8")
        n_maps = len([x for x in maps_text.splitlines() if re.match(r"^[0-9a-f]+-", x)])
        print(f"  maps {n_maps} 段")
        if n_maps < 50:
            errors.append("maps 读到的段数异常偏少，shell 通道可能不稳")
            return False

        # 音效目录
        o = cam.sh(f"busybox ls -1 {SOUND_DIR}", 60)
        names = [x.strip() for x in o.splitlines() if x.strip().endswith((".bin", ".txt"))]
        if not names:
            toks = re.split(r"\s+", o)
            names = [t for t in toks if t.endswith((".bin", ".txt")) and not t.startswith("/")]
        names = [n for n in names if re.fullmatch(r"[A-Za-z0-9_.\-]+", n)]
        print(f"  音效目录 {len(names)} 个文件")
        if len(names) < 25:
            errors.append(f"音效目录只列出 {len(names)} 个文件，异常")
            return False

        todo = ([LIBOBJ] if not args.no_libobj else []) + [f"{SOUND_DIR}/{n}" for n in names]

        # 第一步：趁 shell 通道还没被大文件传输干扰，先把相机端哈希全部问出来
        print("  读取相机端哈希 …")
        cam_hashes: dict[str, tuple[str, str]] = {}
        for remote in todo:
            algo, val = camera_hash(cam, remote)
            if val:
                cam_hashes[remote] = (algo, val)
            else:
                errors.append(f"相机端哈希读不到：{remote}")
        print(f"    拿到 {len(cam_hashes)}/{len(todo)} 个")

        # 第二步：拉文件（大文件放最后，避免影响前面的小文件）
        todo.sort(key=lambda r: 0 if r.startswith(SOUND_DIR) else 1)
        for remote in todo:
            local = outdir / remote.lstrip("/").replace("/", "_")
            print(f"  [pull] {remote}", end="", flush=True)

            ok = False
            for _ in range(4):
                try:
                    with open(local, "wb") as f:
                        cam.camera.readFile(remote, f)
                    if local.stat().st_size > 0:
                        ok = True
                        break
                except Exception:
                    time.sleep(2.5)
            if not ok:
                print("  拉取失败")
                errors.append(f"拉取失败：{remote}")
                if local.exists():
                    local.unlink()
                continue

            size = local.stat().st_size
            local_md5 = md5_of(local)
            algo, cam_val = cam_hashes.get(remote, ("", ""))
            if algo == "sha256sum":
                local_cmp = sha256_of(local)
            else:
                local_cmp = local_md5
            cam_md5 = cam_val

            if not cam_md5:
                print(f"  {size:,} B  [无法交叉校验]")
                errors.append(f"相机端 md5 读不到：{remote}")
                cross = "unknown"
            elif cam_md5 != local_cmp:
                print(f"  {size:,} B  [不一致] 相机 {cam_md5[:12]} 本地 {local_cmp[:12]}")
                errors.append(f"内容不一致：{remote}")
                cross = "mismatch"
            else:
                print(f"  {size:,} B  ok")
                cross = "ok"

            files.append({
                "remote": remote,
                "file": local.name,
                "size": size,
                "sha256": sha256_of(local),
                "md5": local_md5,
                "camera_md5": cam_md5,
                "cross_verified": cross,
            })
        return True

    print(f"备份到 {outdir}")
    print()
    print("本次操作只读。发给相机的全部内容：")
    print("  camera.readFile()          逐个读文件")
    print("  busybox ps                 找 im.elf 的 pid")
    print("  busybox cat /proc/<pid>/maps")
    print("  busybox ls -1 <音效目录>")
    print("  busybox md5sum <每个文件>   交叉校验用")
    print()
    print("不写文件、不写内存、不改设置、不重启。")
    print()

    try:
        A.run_on_camera(work)
    except Exception as exc:
        print(f"\n连接或读取失败：{exc}")
        print("USB 不稳时重试几次。见 docs/附录/踩过的坑.md 第二节。")
        return 1

    if not files:
        print()
        print("备份失败：一个文件都没有拉下来。")
        print()
        print("常见原因：")
        print("  · 相机没插好，或者还停在普通模式（需要服务模式 054C:0336）")
        print("  · 相机休眠了，按一下快门唤醒")
        print("  · Windows 驱动没装对，见 docs/02-依赖与环境.md")
        print("  · 残留的 python 进程占着 USB 句柄")
        return 1

    # 清单
    has_libobj = any(f["remote"] == LIBOBJ for f in files)
    n_sound = sum(1 for f in files if f["remote"].startswith(SOUND_DIR))
    total = sum(f["size"] for f in files)

    print()
    print(f"完成：{len(files)} 个文件，{total:,} 字节")
    print(f"  音效目录 {n_sound} 个")
    print(f"  libObj.so {'已备份' if has_libobj else '未备份（--no-libobj）'}")

    # 判断 libObj 状态
    libobj_state = None
    if has_libobj:
        entry = next(f for f in files if f["remote"] == LIBOBJ)
        libobj_state = KNOWN_LIBOBJ.get(entry["sha256"])
        print()
        if libobj_state:
            label, hint = libobj_state
            print(f"libObj.so 状态：{label}")
            print(f"  {hint}")
            if label != "原厂":
                print()
                print("  ⚠ 你备份的不是原厂文件。")
                print("  如果这台相机已经打过补丁，这份备份无法用来回滚到原厂。")
                print("  要拿到原厂文件，只能先按 教程/06 的反向操作恢复再重新备份，")
                print("  或者用固件包里的原始块（见 docs/01-固件介绍.md）。")
        else:
            print("libObj.so 状态：未识别的 SHA256")
            print(f"  {entry['sha256']}")
            print("  既不是记录里的原厂值，也不是已知的补丁值。")
            print("  可能是别的构建，或者被别的工具改过。先搞清楚再继续。")

    manifest = {
        "created": datetime.now().isoformat(timespec="seconds"),
        "device": "ILCE-7RM3A / firmware 1.00",
        "file_count": len(files),
        "total_bytes": total,
        "libobj_state": libobj_state[0] if libobj_state else "未识别",
        "files": files,
        "errors": errors,
    }
    (outdir / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8")

    # 恢复说明
    lines = [
        "# 备份说明",
        "",
        f"创建时间：{manifest['created']}",
        f"设备：{manifest['device']}",
        f"libObj.so 状态：{manifest['libobj_state']}",
        f"文件数：{manifest['file_count']}，合计 {manifest['total_bytes']:,} 字节",
        "",
        "## 校验",
        "",
        "```bash",
        f"python tools/camera/a7r3a_backup.py --verify {outdir}",
        "```",
        "",
        "## 恢复音效文件",
        "",
        "```sh",
        "mount -o remount,rw /usr",
        "busybox cp /log/w/<文件名> /usr/share/avsystemsound/<原名>",
        "busybox sync",
        "busybox fsync /dev/nflasha15",
        "busybox sync",
        "mount -o remount,ro /usr",
        "```",
        "",
        "恢复 `libObj.so` 必须按 1 KB 块原地写，不能用 `cp`。",
        "见 `docs/教程/06-持久化到闪存.md` 的反向操作。",
        "",
        "## 文件清单",
        "",
        "| 远端路径 | 本地文件 | 大小 | 与相机一致 |",
        "|---|---|---|---|",
    ]
    for f in files:
        mark = {"ok": "是", "mismatch": "**否**", "unknown": "未校验"}[f["cross_verified"]]
        lines.append(f"| `{f['remote']}` | `{f['file']}` | {f['size']:,} | {mark} |")
    (outdir / "README.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    bad = bool(errors)
    if libobj_state and libobj_state[0] != "原厂":
        bad = True
    if not has_libobj and not args.no_libobj:
        bad = True
        print()
        print("libObj.so 没备份成功。补丁改的就是这个文件，没有它无法回滚。")

    print()
    print(f"目录：{outdir}")
    print(f"校验：python tools/camera/a7r3a_backup.py --verify {outdir}")

    if errors:
        print()
        print(f"有 {len(errors)} 个错误：")
        for e in errors:
            print(f"  {e}")

    return 1 if bad else 0


if __name__ == "__main__":
    raise SystemExit(main())
