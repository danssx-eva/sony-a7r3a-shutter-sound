"""从服务模式相机拉文件（Senser FileControl，不是 Jiritsu）。

用法：
    python a7r3a_pull.py --pmca <PMCA源码目录> --out logs/pull-<时间> --path /usr/share/avsystemsound/beeplist.txt
"""
from __future__ import annotations
import argparse, pathlib
import hashlib
import sys
from datetime import datetime
from pathlib import Path


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--pmca", default=str(pathlib.Path(__file__).resolve().parents[2] / "vendor" / "Sony-PMCA-RE"))
    ap.add_argument("--out", default="logs/pull")
    ap.add_argument("--path", action="append",
                    help="要拉的文件，可重复。不给则拉默认的关键模块")
    args = ap.parse_args()
    if not args.path:
        args.path = [
            "/usr/lib/libObj.so",
            "/usr/lib/CautionConfig.so",
            "/usr/lib/viewUnified2.so",
            "/usr/share/avsystemsound/beeplist.txt",
        ]
        print("未指定 --path，拉默认的关键模块")

    sys.path.insert(0, str(Path(args.pmca).resolve()))
    from pmca.commands.usb import senserShellCommand  # noqa: E402

    outdir = Path(args.out) / datetime.now().strftime("%Y%m%d-%H%M%S")
    outdir.mkdir(parents=True, exist_ok=True)
    results = []
    done = {"ok": False}

    def run(camera):
        camera.readHasp()
        for path in args.path:
            name = path.strip("/").replace("/", "_")
            dst = outdir / name
            print(f"[pull] {path}", flush=True)
            try:
                with open(dst, "wb") as f:
                    camera.readFile(path, f)
                size = dst.stat().st_size
                sha = hashlib.sha256(dst.read_bytes()).hexdigest() if size <= 64 << 20 else ""
                results.append({"path": path, "ok": True, "size": size, "sha256": sha})
                print(f"       ok {size} bytes -> {dst.name}", flush=True)
            except Exception as exc:
                if dst.exists():
                    dst.unlink()
                results.append({"path": path, "ok": False, "error": repr(exc)})
                print(f"       FAIL {exc}", flush=True)
        done["ok"] = True

    senserShellCommand(complete=run)

    import json
    (outdir / "pull-result.json").write_text(json.dumps(results, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"\n输出目录：{outdir}")
    ok = sum(1 for r in results if r.get("ok"))
    print(f"成功 {ok}/{len(results)}")
    return 0 if done["ok"] and ok == len(results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
