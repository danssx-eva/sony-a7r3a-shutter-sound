"""调上游 fwtool.py 解密并解包。"""
from __future__ import annotations
import subprocess
import sys

from . import config


def run() -> int:
    dat = config.WORK / config.DAT_NAME
    if not dat.exists():
        raise SystemExit("先跑 `python -m fwlab carve`")
    if not config.FWTOOL.exists():
        raise SystemExit(f"找不到 fwtool：{config.FWTOOL}")

    out = config.UNPACK
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, str(config.FWTOOL), "unpack", "-f", str(dat), "-o", str(out)]
    print("$", " ".join(cmd))
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    print(proc.stdout)
    if proc.returncode != 0:
        print(proc.stderr, file=sys.stderr)
        return proc.returncode

    cfg = out / "config.yaml"
    if cfg.exists():
        print("--- config.yaml ---")
        print(cfg.read_text(encoding="utf-8"))
    return 0
