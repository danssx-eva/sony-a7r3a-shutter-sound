"""下载官方 updater，记录来源与哈希。只做 GET，不碰相机。"""
from __future__ import annotations
import json
import os
import time
import urllib.request
from pathlib import Path

from . import config
from .util import human, sha256_file


def _download(url: str, dst: Path) -> None:
    pos = dst.stat().st_size if dst.exists() else 0
    req = urllib.request.Request(url, headers={
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/131.0",
        "Referer": "https://support.d-imaging.sony.co.jp/",
    })
    if pos:
        req.add_header("Range", f"bytes={pos}-")
    with urllib.request.urlopen(req, timeout=60) as r:
        total = int(r.headers.get("Content-Length", 0)) + pos
        mode = "ab" if r.status == 206 else "wb"
        if mode == "wb":
            pos = 0
        with open(dst, mode) as f:
            last = 0.0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                f.write(chunk)
                pos += len(chunk)
                now = time.time()
                if now - last > 5:
                    pct = pos / total * 100 if total else 0
                    print(f"\r{human(pos)} / {human(total)}  {pct:5.1f}%", end="", flush=True)
                    last = now
    print()


def run() -> int:
    config.RAW.mkdir(parents=True, exist_ok=True)
    dst = config.RAW / config.FW_NAME

    if dst.exists() and dst.stat().st_size == config.FW_SIZE:
        print(f"已存在且大小正确：{dst} ({human(dst.stat().st_size)})")
    else:
        print(f"下载 {config.FW_URL}")
        _download(config.FW_URL, dst)

    size = dst.stat().st_size
    digest = sha256_file(dst)
    manifest = {
        "url": config.FW_URL,
        "file": str(dst.relative_to(config.ROOT)),
        "size": size,
        "expected_size": config.FW_SIZE,
        "size_ok": size == config.FW_SIZE,
        "sha256": digest,
        "model": "ILCE-7RM3",
        "version": "3.10",
    }
    (config.RAW / "manifest.json").write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    print(json.dumps(manifest, ensure_ascii=False, indent=2))
    return 0 if manifest["size_ok"] else 1
