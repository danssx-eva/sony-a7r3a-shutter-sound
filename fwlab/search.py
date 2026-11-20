"""在解包树里搜字符串 / 十六进制。"""
from __future__ import annotations
import mmap
import re
from pathlib import Path

from . import config
from .index import connect


def _ctx(data: bytes, i: int, n: int, width: int = 48) -> str:
    lo = max(0, i - width)
    hi = min(len(data), i + n + width)
    chunk = data[lo:hi]
    txt = "".join(chr(c) if 32 <= c < 127 else "." for c in chunk)
    return txt


def run(needle: str, ignore_case: bool = True, limit: int = 200, glob: str = "*") -> int:
    pat = needle.encode("utf-8", "ignore")
    if pat.startswith(b"0x"):
        pat = bytes.fromhex(needle[2:])
        mode = "hex"
    else:
        mode = "text"

    db = connect()
    paths = [r[0] for r in db.execute("SELECT path FROM files ORDER BY size")]
    hits = 0
    for rel in paths:
        p = config.UNPACK / rel
        if not p.match(glob):
            continue
        if p.stat().st_size == 0:
            continue
        try:
            with open(p, "rb") as f, mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ) as mm:
                hay = mm[:]
        except (ValueError, OSError):
            continue
        if ignore_case and mode == "text":
            idx = hay.lower().find(pat.lower())
        else:
            idx = hay.find(pat)
        while idx >= 0:
            hits += 1
            print(f"[{rel}] @0x{idx:x}")
            print("   " + _ctx(hay, idx, len(pat)))
            if hits >= limit:
                print(f"... 达到上限 {limit}")
                return 0
            if ignore_case and mode == "text":
                idx = hay.lower().find(pat.lower(), idx + 1)
            else:
                idx = hay.find(pat, idx + 1)
    print(f"共 {hits} 处")
    return 0
