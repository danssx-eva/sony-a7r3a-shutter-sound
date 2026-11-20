"""从 updater exe 里把 DAT 容器切出来。

fwtool 只认两种 exe：末尾追加 ZIP 或 LZH 的那种。2019 这批 Sony updater 是
PE + overlay（DAT 直接在 overlay 里），fwtool 会报 "Unknown exe file"。
这里用容器自身的 chunk 结构定位边界，并用 DEND 的 CRC32 复核。
"""
from __future__ import annotations
import struct
import zlib
from pathlib import Path

from . import config
from .util import human


def find_dat_offset(path: Path, limit_scan: int = 8 << 20) -> int:
    with open(path, "rb") as f:
        head = f.read(limit_scan)
    off = head.find(config.DAT_MAGIC)
    if off < 0:
        raise SystemExit("exe 里没有找到 DAT 魔数（前 8 MiB）")
    return off


def container_end(path: Path, start: int) -> int:
    """走 chunk 链，返回 DEND 之后的偏移。"""
    with open(path, "rb") as f:
        f.seek(start + 8)  # 跳过 DAT 头
        while True:
            hdr = f.read(8)
            if len(hdr) < 8:
                raise SystemExit("chunk 链在 DEND 之前断了")
            size, typ = struct.unpack(">i4s", hdr)
            if size < 0:
                raise SystemExit(f"chunk {typ!r} 长度非法：{size}")
            f.seek(size, 1)
            if typ == b"DEND":
                return f.tell()


def verify_crc(path: Path, start: int, end: int):
    """DEND 的 crc 覆盖 [start, DEND 头)，big-endian u32。"""
    with open(path, "rb") as f:
        f.seek(end - 4)
        want = struct.unpack(">I", f.read(4))[0]
        f.seek(start)
        crc = 0
        remain = end - 12 - start
        while remain > 0:
            b = f.read(min(1 << 20, remain))
            if not b:
                break
            crc = zlib.crc32(b, crc)
            remain -= len(b)
    return (crc & 0xFFFFFFFF) == want, want, crc & 0xFFFFFFFF


def run() -> int:
    exe = config.RAW / config.FW_NAME
    if not exe.exists():
        raise SystemExit("先跑 `python -m fwlab fetch`")

    start = find_dat_offset(exe)
    end = container_end(exe, start)
    ok, want, got = verify_crc(exe, start, end)
    print(f"DAT 区间：{start:,} .. {end:,}  长度 {human(end - start)}")
    print(f"DEND CRC32：文件内 {want:08x} / 实算 {got:08x} -> {'OK' if ok else 'MISMATCH'}")
    if not ok:
        raise SystemExit("CRC 不匹配，拒绝写盘")

    dst = config.WORK / config.DAT_NAME
    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(exe, "rb") as f, open(dst, "wb") as o:
        f.seek(start)
        remain = end - start
        while remain:
            b = f.read(min(1 << 20, remain))
            if not b:
                break
            o.write(b)
            remain -= len(b)

    print(f"写出 {dst} ({human(dst.stat().st_size)})")
    return 0
