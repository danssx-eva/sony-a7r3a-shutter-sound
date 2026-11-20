"""通用工具：哈希、类型嗅探、熵。"""
from __future__ import annotations
import hashlib
import math
from pathlib import Path

MAGICS = [
    (b"\x7fELF", "ELF"),
    (b"UDTRFIRM", "SONY-FDAT"),
    (b"\x89UFU\r\n\x1a\n", "SONY-DAT"),
    (b"\x1f\x8b", "gzip"),
    (b"\xfd7zXZ\x00", "xz"),
    (b"BZh", "bzip2"),
    (b"\x28\xb5\x2f\xfd", "zstd"),
    (b"hsqs", "squashfs"),
    (b"sqsh", "squashfs-be"),
    (b"\x45\x3d\xcd\x28", "cramfs"),
    (b"PK\x03\x04", "zip"),
    (b"\x89PNG\r\n\x1a\n", "png"),
    (b"\xff\xd8\xff", "jpeg"),
    (b"RIFF", "riff"),
    (b"OggS", "ogg"),
    (b"ID3", "mp3-id3"),
    (b"\xff\xfb", "mp3"),
    (b"fLaC", "flac"),
    (b"\x00\x00\x01\xba", "mpeg-ps"),
    (b"\x00\x00\x01\xb3", "mpeg-vs"),
    (b"\x1a\x45\xdf\xa3", "matroska"),
    (b"MZ", "pe"),
    (b"\x27\x05\x19\x56", "u-boot"),
    (b"ANDROID!", "android-boot"),
]


def human(n: int) -> str:
    for unit in ("B", "KiB", "MiB", "GiB"):
        if n < 1024 or unit == "GiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024
    return f"{n} B"


def sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha1_bytes(b: bytes) -> str:
    return hashlib.sha1(b).hexdigest()


def entropy(b: bytes) -> float:
    """0..8 bits/byte。"""
    if not b:
        return 0.0
    counts = [0] * 256
    for x in b:
        counts[x] += 1
    n = len(b)
    return -sum((c / n) * math.log2(c / n) for c in counts if c)


def sniff(head: bytes) -> str:
    for magic, name in MAGICS:
        if head.startswith(magic):
            return name
    # 文本/代码
    sample = head[:512]
    if sample and sum(32 <= c < 127 or c in (9, 10, 13) for c in sample) / len(sample) > 0.95:
        return "text"
    if not sample.strip(b"\x00"):
        return "zero"
    return "data"
