"""音频资产扫描：容器识别 + 关键字命中 + 原始 PCM 导出试听。"""
from __future__ import annotations
import struct
from pathlib import Path

from . import config
from .index import connect
from .util import human

CONTAINERS = [
    (b"RIFF", "RIFF"),
    (b"OggS", "Ogg"),
    (b"fLaC", "FLAC"),
    (b"ID3", "MP3(ID3)"),
    (b"EA3", "ATRAC3(.oma)"),
]

KEYWORDS = [
    b"shutter", b"Shutter", b"SHUTTER",
    b"beep", b"Beep", b"BEEP",
    b"SE_", b"se_",
    b"sound", b"Sound", b"SOUND",
    b"audio", b"Audio", b"AUDIO",
    b".wav", b".WAV", b".pcm", b".PCM",
    b"ATRAC", b"atrac",
]

WAV_HEADER = b"RIFF"


def _parse_wav(data: bytes, off: int) -> str:
    try:
        riff, size, wave = struct.unpack_from("<4sI4s", data, off)
        if riff != b"RIFF" or wave != b"WAVE":
            return ""
        pos = off + 12
        info = []
        while pos + 8 <= len(data):
            cid, csize = struct.unpack_from("<4sI", data, pos)
            if cid == b"fmt " and csize >= 16:
                fmt, ch, rate, _br, _ba, bits = struct.unpack_from("<HHIIHH", data, pos + 8)
                info.append(f"fmt={fmt} ch={ch} rate={rate} bits={bits}")
            if cid == b"data":
                info.append(f"data={csize}")
                break
            pos += 8 + csize + (csize & 1)
        return "; ".join(info)
    except struct.error:
        return ""


def scan() -> list[dict]:
    db = connect()
    out = []
    for (rel,) in db.execute("SELECT path FROM files ORDER BY size DESC"):
        p = config.UNPACK / rel
        if not p.is_file():
            continue
        data = p.read_bytes()
        for magic, name in CONTAINERS:
            start = 0
            while True:
                i = data.find(magic, start)
                if i < 0:
                    break
                rec = {"file": rel, "offset": i, "kind": name}
                if name == "RIFF":
                    detail = _parse_wav(data, i)
                    if not detail:
                        start = i + 1
                        continue
                    rec["detail"] = detail
                out.append(rec)
                start = i + 1
                if len(out) > 500:
                    return out
    return out


def keyword_hits() -> dict[str, list[tuple[str, int]]]:
    db = connect()
    res: dict[str, list[tuple[str, int]]] = {}
    for (rel,) in db.execute("SELECT path FROM files ORDER BY size DESC"):
        p = config.UNPACK / rel
        if not p.is_file():
            continue
        data = p.read_bytes()
        for kw in KEYWORDS:
            i = data.find(kw)
            if i >= 0:
                res.setdefault(kw.decode("ascii", "ignore"), []).append((rel, i))
    return res


def extract(rel: str, offset: int, length: int, out: Path,
            rate: int = 48000, channels: int = 1, bits: int = 16) -> Path:
    """把一段原始字节包成 WAV，便于直接试听。"""
    src = (config.UNPACK / rel).read_bytes()[offset:offset + length]
    if bits == 8:
        # WAV 的 8bit 是 unsigned，源数据按 signed 处理
        src = bytes((b + 128) & 0xFF for b in src)
    block = channels * bits // 8
    byte_rate = rate * block
    hdr = b"RIFF" + struct.pack("<I", 36 + len(src)) + b"WAVE"
    hdr += b"fmt " + struct.pack("<IHHIIHH", 16, 1, channels, rate, byte_rate, block, bits)
    hdr += b"data" + struct.pack("<I", len(src))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(hdr + src)
    print(f"写出 {out}（{human(len(src))}，{rate}Hz/{channels}ch/{bits}bit）")
    return out


def run() -> int:
    hits = scan()
    print(f"音频容器命中 {len(hits)} 处")
    for h in hits[:80]:
        print(f"  {h['kind']:<12} {h['file']} @0x{h['offset']:x} {h.get('detail','')}")

    kw = keyword_hits()
    print("\n关键字命中（文件数）:")
    for k, v in sorted(kw.items(), key=lambda kv: -len(kv[1])):
        print(f"  {k:<10} {len(v):>4} 个文件  例: {v[0][0]} @0x{v[0][1]:x}")
    return 0
