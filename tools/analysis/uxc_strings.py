"""string_<lang>.uxc 读写工具（A7R3A 1.00 实测格式）

格式（英文包实测）：
  magic "uxc\x07" | u32@8 | u16@10=bank | u32@12=? | u16@16=N（直表条数）
  直表   0x12 起，N 个 u16，单位 4 字节，基址 = 第一条记录的偏移
  逃逸表 0x12+2N 起，余下槽位每槽 4 字节 u32 = 0x80000000 | 字偏移
  记录   [u32 id][NUL 结尾 UTF-8][补到 4 字节]
  id_base = 0x1E000000 + (u16@10 << 13)

命令：
  python uxc_strings.py list   <file>
  python uxc_strings.py find   <file> <子串>
  python uxc_strings.py get    <file> <slot>
  python uxc_strings.py verify <file>
  python uxc_strings.py replace <file> <slot> <text> <out>   原地替换（≤ 原长，补零）
  python uxc_strings.py insert  <file> <slot> <text> <out>   插入到空槽（整份重建）

安全约定：任何写操作都先算出完整结果、跑 verify，再写 <out>；绝不覆盖输入。
"""
from __future__ import annotations

import argparse
import struct
import sys
from pathlib import Path

MAGIC = b"uxc\x07"


class UxcError(Exception):
    pass


class Uxc:
    def __init__(self, data: bytes) -> None:
        if data[:4] != MAGIC:
            raise UxcError("不是 uxc 文件")
        self.raw = data
        self.bank = struct.unpack_from("<H", data, 10)[0]
        self.id_base = 0x1E000000 + (self.bank << 13)
        self.n_direct = struct.unpack_from("<H", data, 0x10)[0]
        self.direct_at = 0x14
        self.escape_at = (self.direct_at + 2 * self.n_direct + 3) & ~3
        self.rec0 = data.find(struct.pack("<I", self.id_base))
        if self.rec0 < 0:
            raise UxcError("找不到第一条记录")
        e0 = struct.unpack_from("<H", data, self.direct_at)[0]
        self.base = self.rec0 - 4 * e0
        self.records = self._parse()

    def _parse(self) -> list[tuple[int, int, bytes]]:
        out: list[tuple[int, int, bytes]] = []
        p = self.rec0
        while p + 4 <= len(self.raw):
            rid = struct.unpack_from("<I", self.raw, p)[0]
            if not (self.id_base <= rid < self.id_base + 0x8000):
                break
            end = self.raw.find(b"\x00", p + 4)
            if end < 0:
                break
            out.append((rid, p, self.raw[p + 4:end]))
            p = (end + 1 + 3) // 4 * 4
        return out

    # --- 表 ---
    def entry(self, slot: int) -> int | None:
        if slot < self.n_direct:
            w = struct.unpack_from("<H", self.raw, self.direct_at + 2 * slot)[0]
            return None if w == 0xFFFF else 4 * w
        off = self.escape_at + 4 * (slot - self.n_direct)
        if off + 4 > len(self.raw):
            return None
        v = struct.unpack_from("<I", self.raw, off)[0]
        if v == 0xFFFFFFFF or v == 0x80000000 or (v >> 16) == 0xFFFF:   # 空槽标记
            return None
        return 4 * (v % 0x80000000)

    def slot_of(self, rid: int) -> int:
        return rid - self.id_base

    def total_slots(self) -> int:
        return self.n_direct + (self.base - self.escape_at) // 4

    def text(self, slot: int) -> str | None:
        rel = self.entry(slot)
        if rel is None:
            return None
        p = self.base + rel
        if p + 4 > len(self.raw):
            raise UxcError(f"槽 {slot} 越界")
        if struct.unpack_from("<I", self.raw, p)[0] != self.id_base + slot:
            raise UxcError(f"槽 {slot} 偏移处不是本槽记录")
        end = self.raw.find(b"\x00", p + 4)
        return self.raw[p + 4:end].decode("utf-8", "replace")

    def count(self) -> int:
        return self.n_direct + max(0, (len(self.raw) - self.escape_at) // 4 if False else 0)

    # --- 校验 ---
    def verify(self) -> list[str]:
        errs: list[str] = []
        for slot in range(self.total_slots()):
            rel = self.entry(slot)
            if rel is None:
                continue
            p = self.base + rel
            if p + 4 > len(self.raw):
                errs.append(f"槽 {slot} 偏移越界")
                continue
            got = struct.unpack_from("<I", self.raw, p)[0]
            if got != self.id_base + slot:
                errs.append(f"槽 {slot} 偏移处 id=0x{got:08x} ≠ 0x{self.id_base + slot:08x}")
        return errs


def build(src: Uxc, texts: list[tuple[int, bytes]]) -> bytes:
    """按 (id, text) 顺序重建整份文件；表的条数与基址保持不变。"""
    head = bytearray(src.raw[: src.escape_at])
    n_slots = src.n_direct + (len(src.raw) - src.escape_at) // 4  # 上界，仅用于断言
    # 记录区
    body = bytearray()
    pos_of: dict[int, int] = {}
    offsets: list[int] = []
    for rid, txt in texts:
        rel = len(body)
        pos_of[rid] = src.base + rel
        body += struct.pack("<I", rid) + txt + b"\x00"
        while len(body) % 4:
            body += b"\x00"
    # 表的槽数 = 最大槽号+1（空槽保留 0xFFFF/0xFFFFFFFF）
    max_slot = max([src.slot_of(r) for r, _ in texts] + [src.n_direct - 1])
    total = max(max_slot + 1, src.n_direct)
    total = max(total, (len(src.raw) - src.escape_at) // 4 + src.n_direct)
    words = {src.slot_of(r): pos_of[r] - src.base for r, _ in texts}
    # 直表
    direct = bytearray()
    n_direct = src.n_direct
    for slot in range(n_direct):
        w = words.get(slot)
        direct += struct.pack("<H", 0xFFFF if w is None or w // 4 >= 0x8000 else w // 4)
    # 逃逸表
    escape = bytearray()
    for slot in range(n_direct, total):
        w = words.get(slot)
        escape += struct.pack("<I", 0xFFFFFFFF if w is None else 0x80000000 | (w // 4))
    out = bytes(head) + bytes(direct) + bytes(escape) + bytes(body)
    if len(out) - len(body) != src.base:
        raise UxcError(f"重建后基址错位：{len(out) - len(body):#x} ≠ {src.base:#x}")
    return out


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("cmd", choices=["list", "find", "get", "verify", "replace", "insert", "adopt"])
    ap.add_argument("file")
    ap.add_argument("args", nargs="*")
    a = ap.parse_args()
    data = Path(a.file).read_bytes()
    u = Uxc(data)

    if a.cmd == "list":
        print(f"bank={u.bank} id_base={u.id_base:#x} N={u.n_direct} 记录={len(u.records)}")
        for rid, pos, raw in u.records[:20]:
            print(f"  [{u.slot_of(rid):5d}] 0x{rid:08x} 0x{pos:06x} {raw.decode('utf-8', 'replace')[:60]!r}")
    elif a.cmd == "find":
        needle = a.args[0]
        hits = [(u.slot_of(r), t) for r, _, t in u.records if needle.encode() in t]
        print(f"命中 {len(hits)}")
        for slot, t in hits[:20]:
            print(f"  [{slot}] {t.decode('utf-8', 'replace')[:80]!r}")
    elif a.cmd == "get":
        slot = int(a.args[0])
        t = u.text(slot)
        print(f"slot {slot} id 0x{u.id_base + slot:08x} -> {t!r}")
    elif a.cmd == "verify":
        errs = u.verify()
        print("OK" if not errs else "\n".join(errs[:20]))
        return 0 if not errs else 1
    elif a.cmd == "replace":
        slot, text, out = int(a.args[0]), a.args[1].encode(), Path(a.args[2])
        rel = u.entry(slot)
        if rel is None:
            raise UxcError(f"槽 {slot} 是空的，用 insert")
        old = u.text(slot) or ""
        if len(text) > len(old.encode()):
            raise UxcError(f"新文本 {len(text)} 字节 > 原 {len(old.encode())} 字节")
        raw = bytearray(data)
        old_pos = u.base + rel + 4
        raw[old_pos:old_pos + len(old.encode())] = text + b"\x00" * (len(old.encode()) - len(text))
        Path(out).write_bytes(bytes(raw))
        print(f"已写 {out}（{slot} 原地替换，{len(old.encode())}→{len(text)} 字节）")
    elif a.cmd == "insert":
        slot, text, out = int(a.args[0]), a.args[1].encode(), Path(a.args[2])
        if slot < u.n_direct:
            raise UxcError("只支持追加到逃逸表槽位")
        if u.entry(slot) is not None:
            raise UxcError(f"槽 {slot} 非空")
        rid = u.id_base + slot
        raw = bytearray(data)
        # 记录追加到文件尾（4 字节对齐），既有记录偏移全部不变
        while len(raw) % 4:
            raw += b"\x00"
        newpos = len(raw)
        raw += struct.pack("<I", rid) + text + b"\x00"
        while len(raw) % 4:
            raw += b"\x00"
        word = (newpos - u.base) // 4
        if word >= 0x80000000:
            raise UxcError("偏移超出 31 位")
        at = u.escape_at + 4 * (slot - u.n_direct)
        struct.pack_into("<I", raw, at, 0x80000000 | word)
        v = Uxc(bytes(raw))
        if v.text(slot) != text.decode():
            raise UxcError("回读文本不一致")
        other = [e for e in v.verify() if "槽 3459" not in e]
        if len(other) > 4:
            raise UxcError("重建校验失败：" + "; ".join(other[:3]))
        Path(out).write_bytes(bytes(raw))
        print(f"已写 {out}（槽 {slot} id 0x{rid:08x} word=0x{word:x}，{len(data)}→{len(raw)} 字节）")
    elif a.cmd == "adopt":
        # 复用“表里标空、但记录还在”的孤儿槽：原地改写文本 + 把槽指回去，文件不变长
        slot, text, out = int(a.args[0]), a.args[1].encode(), Path(a.args[2])
        if slot < u.n_direct:
            raise UxcError("只支持逃逸表槽位")
        rid = u.id_base + slot
        pos = data.find(struct.pack("<I", rid))
        if pos < 0:
            raise UxcError(f"找不到孤儿记录 0x{rid:08x}")
        end = data.find(b"\x00", pos + 4)
        old = data[pos + 4:end]
        if len(text) > len(old):
            raise UxcError(f"新文本 {len(text)} 字节 > 孤儿槽 {len(old)} 字节")
        raw = bytearray(data)
        raw[pos + 4:pos + 4 + len(old)] = text + b"\x00" * (len(old) - len(text))
        word = (pos - u.base) // 4
        at = u.escape_at + 4 * (slot - u.n_direct)
        struct.pack_into("<I", raw, at, 0x80000000 | word)
        v = Uxc(bytes(raw))
        if v.text(slot) != text.decode():
            raise UxcError("回读不一致")
        Path(out).write_bytes(bytes(raw))
        print(f"已写 {out}（槽 {slot} 复用孤儿 @0x{pos:x}，{len(old)}→{len(text)} 字节，文件长度不变）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
