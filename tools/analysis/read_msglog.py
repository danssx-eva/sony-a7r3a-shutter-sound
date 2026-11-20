"""读取 osal_rcv_msg_tmo 环形缓冲日志并解析（只读，不改相机任何状态）

流程
    1. /proc/155/maps → libosal_uipc.so 基址
    2. 读粘滞区 base+0xEFE0 = { u32 buf_ptr ; u32 calls }
    3. buf_ptr == 0 → 载荷还没分配缓冲（函数没被调用过，或还没收到包）
    4. 读缓冲头 {cursor, count, magic} 与 count 条 8 字节记录
    5. 输出明细表 + 按消息头聚合的统计

用法
    python tools/read_msglog.py                      # 连相机读一次并汇报
    python tools/read_msglog.py --last 60            # 只打印最近 60 条明细
    python tools/read_msglog.py --dump raw.bin       # 顺便把原始数据存本地
    python tools/read_msglog.py --file raw.bin       # 离线解析本地 dump（不连相机）
    python tools/read_msglog.py --json out.json      # 结果存 JSON

dump 文件格式（--dump 写、--file 读）：粘滞区 8B + 缓冲 8208B = 8216B
"""
from __future__ import annotations

import argparse
import json
import pathlib as _pl
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))

_ROOT = _pl.Path(__file__).resolve().parents[2]

sys.path.insert(0, str(_ROOT / 'tools' / 'camera'))

sys.path.insert(0, str(_ROOT / 'vendor' / 'Sony-PMCA-RE'))

import a7r3a_shell as A                                    # noqa: E402

LAB = pathlib.Path(__file__).resolve().parents[2]
LIBOSAL_SO = "libosal_uipc.so"

# ---- 与 build_msglog_payload.py 必须一致的布局常量 ----
G_OFF = 0xEFE0          # 粘滞区：{u32 buf_ptr, u32 calls}
G_SIZE = 8
BUF_HDR = 0x10
RECORD_BYTES = 8
DEFAULT_RECORDS = 1024
BUF_SIZE = BUF_HDR + DEFAULT_RECORDS * RECORD_BYTES      # 0x2010
MAGIC = 0x4D53474C      # "MSGL"
BUF_MAP_LEN = 0x8000
HOLE_OFF = 0x6000
DUMP_SIZE = G_SIZE + BUF_SIZE


# --------------------------------------------------------------------------
def parse_dump(raw: bytes, records: int = DEFAULT_RECORDS) -> dict:
    """把 8B 粘滞区 + 8208B 缓冲解析成结构化结果"""
    if len(raw) < G_SIZE + BUF_HDR:
        raise ValueError(f"dump 太短: {len(raw)}")
    buf_ptr, calls = struct.unpack_from("<2I", raw, 0)
    out = dict(buf_ptr=buf_ptr, calls=calls, ok=False)
    if buf_ptr == 0:
        out["reason"] = "载荷还没有缓冲（osal_rcv_msg_tmo 尚未成功收包）"
        return out
    buf = raw[G_SIZE:G_SIZE + BUF_SIZE]
    if len(buf) < BUF_HDR:
        out["reason"] = "dump 不含缓冲内容"
        return out
    cursor, count, magic, _pad = struct.unpack_from("<4I", buf, 0)
    out.update(cursor=cursor, count=count, magic=magic)
    if magic != MAGIC:
        out["reason"] = f"magic 不匹配: 0x{magic:08x}（期望 0x{MAGIC:08x}）"
        return out
    n = min(count, records)
    recs_off = BUF_HDR
    items = []
    for seq in range(count - n, count):
        slot = seq % records
        h0, h1 = struct.unpack_from("<2I", buf, recs_off + slot * RECORD_BYTES)
        items.append(dict(seq=seq, slot=slot, h0=h0, h1=h1))
    out.update(ok=True, items=items)
    return out


def summarize(items: list[dict]) -> list[dict]:
    agg: dict[tuple[int, int], list[int]] = {}
    for it in items:
        agg.setdefault((it["h0"], it["h1"]), []).append(it["seq"])
    rows = []
    for (h0, h1), seqs in agg.items():
        rows.append(dict(h0=h0, h1=h1, n=len(seqs), first=seqs[0], last=seqs[-1],
                         gaps=[b - a for a, b in zip(seqs, seqs[1:])][:8]))
    rows.sort(key=lambda r: (-r["n"], r["h0"], r["h1"]))
    return rows


# --------------------------------------------------------------------------
def fetch(cam: A.Cam, base: int, records: int = DEFAULT_RECORDS) -> bytes:
    """读粘滞区 + 缓冲；缓冲指针为 0 时只返回粘滞区 + 零缓冲"""
    g = cam.read_mem(base + G_OFF, G_SIZE)
    buf_ptr = struct.unpack_from("<I", g, 0)[0]
    if buf_ptr == 0:
        return g + b"\x00" * BUF_SIZE
    # 只读实际用到的部分，省传输
    hdr = cam.read_mem(buf_ptr, BUF_HDR)
    cursor, count, magic, _ = struct.unpack_from("<4I", hdr, 0)
    if magic != MAGIC:
        return g + hdr + b"\x00" * (BUF_SIZE - BUF_HDR)
    n = min(count, records)
    body = cam.read_mem(buf_ptr + BUF_HDR, n * RECORD_BYTES) if n else b""
    return g + hdr + body + b"\x00" * (BUF_SIZE - BUF_HDR - len(body))


def report(res: dict, last: int = 40, top: int = 30) -> None:
    print("=" * 86)
    print("osal_rcv_msg_tmo 环形缓冲日志")
    print("=" * 86)
    print(f"  粘滞区  buf_ptr=0x{res['buf_ptr']:08x}   hook 调用次数 calls={res['calls']}")
    if not res.get("ok"):
        print(f"  ⚠ {res.get('reason')}")
        if res["calls"] == 0:
            print("    → 钩点一次都没被调用：可能 osal_rcv_msg_tmo 不是当前活跃的收包路径")
            print("      可改用 --scheme entry-count 先确认，或改钩 u_osal_rcv_msg_tmo")
        return
    print(f"  缓冲    cursor={res['cursor']}  count={res['count']}  "
          f"magic=0x{res['magic']:08x} ({'MSGL' if res['magic'] == MAGIC else '?'})")
    items = res["items"]
    print(f"  本次解析 {len(items)} 条（容量 {DEFAULT_RECORDS}，满了覆盖最老）")
    if not items:
        return

    print()
    print(f"  最近 {min(last, len(items))} 条明细（序号 | 头0x0 | 头0x4 | 槽位）")
    print("  " + "-" * 82)
    print(f"  {'序号':>7}  {'头[0:4]':>10}  {'头[4:8]':>10}  {'槽':>5}")
    for it in items[-last:]:
        print(f"  {it['seq']:>7}  0x{it['h0']:08x}  0x{it['h1']:08x}  {it['slot']:>5}")

    rows = summarize(items)
    print()
    print(f"  按消息头聚合（共 {len(rows)} 种），出现次数降序前 {min(top, len(rows))} 种：")
    print("  " + "-" * 82)
    print(f"  {'次数':>6}  {'头[0:4]':>10}  {'头[4:8]':>10}  {'首序':>7} {'末序':>7}  间隔样本")
    for r in rows[:top]:
        gaps = ",".join(str(g) for g in r["gaps"][:6])
        print(f"  {r['n']:>6}  0x{r['h0']:08x}  0x{r['h1']:08x}  "
              f"{r['first']:>7} {r['last']:>7}  {gaps}")
    print()
    print("  ↳ 拍 N 张后，出现次数≈N 且间隔稳定的那条，就是「每帧一次」的候选消息。")


# --------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--file", type=pathlib.Path, default=None,
                    help="离线解析本地 dump（不连相机）")
    ap.add_argument("--dump", type=pathlib.Path, default=None, help="把原始数据存到本地")
    ap.add_argument("--json", type=pathlib.Path, default=None, help="结果存 JSON")
    ap.add_argument("--last", type=int, default=40, help="打印最近多少条明细")
    ap.add_argument("--top", type=int, default=30, help="聚合表最多打印多少行")
    ap.add_argument("--base", type=lambda x: int(x, 0), default=None,
                    help="libosal_uipc.so 基址（默认从 maps 读）")
    ap.add_argument("--pid", type=int, default=A.DEFAULT_PID)
    a = ap.parse_args()

    # ---- 离线 ----
    if a.file:
        raw = a.file.read_bytes()
        res = parse_dump(raw)
        report(res, a.last, a.top)
        if a.json:
            a.json.write_text(json.dumps(dict(res, items=res.get("items", [])),
                                         ensure_ascii=False, indent=2), encoding="utf-8")
            print(f"\n  JSON → {a.json}")
        return 0 if res.get("ok") else 3

    # ---- 连相机 ----
    def work(cam: A.Cam):
        ms = cam.maps()
        base = a.base if a.base is not None else A.find_base(ms, LIBOSAL_SO)
        if base is None:
            raise RuntimeError("在 /proc/155/maps 里找不到 libosal_uipc.so")
        m = A.mapping_at(ms, base)
        print(f"  libosal_uipc.so 基址 0x{base:08x}  映射 {m}")
        if a.base is None and base != 0x04050000:
            print(f"  ⚠ 基址与预期 0x04050000 不同（ASLR?）；载荷若是按旧基址注入的需要重新注入")
        raw = fetch(cam, base)
        return base, raw

    base, raw = A.run_on_camera(work)
    res = parse_dump(raw)
    res["base"] = base
    report(res, a.last, a.top)
    if a.dump:
        a.dump.write_bytes(raw)
        print(f"\n  原始数据 → {a.dump}（{len(raw)} 字节）")
    if a.json:
        a.json.write_text(json.dumps(res, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"  JSON → {a.json}")
    return 0 if res.get("ok") else 3


if __name__ == "__main__":
    sys.exit(main())
