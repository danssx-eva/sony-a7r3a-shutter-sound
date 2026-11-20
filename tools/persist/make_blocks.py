"""从原厂 libObj.so 和载荷生成两个 1 KB 闪存块。

持久化那一步往相机上写的就是这两个块。本项目不提供现成的块文件——块里除了本项目的
补丁，其余是 Sony 的原始代码，分发它们等于分发 Sony 二进制。所以你在自己机器上生成。

用法：
    python tools/persist/make_blocks.py --so backup/<时间戳>/usr_lib_libObj.so --hook 63f7579b
    python tools/persist/make_blocks.py --so <原厂.so> --hook 63f7579b --payload docs/patches/payload.bin
    python tools/persist/make_blocks.py --so <原厂.so> --hook 63f7579b --outdir work/blocks

产物：
    blkA.bin     1 KB，钩点所在块（文件偏移 0xA31000）
    blkB.bin     1 KB，载荷所在块（文件偏移 0x194800）
    blocks.json  块内偏移、原厂块哈希、预期整文件 SHA256

脚本会自检：
    · 原厂块的 MD5 必须与记录值一致（防止拿错构建）
    · 改完的整文件 SHA256 必须与 soundId 对应的记录值一致
"""

from __future__ import annotations

import argparse
import hashlib
import json
import pathlib
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

# 布局（fileVA）
HOOK = 0xA31226          # 钩点 4 字节
SLOT = 0x1948D8          # 载荷起点
PAYLOAD_LEN = 240

BLK_SIZE = 1024
BLK_A = (HOOK // BLK_SIZE) * BLK_SIZE      # 0xA31000
BLK_B = (SLOT // BLK_SIZE) * BLK_SIZE      # 0x194800

# 原厂整文件
SHA_FACTORY = "f1351204d2dd1c4033d427e09e7848fbbff0dd577abb205e00ef97bb4e6b81ed"

# 打完补丁后的整文件 SHA（取决于载荷里的 soundId）
SHA_PATCHED = {
    0x04: "d45ca8d7821b7a771555faab179ec268316d75acb4cb1a0ee8bae70453730e6a",
    0x07: "d80aa1e00b84f5f719eb5e427bf760a06b81b6401a7550edada355d8f2d4a960",
}

# 原厂块 MD5（用来校验拿到的 .so 是不是同一个构建）
MD5_BLOCK_A = "dec50e33dee037f0567ac23fc992f625"
MD5_BLOCK_B = "931b4cbea18416ce22442b5dca5263ce"


def md5(b: bytes) -> str:
    return hashlib.md5(b).hexdigest()


def sha256(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def main() -> int:
    ap = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--so", type=pathlib.Path, required=True,
                    help="原厂 libObj.so（从相机备份里来）")
    ap.add_argument("--payload", type=pathlib.Path,
                    default=ROOT / "docs" / "patches" / "payload.bin",
                    help="载荷二进制，默认 docs/patches/payload.bin")
    ap.add_argument("--hook", default=None,
                    help="钩子 4 字节，十六进制，如 63f7579b。不给则从原厂 .so 里保留原值（不推荐）")
    ap.add_argument("--outdir", type=pathlib.Path, default=None,
                    help="输出目录，默认 <仓库>/work/blocks")
    ap.add_argument("--skip-sha-check", action="store_true",
                    help="跳过整文件 SHA 校验（只用于别的 soundId）")
    args = ap.parse_args()

    if not args.so.exists():
        print(f"找不到 {args.so}")
        return 2
    if not args.payload.exists():
        print(f"找不到载荷 {args.payload}")
        print("  先跑 tools/build_payload/build_burst_only.py 生成")
        return 2

    orig = args.so.read_bytes()
    data = bytearray(orig)
    print(f"原厂 .so  {len(data):,} 字节")

    # ---- 校验：这是不是原厂 ----
    whole_sha = sha256(data)
    if whole_sha == SHA_FACTORY:
        print("  整文件 SHA256 = 原厂 ✓")
    else:
        print(f"  ⚠ 整文件 SHA256 = {whole_sha[:24]}…")
        print("    不是原厂值，说明这台机器/这个文件已经被改过。")
        for sid, want in SHA_PATCHED.items():
            if whole_sha == want:
                print(f"    它等于 soundId 0x{sid:02x} 打完补丁后的值。")
                print("    要重新生成块，请先回滚到原厂，或者用真正的原厂备份。")
                return 1
        print("    不认识的 SHA，先搞清楚这个文件是什么再继续。")
        return 1

    # ---- 校验：两个块是否与原厂记录一致 ----
    blk_a_orig = bytes(data[BLK_A:BLK_A + BLK_SIZE])
    blk_b_orig = bytes(data[BLK_B:BLK_B + BLK_SIZE])
    ok_a = md5(blk_a_orig) == MD5_BLOCK_A
    ok_b = md5(blk_b_orig) == MD5_BLOCK_B
    print(f"  块 A 0x{BLK_A:06X}  原厂 md5 {md5(blk_a_orig)}  {'✓' if ok_a else '✗ 与记录不符'}")
    print(f"  块 B 0x{BLK_B:06X}  原厂 md5 {md5(blk_b_orig)}  {'✓' if ok_b else '✗ 与记录不符'}")
    if not (ok_a and ok_b):
        print()
        print("块的原厂哈希与记录不一致。这通常意味着固件版本不同。")
        print("地址不能照搬，先用 tools/sigscan.py 在本地固件上重新定位。")
        return 1

    # ---- 载荷 ----
    payload = args.payload.read_bytes()
    if len(payload) != PAYLOAD_LEN:
        print(f"载荷长度 {len(payload)}，应该是 {PAYLOAD_LEN}")
        return 2
    print(f"载荷      {len(payload)} 字节  sha256 {sha256(payload)[:24]}")

    # ---- 钩子 ----
    hook_orig = bytes(data[HOOK:HOOK + 4])
    if args.hook:
        try:
            hook = bytes.fromhex(args.hook.replace(" ", ""))
        except ValueError:
            print(f"--hook 格式不对：{args.hook}（应该是 8 个十六进制字符）")
            return 2
        if len(hook) != 4:
            print(f"--hook 需要正好 4 字节，给了 {len(hook)}")
            return 2
        source = "命令行指定"
    else:
        hook = hook_orig
        source = "保留原厂值（危险）"
        print("  ⚠ 没给 --hook，钩子字节保持原样。这样不会跳到载荷。")
        print("    正常用法是 --hook 63f7579b（对应 b.w 到 0x1948D8）")
    print(f"钩子      {hook.hex()}  （原厂 {hook_orig.hex()}，{source}）")

    # ---- 写入 ----
    data[HOOK:HOOK + 4] = hook
    data[SLOT:SLOT + PAYLOAD_LEN] = payload

    out_sha = sha256(data)
    print()
    print(f"改后整文件 SHA256 {out_sha}")
    known = [sid for sid, want in SHA_PATCHED.items() if want == out_sha]
    if known:
        print(f"  与记录一致：soundId 0x{known[0]:02x} ✓")
    elif args.skip_sha_check:
        print("  （跳过了 SHA 校验）")
    else:
        print("  ⚠ 与记录的两个已知值都不一致。")
        print("    可能是别的 soundId，或者载荷内容不同。确认没问题再加 --skip-sha-check。")
        return 1

    # ---- 差异统计 ----
    n_diff = sum(1 for a, b in zip(data, orig) if a != b)
    print(f"  与原厂不同 {n_diff} 字节")

    # ---- 输出 ----
    outdir = args.outdir or (ROOT / "work" / "blocks")
    outdir.mkdir(parents=True, exist_ok=True)

    blk_a = bytes(data[BLK_A:BLK_A + BLK_SIZE])
    blk_b = bytes(data[BLK_B:BLK_B + BLK_SIZE])
    (outdir / "blkA.bin").write_bytes(blk_a)
    (outdir / "blkB.bin").write_bytes(blk_b)

    meta = {
        "source_so": str(args.so),
        "source_sha256": SHA_FACTORY,
        "out_sha256": out_sha,
        "bytes_changed": n_diff,
        "hook": hook.hex(),
        "hook_orig": hook_orig.hex(),
        "hook_fileva": f"0x{HOOK:X}",
        "payload_fileva": f"0x{SLOT:X}",
        "payload_len": PAYLOAD_LEN,
        "payload_sha256": sha256(payload),
        "blocks": [
            {
                "file": "blkA.bin",
                "file_offset": f"0x{BLK_A:X}",
                "file_offset_dec": BLK_A,
                "dd_block_index": BLK_A // BLK_SIZE,
                "edit_inner_offset": f"0x{HOOK - BLK_A:X}",
                "orig_md5": MD5_BLOCK_A,
                "new_md5": md5(blk_a),
            },
            {
                "file": "blkB.bin",
                "file_offset": f"0x{BLK_B:X}",
                "file_offset_dec": BLK_B,
                "dd_block_index": BLK_B // BLK_SIZE,
                "edit_inner_offset": f"0x{SLOT - BLK_B:X}",
                "orig_md5": MD5_BLOCK_B,
                "new_md5": md5(blk_b),
            },
        ],
    }
    (outdir / "blocks.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    print()
    print(f"输出到 {outdir}")
    print(f"  blkA.bin  1,024 B  md5 {md5(blk_a)}   写到文件偏移 0x{BLK_A:X}")
    print(f"  blkB.bin  1,024 B  md5 {md5(blk_b)}   写到文件偏移 0x{BLK_B:X}")
    print()
    print("相机上怎么用这两个块，见 docs/教程/06-持久化到闪存.md")
    print("上传到相机：python tools/camera/push_files.py --dir work/blocks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
