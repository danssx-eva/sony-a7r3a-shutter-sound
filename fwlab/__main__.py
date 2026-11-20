"""命令行入口：python -m fwlab <command>"""
from __future__ import annotations
import argparse
import sys
from pathlib import Path

from . import audio, carve, config, fetch, index, report, search, unpack


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="fwlab", description="ILCE-7RM3 固件只读分析")
    sub = ap.add_subparsers(dest="cmd", required=True)

    sub.add_parser("fetch", help="下载官方 updater")
    sub.add_parser("carve", help="从 exe 切出 DAT 容器")
    sub.add_parser("unpack", help="解密并解包")
    sub.add_parser("index", help="建立 sqlite 索引")
    sub.add_parser("audio", help="音频资产扫描")
    sub.add_parser("report", help="生成 markdown 报告")

    f = sub.add_parser("find", help="字符串/十六进制搜索")
    f.add_argument("pattern")
    f.add_argument("--glob", default="*")
    f.add_argument("--limit", type=int, default=200)
    f.add_argument("--case", action="store_true", help="区分大小写")

    e = sub.add_parser("extract", help="把一段原始字节导出成 WAV")
    e.add_argument("file")
    e.add_argument("offset", type=lambda s: int(s, 0))
    e.add_argument("length", type=lambda s: int(s, 0))
    e.add_argument("out")
    e.add_argument("--rate", type=int, default=48000)
    e.add_argument("--channels", type=int, default=1)
    e.add_argument("--bits", type=int, default=16)

    s = sub.add_parser("sym", help="在 ELF 里查符号")
    s.add_argument("pattern")
    s.add_argument("--lib", default="lib/libObj.so")

    d = sub.add_parser("dis", help="反汇编符号或地址")
    d.add_argument("target")
    d.add_argument("--lib", default="lib/libObj.so")
    d.add_argument("--count", type=int, default=40)
    d.add_argument("--arm", action="store_true")

    c = sub.add_parser("callers", help="找 BL/BLX 调用点")
    c.add_argument("target")
    c.add_argument("--lib", default="lib/libObj.so")
    c.add_argument("--around", type=int, default=12, help="每个调用点前后反汇编条数")

    args = ap.parse_args(argv)

    if args.cmd == "fetch":
        return fetch.run()
    if args.cmd == "carve":
        return carve.run()
    if args.cmd == "unpack":
        return unpack.run()
    if args.cmd == "index":
        return index.run()
    if args.cmd == "audio":
        return audio.run()
    if args.cmd == "report":
        return report.run()
    if args.cmd == "find":
        return search.run(args.pattern, ignore_case=not args.case, limit=args.limit, glob=args.glob)
    if args.cmd == "extract":
        audio.extract(args.file, args.offset, args.length, Path(args.out),
                      rate=args.rate, channels=args.channels, bits=args.bits)
        return 0
    if args.cmd in ("sym", "dis", "callers"):
        from . import arm
        elf = arm.Elf(config.UNPACK / "firmware.tar_unpacked/0700_part_image/dev/nflasha15_unpacked" / args.lib)
        tgt = args.target
        if args.cmd == "sym":
            hits = [k for k in elf.symbols if args.pattern.lower() in k.lower()]
            print(f"{len(hits)} 个符号")
            for k in sorted(hits, key=lambda k: elf.symbols[k][0]):
                v, sz = elf.symbols[k]
                print(f"  0x{v:08x}  size={sz:<5} {k}")
            return 0
        addr = int(tgt, 0) if tgt.startswith("0x") else (elf.sym(tgt)[0] & ~1)
        if args.cmd == "dis":
            for ins in elf.disasm(addr, args.count * 4, count=args.count, thumb=not args.arm):
                print(f"  0x{ins.address:08x}: {ins.mnemonic:<8}{ins.op_str}")
            return 0
        calls = elf.bl_calls(addr)
        print(f"{len(calls)} 处调用 -> 0x{addr:08x}")
        for caddr, kind in calls:
            print(f"  caller 0x{caddr:08x} ({kind})")
            start = max(addr - 0, caddr - args.around * 2)
            for ins in elf.disasm(start, (caddr - start) + 4):
                mark = "  <== call" if ins.address == caddr else ""
                print(f"     0x{ins.address:08x}: {ins.mnemonic:<8}{ins.op_str}{mark}")
        return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
