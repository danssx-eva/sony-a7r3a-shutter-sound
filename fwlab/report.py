"""把索引/扫描结果汇总成一份 markdown 报告。"""
from __future__ import annotations
import datetime as dt

from . import config
from .index import connect
from .util import human


def run() -> int:
    db = connect()
    total_files, total_size = db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM files").fetchone()
    by_magic = list(db.execute(
        "SELECT magic, COUNT(*), SUM(size) FROM files GROUP BY magic ORDER BY SUM(size) DESC"
    ))
    biggest = list(db.execute("SELECT path,size,magic FROM files ORDER BY size DESC LIMIT 20"))

    lines = [
        "# ILCE-7RM3 固件分析报告",
        "",
        f"生成时间：{dt.datetime.now():%Y-%m-%d %H:%M}",
        f"样本：`{config.DAT_NAME}`（官方 3.10 Windows updater carv 所得）",
        f"文件数：{total_files}，总计 {human(total_size)}",
        "",
        "## 类型分布",
        "",
        "| 类型 | 数量 | 大小 |",
        "|---|---:|---:|",
    ]
    for magic, cnt, sz in by_magic:
        lines.append(f"| {magic} | {cnt} | {human(sz)} |")

    lines += ["", "## 最大的 20 个文件", "", "| 路径 | 大小 | 类型 |", "|---|---:|---|"]
    for path, size, magic in biggest:
        lines.append(f"| `{path}` | {human(size)} | {magic} |")

    out = config.REPORTS / "report.md"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"写出 {out}")
    return 0
