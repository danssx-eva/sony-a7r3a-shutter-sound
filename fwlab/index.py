"""把解包树建成 sqlite 索引，后续搜索都走它。"""
from __future__ import annotations
import sqlite3
from pathlib import Path

from . import config
from .util import entropy, human, sha1_bytes, sniff

SCHEMA = """
CREATE TABLE IF NOT EXISTS files (
    id      INTEGER PRIMARY KEY,
    path    TEXT UNIQUE,
    size    INTEGER,
    sha1    TEXT,
    magic   TEXT,
    entropy REAL
);
CREATE INDEX IF NOT EXISTS idx_magic ON files(magic);
"""


def connect() -> sqlite3.Connection:
    db = sqlite3.connect(config.WORK / "index.db")
    db.executescript(SCHEMA)
    return db


def run() -> int:
    if not config.UNPACK.exists():
        raise SystemExit("先跑 `python -m fwlab unpack`")

    db = connect()
    db.execute("DELETE FROM files")
    rows = []
    total = 0
    for p in sorted(config.UNPACK.rglob("*")):
        if not p.is_file():
            continue
        size = p.stat().st_size
        total += size
        with open(p, "rb") as f:
            head = f.read(4096)
            body = head + f.read(max(0, size - len(head))) if size <= 64 << 20 else head
        rows.append((
            str(p.relative_to(config.UNPACK)), size, sha1_bytes(body),
            sniff(head), round(entropy(head), 3),
        ))
    db.executemany("INSERT OR REPLACE INTO files(path,size,sha1,magic,entropy) VALUES (?,?,?,?,?)", rows)
    db.commit()

    print(f"{len(rows)} 个文件，共 {human(total)}")
    print(f"{'类型':<16}{'数量':>6}{'大小':>14}")
    for magic, cnt, sz in db.execute(
        "SELECT magic, COUNT(*), SUM(size) FROM files GROUP BY magic ORDER BY SUM(size) DESC"
    ):
        print(f"{magic:<16}{cnt:>6}{human(sz):>14}")
    return 0
