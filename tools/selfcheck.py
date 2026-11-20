"""对仓库里所有可执行工具跑一遍 --help，检查有没有导入错误或崩溃。

这是「新人拿到仓库能不能用」的自检。不需要相机，不需要 dump 文件。

用法：
    python tools/selfcheck.py
"""

from __future__ import annotations

import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]

# 需要 --help 就能退出的工具
SKIP = {
    "selfcheck.py",
    "a7r3a_shell.py",       # 库，不是 CLI
}

# 需要在仓库根目录跑、且可能需要相机的脚本，只检查能不能被 Python 解析
# 库模块，不是命令行工具，只检查能不能被 Python 解析
LIBRARIES = {
    "armlib.py",
    "emu_burst.py",
    "a7r3a_shell.py",
}

PARSE_ONLY = {
    "verify_environment.py",
    "a7r3a_prop.py",
    "a7r3a_status.py",
    "a7r3a_pull.py",
    "a7r3a_watch_pull.py",
    "a7r3a_clean_check.py",
    "a7r3a_restore_all.py",
    "a7r3a_restore_props.py",
    "a7r3a_recon_kernel.py",
    "a7r3a_film.py",
    "a7r3a_zh_label.py",
    "cam_memdump.py",
    "cam_memdump_file.py",
    "cam_mempoke.py",
    "inject_generic.py",
    "ldpreload_deploy.py",
    "read_probe.py",
    "sim_play_sound.py",
}


def iter_tools():
    for p in sorted((ROOT / "tools").rglob("*.py")):
        if p.name in SKIP:
            continue
        yield p


def main() -> int:
    ok = bad = skipped = 0
    problems = []

    for p in iter_tools():
        rel = p.relative_to(ROOT)
        if p.name in PARSE_ONLY or p.name in LIBRARIES:
            r = subprocess.run([sys.executable, "-c",
                                f"import ast,pathlib; ast.parse(pathlib.Path(r'{p}').read_text(encoding='utf-8'))"],
                               capture_output=True, text=True,
                               encoding="utf-8", errors="replace")
            if r.returncode == 0:
                ok += 1
            else:
                bad += 1
                problems.append((rel, "语法错误", r.stderr.strip().splitlines()[-1][:100] if r.stderr else ""))
            continue

        r = subprocess.run([sys.executable, str(p), "--help"],
                           capture_output=True, text=True, cwd=ROOT, timeout=120,
                           encoding="utf-8", errors="replace")
        if r.returncode == 0:
            ok += 1
        elif "SystemExit: 0" in r.stderr or "usage:" in (r.stdout + r.stderr).lower():
            skipped += 1
        else:
            bad += 1
            tail = (r.stderr or r.stdout).strip().splitlines()
            msg = tail[-1] if tail else ""
            problems.append((rel, f"exit={r.returncode}", msg[:100]))

    print(f"通过 {ok}   有问題 {bad}   跳过 {skipped}")
    if problems:
        print()
        for rel, kind, msg in problems:
            print(f"  {rel}")
            print(f"      {kind}: {msg}")
        return 1
    return 0


def check_doc_commands() -> int:
    """文档里写的每一行 python 命令，工具必须真的支持那些参数。

    文档和工具是分开写的，很容易漂：文档里写 --so，工具里是 --file，
    读者照着抄就失败。这个检查专门防这个。
    """
    import re

    docs = ROOT / "docs"
    if not docs.exists():
        return 0

    cmds: set[str] = set()
    for p in docs.rglob("*.md"):
        t = p.read_text(encoding="utf-8", errors="ignore")
        lines = t.split("\n")
        i = 0
        while i < len(lines):
            line = lines[i].strip()
            if not line.startswith(("python tools/", "python examples/")):
                i += 1
                continue
            # 拼接续行：行尾有 \ 就吃掉下一行
            buf = [line]
            while buf[-1].rstrip().endswith("\\") and i + 1 < len(lines):
                buf[-1] = buf[-1].rstrip()[:-1].rstrip()
                i += 1
                buf.append(lines[i].strip())
            cmd = " ".join(x for x in buf if x)
            cmd = re.sub(r"\s+#.*$", "", cmd)
            cmds.add(cmd)
            i += 1

    bad = 0
    for c in sorted(cmds):
        parts = c.split()
        script = ROOT / parts[1]
        if not script.exists():
            print(f"  [文件不存在] {c}")
            bad += 1
            continue
        try:
            r = subprocess.run([sys.executable, str(script), "--help"],
                               capture_output=True, text=True, encoding="utf-8",
                               errors="replace", cwd=ROOT, timeout=120)
        except subprocess.TimeoutExpired:
            print(f"  [--help 超时] {c}")
            bad += 1
            continue
        help_text = (r.stdout or "") + (r.stderr or "")
        missing = [a for a in parts[2:]
                   if a.startswith("--") and "=" not in a and a not in help_text]

        # 还要求文档命令把「必需参数」都带上。
        # argparse 的 usage 行里，必需参数不带方括号： [--opt X] 是可选， --req X 是必需。
        # usage 可能跨多行（互斥组常常折行），要一直取到空行或 options 为止
        usage_lines: list[str] = []
        collecting = False
        for line in help_text.split("\n"):
            low = line.strip().lower()
            if low.startswith("usage:"):
                collecting = True
                usage_lines.append(line)
                continue
            if collecting:
                if not line.strip() or low.startswith(("options:", "positional")):
                    break
                usage_lines.append(line)
        usage = " ".join(usage_lines)
        usage = re.sub(r"\[[^\]]*\]", "", usage)      # 去掉所有方括号块

        # 互斥组形如 (--a A | --b B)：只要求至少给一个
        groups = re.findall(r"\(([^()]*\|[^()]*)\)", usage)
        alternates: list[list[str]] = []
        for g in groups:
            opts = re.findall(r"--[a-z][a-z0-9\-]*", g)
            if len(opts) > 1:
                alternates.append(opts)
        usage_wo_groups = usage
        for g in groups:
            usage_wo_groups = usage_wo_groups.replace("(" + g + ")", " ")

        required = re.findall(r"--[a-z][a-z0-9\-]*", usage_wo_groups)
        given = {a.split("=")[0] for a in parts[2:]}
        not_given = [x for x in required if x not in given]

        # 互斥组里一个都没给，才算缺
        for opts in alternates:
            if not any(o in given for o in opts):
                not_given.append("/".join(opts[:2]) + " 之一")

        if r.returncode != 0 or missing or not_given:
            print(f"  [{parts[1]}] {c}")
            if missing:
                print(f"      工具不支持这些参数: {missing}")
            if not_given:
                print(f"      缺必需参数: {not_given}")
            bad += 1

    print(f"文档命令 {len(cmds)} 条，不匹配 {bad} 条")

    # 过时的文档路径（文档重组后留下的旧引用）
    stale_prefixes = ("docs/guide/", "docs/explain/", "docs/findings/")
    stale = 0
    for p in list((ROOT / "docs").rglob("*.md")) + [
            ROOT / "README.md", ROOT / "CONTRIBUTING.md", ROOT / "DISCLAIMER.md",
            ROOT / "tools" / "README.md", ROOT / "examples" / "README.md"]:
        if not p.exists():
            continue
        t = p.read_text(encoding="utf-8", errors="ignore")
        for i, line in enumerate(t.split("\n"), 1):
            if any(s in line for s in stale_prefixes):
                print(f"  [过时路径] {p.relative_to(ROOT)}:{i}  {line.strip()[:80]}")
                stale += 1
    if stale:
        print(f"过时路径 {stale} 处")
        bad += stale

    return bad


if __name__ == "__main__":
    rc = main()
    print()
    print("=== 文档命令与工具接口一致性 ===")
    bad = check_doc_commands()
    sys.exit(rc or (1 if bad else 0))
