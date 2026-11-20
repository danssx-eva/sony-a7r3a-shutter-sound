#!/usr/bin/env python3
"""convert_audio —— 把普通音频转成 Sony 相机音效格式（.bin）

相机音效**不是裸 PCM**。格式是从相机固件里逆向出来的：

    每 32 字节一个块
    byte[0]      控制字节
                   bit0-3 = 指数 exponent  → step = 1 << exponent
                   bit4   = 预测器开关（原厂文件全是 1）
    byte[1..31]  31 个有符号残差（int8，-128..127）

    解码：last = residual * step + (PREDICTOR * last if control & 0x10 else 0)
    预测器系数 PREDICTOR = 60/64（= 0.9375）
    采样率 24000 Hz，单声道，样本为 int16

用法
----
生成示例音（不需要任何素材）::

    python examples/convert_audio.py --preset click --target caution --out my.bin

从自己的 WAV 转（WAV 需为 16-bit PCM；转码用 ffmpeg）::

    ffmpeg -i mine.mp3 -ar 24000 -ac 1 -sample_fmt s16 mine.wav
    python examples/convert_audio.py --input mine.wav --target caution --out my.bin

反解回 WAV 听一遍（**必做**，确认没有搞错）::

    python examples/convert_audio.py --decode my.bin --wav-out check.wav

注意
----
- `--size` 必须等于目标 `.bin` 的**原始大小**（相机按文件长度索引，多一字节都不行）。
  用 `--target <名字>` 可以从下表自动取大小。
- 建议只替换 **priority ≤ 5** 的音效（`0x01/0x02/0x03/0x05/0x06/0x37` 是 priority 6，本项目测试时没有声音）。
- 部署后必须**冷启动**（拔电池）才生效。部署与验证见 docs/05-声音系统.md §3.1。
"""
from __future__ import annotations

import argparse
import math
import random
import struct
import sys
import wave
from pathlib import Path

RATE = 24000
PREDICTOR = 60 / 64

# 相机自带的音效文件（名字 → (soundId, 字节大小, 是否可播)）
# 数据来自 docs/附录/结构规格.md；priority 6 的那几个在本项目测试时没有声音。
TARGETS: dict[str, tuple[int, int, bool]] = {
    "ka": (0x01, 256, False),
    "sha": (0x02, 2944, False),
    "kasha": (0x03, 2944, False),
    "focuslock": (0x04, 3712, True),
    "caution": (0x07, 8640, True),
    "select": (0x08, 2496, True),
    "menu_open": (0x0E, 1792, True),
    "wps_pbc": (0x33, 29760, True),
}


# ---------------------------------------------------------------------------
# 编解码
# ---------------------------------------------------------------------------
def encode(samples: list[int], use_predictor: bool = True) -> bytes:
    """把 int16 样本编码成相机格式（每 32 字节一块）。"""
    out = bytearray()
    last = 0.0
    for at in range(0, len(samples), 31):
        block = list(samples[at:at + 31])
        block += [0] * (31 - len(block))

        best: tuple[int, list[int], float] | None = None
        for exp in range(10):
            step = 1 << exp
            pl = last
            residuals: list[int] = []
            ok = True
            max_err = 0
            for x in block:
                pred = PREDICTOR * pl if use_predictor else 0.0
                r = round((x - pred) / step)
                if r < -128 or r > 127:
                    ok = False
                    break
                residuals.append(r)
                pl = r * step + pred
                max_err = max(max_err, abs(pl - x))
            if ok:
                best = (exp, residuals, pl)
                if max_err < step:          # 已经够精确，不再增大指数
                    break
        if best is None:
            exp, residuals, pl = 9, [0] * 31, last
        else:
            exp, residuals, pl = best

        out.append((0x10 if use_predictor else 0x00) | exp)
        out.extend(r & 0xFF for r in residuals)
        last = pl

    if len(out) % 64:                        # 原厂文件都是 64 的倍数
        out.extend(bytes(32))
    return bytes(out)


def decode(raw: bytes) -> list[int]:
    """把相机格式解回 int16 样本。"""
    samples: list[int] = []
    last = 0.0
    for off in range(0, len(raw), 32):
        control = raw[off]
        step = 1 << (control & 0x0F)
        for byte in raw[off + 1:off + 32]:
            residual = byte if byte < 128 else byte - 256
            last = residual * step + (PREDICTOR * last if control & 0x10 else 0.0)
            samples.append(max(-32768, min(32767, round(last))))
    return samples


# ---------------------------------------------------------------------------
# 读 WAV / 写 WAV / 重采样
# ---------------------------------------------------------------------------
def read_wav(path: Path) -> tuple[list[float], int]:
    with wave.open(str(path), "rb") as f:
        channels, width, rate = f.getnchannels(), f.getsampwidth(), f.getframerate()
        frames = f.readframes(f.getnframes())
    if width != 2:
        raise SystemExit(f"只支持 16-bit PCM WAV（当前 {width*8}-bit）。"
                         "请先转换：ffmpeg -i in -sample_fmt s16 out.wav")
    count = len(frames) // 2
    raw = struct.unpack(f"<{count}h", frames)
    if channels == 1:
        mono = [float(v) for v in raw]
    else:                                    # 混缩成单声道
        mono = [float(sum(raw[i:i + channels]) / channels)
                for i in range(0, len(raw) - channels + 1, channels)]
    return mono, rate


def resample(samples: list[float], src_rate: int, dst_rate: int = RATE) -> list[float]:
    """线性插值重采样。音效只有几百毫秒，够用。"""
    if src_rate == dst_rate or not samples:
        return samples
    ratio = src_rate / dst_rate
    out_len = int(len(samples) / ratio)
    out: list[float] = []
    n = len(samples)
    for i in range(out_len):
        src = i * ratio
        j = int(src)
        frac = src - j
        if j + 1 < n:
            out.append(samples[j] * (1 - frac) + samples[j + 1] * frac)
        else:
            out.append(samples[-1])
    return out


def write_wav(path: Path, samples: list[int]) -> None:
    with wave.open(str(path), "wb") as f:
        f.setnchannels(1)
        f.setsampwidth(2)
        f.setframerate(RATE)
        f.writeframes(b"".join(struct.pack("<h", s) for s in samples))


# ---------------------------------------------------------------------------
# 处理链
# ---------------------------------------------------------------------------
def normalize(samples: list[float]) -> list[float]:
    peak = max(abs(v) for v in samples) or 1.0
    return [v / peak for v in samples]


def high_shelf(samples: list[float], gain: float = 0.8) -> list[float]:
    """一阶差分提升高频 —— 让快门声更"脆"。"""
    out = list(samples)
    for i in range(1, len(out)):
        out[i] = samples[i] + gain * (samples[i] - samples[i - 1])
    return out


def compress(samples: list[float], threshold: float = 0.20, ratio: float = 4.0) -> list[float]:
    """简单动态压缩：提高 RMS（听感更响）。"""
    out = []
    for v in samples:
        a = abs(v)
        if a <= threshold:
            out.append(v)
        else:
            out.append(math.copysign(threshold + (a - threshold) / ratio, v))
    return out


def soft_clip(samples: list[float], drive: float = 1.15) -> list[float]:
    """tanh 软限幅：加谐波，提升响度感而不硬削波。"""
    norm = math.tanh(drive)
    return [math.tanh(v * drive) / norm for v in samples]


def fit_length(samples: list[float], nsamp: int) -> list[float]:
    """截断或补零到目标采样数。"""
    if len(samples) >= nsamp:
        return samples[:nsamp]
    return samples + [0.0] * (nsamp - len(samples))


def to_int16(samples: list[float], peak: int = 32000) -> list[int]:
    m = max((abs(v) for v in samples), default=1.0) or 1.0
    scale = peak / m
    return [int(max(-32768, min(32767, round(v * scale)))) for v in samples]


# ---------------------------------------------------------------------------
# 示例音合成（用于没素材时也能试）
# ---------------------------------------------------------------------------
def preset_click(nsamp: int, pitch: float = 1.0) -> list[float]:
    """高音"咔嚓"：噪声爆发 + 快速衰减共振（模拟快门叶片）。"""
    rng = random.Random(12345)
    out: list[float] = []
    click_len = int(RATE * 0.004)
    for i in range(nsamp):
        t = i / RATE
        v = 0.0
        if i < click_len:                                        # 4ms 噪声爆发
            v += rng.uniform(-1, 1) * (1.0 - i / click_len) ** 2 * 0.85
        if 0.002 < t < 0.040:                                    # 金属余响
            tt = t - 0.002
            env = math.exp(-tt * 95)
            v += math.sin(2 * math.pi * 4200 * pitch * tt) * env * 0.55
            v += math.sin(2 * math.pi * 6100 * pitch * tt) * env * 0.30
        if 0.040 <= t < 0.100:                                   # 极弱尾音
            tt = t - 0.040
            v += math.sin(2 * math.pi * 2400 * pitch * tt) * math.exp(-tt * 40) * 0.10
        out.append(max(-1.0, min(1.0, v)))
    return out


def preset_beep(nsamp: int, freq: float = 3000.0) -> list[float]:
    """电子"嘀"（近似相机对焦音）。"""
    out = []
    for i in range(nsamp):
        t = i / RATE
        attack = min(1.0, t / 0.002)
        release = max(0.0, 1.0 - max(0.0, t - 0.060) / 0.040)
        out.append(math.sin(2 * math.pi * freq * t) * attack * release)
    return out


def preset_snap(nsamp: int) -> list[float]:
    """干脆的"咔"：单次脉冲 + 极短衰减。"""
    rng = random.Random(999)
    out = []
    for i in range(nsamp):
        t = i / RATE
        v = rng.uniform(-1, 1) * math.exp(-t * 400) * 0.9
        v += math.sin(2 * math.pi * 3000 * t) * math.exp(-t * 180) * 0.5
        out.append(max(-1.0, min(1.0, v)))
    return out


PRESETS = {"click": preset_click, "beep": preset_beep, "snap": preset_snap}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def cmd_list_targets() -> None:
    print(f"{'名字':14s} {'soundId':>8s} {'大小':>7s}  可播")
    for name, (sid, size, ok) in TARGETS.items():
        print(f"{name:14s} 0x{sid:02X}      {size:6d}  {'是' if ok else '否（priority 6）'}")
    print("\n用法：--target caution   （大小自动取 8640）")


def main() -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8")  # type: ignore[attr-defined]
        except Exception:
            pass

    ap = argparse.ArgumentParser(
        description="普通音频 → Sony 相机音效格式（.bin）",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--input", type=Path, help="输入 WAV（16-bit PCM）")
    src.add_argument("--preset", choices=list(PRESETS), help="用内置合成音")
    src.add_argument("--decode", type=Path, metavar="BIN", help="解码一个 .bin 成 WAV")

    ap.add_argument("--target", choices=list(TARGETS), help="目标音效（自动决定 --size）")
    ap.add_argument("--size", type=int, help="输出字节数（必须是 64 的倍数，且等于目标 .bin 的原始大小）")
    ap.add_argument("--filter", type=int, default=1, choices=[0, 1],
                    help="0=不用预测器，1=用预测器（默认，与原厂一致）")
    ap.add_argument("--out", type=Path, help="输出 .bin 路径")
    ap.add_argument("--wav-out", type=Path, help="配合 --decode：输出 WAV 路径")
    ap.add_argument("--no-loudness", action="store_true",
                    help="跳过响度处理链（归一化/高频提升/压缩/tanh 限幅），但仍然按峰值缩放。跳过归一化/高频提升/压缩/软限幅，原样编码")
    ap.add_argument("--list-targets", action="store_true", help="列出已知音效文件大小")
    ap.add_argument("--json", action="store_true", help="输出机器可读的摘要")
    args = ap.parse_args()

    if args.list_targets:
        cmd_list_targets()
        return 0

    # ---- 解码模式 ----
    if args.decode:
        raw = args.decode.read_bytes()
        samples = decode(raw)
        dst = args.wav_out or args.decode.with_suffix(".decoded.wav")
        write_wav(dst, samples)
        info = {
            "bytes": len(raw),
            "blocks": len(raw) // 32,
            "samples": len(samples),
            "ms": round(len(samples) / RATE * 1000, 1),
            "min": min(samples), "max": max(samples),
            "out": str(dst),
        }
        if args.json:
            print(__import__("json").dumps(info, ensure_ascii=False))
        else:
            print(f"解码 {info['bytes']} 字节 = {info['blocks']} 块 × 31 = "
                  f"{info['samples']} 采样 = {info['ms']} ms")
            print(f"  幅度范围 {info['min']} .. {info['max']}")
            print(f"  输出 {dst}")
        return 0

    # ---- 计算目标大小 ----
    if args.target:
        sid, size, playable = TARGETS[args.target]
        if args.size and args.size != size:
            print(f"⚠️  --size {args.size} 与 --target {args.target} 的 {size} 冲突，以后者为准")
        args.size = size
        if not playable:
            print(f"⚠️  soundId 0x{sid:02X} 是 priority 6，本项目测试时没有声音，"
                  "建议换 caution/select/menu_open")
    if not args.size:
        print("需要 --size 或 --target（--list-targets 查看已知大小）", file=sys.stderr)
        return 2
    if args.size % 64:
        print(f"--size 必须是 64 的倍数（{args.size} % 64 = {args.size % 64}）",
              file=sys.stderr)
        print("  编码器按 64 字节补齐；32 字节的奇数块会多出 32 字节。", file=sys.stderr)
        return 2

    nsamp = (args.size // 32) * 31

    # ---- 取素材 ----
    if args.input:
        samples, rate = read_wav(args.input)
        samples = resample(samples, rate)
        source = args.input.name
    elif args.preset:
        samples = PRESETS[args.preset](int(nsamp * 2))   # 先做长一点再截
        source = f"preset:{args.preset}"
    else:
        print("需要 --input / --preset / --decode 之一", file=sys.stderr)
        return 2

    # ---- 处理链 ----
    if not args.no_loudness:
        samples = normalize(samples)
        samples = high_shelf(samples)
        samples = compress(samples)
        samples = soft_clip(samples)
    samples = fit_length(samples, nsamp)
    pcm = to_int16(samples)

    # ---- 编码 ----
    raw = encode(pcm, use_predictor=bool(args.filter))
    if len(raw) != args.size:
        # 相机按固定长度读取该槽位，长度不符会导致内容错位。写文件前就失败。
        print(f"✗ 输出长度 {len(raw)} ≠ 目标 {args.size}", file=sys.stderr)
        print("  补齐规则会把结果补到 64 的倍数。--size 请用 64 的倍数，", file=sys.stderr)
        print("  并且等于目标 .bin 的原始大小（--list-targets 可以查）。", file=sys.stderr)
        return 2
    dst = args.out or Path("custom_sound.bin")
    dst.write_bytes(raw)

    # ---- 回环验证 ----
    back = decode(raw)[:nsamp]
    err = max((abs(back[i] - pcm[i]) for i in range(nsamp)), default=0)
    peak = max((abs(v) for v in pcm), default=0)
    info = {
        "source": source,
        "out": str(dst),
        "bytes": len(raw),
        "blocks": len(raw) // 32,
        "samples": nsamp,
        "ms": round(nsamp / RATE * 1000, 1),
        "peak": peak,
        "roundtrip_max_error": err,
        "filter": args.filter,
        "first_block": raw[:32].hex(" "),
    }
    if args.json:
        print(__import__("json").dumps(info, ensure_ascii=False))
        return 0

    print(f"素材   {source}")
    print(f"输出   {dst}  {len(raw)} 字节 = {info['blocks']} 块 × 31 = "
          f"{nsamp} 采样 = {info['ms']} ms")
    print(f"  首块     {info['first_block']}")
    print(f"  控制字节 0x{raw[0]:02x}（指数={raw[0] & 0x0F}，"
          f"预测器={'开' if raw[0] & 0x10 else '关'}）")
    print(f"  峰值     {peak}")
    print(f"  回环误差 {err} / 32768  ({err / 32768 * 100:.3f}%)")
    if err > 4000:
        print("  ⚠️  回环误差偏大：素材可能太响或含突变，加 --no-loudness 或降增益再试")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
