"""生成相机可播放的自定义音效（破解格式后的编码器）

格式（逆向自 A7C2 项目 + 本机验证）：
    每 32 字节一个块
    [0]      控制字节
             低 4 位 = 指数 exponent → scale = 1 << exponent
             bit4   = 预测器开关（1 = 用前一采样做预测）
    [1..31]  31 个有符号残差（-128..127）

    解码：
        last = residual * scale + (predictor * last if control & 16 else 0)
        predictor = 60/64

    采样率 24000 Hz

用法:
    python tools/make_sound.py --preset click --size 2496 --out work/myclick.bin
    python tools/make_sound.py --wav input.wav --size 2496 --out work/myclick.bin
    python tools/make_sound.py --preset click --decode work/myclick.bin   # 反解验证
"""
from __future__ import annotations

import argparse
import math
import pathlib
import random
import struct
import sys
import wave

RATE = 24000
PREDICTOR = 60 / 64


# ---------------------------------------------------------------- 编码/解码
def encode_filter0(samples: list[int]) -> bytes:
    """filter0（不用预测器）—— 简单可靠，已验证能播"""
    out = bytearray()
    for at in range(0, len(samples), 31):
        block = list(samples[at:at + 31])
        block += [0] * (31 - len(block))
        exponent = next(
            n for n in range(9)
            if min(block) >= -128 * (1 << n) and max(block) <= 127 * (1 << n)
        )
        step = 1 << exponent
        out.append(exponent)                      # bit4 = 0 → filter0
        out.extend((max(-128, min(127, round(x / step))) & 0xFF) for x in block)
    if len(out) % 64:
        out.extend(bytes(32))
    return bytes(out)


def encode_filter1(samples: list[int]) -> bytes:
    """filter1（用前一采样做预测）—— 原厂文件多半是这个（首字节 0x17 = 指数7|bit4）"""
    out = bytearray()
    last = 0.0
    for at in range(0, len(samples), 31):
        block = list(samples[at:at + 31])
        block += [0] * (31 - len(block))
        # 对每个可能的指数，算残差，选第一个能装下的
        chosen = None
        for exponent in range(9):
            step = 1 << exponent
            pred_last = last
            ok = True
            res = []
            for x in block:
                r = (x - PREDICTOR * pred_last) / step
                ri = round(r)
                if ri < -128 or ri > 127:
                    ok = False
                    break
                res.append(ri)
                pred_last = ri * step + PREDICTOR * pred_last
            if ok:
                chosen = (exponent, res, pred_last)
                break
        if chosen is None:
            exponent, res, pred_last = 8, [127] * 31, last
        else:
            exponent, res, pred_last = chosen
        out.append(0x10 | exponent)               # bit4 = 1 → filter1
        out.extend((r & 0xFF) for r in res)
        last = pred_last
    if len(out) % 64:
        out.extend(bytes(32))
    return bytes(out)


def decode(raw: bytes) -> list[int]:
    result, last = [], 0.0
    for offset in range(0, len(raw), 32):
        control = raw[offset]
        scale = 1 << (control & 15)
        for byte in raw[offset + 1:offset + 32]:
            residual = byte if byte < 128 else byte - 256
            last = residual * scale + (PREDICTOR * last if control & 16 else 0)
            result.append(max(-32768, min(32767, round(last))))
    return result


# ---------------------------------------------------------------- 音效预设
def preset_click(n: int, pitch: float = 1.0) -> list[int]:
    """高音"咔嚓"：噪声爆发 + 快速衰减共振"""
    rng = random.Random(12345)
    out = []
    click_len = int(RATE * 0.004)      # 4ms 噪声爆发
    for i in range(n):
        t = i / RATE
        v = 0.0
        # ① 前 4ms：高频噪声爆发（快门叶片撞击）
        if i < click_len:
            v += rng.uniform(-1, 1) * (1.0 - i / click_len) ** 2 * 0.85
        # ② 4-40ms：4kHz + 6kHz 衰减共振（金属叶片余响）
        if 0.002 < t < 0.040:
            tt = t - 0.002
            env = math.exp(-tt * 95)
            v += math.sin(2 * math.pi * 4200 * pitch * tt) * env * 0.55
            v += math.sin(2 * math.pi * 6100 * pitch * tt) * env * 0.30
        # ③ 40-100ms：极弱余音
        if 0.040 <= t < 0.100:
            tt = t - 0.040
            env = math.exp(-tt * 40) * 0.10
            v += math.sin(2 * math.pi * 2400 * pitch * tt) * env
        out.append(int(max(-1.0, min(1.0, v)) * 30000))
    return out


def preset_beep(n: int, freq: float = 3000.0) -> list[int]:
    """高音电子"嘀" """
    out = []
    for i in range(n):
        t = i / RATE
        env = min(1.0, t / 0.002) * max(0.0, 1.0 - (t - 0.060) / 0.040) if t > 0.060 else min(1.0, t / 0.002)
        out.append(int(math.sin(2 * math.pi * freq * t) * env * 30000))
    return out


def preset_snap(n: int) -> list[int]:
    """干脆的"咔"：单次脉冲 + 极短衰减"""
    rng = random.Random(999)
    out = []
    for i in range(n):
        t = i / RATE
        env = math.exp(-t * 400)
        v = rng.uniform(-1, 1) * env * 0.9
        v += math.sin(2 * math.pi * 3000 * t) * math.exp(-t * 180) * 0.5
        out.append(int(max(-1.0, min(1.0, v)) * 30000))
    return out


PRESETS = {"click": preset_click, "beep": preset_beep, "snap": preset_snap}


# ---------------------------------------------------------------- 入口
def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--preset", choices=list(PRESETS))
    ap.add_argument("--wav", type=pathlib.Path)
    ap.add_argument("--size", type=int, default=2496, help="输出字节数（须为 32 的倍数，默认 2496）")
    ap.add_argument("--filter", type=int, default=0, choices=[0, 1])
    ap.add_argument("--out", type=pathlib.Path)
    ap.add_argument("--decode", type=pathlib.Path, help="解码一个 .bin 成 wav 验证")
    ap.add_argument("--wav-out", type=pathlib.Path)
    a = ap.parse_args()

    if a.preset == "click":
        pass

    if a.decode:
        raw = a.decode.read_bytes()
        samples = decode(raw)
        dst = a.wav_out or a.decode.with_suffix(".decoded.wav")
        with wave.open(str(dst), "wb") as f:
            f.setnchannels(1)
            f.setsampwidth(2)
            f.setframerate(RATE)
            f.writeframes(b"".join(struct.pack("<h", s) for s in samples))
        print(f"解码 {len(raw)} 字节 → {len(samples)} 采样 ({len(samples)/RATE*1000:.1f} ms)")
        print(f"  范围 {min(samples)} .. {max(samples)}")
        print(f"  输出 {dst}")
        return 0

    nbytes = a.size
    if nbytes % 32:
        print("size 必须是 32 的倍数")
        return 1
    nsamp = (nbytes // 32) * 31

    if a.wav:
        with wave.open(str(a.wav), "rb") as w:
            ch, sw, rate = w.getnchannels(), w.getsampwidth(), w.getframerate()
            frames = w.readframes(w.getnframes())
        if sw != 2:
            print("只支持 16-bit WAV")
            return 1
        pcm = list(struct.unpack(f"<{len(frames)//2}h", frames))
        if ch == 2:
            pcm = pcm[0::2]
        # 重采样到 24kHz
        ratio = RATE / rate
        out = []
        for i in range(nsamp):
            src = i / ratio
            j = int(src)
            if j + 1 < len(pcm):
                frac = src - j
                out.append(int(pcm[j] * (1 - frac) + pcm[j + 1] * frac))
            else:
                out.append(0)
        samples = out
    elif a.preset:
        samples = PRESETS[a.preset](nsamp)
    else:
        print("需要 --preset 或 --wav")
        return 1

    raw = encode_filter1(samples) if a.filter == 1 else encode_filter0(samples)
    dst = a.out or pathlib.Path("custom_sound.bin")
    dst.write_bytes(raw)

    # 验证
    back = decode(raw)[:nsamp]
    err = max(abs(back[i] - samples[i]) for i in range(nsamp)) if nsamp else 0
    peak = max(abs(x) for x in samples) if samples else 0
    print(f"预设: {a.preset or a.wav.name}   filter{a.filter}")
    print(f"输出: {dst}  {len(raw)} 字节 = {len(raw)//32} 块 × 31 = {nsamp} 采样 = {nsamp/RATE*1000:.1f} ms")
    print(f"  前 32 字节: {raw[:32].hex()}")
    print(f"  控制字节 0x{raw[0]:02x} (指数={raw[0] & 15}, 预测器={'开' if raw[0] & 16 else '关'})")
    print(f"  峰值 {peak}  软件回环误差 {err}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
