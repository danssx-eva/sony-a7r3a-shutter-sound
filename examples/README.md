# examples/ —— 示例

## `convert_audio.py`

把普通音频转成 **Sony 相机音效格式**（`.bin`），也可以反解回 WAV 对照。
纯标准库，没有第三方依赖。

### 什么是"相机音效格式"

不是裸 PCM。**每 32 字节一块**：1 个控制字节（低 4 位 = 指数，bit4 = 预测器开关）+
31 个 `int8` 残差，一阶预测器系数 **60/64**，24 kHz 单声道。
完整规格与推导见 [结构规格](../docs/附录/结构规格.md) §2。

### 用法

```bash
# 0) 看已知的音效文件（大小必须严格对上）
python examples/convert_audio.py --list-targets

# 1) 没素材也能试：生成一个合成"咔嚓"
python examples/convert_audio.py --preset click --target caution --out my.bin

# 2) 用自己的音频（先转成 24k/单声道/16-bit WAV）
ffmpeg -i mine.mp3 -ar 24000 -ac 1 -sample_fmt s16 mine.wav
python examples/convert_audio.py --input mine.wav --target caution --out my.bin

# 3) 一定解回来听一遍
python examples/convert_audio.py --decode my.bin --wav-out check.wav

# 4) 想跳过响度处理（原样编码）
python examples/convert_audio.py --input mine.wav --target caution --no-loudness --out my.bin
```

### 内置目标（`--target`）

| 名字 | soundId | 字节大小 | 能播？ |
|---|---|---|---|
| `ka` | `0x01` | 256 | 测试时无输出（priority 6） |
| `sha` | `0x02` | 2944 | 测试时无输出（priority 6） |
| `kasha` | `0x03` | 2944 | 测试时无输出（priority 6） |
| `focuslock` | `0x04` | 3712 | 是 |
| **`caution`** | **`0x07`** | **8640** | 是（本项目用的就是它） |
| `select` | `0x08` | 2496 | 是 |
| `menu_open` | `0x0E` | 1792 | 是 |
| `wps_pbc` | `0x33` | 29760 | 是 |

> `priority 6` 的音效（真实的机械快门声）在本项目测试时没有声音，
> 所以要用 `caution` / `select` / `menu_open` 这类来承载自己的音频。

### 处理链（默认开启）

```
归一化 → 高频提升（更"脆"）→ 动态压缩（提高 RMS）→ tanh 软限幅 → 峰值缩放到 32000
```

`--no-loudness` 可全部跳过。处理链主要改变动态和音色；响度主要由相机 Backup 音量（0..7）决定。

### 输出里的"回环误差（同一编解码器往返，只反映实现自洽，不证明设备接受的格式）"是什么

把编好的数据**解回来**和原样本逐点比，取最大差值。
它只证明编码器和解码器自洽，不证明设备接受这个格式。真正确认要在相机上冷启动试听。
它能抓到的是参数错误和素材问题：

- 正常：几十 ~ 几百（远小于 32768）；
- 上千甚至满幅：素材太响/有突变，或编码器参数不对 → **不要部署**。

### 部署

```text
① 用 FTB/分段上传把 my.bin 传到相机（每段 ≤ 4096 字节）
② 相机端 cat 拼接 → cp 到 /usr/share/avsystemsound/Dslr_Emnt_High_Caution.bin
③ sync → fsync /dev/nflasha15 → sync → 挂回只读
④ 整个文件 md5sum 核对
⑤ 拔电池冷启动
```

详细命令见 [结构规格](../docs/附录/结构规格.md) §3.1，
风险与前置检查见 [教程/05-打钩子](../docs/教程/05-打钩子.md)。

## 示例产物

| 文件 | 说明 |
|---|---|
| `demo_click.bin` | 用 `--preset click --target caution` 生成，8640 字节（可直接替换 CAUTION 音效） |
| `demo_click.wav` | 上面那个的反解结果，用来听"编码有没有问题" |
| `demo_snap.bin` | 用 `--preset snap --target select` 生成，2496 字节 |

这些都是**本项目代码自己合成**的音频，不含任何 Sony 素材。
