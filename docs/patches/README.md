# 补丁产物

这里只有**本项目自己生成的东西**。不含 Sony 的任何二进制。

## 文件

| 文件 | 大小 | 内容 |
|---|---|---|
| `payload.bin` | 240 B | 载荷机器码，soundId = 0x07 CAUTION |
| `payload.asm.txt` | 3,956 B | 载荷的反汇编清单（带地址和机器码），用来核对 |

**载荷的源码不在这个文件里。** `payload.asm.txt` 是构建工具的输出，是给你核对用的。
真正的源码是 `tools/build_payload/build_burst_only.py` 里的 `build_code()` 函数——
它按参数生成汇编文本，再交给 keystone 汇编。改 soundId、改触发 NID 都从那里走。

| `sound-caution-8640.bin` | 8640 B | 本项目使用的快门音效 |

```
payload.bin  md5     1b70e883be75fef791267d07bce40ece
             sha256  a3eeb66dd0c816ca92b78358297a75e28e484c1e1f120b7c76a77c6870e22064
```

## 钩子的字节

```
位置    libObj.so fileVA 0xA31226（运行期基址 + 0xA31226）
原字节  7c 69 23 78
补丁    63 f7 57 9b        b.w 到载荷
```

`63 f7 57 9b` 是 `b.w 0x05F5E8D8` 的 Thumb-2 编码，用 keystone 从 `b.w <载荷地址>` 汇编得到。
原字节是两条 16 位指令 `ldr r4,[r7,#0x14]` 和 `ldrb r3,[r4]`，载荷执行完会重放它们。

## 没有提供的东西

以下内容**故意不放在仓库里**，因为它们包含 Sony 的代码：

| 内容 | 为什么不给 |
|---|---|
| 1 KB 闪存块（`blkA` / `blkB`） | 块里除了本项目的补丁，其余是 Sony 的原始代码 |
| 打过补丁的 `libObj.so` | 同上，而且是整份二进制 |
| 载荷位置的原始字节 | 328 字节的 Sony 代码 |

**你需要的东西这里都有：** 载荷、钩子字节、位置。用工具对你自己 dump 出来的
`libObj.so` 应用这两处改动，就是完整补丁。

## 自己生成补丁

```bash
# 1. 从你的相机 dump libObj.so（见 教程/01-备份与读取固件）
# 2. 用特征码确认钩点位置（见 附录/特征码定位）
python tools/sigscan.py scan --file my_libObj.so --pattern "7c 69 23 78 ?? ??"

# 3. 构建载荷（可改 soundId）
python tools/build_payload/build_burst_only.py --nid 0x1001 --sound 0x07

# 4. 内存注入测试
python tools/inject/inject_generic.py --so <生成的.so> \
    --hook-va 0xA31226 --pay-va 0x1948D8 --pay-len 240

# 5. 确认稳定后写闪存（见 教程/06-持久化到闪存）
```

第 3 步会输出完整 `.so`、`pay.bin`、`hok.bin`，并跑 18 项 Unicorn 仿真自检。

## 音效文件

`sound-caution-8640.bin` 是本项目用的快门声，从一段相机快门录音处理而来：

```
源素材  去掉了前面 0-125 ms 的对焦滴声，取 150-330 ms 的主脉冲和回响
处理    峰值归一化 → 高频提升 → 动态压缩 → tanh 软限幅 → 缩放到峰值 32000
长度    349 ms（后 169 ms 静音，补齐到 8640 字节）
```

你可以用 `examples/convert_audio.py` 换成自己的音频。
