# ILCE-7RM3A 静音拍摄自定义快门声

在 SONY ILCE-7RM3A 上修改相机与相机的通信链路，使电子快门（静音拍摄）时播放自定义声音，
单拍和连拍都支持。

本项目提供研究结论和完整制作教程。所有地址、结构和代码均为 AI 逆向而来。

> 本项目使用有难度，建议配合 AI 食用。

## 支持的设备

| 项目 | 值 |
|---|---|
| 机型 | SONY ILCE-7RM3A（α7R III A） |
| 销售版本 | 非国行 |
| 固件 | 1.00 |

其他机型、其他固件版本、国行均未验证。同机型同固件也不保证一定有效——见[安全吗](#安全吗)。

## 开始之前：先备份

**在改动相机之前，把原厂内容完整备份到本地。**

ILCE-7RM3A 没有官方固件包，相机上的原厂内容一旦被覆盖就下载不回来。你自己那份备份是唯一退路。

```bash
python tools/camera/a7r3a_backup.py            # 完整备份到 backup/<时间戳>/
python tools/camera/a7r3a_backup.py --verify backup/<时间戳>   # 校验
```

备份内容包括 `libObj.so`（19 MB，补丁改的就是它）、30 个音效文件和 `beeplist.txt`。
工具会做交叉校验：拉下来之后让相机自己算一遍哈希，确认备份和相机上的一致。
你也可以用自己的工具备份，只要确认这三样都在、哈希记下来了。

**备份必须在打补丁之前做。** 打完补丁再备份，存下来的是补丁本身，回滚不到原厂。
工具会识别 `libObj.so` 是原厂还是已打补丁——看到「已打补丁」就说明已经错过时机了。

详见 [docs/教程/01-备份与读取固件.md](docs/教程/01-备份与读取固件.md)。

没有这份备份，后面任何一步出错都可能不可逆。

## 安装

需要 Python 3.10 以上，以及一个能进服务模式的相机。

```bash
git clone https://github.com/danssx-eva/sony-a7r3a-shutter-sound
cd sony-a7r3a-shutter-sound
pip install -r requirements.txt
```

### Windows

服务模式需要 libusb-win32 驱动。用 [Zadig](https://zadig.akeo.ie/) 给相机装驱动，
切换到服务模式后需要再装一次（两个模式的设备号不同）。详细步骤见
[docs/02-依赖与环境.md](docs/02-依赖与环境.md)。

### macOS / Linux

用 libusb 驱动即可，不需要额外安装。

## 验证环境

```bash
python tools/verify_environment.py --check-all
```

六项只读检查：相机连接、`libObj.so` 指纹、钩点字节、音频信号属性表、音效格式、Backup 属性。
磁盘指纹与内存钩点不是同一种状态时，会另加一项整体状态判定。
有不匹配就停下，先按 [docs/附录/特征码定位.md](docs/附录/特征码定位.md) 在本地固件上重新确认地址。

不连相机也能检查工具是否正常：

```bash
python tools/selfcheck.py
```

## 用法

### 只换提示音（不需要注入）

相机有 30 个可替换的音效槽位，其中 21 个可以安全替换。换成自己的音频后，**当相机本来要播这个槽位的提示音时**就会播你换的那段。

电子快门本身不触发任何原生提示音——要在快门时出声，需要先做下面的注入方案。

```bash
# 先转成 24 kHz 单声道 16 位 WAV（转换器只读 WAV；ffmpeg 需单独安装）
ffmpeg -i my.mp3 -ar 24000 -ac 1 -sample_fmt s16 my.wav
python examples/convert_audio.py --input my.wav --target caution --out my.bin

# 解回来听，确认格式理解正确
python examples/convert_audio.py --decode my.bin --wav-out check.wav
```

部署方法见 [docs/教程/07-替换音效.md](docs/教程/07-替换音效.md)。需要冷启动才生效。

### 让电子快门出声（注入方案）

电子快门下相机本来不播放任何提示音。要让它出声，需要在相机的 CP 收包循环里打一个钩子，
由钩子检测到"开始曝光"的消息时，向 RTOS 投递一条播放请求。

完整步骤见 [docs/教程/](docs/教程/)，九篇，从读取固件到持久化。

```bash
# 构建载荷（含 18 项 Unicorn 仿真自检）
python tools/build_payload/build_burst_only.py \
    --so backup/<时间戳>/usr_lib_libObj.so --nid 0x1001 --sound 0x07

# 内存注入测试（重启即恢复）
python tools/inject/inject_generic.py --so <生成的.so> \
    --hook-va 0xA31226 --pay-va 0x1948D8 --pay-len 240
```

## 安全吗

这是逆向工程的实验结果。所有信息都是通过分析 Sony 的固件得到的。虽然在本项目验证过的相机上
验证过，但它可能损坏你的硬件。

**如果相机因此损坏，本项目不承担任何责任。**

风险最高的两步是写闪存（`docs/教程/06-持久化到闪存.md`）和替换音效文件（`docs/教程/07-替换音效.md`）。
两步都要求先备份原厂内容。ILCE-7RM3A 没有官方固件包（官方下载页只有配套软件），
刷坏没有官方恢复路径。

本项目没有破解 Sony 的固件签名，也没有绕过任何认证。它用的是 Sony 自己保留的服务模式
诊断接口。

## 局限性

- **没有独立开关。** 复用相机原生的「音频信号」设置。关掉它，相机的所有提示音一起静音，
  包括对焦音。
- **需要冷启动。** 换音效、改音量、闪存补丁都要拔电池才生效，普通 `reboot` 不够。
  内存注入是例外，立即生效。
- **只在一种配置上验证过。** 见[支持的设备](#支持的设备)。
- **替换音效会丢失原厂内容。** 覆盖之后相机上就没有了，只能靠替换前的备份。
- **调用点栈对齐有偏差。** 载荷的 9 个 `blx` 调用点 `SP % 8 = 4`，不符合 AAPCS；
  仿真把它作为警告列出，真机后果未验证。

## 怎么工作的

相机是双系统。Linux 侧管界面和文件，另一颗核跑 RTOS 管影像、快门和发声。Linux 侧没有音频
设备，所以声音只能由 RTOS 播放。

Linux 侧能做的只有一件事：往 `/dev/uipc` 发一条消息请求 RTOS 播放。

本项目在 CP 收包循环里打一个 4 字节跳转，跳到一段 240 字节的载荷。载荷看到"开始曝光"的
消息（`nid == 0x1001`），就构造一条播放请求异步投递给 RTOS。

```
钩点   libObj.so fileVA 0xA31226
载荷   libObj.so fileVA 0x1948D8，240 字节
改动   2 个 1KB 块；覆盖 244 字节，与原厂差 238 字节
```

连拍不需要额外处理——`0x1001` 每帧出现一次，单拍 1 张响应 1 次，连拍 8 张响应 8 次。

详细原理见 [docs/教程/04-编写载荷.md](docs/教程/04-编写载荷.md)。

## 还有没做到的

- 没有独立菜单项。快门声挂在「音频信号」上，和它绑定；关掉「音频信号」，
  对焦声这类系统提示音也会一起消失。
- 不能新增音效槽位。往 `beeplist.txt` 的空槽挂文件不影响播放。
- 不能在相机正常模式下切换自定义音效，只能用固定的槽位。

这些方向的探索记录在 [死路清单](docs/附录/死路清单.md)（E 组、G-01）和
[结构规格](docs/附录/结构规格.md) 里，后面有人想继续可以接着试。

## 仓库内容

```
docs/            逆向结论与教程
tools/           工具（验证、定位、注入、构建、分析、仿真）
examples/        音效转换与示例
fwlab/           固件包只读分析
vendor/          Sony-PMCA-RE（原样副本，MIT）
```

仓库里**没有** Sony 的固件包、二进制、打过补丁的库文件。`docs/patches/` 只有本项目自己
生成的载荷、汇编和音效。

## 致谢

本项目建立在 [Sony-PMCA-RE](https://github.com/ma1co/Sony-PMCA-RE) 之上。相机通道、
服务模式切换、shell 交互全部来自该项目，没有它本项目不可能存在。

特征码定位的思路来自 [Magic Lantern](https://magiclantern.fm/) 的 `constable`
（`tools/sigscan.py` 为独立实现，不含其代码）。固件解包工具
[fwtool.py](https://github.com/ma1co/fwtool.py) 来自 ma1co，其谱系可追溯到 nex-hack 社区。

第三方组件的完整许可见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。

## 许可

MIT，见 [LICENSE](LICENSE)。
