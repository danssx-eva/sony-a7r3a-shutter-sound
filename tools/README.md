# 工具

这些脚本分两类：日常使用的，和复现分析用的。

所有脚本只对 ILCE-7RM3A / 固件 1.00 验证过。换设备前先跑 `verify_environment.py`。

环境变量（可选）：

```
PMCA_DIR             Sony-PMCA-RE 路径，默认 vendor/Sony-PMCA-RE
FWTOOL               fwtool.py 路径，fwlab/ 解包固件时用
LAB_ROOT             本地研究工作区根目录，默认当前目录；只有少数脚本用到
LIBUSB_PACKAGE_DIR   libusb DLL 目录，Windows 下用
```

## 先看这两个

| 脚本 | 用途 |
|---|---|
| `verify_environment.py` | 只读核对你的设备与本项目记录是否一致。不匹配就别往下走 |
| `sigscan.py` | 用字节特征在固件里定位函数，换固件版本时用 |
| `selfcheck.py` | 35 项工具自检 + 文档命令一致性检查；不需要相机 |

```bash
python tools/verify_environment.py --check-all
python tools/verify_environment.py --list
python tools/sigscan.py list
python tools/sigscan.py locate --file my_libObj.so --base 0x05DCA000
```

## 换成自己的音效

| 脚本 | 用途 |
|---|---|
| `../examples/convert_audio.py` | WAV / MP3 转成相机音效格式，也能反向解码 |
| `build_payload/make_sound.py` | 同上，早期版本，处理链更完整 |

```bash
python examples/convert_audio.py --input my.wav --target caution --out my.bin
python examples/convert_audio.py --decode my.bin --wav-out check.wav
```

## 写入载荷

| 脚本 | 用途 |
|---|---|
| `inject/inject_generic.py` | 通用内存注入：把一段机器码写到指定地址 |
| `inject/cam_memdump_file.py` | 读相机内存到本地文件 |
| `inject/cam_mempoke.py` | 写少量字节到相机内存 |
| `inject/pw_nolibc.c` + `pw_start.S` | 无 libc 的闪存写入器，编译后推到相机上跑 |
| `inject/build_pw.sh` | 用 ARM 交叉编译器编译 `pw` |
| `inject/cam_memdump.py` | 读一段相机内存并打印十六进制 |
| `inject/ldpreload_deploy.py` | LD_PRELOAD 通道部署（未走通，见 docs/附录/死路清单.md） |

`pw_nolibc.c` 解决的是这个问题：busybox 的 `dd` 写文件时会截断，`O_WRONLY` 不带
`O_TRUNC` 才能原地改。编译方法见文件头注释。

## 持久化

| 脚本 | 用途 |
|---|---|
| `persist/make_blocks.py` | 从原厂 `.so` 生成两个 1 KB 闪存块，校验整文件 SHA 与块 MD5 |

## 构建载荷

| 脚本 | 用途 |
|---|---|
| `build_payload/build_burst_only.py` | 连拍发声载荷构建器（本项目实际用的） |
| `build_payload/make_sound.py` | 音效编解码与处理链 |
| `build_payload/selfcheck_burst.py` | 用 Unicorn 仿真自检载荷，不需要相机 |
| `build_payload/build_msglog_payload.py` | 消息日志载荷，用于观察 CP 收包 |

`build_burst_only.py` 会输出 `.so` 和 `.bin`，并在末尾跑 18 项 Unicorn 仿真自检。
自检全过再上机。

## 相机操作

| 脚本 | 用途 |
|---|---|
| `camera/a7r3a_shell.py` | 连相机、切服务模式、跑 shell 命令、读写内存。其他脚本都依赖它 |
| `camera/a7r3a_backup.py` | 备份原厂 `libObj.so`、音效目录和 maps，并做相机端哈希交叉校验 |
| `camera/push_files.py` | 把文件传到相机 `/log/w/`，读回校验 |
| `camera/a7r3a_prop.py` | 读写 Backup 属性（音量、开关） |
| `camera/a7r3a_status.py` | 打印相机当前状态 |
| `camera/a7r3a_pull.py` | 从相机拉文件 |
| `camera/a7r3a_restore_all.py` | 回滚补丁 |
| `camera/a7r3a_restore_props.py` | 回滚 Backup 属性 |
| `camera/a7r3a_clean_check.py` | 检查相机是否处于干净状态 |
| `camera/a7r3a_film.py` | 滤镜参数实验 |
| `camera/a7r3a_recon_kernel.py` | 内核与内存布局侦察 |
| `camera/a7r3a_watch_pull.py` | 定期拉日志 |
| `camera/a7r3a_zh_label.py` | 中文标签实验 |

```bash
python tools/camera/a7r3a_prop.py --read --id 0x002B0020
python tools/camera/a7r3a_status.py
```

## 静态分析

需要先把 `.so` 拉到本地。这些脚本用 capstone / pyelftools 分析 ELF。

| 脚本 | 用途 |
|---|---|
| `analysis/who_calls.py` | 找某个地址的所有调用点（BL / B.W / BLX）和字面量引用 |
| `analysis/xref_address.py` | 地址交叉引用 |
| `analysis/find_string_refs.py` | 找引用某字符串的代码 |
| `analysis/plt_map.py` | 解析 PLT 与 GOT |
| `analysis/read_msglog.py` | 解析消息日志 |
| `analysis/uxc_strings.py` | 读写 `string_<lang>.uxc` 字符串资源 |

## 离线仿真

不开相机也能验证载荷逻辑。

| 脚本 | 用途 |
|---|---|
| `emulation/emu_verify_payload.py` | 按 PT_LOAD 映射镜像跑载荷，检查越界访问。**配套的是早期载荷**，当前载荷的自检请用 `build_payload/build_burst_only.py`（自带 18 项） |
| `emulation/sim_play_sound.py` | 仿真整条播放链路 |

## 相机端脚本

`camera_scripts/` 下的 shell 脚本是推到相机上跑的，不依赖本机 Python。

| 脚本 | 用途 |
|---|---|
| `cam_health.sh` | 相机基本状态 |
| `check_all.sh` | 综合检查 |
| `check_persist.sh` / `verify_persist.sh` | 验证补丁是否落盘 |
| `write_persist.sh` | 写补丁到闪存（参数：预期整文件 SHA256，必须提供） |
| `write_snd7.sh` | 只写 soundId 0x07 的音效文件 |
| `backup_blocks.sh` | 备份要改的 1KB 块 |
| `test_dd_notrunc.sh` / `test_dd2.sh` | 验证 busybox dd 的截断问题 |
| `list_sounds.sh` | 列音效文件 |
| `scan_zero.sh` | 扫内存零区 |
| `load_check.sh` / `thread_check.sh` | 负载与线程 |
| `memscan.c` / `memscan_tiny.c` | 交叉编译后推到相机上的内存扫描器 |
| 其余 | 各次实验的一次性验证脚本 |

## 已删除的脚本

两百多个一次性验证脚本已从仓库移除，对读者没有复用价值。

如果你需要某个具体功能的脚本而这里没有，可以开 issue 说明要做什么。
