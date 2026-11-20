# THIRD PARTY NOTICES

本仓库包含下列第三方组件。分发时须保留本文件与对应许可证文本。

## Sony-PMCA-RE

```
Copyright (c) 2015 ma1co
MIT License
许可证全文 : vendor/Sony-PMCA-RE/LICENSE.txt
位置       : vendor/Sony-PMCA-RE/   （原样复制，未修改）
上游       : https://github.com/ma1co/Sony-PMCA-RE
```

相机通道（`pmca.platform.backend.senser`、`pmca.usb.sony`、`pmca.commands.usb`、
`pmca.backup`）来自该项目，`tools/camera/` 直接 import 其模块。

## 未随仓库分发的依赖

| 组件 | 许可证 |
|---|---|
| [fwtool.py](https://github.com/ma1co/fwtool.py) | MIT |
| [capstone](https://www.capstone-engine.org/) | BSD-3-Clause |
| [keystone](https://www.keystone-engine.org/) | GPL-2.0 |
| [unicorn](https://www.unicorn-engine.org/) | GPL-2.0 |
| [pyelftools](https://github.com/eliben/pyelftools) | Public domain |
| [numpy](https://numpy.org/) / [scipy](https://scipy.org/) | BSD-3-Clause |
| [pyusb](https://github.com/pyusb/pyusb) | BSD-3-Clause |
| [libusb-package](https://github.com/pyusb/libusb-package) | Apache-2.0（内含 libusb，LGPL-2.1） |
| ffmpeg | LGPL-2.1+ / GPL-2.0+（取决于构建） |

keystone 与 unicorn 仅作为库调用，未修改、未内联。

## 思路来源

`tools/sigscan.py` 的特征码定位方法参考 Magic Lantern 的 `constable`：不硬编码地址，
用字节特征在本地固件里定位。该脚本为独立实现，不含 Magic Lantern 代码。

其余参考：OpenMemories（Sony 相机平台研究）、nex-hack 社区（固件解包）、
Sony-PMCA-RE（`README.md` 中 "Is it safe?" 段落的措辞）。

## 未包含的内容

Sony 官方固件包、Sony 二进制（`.so` / `.ko` / `.bin` / dump）、官方固件的解包产物、
相机备份文件、打过补丁的库文件、Sony 原始音效资源、Ghidra 反编译全量导出。

详见 [DISCLAIMER.md](DISCLAIMER.md)。
