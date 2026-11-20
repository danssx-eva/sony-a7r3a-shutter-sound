# 贡献指南

这个仓库是 ILCE-7RM3A 静音快门声的研究记录和工具集。比起新增功能，更需要能提高结论可靠性的内容。

## 可以贡献什么

| 类型 | 内容 |
|---|---|
| 补一条死路 | 你试过但走不通的路线：假设、现象、原因。写进 [死路清单](docs/附录/死路清单.md) |
| 纠正一条结论 | 文档说 A，你实测是 B。保留旧结论并标注 ~~废弃~~，指向新结论，附证据 |
| 换机型 / 固件验证 | 在别的机器上跑 `tools/sigscan.py`，给出型号、固件版本、模块大小、SHA256 |
| 修工具 | 复现命令、最小样本、报错输出 |
| 补文档 | 步骤缺失、命令对不上、链接失效 |

## 提交方式

- 开 issue 或 PR。
- 每条结论标证据强度：`[实测]` / `[静态]` / `[推断]` / `[未验证]`，定义见 [逆向方法](docs/附录/逆向方法.md)。
- 地址注明类型：`fileVA` / 运行期 / Ghidra 地址。
- 改动文档编号或路径后，全局检查一遍相对链接。

## 代码

- Python 3.10+，标准库优先；第三方依赖登记到 `requirements.txt` 和 `tools/README.md`。
- 文件名沿用现有前缀：`build_*` / `inject_*` / `probe_*` / `a7r3a_*` / `emu_*`。
- 每个脚本顶部写 docstring：一句话说明做什么、怎么用。
- 危险脚本默认只读或干跑，真正写设备要 `--go`。
- 路径用环境变量（`LAB_ROOT` / `PMCA_DIR` / `FWTOOL`）。
- 新增或修改工具后跑 `python tools/selfcheck.py`，并在 `tools/README.md` 补一行。

## 文档

- 中文为主，技术术语保留英文（`fileVA`、`PT_LOAD`、`callee-saved`）。
- 结论强度不超过证据；没上机验证的写“推断”或“未验证”。

## 提交信息

```
<区域>: <一句话>

区域 = docs / tools / examples / fwlab / research
例：
  docs: 补两条“在 CP 线程里读文件”的死路
  tools: sigscan 支持带区间的 --wildcard
  examples: convert_audio 支持 8 位输入
```

## 许可

提交即表示你同意：你的贡献以 [MIT](LICENSE) 授权，并且你有权提交这些内容。
内容边界与风险见 [DISCLAIMER.md](DISCLAIMER.md)。
