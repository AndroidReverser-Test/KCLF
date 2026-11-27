# KCLF 文档 / Documentation

[项目首页 / Project](../README.md) · [下载 / Releases](https://github.com/AndroidReverser-Test/KCLF/releases)

当前版本为 1.6.4。从使用说明开始，再按需要查看实现或测试细节。
Current version: 1.6.4. Start with usage, then consult implementation and test details.

| 文档 / Document | 内容 / Contents |
| --- | --- |
| [编译与使用 / Build and use](USAGE.md) | 工具链、测试 App、控制命令、路径要求、清理与卸载 / Toolchains, app, commands, paths and cleanup |
| [实现说明 / Implementation](IMPLEMENTATION.md) | 执行模型、状态机、ELF/TLS、内核适配及能力边界 / Execution, states, ELF/TLS, kernel compatibility and limits |
| [TLS 测试 / TLS testing](TLS_TESTING.md) | 主机与设备回归步骤 / Host and device regression instructions |
| [HybridCLR 加载失败修复 / Loading fix](HYBRIDCLR_LOADING_FIX.md) | Android 5.15 non-dumpable VMA 回退与 SO 路径权限 / VMA fallback and payload access |
| [1.6.4 审计 / Audit](AUDIT_1.6.4.md) | 修复、效率、可靠性与实测范围 / Fixes, performance, reliability and validation scope |
| [1.6.4 证据索引 / Evidence](EVIDENCE_1.6.4.json) | 产物和本地测试日志的 SHA-256 / Artifact and local test-log hashes |
| [更新记录 / Changelog](CHANGELOG.md) | 简要版本变化 / Concise release history |

## 历史报告 / Historical reports

历史报告保留当时的代码、环境和实验结论，不代表当前版本在其他设备上已通过认证。
Historical reports describe their original code and environment; they do not certify the current release on other devices.

| 版本或主题 / Version or topic | 记录 / Record |
| --- | --- |
| 1.6.3 | [兼容性 / Compatibility](COMPATIBILITY_1.6.3.md) |
| 1.6.0 | [兼容性 / Compatibility](COMPATIBILITY_1.6.0.md) · [证据索引 / Evidence](EVIDENCE_1.6.0.json) |
| 1.5.7 | [兼容性 / Compatibility](COMPATIBILITY_1.5.7.md) |
| 1.5.6 | [兼容性 / Compatibility](COMPATIBILITY_1.5.6.md) |
| 1.5.5 | [兼容性 / Compatibility](COMPATIBILITY_1.5.5.md) |
| 目标进程崩溃分析 / Target crash investigation | [历史实验 / Investigation](CRASH_ANALYSIS_MANJUU_PROMILIA.md) |

文档中的 `build/` 路径是仓库根目录下的本地测试证据，不提交原始设备日志、签名材料或 superkey。
源码与测试在仓库根目录和 `test/`；编译产物通过 Releases 分发。
Paths under `build/` refer to local evidence relative to the repository root. Raw device logs,
signing material and superkeys are excluded. Sources and tests remain in the root and `test/`;
compiled modules are distributed through Releases.
