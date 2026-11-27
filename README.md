# KCLF

Kernel Controlled Loading Framework — Android ARM64 / KernelPatch KPM

KCLF 通过内核 `task_work` 借用目标线程，在 EL0 执行 SO 的构造与析构函数。
默认 `manual` 后端映射并重定位 ELF；可显式选择 `linker` 后端调用目标 bionic loader。
`manual` 可自动加载 `/data/local/tmp/` 下可读 SO，详见[后备文件与兼容性](docs/TMP_SO_LOADING.md)。

KCLF runs SO constructors and finalizers in a target ARM64 thread through kernel
`task_work`. It provides a manual ELF loader and an explicit bionic linker backend.
Manual loading can stage readable `/data/local/tmp/` payloads automatically; see
[backing files and compatibility](docs/TMP_SO_LOADING.md).

[下载 / Releases](https://github.com/AndroidReverser-Test/KCLF/releases/latest) ·
[文档 / Documentation](docs/README.md) · [使用 / Usage](docs/USAGE.md)

## 快速开始 / Quick start

在 Linux/WSL 中使用 GNU Make、AArch64 GCC/binutils 和 KernelPatch 源码构建：
Build on Linux/WSL with GNU Make, AArch64 GCC/binutils and KernelPatch sources:

```sh
make KP_DIR=/path/to/KernelPatch TARGET_COMPILE=aarch64-linux-gnu-
make test
adb push kclf.kpm /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch "$KEY" kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf probe
```

`KEY` 是本地设置的 KernelPatch superkey；测试 App、注入命令和卸载步骤见[使用说明](docs/USAGE.md)。
Set `KEY` locally to your KernelPatch superkey. See [usage](docs/USAGE.md) for the test app, injection and unloading.

## 适用范围 / Scope

- 仅支持 ARM64 64 位目标；兼容性取决于运行时 ABI 和设备配置。
  ARM64 targets only; compatibility depends on runtime ABI and device configuration.
- 1.6.4 实测为 Pixel 6 / Android 16 / Linux 6.1.134 / 4K；其他内核及 16K/64K 真机未认证。
  Device validation covers this configuration; host simulations do not certify other kernels or page sizes.
- 需选择 x16 已无活跃值的协作边界，保持 manual 依赖驻留，并在 `quiesce=idle` 后卸载 KPM。
  Use a cooperative boundary where x16 is dead, keep manual dependencies loaded, and drain before KPM unload.

## 文档 / Documentation

| 内容 / Topic | 文档 / Guide |
| --- | --- |
| 构建、命令、测试 App / Build, commands, test app | [USAGE](docs/USAGE.md) |
| 架构、实现和限制 / Architecture and limits | [IMPLEMENTATION](docs/IMPLEMENTATION.md) |
| ELF TLS 回归 / ELF TLS regression | [TLS_TESTING](docs/TLS_TESTING.md) |
| 1.6.4 审计与验证 / Audit and validation | [AUDIT](docs/AUDIT_1.6.4.md) |
| 版本与历史报告 / Changes and historical reports | [CHANGELOG](docs/CHANGELOG.md) · [文档目录 / Index](docs/README.md) |

许可证 / License: [GPL-2.0](LICENSE)
