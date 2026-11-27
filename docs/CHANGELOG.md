# 更新记录 / Changelog

[文档目录 / Documentation](README.md) · [发布产物 / Releases](https://github.com/AndroidReverser-Test/KCLF/releases)

## 未发布 / Unreleased

- `manual` 自动加载 `/data/local/tmp/` 下可读 SO：使用目标凭据创建 tmpfs 快照，
  镜像、TLS 和跳板共享后备文件；覆盖源文件删除后的重入、release 与退出回收。
  Automatically stage readable tmp-path payloads in a retained target-credential tmpfs file.
- 可选接口采用精确符号与 BTF 原型校验，已知 5.x–6.16 ABI 可无 BTF 使用；
  缺少接口或遇到未知 ABI 时保持普通路径可用。详见 [兼容性与验证](TMP_SO_LOADING.md)。
- 修复部分 Android 5.15 内核缺少 `find_vma` 时 non-dumpable 目标无法准备的问题；
  通过明确的三参数 `find_vma_prev` ABI 保留 BTF 校验和加锁 VMA 回退。
  Retain the locked VMA fallback through `find_vma_prev` when `find_vma` is absent.
- `probe` 显示实际 VMA accessor，PT_LOAD 映射失败显示段号、权限和访问策略提示；
  增加 non-dumpable App 与 accessor 缺失回归。
  Report the selected accessor and mapping errors; add non-dumpable regression.

复现、路径权限与验证结果见 [HybridCLR 加载失败分析](HYBRIDCLR_LOADING_FIX.md)。

## 1.6.4

- 修复 worker 引用释放、槽位回收、取消与回滚之间的所有权竞争。
  Fix worker reference release and ownership across slot reuse, cancellation and rollback.
- 修复无 BTF 的借用 mm、目标凭据/remote-mm 能力回退及 provider 文件引用泄漏。
  Correct borrowed-mm access, worker capability fallback and provider file cleanup.
- 四槽轮询，按 mm 串行处理 manual 事务；增加故障、取消和跨后端排队回归。
  Add round-robin service, per-mm manual serialization and fault/cancellation regression.
- 文档统一归入 `docs/`，README 保留快速开始和入口。
  Consolidate documentation under `docs/` and simplify the README.

验证范围与剩余限制见 [1.6.4 审计 / Audit](AUDIT_1.6.4.md)。

## 1.6.3

Provider ELF 元数据优先从文件读取；BTF direct walker 保留路径、偏移和权限，
无法重开的文件使用 resident-only 回退。新增文件 view 回归。
Read provider metadata from files, retain direct-walker metadata and use resident-only fallback.
See [兼容性报告 / Compatibility](COMPATIBILITY_1.6.3.md).

## 1.6.2

准备阶段移至借用目标 mm 和凭据的 worker；默认使用独立临时栈，`borrowstack` 为显式选项。
Move preparation to a worker with the target mm/credentials and default to a dedicated transient stack.

## 1.6.1

可执行 PT_LOAD、跳板和 TLS 代码页使用 payload 文件的私有映射，直接采用最终权限。
Use private payload-file mappings with final permissions for executable segments, trampolines and TLS code.

## 1.6.0

加入 payload 本地 PT_TLS/TLSDESC、NODELETE 生命周期、TLS 夹具和回退回归。
Add payload-local ELF TLS, NODELETE lifetime rules and TLS/fallback regression.
See [兼容性报告 / Compatibility](COMPATIBILITY_1.6.0.md).

## 1.5.7

支持完整长符号名匹配，识别本地 emutls 并保留其生命周期。
Support full long-symbol matching and local emutls lifetime handling.
See [兼容性报告 / Compatibility](COMPATIBILITY_1.5.7.md).

## 1.5.6 / 1.5.5

内核 ABI、BTF 结构解析与兼容性验证记录。
Kernel ABI, BTF layout parsing and compatibility validation:
[1.5.6](COMPATIBILITY_1.5.6.md) · [1.5.5](COMPATIBILITY_1.5.5.md).
