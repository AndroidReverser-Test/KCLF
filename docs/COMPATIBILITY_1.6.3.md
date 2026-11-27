# KCLF 1.6.3 兼容性与验证报告

- 日期：2026-11-27
- 设备：Pixel 6（oriole_beta），Android 16，Linux 6.1.134-android14-11，arm64，4 KiB 页
- 控制器：`/data/local/tmp/kpatch`，superkey 通过环境变量传递，不写入本报告
- 源码：`kpms/kclf`（KCLF 1.6.3）

## 1. 变更摘要

1.6.3 修复 1.6.2 在 non-dumpable 目标上的 provider 发现缺口，并消除 provider
解析对目标映射页的读取：

- direct VMA walker 通过 BTF 校验的 `vm_file`/`vm_pgoff`/`vm_flags` 与
  `d_path()` 恢复路径、文件偏移和权限；`/proc/<tgid>/maps` 不可读时不再退化为
  “无路径、权限未知”。
- manual provider 的 ELF 头/动态段/符号表从文件页缓存读取，按 PT_LOAD 几何换算
  文件偏移（含 APK entry 偏移），不再 GUP 读 provider 映射页。
- memfd/已删除 provider 才回退到 `copy_from_user_nofault` 的 resident-only 解析。
- provider 表增长后重建 view/io 绑定，provider 文件句柄统一释放。
- 新增第 15 组主机测试 `test/test_provider_file.py`。

详细实现与证据见
[崩溃分析第 11 节](CRASH_ANALYSIS_MANJUU_PROMILIA.md) 与
[实现说明](IMPLEMENTATION.md)。

## 2. 产物

- `kclf.kpm`
  - SHA-256：`8FA9DDFC7FFAD556D8261D61EFEB00E28D6AAF08A48D9D51724F221686C72B89`
  - 构建：WSL Ubuntu 24.04，`aarch64-linux-gnu-gcc` 13，
    `make KP_DIR=/mnt/e/KernelPatch TARGET_COMPILE=aarch64-linux-gnu-`
- 测试 App：`build/kclf-apptest/app.apk`，包名 `com.kclf.apptest`
- TLS fixtures：`build/tls/`（NDK clang 构建，未随本报告重新生成）

## 3. 主机回归

`make test` 在 WSL Ubuntu 24.04 通过全部 **15** 组：

- `test_helpers`、`test_maps`、`test_manual_elf`、`test_manual_symbols`
- `test_provider`、`test_provider_file`、`test_provider_table`
- `test_symbols`、`test_compat`、`test_completion`、`test_runtime`
- `tls/prepare`、`test_btf`、`test_codegen`（4K/16K/64K）、`tls/elf`

均启用 ASan/UBSan（`UBSAN_OPTIONS=halt_on_error=1`）；主机测试不是设备或内核认证。

## 4. 设备回归

### 4.1 测试 App：manual 后端

`.\test\app\device-test.ps1 -SuperKey <key> -Backend manual -Repeat 3`

结果：`ALL APP CASES PASSED`。覆盖主线程/Binder/sleeper 注入、FPSIMD 恢复、
四线程排队/取消、`unload`/`release`、marker、transient/guard 布局、无匿名可执行
映射、忙 `quiesce`、模块 reload 及排空卸载。

证据：`build/kclf-app-20bb3ae036b3/results.txt`（Repeat 3）；最终产物另做
`-Repeat 1`，`build/kclf-app-663e8f796f99/results.txt` 同为 `ALL APP CASES PASSED`。

### 4.2 测试 App：linker 后端

`.\test\app\device-test.ps1 -SuperKey <key> -Backend linker -Repeat 3`

结果：`ALL APP CASES PASSED`，`via=__loader_dlopen`、`by=__loader_dlclose`。

证据：`build/kclf-app-810f0c989e36/results.txt`（Repeat 3）；最终产物另做
`-Repeat 1`，`build/kclf-app-fbbd29f1654f/results.txt` 同为 `ALL APP CASES PASSED`。

### 4.3 测试 App：ELF TLS

`python test/tls/device-test.py --serial <SERIAL> --repeat 3`

结果：`PASS: 93 TLS device assertions`。覆盖 native `tls-elf`/`tls-runtime`、
文件后备 TLS 代码页、模板/BSS、8 线程、image reuse、NODELETE 拒绝、key 耗尽
回滚、失败加载回滚及安全卸载。

证据：`build/kclf-tls-8f8e44af6d65/`。

### 4.4 目标应用：50 s 保护态注入

目标：`com.manjuu.promilia` 1.0.1（Unity/il2cpp，内置 `libtersafe2.so`），
进程在启动后调用 `prctl(PR_SET_DUMPABLE, 0)`。

步骤：启动目标，等待 50 s（保护态已建立），注入
`/data/user/0/com.manjuu.promilia/files/kclf-probe.so,wake`。

结果：

```text
#0 id=1 pid=<pid>(manjuu.promilia) state=done stage=restore handle=1
   done=syscall stack=transient/0 via=manual image=1 refs=1
   resident=<addr>+86016 hdr=scrubbed
```

- 1.6.3 迭代构建（direct VMA 元数据 + resident-only provider 回退）2 s 间隔
  持续观测 120 s：进程存活。
- 文件后备 provider 构建复测 60 s：进程存活，`VmHWM` 注入前后相同
  （`1440696 KiB`）。
- 最终产物（SHA-256 `8FA9DDFC...C72B89`）再次注入并观测 60 s：进程存活，
  `state=done via=manual`。
- 一次准备发现 `providers=359 file=343 resident=16`。
- `dmesg` 无 `KCLFSIG*` 的 handler 改写/伪造信号。
- `release`：`refs=0 resident=0+0 unload=ok rc=0`。

## 5. 未覆盖与限制

- 未在 16K/64K 页设备、其他内核版本或其他厂商配置上实测；主机模拟不能替代真机。
- provider 文件必须在准备期间仍可按路径打开且内容与映射 inode 一致；应用更新替换、
  反作弊 unlink 后只能走 resident-only 回退，元数据页已回收时会明确失败。
- APK 内嵌库按“ELF 头位于映射起始位置”处理，对应 Android 未压缩 native library
  的页对齐布局；非页对齐异常 entry 需改用已解压/预加载库。
- `linker` 后端仍由目标 bionic loader 自行映射和解析依赖，本轮“不读目标页”的
  优化只覆盖默认 `manual` 后端。
- 不承诺对所有 in-process 反作弊不可见；本轮修复的是已量化的 provider 元数据
  读取与 non-dumpable VMA 元数据缺口。
