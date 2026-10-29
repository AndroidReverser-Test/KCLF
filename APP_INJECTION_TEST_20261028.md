# 指定 App 的 KCLF 注入实测（2026-10-28）

## 结论

当前源码重新构建的 **KCLF 1.3.1 在本次设备上的两个目标 App 均通过测试**。
最终一轮共执行 14 个注入请求：10 次成功加载并独立确认构造函数执行，4 次
缺失/截断 SO 的预期失败。未发现需要修改框架核心代码的问题。

| 项目 | com.miHoYo.Nap | com.yhhy.neon.mi |
| --- | --- | --- |
| App 版本 | 3.3.0 | 3.2.861 |
| 本轮原进程 PID | 25314 | 25876 |
| 主线程 wake + unload | 3/3 通过 | 3/3 通过 |
| Binder wake + unload | TID 25326，通过 | TID 25913，通过 |
| 主线程 wake，SO 驻留 | 通过 | 通过 |
| 缺失 SO / 截断 SO | 2/2 按预期失败并恢复 | 2/2 按预期失败并恢复 |
| 停止后重启 | 新 PID 25648 | 新 PID 26353 |

每次成功都同时检查了 `state=done stage=restore`、非零 loader handle、
`via=__loader_dlopen`、`loading=0`、无剩余 `pending`/临时 `map`，以及 App 自己
写出的 PID/TID 标记。卸载模式额外检查 `unload=ok rc=0` 和 `/proc/<pid>/maps`
中测试 SO 已消失；驻留模式则检查 SO 仍有映射。

本次覆盖 App 启动后的进程、线程、加载/卸载和生命周期。驻留后观察 5 秒，
原进程保持存活；随后确认停止和重新启动成功。未登录游戏账号或验证实际游戏
流程，也没有对这些 App 做长时间稳定性、性能或全部寄存器状态的验证。

## 设备和产物

| 项目 | 实测值 |
| --- | --- |
| 设备 | 22041211AC / rubens |
| ADB serial | LVLNINYXKR4L6HAE |
| Android | 12，API 31 |
| ABI | arm64-v8a |
| 内核 | 5.10.66-android12-9-00001-gd262b276948e-ab8291727 |
| 页大小 | 4096 |
| SELinux | 测试前后均为 Enforcing |
| App seccomp | 两个原进程均为 Seccomp: 2 |
| App SELinux 域 | 两者均为 untrusted_app 域 |
| 布局路径 | 无 BTF；get_task_mm + proc_maps；实测 pt_regs 大小 336 |
| 模块 SHA256 | b5483b9384a6d79795b9322ff3c02a621fb81421b5e7931d964090bafc0fbc66 |
| 最终 run ID | kclf-packages-861e0addbf4a |

构建命令：

```sh
make -B -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

在 WSL Ubuntu 24.04 使用 AArch64 GCC 13.3.0，按 Makefile 的 `-Werror`、
freestanding、通用寄存器等选项完整重建。两个测试 SO 使用 Android NDK
27.0.12077973 的 clang、Android API 26、16K ELF 段对齐构建；仍只代表本次
4K 页设备实测。源码复用 `test/app/jni/payload.c`，只按目标包配置 files 目录和
本轮独立的 marker 文件名前缀。

## 框架实现梳理

### 1. 控制和任务身份

`kclf.c` 中 `KPM_CTL0(kclf_ctl0)` 提供 `inject/status/cancel/reap/quiesce/probe`
等命令，控制入口由 KernelPatch superkey 保护。框架有 4 个请求槽，记录目标
TID、持有引用的 `struct pid` 和借用的 mm 身份，避免 TID 复用导致错误匹配。
它不长期持有目标 mm，以免妨碍进程退出及 ActivityManager 生命周期。

`inject,<tid>,<so-path>,wake` 将准备回调通过 `task_work_add(..., TWA_SIGNAL)`
排到目标线程。默认 resume 用 `TWA_RESUME`，等待目标自然返回用户态；wake
可以通知阻塞线程。本轮全部使用默认安全点检查加 wake，未使用 force。

### 2. 目标上下文中的准备

`kclf_exec_prepare()` 由目标线程执行，以目标凭据打开 SO，检查 ELF64、小端、
`ET_DYN` 和 `EM_AARCH64`。随后建立临时 11 页映射，布局为：

```text
[1 页 RX trampoline][1 页 RW 参数][1 页 PROT_NONE guard][8 页 RW 栈]
```

本设备无 BTF，`kclf_compat.c` 使用内核 `get_task_mm` accessor；VMA 枚举通过
目标自身 `/proc/thread-self/maps`，不猜 `mm_struct`/VMA 私有结构偏移。
`pt_regs` 的真实大小从 getpid syscall wrapper 帧学习，`probe` 实测为 336。

`kclf_resolve()` 在目标内存中扫描 ELF、动态表和符号表，优先解析 linker 的
`__loader_dlopen`、`__loader_dlclose` 和 `__loader_dlerror`，并提供 caller
地址用于命名空间选择。写入 trampoline 和参数使用 `access_process_vm`，
之后调整 code 页权限、设置 guard 并刷新指令缓存。

本次将测试 SO 临时放在各 App 现有 `/data/app/.../lib/arm64/` 目录，权限
0644、所有者 system:system、SELinux 标签 `apk_data_file`，满足实际 linker
路径和可执行映射要求。未改变 SELinux 模式或目标 seccomp 规则。

### 3. 返回用户态和加载

准备后排队 hijack 回调，检查准确的 `pt_regs` 帧、架构和线程状态。安全模式
检查目标不在 linker 内部、系统调用属于允许的启发式集合；跟踪/模拟及
SVE/SME 等不支持状态仍会被拒绝。

`kclf_exec_hijack()` 保存通用寄存器、PC/SP/PSTATE 及系统调用恢复信息，
将返回 PC/SP 指向 trampoline 和临时栈。`kclf_tramp.S` 另行保存全部
q0–q31、FPCR/FPSR，再以 `RTLD_NOW` 调用目标自身 loader。unload 选项使
构造函数返回后继续调用 dlclose。

### 4. 完成、现场恢复和回收

trampoline 通过寄存器携带 loader handle、错误指针、dlclose 返回码和随机
cookie，恢复 FPSIMD 状态后执行 `getpid`。`kclf_getpid_before/after()` 校验
目标身份、mm、cookie、系统调用号和准确返回 PC，识别框架完成通知，并恢复
原来的通用寄存器及系统调用恢复语义。

随后目标线程执行 cleanup task_work，读取必要的错误信息并 `vm_munmap`
临时映射。状态、未完成回调引用和映射都清理后，`reap` 才能回收请求槽。
stock KernelPatch 宿主不遵守模块 exit-veto，因此必须先 `quiesce=idle` 再
卸载。本轮按此顺序完成卸载，最终 KPM 列表恢复为空。

## 独立执行证据

两个 Binder 注入分别得到：

```text
pid=25314 tid=25326 marker=0x72ea76e870
pid=25876 tid=25913 marker=0x753b84c870
```

两个主线程驻留注入分别得到：

```text
#0 id=7 pid=25314(com.miHoYo.Nap) state=done stage=restore handle=5e4adb897ebd0a8d via=__loader_dlopen
hook=getpid loading=0 page=4096
pid=25314 tid=25314 marker=0x72ea756870

#0 id=14 pid=25876(om.yhhy.neon.mi) state=done stage=restore handle=7b5ad6f5d4ad4059 via=__loader_dlopen
hook=getpid loading=0 page=4096
pid=25876 tid=25876 marker=0x753b84d870
```

`comm` 中 `com.yhhy.neon.mi` 显示为 `om.yhhy.neon.mi` 是内核线程名长度限制；
目标选择和独立验证使用实际包名、PID/TID，不依赖截断的 comm。

缺失文件返回 `state=failed stage=prepare`、`open library failed rc=-2`。
只保留 ELF 头的截断文件返回 `state=failed stage=loader`，动态链接器报告
`invalid phdr offset/size: 64/504`。两者均没有运行构造函数，临时映射和回调
均完成回收，原进程保持存活，后续成功注入继续完成。

ActivityManager 快照显示驻留观察后：`com.miHoYo.Nap` 的 resumed activity 为
`ComboSDKActivity`，`com.yhhy.neon.mi` 已进入 `com.tpf.sdk.unity.GameActivity`。
快照仅说明前台 Activity 状态，不作为登录或游戏流程已通过的依据。

## 清理和日志

- 两个 App 均恢复到测试前的停止状态；没有清空数据或重新安装 APK。
- App native library 目录中的本轮正常/截断 SO 和 files 中的 marker 全部删除。
- `/data/local/tmp/kclf-packages-861e0addbf4a` 的本轮暂存文件及空目录已删除。
- `quiesce=idle` 后卸载 KCLF，最终 KPM 列表与测试前一致；无清理错误。
- boot ID 前后相同；设备未重启，SELinux 仍为 Enforcing。
- 前后保留的 dmesg 中没有新增 `BUG/WARNING/Oops/panic`；crash buffer 没有
  新增目标 App 条目。logcat 中的 10-27 kpatch SIGSEGV 是测试前已有的旧记录。
- 主机侧 `test_helpers.py`、`test_maps.py`、`test_compat.py` 均实际执行通过；
  其中模拟内核版本测试不代表相应版本已做真机回归。

## 文件和复测

最终证据目录：`E:/KernelPatch/build/kclf-packages-20261028-final/`。

- `summary.json`：`passed: true`，两包各 7 条请求、PID/TID、handle、独立 marker。
- `results.txt`：完整控制交互和每项断言结果。
- `baseline.json`、`probe.txt`：设备、模块哈希和运行时能力。
- `*-status.txt`、`*-marker.txt`、`*-maps.txt`：逐项原始证据。
- `*-activity-after.txt`、`*-threads.txt`：Activity 和线程快照。
- `dmesg-before/after.txt`、`crash-before/after.txt`、`logcat-after.txt`：日志。
- `kclf.kpm`、两个测试 SO、`package-test.py`、`payload.c`：产物及测试源码快照。

首次试跑证据保留于 `E:/KernelPatch/build/kclf-packages-20261028/`：两个包的
主线程重复注入都通过，后因测试脚本只匹配小写 `binder:` 而未匹配设备实际的
`Binder:`，未继续驻留和重启用例。这是测试脚本匹配问题；修正为大小写兼容后，
相同 SHA256 的 KPM 完成上述全部测试。首轮退出时同样已清理 App 文件并卸载 KPM。

复测入口为 `test/package-test.py`，superkey 从 `KCLF_SUPERKEY` 环境变量读取，
不写入脚本。PowerShell 示例：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/package-test.py `
  --package com.miHoYo.Nap --package com.yhhy.neon.mi `
  --serial LVLNINYXKR4L6HAE `
  --clang D:/androidSDK/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe `
  --repeat 3 --observe 5
Remove-Item Env:KCLF_SUPERKEY
```

本次新增可复用脚本，并给原 app 测试 payload 增加可选的
`KCLF_APP_MARKER_PREFIX`；默认仍为 `hit_`，原自有测试 APK 行为保持兼容。
框架核心 C/ASM 源码无需修改。
