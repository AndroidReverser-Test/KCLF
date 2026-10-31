# KCLF 1.5.3 实现与代码规范审查

日期：2026-10-31。审查基线：本目录独立 Git 仓库的 `c35dc06`（1.5.2）。

结论：框架已有分层、长度限制、目标身份检查和失败回收机制，但不能认定为完全符合
内核编程及异步上下文恢复约束。本轮修复可局部验证的问题，保留双后端和控制面；
未改动 KernelPatch 宿主，未扩大加载能力，也未修改安全策略。

## 1. 实际实现

| 部分 | 文件 / 关键函数 | 职责与边界 |
| --- | --- | --- |
| 控制面与生命周期 | `kclf.c` / `kclf_ctl0`、`kclf_cmd_inject` | superkey 保护的 ctl0 字符串协议；4 个请求槽；固定容量输出；控制端互斥 |
| 目标调度 | `kclf.c` / `kclf_queue_work`、`kclf_work_*` | 持有 `struct pid` 引用，mm 仅作身份比较；prepare/hijack/cleanup/poll 在目标线程执行；pending 计数覆盖排队和执行中的回调 |
| 运行时兼容性 | `kclf_compat.c`、`kclf_btf.h` | BTF 校验结构偏移与取消 ABI；缺失时使用 accessor、procfs、syscall 帧学习；未知 ABI 拒绝 |
| 映射与跳板 | `kclf_exec.c`、`kclf_codegen.c` | 准备临时 RX/RW 页面、参数、栈；检查返回边界并修改 pt_regs；EL0 调用加载器或初始化函数，恢复大部分上下文 |
| manual 后端 | `kclf_manual.c`、`kclf_elf.c` | 文件快照、ELF/PT_LOAD 校验、已加载 DT_NEEDED 闭包、符号版本与 RELA/APS2/RELR 重定位、EL0 IFUNC/构造/析构、32 项驻留镜像及引用计数 |
| linker 后端 | `kclf_exec.c` / `kclf_resolve` | 从目标 ELF 查找 bionic loader 入口；在 EL0 调用 dlopen/dlclose，依赖系统 linker 的命名空间和加载规则 |
| 完成与回收 | `kclf.c` / `kclf_complete`、`kclf_work_cleanup_body` | 普通 syscall hook 或目标上下文 poll 观察 token；读取结果，应用延迟 RELRO，再提交镜像与回收临时映射 |

主要状态链是 `IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE/FAILED`。
`DONE` 表示已经观察到 EL0 完成；只有清理完成、pending 为零且临时映射消失，槽位才可复用。
驻留镜像独立于短期请求槽，必须 release 或在进程退出后 reap，才能满足卸载条件。

manual 是受限的手动加载器，不是 bionic 的完整替代：依赖必须事先加载并保持驻留；
不注册 soinfo/展开信息；TLS、部分 IFUNC、GNU property 等未实现语义被拒绝。

## 2. 本轮“规范”的范围

- 格式遵循父仓库现有 `.clang-format`（4 空格、120 列等），不将它误称为 Linux 上游
  8 列 Tab 风格；本轮没有全目录重排。参考 [Linux coding style](https://www.kernel.org/doc/html/latest/process/coding-style.html)。
- 重点是确定的初始化、错误传播、边界校验、资源所有权和可重复验证，不宣称通过 MISRA、
  CERT C、KCSAN 或完整内核静态验证。
- AArch64 调用约定以 [AAPCS64](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst)
  为依据。IP0/x16 可以在子程序调用间保存临时值；caller-saved 不等于异步中断时可以丢弃。
- ELF 扩展语义对照 [AOSP APS2 实现](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_reloc_iterators.h)
  和 [AOSP ELF/RELRO 实现](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_phdr.cpp)。
  APS2 分组 addend 的现有实现与参考一致，本轮没有凭推测修改它。

## 3. 已修复的问题

### P1：RELRO 失败仍可能被报告为成功

原 `kclf_apply_relro()` 在首个 mprotect 前就置 `relro_done=1`；失败后重试会直接成功返回。
`kclf_work_cleanup_body()` 又用 `kclf_exec_finish()` 的结果覆盖保护错误，可能将未完整保护
的镜像登记为 LIVE，并回收用于诊断的临时资源。

改动：

- `relro_done` 改为成功完成的范围数，仅在对应 mprotect 成功后前进。
- 验证范围数和进度边界；后续重试从失败范围继续，不重复已成功的范围。
- 保护全部完成前不执行镜像提交/回收；最多 8 次重试。
- 重试耗尽或队列拒绝时报告 `FAILED/RESTORE` 并保留所有权。构造函数可能已经产生副作用，
  不尝试伪装成功，也不自动拆掉可能仍有引用的代码。
- cleanup 使用 `kclf_complete()` 已提交的完整结果快照，不在重试中重新读取可变 EL0 结果。

这是错误处理修复，**没有改变 RELRO 仍在构造函数后应用的架构限制**。

### P2：结果页中错误指针未初始化

参数页先随机填充；原代码未初始化 `KCLF_P_ERRPTR`。成功加载或没有 dlerror 入口时，
EL0 尾段仍会读取它，linker 清理路径可能尝试从随机地址取错误文本。

抽取 `kclf_init_params()`，明确初始化 HANDLE、ERRPTR、后端标志、卸载标志及入口字段；
manual 再覆盖自己的句柄和调用向量。路径复制固定字段完整长度并保证 NUL。

### P2：控制面存在静默忽略和分散的数字解析

新增共享有界十进制解析器，覆盖 TID、镜像 ID、槽号和分页游标；在乘法前检查溢出，
失败不改结果。容量使用公共常量，避免取消命令硬编码 4 槽、分页硬编码 32 项。

拒绝重复参数、互斥的 wake/resume 与 manual/linker、无意义的 linker/keepelf、release 的
非法选项；接收 CRLF，拒绝非分隔控制字符。只有完整验证通过才查找目标和排队。
未提供专用文字的失败也返回 `error: rc=...`，不再只给空输出。

这会收紧部分历史命令的接受范围，但不改变合法命令默认 manual 的行为。

### P2：用户写入边界与 errno 不一致

`kclf_uwr()` 复用读侧同一个地址区间判断，非法区间统一返回 `-EFAULT`，不再返回含义不明
的 `-1`，也不接受恰好位于用户空间上界的零长度写。保留有条件的 TBI 去标签和短拷贝检测。

### 可维护性与验证约束

- 添加 `-Wformat=2`、`-Wshadow`、`-Wframe-larger-than=2048`，保留 `-Werror`；为错误输出函数
  添加 printf 格式属性，并修复遮蔽宿主全局 `va_bits` 的局部变量名。
- 添加 `-fno-strict-aliasing`，使已有字节 ABI 缓冲区/整数视图操作不依赖严格别名优化假设。
  这不是其他未定义行为或对齐问题的通用豁免。
- 新增 `make test`：8 个 Python 主机测试套件，加 BTF 与代码生成 C 套件；临时产物在临时目录。
- 新增真实生产函数的 mock 故障注入；保留 ASan/UBSan，UBSan 报错即失败。
- 设备回归增加无效命令和结果初始化断言；adb 超时不输出包含密钥的 argv。
  最终验收结果纳入内核告警和模块清理，功能通过不再提前标为全部验收通过。
- 更正代码中“内核恢复全部 pt_regs”“恢复中间状态不可观察”等过时注释。模块版本为 1.5.3。

## 4. 仍未解决的限制

1. **P1，x16 不是透明恢复。** 最终 `br x16` 会破坏原 x16。调用约定不证明任意 syscall
   返回点、信号返回点或中断点的 x16 都不存活。现有安全点列表和 `force` 无法提供这种证明。
   完整解决需要重新设计恢复协议，或目标明确提供协作边界，本轮未改写完成机制。
2. **P1，RELRO 生效偏晚。** IFUNC 结果写入之后，构造函数仍在 RELRO 可写期间运行，直到
   观察完成后的 cleanup 才收紧权限。修复错误传播不等于达到常规动态链接器的初始化时序。
3. **P1，强制卸载仍不安全。** 宿主 `unload_module()` 不以 exit 返回值阻止释放代码。
   必须先排空并看到 `quiesce=idle`；本轮没有改动宿主装卸 ABI。
4. 异步插入可能遇到用户锁、信号和其他线程的地址空间修改；manual 依赖来源匹配是启发式，
   不保证 bionic 全局插入/命名空间语义。目标及 payload 必须属于受控协作场景。
5. BTI、SVE/SME、MTE/标记栈等扩展状态和跨版本供应商内核没有全面验收；不把单一 6.1 设备
   或 mock 的版本号测试推广成所有 Android/5.x/6.x 都兼容。

## 5. 本轮验证与设备告警

### 主机与构建

```sh
make -C kpms/kclf test
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
git -C kpms/kclf diff --check
```

10 组主机测试通过；ARM64 freestanding 严格编译通过。代码生成器检查了 4K/16K/64K
页面，但没有在主机执行这些 ARM64 指令。mock 保护失败测试不能替代真实内核故障注入。

### 设备

Pixel 6 / Android 16 / `6.1.134-android14-11-g66e758f7d0c0-ab13748739` / ARM64 / 4096 字节页。
执行 `test/manual-device-test.py` 完整 native 套件，未使用 `--app`，未测试既有应用。

- 功能断言 **148/148 通过**：双后端、引用复用/释放、RELA/APS2/RELR、SysV hash、
  构造/析构顺序、失败回滚、FPSIMD、测试进程 seccomp、取消、进程退出、分页及 quiesce。
- **总体验收未通过**：新增一条 `WARNING: CPU: 7 PID: 1 at kernel/ucount.c:285
  dec_rlimit_ucounts+0x60/0x78`，发生在停止测试进程阶段。
- 栈包含 `release_task` / `wait_consider_task` / `do_wait` / `kernel_wait4` / `__arm64_sys_wait4`。
  现场指向进程回收/计数路径；仅凭此栈不能排除 KCLF、已部署 KP 凭据处理或其他宿主因素，
  **根因未确定**，不能将其忽略为无关告警。
- 未看到新的 Oops/Kernel panic；boot ID 未改变，SELinux 保持 Enforcing。
- 已完成 `reap -> quiesce=idle -> unload`，后续只读确认 `kpm num=0`；本轮自有测试进程已结束。
  未继续加载模块重跑，未清除日志、重启设备或改动内核告警配置。

产物：`kclf.kpm`，SHA-256：
`23d18d42349a593b36bc36f35fc692fd41a494955d1361267f5dfaca599db44e`。

原始证据位于父仓库的 `build/kclf-manual-861d6dfac8a9/`：`results.json`、
`dmesg-before.txt`、`dmesg-after.txt` 及拉回的测试日志。设备测试文件保留在
`/data/local/tmp/kclf-manual-861d6dfac8a9/` 供复核，模块没有继续加载。
原始 JSON 的 `ALL MANUAL DEVICE CASES PASSED` 是旧脚本的功能阶段标记，最后的
`new_kernel_faults` 才给出告警；本轮已修订脚本，使今后的最终 `result` 明确反映总体验收。

后续应先对比无 KCLF 的自有进程生命周期和设备实际部署的 KP 版本，定位 ucounts 告警；
这涉及宿主凭据/进程计数，不能在没有确认根因的情况下修改本模块来掩盖它。
