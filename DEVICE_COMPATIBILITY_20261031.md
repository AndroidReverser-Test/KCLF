# KCLF 内核兼容性与当前设备复核

日期：2026-10-31（用户时区 Asia/Shanghai）。

## 结论

框架具有跨内核适配设计，但不是对全部 Android 内核的通用兼容保证。代码接受的版本
范围是 `5.0 <= kver < 7.0`；运行时还要满足宿主、符号、ABI、目标架构和状态检查。
本次使用源码重新构建，在当前 Pixel 6 的自建普通 App 上验证，发现并修复了完成轮询
不能唤醒阻塞线程的问题。修复后默认 manual、显式 linker 及禁用 BTF/nofault 的
manual 回退构建通过所测场景。其他内核和大页设备未在本次实测。

工作起点是独立仓库 `kpms/kclf` 的 `c35dc06` 加已有未提交 1.5.3 修改；原始差异保存在
`../../build/kclf-device-audit-20261031/initial-changes.patch`。此前的错误处理、RELRO、
控制面等修改属于既有工作，本次仅继续修复下文的问题。没有提交 Git。

## 1. 实现流程

| 部分 | 实现与约束 |
| --- | --- |
| 控制面 | `kclf.c` 经 KernelPatch 的 superkey 保护 `ctl0` 接收命令，管理 4 个请求槽和目标 PID 引用 |
| 调度 | `task_work_add` 将 prepare、hijack、poll、cleanup 排到目标线程；验证 mm 身份，避免 PID 复用及 exec 后误操作 |
| 准备 | `kclf_exec.c` 在目标上下文准备临时 RX 代码页、RW 参数页和私有页；可借用目标栈，否则使用带 guard 的临时栈 |
| manual（默认） | `kclf_manual.c` / `kclf_elf.c` 快照并检查 ELF，映射 PT_LOAD，查找已加载依赖，解析符号和版本，处理 RELA/APS2/RELR；维护 32 项驻留镜像及引用 |
| linker（显式） | 从目标的 ELF 映射解析 bionic loader 入口，EL0 调用 dlopen/dlclose；受目标 namespace、文件访问等约束 |
| 执行 | `kclf_codegen.c` 生成 ARM64 程序；返回用户态前修改 `pt_regs`，在目标线程执行初始化/终结函数并恢复上下文 |
| 完成 | EL0 写请求 token；目标后续普通 syscall 的 nofault hook，或控制端排队的目标上下文 poll 观察结果；cleanup 应用延迟 RELRO 并解除临时映射 |
| 生命周期 | `IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE/FAILED`；DONE 本身不代表映射和回调已回收；驻留镜像另需 release |

manual 只处理已实现的 ELF 子集：依赖（含传递依赖）必须已加载且保持驻留；不提供
完整 bionic soinfo、TLS、异常展开注册和 namespace 语义。不支持的 ELF 特性明确失败。

## 2. 多内核适配方式及边界

| 内核差异 | 当前处理 | 本次证据 |
| --- | --- | --- |
| task_work 通知 ABI | 5.0–5.7 基线为 bool/RESUME；5.8+ 支持 SIGNAL；BTF 中可验证的 enum/bool 原型优先 | 主机 ABI 用例；当前内核 BTF 验证 |
| task_work 取消 ABI | 优先明确的 cancel_match/cancel_func；同名 cancel 的不兼容原型用 BTF 区分；不能证明时拒绝 | 主机用例；当前设备 `cancel=match` |
| task/mm/VMA/锁布局 | 有 BTF 则验证偏移；否则用 get_task_mm 和目标自己的 proc maps，避免依赖 rb-tree/maple-tree 内部布局 | 正式构建及关闭 BTF 的专用构建 |
| pt_regs 大小 | 优先 BTF；无 BTF 时从宿主 syscall wrapper 的真实帧学习，无法定位时不注入 | 当前设备 336 字节；回退构建也成功学习 |
| 用户内存读取 | hook 中只用 nofault；缺失时交给可睡眠 task_work 使用 access_process_vm/GUP | 关闭 nofault 的 App 全流程回归；阻塞线程缺陷见下文 |
| ARM64 TIF 位号 | 6.16 起 UPROBE 使用 bit 5；较旧版本 bit 4；SVE/SME 状态拒绝 | 对照上游代码及主机模拟，未在 6.16 硬件测试 |
| 页大小/用户地址 | 从 TCR_EL1 检测 4K/16K/64K、用户地址上界及 TBI | 主机生成器覆盖三种页；真机仅 4K |

版本族判断：

- 5.0–5.7：实现了保守 RESUME 路径；没有本次真机证据，不能承诺主动 wake。
- 5.8–5.19：有相应通知/取消/旧 procfs ABI 适配；没有本次真机证据。
- 6.0–6.15：本次仅 **6.1.134 / ARM64 / 4K** 实测；其他小版本仍需回归。
- 6.16 及更新 6.x：已有部分位号和能力适配，未逐版认证；版本范围通过不等于兼容。
- 无 BTF/nofault：本次是同一 6.1 设备关闭能力的专用构建，不能将它称为 5.x 真机测试。

宿主仍须正确提供 current/stack/thread_size、hook、RCU 和导出接口，并兼容内核的
CFI/LTO 等配置。缺少必需符号或布局验证失败会拒绝加载/注入。厂商若回移 TIF 位号而
保留旧版本标签，版本推断仍有局限。32 位、SVE/SME、强制 BTI、MTE/标记栈及复杂信号
重入不属于本次已验收范围。

ABI 对照来源：[Linux 5.4 task_work](https://github.com/torvalds/linux/blob/v5.4/include/linux/task_work.h)、
[Linux 5.8 task_work](https://github.com/torvalds/linux/blob/v5.8/include/linux/task_work.h)、
[ARM64 6.1 pt_regs](https://github.com/torvalds/linux/blob/v6.1/arch/arm64/include/asm/ptrace.h)、
[ARM64 6.16 thread_info](https://github.com/torvalds/linux/blob/v6.16/arch/arm64/include/asm/thread_info.h)。

## 3. 本次复现与修复

### 完成轮询无法唤醒阻塞线程

在关闭 BTF、关闭 nofault 的构建中，向 App 的 `kclf-idle0`（阻塞 pipe read）执行
`wake,unload,manual`。构造函数实际执行，但请求长期保持 `RUNNING/pending=1`，15 秒
后测试超时。独立 marker 是 `pid=19449 tid=19475 marker=0x7b9c014858`。

根因：nofault 不可用时 syscall hook 不能读 token，只能依赖可睡眠 poll；EL0 返回
原程序后线程再次阻塞，`kclf_poll_running()` 却始终用 `TWA_RESUME`，不能促使该线程
处理已经排队的 poll。此问题也影响其他只能依赖 poll 的配置。

修复：请求显式选择 `wake` 且内核支持时，poll 同样使用 `TWA_SIGNAL`；默认 resume
请求仍等待自然返回边界，旧 bool ABI 也仍只传 RESUME。保留原来的 poll 去重及队列
失败恢复逻辑。主机测试直接提取生产函数，验证 wake/能力组合、重复排队及拒绝后重试；
新增断言在修复前失败，修复后通过。真机回归进一步验证实际阻塞线程能完成与回收。

行为影响：对 wake 请求调用 status/reap/quiesce 可能再次打断目标的可中断 syscall，
包括构造函数自己的等待。测试 payload 的两秒 hold 已改为重试 EINTR/剩余时间，保证
生命周期测试不因轮询提前结束等待。payload 本身仍应正确处理 syscall 中断。

### status 先排队 poll，遮蔽运行映射信息

首轮 manual App 测试在长构造函数中只读到 `pending=1`，无法观察已准备好的映射。
原因是 status 自己先排队 poll，再因 pending 非零省略详细信息。现改为先渲染状态，
再请求下一次 poll；此前已有 in-flight work 时仍只输出保守的 pending 状态。

### App 驱动与现有实现脱节

- 删除已移除的 `hook=libc` 验收条件，检查实际 `completion=el0`。
- 新增 `-Backend manual|linker`（默认 manual）、独立 `-Kpm` 及 `-ExpectPoll`。
- 按后端验证驻留、错误阶段和回收；借用目标栈时允许无额外 guard，修正临时栈页数范围。
- 每次常规注入先删除旧 marker；从新 marker 的函数地址核对实际解除映射，避免把匿名
  manual 映射按文件名判断，或把旧构造记录当成此次执行证据。
- 保留最终日志/内核告警检查，排空后卸载模块，停止测试 App；APK 和本地证据保留。

## 4. 设备与证据

设备为 Pixel 6，序列号 `25091FDF60063J`，Android 16 / API 36，内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`，ARM64 / 4096 字节页，KP `c00`。
测试包是本仓库构建的 `com.kclf.apptest`：普通非 root UID、untrusted_app、zygote
seccomp mode 2。未测试第三方目标。

正式 probe：BTF=1、mm_off=1440、mmap_lock_off=96、pt_regs=336、thread_size=16384、
cancel=match、wake_abi=btf、70/70 syscall hooks。回退 probe：BTF=0、proc_maps、
get_task_mm、nofault=0，使用学习到的寄存器帧和 `done=poll` 完成。

主机 10 组 ASan/UBSan 测试、4K/16K/64K 代码生成结构检查、ARM64 严格构建和
`git diff --check` 通过；未新增 libc 或 outline atomic 链接依赖。

验收表及最终 SHA256 在本节末尾记录。原始失败也保留：

| 证据 | 位置（父仓库 build/） |
| --- | --- |
| 原测试误查 hook=libc | `kclf-app-26860bc4e287/results.txt` |
| status 无运行映射信息 | `kclf-app-26fe277f85b4/results.txt` |
| nofault 回退阻塞超时 | `kclf-app-53f24b14557e/results.txt` |
| 失败时的独立构造 marker | `kclf-device-audit-20261031/fallback-timeout-marker.txt` |
| 修复前回退模块 | `kclf-device-audit-20261031/fallback-before-fix.kpm`，SHA256 `1930bf277bf32151e1709fbcd44ef07d44e0175866d8cb33eecb02a2993ef564` |
| 新增主机回归修复前失败 | `kclf-device-audit-20261031/poll-regression-before.txt` |
| 修复后主机测试及构建 | `kclf-device-audit-20261031/host-after-poll.txt`、`build-after-poll.txt`、`fallback-after-poll-build.txt` |

最终验收：

| 构建 / 后端 | 结果 | 原始证据（父仓库 build/） |
| --- | --- | --- |
| 正式模块 / manual，连续加载卸载 10 次 | 236 项断言通过 | `kclf-app-7d3257d80616/results.txt` |
| 同一正式模块 / linker，连续加载卸载 10 次 | 219 项断言通过 | `kclf-app-8c5cd2ae9745/results.txt` |
| 关闭 BTF/nofault 的独立模块 / manual，连续加载卸载 3 次 | 178 项断言通过，12 个成功完成请求显式验证 done=poll | `kclf-app-639d5bdf51c9/results.txt` |

数量是断言数，不是独立内核或独立场景数。三套均覆盖主线程、Java sleeper、Binder、
FPSIMD、四槽取消/满表/重复请求、缺失及截断 SO、三种时机的进程退出、长构造函数、
临时 RX/栈映射回收、quiesce 和 reload。最终构造函数实际地址解除映射也经过检查。
最终摘要为 `kclf-device-audit-20261031/summary.json`；每轮目录含前后 dmesg/crash buffer。

最终 SHA256：

| 产物 | SHA256 |
| --- | --- |
| `kpms/kclf/kclf.kpm`（正式 1.5.3，含本次修复） | `52bf633ce914ef5af351c72da721f1a519995916159af4ccaece4c65ee26f01c` |
| `build/kclf-device-audit-20261031/fallback/kclf.kpm`（仅用于能力回退测试） | `47ee7cd2db366d9808ca7bef6b2f9671a66251328c2eb1959696c38f7035b22a` |
| `build/kclf-device-audit-20261031/app/app.apk` | `ec3bf02513fd00cb6d08cea87a8862b10807c449db25be6aab064d706abc00b3` |

正式模块版本字符串仍为既有 1.5.3，使用上述 hash 区分此前同版本产物。
最终只读确认 `kpm num=0`、测试 App 进程已停止、SELinux 为 Enforcing，boot ID 仍为
`4cac44fa-7107-401f-9352-cdb01df4de69`。测试 APK 保留供复现。

## 5. 保留的风险

本次 App 验收未发现新增 BUG/WARNING/Oops/panic 或测试 App crash；这不消除此前
`CODE_REVIEW_1.5.3.md` 记录的 `dec_rlimit_ucounts` WARNING。它在本次测试前已存在，
同一 boot 下的无 KCLF root 进程生命周期对照没有新增该告警，也不能证明根因消失。
上游该路径使用 [WARN_ON_ONCE](https://github.com/torvalds/linux/blob/v6.1/kernel/ucount.c)，
本次未重启、清空日志或修改宿主凭据/计数处理，不能凭后续没有重复打印认定已修复。

此外，最终 EL0 `br x16` 会占用原 x16；通用安全点启发式无法证明任意异步边界的 x16
均可丢弃。manual RELRO 仍在构造函数之后由 cleanup 收紧；依赖驻留/用户锁及信号重入
也有既有边界。本次修复没有将这些架构限制变为完整透明恢复保证。

stock KP 卸载不因模块 exit 返回错误而停止释放代码，必须先释放驻留镜像并获得
`quiesce=idle`。本次各轮均按此排空，没有强卸载活动模块。

## 6. 复现

```sh
make -C kpms/kclf test
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

```powershell
./kpms/kclf/test/app/build.ps1 -OutDir ./build/kclf-device-audit-20261031/app
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' `
  -Apk './build/kclf-device-audit-20261031/app/app.apk' -Backend manual -Repeat 10
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' `
  -Apk './build/kclf-device-audit-20261031/app/app.apk' -Backend linker -Repeat 10
```

回退验证须另建源文件副本，使用
`CFLAGS="-DKCLF_TEST_NO_BTF -DKCLF_TEST_NO_NOFAULT"` 和指向父仓库的绝对 `KP_DIR`
构建，再给驱动追加 `-Kpm '<独立回退产物>' -ExpectPoll`。该产物不替换正式模块，
也不代表在另一内核版本实测。
