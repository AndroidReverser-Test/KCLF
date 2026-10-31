# KCLF 1.5.4：实现、内核兼容性与小米 13 实测

日期：2026-10-31（Asia/Shanghai）。

## 结论

框架通过运行时符号查找、BTF 校验和 accessor/procfs 回退适配多个内核版本，
但 `5.0 <= kver < 7.0` 只是候选版本范围，不是全部版本、厂商配置的兼容保证。

本轮实际设备是 **小米 13 / 2211133C / fuxi，Android 13，5.15.74，ARM64，4K 页**。
源码起点为子仓库 `c35dc06` 加已有未提交的 1.5.3 修改；没有覆盖、重置或提交这些修改。
起始差异保存在父仓库 `build/kclf-fuxi-20261031/initial-changes.patch`。

原产物在普通测试 App 上执行了构造函数，却在返回 libc 时触发 SIGILL，不能正常工作。
已修复 BTI 返回指令，版本更新为 **1.5.4**。修复后 manual、linker 和无 BTF/nofault
回退构建均通过本轮 App 用例。测试结束已排空并卸载模块、停止测试 App。

## 1. 具体实现

| 文件 / 入口 | 实际职责 |
| --- | --- |
| `kclf.c` / `kclf_ctl0`、`kclf_cmd_inject` | superkey 保护的 KernelPatch ctl0 协议；4 个请求槽；验证数字、选项、PID 引用和 mm 身份 |
| `kclf.c` / `kclf_queue_work`、`kclf_work_*` | 使用 task_work 在目标线程执行准备、寄存器重定向、轮询和清理；pending 计数保护异步回调生命周期 |
| `kclf_compat.c`、`kclf_btf.h` | 运行时验证 task/mm/VMA/锁/pt_regs 布局及 task_work ABI；缺失信息时使用保守回退 |
| `kclf_exec.c` | 以目标凭据打开 SO；准备临时 RX 代码页、RW 参数/私有页；借用目标栈或分配带 guard 的临时栈；修改返回用户态的 pt_regs |
| `kclf_manual.c`、`kclf_elf.c` | 默认后端：快照 ELF、映射 PT_LOAD、查找已驻留 DT_NEEDED 闭包、解析符号版本、处理 RELA/APS2/RELR；维护 32 项驻留镜像及引用计数 |
| `kclf_exec.c` / `kclf_resolve` | 显式 linker 后端：从目标映射解析 bionic loader 入口，由 EL0 调用 dlopen/dlclose，受目标 linker namespace 限制 |
| `kclf_codegen.c` | 按请求生成 ARM64 EL0 程序，执行 IFUNC/构造/终结或 linker 调用；保存/恢复基本 FPSIMD、SP、NZCV 和除 x16 外的 GPR |
| `kclf.c` / `kclf_complete`、cleanup | EL0 发布 token 后，普通 syscall 的 nofault hook 或可睡眠 task_work poll 收集结果；应用延迟 RELRO，提交/回收镜像，解除临时映射 |

请求流为 `IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE/FAILED`。
`DONE` 不独立证明 App 存活，也不代表所有回调和映射已经回收；还需检查 pending、map、
loading 及驻留镜像。手动驻留镜像需 release 或等待所属地址空间退出后 reap。

模块不通过 ptrace 或暂停整个进程实施注入。默认 RESUME 等目标自然返回用户态，wake
使用 TWA_SIGNAL 推动可中断阻塞线程处理 task_work。它可能打断原程序或构造函数的 syscall，
不能将异步插入点视为用户锁安全点。manual 不是完整 bionic linker：依赖必须事先加载且
保持驻留，不支持的 TLS、payload IFUNC/IRELATIVE、GNU property 等语义明确失败。

## 2. 多内核兼容性

| 变化点 | 当前适配 | 证据和限制 |
| --- | --- | --- |
| task_work 通知 | 旧 bool ABI 只用 RESUME；5.8+ 基线支持 SIGNAL；可验证的 BTF 原型优先于版本推断 | 主机模拟；本机 `wake_abi=btf` |
| task_work 取消 | 优先明确的 cancel_match/cancel_func；同名 cancel 的函数/对象 ABI 用 BTF 区分，不能证明时拒绝 | 本机 `cancel=match`，不盲猜 Android 回移 ABI |
| task/mm/VMA 与锁 | BTF 验证偏移；否则 get_task_mm + 目标上下文 proc maps，不直接依赖 rb-tree 或 maple-tree 布局 | 本机正式构建与无 BTF 构建均通过，实际 VMA 路径为 proc_maps |
| pt_regs 帧 | BTF 校验成员位置与大小；无 BTF 时从真实 syscall wrapper 帧学习 | 本机两种构建均定位 336 字节帧；无法定位时拒绝重定向 |
| 用户内存访问 | hook 只用 nofault；缺失时由 task_work 使用可睡眠 access_process_vm/GUP | 本轮关闭 nofault 后显式验证 `done=poll` |
| TIF 位号 | 6.16 起 UPROBE bit 5，此前 bit 4；拒绝所检查的 tracer/SVE/SME 状态 | 主机模拟覆盖 5.0–6.18 标签；厂商回移宏定义仍有限制 |
| 页大小、用户地址 | TCR_EL1 检测 4K/16K/64K、地址上界与 TBI | 代码生成主机检查覆盖三种页；本轮真机只有 4K |
| BTI | 1.5.4 使用 RET 返回被中断指令，避免 BR 把函数内部当作新入口 | 本轮在 BTI/PAC libc 上通过；不代表 GCS 或任意扩展状态已兼容 |

版本族结论：

- **5.0–5.7**：有保守 RESUME 路径；本轮未实测，不能承诺主动 wake。
- **5.8–5.19**：具备通知、取消及旧 procfs ABI 的适配；本轮仅 **5.15.74** 真机通过。
- **6.x**：有相应布局回退和位号适配；历史 6.1.134 证据属于旧产物，本轮 1.5.4 没有在 6.x 重测。
- **4.x、7.x**：当前版本检查明确拒绝。

宿主必须正确提供 current/stack/thread_size、hook、RCU 和所需导出接口。
隐藏必需符号、异常 CFI/LTO ABI、未知布局和厂商回移仍可能导致不支持。
关闭能力的构建仍运行在同一个 5.15 内核，不是另一内核版本的实测。

对照来源：[Linux 5.15 task_work ABI](https://raw.githubusercontent.com/torvalds/linux/v5.15/include/linux/task_work.h)、
[Linux 5.15 pt_regs](https://raw.githubusercontent.com/torvalds/linux/v5.15/arch/arm64/include/asm/ptrace.h)、
[Linux 6.16 TIF 定义](https://raw.githubusercontent.com/torvalds/linux/v6.16/arch/arm64/include/asm/thread_info.h)。

## 3. 故障复现与修复

### BTI 设备在恢复原 PC 时 SIGILL

首次实际注入的目标为测试 App 主线程 PID/TID `28279`。marker 记录
`pid=28279 tid=28279 marker=0x79c10f4890`；模块报告 `state=done ... done=syscall`，
但 App 主线程随后出现：

```text
Fatal signal 4 (SIGILL), code 1 (ILL_ILLOPC), fault addr 0x79b3b7bb1c
```

拉取设备 `/apex/com.android.runtime/lib64/bionic/libc.so` 后检查：GNU property 标记
`BTI, PAC`，Build ID 为 `2bb0d7188c0db2e8beecb24658ba9d71`。故障地址对应：

```text
__epoll_pwait:
e1b10: bti c
e1b14: mov x8, #0x16
e1b18: svc #0
e1b1c: cmn x0, #0x1, lsl #12   <- 原 PC / 故障位置
```

旧尾段 `br x16` 将 BTYPE 设为 01；原 PC 位于受保护函数内部，并非 BTI landing pad。
1.5.4 将其改为 `ret x16`，按返回语义保持 BTYPE=00；继续使用 x16 保存原 PC，
原 x30 保持为被中断线程的值。未修改 libc 或任何页面的 BTI 属性。
依据为 [Arm 指针认证、BTI 与 MTE 指南，第 4.4–4.6 节](https://developer.arm.com/-/media/Arm%20Developer%20Community/PDF/Learn%20the%20Architecture/Providing%20protection%20for%20complex%20software.pdf)。

`test_codegen.c` 新增末尾 RET 返回约束。先添加检查并运行旧实现，4K 的 8 个 seed
全部失败；修改生产代码后，4K/16K/64K 共 24 个生成程序通过。主机检查只验证指令结构，
真实 BTI 执行证据来自后续设备回归。

### 测试驱动修正

- 密钥校验接受 shell 安全字符 `@`，密钥没有写入源码或证据文件。
- 默认 adb 安装被本机返回 `INSTALL_FAILED_USER_RESTRICTED` 拒绝，模块尚未加载。
  增加显式 `-RootInstall`，通过用户授权的 kpatch root 执行 `pm install -r -t`，
  成功安装自建 APK；没有修改系统安装设置。
- 原崩溃检查只读 crash buffer，且匹配完整包名，漏掉 main buffer 中截断为
  `om.kclf.apptest` 的 libc fatal signal。现在同时采集 main/crash 的 libc/DEBUG/
  AndroidRuntime 日志，并识别截断线程名；保留前后差分，不清理日志。
- 存活检查失败时记录期望和实际 PID，避免只有不明确的断言文字。

## 4. 设备回归结果

设备序列号 `3bb96edd`，内核完整版本：
`5.15.74-android13-8-00049-g8945ccdb2203-ab9500309`，KernelPatch `c00`。
测试目标是自建 `com.kclf.apptest`，普通非 root UID、untrusted_app 域、seccomp mode 2。

正式 probe：BTF=1、mm_off=1312、mmap_lock_off=104、pt_regs=336、thread_size=16384、
page=4096、cancel=match、wake_abi=btf、nofault=1，syscall hooks 70/70。
回退 probe：BTF=0、get_task_mm/proc_maps、nofault=0，仍能学习真实寄存器帧。

| 构建 / 后端 | 连续循环 | 通过断言 | 原始证据（父仓库 build/） |
| --- | --- | --- | --- |
| 正式 1.5.4 / manual | 10 | 236 | `kclf-app-de27b84fa2bb/results.txt` |
| 同一正式产物 / linker | 10 | 219 | `kclf-app-5b1f9918af7a/results.txt` |
| 独立无 BTF/nofault 产物 / manual | 3 | 178 | `kclf-app-406c40c1ed14/results.txt` |

数量为断言数，不是独立内核数。回退轮次有 12 个成功请求显式验证 `done=poll`。
三轮覆盖主线程、Java sleeper、Binder、故意修改 FPSIMD 的构造函数、四槽排队/取消、
重复/满表、缺失/截断 SO、完成未 reap/排队中/构造中进程退出、长构造函数、临时映射
回收、busy quiesce 和模块 reload。marker 核对准确 PID/TID，且检查构造函数地址实际
不再处于任何 VMA；没有把匿名映射按文件名查不到当成回收成功。

三轮修复后均未发现新增内核 BUG/WARNING/Oops/panic 或 App fatal signal/Java crash。
boot ID 保持 `17373dba-3c00-454f-bf6e-97670514877c`，SELinux 始终 Enforcing。
最终只读确认 `kpm num=0`、测试 App 无进程；测试 APK 和原始证据保留。

## 5. 产物与复现

| 产物 | SHA-256 |
| --- | --- |
| `kpms/kclf/kclf.kpm`，正式 1.5.4 | `4c8049293cf36be3397a314cc43e44bb0d11031d28e22d1238a454e570d9ccf7` |
| `build/kclf-fuxi-20261031/fallback/kclf.kpm`，测试专用 | `77f41241c7b30dd8e7c46a63bfd85160404852a84d0211347a54c1a720e814c3` |
| `build/kclf-fuxi-20261031/app/app.apk` | `f3dde6e73d7f993e673507b8954930577cef87c00352b2ca862712e52b4b54ba` |

集中证据目录为父仓库 `build/kclf-fuxi-20261031/`：初始差异、修复前模块和
PID 28279 日志、设备 libc/反汇编、修复前失败的主机检查、修复后主机/构建日志和
三轮控制台日志。原始设备目录包含完整前后 dmesg、main/crash 摘要与 maps。
安装失败原始目录为 `kclf-app-1b3855fe93bd`，BTI 失败为 `kclf-app-61a87f09e0fb`。

```sh
make -C kpms/kclf test
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

```powershell
./kpms/kclf/test/app/build.ps1 -OutDir ./build/kclf-fuxi-20261031/app
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial 3bb96edd `
  -Apk ./build/kclf-fuxi-20261031/app/app.apk -Backend manual -Repeat 10 -RootInstall
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial 3bb96edd `
  -Apk ./build/kclf-fuxi-20261031/app/app.apk -Backend linker -Repeat 10 -RootInstall
```

回退构建在独立源码副本使用 `CFLAGS="-DKCLF_TEST_NO_BTF -DKCLF_TEST_NO_NOFAULT"`，
并指定父仓库的绝对 KP_DIR。驱动额外传入 `-Kpm <回退产物> -ExpectPoll`。
它不替换正式模块，也不作为部署产物。

## 6. 保留的限制

- x16 仍被返回地址占用，通用 syscall 安全点启发式无法证明任意异步边界都可以丢弃它。
  需要受控、可协作的目标边界；本修复不等于完整透明恢复。
- SVE/SME、32 位目标被拒绝；GCS、MTE/标记栈和复杂信号重入未验收。特别是 GCS 启用
  时不能依赖此次 RET 尾段，其返回栈协议不在当前支持范围。
- manual 的 RELRO 仍在构造函数之后由 cleanup 收紧；依赖驻留、用户锁、TLS/异常展开
  等限制没有被返回指令修复消除。
- stock KernelPatch 不以模块 exit 返回值阻止释放代码，必须先释放驻留镜像并确认
  `quiesce=idle`；本轮没有强制卸载活动回调。
- 历史 Pixel 6 的 `dec_rlimit_ucounts` 告警属于另一设备/产物的未定根因记录；本轮
  无新增告警不能视为对那条历史问题的修复证明。
