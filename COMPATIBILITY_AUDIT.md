# KCLF 1.3.0：普通 app 注入、实现与兼容性审计

> 历史版本记录。当前 1.3.1 的无 BTF / 5.10 适配和本次测试见
> [COMPATIBILITY_1.3.1.md](COMPATIBILITY_1.3.1.md)。本文件的 6.1 测试不能当作新版已实测。

日期：2026-10-28。范围：`kpms/kclf` 模块源码、stock KernelPatch 宿主、Pixel 6
测试设备、自有 native 测试进程和一次性普通 app 测试 APK。

## 1. 结论

1.3.0 在 1.2.0 的 task_work + EL0 trampoline + linker 加载框架上，增加了对普通
64 位 Android 应用进程的支持，并删除了对 KernelPatch 宿主的所有修改。设备验证配置：

```text
Pixel 6 / Android 16 / kernel 6.1.134-android14-11 / ARM64 / 4K 页 / BTF
SELinux Enforcing / stock KernelPatch (kpver=c00)
```

最终模块为 63728 字节，SHA-256：

```text
b343a5d00d026c4c034930e4fbe09695f34588f46e3e76b1e1e274bfb8627bab
```

本设备上的 native 回归为 **59 项 PASS**，另外完成了普通 app 的主线程（epoll）、
binder 线程（ioctl）、睡眠线程（nanosleep）、`unload`、force-stop 和路径拒绝测试。
这些是当前设备/当前构建的结论，不外推到全部 5.x/6.x、厂商内核、32 位 app 或
任意自定义 seccomp 策略。

## 2. 1.3.0 的关键修改

| 问题 | 1.2.0 行为 | 1.3.0 修改 |
| --- | --- | --- |
| 普通 app 带 zygote seccomp | `TIF_SECCOMP` 直接 `-EOPNOTSUPP`，所有 app 被拒绝 | 不再因 seccomp 拒绝；标准 app 策略允许完成用的 `getpid`。跟踪/单步/模拟状态仍拒绝 |
| app 线程常有 pending signal | `TIF_SIGPENDING`/`TIF_NOTIFY_SIGNAL` 直接 `-EAGAIN`，大量真实 app 无法注入 | 不再预先拒绝；信号按内核 `arch_do_signal_or_restart` 的正常路径处理，trampoline 只改 pc/sp，FPSIMD 保存恢复不破坏信号帧 |
| app VMA 数量大 | 扫描上限 2048，2000+ VMA 的 app 可能扫不到高地址 linker/libc | 上限提高到 16384；找到 linker/libdl/libc 即提前结束 |
| 长时间持有目标 `mm` | `get_task_mm()` 引用保存到请求槽位释放 | 只保存 `mm` 指针做身份比较，取得后立即 `mmput_async`；用 pinned `struct pid` 防 PID 复用，完成 hook 再用 `pid_task` 核对任务身份 |
| 请求完成后目标被杀死 | 未 `reap` 时额外 `mm_users` 延后 `exit_mmap`，binder VMA 拆除被拖后，ActivityManager 收不到死亡，出现 `refused to die` | 不再持有 mm 引用；设备实测 force-stop 后进程正常消失，冷启动 142–144ms |
| app 线程阻塞在 futex/poll | 安全点白名单只有 28 个 syscall，futex 返回边界会失败 | 增加 `futex`、`poll`、`select`、`pselect6`、`rt_sigtimedwait`、`futex_waitv` 等阻塞/元数据 syscall；不加入 `openat`/`close` 等可能位于 allocator 临界区的调用 |
| 默认 `resume` 在 app 主线程上长期等待 | 只能看到 `armed` | `status` 超过 1 秒显示 `hint=blocked(use wake)`；取消后用 `wake` 重试 |
| stock 宿主忽略 exit 返回值 | 1.2.0 依赖未部署的 `kpm.exit_veto` 宿主补丁 | 删除宿主补丁；`kclf_exit` 先取消排队 work，再用可选 `msleep` 做 2 秒有限排空；无论是否排空都移除完成 hook，避免 stock 宿主释放代码后全局 `getpid` 指向已释放内存；仍在执行的 task_work/trampoline 无法被 stock 宿主保护，文档要求控制端先 `quiesce` |
| 目标 app 内路径/namespace | 未说明 | 明确要求 SO 位于 app 自己的 native library dir 等 linker namespace 允许路径；`/data/local/tmp` 对 `untrusted_app` 实测在 loader 阶段被拒绝 |

## 3. 实现摘要

1. `kclf_ctl0` 接收 superkey 保护的控制串，固定 4 个请求槽；每个目标线程一条活动
   请求。任务身份由 `find_get_pid` 得到一个 pinned `struct pid`，不长期持有 mm。
2. `work_prepare` 在目标上下文运行：用目标凭据打开 SO、校验 ELF；持 mmap 读锁
   快照 VMA 起止，释放锁后用 `access_process_vm` 读目标 ELF；解析
   `ld-android.so`/`libdl.so` 的 `__loader_dlopen` 或 `dlopen`。
3. 建立 `[RX 代码][RW 参数][PROT_NONE guard][8 页 RW 栈]` 的 11 页临时映射。
4. `work_hijack` 在返回用户态边界校验真实 `pt_regs`、任务/mm、32 位、SVE/SME 和
   跟踪状态，保存通用寄存器、SP、PC、PSTATE、`orig_x0`、`syscallno`，重定向到
   trampoline。
5. trampoline 保存 q0–q31/FPCR/FPSR，调用 linker；可选 `dlclose`；擦参数区后用
   `getpid(cookie)` 自陷。完成 hook 恢复寄存器、`args->ret` 和系统调用重启状态，
   再排队 cleanup。
6. cleanup 在目标上下文读 `dlerror`、`vm_munmap` 临时区间、检查返回值；失败保留
   状态并有限重试。

普通 app 的 `seccomp` 过滤器在 `invoke_syscall` 之前执行，所以完成自陷必须使用
目标策略允许的 syscall。标准 zygote app 策略允许 `getpid`；如果目标另外安装了
杀死/拒绝 `getpid` 的过滤器，本框架不支持，也不会绕过它。

## 4. 宿主框架修改已删除

1.3.0 不再包含 `patches/` 目录。原先的三处宿主修改已恢复为 stock：

```text
kernel/base/symbol.c
kernel/linux/include/linux/rcupdate.h
kernel/patch/module/module.c
```

同时删除了宿主生命周期测试 `checks/test_module_lifecycle.py`，以及能力字符串
`kpm.exit_veto`/`kpm.sleepable_ctl` 的依赖。根仓库现在只在 `kpms/kclf` 中保留
模块源码/测试修改；设备仍使用原来的 stock 宿主。

由此产生的边界必须明确：

- stock `unload_module` 在 exit 返回错误时仍会释放模块代码；
- 因此不能依赖模块的 `-EBUSY` 保护，必须在 `quiesce` 后等待所有请求和 cleanup
  结束，再执行 `kpm unload`；
- 模块 exit 只做有限的取消/等待（`msleep` 可用时最多约 2 秒），用于降低误操作
  风险，不是完整排空保证；exit 无论如何都会移除完成 hook，避免 stock 宿主释放
  代码后留下指向模块代码的全局 hook；
- 并发 load/ctl/unload 的宿主级竞态不在本模块可修复范围内。

## 5. 兼容性

| 内核/配置 | 策略 | 验证级别 |
| --- | --- | --- |
| 5.0–5.9 | 旧 bool `task_work_add` 语义；禁用 wake；需布局/符号前提 | 源码适配，未实测 |
| 5.10 | 默认 resume；保守禁用 wake | 源码适配，未实测 |
| 5.11–5.19 | resume / TWA_SIGNAL，按实际取消函数符号选择 ABI | 源码适配，未实测 |
| 6.1.134-android14-11 | BTF 布局、cancel_match、resume/wake、4K 页 | 本设备完整回归通过 |
| 其他 6.x | 相同能力检测；不按版本猜布局 | 未实测 |
| <5.0 或 ≥7.0 | 初始化拒绝 | 不在范围 |
| 16K/64K 页 | 从 TCR_EL1 取页粒度，映射/栈按页大小计算 | 代码路径存在，未实测 |
| 缺 BTF 且无可调用 mmap_read_lock/unlock | 拒绝加载 | 不以无锁遍历回退 |
| 32 位目标 | hijack 拒绝 | 仅静态/错误路径 |
| 已有 SVE/SME | hijack 拒绝 | 仅静态检查 |
| 普通 64 位 app + 标准 seccomp | 允许；主线程 epoll 用 wake，睡眠线程用 resume | 本设备实测 |
| 追踪/单步/模拟目标 | 拒绝 | 未实测 |
| 自定义 seccomp 杀死/拒绝 getpid | 不支持，可能无法完成 | 未实测，明确不承诺 |

运行时前提与 1.2.0 相同：KernelPatch 已识别的 current/线程栈、syscall wrapper、
任务/内存/文件访问符号、可用的 mmap 读锁和可验证的 `pt_regs` 布局。

## 6. 设备验证

native 回归证据：`build/kclf-test-cb80bd0627e9/`，59 项 PASS，覆盖：

- 默认 resume、wake、unload、seccomp 目标成功注入；
- 构造函数 marker、q0/q8/q31 与 FPCR/FPSR 恢复；
- 缺失/截断 ELF、非法命令、取消、4 槽容量、重复目标；
- 排队中退出、loader 中退出、暂态 11 页映射、guard 页、无 RWX、回收；
- 忙时 quiesce、reload、最终 unload、SELinux/boot_id 不变、无新增内核 BUG/WARNING。

普通 app 验证（`com.kclf.apptest`，`u:r:untrusted_app:s0`，`Seccomp: 2`，
`Seccomp_filters: 1`，32 个线程）：

```text
main thread (epoll_pwait) + wake:
#0 ... state=done stage=restore handle=... via=__loader_dlopen

binder:..._1 (ioctl) + wake:                      done
kclf-sleeper (nanosleep) + resume:                done
main thread + 5× pending SIGURG + wake:           done
main thread + wake,unload:                        unload=ok rc=0 by=__loader_dlclose
  /proc/<pid>/maps 中 libkclfapp_payload.so 消失，进程存活
force-stop 后不 reap 再冷启动:                     142–144 ms 完成，无 refused to die
/data/local/tmp payload + wake:                   stage=loader
                                                  dlopen failed ... Permission denied
默认 resume 注入 epoll 主线程:                    armed + hint=blocked(use wake)
```

app 测试期间的 `AndroidRuntime:E` 日志没有新崩溃；最终 app 进程在注入后继续运行。
app 测试源码和步骤见 [test/app/README.md](test/app/README.md)。

补充真实应用测试（2026-10-28）：已安装的 `me.bmax.apatch`（APatch，versionName 11107，
UID 10280，`untrusted_app`，`Seccomp: 2`，1 个过滤器，36 个线程）作为第二个目标。
只在其 native library dir 临时放入 `libkclf_apatch_payload.so`（标签
`apk_data_file`，755），测试后删除：

```text
main thread + wake:                    state=done ... via=__loader_dlopen
  /data/user/0/me.bmax.apatch/files/hit_<pid>  marker 写入成功
force-stop 后不 reap 再冷启动:          149 ms COLD 完成，无 refused to die
新进程 + wake,unload:                  unload=ok rc=0 by=__loader_dlclose
  /proc/<pid>/maps 中 libkclf_apatch_payload.so 消失，进程存活
```

测试结束时已删除 staged payload 和 marker、卸载 kclf、确认 APatch 进程仍在运行。

## 7. 仍然存在的边界

1. 只支持 64 位 ARM64；32 位 app 需要 compat `pt_regs` 和 AArch32 trampoline，未实现。
2. 标准 Android app seccomp 策略允许 `getpid`，但任意第三方过滤器不保证；完成
   syscall 被拒绝时请求可能停在 `running`，属于不支持场景。
3. 已有 SVE/SME、被 ptrace 跟踪、syscall 模拟、单步、uprobe 的线程仍拒绝。
4. payload 构造函数在 linker 锁内运行，不能再次 dlopen/dlsym，不能依赖 JNI/ART，
   不能长时间阻塞；固定 8 页备用栈不满足所有库。
5. 其他线程仍可并发修改地址空间/loader 状态；框架不冻结进程，不能保证任意锁或
   信号时序透明。
6. `dlclose` 不保证撤销构造函数副作用、NODELETE 或后台线程；存在 payload 线程时
   不能贸然 unload。
7. 临时映射、loader 记录、构造函数行为和耗时仍可被目标观察；不提供不可检测保证。
8. 目标退出/exec 后，旧 mm 的临时映射随最后使用者释放；`reap` 会报告 orphaned map，
   不会在另一个地址空间强行 munmap。
9. BTF/符号名不是完整内核 ABI 证明；裁剪符号、厂商结构重排、未来 6.x 扩展必须逐
   构建验证。
10. 没有 5.x、其他 6.x、16K/64K 页真机；没有验证 stock 宿主的并发 load/ctl/unload。
