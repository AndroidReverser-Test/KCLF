# KCLF 1.5.1 防检测改造：方案说明与实现进度

日期：2026-10-31（Asia/Shanghai）。对象：`kpms/kclf`（默认 manual 后端）。
状态：**实现与真机验收已完成**。源码树可编译；默认构建 `kpms/kclf/kclf.kpm` 的 SHA-256 为
`fa378fcdeece9725b61d10ae89c4a4133c43c52e5200d440fd1057c9fc4450b8`。`test/selfcheck_v15`
full 套件 45/45 用例 `detections=0`、`done=syscall`，构造函数/析构函数均执行、目标存活；
另用 `KCLF_TEST_NO_TOKEN_HOOK` 构建单独验证了控制器 poll 路径（`done=poll`）。证据目录见
附录 A，逐项完成状态见第 9 节。

---

## 1. 结论摘要

1. `test/selfcheck_v15` 记录的稳定检测链**已被定位并复现**：框架每次注入后都会用真实 libc
   `usleep()`/`open()` 发一个“完成系统调用”，检测器在自己的 seccomp `SECCOMP_RET_TRAP`
   处理器里从保存的 `x29` 沿 libc 帧拿到指向跳板代码页的返回地址，再校验固定的 72 字节调用
   结构、`[sp,#0x80]` 里的私有页指针、x6/x7 cookie 与 libc 函数地址。基线真机复现：每次注入
   2 个事件（`nr=0x65`、`nr=0x38`）。
2. 因此改造的核心是**让框架的完成路径不再产生任何系统调用、信号、库函数调用和可识别的代码/
   栈痕迹**：完成改为“EL0 自行恢复整份寄存器 + 写入每请求随机 token + 直接 `br` 回被中断 PC”，
   token 由目标线程之后的普通系统调用入口观察，或在控制器 `status`/`reap`/`quiesce` 时由目标
   线程上排队的 poll 回调观察。整个完成路径**不调用任何库函数、不执行 `svc`、不产生故障**。
3. 最终 1.5.1 构建的真机结果：`test/selfcheck_v15 --suite full --rounds 5` 的 45 个用例
   **detections=0**（1.5.0 基线为 45/45 检出、每例 2 个完成 syscall 事件），45/45
   `done=syscall`，构造函数/析构函数都执行，目标进程存活，`quiesce=idle`，KPM 正常卸载
   （`kpm num=0`）。证据：`build/kclf-selfcheck-bd20c95e8a63/`。另用
   `KCLF_TEST_NO_TOKEN_HOOK` 构建跑 pilot，得到 `done=poll`，证明控制器轮询路径可独立收尾：
   `build/kclf-selfcheck-d1e2ffc81c6c/`。
4. 期间还实现并真机验证过一版“写入未缺页触发页 → `handle_mm_fault` 钩子改写 pt_regs”的
   完成方案：在 shell/native 目标上完全成功（`done=fault`），但在 `untrusted_app` 的普通 App
   **观察不到它的用户态缺页**，且把钩子换到 `do_page_fault` 会直接把设备打崩。该方案已放弃，
   理由与实验记录见第 4.1 节。这一结论也说明：**不要再在热路径上安装 inline hook**。
5. **事故与恢复**：`kpms/kclf/kclf.c` 在 2026-10-31 00:50 被一个 Python 批量替换脚本以
   `open(..., 'w')` 打开后因为 `newline` 参数非法抛异常，文件被截断为 0 字节。`kpms/kclf` 本身
   是一个独立 git 仓库（HEAD `ad1a590`“继续抹去特征”），已用 `git checkout -- kclf.c` 完整恢复
   （49,504 字节，即 1.5.0 原文件）。其余源文件的改动与全部真机证据未受影响。1.5.1 的完成段全文
   保存在 `build/kclf-harden/restore/kclf_c_completion_block.c`，恢复后的逐段改写清单见 6.2。

---

## 2. 改造目标

用户要求：**分析并去除框架源码中“能被被注入的普通 App 稳定检测出来”的检测点，并修改源码实现。**

这里的“普通 App”指被注入进程自身（non-debuggable、`dumpable=0`、`CapEff=0`、`untrusted_app`、
继承 zygote seccomp），它不要求 root、不需要 ptrace、不跨 UID 读别的进程。它可以：
安装/追加自己的 seccomp 过滤器、注册 SIGSYS/SIGSEGV 处理器、用 `process_vm_readv(self)` 读自己
的内存、读 `/proc/self/maps`、任意时刻扫描自己的地址空间、拉高精度定时器。

目标不是“不可检测”（本框架从未承诺），而是**消除可稳定复现、且能唯一归因到 KCLF 的事件型
检测点**，并把残余可观测面如实记录。

---

## 3. 现状：selfcheck_v15 记录的检测链（基线）

真机基线（原始 1.5.0 源码构建，KPM SHA-256
`f272f9cc5bd83a17ceec8a2de67d2105409af172269a35c0ef7a8fe87165e106`，
证据 `build/kclf-selfcheck-4e292dcbedf1/`）：

| 项 | 结果 |
| --- | --- |
| baselines（observe/denyexec） | 1800/1800 合法调用被观察，detections=0 |
| 注入用例 | detections=2（`nr=0x65` nanosleep、`nr=0x38` openat） |
| 构造函数先于检测 | 是 |
| 目标存活 / 框架 `state=done` | 是 / 是 |

检测实现见 `test/selfcheck_v15/probe.c` 的 `completion_match()`：

1. 自检线程装 seccomp 过滤器，对 `nanosleep`/`openat` 返回 `SECCOMP_RET_TRAP`（只放行自检
   网关 PC `audit_after_svc` 上的调用）。
2. 注入后框架执行 payload，随后**必然**经 libc 发完成调用：
   `usleep(0)` → libc 内 `nanosleep`（`svc #101`），`open(random)` → libc 内 `__openat`（`svc #56`）。
3. SIGSYS 现场：`pc/lr` 在 libc，`x6==x7==cookie`。从 `x29`（libc 帧记录）读 `[fp+8]` 得到
   **指向跳板代码页的返回地址**。
4. 读 `ret-72` 起的 18 条指令：`ldr x9,[sp,#0x80]` + 3 条变偏移 `ldr`（arg0/fn/cookie）+
   **固定 14 条**（`mov x7,x6`、`mov x1..x5,xzr`、`mov x10..x15,xzr`、`mov x9,xzr`、`blr x16`），
   即末尾 56 字节完全固定。
5. 由 libc 帧大小推出调用者 SP，读 `[caller_sp+0x80]` 得到私有页基址；解码三条 `ldr` 的偏移，
   交叉校验 cookie、真实 libc `usleep`/`open` 入口与调用参数。

这条链之所以“稳定”：完成调用是**框架自己**在 payload 之后无条件做的；事件现场由内核 seccomp
产生，普通 App 只要肯装过滤器就一定能看到。除这条链外，README 还列出的方案 B（已知镜像全段
内容比对）、方案 C（linker 记录）与“匿名 RX / 异常 syscall 来源 / 卡顿”等单项，都**不能单独
稳定归因**。

---

## 4. 方案选型与实验记录

### 4.1 方案 A：缺页触发 + `handle_mm_fault` 钩子（已实现、已真机验证、**已放弃**）

思路：生成程序恢复寄存器后，向映射里**故意留空未缺页**的一页写一次；KPM 在
`handle_mm_fault` 上装 inline hook，命中 `(task, mm, RUNNING, trigger 地址)` 时用 hijack 时保存
的寄存器文件改写故障帧的 pt_regs，并 `skip_origin` 丢弃这次缺页；于是目标“无系统调用、无信号、
无库调用”地回到原 PC，且全部 31 个通用寄存器（含 x16）都精确恢复。

真实设备实验（Android 12 / 5.10.66 / 4K / KP 1.1.58）：

| 实验 | 结果 |
| --- | --- |
| 独立 de-risk KPM：hook `handle_mm_fault`，把故障线程改跳到 landing 函数 | 成功：`matched=1 skipped=1`，目标继续运行 |
| native shell 目标（`/data/local/tmp/kclf_target`）注入 | 成功：`done=fault`，`trigger_diag faults=1 hit=1` |
| **普通 App**（selfcheck APK，untrusted_app）注入 | **失败**：`done=el0`，`trigger_diag faults=0`，`pid_diag el0_write_faults=0` |
| 把 trigger 页预填并 `mprotect(PROT_READ)`，强制产生权限故障 | App 收到致命信号并退出，但钩子**仍未观察**到该缺页 |
| 在 `do_page_fault` 上装 `hook_wrap3` | **设备内核 panic**（pstore：`el1_undef` → 模块地址 `do_undefinstr`，进程 `perfetto_hprof_`） |

结论：
- 在这台设备的这套内核/KP 组合上，**普通 App 的用户态缺页没有走到 KPM inline hook 所 patch 的
  `handle_mm_fault`**（native/shell 进程能走到）；机理未完全定论，但结果可复现（App 侧 10+ 次
  全部如此），不能作为生产主路径。
- 在热路径（缺页、异常入口）上装 inline hook 的**风险不可接受**：`do_page_fault` 一次即崩。
- 已把该方案的全部代码（trigger 页、fault hook、诊断计数器）从源码中移除。

### 4.2 方案 B：未分配系统寄存器陷阱 + `do_sysinstr` 钩子（评估后**不采用**）

思路：生成程序执行一条未分配 `MRS`（EC=0x18 陷入 EL1），hook `do_sysinstr` 消费它并改写 pt_regs，
可做到“无 syscall、无信号、全寄存器精确恢复、立即完成”。

不采用的原因：**如果钩子不生效，目标会收到 SIGILL 直接死亡**；而 4.1 已经证明“inline hook 对
普通 App 是否生效”在本环境不可靠。用目标进程的生命去赌一个未验证的热路径钩子不可接受。

### 4.3 采用方案 C：纯 EL0 完成 + 两个“只读观察点”

- 完成路径不含任何系统调用/库调用/故障；
- 内核侧只在**普通系统调用入口**（已有、已被证明对 App 生效的 per-syscall 观察点）或**控制器
  轮询时排队到目标线程的 task_work** 里读私有页 token；
- 不新增任何 inline hook，不触碰缺页/异常热路径。

代价（如实记录）：
1. 完成由 EL0 自己 `br` 回原 PC，因此**无法恢复 x16/IP0**（31 个 GPR 里必须牺牲一个作为分支
   寄存器）。bionic/ART 把 x16/x17 当 scratch（IP0/IP1），跨 syscall 不保存；1.5.0 的 EL0 bail
   兜底路径本来就有同样限制，现在它成为唯一路径。
2. 清理（解除临时映射）发生在“目标线程下一次进入被观察的系统调用”或“控制器下一次
   `status`/`reap`/`quiesce`”时，不再像 1.5.0 那样在完成调用现场立刻发生。窗口因此变长；通过
   扩大观察系统调用集合（见 5.3）和控制器轮询把窗口压到“通常一次 syscall 之内”。
3. 匿名 RX 代码页、私有状态页、payload 自身内容/副作用等**静态残余**依旧存在（1.5.0 文档已
   列为残余），本方案没有、也无法承诺消除它们。

---

## 5. 最终方案（1.5.1）细节

### 5.1 生成程序（`kclf_codegen.c`）

- 每个请求仍随机生成 AArch64 程序：随机入口偏移、随机角色寄存器（x19–x23）、随机 FPSIMD
  保存/恢复配对、随机填充指令、随机 ABI 页布局。
- **生成页内没有任何 `svc`、没有任何对库函数的调用、没有任何故意缺页的写**。
- 尾部顺序（固定语义、随机化细节）：
  1. 把 handle/errptr/rc 从 ABI 页复制到私有页；
  2. 整页擦除 ABI 页；
  3. 从私有页恢复 FPSIMD（q0–q31、FPCR/FPSR）；
  4. 恢复 SP、NZCV；
  5. 把私有页基址移入 x10，随机顺序恢复除 x10/x16 外的全部 GPR；
  6. 写完成 token：`ldr x16,[x10,#donetok]; str x16,[x10,#done]`；
  7. 兜底返回：`ldr x16,[x10,#pc]; ldr x10,[x10,#x10]; br x16`。
- 不再有：完成调用循环、cookie、`KCLF_STACK_SLOT`、`mprotfn`/RELRO 内联调用、`KCLFBAIL` 标记。

### 5.2 私有页布局（`kclf_codegen.h`）

`struct kclf_priv_layout` 现在只有 9 个字段，每个字段独立随机偏移：
`saved`(34×u64)、`qregs`(512B)、`fpcr`、`fpsr`、`done`、`donetok`、`handle`、`errptr`、`rc`、`end`。
已删除：`nrkey`、`nrcnt`、`nrs[]`、`cookie`、`mprotfn`、`complfn[]`、`complarg0[]`、`path`、
`KCLF_COMPL_MAX`、`KCLF_COMPL_PATH`、`KCLF_STACK_SLOT`。

### 5.3 完成观察（`kclf.c`）

`kclf_watch_pool[]`（`kclf_exec.c`，现 70 项）覆盖 App 线程“下一步最可能做的系统调用”：元数据
（getpid/gettid/getuid/getcwd/uname/信号类）、内存（brk/mmap/munmap/mprotect/madvise/getrandom/
memfd_create）、文件与 fd（openat/close/read/write/readv/writev/pread64/pwrite64/lseek/fstat/
newfstatat/getdents64/fsync/unlinkat/dup/fcntl/pipe2）、等待与调度（epoll_pwait/epoll_pwait2/
epoll_create1/epoll_ctl/pselect6/ppoll/futex/futex_waitv/nanosleep/clock_gettime/clock_nanosleep/
sched_yield/wait4）、ioctl/binder/socket 类、exit/exit_group。

观察点 1（`kclf_token_before`）：per-syscall before 钩子，**只读**私有页 token；命中则
`kclf_complete(r, KCLF_VIA_SYSCALL, force_drain=1)`。不设 `skip_origin`、不改返回值、不改寄存器。
安装时对内核不存在的 syscall 号**跳过而不整体失败**（`KCLF_WATCH_MAX 96` 位图记录已装项）。

观察点 2（`kclf_work_poll`）：控制器在 `status`/`reap`/`quiesce` 里调用 `kclf_poll_running()`，
对每个 RUNNING 请求在目标线程上排一个 `work_poll`（`TWA_RESUME`）；回调在目标上下文运行，读
token，命中则 `kclf_complete(r, KCLF_VIA_POLL, 0)`。这样即使目标线程不再发被观察的系统调用，
控制器一次轮询也能收尾。请求结构里的 `poll_queued` 保证同一个 `callback_head` 在回调真正运行
前不会被控制器重复入队（轮询频率高于目标返回用户态的频率时也不会破坏 task_work 链表）。

`kclf_complete()`：读结果 → `stage=restore` → `state=DONE` → 递减 `kclf_loading_num` → 在目标
线程排 `work_cleanup`（syscall 路径用 `TWA_SIGNAL` 强制排水，poll 路径用 `TWA_RESUME`）。

`work_cleanup`：清 `completing` → 在目标上下文读结果（幂等）→ **应用延迟 RELRO** →
`kclf_exec_finish()`（manual_finish + munmap）→ `finished=1`；munmap 失败最多重试 8 次。

### 5.4 RELRO 移到内核侧

`kclf_manual.c::protect_image()` 不再在 EL0 里做 RELRO：它现在只做段保护（RX/RW），并把每个
`PT_GNU_RELRO` 区间记录到 `r->relro[][2]`（上限 `KCLF_MAX_RELRO 8`，超出报 `-E2BIG`）。
`kclf_apply_relro()` 在完成清理回调里用 `raw_syscall3(__NR_mprotect, ..., PROT_READ)` 应用。
原因：IFUNC resolver 必须在 EL0 先写结果，而 RELRO 又必须在一个确定点生效；把它移到内核后，
生成程序里连 `mprotect` 的库调用都不需要了。语义变化：RELRO 现在在构造函数之后生效（构造函数
运行期间 RELRO 页仍可写），这一点要在文档里写明；对 payload 只会更宽松，不会更严。

`kclf_param.h` 删除 `KCLF_P_PROTV`/`KCLF_P_PROTN`；`kclf_manual_params()` 不再导出保护区间。

### 5.5 控制面/状态机

- `struct kclf_req`：删除 `cookie`、`compl_fn[]`、`compl_arg0[]`、`compl_nrs[]`、`compl_count`、
  `mprot_fn`、`compl_obs_pc/lr/sp`、`bail_token`、`trigger_addr`、`code_len`、`protect_count`；
  新增 `done_token`、`completion_via`（0/1=syscall/2=poll）、`relro_count`、`relro_done`、
  `relro[8][2]`、`work_poll`。
- `status` 的 DONE 行：`done=syscall|poll`、`stack=task|transient/状态码`，不再打印
  `svc/lr/sp`、`compl=`、`trigger=`。
- `probe`：`completion=el0 watch=on|off syscall_wrapper=... pool=... tokens=...`。
- 注入只要求 `kclf_hook_ok`（观察点 1）。没有它时 `probe` 会提示只剩控制器轮询路径；在没有
  观察钩子的内核上，`kclf_regs_size` 只能来自 BTF，否则无法定位 pt_regs。
- 版本号：`KCLF_VER "1.5.1"`（已改）。

### 5.6 已消除的检测点（相对 1.5.0）

| 1.5.0 的检测证据 | 1.5.1 状态 |
| --- | --- |
| 完成系统调用（`nanosleep`/`openat`）本身 | 不存在：框架不再发任何系统调用 |
| libc 帧里指向跳板代码页的返回地址 | 不存在：没有任何从代码页发出的调用 |
| 固定 72 字节完成结构（末 56 字节固定） | 已从生成器中删除 |
| `[sp,#0x80]` 里的私有页指针 | 已删除（不再需要栈槽保存私有页） |
| x6/x7 cookie 与私有页 cookie 交叉校验 | 两者都已删除 |
| 完成现场的 libc 函数地址/参数校验 | 不存在（无调用现场） |

### 5.7 残余可观测面（必须如实写进 README/DETECTION_POINTS）

1. 短驻留的**匿名 RX 代码页** + 匿名 RW 私有页/ABI 页；窗口 = 到目标线程下一次被观察的系统
   调用或控制器下一次轮询为止（1.5.0 是完成调用现场立刻回收）。
2. **payload 自身的 syscall 现场**：构造函数/析构函数的 `blr` 返回地址在跳板代码页上，
   检测器若在 payload 运行期间的任意 syscall 里扫栈，仍可能看到匿名 RX 指针（这是 EL0 跳板
   方案的固有属性，与本方案无关）。
3. 私有页在完成前保存整份寄存器/FPSIMD；完成 token 是随机 64 位值。
4. payload 内容（方案 B）、linker 记录（方案 C，仅 `,linker`）、构造函数副作用与时序。
5. **x16/IP0 在完成后不恢复**（见 4.3 代价 1）。
6. 若宿主把 syscall hook 回调按 UID 门控（新版 KP 的 `su_syscall_gate`），观察点 1 对普通 App
   不触发，只能依赖控制器轮询；此时窗口更长。

---

## 6. 实现进度

### 6.1 逐文件状态

| 文件 | 状态 | 说明 |
| --- | --- | --- |
| `kclf_param.h` | 完成 | 删除 `KCLF_P_PROTV/PROTN`；头注释改为“完成不发系统调用” |
| `kclf_internal.h` | 完成 | `KCLF_VER 1.5.1`；`KCLF_MAX_RELRO`；`struct kclf_req` 新字段；删除 trigger/diag；新增 `work_poll`、`kclf_apply_relro`；删除 `kclf_restore_saved`/`kclf_diag_*` |
| `kclf_manual.c` | 完成 | RELRO 延迟到内核（记录区间，`-E2BIG` 上限）；删除 `c->protections`、PROTV/PROTN 导出；`protect_count` 不再使用 |
| `kclf_exec.c` | 完成 | 3/4 块布局（无 trigger 页）；删除 libc completion resolver、`kclf_export_completion`、`kclf_pick_completion`、`kclf_restore_saved`、全部 diag；新增 `kclf_export_private`、`kclf_apply_relro`；`kclf_watch_pool` 扩到 70 项 |
| `kclf_codegen.h` | 完成 | 新私有页布局；`kclf_prog_build()` 已删除 `trigger_addr` |
| `kclf_codegen.c` | 完成 | 完成循环/RELRO/cookie/栈槽/trigger 写已删除；尾部在 token 写完后直接 `ldr pc / ldr x10 / br x16` |
| `kclf.c` | 完成 | 已按 6.2 清单改写为 1.5.1：完成观察、poll、cleanup RELRO、status/probe/init/exit |
| `test/test_codegen.c` | 完成 | 删除 trigger 常量与 `encodes_address()` 断言；主机测试通过 |
| `test/test_observability_signature.c` | 完成 | 删除 trigger 实参；30,000 样本 PASS |
| `README.md` / `DETECTION_POINTS.md` / `test/selfcheck_v15/README.md` | 完成 | 已按 5.6/5.7 更新并追加 1.5.1 真机结果 |
| `HARDENING_PLAN_20261031.md` | 完成 | 本文档，记录最终状态与证据 |

当前 `make` 通过（`aarch64-linux-gnu-gcc 13.3` / `-Werror`），无遗留 trigger 字段或
1.5.0 completion 符号引用。

### 6.2 事故与恢复：`kclf.c` 曾被截断为 0 字节（已恢复）

- 时间：2026-10-31 00:50（本机时间）。
- 原因：一个批量文本替换脚本用 `open(path, 'w', encoding='utf-8', newline='\r\n')` 打开
  `kpms/kclf/kclf.c`；Python 在**打开并截断文件之后**才校验 `newline` 参数，参数被写成字面量
  `\\r\\n` 导致 `ValueError: illegal newline value`，异常退出时文件已经被清空。
- 恢复：`kpms/kclf` 是**独立 git 仓库**（HEAD `ad1a590`“继续抹去特征”），执行
  `git -C kpms/kclf checkout -- kclf.c` 即完整恢复：49,504 字节，`kclf.c` 在该仓库内是跟踪文件。
  已核对恢复后的文件包含 1.5.0 最终完成协议（`regs->regs[6]/[7]` cookie、`kclf_compl_pool`）。
- 现状：`kclf.c` 已按下面的清单改写为 1.5.1 并通过真机验收；恢复素材保留在
  `build/kclf-harden/restore/`，不再参与构建。
- 改写素材：`build/kclf-harden/restore/kclf_c_completion_block.c`（新完成段全文，含
  `kclf_read_results`/`kclf_learn_regs_size`/`kclf_complete`/`kclf_token_before`/
  `kclf_work_poll_body`/`kclf_poll_running`/`kclf_hook_install`/`kclf_hook_remove`、
  `KCLF_WATCH_MAX` 与“装不上就跳过”的逻辑）。
- 待执行的逐段改写清单（对照已恢复的 1.5.0 文件）：
  1. 文件头注释（第 1–27 行）：把“完成 = syscall + cookie”的段落改成“完成 = EL0 恢复 + token，
     由普通 syscall 入口或控制器 poll 观察”。
  2. `#include` 之后：无需新增头文件（`hook.h`/`linux/sched.h` 已由 `kclf_internal.h` 带入）。
  3. 全局变量区：删除 `static int kclf_hook_ok;` 原声明与 `cookie` 相关；保留
     `kclf_next_id/kclf_control_busy` 等。
  4. `kclf_slot_reset()`：追加 `r->work_poll.func = kclf_work_poll;`。
  5. 在三个 `kclf_work_*` 前置声明后追加 `static void kclf_work_poll(struct callback_head *head);`。
  6. `kclf_work_cleanup_body()`：重写为
     “清 `completing` → 同 mm 且有 map 时：DONE 则 `kclf_read_results(r)` →
     `kclf_apply_relro(r)` → `kclf_exec_finish(r,1)`（失败重排最多 8 次）→ `finished=!map_addr`”，
     并保留 `st==RUNNING` 与 `st==DONE && !handle` 两个失败分支。
  7. `KCLF_WORK_WRAPPER(...)` 追加 `KCLF_WORK_WRAPPER(poll)`。
  8. 整段“completion trap”（原 `kclf_completion_bailed`/`kclf_completion_before`/
     `kclf_completion_after`/`kclf_hook_install`/`kclf_hook_remove`）替换为
     `build/kclf-harden/restore/kclf_c_completion_block.c` 的全文。
  9. `kclf_status_line()`：DONE 分支用 `done=syscall|poll`，删除 `svc/lr/sp`、`compl=`、`trigger=`。
  10. `kclf_cmd_status()`：开头 `kclf_poll_running();`；脚注改 `watch=on|off`。
  11. `kclf_cmd_reap()`：开头 `kclf_poll_running();`。
  12. `kclf_cmd_quiesce()`：在 `kclf_manual_reap()` 前加 `kclf_poll_running();`。
  13. `kclf_cmd_inject()`：删除 `cookie = get_random_u64(); r->cookie = ...`；完成后端检查保持
      `if (!kclf_hook_ok)`。
  14. `kclf_ctl0()` 的 `probe` 分支：输出
      `completion=el0 watch=... syscall_wrapper=%d pool=%d tokens=%llu`。
  15. `kclf_init()`：删除 fault hook 安装；只调用 `kclf_hook_install()`，失败/为空时用
      `logkw` 说明“只剩控制器轮询”，不再报错返回。
  16. `kclf_exit()`：只调用 `kclf_hook_remove()`。

### 6.3 已完成的小改动

1. `kclf_codegen.h`：`kclf_prog_build()` 去掉 `u64 trigger_addr` 参数；注释去掉“trigger page”。
2. `kclf_codegen.c`：
   - 删除 `kce_mov64(&c, 16, trigger_addr);` 与其后的 `#ifdef KCLF_TEST_TRIGGER_READ ... #endif`
     和 `kce_str_x(31, 16, 0)`；
   - 保留 token 写（步骤 6），其后直接兜底 `ldr x16,[x10,#pc]; ldr x10,[x10,#x10]; br x16`；
   - 头注释去掉“trigger page/最终 store 是完成事件”；并明确 x16/IP0 是唯一不恢复的 GPR。
3. `test/test_codegen.c`：删除 `trigger` 常量与 `encodes_address()` 断言（其余不变）。
4. `test/test_observability_signature.c`：`kclf_prog_build()` 去掉 trigger 实参（负样本/旧识别器
   检查保留）。
5. 主机测试重跑（见 7.1）：全部通过。

---

## 7. 验证计划与已有证据

### 7.1 主机侧（WSL，GCC 13.3）

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -DKCLF_CODEGEN_HOST -fsanitize=address,undefined -g \
  kpms/kclf/test/test_observability_signature.c kpms/kclf/kclf_codegen.c -o /tmp/kclf-sig && /tmp/kclf-sig
gcc -std=c11 -O2 -Wall -Wextra -Werror -DKCLF_CODEGEN_HOST \
  kpms/kclf/test/test_codegen.c kpms/kclf/kclf_codegen.c -o /tmp/kclf-cg && (cd /tmp && /tmp/kclf-cg 4096)
python3 kpms/kclf/test/test_helpers.py   # 以及 README 列出的其它主机侧 python 测试
```

最终（无 trigger）结果：

```text
PASS generated=30000 random_pages=3000 in_page_svc=0 old_143_matches=0 old_150_matches=0
seed=1..8 entry=0x10..0x60 length=724..768 svc=0
ok
```

即：30,000 个随机生成程序（4K/16K/64K 页各 10,000）内 **0 条 `svc`**、**0 个 1.4.3 尾段命中**、
**0 个 1.5.0 完成 stub 命中**，3,000 个随机反例页 0 命中；`test_codegen.c` 的 8 个 seed
全部通过。`test_helpers.py`、`test_maps.py`、`test_compat.py`、`test_manual_elf.py`、
`test_provider.py` 全部 PASS。KPM 以 `aarch64-linux-gnu-gcc 13.3` + `-Werror` 构建通过。

### 7.2 真机自检（关键验收）

```powershell
$env:KCLF_SUPERKEY = 'Test6666'
python kpms/kclf/test/selfcheck_v15/run.py --serial LVLNINYXKR4L6HAE --suite full --rounds 5
```

最终版（KPM SHA `fa378fcdeece9725b61d10ae89c4a4133c43c52e5200d440fd1057c9fc4450b8`）：

| 项 | 结果 |
| --- | --- |
| full 套件 | 45/45 用例，`detections=0`（45 个用例各 1800 次合法调用均被过滤器观察） |
| 完成路径 | 45/45 `done=syscall`，无 `pending=`、无 `state=failed` |
| payload | 构造函数 45/45 执行，unload 用例析构函数全部执行 |
| 目标进程 | 45/45 存活 |
| 清理 | `quiesce=idle`、`final_kpm_num=0`、`module_left_loaded=false` |

probe：`completion=el0 watch=on installed=70/70 syscall_wrapper=1 tokens=...`；
典型 status：`state=done stage=restore handle=1 done=syscall stack=task/6 ... unload=ok rc=0`。
证据：`build/kclf-selfcheck-bd20c95e8a63/`。

poll 路径（`CFLAGS=-DKCLF_TEST_NO_TOKEN_HOOK` 构建）：pilot 用例
`constructor_ran=true`、`finalizer_ran=true`、`framework_done=true`、
status `done=poll`、`quiesce=idle`、`final_kpm_num=0`。证据：
`build/kclf-selfcheck-d1e2ffc81c6c/`，KPM SHA `5ea0faf7…`。

最终版验收三项均满足：detections 全 0；`done=syscall|poll` 两条路径均实测；`quiesce=idle`、
`kpm num=0`。

### 7.3 其他必须回归的夹具

- `test/observability/run.py --rounds 2`：**通过**。旧方法 A/B、ELF 页级扫描、
  `KCLFBAIL` 扫描、syscall guard、`keepelf` 均符合预期；证据
  `build/kclf-observability-306d19a346c4/`。夹具的 1.5.0 断言（`hook=libc`、
  `pool=9`、`compl=`、完成候选 101/56）已按 1.5.1 改成 `completion=el0`、`done=`。
- `test/manual-device-test.py --app`（native + 普通 App、manual 后端）：**通过**。
  覆盖注入/驻留/重复引用/release/unload/RELRO/FPSIMD/seccomp/IFUNC 拒绝、失败回滚、
  目标退出回收、取消、quiesce 语义和普通 App 主线程；证据
  `build/kclf-manual-a7529dd12051/`。
- `test/device-test.ps1`（linker 后端历史回归）：未重跑；本轮 manual 回归中的
  “explicit legacy linker backend still works”已覆盖 linker 基本路径，但不等于
  完整历史套件。
- 可选：`test/package-test.py` 对真实 App 做 linker 后端标记测试，未在本轮执行。

### 7.4 需要新增/更新的断言

- 自检夹具：新增“注入后目标线程无被 trap 的完成系统调用”的显式检查（现在 detections=0 已能
  体现，但建议在 README 写明“0 = 无完成事件”）。
- 建议给 `probe` 增加 `watch_installed=<n>`（当前只有 `pool=`），便于确认 70 项里实际装上了多少。

---

## 8. 风险与限制

1. **x16/IP0 不恢复**：EL0 完成路径的固有限制；1.5.0 的兜底路径同源。需要在 README 明写。
2. **回收窗口变长**：映射在目标线程下一次被观察 syscall 或控制器轮询前一直存在；对“扫描匿名
   RX 页”的检测器更有利。缓解：70 项观察集合 + 控制器轮询；无法根治。
3. **syscall hook 被宿主门控时**：只剩控制器轮询路径（`probe` 会显示 `watch=off` 或装 0 项）；
   没有 BTF 时无法定位 pt_regs，注入会明确拒绝。
4. **RELRO 时序变化**：构造函数执行期间 RELRO 页可写（仅影响 payload 安全性，不影响 App）。
5. **BTI 落点未全面验收**：EL0 完成用 `br x16` 返回被中断 PC；BTI 强制设备上该 PC 必须是
   合法 landing pad。当前设备未触发，但未在 BTI 强制设备上验证。
6. **本结论的边界**：只覆盖一台 Android 12 / 5.10.66 / 4K 设备、KP 1.1.58、manual 后端为主；
   16/64 KiB 页、其它 bionic、真实 App 的 seccomp 策略、并发 mmap 等都还没有在 1.5.1 上复测。
   **不得据此宣称“不可检测”**。

---

## 9. 完成清单

1. [x] 恢复 `kclf.c`（`git -C kpms/kclf checkout -- kclf.c`，49,504 B）。
2. [x] 按 6.2 清单把 `kclf.c` 改写为 1.5.1（完成段、观察点、poll、cleanup RELRO、
   status/probe/init/exit 全部完成）。
3. [x] 收尾 `kclf_codegen.h/.c`（去掉 trigger），按 6.3 修改两个主机测试。
4. [x] 主机测试全绿（7.1）。
5. [x] 构建 KPM，真机 full selfcheck 45/45 detections=0（7.2）。
6. [x] 用 `KCLF_TEST_NO_TOKEN_HOOK` 构建验证 controller poll 路径（`done=poll`）。
7. [x] `test/observability/run.py`、`manual-device-test.py --app` 回归通过；
   `device-test.ps1` 未重跑（见 7.3）。
8. [x] 更新 `README.md`、新增 `DETECTION_POINTS_20261031.md`、更新
   `test/selfcheck_v15/README.md`：已写明消除的检测链、新协议、x16/回收窗口代价与残余面。
9. [x] 记录最终 KPM SHA-256、设备指纹与证据目录（附录 A/B）。
10. [ ] 在 `kpms/kclf` 独立 git 仓库提交（本轮未提交，等待用户确认）。

---

## 附录 A：证据目录

| 目录 | 内容 |
| --- | --- |
| `build/kclf-selfcheck-4e292dcbedf1/` | 1.5.0 基线：detections=2（101/56），KPM SHA `f272f9cc…` |
| `build/kclf-selfcheck-bd20c95e8a63/` | **1.5.1 最终 full**：45/45 detections=0、45/45 `done=syscall`、`quiesce=idle`、`kpm num=0`，KPM SHA `fa378f…` |
| `build/kclf-selfcheck-d1e2ffc81c6c/` | `KCLF_TEST_NO_TOKEN_HOOK` poll 路径：`done=poll`、构造/析构执行、`quiesce=idle` |
| `build/kclf-observability-306d19a346c4/` | 旧检测规则回归通过（旧方法 A/B、ELF 头扫描、guard、keepelf） |
| `build/kclf-manual-a7529dd12051/` | native + 普通 App manual 回归通过（RELRO/FPSIMD/seccomp/IFUNC 拒绝/卸载） |
| `build/kclf-selfcheck-c35449821dde/` | 中间改造版：detections=0，`done=el0`，`quiesce=idle`，`kpm num=0` |
| `build/kclf-harden/faulthook/` | 缺页触发 de-risk KPM 与 native 测试（证明 `handle_mm_fault` + pt_regs 改写可行） |
| `build/kclf-harden/restore/kclf_c_completion_block.c` | 恢复 `kclf.c` 用的新完成段全文 |
| `build/kclf-harden/*.ps1` | 真机实验脚本（app/native 探针、affinity、smaps、maps） |

## 附录 B：环境

- 设备：Android 12；`Linux 5.10.66-android12-9-00001-gd262b276948e-ab8291727`；MT6895Z；arm64；4 KiB 页；SELinux Enforcing。
- KernelPatch：kpatch 1.1.58（`/data/local/tmp/kpatch`，2025-08-12），superkey `Test6666`。
  `probe`：`btf=0`、`pt_regs=ok size=336`、`thread_size=16384`、
  `completion=el0 watch=on installed=70/70 syscall_wrapper=1`。
  该 KP 早于上游 `2dc68c2 "syscall: one gated dispatcher hook"`，因此 per-syscall 钩子对
  untrusted_app **生效**（自检的 70/70 安装、`done=syscall` 和 poll 路径都证明了这一点）。
- 工具链：`aarch64-none-elf-gcc 14.2`（`D:\arm_gnu\14.2 rel1\bin`）、WSL Ubuntu 24.04 gcc 13.3、
  NDK 27 / build-tools 35.0.1 / JDK 21。

## 附录 C：放弃方案 A 的关键观测（原文摘录）

```text
# native shell 目标
status: ... state=done stage=restore handle=1 done=fault stack=task/6
probe:  fault calls=.. seen=4 slot=4 hit=2 done=2 last=.../255/80001000
        trigger_diag va=... faults=2 flags=255 pstate=80001000 loading=1

# untrusted_app 目标
status: ... state=done done=el0 stack=task/6
probe:  fault seen=0 slot=0 hit=0 done=0 token=1
        trigger_diag va=... faults=0 flags=0 pstate=0 loading=0
        pid_diag pid=<tid> el0_write_faults=0        # 该线程的用户态写缺页从未进入钩子
        resident trigger=0 pad=1 hijack=0 prog=1     # prepare/hijack 时触发页确实未缺页
```

把触发页预填并 `mprotect(PROT_READ)` 后：App 因致命信号退出（`avc: denied { write } ...
tombstoned_crash`），而钩子侧仍是 `faults=0`；把钩子换到 `do_page_fault` 后设备 panic：

```text
brk_handler -> do_debug_exception -> el1_dbg -> el1_sync -> do_undefinstr
  -> 0xffffffdb0a105168（模块地址） -> el0_svc_common -> el0_svc
CPU: 5 PID: 11014 Comm: perfetto_hprof_
```
