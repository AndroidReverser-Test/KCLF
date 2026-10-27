# KCLF KPM 实现说明

本文描述 `kpms/kclf` 当前的实际实现（代码即事实），包括触发链、寄存器处理、
用户态 trampoline ABI、错误模型、可观测性分析与已知限制。

2026-10-27 静态审计更正：当前实现仍可被目标进程自身观察，不能保证注入不可检测。
第 14 节区分源码事实与历史测试记录；完整结论见 [可观测性审计](OBSERVABILITY_AUDIT.md)。
2026-10-27 已按审计做了一轮可观测性收敛（临时映射 40 KB、参数页擦除、默认不伪造
signal、可选 `unload`、munmap 校验等），改动与设备实测见
[HARDENING.md](HARDENING.md)。本文以下涉及 trampoline、参数页、控制面和清理
路径的段落已同步到当前源码；历史设备输出仍不构成新的验证结论。

设计目标来自 `kclf-design.md` / `kclf-shadow-design.md`；两份设计文档里依靠
内核补丁才能实现的部分（`handle_mm_fault` 故障期派发、misc 设备 ioctl 控制面）
在 KPM 环境中不可得，改用下面第 1 节列出的等价手段。

---

## 1. 设计取舍（相对设计文档的偏差）

| 设计文档方案 | 本实现 | 原因 |
| --- | --- | --- |
| misc 设备 + ioctl/poll 控制面 | KernelPatch superkey 保护的 `ctl0` 字符串通道 | KPM 无法注册字符设备；superkey 等价于原来的 fd 权限校验 |
| `handle_mm_fault` 故障期派发（Tier-H） | 只改 `pt_regs`（Tier-L）：`task_work` 触发 + 返回用户态前重定向 | KPM 不能挂内核内部函数；故障路径需要页表级改写 |
| 写故障 trap 检测 payload 完成 | `svc #0` + `getpid`(172) 系统调用 trap，cookie 在 `x0` | 无需新增页表项；cookie 用于关联请求，不隔离目标进程（见 11 节） |
| 注入后可观测面为 0 | 部分收敛：临时跳板降到 40 KB 且参数页在完成前擦除；`unload` 模式可移除 `dlopen` 的持久映射/记录；默认仍保留常规映射与 linker 记录 | 见第 14 节、可观测性审计与 [HARDENING.md](HARDENING.md) |

实现边界：

* **不使用 ptrace**：不 attach、不注入信号处理器、不 `SIGSTOP`；这不能保证
  `TracerPid` 恒为 0，目标可能已有其他 tracer。
* **复用目标线程**：框架不显式创建用户线程或安装用户 fd；动态链接器和 payload
  仍可能打开 fd、创建线程或产生其他副作用。
* **临时映射回收**：完成路径通过 `work_cleanup`（在目标上下文里执行）调用
  `vm_munmap`。其他线程可以在此前观察共享地址空间；回收现在会检查
  `vm_munmap` 返回值并最多重试 8 次，失败时保留映射字段并在 `status` 里报告，
  但不承诺映射必定删除。

---

## 2. 文件与构建

```
kpms/kclf/
  kclf.c            生命周期、符号/偏移解析、控制面、请求状态机、task_work 回调、getpid 完成 hook
  kclf_exec.c       目标 ELF 解析、loader 解析、prepare/hijack/restore/finish、诊断
  kclf_tramp.S      EL0 trampoline（位置无关、不建栈帧、末尾 svc 自陷）
  kclf_internal.h   请求结构、阶段/状态枚举、符号表结构、跨文件原型
  kclf_param.h      参数块 ABI（内核侧与 trampoline 共用的偏移常量）
  Makefile          -r 链接成单个 .kpm（kclf.o + kclf_exec.o + kclf_tramp.o）
  test/             测试目标与 payload（见第 17 节）
```

* 编译：`aarch64-none-elf-gcc -O2 -fno-stack-protector -fno-asynchronous-unwind-tables`，
  KPM 头文件来自 `kernel/`（`-I` 见 Makefile）。
* 模块元信息：`KPM_NAME("kclf")`、`KPM_VERSION(KCLF_VER)` = `1.1.0`、`KPM_LICENSE("GPL v2")`。
* 三个目标文件用 `gcc -r` 合并；`kclf_tramp.S` 单独放在 `.text.kclf_tramp` 段，
  便于内核侧用符号差值定位 blob 与字面量槽位。

---

## 3. 生命周期

### 3.1 `kclf_init`

1. `kclf_slot_reset()` 清空 4 个请求槽。
2. `kclf_page_size = kclf_detect_page_size()`，必须是 2 的幂。
3. 校验 `stack_in_task_offset`、`thread_size`（来自 KernelPatch 的探测结果）。
4. `kclf_sym_lookup_all()` 解析全部内核符号（见第 4 节），缺任何一个必要符号即
   返回 `-ENOENT` 并打印缺失名（模块加载失败，不半初始化）。
5. `kclf_probe_mm_offset()` 推导 `task_struct.mm` 偏移（见 4.2）。
6. `kclf_exec_init()`（当前为空，保留扩展点）。
7. `kclf_hook_install()` 安装 `getpid` 完成 hook；失败不卸载模块，只是
   `inject` 会因为 `kclf_hook_ok == 0` 直接返回 `-EOPNOTSUPP`（便于现场排查）。
8. `kclf_ready = 1`，打印 `ready, page=..., thread=..., hook=...`。

### 3.2 `kclf_exit`

1. `kclf_unloading = 1`（所有回调入口先看这个标志，避免卸载竞态）。
2. 对每个请求：
   * `ARMED` → `task_work_cancel(work_prepare)`；
   * `READY` → `task_work_cancel(work_hijack)`；
   * `PREPARING` → 直接置 `CANCELLED`（说明回调正在跑，靠下面的排空等待）。
   * `RUNNING` 没有安全中止逻辑。
3. `unhook_syscalln(172, ...)`。
4. 最多轮询 3000 次检查 `busy`/`completing`/`loading_num`，每次有 `msleep`
   时请求睡眠 1ms；缺少 `msleep` 时提前退出。循环结束后仍返回成功。

当前代码先移除完成 hook，再进行上述有限等待，**没有保证所有回调已经排空**。
因此不能把此卸载路径描述为安全排空；仍在执行或排队的工作可能引用模块代码。

---

## 4. 内核符号与偏移

### 4.1 符号解析

全部通过 `kallsyms_lookup_name()`（KernelPatch 导出）解析，不使用
`kallsyms_lookup_name_by_suffix`（部分部署版本未导出该符号）。
带候选回退的项：

| 用途 | 首选 | 回退 |
| --- | --- | --- |
| 用户态读 | `__arch_copy_from_user`（配合逐页预缺页） | `_copy_from_user` → `copy_from_user_nofault` |
| 预缺页 | `fault_in_pages_readable` | `access_process_vm` |
| 用户态写 | `__arch_copy_to_user` | `_copy_to_user` → KP 的 `compat_copy_to_user` |
| 取消 task_work | `task_work_cancel` | `task_work_cancel_func` |
| 唤醒阻塞任务 | `signal_wake_up_state` | `signal_wake_up` |
| RCU 读锁 | `__rcu_read_lock` | 无（尽量用） |
| 时间戳 | `ktime_get` | 无（缺失则时间字段为 0） |

必需符号（缺失即加载失败）：`task_work_add`、`task_work_cancel*`、
`find_task_by_vpid`、`vm_mmap`、`vm_munmap`、`find_vma`、`filp_open`、
`kernel_read`、`fput`。可选：`get_task_mm`/`mmput`（用于 mm 偏移推导）、
`msleep`（卸载等待）、`fault_in_pages_readable`/`access_process_vm`（冷页读取）、
`signal_wake_up_state`（仅 `wake` 模式需要）。

> 注意：`__arch_copy_from_user` / `__arch_copy_to_user` 返回"未拷贝字节数"，
> 0 表示成功；KP 的 `compat_copy_to_user` 语义相反（返回已拷贝长度），
> `kclf_uwr()` 里分别处理。
>
> 设备实测（Android 12 / kernel 5.10）中 `_copy_from_user` 在 KPM task_work
> 上下文里会返回 0 但不填充目标缓冲区，因此首选 `__arch_copy_from_user`；
> 后者不会为未驻留的文件页缺页，读 ELF/符号前先用 `fault_in_pages_readable`
> 逐页触摸，失败时回退 `access_process_vm`。

### 4.2 `task_struct.mm` 偏移推导

KernelPatch 用 `init_mm` 反查 `mm_offset`，但 `init_mm` 在部分内核不可解析
（本机探测结果为 0）。因此本模块自带推导：

1. `mm = get_task_mm(current)`，记下指针值 `want`；
2. 在 `current` 的 `task_struct` 前 0x1800 字节里按 8 字节步长找等于 `want` 的字段；
3. 用 `find_task_by_vpid(2)`（kthreadd，`mm == NULL`、`active_mm == init_mm`）
   去掉等于 0 的候选；
4. 命中即写入 `kclf_mm_off`（本机实测 1440，即 `0x5a0`）。

推导失败则模块拒绝加载：后续所有安全检查都依赖 `kclf_task_mm()`。

---

## 5. 控制面（ctl0 协议）

KernelPatch 把 `kpatch <KEY> kpm ctl0 kclf <args>` 的 `<args>` 原样交给
`kclf_ctl0()`。由于中间可能经过多种 shell 引用，参数按
`空格 / 逗号 / 制表符` 统一切分（`kclf_tokenize`），因此两种写法等价：

```
kpatch Test6666 kpm ctl0 kclf inject,<tid>,<path>[,force][,wake][,unload]
kpatch Test6666 kpm ctl0 kclf "inject <tid> <path> force"
```

| 命令 | 作用 |
| --- | --- |
| `probe` | 解析当前进程的 linker/libdl/libc、`__loader_dlopen` 地址，并检查本上下文能否取到合法 `pt_regs`（用于灰度验证内核兼容性） |
| `inject,<tid>,<path>[,force][,wake][,unload]` | 排队一次加载请求 |
| `status` | 打印请求表（状态/阶段/handle/错误文本）与后端可用性 |
| `cancel,<slot>` | 取消仍在 `ARMED`/`READY` 的请求 |
| `reap` | 回收 `finished` 槽位；对目标已退出/`exec` 的请求补记失败 |
| `sym` | 打印本模块关心的内核符号解析结果（现场排障） |
| `help` | 用法 |

输出通过 KP 的 `compat_copy_to_user` 写回（`kclf_ctl0` 的 `out_msg`），
缓冲区 1KB，超长截断。

默认行为（不带标志）：用 `TWA_RESUME` 排队，不调用 `signal_wake_up_state`，
不伪造 pending signal；目标若在可中断睡眠中，请求会停在 `armed` 直到该调用
自然返回。`force`：跳过 10.2 的安全点启发式。`wake`：恢复旧的低延迟路径，
主动打断可中断睡眠，但会改变系统调用重启和耗时语义。`unload`：`dlopen`
成功后调用 `__loader_dlclose`/`dlclose`，用于构造函数完成即自洽的 payload。
`resume` 仍被接受，等价于默认行为。

---

## 6. 请求对象与状态机

`struct kclf_req`（`kclf_internal.h`）是唯一的状态载体，`KCLF_MAX_REQ = 4`
个静态槽位，全部位于模块 `.bss`（约 1.6KB/槽）。

```
IDLE ──inject──► ARMED ──prepare──► PREPARING ──► READY ──hijack──► RUNNING
                   │                                   │               │
                   ├── cancel ──► CANCELLED            ├── cancel ──► CANCELLED
                   └── fail ────► FAILED               └── fail ────► FAILED
                                                                       │
                                                     completion trap ──┴──► DONE
```

关键字段：

| 字段 | 含义 |
| --- | --- |
| `state/stage` | 状态机；`stage` 记录失败发生点（queue/prepare/hijack/restore/loader） |
| `id` | 全局自增序号（原子） |
| `pid`/`comm` | 目标任务（`tid`）与进程名，用于状态机与回收判定 |
| `mm`/`pgd` | 地址空间身份；`exec`/退出后不匹配则放弃请求（绝不写坏新 `mm`） |
| `task` | 仅记录，不 deref（避免引用计数问题） |
| `map_addr/map_len/code_addr/param_addr/stack_top` | 目标内临时映射布局 |
| `ld` | loader 解析结果（`fn`/`dlerror`/`caller`/linker 区间/符号名） |
| `saved`/`saved_orig_x0`/`saved_syscallno` | 被打断的 EL0 上下文 |
| `woke` | 本次请求是否由我们制造了 pending-signal 标志（11.3 用） |
| `handle`/`err_user`/`unload_rc` | 完成陷阱从 x1/x2/x3 取回的结果 |
| `busy`/`completing`/`finished`/`cleanup_tries` | 并发保护 / 回收重试计数 |
| `work_prepare`/`work_hijack`/`work_cleanup` | 三段 `callback_head` |
| `codebuf[512]` | trampoline 副本（补丁后再拷入目标） |

`kclf_slot_by_task(task)` 只按"当前 task 是否等于某请求的 `run_task`/目标任务"
匹配，用于完成 hook 与回调入口的快速索引；`run_task` 在 hijack 成功时写入，
在 `kclf_slot_reset()` 里清零。

---

## 7. 触发链：三段 task_work

不用 ptrace、不发真实信号，全部在目标线程**已经在内核里**的返回用户态路径上完成：

```
target 阻塞/运行
   │  inject (默认):
   │    task_work_add(work_prepare, TWA_RESUME)   ← 下一个返回边界执行，不唤醒
   │  inject,wake:
   │    signal_wake_up_state(task, 0) + TWA_SIGNAL ← 旧低延迟路径
   ▼
work_prepare   (目标上下文, 非原子)
   check mm 身份 → kclf_exec_prepare() → task_work_add(work_hijack, TWA_RESUME)
   ▼
work_hijack    (同一次 exit_to_user_mode 循环内)
   检查安全点 → 保存 pt_regs → pc/sp 重定向 → state = RUNNING
   ▼
目标执行 trampoline（EL0）：dlopen →（可选 dlclose）→ 擦参数页 → svc getpid
   ▼
kclf_getpid_before/after (KP 系统调用 hook, 172)
   校验 task + cookie + x8 → 取 x1/x2/x3 → skip_origin → 回填寄存器 → DONE
   → task_work_add(work_cleanup, TWA_RESUME)
   ▼
work_cleanup   (目标上下文)
   读 dlerror 指针 → vm_munmap(临时映射，失败重试) → finished = 1 → 分类
```

为什么必须拆成两段（prepare + hijack）：`prepare` 里要 `vm_mmap`、`mprotect`、
读文件，可能睡眠；`hijack` 必须严格发生在"即将返回 EL0"的那一刻，不能有睡眠。
`work_hijack` 用 `TWA_RESUME` 排队后，通常在同一次
`exit_to_user_mode_loop` 的 `task_work_run()` 里紧接着执行，中间不会再返回用户态。

`work_cleanup` 单独一段是因为完成 hook 运行在系统调用返回路径上，`vm_munmap`
不应在 hook 里做（且需要在目标上下文里执行才能命中正确的 `mm`）。

---

## 8. `prepare` 阶段

`kclf_exec_prepare()`（`kclf_exec.c`）按顺序：

1. **路径与文件校验**（默认拒绝）
   * 路径必须 `/` 开头、长度 < 256；
   * `filp_open(path, O_RDONLY, 0)`（错误指针用 `>= -4095` 判定，不能用 `(long) < 0`，
     内核指针强制转换后是负数）；
   * `kernel_read` 读前 64 字节，校验 ELF：magic、`ELFCLASS64`、`ELFDATA2LSB`、
     `EM_AARCH64`、`ET_DYN`/`ET_EXEC`、`phentsize`/`phnum` 合理；
   * `fput`。
   任何一步失败都在 `prepare` 阶段报告；此前排队可能已经唤醒目标，
   不能把这一结果等同于目标完全未受影响。
2. **loader 解析**（`kclf_loader_resolve()`）
   * 遍历 `mm->mm_mt`（`find_vma` + `vma->vm_start/vm_end`），对每个 VMA 起始地址
     直接试读 ELF 头；不依赖 `vma->vm_flags`（部分厂商内核偏移不一致，按它过滤
     会漏掉 `ld-android.so`）；
   * 用 `DT_SONAME` 识别 `ld-android.so`（linker）、`libdl.so`、`libc.so`；
   * 逐个镜像查动态符号表拿 `__loader_dlopen` / `__loader_dlerror` /
     `__loader_dlclose`（linker），找不到时退回 `libdl.so` 的
     `dlopen`/`dlerror`/`dlclose`；
   * `caller` 取 `libc` 基址（bionic 用 `find_containing_library(caller)` 决定命名空间，
     因此必须是真实库内地址）；
   * 校验 `fn` 非 0、4 字节对齐、落在用户地址空间内。
3. **临时映射**
   * `vm_mmap(NULL, 0, (2 + 8) * page, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, 0)`；
   * 布局：`[0] 代码页`、`[1] 参数页`、`[2..9] 备用栈`（共 10 页 / 40 KB；`stack_top` = 映射末尾）；
   * `code_addr = map`、`param_addr = map + page`、`stack_top = map + len`。
4. **trampoline 准备**
   * `code_len = kclf_tramp_end - kclf_tramp_start`，`ptr_off = kclf_tramp_ptr_slot - kclf_tramp_start`；
   * `memcpy` 到 `r->codebuf`，`kclf_patch_ptr()` 把参数页地址写进 `movz/movk x19` 四连；
   * `kclf_verify_patch()` **反解**这四条指令，必须还原出同一个地址，否则失败
     （编译器的向量化/常量合并曾把这里算错，自检是硬性防线）；
   * `kclf_uwr(code_addr, codebuf, code_len)` 拷入目标；
   * `raw_syscall3(SYS_mprotect, code_addr, page, PROT_READ|PROT_EXEC)`
     —— 代码页最终是 **R-X**，全程不存在 RWX；
   * 参数块按 `kclf_param.h` 填写（新增 `dlclose`、`unload`）后拷入参数页。
5. 任何失败：`kclf_free_user(r, 0)` 用 `vm_munmap` 撤销映射；失败会保留区间并
   排 cleanup 重试，置 `FAILED/stage=prepare`。

失败文本示例：`open library failed rc=-2`（不存在）、`resolve loader failed rc=-3`、
`mmap failed 0x...`、`trampoline patch verification failed`、`mprotect failed rc=...`。

---

## 9. EL0 trampoline ABI

`kclf_tramp.S`（`.text.kclf_tramp`，当前 0xa0 字节）：

```
   0: b    1f                  ; +4 是入口，向前跳一步避免擦除窗口落到 bti 上
   4: bti  c                   ; BTI 内核/硬件要求
   8: movz/movk x19, #<param>  ; 由内核写入的四条指令（字面量槽）
  18: add  x0, x19, #0x40      ; path
  1c: ldr  w1, [x19, #0x28]    ; dlopen flags
  20: ldr  x2, [x19, #0x10]    ; caller
  24: ldr  x16, [x19, #0x00]   ; fn = __loader_dlopen / dlopen
  28: blr  x16
  2c: str  x0, [x19, #0x18]    ; handle 暂存
  30: cbnz x0, 2f              ; 失败才取 dlerror
  34: ldr  x16, [x19, #0x08]
  38: cbz  x16, 3f
  3c: blr  x16
  40: str  x0, [x19, #0x140]   ; dlerror 字符串指针
  44: b    3f
  48: (成功且 unload) ldr w3,[x19,#0x38]; ldr x16,[x19,#0x30]
       ldr x0,[x19,#0x18]; blr x16; mov x10,x0
  68: mov  x10, #0              ; 非 unload / 失败
  6c: ldr  x1, [x19, #0x18]    ; handle
  70: ldr  x2, [x19, #0x140]   ; dlerror 指针
  74: ldr  x9, [x19, #0x20]    ; cookie
  78: 清零 [x19, x19+0x150)    ; 整页参数（路径/cookie/指针）
  8c: mov  x0, x9
  90: mov  x3, x10             ; dlclose 返回值
  94: mov  x8, #172            ; getpid
  98: svc  #0
  9c: b    .                   ; 内核不会返回这里；若返回则停住而不是跑飞
```

约定：

* 入口 `pc = code_addr + 4`（跳过 `b`），因此即便有 4 字节擦除窗口也仍落在 `bti c` 上；
* `x19` 是参数页地址，全程只用 `x19`，不建栈帧、不碰 `sp`（所以调用者给的
  `sp = stack_top` 就是 loader 的栈）；
* 完成后结果只经寄存器回传：`x1=handle`、`x2=dlerror 字符串指针`、`x3=dlclose
  返回值`；参数页在 `svc` 前已清零，目标内存不再保留路径/cookie/loader 地址；
* 只有 `x19`/`x0`/`x1`/`x2`/`x3`/`x9`/`x10`/`x16` 被使用；loader 按 AAPCS 保存
  其余 callee-saved 寄存器，`dlopen`/`dlclose` 返回后 `x19` 仍有效。

参数块（`kclf_param.h`，一页）：

| 偏移 | 内容 |
| --- | --- |
| `0x00` | loader 入口（`__loader_dlopen` 或 `dlopen`） |
| `0x08` | `dlerror` 入口，0 表示不可用 |
| `0x10` | `caller`（libc 内地址，用于命名空间解析） |
| `0x18` | handle 暂存 |
| `0x20` | 完成 cookie |
| `0x28` | `dlopen` flags（`RTLD_NOW`） |
| `0x30` | `dlclose` 入口，0 表示不可用 |
| `0x38` | unload 标志（0/1） |
| `0x40` | 库路径（≤255 字节，`\0` 结尾） |
| `0x140` | `dlerror()` 字符串指针（不是文本） |
| `0x148` | 参数区结束（清零到 `0x150`，余下为页内对齐） |

> payload 的构造函数在 `dlopen` 内部执行，此时该线程正持有 linker 锁：
> payload **不得**再调用 `dlopen`/`dlsym`（会自死锁），也不应长时间阻塞。
> `unload` 模式下 `dlclose` 在构造函数返回后执行；若 payload 还有线程在执行库内
> 代码，卸载会崩溃，调用者需自行保证。

---

## 10. `hijack` 阶段

### 10.1 `pt_regs` 定位

`kclf_find_regs()`：

1. 不依赖 KernelPatch 的 `_task_pt_reg` 导出（老版本不导出，模块会加载失败）；
2. 从 `get_stack(current) + thread_size` 起按 288/296/…/400 逐个回退候选，用
   `kclf_regs_basic()` 校验：帧位于当前线程内核栈顶下方 1KB 内、8 字节对齐、
   `pc` 4 字节对齐且落在 `(0x1000, 0x8000000000)`、`sp` 16 字节对齐、
   `pstate & PSR_MODE_MASK == 0`（EL0t）、高 32 位为 0；
3. 再用更严格的 `kclf_regs_sane()`（额外要求 `syscallno ∈ [-1, 600]` 且
   `syscallno == regs[8]`）确认；本机 5.10 命中 336。

### 10.2 安全点判定

`inject` 的 `force` 未设置时，`kclf_exec_hijack()` 会拒绝以下边界并返回 `-EAGAIN`：

1. `pc` 落在 linker 的映射区间内（不能在 linker 里递归进 linker）；
2. `syscallno` 不在白名单（`epoll_pwait`、`ioctl`、`nanosleep`、`clock_nanosleep`、
   `read/write/readv/writev`、`ppoll`、`sendmsg/recvmsg`、`getpid/getuid/gettid`、
   `sched_yield`、`rt_sigprocmask`、`*stat*`、`fsync`、`epoll_pwait2`… 共 28 个；
   arm64 的 `nanosleep` 编号是 **101**，列表已按此修正），
   目的是避开 malloc/linker 临界区，防止注入后 payload 里的 `dlopen` 自锁；
3. `TIF_NOTIFY_SIGNAL` 置位；
4. `TIF_SIGPENDING` 置位且**不是**本次请求自己制造的标志（`r->woke`）。

`-EAGAIN` 会重新以 `TWA_RESUME` 排队，最多 8 次；仍失败则
`FAILED/stage=hijack` + 提示"中途点在 linker/分配器临界区，可重试或使用 force"。
`force` 模式下上述 1–4 全部跳过（调用者承担风险）。

32 位目标：`pstate & PSR_MODE32_BIT` 命中即返回 `-EOPNOTSUPP`
（`FAILED/stage=hijack  32-bit target unsupported`）。

### 10.3 重定向

只改三个字段：

```c
r->saved = { regs[0..30], sp, pc, pstate };   /* 完整快照 */
r->saved_orig_x0 = regs->orig_x0;
r->saved_syscallno = regs->syscallno;

regs->pc = r->code_addr + 4;   /* trampoline 入口（bti 之后） */
regs->sp = r->stack_top;       /* 备用栈顶 */
regs->syscallno = -1;          /* 入口不是系统调用返回，屏蔽重启机制 */
```

`x0` 保持目标原值不动（cookie 由 trampoline 在 `svc` 前自己设置），
因此目标寄存器文件除了 `pc`/`sp` 之外未被改写；`RUNNING` 状态与
`kclf_loading_num`（原子计数）在此写入，完成 hook 用它们做快速过滤。

---

## 11. 完成与恢复

### 11.1 完成 trap

`kclf_hook_install()` 用 `hook_syscalln(172, 0, before, after, 0)` 挂到
KernelPatch 的系统调用分发器（`invoke_syscall`/`el0_svc_common`）上。

`before` 匹配条件全部满足才消费：`kclf_loading_num != 0`、存在当前任务的请求、
`saved_valid`、`state == RUNNING`、`regs->regs[0] == cookie`、`regs->regs[8] == 172`。
命中后置 `completing = 1`、`skip_origin = 1`（不执行真正的 `getpid`）、`ret = 0`。

`after` 负责：`kclf_exec_restore()` → `args->ret = regs->regs[0]` →
`state = DONE` → 递减 `loading_num` → 排 `work_cleanup`。

> `args->ret = regs->regs[0]` 不是可选项：KP 的分发器在 after 回调**之后**才把
> `args->ret` 写回 `regs->regs[0]`。漏这一句会被写成 0，导致被重启的系统调用
> 参数指针变成 NULL（实测表现为 `nanosleep` 返回 `EFAULT`）。

cookie 用 `get_random_u64()` 生成，只在 prepare 到完成陷阱之间暂存于目标参数页；
trampoline 在 `svc` 前擦除整页，完成后结果经 `x1/x2/x3` 回传。cookie 对目标本身
不保密，不能把此机制描述为“目标无法伪造”或安全隔离边界。

### 11.2 恢复

`kclf_exec_restore()` 先把 31 个通用寄存器、`sp`、`pc`、`pstate`、
`syscallno` 全部还原，再处理系统调用重启语义。

### 11.3 被中断系统调用的重启语义（本实现的重点与坑）

`task_work` 可能在两种边界上执行，必须都正确：

**情况 A：内核已经做过回退。** 若被打断的系统调用返回
`-ERESTARTNOINTR/-ERESTARTNOHAND/-ERESTARTSYS/-ERESTART_RESTARTBLOCK`，
arm64 的 `do_signal()` 在进入 `get_signal()` 之前就已经把 `pc` 回退到 `svc`、
`x0` 还原成 `orig_x0`，并把 `syscallno` 置为 `-1`。此时快照里的
`pc` 指向 `svc` 指令本身（`0xd4000001`），恢复时**不能**再回退一次。

**情况 B：内核还没回退。** 快照里 `pc` 指向 `svc` 的下一条指令、`x0` 仍是
`-ERESTART*`。此时需要我们自己 `pc -= 4`、`x0 = orig_x0`，并对
`-ERESTART_RESTARTBLOCK` 把 `x8` 设为 `__NR_restart_syscall(219)`。

判别方式：读 `pc` 与 `pc-4` 处的指令字（`kclf_is_svc()`）：
`pc` 是 `svc` → 情况 A，原样恢复；`pc-4` 是 `svc` → 情况 B，自己回退；
两者都不是 → 兜底返回 `-EINTR`。回退时同时把 `syscallno` 置 `-1`，
阻止 `do_signal()` 再次回退。

**默认路径不再制造 pending signal。** `inject` 默认用 `TWA_RESUME` 排队，
只在目标下一次自然返回用户态时执行，不唤醒睡眠线程，也不触发上述重启分支。
代价是阻塞在长时间 `nanosleep`/`epoll_wait` 的目标要等该调用返回后才处理请求
（实测 5 秒睡眠期间请求保持 `armed`，睡眠耗时无异常）。

`wake` 模式保留旧行为：`signal_wake_up_state(task, 0)` 只置 `TIF_SIGPENDING`、
不排真实信号，被唤醒的系统调用返回 `-ERESTART_RESTARTBLOCK`，随后按上面的
语义重启。实测 5 秒 `nanosleep` 变为约 5.886 秒；这是用时间语义换低延迟。
`hijack` 通过 `r->woke` 区分“我们制造的标志”和真实待投递信号；真实信号若在
此刻投递，会以 trampoline 的 `sp` 建立信号帧。

历史 `block_target` 记录（旧 `wake` 路径）：`elapsed=6s`，同样说明总耗时
会变化，不能据此保证所有 `errno`/超时/线程状态不变。

---

## 12. 回收、取消与目标消失

* `work_cleanup`（目标上下文）：在 `mm` 仍是同一地址空间时调用
  `kclf_exec_finish(r, 1)`——按 `x2` 指针读 `dlerror` 文本，然后
  `vm_munmap` 回收整块临时映射（2+8 页）。只有 munmap 成功（或返回 `EINVAL`，
  说明区间已不存在）才清空 `map_addr/map_len`；失败最多重试 8 次，仍失败则保留
  区间并在 `status` 里报告 `cleanup incomplete`。`finished` 不再单独代表回收成功。
  * 若 `state == RUNNING`（trampoline 跑完但 trap 没被消费）→
    `FAILED/stage=restore  completion trap missed`；
  * 若 `state == DONE` 但 `handle == 0` → `FAILED/stage=loader`，
    错误文本就是 loader 的 `dlerror()`，例如
    `dlopen failed: "..." has invalid shdr offset/size: 2132216/1536`。
* `unload`：`dlopen` 成功后 trampoline 调用 `__loader_dlclose`/`dlclose`，状态行
  显示 `unload=ok|failed rc=... by=...`。引用计数大于 1 时 `dlclose` 只减计数，
  映射仍在，这是 linker 语义。
* `reap`：只回收 `finished` 且 `map_addr == 0` 的槽位；有残留映射时报告
  `cleanup incomplete` 而不静默复用。对 `ARMED/PREPARING/READY/RUNNING` 的请求，
  用 `find_task_by_vpid(pid)` + `kclf_task_alive()`（`mm`/`pgd` 一致且 `mm_users>0`）
  判断目标是否还在，不在则记 `FAILED/target exited or exec'd`。
* `cancel,<slot>`：`ARMED`/`READY` 时 `task_work_cancel` 两段 work 并置
  `CANCELLED`；`RUNNING` 拒绝（payload 已在目标里跑，只能等）。
* 槽位复用：4 个槽位，`reap` 后可复用；未 `reap` 的槽位在下次 `inject`
  时不会抢占（`kclf_slot_alloc` 只取 `IDLE`）。

---

## 13. 目标侧 ELF 解析器（`kclf_exec.c`）

不依赖目标进程自己的 `libdl`/`libc` 接口，全部用"内核读用户态内存 + 手工解析"：

* `kclf_elf_open()`：读 `Ehdr` → 校验 → 遍历 `Phdr` 取第一个 `PT_LOAD`
  （`p_offset == 0`）算 `bias = map_start - p_vaddr`，并记录 `PT_LOAD` 的
  `[vaddr, vaddr+memsz)` 范围与 `PT_DYNAMIC`；
* `kclf_elf_dyninfo()`：读 `DT_SYMTAB/DT_STRTAB/DT_STRSZ/DT_SONAME/DT_GNU_HASH/DT_HASH`；
* `kclf_elf_symcount()`：优先 `DT_HASH`（`nchain`），否则用 `DT_GNU_HASH`
  遍历 buckets + chain 求最大符号下标；两者都没有时用
  `(image_end - symtab)/sizeof(Sym)` 作上限；
* `kclf_elf_lookup()`：线性扫描 `.dynsym`，比 `DT_STRTAB` 里的名字，
  `st_shndx == 0` 视为未定义，`st_value == 0` 跳过；
* 所有读都经过 `kclf_urd()`，地址一律限制在 `0x8000000000` 以下，任何一次失败
  都安全退出（返回 -1）。

VMA 遍历：从 `0x1000` 起反复 `find_vma(mm, addr)`，只读 `vm_start/vm_end`，
在每个 VMA 起始地址试读 ELF 头；不依赖 `vm_flags`（厂商内核偏移不一致会漏掉
linker）。`kclf_probe` 在本机扫描到约 100 个 VMA 后定位到
`ld-android.so` / `libdl.so` / `libc.so`。

---

## 14. 可观测性与历史测试记录

### 14.1 普通进程的观察范围

目标进程可检查自己的地址空间和动态库列表，通常无需 root。其他无关进程能否
读取该目标的 `/proc/<pid>`，还受 UID、ptrace 访问检查及 Android SELinux 策略
限制；跨进程读取受限不能证明目标进程无法自检。

| 可能被观测的点 | 当前源码能支持的结论 |
| --- | --- |
| `TracerPid` | 框架不执行 ptrace attach；值为 0 不能证明没有注入 |
| `Threads` | 框架复用一个线程；payload 仍可创建线程，数量不变也不能证明没有注入 |
| `/proc/self/fd` | 内核 `filp_open` 校验不安装用户 fd；用户态 linker 加载文件时仍可能产生临时 fd，payload 也可打开 fd |
| `/proc/self/maps`、`smaps` | 默认加载仍保留常规映射；`unload` 模式可使 payload 映射消失（引用计数为 1 时）；临时跳板回收不等于库映射消失 |
| `dl_iterate_phdr` | 默认仍可枚举到 payload 记录；`unload` 后记录消失；框架没有做通用隐藏 |
| 临时匿名映射 | 现在为 40 KB / 2 个 VMA；从准备到清理仍跨越 trampoline、`dlopen` 和构造函数执行，其他线程可并发观察 |
| 多次加载 | 同一库可能复用 handle；`unload` 只减引用计数，引用计数大于 1 时映射仍在 |
| 目标上下文 | 默认不再制造 pending signal；保存/恢复部分 `pt_regs` 仍不等于完整运行状态或时间语义不变 |
| 信号与耗时 | 默认不排真实信号、不唤醒睡眠线程；`wake` 仍会影响系统调用重启和耗时 |
| payload 行为 | 测试 payload 默认静默；只有 `KCLF_TEST_VERBOSE=1` 才写文件/打印；payload 自身副作用仍可观察 |

以上信息可用于发现非预期加载，但某一条映射或单次耗时变化不能单独证明注入
来源就是 KCLF。[Linux maps 文档](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
说明了映射信息和访问检查；[AOSP linker 实现](https://android.googlesource.com/platform/bionic/+/d3e7d088453e089b3d625b0864ccdf3c74893f18/linker/linker.cpp)
展示了动态库枚举机制。具体 ROM 行为仍需单独验证。

本轮修改后的设备实测（Android 12 / kernel 5.10）见
[HARDENING.md](HARDENING.md)：临时映射 40 KB，默认注入不改变 5 秒睡眠，
`unload` 后 payload 映射消失；这些结果仍不能证明目标无法检测。

### 14.2 历史记录（OnePlus PJF110，Android 15，kernel 6.1，`/data/local/tmp`）

下列为原文保留的历史输出，本次未在设备复测。这份快照已经显示加载后的持久
变化；它不支持“VMA、VmSize 回到注入前基线”或“零可观测面”的结论：

```
== before                      == after
TracerPid: 0                   TracerPid: 0
Threads: 1                     Threads: 1
fd=3                           fd=3
task=1                         task=1
vma=91                         vma=98            (+7 = payload 的 r--/r-x/r--/rw/bss)
anon exec=8                    anon exec=9       (原记录未附统计方法，无法验证归因)
VmSize 2170732 kB              VmSize 2170768 kB (+36KB = payload)
min_flt=371                    min_flt=387
```

状态机输出：

```
#0 id=1 pid=25159(kclf_target) state=done stage=queue handle=2aadbe4a13ae1f05 via=__loader_dlopen
```

以下也仅为历史记录，不能作为本次修改后的验证结果；同一 handle 或目标存活
不足以证明语义完全透明：

* 连续注入 6 次同一目标：记录为全部 `done`（同一 handle），目标存活；
* 错误路径：不存在文件 → `failed/prepare  open library failed rc=-2`；
  损坏 ELF → `failed/loader  dlopen failed: ... invalid shdr offset/size`，
  目标继续正常运行（其 tick 日志连续）;
* 阻塞在 5s `nanosleep` 的目标：注入成功且系统调用最终 `rc=0`；
* 卸载：记录为 `kpm unload kclf` 后 `kpm num` 为 0；该计数不能证明目标侧
  库已卸载或所有异步回调均已安全排空。

---

## 15. 错误模型

`stage` 明确区分"框架没做到"和"目标/loader 拒绝"：

| `stage` | 典型错误文本 | 含义 |
| --- | --- | --- |
| `queue` | `task_work_add failed` | 无法排队（任务正在退出等） |
| `prepare` | `open library failed rc=-2`、`resolve loader failed rc=-3`、`mmap failed 0x...`、`trampoline patch verification failed`、`mprotect failed rc=...` | 准备失败；此前可能已唤醒目标或建立临时映射，不能保证目标未受影响 |
| `hijack` | `no pt_regs frame at return boundary`、`no safe point in N attempts ...`、`32-bit target unsupported`、`target address space replaced` | 未进入 trampoline；仍可能已有准备阶段的副作用 |
| `restore` | `completion trap missed`、`no register frame on completion` | trampoline 已执行但内核没能完成恢复（目标可能已异常） |
| `loader` | `dlopen failed: ...`（`dlerror()` 原文） | loader 拒绝加载；此阶段标签本身不能证明所有目标运行状态已恢复 |

`err` 字段一律为可读文本（不是裸 errno），以 `snprintf` 语义写入，
`status` 原样输出；`reap` 后清空。

---

## 16. 已知限制

1. **仅支持 64 位目标**。命中 `PSR_MODE32_BIT` 直接拒绝，未实现 arm32
   trampoline 与 compat `pt_regs` 布局。
2. **必须具备可用的后端**：`has_syscall_wrapper`（KernelPatch 系统调用分发器）、
   `task_work_add`、`kallsyms_lookup_name`、`signal_wake_up_state`。
   缺任意一项时模块仍可加载（便于排障），但 `inject` 返回
   `-EOPNOTSUPP`。
3. **需要一次返回用户态的机会**：若线程永久阻塞在不可中断睡眠
   （如 `io_schedule()` 的 D 状态）或内核线程，请求会停在 `ARMED`，
   需要用 `cancel`/`reap` 收尾。
4. **系统调用时间语义未经完整验证**：`nanosleep`/`poll`/`epoll_wait` 等
   调用可能受到唤醒和重启影响（见 11.3）；不能承诺超时、剩余时间和
   总耗时不变，也不能仅凭可重试就认定没有影响。
5. **payload 约束**：构造函数运行在 linker 锁内，不得再次 `dlopen`、
   不得长时间阻塞；且必须能被目标自身的 seccomp 策略允许加载。
6. **静态/无 linker 目标**：`prepare` 阶段失败（找不到 `ld-android.so`）。
7. **`force` 模式**：跳过安全点判定，可能把 linker 的锁重入，或者与真实
   待投递信号交错，仅用于排障。
8. **`mm` 偏移推导**依赖 `get_task_mm`/`mmput`；若内核不导出这两个符号，
   模块拒绝加载（宁可失败也不做不可靠写入）。
9. **按 tid 重定向，共享进程状态**：框架不暂停整个进程，其他线程仍共享
   同一地址空间、文件描述符表和 linker 状态，能够观察加载产生的变化。
10. **不提供不可检测保证**：临时映射清理不会删除加载库的映射及记录；
    清理失败和卸载期间的未完成工作也尚无完整成功保证。

---

## 17. 测试方法

```bash
# 构建（需要 aarch64-none-elf- 工具链）
make TARGET_COMPILE=aarch64-none-elf-

# 部署
adb push kclf.kpm /data/local/tmp/kclf.kpm
adb push test/libkclf_payload.so /data/local/tmp/
adb push test/kclf_target /data/local/tmp/

# 加载与自检
adb shell /data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf probe
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf sym

# 默认注入（TWA_RESUME，不主动唤醒）
adb shell '/data/local/tmp/kclf_target 400000 >/dev/null 2>&1 & echo $!'
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf inject,<tid>,/data/local/tmp/libkclf_payload.so
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf status

# 需要证据时（默认静默 payload）
adb shell 'KCLF_TEST_VERBOSE=1 /data/local/tmp/kclf_target 400000 >/data/local/tmp/t.log 2>&1 & echo $!'

# 一次性 payload：构造函数返回后 dlclose
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf inject,<tid>,/data/local/tmp/libkclf_payload.so,unload

# 睡眠中的目标需要低延迟时（会改变 sleep 耗时）
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf inject,<tid>,/data/local/tmp/libkclf_payload.so,wake

# 卸载
adb shell /data/local/tmp/kpatch <KEY> kpm unload kclf
```

`test/` 说明：`target.c` 循环 `nanosleep`，支持 `KCLF_TEST_SLEEP_MS`、
`KCLF_TEST_VERBOSE`（报告 sleep 异常）、`KCLF_TEST_PHDR_EVERY`（周期性调用
`dl_iterate_phdr` 打印自身模块列表）；`payload.c` 默认静默，`KCLF_TEST_VERBOSE=1`
才写 hit 文件/打印，`KCLF_TEST_HOLD_MS` 可让构造函数保持临时映射以便观察。
这些样例仍不构成完整可观测性测试。

---

## 18. 关键实现经验（避免重复踩坑）

1. **内核指针不能用 `(long)p < 0` 判错**，必须用 `>= -4095`（`kclf_is_err`）。
   `filp_open` 返回的合法指针强制转 `long` 也是负数。
2. **KPM 的 `compat_copy_to_user` 语义是"返回已拷贝长度"**，与
   `__arch_copy_to_user`（返回未拷贝字节数）相反。
3. **编译器会把 `movz/movk` 字面量构造向量化**（GCC 对 4 次循环的 NEON 化
   曾把高 16 位算错）。构造指令序列必须标量 + `volatile` 存储，并用
   `kclf_verify_patch()` 反解自检。
4. **KP 系统调用 hook 的返回值在 after 回调之后写回**：恢复寄存器时
   必须同步 `args->ret`，否则 `x0` 被写成 0（`nanosleep` 表现为 `EFAULT`）。
5. **`task_work` 与 `do_signal` 的先后不确定**：重启语义必须能识别
   "内核已回退"和"未回退"两种现场，靠 `svc` 指令字判别。
6. **只踢醒不置 pending signal 会截断可中断睡眠**：`signal_wake_up_state(task, 0)`
   是让被中断系统调用正确重启的关键。
7. **卸载前必须排空所有 `callback_head`**：模块代码被释放后，残留的
   `func` 指针会在目标线程里被调用。完成 hook 要最后移除，否则正在运行的
   trampoline 会执行真实 `getpid` 后死循环。
8. **`vma->vm_flags` 不能假设固定偏移**：设备 5.10 上按 offset 32 读到的不是
   `vm_flags`，按 READ/WRITE 过滤会漏掉 linker，导致一直退回 `libdl.dlopen`。
   现在不依赖 flags，逐个 VMA 试读 ELF 头。
9. **`_copy_from_user` 在部分 KPM task_work 上下文会返回 0 但不填充缓冲区**：
   改用 `__arch_copy_from_user`，并在读 ELF/符号前用
   `fault_in_pages_readable` 逐页预缺页，失败再回退 `access_process_vm`。
10. **arm64 的 `nanosleep` 是 101，不是 35**：35 是 `unlinkat`。安全点白名单
    写错会让默认 `TWA_RESUME` 注入在睡眠边界反复 `-EAGAIN`。
11. **GCC 14 的 C11 原子默认走 `__aarch64_ldadd*` libcall**：老 KernelPatch
    不导出这些符号，构建需 `-mno-outline-atomics`。
