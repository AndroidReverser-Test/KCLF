# KCLF 1.6.4 实现说明 / Implementation

[中文](#中文) · [English](#english) · [编译与使用 / Build and use](USAGE.md)

本文描述当前源码。版本变更见 [更新记录](CHANGELOG.md)，测试依据见 [1.6.4 审计报告](AUDIT_1.6.4.md)。
This document describes the current implementation; see the [changelog](CHANGELOG.md) and [audit](AUDIT_1.6.4.md) for release history and evidence.

## 中文

### 1. 架构与源码分工

KCLF 是 KernelPatch 加载的可重定位 KPM（`ld -r`），不是常规 Linux LKM。
控制器通过 superkey 保护的 `kpatch ... kpm ctl0 kclf <命令>` 提交请求。
准备阶段优先由 `kclf-prep` 内核线程借用目标 mm、使用目标凭据完成；能力不足时
回退到目标线程的 `task_work`。worker 不会自动切换到目标的 mount/PID 命名空间。
准备完成后排队目标线程的 `task_work`，修改返回用户态的 `pt_regs`，
让 EL0 跳板执行加载工作，随后恢复目标继续运行。
用户态函数始终在 EL0 执行，内核不直接调用 SO 构造函数。

| 文件 | 职责与主要入口 |
| --- | --- |
| [kclf.c](../kclf.c) | KPM 生命周期、命令解析、请求槽、task_work、完成观察；`kclf_ctl0`、`kclf_work_*` |
| [kclf_internal.h](../kclf_internal.h) | 状态机、请求、运行时内核接口和限制 |
| [kclf_compat.c](../kclf_compat.c)、[kclf_btf.h](../kclf_btf.h) | 内核布局和 ABI 验证、BTF 解析、访问器回退 |
| [kclf_exec.c](../kclf_exec.c)、[kclf_maps.h](../kclf_maps.h) | 用户内存访问、VMA/loader 解析、临时映射、现场重定向和清理 |
| [kclf_elf.c](../kclf_elf.c)、[kclf_elf.h](../kclf_elf.h) | 有界 ELF64 解析、哈希/版本符号查询、重定位解码 |
| [kclf_manual.c](../kclf_manual.c) | manual 文件快照、依赖闭包、权限、初始化表及镜像引用登记 |
| [kclf_codegen.c](../kclf_codegen.c)、[kclf_codegen.h](../kclf_codegen.h)、[kclf_param.h](../kclf_param.h) | 每请求 AArch64 机器码生成、随机私有布局和 EL0 ABI |
| [test/app](../test/app) | 普通 Android 测试目标、payload、构建和设备回归 |
| [kclf_tls.S](../kclf_tls.S)、[kclf_tls.h](../kclf_tls.h)、[test/tls](../test/tls) | 驻留的 EL0 TLS 运行时、共享状态布局和 TLS 回归 |

### 2. 初始化与运行时兼容

`kclf_init` 从 ARM64 翻译配置识别页大小，检查 KernelPatch 已知的内核栈布局，
通过 `kallsyms_lookup_name` 精确解析 task_work、PID、VFS、mm、GUP 等入口。
必需符号缺失时拒绝初始化；可选符号缺失时仅在已实现的回退条件下继续。
代码接受的内核版本族为 `5.0 <= version < 7.0`，不是对所有设备的兼容认证。

有 BTF 时检查 `task_struct.mm`、VMA 范围、mmap 锁和 `pt_regs` 的大小及关键偏移；
并验证 `task_work_add` 通知参数与同名不同 ABI 的 `task_work_cancel`。
取消优先选择明确的 `task_work_cancel_match` / `task_work_cancel_func`，
其余情况结合 BTF 和有限版本基线决定，无法确认时拒绝。

没有可验证布局时：
- mm 使用内核 `get_task_mm` / `mmput_async` 访问器；worker 使用自己已持有的借用 mm，
  避免 `get_task_mm(current)` 对 PF_KTHREAD 返回 NULL；
- VMA 使用 procfs maps，由内核处理锁与 rb-tree/maple-tree 差异；目标上下文使用
  `/proc/thread-self/maps`，worker 使用 `/proc/<tgid>/maps`，后者仍受 procfs 访问策略限制；
- `pt_regs` 大小可从被观察的真实 syscall wrapper 帧学习，不能扫描内核栈猜测；
- syscall hook 只用 nofault 读取；缺少 nofault 时通过可睡眠 poll task_work 使用 GUP。

`probe` 输出 BTF、页大小、寄存器帧、VMA 方法、wake ABI、HWCAP 来源和完成观察能力。
无 syscall 观察且无已知 `pt_regs` 时不能注入。TIF 宏不在 BTF 中，仍使用版本基线；
6.16 的 UPROBE 位变化等已有处理，但厂商回移标志位仍需要核验。

### 3. 控制面、身份和状态机

命令使用逗号分隔，最多 8 个 token、512 字节解析缓冲区；数字只接受十进制无符号形式。
路径必须是绝对路径、最多 255 字节，逗号没有转义机制。
默认 manual，不会在失败时自动切到 linker；重复、冲突或未知选项直接报错。

全局控制命令用原子 busy 标记串行化。最多 4 个请求槽，每个线程只能有一个活动请求。
持有 `struct pid` 引用避免 PID 重用误认；worker 在排队/准备期间持有 mm 与凭据引用，
准备结束时释放。驻留镜像只记录 mm 身份，不长期持有 `mm_users`，以免阻碍进程退出和
Binder 清理。跨线程查找在 RCU 下完成；回滚再次核对实际取得的 mm 引用，避免操作 exec 后的新 mm。

正常路径：

```text
IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE -> reap -> IDLE
                  |           |          |
                  +-----------+----------+-> FAILED
ARMED -> cancel/quiesce -> CANCELLED -> reap -> IDLE
```

`DONE` 表示观察到了完整结果；仍需等待清理，`pending=` / `map=` 表示尚未排空。
`stage=queue|prepare|hijack|loader|restore` 表示当前阶段或失败位置。
每个排队和执行中的 task_work 都计入 `pending`，直到回调真正退出才释放引用。
`worker_phase` 单独记录准备/回滚 worker 的所有权，其最后一次 release-store 才允许回收；
slot、reap 和 quiesce 同时检查两者，不能只根据 pending 为零复用槽位。
取消 queued 请求必须先认领 worker 所有权；worker 已在准备时返回 EBUSY。
READY 请求需等 worker 退出并成功移除 task_work，才能交给回滚 worker；取消成功仍需等待排空。

### 4. 借用目标线程与安全点

`inject` 优先提交准备 worker；只有 worker 所需能力不可用时才排队目标线程的 `work_prepare`。
针对目标线程的 task_work 默认使用 `TWA_RESUME` 等待线程自然返回 EL0；
`wake` 使用经验证的 `TWA_SIGNAL` 唤醒可中断等待，没有人为挂起的用户信号。
旧 bool 通知 ABI 不支持 wake，明确返回错误。

worker 用 `kthread_use_mm()`、`override_creds()` 和 `access_remote_vm()` 完成
可睡眠的文件、映射、符号工作及框架映射的页填充，再排队 `work_hijack`。
缺少目标凭据、remote-mm 或其他必要 worker 接口时采用目标线程准备路径。
四个槽轮询服务；同 mm 的 manual 镜像事务串行，独立目标及 linker 请求可以继续进展。
hijack 根据已验证/学习的帧大小定位栈顶 `pt_regs`，检查用户 PC/SP、EL0t、
64 位目标、跟踪/模拟标志、SVE/SME 状态。基础 FPSIMD 可保存，SVE/SME 不支持，
即使用 force 也拒绝；跟踪目标同样拒绝。

默认还拒绝 linker 内部返回 PC 和非白名单系统调用边界；这只是启发式。
`-EAGAIN` 时回滚，控制器稍后重新提交，不在同一次 task_work_run 中无限重排。
`force` 仅跳过这些启发式，不能让持锁/重入或寄存器竞态消失。

**x16/IP0 不能完整恢复**：最终 `RET x16` 必须用 x16 保存原 PC。
AAPCS64 的 caller-saved 约定只适用于函数调用边界，不意味着任意中断点的 x16 都可丢弃。
调用方应提供 x16 已无活跃值、没有相关锁/协议中间态的协作边界；
框架的系统调用白名单无法证明这一条件。真实信号仍由内核正常处理，
不保证对异步观察者呈现原子化的寄存器恢复。

### 5. 临时映射、参数和现场重定向

`kclf_exec_prepare` 分配一段匿名 RW 区，随机排列三块：一页 ABI 参数、一页私有参数、
一页 guard 加 6–14 页独立临时栈。各块之间和首尾可加 0–2 页随机填充。
默认在独立临时栈运行，栈顶预留 256 字节余量。即使指定 `borrowstack`，准备时仍分配临时栈。
只有显式 `borrowstack` 才在 hijack 边界尝试借用目标栈：要求栈 VMA 至少 128 KiB、
SP 下方至少 48 KiB，并预留 headroom；无法满足则使用已分配的独立栈。
hijack 还会检查借用 SP 的变化，不再执行 EL0 栈擦除。

这段匿名区**不含任何可执行页**。每请求的 EL0 跳板是一页独立的私有文件映射：
`kclf_map_file_code` 打开 payload 文件，把第 0 页以 `PROT_READ|PROT_EXEC` 私有映射进来，
再用 GUP `FOLL_FORCE|FOLL_WRITE` 把生成的程序写进它的私有 COW 页。
因此目标地址空间里既不会出现框架创建的匿名 `r-xp`，也不会出现"先映射可写、再改成可执行"
的过渡映射（SELinux 对后者的要求见第 7 节）。参数页、私有页和临时栈仍为匿名 RW——
这类映射在普通 Android 进程里大量存在；专用栈的 guard 页为 PROT_NONE。

所有临时页先随机填充；专用栈 guard 改为 PROT_NONE，参数和栈保持 RW。
代码页从 mmap 起就是 RX，数据页从 mmap 起就是最终权限，整个流程没有 W+X。
完成准备后刷新指令缓存。
私有页在前 4 KiB 布局窗口内随机分配保存 GPR、FPSIMD、FPCR/FPSR、结果和 token 的槽，
ABI 页与私有页没有固定相邻关系。

重定向前把 x0–x30、SP、PC、PSTATE 存在请求中，并把 GPR、SP、PC、NZCV 导出到私有页。
随后只将返回帧的 PC/SP 指向跳板和选定栈，清除入口 BTYPE 并设置 `syscallno=-1`，
避免 syscall restart 机制把跳板当作原调用返回。
内核侧使用 `-mgeneral-regs-only -ffixed-x18`；
保存/恢复 SIMD 的机器码在 EL0 执行。

### 6. manual 后端：文件、映射与依赖

`kclf_manual_prepare` 先在独立的 32 项镜像表中预留事务。
按 TGID 的 `struct pid` 和 mm 绑定进程，同进程的 manual 镜像事务遇到正在处理项返回 busy；
短原子元数据锁不会跨 VFS/GUP/mmap 或用户代码持有，也不冻结其他用户线程。

新镜像的顺序：

1. 用目标凭据打开文件，以有界快照读取，限制 64 MiB。快照避免反复解析变化的文件，
   不是文件系统原子快照；加载期间不要修改文件。文件句柄保留到所有映射建立完成。
2. 验证 ELF64、小端、AArch64、ET_DYN 和 program headers，预留 1–8 页随机前导 pad
   及对齐余量。每个 PT_LOAD 的页用 `MAP_PRIVATE` 从 payload 文件同偏移映射进预留区间，
   **一次就使用该段的最终权限**（R / RW / RX）；文件未覆盖的 .bss 尾部补匿名 RW 页。
   镜像因此与 bionic 加载的库同形：每段在 `/proc/<pid>/maps` 中带模块路径，
   可执行段是文件后备的 `r-xp`，段间空洞保持 PROT_NONE。
3. 默认擦除内存 ELF 头；程序头在满足首个页及前缀范围限制时一并清除。
   解析元数据已在内核保存，后续不重新依赖这些头。`keepelf` 用于需自查 ELF 头的 payload。
   初始化前扫描动态符号表，识别本地 emutls 并设定 NODELETE 生命周期策略。
4. 扫描目标 VMA，解析有有效 ELF 和 SONAME 的已加载提供库。maps 路径优先可用，
   验证的直接 VMA 遍历为回退，通过 BTF 校验的 `vm_file/f_path` 和 `d_path()` 取得路径，
   通过 `vm_pgoff/vm_flags` 取得偏移和权限。provider 元数据优先从文件页缓存读取，
   按 PT_LOAD 几何换算文件偏移，支持 APK entry；无法按路径重开的文件使用 nofault
   resident-only 回退，缺页即失败。文件句柄在准备结束时统一释放。
   不把框架自己的 manual 镜像隐式当作依赖库。
   被保护应用可能额外保留同一 ELF 文件的只读私有映射（完整性扫描用），它与 loader
   的真实映射同 SONAME/路径但可执行段为 `r--`；必须要求每个可执行 PT_LOAD 落在
   可执行 VMA 内，否则跳过该候选，避免把函数地址解析到不可执行副本。
5. 根据导入对象的路径，为每条 DT_NEEDED 选择同名 SONAME 的提供库，并按稳定顺序
   广度优先展开传递依赖，去重且处理环。
6. 解析符号、执行可在内核完成的重定位，保存 IFUNC fixup 和初始化/析构表；
   保存延迟 RELRO 范围，导出 EL0 调用元数据。

可执行段的 `.bss` 尾部同样不能落到匿名可执行页：`p_memsz > p_filesz` 的 RX 段
用文件内的等价长度页后备并在运行前清零；文件比该尾部还小时明确拒绝。
前导 pad 是匿名 RW，不继承首个段的权限，因此不会变成匿名可执行页。

提供库路径评分依次优先：完全相同路径、同目录、同 APEX、同分区、
vendor/odm 来源对应的 VNDK APEX、平台 system/system_ext/product、runtime APEX，
最后最长公共路径前缀。最高分的不同路径仍并列时失败；没有路径且多个候选也失败。
这是来源启发式，不是 bionic namespace 的完整复刻。

**不会自动加载依赖或增加其 linker 引用数**。整个准备和 payload 存活期间，
调用方必须保证所有直接/传递依赖已加载且不会被其他线程 dlclose/munmap。
框架没有取得 bionic loader 锁，无法提供并发卸载保护。

### 7. ELF 符号、重定位与权限

ELF 核心通过 `ke_io` 读写回调工作，不依赖内核结构布局或 section headers。
表、字符串、符号及写入目标都检查边界；读表限制在真实可读 PT_LOAD 内，
重定位写入限制在可写段内，拒绝越界、溢出和不支持语义。

支持 SysV/GNU hash、版本符号 VERSYM/VERNEED/VERDEF、函数/数据/绝对符号；
本地定义优先，未定义符号只在 DT_NEEDED 闭包中按序搜索。未定义弱符号可取零，
强符号或所需版本未找到则失败。

1.5.7 的符号名按 DT_STRSZ、可读 PT_LOAD 和用户地址上限分块读取，完整比较，
不截断匹配；名称缓冲在 vmalloc 中按需扩容复用，最多 64 MiB（含 NUL），
共享字符串读取预算 256 MiB。SONAME、DT_NEEDED 和版本名仍限制为 255 字节。
所有操作在可睡眠 prepare 中执行；预算/分配失败返回错误并沿既有事务回滚。

| 重定位 | 实际计算 |
| --- | --- |
| NONE | 无写入 |
| RELATIVE | `*(B + offset) = B + A` |
| ABS64 / GLOB_DAT / JUMP_SLOT | `*(B + offset) = S + A` |
| RELR | 位图/地址表指定位置的原值加 B |
| Android APS2 packed RELA | 有界 SLEB128 解码后复用 RELA 逻辑 |
| `R_AARCH64_TLSDESC` | prepare 记录 `(descriptor 地址, TLS offset)`，映射 TLS 运行时后写入 descriptor |

TLSDESC 不在通用重定位阶段直接写 GOT：它需要先完成 TLS 运行时映射和 libc 入口
校验，再由 kernel 侧写入 16 字节 descriptor；写入目标仍限制在可写 PT_LOAD 内。

B 是 load bias，S 是符号地址，A 是 addend；地址加法按 ELF 的模 2^64 语义。
执行顺序为 RELR、APS2、普通 RELA 和 PLT RELA，共享累计重定位上限。
导入提供库的 IFUNC 时记录 resolver、写入位置、addend 三元组，延迟到 EL0，
不会从 EL1 执行 resolver；需要写 init/fini 数组的 IFUNC fixup 明确拒绝。

镜像地址区间先以 PROT_NONE 预留，随后每个 PT_LOAD 直接以最终权限（R/RW/RX）映射，
空洞及尾部对齐空间保持不可访问，前导 pad 在段映射完成后改为匿名 RW。
**镜像里不存在"先可写、后加执行"的页**：SELinux 对私有文件映射的
`mmap(PROT_READ|PROT_WRITE) -> mprotect(PROT_READ|PROT_EXEC)` 要求 `execmod`
（`avc: denied { execmod } ... tclass=file`），而 `untrusted_app` 没有该权限；
只读页上的 ELF 头擦除与 .bss 清零因此改走 GUP `FOLL_FORCE` 写私有 COW 页
（与调试器给共享库 .text 打断点同一机制），既不经过 mmap/mprotect 授权检查，
也不产生 W+X 映射。
**GNU_RELRO 在所有 EL0 初始化/析构工作完成后的 cleanup 中由 EL1 应用**；
构造期间相关页仍可写，即使没有 IFUNC 也一样。失败逐范围重试，
没有成功应用全部保护就不提交驻留镜像。这比常规 linker 更晚施加 RELRO。
linker 常把 GNU_RELRO 的 memsz 向上取整到页边界，因此其尾部可以超出最后一个
可写 PT_LOAD 的 p_memsz、但必须仍落在该段页对齐后的范围内；否则拒绝。

### 8. 每请求生成的 EL0 程序

`kclf_prog_build` 直接编码 AArch64 指令并回填分支。
每请求随机代码页内容、入口偏移、x19–x26 的八种工作寄存器角色、
FPSIMD 槽顺序、GPR 恢复顺序及只修改失活临时值的填充指令。
入口前有一条可落入的 restart pad，入口为 `bti c`。
生成结果写进 payload 文件第 0 页的私有映射（`kclf_map_file_code`），
因此 EL0 执行期间 PC 始终落在 `/proc/<pid>/maps` 中有模块路径的映射里。

程序先保存 q0–q31、FPCR、FPSR 到私有页，然后分后端执行：

- manual：逐个调用导入 IFUNC resolver，传入 HWCAP（含 Android IFUNC 参数标志）
  和 `__ifunc_arg_t`，检查非零及 4 字节对齐结果，写回结果加 addend；
  再执行 DT_INIT、正序 INIT_ARRAY；需要释放时执行逆序 FINI_ARRAY、DT_FINI。
  构造函数的 argc/argv/envp 均为零。HWCAP 优先来自内核 accessor，缺失时读目标 auxv。
- linker：调用 loader(path, RTLD_NOW, caller)，失败时可调用 dlerror；
  `unload` 时再调用 dlclose，并记录返回值。

结果先复制到私有页，随后清零整个 ABI 页。恢复 q0–q31、FPCR/FPSR、SP、NZCV 和
除 x16 外的 GPR，写入每请求非零随机完成 token，最后取原 PC 到 x16、
恢复 x10 并执行 `RET x16`。保留原 x30；RET 令 BTYPE=00，
可以返回 BTI 保护函数内部的被中断指令，避免 BR 的 BTYPE 导致异常。

生成程序自身没有 SVC 指令；其完成尾部也不调用库、不制造故障或信号。
但 payload、IFUNC 和 linker 调用仍可产生普通系统调用、信号和其他副作用。
随机布局不构成不可检测保证：文件后备的跳板页、临时匿名 RW 区和中间现场仍可被观察，
镜像也仍会改变目标的 VMA 数量与 VmSize/VmPeak 记账。

### 9. 完成观察与清理

EL0 写入 token 不触发专门的内核事件。观察有两条路径：
- `kclf_token_before`：在候选池 70 个普通 syscall 的入口安装 before hook；
  只检查被借用线程、mm、随机 token 和完整结果，不修改/吞掉该系统调用。
  实际安装数量可能少于 70，状态显示 `done=syscall`。
- `status/reap/quiesce`：给 RUNNING 线程排队单个 poll task_work，
  在目标上下文用可睡眠 GUP 读取，状态显示 `done=poll`。
  原请求带 wake 时 poll 也允许唤醒，避免目标完成后再次阻塞而无法清理。

token 在最后 RET 前就写入，因此 poll 还检查保存的 PC 已离开整个临时区与跳板页，
避免中断恰落在恢复尾部时提前解除代码映射。
只在结果字段完整读取后发布 DONE，再排队目标上下文的 cleanup：
先应用全部 RELRO，随后提交/释放 manual 引用，再解除文件后备的跳板页和临时区。
RELRO 失败和映射清理失败有有界重试，耗尽后保留所有权和诊断，不能当作成功。
`status` 先渲染再排队本次 poll，可能需要后续查询才能看到完成。

### 10. 驻留镜像、release 与退出

请求槽和镜像表分开，reap 请求不会释放驻留代码。
同进程、完全相同路径字符串的 manual 加载复用原镜像、增加 refs、不重复构造；
不按 inode/符号链接去重，也不感知该路径的文件更新。
`image-id` 是框架十进制 ID，不是 bionic handle。

`release` 可使用同 TGID/mm 的任一满足条件的存活线程。
refs > 1 时只减一；最后引用执行析构并解除整段镜像映射。
新镜像 `inject,...,unload` 在一次事务中构造、析构、回收；
对已驻留镜像使用 unload 只是临时借还，不消耗已有引用。
DF_1_NODELETE 镜像拒绝显式 release 和首次 unload，需目标退出才能排空。

1.5.7 同样将可执行 PT_LOAD 内、由 payload 定义的普通 `__emutls_get_address`
函数标记为 `nodelete=emutls`。compiler-rt 的 pthread-key 析构函数可能在线程退出时
再次调用 payload 代码，故镜像一直保留到目标 mm 退出；不能仅凭 refs 释放。
未定义/跨 DSO emutls、没有可见运行时的控制对象仍拒绝。完全移出 dynsym 的隐藏
emutls 无法自动识别，调用者仍须保证释放前没有线程析构或其他异步使用。

payload 本地 ELF TLS 由框架自带的 EL0 运行时实现（`kclf_tls.S` / `kclf_tls.h`）：

- prepare 读取 PT_TLS 的 memsz/filesz/align/vaddr，验证 TLSDESC 目标位于可写段、
  offset 落在 PT_TLS 内，且只接受 payload 自身定义的 `STT_TLS` 符号；外部 TLS 拒绝。
- 在目标 mm 内建立一段独立的匿名 RW 映射存放状态、descriptor 参数和已重定位模板
  （经 RELRO 变为只读），另用 `kclf_map_file_code` 把 EL0 运行时代码页作为 payload
  文件的私有 `r-xp` 映射装入。首次加载时，EL0 在调用任何构造函数前执行
  `pthread_key_create`，失败则返回错误、不进入 payload 构造函数。
- 每线程首次访问 TLSDESC 时，resolver 用 `pthread_getspecific` 查块；慢路径先屏蔽
  信号再复查，避免信号重入看到半初始化块。线程块用匿名 mmap 提供零填充 .tbss，
  按 PT_TLS 的 align 和首字节偏置定位，并复制已重定位模板。
- PT_TLS 文件模板必须与可读 PT_LOAD 的文件/虚拟范围一致；模板从重定位后的映射复制，
  因而指针初值正确。模板中的延迟 IFUNC 在 prepare 阶段拒绝。
- pthread key 析构函数在该线程退出时 munmap 线程块；代码页、状态和 key 本身保留到
  目标 mm 退出，因此镜像标记 `nodelete=tls`，首次 unload 和显式 release 拒绝。
- 只支持 TLSDESC。TLS_DTPMOD/DTPREL/TPREL 等重定位、initial-exec/local-exec、
  外部 TLS 和 `__cxa_thread_atexit*` 仍拒绝；不向 bionic 注册 TLS/soinfo，
  dlsym/dladdr 看不到这些 TLS 变量。

用户代码已进入但完成结果不可信时，镜像可能标记 abandoned，
需要进程退出后 reap；不能假定没有后台线程或回调引用。
借用线程退出而进程其余线程仍在时也可能需要让整个进程退出。
进程退出/exec 的旧 mm 负责回收映射，控制器不会在自己的 mm 中误执行 munmap。

linker 后端的驻留 handle 由 bionic 管理，`images/release` 不管理它。
需要立即平衡引用时使用 `inject,...,linker,unload`；
否则由目标应用管理 handle 或等待进程退出。

### 11. 能力边界与卸载协议

manual 明确拒绝：外部/跨 DSO TLS、TLS_DTPMOD/DTPREL/TPREL 等非 TLSDESC 重定位、
重复或非法对齐/超限的 PT_TLS、外部或无法验证的 emutls、线程析构注册入口、
需要解析的 payload 自定义 IFUNC、IRELATIVE、GNU_UNIQUE、REL/textrel、
PT_INTERP、PT_GNU_PROPERTY、可执行栈、非可读或 W+X 段、共享/重叠 PT_LOAD 页、
可执行段 `.bss` 尾部大于文件、不支持的动态 flags/filter/preinit，以及跨 DSO CFI 导入。
初始化/析构入口必须在 payload 自身可执行段。

manual 不把 payload TLS 注册到 bionic TLS，也不插入 soinfo、debugger 或异常展开登记，
不自动调用 JNI_OnLoad。TLS 变量只对 payload 自身的 TLSDESC 访问可见；
不保证 C++ 异常、栈展开、ART/JNI、dlsym/dladdr/dl_iterate_phdr 识别，
也不复刻全局符号抢占和 namespace。需要这些集成时评估显式 linker 后端。
目标凭据、SELinux、seccomp 和 non-dumpable 状态未被自动放宽；
payload 自己调用 API 的限制仍生效。

主要上限：4 请求、32 镜像、64 MiB 文件、256 MiB ELF 跨度/最大对齐、
64 program headers、每对象 64 NEEDED、64–4096 按需增长提供库、128 依赖闭包成员、
50 万动态符号、100 万累计重定位、16 MiB APS2、128 初始化和 128 析构、
64 IFUNC fixup、8 RELRO 范围、16384 个 VMA 遍历步数。
调用表和 IFUNC 表还必须共同装入一页 ABI，镜像额外 pad/对齐会增加实际预留长度。
TLS 运行时元数据占用一个 RELRO 范围；PT_TLS 的 memsz/align 和每线程 TLS 块
同样受 256 MiB 镜像上限约束。

卸载顺序：

1. `quiesce` 禁止新 inject；已排队且可取消的请求取消，运行请求继续排空，release 仍允许。
2. 调用方停止 payload 线程、注销异步回调并保证无活跃代码指针。
   用 images/release 排空全部 manual 引用，NODELETE/abandoned 目标需要退出。
3. 重复 status/reap/quiesce，确认 `quiesce=idle`。
4. 才调用 `kpm unload kclf`。quiesce 后没有恢复接收命令，需重新加载 KPM。

引用计数不是代码无人执行的证明。stock KernelPatch 即使 exit 返回 -EBUSY 也可能释放模块；
强制卸载仍有 task_work 指向已释放代码的风险。无回调但有驻留镜像时，
退出仅释放内核登记，活进程中的 orphan 映射要等其退出回收。

### 12. 编译与测试 App 如何衔接

Makefile 使用 KernelPatch 头文件，以 freestanding、无 libc、无栈保护/展开表、
严格警告及 `-mno-outline-atomics` 编译六个 C 对象和一个位置无关的 TLS 汇编对象，避免旧 KPM ABI 缺失原子 libcall，
最后 `ld -r` 生成 kclf.kpm。它不会构建 Android payload，也不是 NDK 内核模块构建。

App 的 build.ps1 依次调用 javac、d8、NDK clang、aapt2、zipalign 和 apksigner，
不依赖 Gradle；输出在独立仓库自己的 build/ 下，支持 -OutDir。
APK 使用 API 26 最低版本、targetSdk 35、debuggable 和 extractNativeLibs。
NDK SO 使用 16 KiB 段对齐，这不等于 16 KiB 页设备认证。

MainActivity 加载 host JNI 库并输出 PID、filesDir、nativeLibraryDir；
主线程回到 Looper，Java sleeper 周期睡眠，四个 native idle 线程阻塞 pipe read，
FP 线程通过 jni/fpsimd.S 验证 nanosleep 两侧的 q0/q8/q31 和 FPCR/FPSR。
payload 构造函数写 files/hit_<pid>，记录 PID/TID 和构造地址；
另外编译 FP 破坏和两秒延时版本。

device-test.ps1 支持 manual/linker、重复次数、指定 APK/KPM 和 poll 预期，
检查 marker、映射回收、引用、取消、多槽、退出/restart、FPSIMD 和排空卸载，
同时保存日志并检查新增内核告警/App 崩溃。它会安装和停止自建测试 App，
不会把编译成功当作设备回归通过。`make test` 提供 16 组主机测试；
`test/tls/device-test.py` 验证 TLS 和失败回滚。历史实验保留在 dev；
构建复现和控制命令见 [使用说明](USAGE.md)。

## English

### 1. Architecture and source map

KCLF is a relocatable KernelPatch KPM built with `ld -r`, rather than a standard
Linux LKM. A controller submits superkey-protected `kpatch ... kpm ctl0 kclf`
commands. Preparation normally runs on the kclf-prep kernel thread with the
target mm and credentials; unavailable worker capabilities select target task_work
preparation instead. The worker does not automatically adopt the target mount/PID
namespaces. Target task_work then redirects return-to-user pt_regs so an EL0
trampoline can perform loading before resuming the thread.
User functions, including constructors, execute in EL0.

| Source | Responsibility and entry points |
| --- | --- |
| [kclf.c](../kclf.c) | KPM lifecycle, commands, request slots, task_work and completion; kclf_ctl0, kclf_work_* |
| [kclf_internal.h](../kclf_internal.h) | States, requests, runtime kernel interfaces and limits |
| [kclf_compat.c](../kclf_compat.c), [kclf_btf.h](../kclf_btf.h) | Runtime layouts, ABI validation, BTF and accessor fallbacks |
| [kclf_exec.c](../kclf_exec.c), [kclf_maps.h](../kclf_maps.h) | User access, VMA/loader lookup, transient mapping, redirection and cleanup |
| [kclf_elf.c](../kclf_elf.c), [kclf_elf.h](../kclf_elf.h) | Bounded ELF64, hash/version lookup and relocation decoding |
| [kclf_manual.c](../kclf_manual.c) | File snapshots, dependencies, protection, call vectors and image references |
| [kclf_codegen.c](../kclf_codegen.c), [kclf_codegen.h](../kclf_codegen.h), [kclf_param.h](../kclf_param.h) | Per-request AArch64 machine code, private layouts and EL0 ABI |
| [test/app](../test/app) | Android target, payloads, build and device regression |
| [kclf_tls.S](../kclf_tls.S), [kclf_tls.h](../kclf_tls.h), [test/tls](../test/tls) | Resident EL0 TLS runtime, shared state layout and regression |

### 2. Initialization and runtime compatibility

kclf_init derives the page size from ARM64 translation configuration, checks the
KernelPatch-discovered kernel stack layout, and resolves exact kernel symbol
names for task_work, PID, VFS, mm and GUP services using kallsyms_lookup_name.
Missing required symbols fail initialization; optional services have specific
fallbacks. The accepted version family is `5.0 <= version < 7.0`, which is not a
certification of every device.

When BTF is present, the module validates task_struct.mm, VMA bounds, mmap lock,
and pt_regs size and key offsets. It also checks task_work_add notification ABI
and the incompatible implementations sharing the task_work_cancel name.
Unambiguous cancel_match/cancel_func APIs take priority; remaining cases use BTF
and limited version baselines, rejecting unknown ABIs.

Without verified layouts:
- mm uses get_task_mm/mmput_async accessors; the worker returns its already
  pinned borrowed mm because get_task_mm(current) returns NULL for PF_KTHREAD;
- procfs supplies a kernel-locked VMA view independent of rb-tree/maple-tree
  internals: /proc/thread-self/maps in target context, /proc/<tgid>/maps in the
  worker, subject to procfs access policy;
- pt_regs size can be learned from a real observed syscall-wrapper frame,
  without scanning the stack for a plausible frame;
- syscall hooks use nofault reads only; sleepable poll task_work can use GUP.

probe reports BTF, pages, register frame, VMA method, wake ABI, HWCAP source and
completion observation. Injection requires syscall observation or an already
known pt_regs layout. TIF macros are absent from BTF and still use version
baselines, including the 6.16 UPROBE bit change; vendor backports need verification.

### 3. Control plane, identity and request states

Commands are comma-separated, with at most eight tokens and a 512-byte parser
buffer. Integers are unsigned decimal. Paths must be absolute, at most 255 bytes,
and cannot contain escaped commas. Manual is the default; failures never trigger
automatic linker fallback. Unknown, duplicate or conflicting options fail.

An atomic busy flag serializes control commands. There are four request slots
and at most one active request per thread. A struct pid reference prevents PID
reuse confusion. The worker holds mm and credential references during queuing
and preparation, then drops them when preparation ends. Resident images retain
mm identity only, without pinning mm_users and delaying process/Binder teardown.
Task lookup uses RCU. Rollback validates the mm reference actually acquired,
preventing unmapping through a replacement mm after exec.

```text
IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE -> reap -> IDLE
                  |           |          |
                  +-----------+----------+-> FAILED
ARMED -> cancel/quiesce -> CANCELLED -> reap -> IDLE
```

DONE means a complete result was observed; cleanup may still be pending.
pending= or map= means draining is incomplete.
stage=queue|prepare|hijack|loader|restore identifies progress or failure.
Every queued and executing task_work holds a pending reference until its callback
actually exits. worker_phase separately tracks preparation/rollback ownership;
its final release-store publishes availability. Slot reuse, reap and quiesce
check both. Cancellation must claim queued worker ownership first; active
preparation returns EBUSY. READY cancellation waits for worker exit and successful
task_work removal before queuing rollback. Accepted cancellation still needs draining.

### 4. Borrowing a thread and choosing a boundary

inject submits preparation to the worker, or queues target work_prepare when
worker capabilities are unavailable. Target task_work defaults to TWA_RESUME,
waiting for a natural EL0 return;
wake requests the validated TWA_SIGNAL mechanism to wake interruptible waits
without synthesizing a pending user signal. Older bool notification ABIs reject wake.

The worker uses kthread_use_mm(), override_creds() and access_remote_vm() for
sleepable I/O, mapping, symbols and framework-page population, then queues
work_hijack. Missing credential, remote-mm or other required worker services
select target-thread preparation. Round-robin service covers all four slots;
manual transactions serialize per mm while independent targets and linker
requests can progress. Hijack locates pt_regs using its verified/learned size,
checks PC/SP, EL0t, 64-bit execution, tracing/emulation flags and SVE/SME state.
Only base FPSIMD is supported. SVE/SME and traced targets remain rejected with force.

Default heuristics also reject a PC inside the linker and non-allowlisted syscall
boundaries. EAGAIN rolls preparation back for a later controller retry, rather
than requeueing indefinitely at the same task_work_run boundary.
force only bypasses these heuristics; it cannot remove lock or reentrancy hazards.

**x16/IP0 cannot be fully restored:** the final RET x16 uses it for the original PC.
AAPCS64 caller-saved rules apply at call boundaries, not arbitrary interruptions.
The caller needs a cooperative point where x16 is dead and relevant locks or
protocol state permit payload execution. The syscall allowlist proves neither.
Real signals retain normal kernel handling, and asynchronous observers can see
intermediate register-restoration states.

### 5. Transient mapping, parameters and redirection

kclf_exec_prepare allocates anonymous RW memory and randomly orders three
blocks: one page each for ABI parameters and private state, plus a guard page
and a six-to-fourteen page dedicated stack. Zero to two padding pages separate
blocks and the ends. The default is the dedicated stack with 256 bytes of
headroom; it is allocated even with borrowstack. Only explicit borrowstack tries
target-stack space at hijack, requiring a VMA of at least 128 KiB and at least
48 KiB below SP with headroom. Otherwise it uses the dedicated stack. Hijack
rechecks borrowed SP movement. The EL0 trampoline no longer wipes the borrowed stack.

That anonymous region contains **no executable page**. The per-request EL0
trampoline is a separate one-page private file mapping: kclf_map_file_code opens
the payload, maps file page 0 with PROT_READ|PROT_EXEC, and fills it through its
private COW page with GUP FOLL_FORCE|FOLL_WRITE. The target therefore never gains
an anonymous r-xp VMA from KCLF, and no writable mapping is turned executable
later (the SELinux execmod requirement is described in section 7). Parameter,
private and temporary-stack pages remain anonymous RW, a mapping form every
Android process already has in quantity; the dedicated stack guard is PROT_NONE.

Pages start with random filler, the dedicated stack guard becomes PROT_NONE, and
parameter/stack pages remain RW. The code page is RX from mmap on, data pages use
their final protection from mmap on, and no mapping is ever W+X; instruction
caches are flushed after preparation. Private GPR, FPSIMD, FPCR/FPSR, result and
token fields occupy random nonoverlapping offsets within a 4 KiB layout window,
even with larger pages. ABI and private pages are separate randomized blocks.

Before redirection, the request saves x0–x30, SP, PC and PSTATE; the private page
receives GPRs, SP, PC and NZCV. The return frame then receives the trampoline PC/SP,
cleared entry BTYPE and syscallno=-1 to avoid syscall restart handling.
Kernel code uses -mgeneral-regs-only and -ffixed-x18; EL0 machine code preserves SIMD.

### 6. Manual loading: file, mapping and dependencies

kclf_manual_prepare reserves a transaction in a separate 32-entry image table.
Images are owned by TGID struct pid plus mm. A busy image transaction prevents
another manual transaction in that process. A short atomic metadata lock never
spans VFS, GUP, mmap or user code; other user threads are not frozen.

For a new image:

1. Open with target credentials and read a bounded snapshot, at most 64 MiB.
   This avoids reparsing changing file contents but is not an atomic filesystem
   snapshot; do not modify the file during loading. The file stays open until all
   mappings are installed.
2. Validate little-endian ELF64/AArch64 ET_DYN and program headers. Reserve
   one-to-eight random leading pages plus alignment slack, then map every PT_LOAD
   page with MAP_PRIVATE from the payload file at the same offset, **directly with
   that segment's final protection** (R, RW or RX); anonymous RW pages supply the
   BSS tail the file does not cover. The image therefore looks like a
   bionic-loaded library: each segment carries the module pathname in
   /proc/<pid>/maps, the executable segment is a file-backed r-xp, and the gaps
   between segments stay PROT_NONE.
3. Scrub the in-memory ELF header by default. Program headers are also cleared
   when their extent fits the first-page/prefix bounds. Kernel metadata is already
   captured. keepelf supports payloads that inspect their own headers.
   Scan dynsym before initialization to identify local emutls and set NODELETE policy.
4. Scan VMAs for valid loaded ELF providers with SONAMEs. Prefer maps pathnames,
   with verified direct VMA traversal as fallback. The direct walker derives the
   same metadata from BTF-verified fields: `vm_file` + `f_path` + `d_path()` for
   the pathname, `vm_pgoff` for the file offset and `vm_flags` for permissions.
   That matters for non-dumpable targets, where `/proc/<tgid>/maps` is denied even
   with the target's credentials. Existing manual images are excluded as implicit
   dependency providers. A protected app can keep an extra read-only private
   mapping of the same ELF file for integrity scanning; it has the same
   SONAME/path but no executable segment. Every executable PT_LOAD must be
   covered completely by executable VMAs or the candidate is skipped, so function
   addresses cannot resolve into a non-executable copy.
   Provider ELF headers, dynamic sections and symbol tables are read from the
   file page cache (`filp_open` + `kernel_read`) and translated from the loaded
   virtual address back to a file offset through the provider's own PT_LOAD
   geometry; `vm_pgoff` also supports APK-embedded entries. No provider page is
   touched through GUP. A memfd/unlinked provider that cannot be reopened by path
   falls back to `copy_from_user_nofault`: the parse succeeds only for pages that
   are already resident, and a missing page fails instead of being faulted in.
5. Resolve each DT_NEEDED using the importing object's origin and expand a stable
   breadth-first transitive dependency closure with deduplication/cycle handling.
6. Resolve symbols and kernel-side relocations, retain IFUNC fixups and call
   vectors, record deferred RELRO and export EL0 metadata.

An executable segment whose p_memsz exceeds p_filesz must not fall back to an
anonymous executable tail either: it is backed by an equivalent file range and
zeroed before the payload runs, and rejected when the file is smaller than that
tail. The leading pad is anonymous RW rather than inheriting the first segment's
protection, so it never becomes an anonymous executable page.

Provider ranking prefers exact path, same directory, same APEX, same partition,
VNDK APEX for vendor/odm importers, platform system/system_ext/product, runtime APEX,
then longest common path prefix. Distinct paths tied for highest score fail.
Multiple candidates without usable paths also fail. This origin heuristic does
not reconstruct bionic namespaces.

**Dependencies are never loaded automatically or pinned through linker references.**
The caller must keep every direct/transitive provider loaded throughout preparation
and the payload lifetime. No bionic loader lock protects against concurrent
dlclose/munmap.

### 7. ELF symbols, relocations and protection

The ELF core uses ke_io callbacks and does not depend on kernel structure layouts
or section headers. Tables, strings, symbols and destinations are bounded.
Table reads must fit real readable PT_LOAD ranges and relocation writes must
target writable segments. Unsupported semantics and invalid ranges fail.

It supports SysV/GNU hash, VERSYM/VERNEED/VERDEF, function/data/absolute symbols,
local definitions before imports, and ordered lookup in the DT_NEEDED closure.
Missing undefined weak symbols resolve to zero; missing strong symbols or required
versions fail.

Since 1.5.7, symbol names are read in bounded chunks and compared in full, without
truncated matches. DT_STRSZ, readable PT_LOAD and user address limits constrain
reads. A reusable vmalloc name buffer is capped at 64 MiB including NUL, with a
shared 256 MiB string-read budget. SONAME, DT_NEEDED and versions retain their
255-byte limit. Work stays in sleepable preparation; resource failures roll back.

| Relocation | Computation |
| --- | --- |
| NONE | No write |
| RELATIVE | `*(B + offset) = B + A` |
| ABS64 / GLOB_DAT / JUMP_SLOT | `*(B + offset) = S + A` |
| RELR | Add B to original words selected by address/bitmap entries |
| Android APS2 packed RELA | Bounded SLEB128 decoding, then the RELA operation |
| `R_AARCH64_TLSDESC` | prepare records `(descriptor address, TLS offset)`; the descriptor is written after the TLS runtime is mapped |

TLSDESC is not written during the generic relocation pass: the TLS runtime and libc
entry points must be validated first. The 16-byte descriptor is then written by the
kernel side, still bounded to a writable PT_LOAD.

B is load bias, S the symbol address, and A the addend, with ELF modulo-2^64
arithmetic. Processing order is RELR, APS2, regular RELA and PLT RELA, sharing a
cumulative relocation limit. Imported provider IFUNCs produce resolver/destination/
addend triples for EL0 execution. IFUNC fixups into init/fini arrays are rejected.

The image address range is reserved PROT_NONE first, then every PT_LOAD is mapped
with its final protection (R/RW/RX). Holes and trailing alignment slack remain
inaccessible; the leading pad becomes anonymous RW once the segments are mapped.
**No page in the image is made writable and then executable**: SELinux requires
execmod for `mmap(PROT_READ|PROT_WRITE) -> mprotect(PROT_READ|PROT_EXEC)` on a
private file mapping (`avc: denied { execmod } ... tclass=file`), and
untrusted_app does not have it. Scrubbing the ELF header and clearing .bss in
read-only pages therefore go through GUP FOLL_FORCE writes to the private COW
page (the same mechanism a debugger uses to plant a breakpoint in a shared
library's .text), which consults neither the mmap nor the mprotect hook and
never creates a W+X mapping.
**GNU_RELRO is applied by EL1 cleanup after all EL0 initialization/finalization.**
Those pages remain writable during constructors, even without IFUNCs.
Protection is retried per range; no resident image is committed before all ranges
succeed. This applies RELRO later than a conventional linker.
Linkers commonly round GNU_RELRO's memsz up to a page boundary, so its tail may
extend past the last writable PT_LOAD's p_memsz as long as it stays inside that
segment's page-rounded extent; otherwise the image is rejected.

### 8. Per-request EL0 code generation

kclf_prog_build directly encodes AArch64 instructions and patches branches.
Each request randomizes code-page contents, entry offset, eight working roles
across x19–x26, FPSIMD slots, GPR restore order and filler touching dead temporaries.
A fall-through restart pad precedes a bti c entry. The generated program is written
into a private mapping of payload file page 0 (`kclf_map_file_code`), so EL0 always
runs with its PC in a mapping that carries the module pathname.

The program saves q0–q31, FPCR and FPSR to the private page, then dispatches:

- Manual: call imported IFUNC resolvers with HWCAP, the Android IFUNC argument flag
  and __ifunc_arg_t; validate nonzero, four-byte-aligned results and store result
  plus addend. Execute DT_INIT and forward INIT_ARRAY, then reverse FINI_ARRAY and
  DT_FINI when releasing. Constructor argc/argv/envp are zero.
  HWCAP comes from kernel accessors, with target auxv as fallback.
- Linker: call loader(path, RTLD_NOW, caller), optionally dlerror on failure,
  and dlclose for unload, preserving the result code.

The common tail copies results to private state and zeros the entire ABI page.
It restores q0–q31, FPCR/FPSR, SP, NZCV and all GPRs except x16, publishes a nonzero
per-request random token, loads the original PC into x16, restores x10 and executes
RET x16. Original x30 is preserved. RET selects BTYPE=00 so resumption inside a
BTI-protected function does not require a new branch landing pad.

The generated program contains no SVC instruction, and its completion tail makes
no library call and deliberately raises no fault/signal. Payload, IFUNC and linker
calls can still make syscalls or have other side effects.
Randomized layouts do not guarantee undetectability: the file-backed trampoline
page, the transient anonymous RW region and intermediate contexts remain
observable, and the image still changes the target's VMA count and VmSize/VmPeak
accounting.

### 9. Completion observation and cleanup

Publishing the token triggers no dedicated kernel event. Two observers exist:

- kclf_token_before installs before hooks from a pool of 70 ordinary syscalls.
  It verifies the borrowed thread, mm, token and complete results without consuming
  or modifying the syscall. Fewer hooks may be available; completion reports
  done=syscall.
- status/reap/quiesce enqueue one poll task_work per RUNNING request.
  Sleepable GUP reads occur in target context; completion reports done=poll.
  A wake-enabled request also allows poll to wake the thread if it blocks again.

The token precedes the final RET, so poll also verifies that the saved PC has left
the entire transient region and the trampoline page before reclaiming either.
Complete result reads precede publication of DONE. Target-context cleanup then
applies every RELRO range, commits/releases manual ownership, unmaps the
file-backed trampoline page and finally the transient region.
Protection and mapping failures have bounded retries; exhaustion retains ownership
and diagnostics. status renders before queuing its own poll, so a later query may
be needed to see completion.

### 10. Resident images, release and process exit

Request slots and image records are independent: reaping a request does not unload
resident code. A repeated manual load in the same process with exactly the same
path string reuses the image, increments refs and skips constructors.
Deduplication does not follow inode/symlink identity or detect file updates.
image-id is a decimal framework ID, not a bionic handle.

release may borrow any suitable live thread with the same TGID/mm.
Nonfinal release decrements refs; final release runs finalizers and unmaps the
whole image. A new inject with unload constructs, finalizes and unmaps in one
transaction. For an existing image, unload temporarily borrows/returns a reference
without consuming prior refs. DF_1_NODELETE rejects explicit release and first-load
unload; process exit is needed to drain it.

Version 1.5.7 applies `nodelete=emutls` to a payload-defined ordinary
`__emutls_get_address` function inside executable PT_LOAD. Its compiler-rt pthread
key destructor can call payload code when threads exit, so the image stays mapped
until the target mm exits. Undefined/cross-DSO emutls and controls without a visible
runtime remain unsupported. Hidden emutls absent from dynsym cannot be identified;
the caller must still exclude thread destructors and other asynchronous users before release.

Payload-local ELF TLS is implemented by a framework-owned EL0 runtime
(`kclf_tls.S` / `kclf_tls.h`):

- prepare reads PT_TLS memsz/filesz/align/vaddr, validates that every TLSDESC target
  is writable and every offset lies inside PT_TLS, and accepts only payload-defined
  `STT_TLS` symbols; external TLS is rejected.
- A separate anonymous RW target mapping holds the state, descriptor arguments and
  the relocated template (made read-only by RELRO); the EL0 runtime code page is a
  private r-xp mapping of the payload file installed by `kclf_map_file_code`. On
  first load, EL0 calls `pthread_key_create` before any payload constructor;
  failure aborts the load.
- On a thread's first TLSDESC access the resolver looks the block up with
  `pthread_getspecific`. The slow path blocks signals and rechecks, so a nested
  signal handler cannot observe a half-initialized block. Per-thread blocks are
  anonymous mmaps supplying zero-filled .tbss, positioned by PT_TLS align and
  first-byte bias, with the relocated template copied in (16-byte chunks plus a byte tail).
- Initialized PT_TLS bytes must match a readable PT_LOAD file/virtual range.
  Preparation snapshots the relocated bytes, including pointer initializers, and
  rejects deferred IFUNC writes into the template.
- The pthread key destructor munmaps that thread's block when it exits; the code page,
  state and key stay live until the target mm exits. The image is therefore marked
  `nodelete=tls`, and first-load unload plus explicit release are rejected.
- Only TLSDESC is supported. TLS_DTPMOD/DTPREL/TPREL relocations,
  initial-exec/local-exec, external TLS and `__cxa_thread_atexit*` remain unsupported.
  TLS is not registered with bionic TLS/soinfo; dlsym/dladdr cannot see these variables.

After entering user code, an untrusted completion may mark an image abandoned;
reap can discard it after process exit. Background threads/callbacks may still use
the code. An execution thread exiting while sibling threads live can require the
whole process to exit. On exit/exec the old mm owns mapping teardown; the controller
never performs munmap in its own unrelated mm.

Resident linker handles belong to bionic and are outside images/release management.
Use inject,...,linker,unload to balance the injected reference immediately;
otherwise let the target manage the handle or wait for process exit.

### 11. Limits and module unload protocol

Manual rejects external/cross-DSO TLS, TLS_DTPMOD/DTPREL/TPREL and other non-TLSDESC
relocations, duplicate or invalid/oversized PT_TLS, external/unverifiable emutls,
thread-destructor registration, resolved payload-defined IFUNCs, IRELATIVE, GNU_UNIQUE,
REL/textrel, PT_INTERP, PT_GNU_PROPERTY, executable stacks, non-readable/W+X segments,
overlapping/shared PT_LOAD pages, an executable segment `.bss` tail larger than the
file, unsupported dynamic flags/filter/preinit, and cross-DSO CFI imports.
Initializer/finalizer addresses must lie in the payload's own executable segments.

It does not register payload TLS with bionic, and does not register soinfo, debugger
or unwind metadata, or automatically call JNI_OnLoad. TLS variables are visible only
to the payload's own TLSDESC accesses. C++ exceptions, unwinding, ART/JNI,
dlsym/dladdr/dl_iterate_phdr recognition, global interposition and namespace semantics
are not guaranteed. Evaluate the explicit linker backend when such integration is needed.
Target credentials, SELinux, seccomp and non-dumpable policy are not automatically
relaxed; payload API calls retain those restrictions.

Main limits: four requests, 32 images, 64 MiB snapshot, 256 MiB ELF span/alignment,
64 program headers, 64 NEEDED per object, 64–4096 dynamically grown providers, 128 closure members,
500,000 dynamic symbols, 1,000,000 cumulative relocations, 16 MiB APS2,
128 initializers and 128 finalizers, 64 IFUNC fixups, eight RELRO ranges and
16,384 VMA traversal steps. Call vectors and IFUNC metadata must also fit one ABI
page. Padding/alignment increases the actual reserved mapping length. The TLS runtime
metadata consumes one RELRO range; PT_TLS memsz/align and each per-thread TLS block
are bounded by the 256 MiB image limit.

Unload sequence:

1. quiesce disables new inject operations and cancels cancellable queued loads.
   Running work drains; release remains allowed.
2. Stop payload threads/callbacks and ensure no live code pointers.
   Drain manual references through images/release. NODELETE/abandoned targets
   require process exit.
3. Repeat status/reap/quiesce until quiesce=idle.
4. Only then issue kpm unload kclf. Accepting new loads requires a KPM reload.

Reference counts do not prove no thread is executing payload code.
Stock KernelPatch may free a module even when exit returns EBUSY, leaving task_work
pointing to freed code after forced unload. With resident images but no callbacks,
shutdown drops kernel bookkeeping only; orphan mappings remain until target exit.

### 12. Build and test app integration

The Makefile compiles six C objects and one position-independent TLS assembly
object against external KernelPatch headers with
freestanding/no-libc settings, strict warnings, no stack protector/unwind tables,
and -mno-outline-atomics to avoid missing atomic libcalls on older KPM hosts.
ld -r produces kclf.kpm. This does not build Android payloads or use the NDK for
kernel code.

build.ps1 invokes javac, d8, NDK clang, aapt2, zipalign and apksigner without Gradle.
Outputs default to this independent repository's build/ directory; -OutDir overrides.
The APK has min API 26, targetSdk 35, debuggable and extractNativeLibs.
Native segments use 16 KiB alignment, which does not certify 16 KiB devices.

MainActivity loads the host JNI library and logs PID, filesDir and nativeLibraryDir.
The main thread returns to Looper; a Java sleeper sleeps periodically; four native
idle threads block on pipe reads; an FP probe uses jni/fpsimd.S to check q0/q8/q31
and FPCR/FPSR across nanosleep. Payload constructors write files/hit_<pid> with
PID/TID and constructor address. Additional builds clobber FP state or hold a
constructor for two seconds.

device-test.ps1 selects manual/linker, repetitions, APK/KPM and expected poll mode.
It checks markers, mapping reclamation, references, cancellation, slots, exit/restart,
FPSIMD and draining, retaining logs and checking new kernel warnings/app crashes.
It installs/stops the test app. Compilation success does not establish device
regression success. `make test` runs 16 host suites; `test/tls/device-test.py` covers TLS and rollback.
Historical experiments remain on dev;
[Usage](USAGE.md) supplies reproducible build and control commands.


### TLS compatibility and cost / TLS 兼容性与开销

权限缓存最多 16,384 个区间（ARM64 约 384 KiB），准备阶段扫描 maps 一次，
每段二分定位后检查相邻 VMA；不会为每个提供库重读 maps。procfs maps 不可用时，
direct walker 用 BTF 校验的 `vm_flags` 恢复权限、`vm_pgoff` 恢复文件偏移、
`d_path()` 恢复路径，因此不再退化为 `prot=-1`。provider 元数据从文件页缓存
读取，不建立也不读取目标映射页。
快照与映射解析之间没有 linker 锁；调用方必须保证依赖不被并发卸载。

TLS 热路径一次 pthread_getspecific，无系统调用、分配或全局锁；为保持 TLSDESC ABI，
保存 GPR、完整 FPSIMD、FPCR/FPSR/NZCV，使用 800 字节栈帧。首次访问需要屏蔽信号、
匿名 mmap、复制模板和设置 key。每线程映射长度为 `memsz + max(align,1) + 16`，
上限 256 MiB，内核按本机页大小取整。key 创建失败可回滚；首次地址解析失败无法向
调用方返回 errno，按运行时约定 abort。调用方须允许 rt_sigprocmask/mmap/munmap。

The permission cache holds up to 16,384 ranges (about 384 KiB on ARM64), with one
maps pass followed by binary searches and adjacent-range checks. Read errors abort
preparation. Since 1.6.3 the direct-walker fallback also recovers permissions,
file offsets and pathnames from BTF `vm_flags`/`vm_pgoff` and `d_path()`, so it
no longer degrades to `prot=-1`. There is no linker lock against concurrent
dependency removal.

A warm TLS access calls pthread_getspecific without syscalls, allocation or a
global lock, but preserves GPRs, full FPSIMD and FP control/status in an 800-byte
frame. First access blocks signals, mmaps a block, copies the template and sets
the key. Each allocation is `memsz + max(align,1) + 16`, capped at 256 MiB and rounded
by the kernel to the device page size. Key-creation failure rolls back; address
resolution failure aborts because TLSDESC cannot return an allocation errno.
The target must permit rt_sigprocmask/mmap/munmap. SVE/SME callers, non-bionic/raw
clone threads, and payload TLS access from other pthread-key destructors during
thread teardown are outside this contract. In particular, destructor ordering can
reinitialize TLS after its block was freed, and pthread destructor iteration limits
can leave such reinitialized blocks until process exit.
