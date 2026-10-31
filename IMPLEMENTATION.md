# KCLF 1.5.4 实现说明 / Implementation

[中文](#中文) · [English](#english) · [编译与使用 / Build and use](README.md)

本文以本分支源码为准。/ This document describes the source on this branch.

## 中文

### 1. 架构与源码分工

KCLF 是 KernelPatch 加载的可重定位 KPM（`ld -r`），不是常规 Linux LKM。
控制器通过 superkey 保护的 `kpatch ... kpm ctl0 kclf <命令>` 提交请求。
内核安排目标线程自己的 `task_work`，在该线程的 mm、凭据及命名空间下准备映射，
修改返回用户态的 `pt_regs`，让 EL0 跳板执行加载工作，随后恢复目标继续运行。
用户态函数始终在 EL0 执行，内核不直接调用 SO 构造函数。

| 文件 | 职责与主要入口 |
| --- | --- |
| [kclf.c](kclf.c) | KPM 生命周期、命令解析、请求槽、task_work、完成观察；`kclf_ctl0`、`kclf_work_*` |
| [kclf_internal.h](kclf_internal.h) | 状态机、请求、运行时内核接口和限制 |
| [kclf_compat.c](kclf_compat.c)、[kclf_btf.h](kclf_btf.h) | 内核布局和 ABI 验证、BTF 解析、访问器回退 |
| [kclf_exec.c](kclf_exec.c)、[kclf_maps.h](kclf_maps.h) | 用户内存访问、VMA/loader 解析、临时映射、现场重定向和清理 |
| [kclf_elf.c](kclf_elf.c)、[kclf_elf.h](kclf_elf.h) | 有界 ELF64 解析、哈希/版本符号查询、重定位解码 |
| [kclf_manual.c](kclf_manual.c) | manual 文件快照、依赖闭包、权限、初始化表及镜像引用登记 |
| [kclf_codegen.c](kclf_codegen.c)、[kclf_codegen.h](kclf_codegen.h)、[kclf_param.h](kclf_param.h) | 每请求 AArch64 机器码生成、随机私有布局和 EL0 ABI |
| [test/app](test/app) | 普通 Android 测试目标、payload、构建和设备回归 |

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
- mm 使用内核 `get_task_mm` / `mmput_async` 访问器；
- VMA 使用目标上下文的 `/proc/thread-self/maps`，由 procfs 处理锁与 rb-tree/maple-tree 差异；
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
持有 `struct pid` 引用避免 PID 重用误认；mm 只记录身份，不长期持有 `mm_users`，
以免阻碍进程退出和 Binder 清理。跨线程查找在 RCU 下完成，使用前复查身份。

正常路径：

```text
IDLE -> ARMED -> PREPARING -> READY -> RUNNING -> DONE -> reap -> IDLE
                  |           |          |
                  +-----------+----------+-> FAILED
ARMED -> cancel/quiesce -> CANCELLED -> reap -> IDLE
```

`DONE` 表示观察到了完整结果；仍需等待清理，`pending=` / `map=` 表示尚未排空。
`stage=queue|prepare|hijack|loader|restore` 表示当前阶段或失败位置。
每个排队和执行中的 task_work 都计入 `pending`，直到回调真正退出才释放引用；
因此“已从 task_work 链表摘下”不等于“可以重用请求槽”。

### 4. 借用目标线程与安全点

`inject` 建立请求后排队 `work_prepare`。默认 `TWA_RESUME` 等待线程自然返回 EL0；
`wake` 使用经验证的 `TWA_SIGNAL` 唤醒可中断等待，没有人为挂起的用户信号。
旧 bool 通知 ABI 不支持 wake，明确返回错误。

prepare 在目标上下文完成可睡眠的文件、映射、符号工作，再排队 `work_hijack`。
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

`kclf_exec_prepare` 分配一段匿名 RW 区，随机排列代码、ABI 参数、私有参数三个块，
各为一页；各块之间和首尾可加 0–2 页随机填充。
优先借用目标线程栈的可用下部空间：要求栈 VMA 至少 128 KiB、SP 下方至少 48 KiB，
并预留 headroom；无法满足则增加 guard 页和 6–14 页临时栈。
hijack 时还会检查借用栈的 SP 是否移动过大。

所有临时页先随机填充；代码写入后改为 RX，专用栈 guard 改为 PROT_NONE，
参数和栈保持 RW。代码和数据没有 W+X。完成准备后刷新指令缓存。
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
   不是文件系统原子快照；加载期间不要修改文件。
2. 验证 ELF64、小端、AArch64、ET_DYN 和 program headers，按 PT_LOAD 分配匿名镜像，
   预留 1–8 页随机前导 pad 及对齐余量。逐段复制文件内容，BSS 使用匿名页的零填充。
3. 默认擦除内存 ELF 头；程序头在满足首个页及前缀范围限制时一并清除。
   解析元数据已在内核保存，后续不重新依赖这些头。`keepelf` 用于需自查 ELF 头的 payload。
4. 扫描目标 VMA，解析有有效 ELF 和 SONAME 的已加载提供库。maps 路径优先可用，
   验证的直接 VMA 遍历为回退；不把框架自己的 manual 镜像隐式当作依赖库。
5. 根据导入对象的路径，为每条 DT_NEEDED 选择同名 SONAME 的提供库，并按稳定顺序
   广度优先展开传递依赖，去重且处理环。
6. 解析符号、执行可在内核完成的重定位，保存 IFUNC fixup 和初始化/析构表；
   设置段权限，保存延迟 RELRO 范围，导出 EL0 调用元数据。

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

| 重定位 | 实际计算 |
| --- | --- |
| NONE | 无写入 |
| RELATIVE | `*(B + offset) = B + A` |
| ABS64 / GLOB_DAT / JUMP_SLOT | `*(B + offset) = S + A` |
| RELR | 位图/地址表指定位置的原值加 B |
| Android APS2 packed RELA | 有界 SLEB128 解码后复用 RELA 逻辑 |

B 是 load bias，S 是符号地址，A 是 addend；地址加法按 ELF 的模 2^64 语义。
执行顺序为 RELR、APS2、普通 RELA 和 PLT RELA，共享累计重定位上限。
导入提供库的 IFUNC 时记录 resolver、写入位置、addend 三元组，延迟到 EL0，
不会从 EL1 执行 resolver；需要写 init/fini 数组的 IFUNC fixup 明确拒绝。

镜像先整体 PROT_NONE，再给各 PT_LOAD 设置 R/RW/RX，空洞及尾部对齐空间保持不可访问。
前导 pad 使用首个段的权限以允许 VMA 合并。
**GNU_RELRO 在所有 EL0 初始化/析构工作完成后的 cleanup 中由 EL1 应用**；
构造期间相关页仍可写，即使没有 IFUNC 也一样。失败逐范围重试，
没有成功应用全部保护就不提交驻留镜像。这比常规 linker 更晚施加 RELRO。

### 8. 每请求生成的 EL0 程序

`kclf_prog_build` 直接编码 AArch64 指令并回填分支。
每请求随机代码页内容、入口偏移、x19–x26 的八种工作寄存器角色、
FPSIMD 槽顺序、GPR 恢复顺序及只修改失活临时值的填充指令。
入口前有一条可落入的 restart pad，入口为 `bti c`。

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
随机布局不构成不可检测保证，x16、匿名映射和中间现场仍可被观察。

### 9. 完成观察与清理

EL0 写入 token 不触发专门的内核事件。观察有两条路径：
- `kclf_token_before`：在候选池 70 个普通 syscall 的入口安装 before hook；
  只检查被借用线程、mm、随机 token 和完整结果，不修改/吞掉该系统调用。
  实际安装数量可能少于 70，状态显示 `done=syscall`。
- `status/reap/quiesce`：给 RUNNING 线程排队单个 poll task_work，
  在目标上下文用可睡眠 GUP 读取，状态显示 `done=poll`。
  原请求带 wake 时 poll 也允许唤醒，避免目标完成后再次阻塞而无法清理。

token 在最后 RET 前就写入，因此 poll 还检查保存的 PC 已离开整个临时区，
避免中断恰落在恢复尾部时提前解除代码映射。
只在结果字段完整读取后发布 DONE，再排队目标上下文的 cleanup：
先应用全部 RELRO，随后提交/释放 manual 引用并解除临时区。
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

用户代码已进入但完成结果不可信时，镜像可能标记 abandoned，
需要进程退出后 reap；不能假定没有后台线程或回调引用。
借用线程退出而进程其余线程仍在时也可能需要让整个进程退出。
进程退出/exec 的旧 mm 负责回收映射，控制器不会在自己的 mm 中误执行 munmap。

linker 后端的驻留 handle 由 bionic 管理，`images/release` 不管理它。
需要立即平衡引用时使用 `inject,...,linker,unload`；
否则由目标应用管理 handle 或等待进程退出。

### 11. 能力边界与卸载协议

manual 明确拒绝：PT_TLS/TLS 重定位、emutls、线程析构注册入口、
需要解析的 payload 自定义 IFUNC、IRELATIVE、GNU_UNIQUE、REL/textrel、
PT_INTERP、PT_GNU_PROPERTY、可执行栈、非可读或 W+X 段、共享/重叠 PT_LOAD 页、
不支持的动态 flags/filter/preinit，以及跨 DSO CFI 导入。
初始化/析构入口必须在 payload 自身可执行段。

manual 不插入 soinfo、TLS、debugger 或异常展开登记，不自动调用 JNI_OnLoad。
不保证 C++ 异常、栈展开、ART/JNI、dlsym/dladdr/dl_iterate_phdr 识别，
也不复刻全局符号抢占和 namespace。需要这些集成时评估显式 linker 后端。
目标凭据、SELinux、seccomp 和 non-dumpable 状态未被自动放宽；
payload 自己调用 API 的限制仍生效。

主要上限：4 请求、32 镜像、64 MiB 文件、256 MiB ELF 跨度/最大对齐、
64 program headers、每对象 64 NEEDED、512 提供库、128 依赖闭包成员、
50 万动态符号、100 万累计重定位、16 MiB APS2、128 初始化和 128 析构、
64 IFUNC fixup、8 RELRO 范围、16384 个 VMA 遍历步数。
调用表和 IFUNC 表还必须共同装入一页 ABI，镜像额外 pad/对齐会增加实际预留长度。

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
严格警告及 `-mno-outline-atomics` 编译六个 C 对象，避免旧 KPM ABI 缺失原子 libcall，
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
不会把编译成功当作设备回归通过。历史实验和其他测试保留在 dev；
构建复现和控制命令见 README。

## English

### 1. Architecture and source map

KCLF is a relocatable KernelPatch KPM built with `ld -r`, rather than a standard
Linux LKM. A controller submits superkey-protected `kpatch ... kpm ctl0 kclf`
commands. The kernel schedules task_work on the target thread, prepares mappings
in its mm, credentials and namespaces, redirects its return-to-user pt_regs,
and lets an EL0 trampoline perform the loading work before resuming the thread.
User functions, including constructors, execute in EL0.

| Source | Responsibility and entry points |
| --- | --- |
| [kclf.c](kclf.c) | KPM lifecycle, commands, request slots, task_work and completion; kclf_ctl0, kclf_work_* |
| [kclf_internal.h](kclf_internal.h) | States, requests, runtime kernel interfaces and limits |
| [kclf_compat.c](kclf_compat.c), [kclf_btf.h](kclf_btf.h) | Runtime layouts, ABI validation, BTF and accessor fallbacks |
| [kclf_exec.c](kclf_exec.c), [kclf_maps.h](kclf_maps.h) | User access, VMA/loader lookup, transient mapping, redirection and cleanup |
| [kclf_elf.c](kclf_elf.c), [kclf_elf.h](kclf_elf.h) | Bounded ELF64, hash/version lookup and relocation decoding |
| [kclf_manual.c](kclf_manual.c) | File snapshots, dependencies, protection, call vectors and image references |
| [kclf_codegen.c](kclf_codegen.c), [kclf_codegen.h](kclf_codegen.h), [kclf_param.h](kclf_param.h) | Per-request AArch64 machine code, private layouts and EL0 ABI |
| [test/app](test/app) | Android target, payloads, build and device regression |

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
- mm uses get_task_mm/mmput_async accessors;
- /proc/thread-self/maps supplies a kernel-locked VMA view independent of
  rb-tree/maple-tree internals;
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
reuse confusion. mm is an identity only: the module does not retain mm_users and
delay process/Binder teardown. Task lookup uses RCU and identity rechecks.

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
actually exits. A detached callback is not yet safe to reuse.

### 4. Borrowing a thread and choosing a boundary

inject queues work_prepare. Default TWA_RESUME waits for a natural EL0 return;
wake requests the validated TWA_SIGNAL mechanism to wake interruptible waits
without synthesizing a pending user signal. Older bool notification ABIs reject wake.

Preparation performs sleepable I/O, mapping and symbol work in target context,
then queues work_hijack. Hijack locates pt_regs using its verified/learned size,
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
one-page blocks: code, ABI parameters and private state. It adds zero to two
padding pages between blocks and at the ends. It first tries borrowing unused
space below the target SP, requiring a stack VMA of at least 128 KiB and at least
48 KiB below SP, with headroom. Otherwise it adds a guard page and a six-to-fourteen
page temporary stack. Hijack rechecks that a borrowed SP has not moved too far.

Pages start with random filler. Written code becomes RX, the dedicated stack guard
becomes PROT_NONE, and parameter/stack pages remain RW. No code/data page is W+X;
instruction caches are flushed after preparation. Private GPR, FPSIMD, FPCR/FPSR,
result and token fields occupy random nonoverlapping offsets within a 4 KiB layout
window, even with larger pages. ABI and private pages are separate randomized blocks.

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
   snapshot; do not modify the file during loading.
2. Validate little-endian ELF64/AArch64 ET_DYN and program headers. Reserve an
   anonymous image with one-to-eight random leading pages and alignment slack.
   Copy PT_LOAD file bytes; anonymous zero-fill supplies BSS.
3. Scrub the in-memory ELF header by default. Program headers are also cleared
   when their extent fits the first-page/prefix bounds. Kernel metadata is already
   captured. keepelf supports payloads that inspect their own headers.
4. Scan VMAs for valid loaded ELF providers with SONAMEs. Prefer maps pathnames,
   with verified direct VMA traversal as fallback. Existing manual images are
   excluded as implicit dependency providers.
5. Resolve each DT_NEEDED using the importing object's origin and expand a stable
   breadth-first transitive dependency closure with deduplication/cycle handling.
6. Resolve symbols and kernel-side relocations, retain IFUNC fixups and call
   vectors, set segment permissions, record deferred RELRO and export EL0 metadata.

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

| Relocation | Computation |
| --- | --- |
| NONE | No write |
| RELATIVE | `*(B + offset) = B + A` |
| ABS64 / GLOB_DAT / JUMP_SLOT | `*(B + offset) = S + A` |
| RELR | Add B to original words selected by address/bitmap entries |
| Android APS2 packed RELA | Bounded SLEB128 decoding, then the RELA operation |

B is load bias, S the symbol address, and A the addend, with ELF modulo-2^64
arithmetic. Processing order is RELR, APS2, regular RELA and PLT RELA, sharing a
cumulative relocation limit. Imported provider IFUNCs produce resolver/destination/
addend triples for EL0 execution. IFUNC fixups into init/fini arrays are rejected.

The whole image first becomes PROT_NONE, then PT_LOAD segments receive R/RW/RX.
Holes and trailing alignment slack remain inaccessible. Leading pad inherits the
first segment's permissions to allow VMA merging.
**GNU_RELRO is applied by EL1 cleanup after all EL0 initialization/finalization.**
Those pages remain writable during constructors, even without IFUNCs.
Protection is retried per range; no resident image is committed before all ranges
succeed. This applies RELRO later than a conventional linker.

### 8. Per-request EL0 code generation

kclf_prog_build directly encodes AArch64 instructions and patches branches.
Each request randomizes code-page contents, entry offset, eight working roles
across x19–x26, FPSIMD slots, GPR restore order and filler touching dead temporaries.
A fall-through restart pad precedes a bti c entry.

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
Randomized layouts do not guarantee undetectability; x16, mappings and intermediate
contexts remain observable.

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
the entire transient allocation before reclaiming it. Complete result reads
precede publication of DONE. Target-context cleanup then applies every RELRO
range, commits/releases manual ownership and unmaps the transient region.
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

After entering user code, an untrusted completion may mark an image abandoned;
reap can discard it after process exit. Background threads/callbacks may still use
the code. An execution thread exiting while sibling threads live can require the
whole process to exit. On exit/exec the old mm owns mapping teardown; the controller
never performs munmap in its own unrelated mm.

Resident linker handles belong to bionic and are outside images/release management.
Use inject,...,linker,unload to balance the injected reference immediately;
otherwise let the target manage the handle or wait for process exit.

### 11. Limits and module unload protocol

Manual rejects payload PT_TLS/TLS relocations, emutls, thread-destructor registration,
resolved payload-defined IFUNCs, IRELATIVE, GNU_UNIQUE, REL/textrel, PT_INTERP,
PT_GNU_PROPERTY, executable stacks, non-readable/W+X segments, overlapping/shared
PT_LOAD pages, unsupported dynamic flags/filter/preinit, and cross-DSO CFI imports.
Initializer/finalizer addresses must lie in the payload's own executable segments.

It does not register soinfo, TLS, debugger or unwind metadata, or automatically call
JNI_OnLoad. C++ exceptions, unwinding, ART/JNI, dlsym/dladdr/dl_iterate_phdr recognition,
global interposition and namespace semantics are not guaranteed. Evaluate the
explicit linker backend when such integration is needed.
Target credentials, SELinux, seccomp and non-dumpable policy are not automatically
relaxed; payload API calls retain those restrictions.

Main limits: four requests, 32 images, 64 MiB snapshot, 256 MiB ELF span/alignment,
64 program headers, 64 NEEDED per object, 512 providers, 128 closure members,
500,000 dynamic symbols, 1,000,000 cumulative relocations, 16 MiB APS2,
128 initializers and 128 finalizers, 64 IFUNC fixups, eight RELRO ranges and
16,384 VMA traversal steps. Call vectors and IFUNC metadata must also fit one ABI
page. Padding/alignment increases the actual reserved mapping length.

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

The Makefile compiles six C objects against external KernelPatch headers with
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
regression success. Other tests and historical experiments remain on dev;
README supplies reproducible build and control commands.