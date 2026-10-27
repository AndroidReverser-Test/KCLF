# KCLF 1.2.0：实现、内核兼容性与代码审计

日期：2026-10-28。范围：`kpms/kclf`、相关 KernelPatch 模块生命周期代码、自有测试程序和连接设备。
原始目录已完整保存在 `build/kclf-audit-baseline/kclf`。未修改 preset 持久化 ABI、`MAP_SYMBOL_NUM`。
`kpms/kclf` 本身是嵌套 Git 仓库；根仓库中的宿主补丁和该目录中的模块修改应分别检查/保存。

## 1. 结论

原实现不能仅凭“内核为 5.x/6.x”认定兼容，尤其存在错误取消函数 ABI、结构体/栈扫描、生命周期竞态、
未保护的 VMA 遍历以及异步重定向破坏 FPSIMD 的风险。1.2.0 已修改这些关键路径，并完成本机设备回归。

当前可确认的是：Pixel 6 的 **6.1.134 / Android 16 / ARM64 / 4K 页 / BTF / 普通 FPSIMD** 配置，
最终 KPM 通过 **15 次请求、59 项断言**。5.x 和其他 6.x 没有本次物理设备实测；下面的兼容矩阵是源码适配范围，
不是对全部厂商内核的保证。缺关键符号、布局信息或安全条件时应拒绝，而非猜测偏移继续执行。

KernelPatch 宿主配套修改已编译并通过主机生命周期测试，但**未部署到设备**。设备仍报告 `kpver=c00`。
旧宿主的并发控制/繁忙卸载缺陷不能通过替换一个 KPM 完全修复，详见第 4 节。

## 2. 具体实现

1. `kclf_ctl0` 解析受宿主 superkey 保护的命令；固定 4 个槽位，每个目标线程只允许一条活动请求。
   PID 对象和 `get_task_mm` 引用固定任务身份/地址空间，RCU 保护任务查找；不长期解引用裸 task 指针。
2. `work_prepare` 在目标线程上下文运行：校验 SO 文件头；在 mmap 读锁下取得单个 VMA 起止快照；
   释放锁后通过 `access_process_vm` 读取 ELF，解析 `ld-android.so`/`libdl.so` 的 loader 符号。
3. 在目标地址空间建立 `[RX 代码][RW 参数][PROT_NONE guard][8 页 RW 栈]`。
   总计 11 页，4K 设备为 45056 字节；代码先写入再设 RX，不建立 RWX 区间。
4. `work_hijack` 在返回边界校验真实 `pt_regs`、信号及不支持的执行状态，保存通用寄存器、SP、PC、PSTATE、
   `orig_x0`、`syscallno`，重定向到备用栈上的 EL0 trampoline。安全点判断只是启发式，不证明用户锁未被持有。
5. trampoline 保存 q0–q31 和 FPCR/FPSR，调用 `__loader_dlopen`（回退 `dlopen`）；可选调用 `dlclose`。
   恢复 FPSIMD 后发出 `getpid` 完成 syscall。完成 hook 校验任务/mm、cookie、x8 和准确的 svc 返回 PC。
6. 完成 hook 恢复原寄存器与系统调用重启状态，排队 cleanup；cleanup 在可睡眠的目标上下文采集 dlerror、
   调用 `vm_munmap` 并检查结果。错误保留在状态中，不将失败回收冒充成功。

请求状态：`idle → armed → preparing → ready → running → done/failed`，另有确定取消的 `cancelled`。
`pending` 覆盖已排队、已脱链尚未进入以及执行中的 task_work；槽位只在完成发布且最终引用释放后回收。
不能只检查 `busy=0`，也不能先读 `pending=0` 再依赖稍后变化的 `finished`。

参数区只擦除实际使用的 0x148 字节向上取整到 0x150 字节，**不是整页**。
临时映射、loader 记录、构造函数行为和时序仍可观察；cookie 仅关联请求，不构成对目标进程的安全隔离。

## 3. 兼容性判断

| 内核/配置 | 当前策略 | 验证级别 |
| --- | --- | --- |
| 5.0–5.9 | `task_work_add(..., 1)` 兼容旧 bool 通知语义；禁用 wake；仍须满足布局/符号前提 | 源码适配，未实测 |
| 5.10 | 默认 resume；保守禁用 wake，包含有 backport 的 5.10 | 源码适配，未实测 |
| 5.11–5.19（含 5.15） | resume / TWA_SIGNAL，按实际取消函数符号选择 ABI | 源码适配，未实测 |
| 6.1.134-android14-11-g66e758f7d0c0-ab13748739 | BTF 布局、cancel_match、resume/wake、4K 页 | 本次设备完整回归通过 |
| 其他 6.x（包括 6.6/6.12） | 使用相同能力检测，不按版本猜取消函数或 mm/pt_regs 布局 | 未实测；仍需对应厂商构建回归 |
| <5.0 或 >=7.0 | 初始化拒绝 | 明确不在当前范围 |
| 16K/64K 页 | 从 TCR_EL1 取得页粒度，映射长度和栈随页大小计算 | 代码路径存在，未实测 |
| 缺 BTF 且缺可调用 mmap_read_lock/unlock | 拒绝加载 | 不以无锁遍历回退 |
| 32 位、已有 SVE/SME 状态、seccomp/跟踪线程 | 拒绝重定向；force 也不绕过 | seccomp 拒绝路径实测，其余仅静态检查 |

### 关键 ABI 差异

- 上游 5.4 的 task_work_add 第三个参数为 bool，旧 task_work_cancel 接受函数指针并返回 callback 指针。
  默认通知值 1 保持两类 ABI 的 resume 语义。[Linux 5.4 task_work.c](https://raw.githubusercontent.com/torvalds/linux/v5.4/kernel/task_work.c)
- 5.10 已有 TWA_SIGNAL，但使用 JOBCTL_TASK_WORK 和信号唤醒；5.11 改用专门 notify-signal 路径。
  因本模块不伪造/忽略真正 SIGPENDING，5.10 及更旧版本保守禁用 wake。
  [Linux 5.10](https://raw.githubusercontent.com/torvalds/linux/v5.10/kernel/task_work.c)、[Linux 5.11](https://raw.githubusercontent.com/torvalds/linux/v5.11/kernel/task_work.c)
- 新版 task_work_cancel 接收 callback 对象并返回 bool，函数指针版命名为 task_work_cancel_func。
  Android 可提前 backport，设备 6.1 就出现新版符号。优先选择 cancel_match，其次 cancel_func，最后才使用旧 cancel。
  不把接口改名武断地归到某个 Android 内核版本。[Linux 6.12 task_work.c](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/task_work.c)
- `pt_regs` 的用户寄存器前缀较稳定，尾部/总大小会变化，因此不能采用本地头文件的 sizeof 或扫描栈猜位置。
  BTF 分支验证关键字段偏移及 size；无 BTF 时仅允许从真实 native getpid wrapper 的 regs 地址学习帧大小。
  [Linux 5.4 ptrace.h](https://raw.githubusercontent.com/torvalds/linux/v5.4/arch/arm64/include/asm/ptrace.h)、[Linux 6.12 ptrace.h](https://raw.githubusercontent.com/torvalds/linux/v6.12/arch/arm64/include/asm/ptrace.h)

### 运行时前提

必须有 KernelPatch 已正确识别的 current/线程栈和 syscall wrapper，完整的任务/内存/文件访问必需符号，
以及可用的 mmap 读锁。BTF 分支检查 task.mm、VMA 起止字段、mmap_lock/mmap_sem 和 rw_semaphore 的范围/对齐，
也验证 `pt_regs` 中 regs/sp/pc/pstate/orig_x0/syscallno 的偏移。损坏或不认识的 BTF 不应被静默当作已验证布局。

无 BTF 的受限回退要求 KP 给出的 task.mm 偏移通过 get_task_mm 校验、可调用的 mmap_read_lock/unlock 函数对、
标准 ARM64 VMA 起止前缀布局，以及真实 syscall wrapper 帧采样。**不覆盖任意厂商重排的无 BTF 结构体**；
常见内联锁 accessor 不在符号表时会明确失败，不能因此宣称所有无 BTF 的 5.x 可用。

VMA 使用 find_vma + 受锁保护的起止快照，不直接遍历红黑树或 Maple Tree；GUP 用户读发生在释放 mmap 锁之后，
避免嵌套获取该锁。该做法遵守 VMA 元数据稳定性要求，但不会冻结其他目标线程修改映射。
[内核 VMA 锁文档](https://www.kernel.org/doc/html/latest/mm/process_addrs.html)

用户地址上界和 TBI0 从 TCR_EL1 取得，用户数据访问在启用 TBI 时去除 top byte；不能把固定 47 位地址宽度
等同于所有 Android ARM64 配置。BTI 分支类型在新入口清零；PAC/MTE/SVE/SME/16K/64K 的完整组合没有设备验证。

## 4. 审计发现与修复

| 级别 | 原问题 | 当前修改 |
| --- | --- | --- |
| 严重 | 错误的 task_work_cancel 原型，取消失败仍清空资源 | 按符号能力选择 match/func ABI；只有确认移除指定 callback 才取消成功 |
| 严重 | busy 无法覆盖已脱链尚未执行的回调；过早复用槽位/卸载 | pending 引用覆盖完整回调周期，完成状态 release/acquire 发布，回收最后检查引用 |
| 严重 | 宿主忽略 exit 非零返回，仍释放模块代码 | 先调用 exit；失败保留对象及链表；成功再 RCU 脱链、宽限期和释放 |
| 严重 | 宿主 ctl/event 持 RCU 调用可睡眠回调，并发 ctl_args 可 UAF | 非阻塞全局操作 gate 序列化 load/ctl/event/unload；回调移出 RCU 临界区；并发/重入返回 EBUSY |
| 高 | synchronize_rcu 包装误调用另一函数 | 修正 rcupdate.h 分派，卸载另在存在时等待 synchronize_rcu_tasks |
| 高 | snprintf 累计“所需长度”导致 1KB 栈缓冲越界 | 饱和 scnprintf 语义；拒绝过长命令、数字溢出、额外参数和未知 flag |
| 高 | 裸 task 指针、PID/mm 重用及重复目标请求 | PID/mm 引用固定身份、RCU lookup、单目标单活动请求、退出/exec 后 reap |
| 高 | 扫描 task_struct/pt_regs、无锁访问 VMA | BTF/真实 syscall 帧校验；访问器核验；持 mmap 读锁快照，无能力则拒绝 |
| 高 | 裸 arch 用户拷贝涉及 PAN/冷页；nofault 返回语义混用 | 可睡眠路径统一 access_process_vm；hook 只用可选 nofault，并区分字节计数与 0/-errno |
| 高 | 异步重定向丢失 caller-saved FPSIMD、orig_x0 | trampoline 保存全部 q 寄存器和 FPCR/FPSR；内核保存/恢复 orig_x0；限制重启 errno |
| 高 | completion syscall 可被过滤/跟踪，导致无法返回 | seccomp/trace/emulation/single-step/uprobe 状态拒绝；校验准确完成 PC、任务/mm、cookie |
| 中 | ELF/phdr/dynamic/hash/string/symbol 不完整的边界判断 | 地址溢出和镜像范围校验、DT_NULL/DT_SYMENT、哈希链上限、STT_FUNC 与可执行 PT_LOAD 校验 |
| 中 | munmap/排队失败被忽略，卸载超时强行释放 | 保留失败状态与映射；有限清理重试；quiesce 停新请求但不提前拆完成 hook |
| 中 | 编译器可引入 SIMD、原子外调、旧宿主不支持的 unwind relocation | -mgeneral-regs-only、-ffixed-x18、-mno-outline-atomics、freestanding、禁止 unwind tables，模块 -Werror |
| 中 | 临时栈无保护页，历史文档与源码不一致 | 独立 guard 页；统一格式、依赖文件；保留旧文档并明确版本边界 |

宿主文件：`kernel/patch/module/module.c`、`kernel/linux/include/linux/rcupdate.h`、`kernel/base/symbol.c`。
独立仓库内的 [配套补丁](patches/README.md) 包含这些修改和主机生命周期测试；不会自动提交父仓库。
能力字符串新增 `kpm.exit_veto`、`kpm.sleepable_ctl`；不是对整个宿主 hook 引擎并发安全的证明。
全局 gate 是非阻塞操作所有权标志，不是允许睡眠时仍持有的 spinlock；重入请求明确 EBUSY。

当前设备仍使用旧宿主，测试全过程只有一个控制端，严格先 quiesce=idle 才 unload，**没有尝试繁忙时实际卸载**。
宿主修复需要在用户正常的固件构建/升级流程中单独部署；本次不刷 boot、不重启。
底层 hook trampoline 的移除/内存回收仍依赖 KernelPatch 的全局实现，不能将本轮局部修复视为全局竞态审计完成。

## 5. 验证结果与复现

最终设备证据目录：`build/kclf-test-88a50bdc1f26/`，包含 results.txt、前后 dmesg 和设备回收的测试文件。
设备保留 `/data/local/tmp/kclf-test-88a50bdc1f26`；此前审计运行的独立测试目录也保留，未删除用户文件。
原始设备日志仅保留在本地，不随独立源码仓库推送，避免上传设备标识和其他无关系统日志。

最终 `kclf.kpm`：62880 字节，SHA-256：

```text
09c4ed00c82d467da65287a041f553aac1a63b148bf27ffcd836053d3d9b3f8f
```

设备运行时输出要点：

```text
kernel=60186 btf=1 mm_off=1440 mmap_lock_off=96 vma=0/8
pt_regs=ok size=336 thread_size=16384 page=4096
user_limit=8000000000 tbi=1
cancel=match user_io=access_process_vm wake=notify_signal
```

59 项断言覆盖：构造函数 marker 独立见证、正常保留库、可选 dlclose、故意破坏 q0/q31/FP 状态后的恢复、
seccomp 目标安全拒绝、缺失/截断文件、错误命令、默认 resume、重复目标拒绝、取消、4 槽容量、wake、
排队/loader 内退出、busy quiesce、guard 精确区间、无 RWX、完整 11 页临时区间回收、reload 和最终卸载。
FPSIMD 测试哨兵实际覆盖 q0/q8/q31、FPCR/FPSR，不能声称逐个动态验证了全部 q0–q31。
`boot_id` 前后一致；SELinux 始终 Enforcing；保留的内核日志未发现新增 BUG/WARNING/Oops/panic。
这些是本轮有限测试结论，不是长期压力测试或任意构造函数正确性的证明。

主机验证：

- 模块 ARM64 GCC 13.3 严格警告构建通过；Android NDK 27 测试程序 -Werror 构建通过。
- `test/test_btf.c`：截断、无效 kind、对齐、成员范围、确定性字节变异及真实设备 BTF，ASan/UBSan 通过。
- `test/test_helpers.py`：抽取真实 C 函数测试饱和输出、tokenizer 边界、ELF 各表/可执行符号、槽位回收条件，ASan/UBSan 通过。
- `checks/test_module_lifecycle.py`：抽取真实宿主函数测试 exit veto、重入 EBUSY、分配失败、宽限期先于释放，ASan/UBSan 通过。
- ARM64 `kernel/kpimg` 已构建。日志 `build/kclf-host-build.log` 仍有宿主原有 unused 警告和 RWX LOAD segment 警告；
  不把模块 -Werror 结果扩展成整个 KernelPatch 零警告。未将 kpimg 写入设备。
- 根仓库和嵌套 KCLF 仓库分别执行 diff --check；统一本次源码 LF 换行，格式变化不改变最终二进制哈希。

构建/运行方法见 [README](README.md)。所有新脚本均通过参数接收密钥，文档不包含密钥。

## 6. 仍然存在的使用边界

1. 普通 Android 应用常启用 seccomp，本版主动拒绝，不尝试绕过应用/系统安全机制。测试对象是自有 native 进程。
2. arbitrary constructor 可以永久阻塞、递归持有 linker/malloc 锁、创建线程或安装信号处理器。固定 8 页备用栈不能满足
   所有库；guard 只能让越界故障显式发生，不能让库继续正确执行。必须在合作的空闲点加载受控 payload。
3. 其他线程仍可并发 munmap/mprotect、更改共享 loader 状态或发送信号；本框架不冻结进程，也不保证任意信号时序透明。
4. dlclose 不能保证撤销构造函数副作用、卸载 NODELETE/仍被引用的库；存在 payload 后台线程时尤其不能贸然 unload。
5. 已有 SVE/SME 状态不保存；payload 自行改变可扩展向量状态、TLS errno、线程配置等也不在透明恢复保证内。
6. 若被注入线程退出但旧 mm 仍被其他线程共享，reap 会报告 orphaned map 并释放引用，不在另一个地址空间强行 munmap；
   残留临时区间可能保留到旧 mm 的最后使用者退出。清理失败保留槽位并拒绝不安全卸载。
7. BTF/符号名不是完整的内核 ABI 证明。裁剪符号、CFI/LTO 私有符号、厂商结构重排、未来 6.x 扩展必须逐构建验证。
8. 当前没有 5.x、其他 6.x、16K/64K 页的真机；没有部署新版宿主，因而未在设备验证宿主 exit-veto 并发卸载路径。
   后续应把同一回归运行在各目标配置，不能用一台 6.1 的 PASS 代替该矩阵。
