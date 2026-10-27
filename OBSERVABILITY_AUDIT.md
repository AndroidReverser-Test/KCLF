# KCLF 可观测性审计

日期：2026-10-27。范围：当前 `kpms/kclf` 源码、汇编、头文件、构建文件、
实现说明和 `test/` 下的三个 C 样例。方法：静态审计及公共接口文档核对。
本次没有获取设备 root、加载 KPM 或执行注入；没有验证既有 `kclf.kpm` 与源码
是否对应，也没有把原说明中的历史输出当作本次实测。

## 1. 结论与权限范围

**当前框架仍能被目标进程自身观察。** 通过系统动态链接器加载 SO 会留下正常的
库映射与加载记录。清理临时跳板不能推出这些持久变化也已消失。

“普通进程”需要区分以下范围：

| 观察者 | 可以得出的结论 |
| --- | --- |
| 被注入进程自身，包括其中的检测线程 | 通常无需 root 即可检查本进程的映射及动态库列表 |
| 其他进程 | 能否检查该目标取决于 UID、ptrace 访问检查和 Android SELinux 策略，不能一概而论 |

发现新增库可以证明加载状态变化；仅凭一条映射、一个计数或单次耗时异常，
不能唯一确定其来源为 KCLF。已有合法加载也必须纳入解释。

## 2. 实际执行链

| 阶段 | 源码位置与行为 |
| --- | --- |
| 控制与排队 | `kclf.c:kclf_ctl0` / `kclf_cmd_inject`：ctl0 解析请求，记录目标及路径，排入 task_work |
| 准备 | `kclf_exec.c:kclf_exec_prepare`：校验 ELF，解析目标 linker/libdl，建立 34 页临时区域，写入跳板及参数，将代码页设为 RX |
| 重定向 | `kclf.c:kclf_work_hijack` / `kclf_exec.c:kclf_exec_hijack`：保存部分 pt_regs，修改目标线程 PC、SP 和 syscallno |
| 加载 | `kclf_tramp.S`：调用已解析的 `__loader_dlopen` 或 `dlopen`，库构造函数在此期间执行 |
| 完成 | `kclf.c:kclf_getpid_before` / `kclf_getpid_after`：识别完成请求并调用寄存器恢复 |
| 回收 | `kclf.c:kclf_work_cleanup` / `kclf_exec.c:kclf_exec_finish`：读回结果，调用 vm_munmap 回收跳板区域 |

该实现没有手工装载 payload 的 ELF；其手工 ELF 解析用于发现现有 loader。
请求回收代码只处理临时区域，没有卸载由 loader 加载的库。

## 3. 可观察事实

### 3.1 持久的库映射和加载记录

`kclf_resolve` 选择系统 loader，汇编随后调用该函数。`kclf_exec_finish` 仅回收
`map_addr/map_len`，没有删除 payload 或其依赖的常规映射。目标可从自身映射
视角发现新增库；常规 linker 加载记录也可通过库枚举接口观察。

[Linux maps 文档](https://man7.org/linux/man-pages/man5/proc_pid_maps.5.html)
定义了映射范围、权限和路径信息及其访问检查；
[smaps 文档](https://man7.org/linux/man-pages/man5/proc_pid_smaps.5.html)
定义了每段映射的内存统计。
[AOSP linker 源码](https://android.googlesource.com/platform/bionic/+/d3e7d088453e089b3d625b0864ccdf3c74893f18/linker/linker.cpp)
展示了 `do_dl_iterate_phdr` 遍历加载列表的机制。此公共实现参考不代替对当前
连接设备所用 ROM 的实测。

### 3.2 临时映射也不具备进程级不可见保证

从 `vm_mmap` 到 `vm_munmap` 之间包含 trampoline、动态链接及构造函数执行。
其他线程没有被暂停，仍可观察共享地址空间。即使清理在被重定向线程恢复原执行
位置之前成功完成，也不能推出同进程其他线程在整个窗口内均看不到它。

代码没有保证该窗口固定为 30–50 微秒；调度、文件访问、缺页、linker 锁与
构造函数耗时都会影响持续时间。当前目录没有给出该微秒数字的原始测量记录。

### 3.3 文件描述符、线程数和 TracerPid 的局限

内核校验使用的 `filp_open` 不等于在目标安装用户 fd，但后续用户态 linker
仍可能打开库文件。AOSP 的
[open_library 实现](https://android.googlesource.com/platform/bionic/+/b996d60/linker/linker.cpp)
包含正常文件打开操作。前后 fd 数相同不足以排除中间发生过临时文件访问。

框架不显式创建用户线程或执行 ptrace attach；payload 的行为不受此约束。
`TracerPid == 0` 和线程数不变均不足以证明未发生注入。

### 3.4 时间和 payload 副作用

排队路径可能主动唤醒目标，恢复代码包含系统调用重启分支。历史说明中 5 秒
睡眠记录为约 6 秒，本身就不能支持“运行语义完全透明”。保存部分 pt_regs
字段也不足以证明线程局部状态和全部体系结构状态均不变；这部分未做设备验证。

`test/payload.c` 的构造函数会尝试创建 `kclf_hit_<pid>` 并写标准输出，属于可
观察副作用；具体文件访问仍受权限约束。`test/target.c` 不检查 nanosleep 返回值，
`test/phdr.c` 只枚举自身所在进程，因此现有样例不能证明目标侧没有可观测变化。

## 4. 清理与证据的限制

- `kclf_exec_finish` 在 vm_munmap 返回错误时也会清空映射字段，cleanup 调用方
  忽略其返回值。`finished` 或 `done` 不能单独证明回收成功。
- `kclf_exit` 先移除完成 hook，再有限等待；等待结束后仍返回成功，没有保证
  在所有排队或运行中的回调结束后才释放模块。这也使“安全排空”的原说明不成立。
- 完成 cookie 存放于目标参数页，属于请求关联信息，不是对目标的保密或隔离边界。
- 原文快照已显示 VMA 从 91 增至 98、VmSize 增加 36 KB，与“回到加载前基线”
  的表述矛盾。重复加载同一库获得同一 handle 也不能证明没有加载引用变化。

## 5. 2026-10-27 修改后复核

上述审计对应的源码已经修改，详见 [HARDENING.md](HARDENING.md)。修改后的状态：

| 审计项 | 修改后 |
| --- | --- |
| 3.1 持久库映射/linker 记录 | 默认仍保留；新增 `unload` 选项，构造函数返回后 `dlclose`，实测 maps 中 payload 消失 |
| 3.2 临时映射 | 从 34 页/136 KB 降到 10 页/40 KB、2 个 VMA；仍非进程级不可见 |
| 3.3 fd/线程/TracerPid | 框架行为未变；测试 payload 默认不再写文件/打印 |
| 3.4 时间与 payload 副作用 | 默认改为 `TWA_RESUME`，不再伪造 pending signal；5 秒 `nanosleep` 实测无异常。`wake` 仍可复现约 5.886 秒的耗时变化 |
| 4 清理与证据 | `munmap` 结果被检查并重试，失败会保留映射信息并报告；卸载改为先排空再移除完成 hook。仍有“目标永不返回”时无法排空的限制 |

仍未消除：默认持久加载的映射与 `dl_iterate_phdr` 记录、加载窗口内的 40 KB
匿名映射、payload 路径、linker 的短暂文件打开，以及 payload 自身行为。修改
不构成“不可检测”保证。
