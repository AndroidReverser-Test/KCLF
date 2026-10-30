# KCLF 1.4.1 可观测性报告

> **当前结论入口（2026-10-30）**：[1.4.3 检测点与稳定性评估](DETECTION_POINTS.md)。
> 本文只描述 1.4.1 历史实验。新版本不再满足旧固定跳板/getpid 和 ELF 头锚点的前提，
> 但仍有可归一化的 208 字节尾段；其主机验证通过，完整 App 方案待验收。当前夹具已
> 删除下文方法 A 的实现，不能用 KCLF_EXEC 无事件声称重新实测了旧规则。
> 1.4.3 的 32 字节内容规则还会命中另一份测试 ELF，详见新报告勘误。

报告日期：2026-10-30（Asia/Shanghai）。对象为历史 KCLF 1.4.1 ARM64 实现。
本文替换并删除旧的 `OBSERVABILITY_AUDIT.md`；旧文中的默认 dlopen、34/10 页
临时区、寄存器与清理问题不再作为当前事实。

## 1. 结论与判定范围

**当前版本可以被目标普通 App 确认检测，但必须满足具体检测条件。** 本次在
非 debuggable、non-dumpable、无 capabilities 的普通 App 中实际验证了两种方法：

| 方法 | 只有满足全部条件才报告什么 | 真机结果 | 覆盖边界 |
| --- | --- | --- | --- |
| A：真实完成 syscall 的完整跳板指纹 | 被保护线程执行了当前 KCLF 的 trampoline 完成路径 | manual/linker × 驻留/unload，各 5 次，共 20/20 | 提前安装线程 seccomp；本例主动阻断完成 syscall 并终止自身 App |
| B：已知 payload 内容与加载段核验 | 已知 ELF 的全部非可写加载段存在于本进程的匿名可执行镜像中，且未登记到 linker | manual 驻留加载/释放 5/5 | 必须预先有可信内容参考；只能确认该已知镜像，不能单独归因 KCLF |

上述数字是本设备、本版本、这些测试条件下的结果，**不是所有应用的准确率估计**。
没有把“发现匿名 RX”“ELF 不在 linker 列表”“线程变慢”等现象列为独立有效判据。
被排除的方法及原因集中在第 7 节。

“普通 App”在这里指被注入进程自身运行检测代码，检测线程的 UID 仍是应用 UID。
本次没有证明另一个不同 UID 的普通 App 能扫描目标；也没有证明任意现成应用默认
部署了这些检测。检测到某段代码或某份镜像，也不自动等于恶意行为。

本报告没有一个适用于未知 payload、所有线程、任意内核改动且事后仍零漏报的
通用检测器。对未知代码，仅凭映射或 linker 差异无法消除合法自定义加载器的解释。

## 2. 对应实现与产物

| 项目 | 本次使用值 |
| --- | --- |
| KCLF 版本 / 框架提交 | 1.4.1 / `894bbf43b3d31495d1e03b1e89949b15ac3c9b05` |
| KPM SHA-256 | `8749c287f1243d433f26e6b0a6e86b32a7136860adc9c4369fe5db881ebd7f59` |
| 测试 payload SHA-256 | `1aca043f7c8cdb3856495c6aaedfa9bd03d9dad01cfc6cacb66f5e62a452a651` |
| 原始 trampoline 长度 / SHA-256 | 548 字节 / `8f85c51973162649380f1484b1925f10bcc753e740f9b5807cf742f1f1185632` |
| 设备 / 系统 | Redmi rubens，Android 12 / API 31，ARM64，Linux 5.10.66 |
| 内存页 / SELinux | 4096 字节 / Enforcing |
| 自有测试包 | `com.kclf.obsprobe`，`debuggable=false`，targetSdk 35 |
| 检测线程实测权限 | UID/EUID 10259，CapEff=0，dumpable=0，`untrusted_app`，Seccomp=2 |

在独立 build 目录从源码重新构建 KPM，结果与工作区 KPM 的哈希完全相同。
没有使用设备上此前哈希不同的 `/data/local/tmp/kclf.kpm`。探针链接的汇编参考由
NDK 另行编译，驱动先逐字节确认它与本次 KPM 对象的 trampoline section 一致。

完整版本、正反例 PID/TID、产物哈希与示例事件保存在
[证据索引](test/observability/EVIDENCE_20261030.json)。
原始运行目录为工作区 `build/kclf-observability-c38359af47ea/`，不把历史运行当作
本次检测证据。

## 3. 当前注入链与实际可观测对象

1. `kclf.c:kclf_cmd_inject` 接收 ctl0 请求，以稳定 PID/mm 身份关联目标 TID，
   用 task_work 排队。默认自然返回用户态，`wake` 请求 TWA_SIGNAL。
2. `kclf_exec.c:kclf_exec_prepare` 在目标上下文分配临时区：代码、参数、guard、
   8 页栈，共 11 页；本机为 45056 字节虚拟空间。代码 RX、参数 RW、guard
   PROT_NONE、栈 RW。相邻 VMA 合并会影响条目数，不能用固定 VMA 数判定。
3. 默认 manual：`kclf_manual.c` 用目标凭据读文件快照，匿名映射 PT_LOAD，解析
   已驻留依赖，完成重定位与权限/RELRO；不修改 bionic soinfo。ELF 头和映射内
   动态元数据仍保留。显式 `linker` 才调用已解析的 loader 入口。
4. 修改返回帧 PC/SP，trampoline 在 EL0 保存 FPSIMD、执行 IFUNC resolver、
   必要的直接 mprotect syscall 和构造/析构。默认保留 payload 镜像。
5. 擦除参数已用区后，`svc getpid` 以 x0 携带 cookie。KPM getpid hook 校验上下文，
   恢复原寄存器，再用 cleanup 回收临时区。manual 最后 release / 适用的 unload
   才解除镜像映射。

对应源码：[控制与完成](kclf.c)、[临时映射与上下文](kclf_exec.c)、
[手动加载与生命周期](kclf_manual.c)、历史 EL0 跳板 `kclf_tramp.S`（当前已删除）、
[共享参数布局](kclf_param.h)。加载器语义详见 [MANUAL_LOADER.md](MANUAL_LOADER.md)。

## 4. 方法 A：确认当前 KCLF 完成路径确实执行

### 4.1 原理与完整判据

KCLF 的 getpid hook 位于 syscall handler；目标从 EL0 发起 syscall 时，已有的
seccomp 策略仍先执行。本例让被保护线程的 getpid 返回 `SECCOMP_RET_TRAP`，由
App 的 `SA_SIGINFO | SA_ONSTACK` SIGSYS handler 检查现场。
安装路径是线程自己的 `PR_SET_NO_NEW_PRIVS` 和 `PR_SET_SECCOMP`，不需要 root。
接口语义参见 [Linux seccomp 文档](https://docs.kernel.org/userspace-api/seccomp_filter.html)。

**只有同时满足以下条件，探针才输出 `KCLF_EXEC`：**

1. 信号为 SIGSYS，`si_code=SYS_SECCOMP`，架构为 `AUDIT_ARCH_AARCH64`，
   `si_syscall=__NR_getpid`。使用内核提供的信号上下文 PC，不相信任意 maps 名字。
2. 由 `ucontext.pc - 544` 推出代码基址，要求页对齐，并安全读到完整 548 字节。
   544 是当前 `kclf_tramp_return` 相对起点的偏移，现场 PC 在完成 `svc` 后。
3. 比较整个 trampoline 的全部指令。仅对偏移 92 起四条 movz/movk 指令的 imm16
   地址字段屏蔽；opcode、目标寄存器 x19、移位字段和其余所有字节必须一致。
   不是只匹配 `svc`、getpid 号或短指令串。
4. 解码四条指令，确认它们形成的参数地址等于 `代码基址 + page_size`。
5. 参数前 `0x1c0` 字节已经全部清零，现场 x0 非零，与当前完成路径顺序相符。
   cookie 不作为密码或独立判据。

实现为 [probe.c](test/observability/probe.c) 中的 `exact_trampoline`、
`syscall_trap`、`install_guard`；构建比对见 [run.py](test/observability/run.py)。
参考字节来自本次已核验的源码/产物，不在运行时从待扫描匿名区自动学习。

### 4.2 为什么不会把普通运行现象直接判成 KCLF

匿名 syscall、JIT、普通 getpid 都不自动命中：还必须位于完整匹配的跳板完成 PC，
并满足指令解码和参数状态。探针自己的库中虽然含参考代码，但它只是正常登记的
DSO 内容，没有在该完成现场执行，也不满足匿名临时参数页关系。

本例特意让普通匿名代码的 getpid 返回 PC 与 KCLF 一样落在**页内偏移 544**；
完整内容不同，因此未报警。此反例排除了“只检查 PC 页内偏移”的伪精确规则。

阳性可以证明“当前 KCLF 跳板代码的完成路径发生在受保护线程中”。如果另一个
实现故意执行完全相同代码和 ABI，它也满足这一定义；不能仅凭用户态证据唯一
证明内核里模块的名称或作者，更不能推导行为是否被用户授权。

### 4.3 真机证据与副作用

manual/linker × 驻留/unload 四组各运行 5 次，20 次都输出一次完整匹配事件。
例如：

```text
REFERENCE bytes=548 patch=92 completion=544
KCLF_EXEC pc=0000007338d0c220 base=0000007338d0c000 cookie=6e0146760d6db56a
```

独立 KPM 状态对应：

```text
state=running stage=loader map=7338d0c000+45056
hook=getpid loading=1 page=4096
```

此处 `running` 是预期结果：seccomp 拦截了完成 syscall，KPM hook 尚未收到它。
探针记录证据后主动 `_exit(86)` 终止自身进程，控制端等进程退出后 reap；**没有
把拦截后的状态当成正常注入完成**。每次均有独立 payload init 标记，unload
组另有 fini 标记，证明检测发生在构造/相应析构执行之后。

这是一种有明确副作用的主动确认，不能用于声称“无感检测”或“构造函数运行前
阻止注入”。过滤器安装后不可撤销，并增加 getpid 处理开销。

### 4.4 必需前提与未覆盖范围

- 必须在注入前安装到**实际被注入的线程**。本例只在 `kclf-observe` 用 prctl
  安装线程局部过滤器；未实测 TSYNC 或整个进程所有现有/未来线程的覆盖。
- 平台须允许追加该 seccomp 策略、安装 SIGSYS/备用信号栈和安全读取自身代码。
  本机实测满足；其他 ROM 不能直接沿用此通过结论。
- 模板绑定当前 548 字节实现。源码、ABI 或完成机制改变后必须更新并重新验证。
- 若 payload 不返回、在完成前改变信号/seccomp 环境或导致进程退出，不能保证
  到达此检测点。未命中不能推出没有注入。
- 测试中非匹配 getpid 被模拟返回缓存的进程 PID，夹具不会 fork。实际应用需
  处理 fork、原有 SIGSYS handler、信号栈和线程生命周期，不能原样移植即承诺全覆盖。

## 5. 方法 B：确认一份已知 payload 的手动驻留镜像

### 5.1 适用问题

当防护方事先知道某份 payload 的准确内容时，可以确认它是否以手动镜像驻留。
本例参考为测试 APK 中预置的 `libobspayload.so`，检测过程中不执行这份参考文件。
真实部署应将参考内容随可信检测组件提供并固定版本，不能信任攻击者可修改的参考。

**此规则只输出“该已知镜像存在”，不把任意未知 ELF、任意自定义加载器或任意
maps/linker 差异直接判为 KCLF。** 若业务本来授权以同样方式加载同一份代码，
业务必须自行区分授权状态；内容检测不能替代授权来源验证。

### 5.2 完整判据

`known_manual_image` 必须同时确认：

1. 候选可读匿名区域的 ELF 头与已知参考完全相同，而非仅检查 ELF magic。
2. 根据可信参考的 PT_LOAD 和候选地址推导 load bias。
3. 每个 PT_LOAD 的内存范围均实际存在于匿名、可读映射中；参考的可执行段
   对应映射也必须可执行，且至少有一个可执行 PT_LOAD。
4. **全部非可写 PT_LOAD 的文件内容逐字节匹配**。可写段会被重定位或运行时
   修改，不用于内容相等判断；不使用 basename、SONAME、短字符串或 ELF magic
   作为身份确认。
5. 该 load bias 不在 `dl_iterate_phdr` 登记列表中。

`dl_iterate_phdr` 枚举 linker 的 soinfo 列表，其单独缺项不代表注入；本例只在
已确认完整已知内容与可执行加载布局后使用这一步。接口依据见
[Android 12 linker 源码](https://raw.githubusercontent.com/aosp-mirror/platform_bionic/android12-release/linker/linker.cpp)。

内容读取用 `process_vm_readv` 指定本进程自身，避免直接解引用已经被并发解除的
地址；短读或读取失败一律放弃本次候选，不产生阳性。`/proc/self/mem` 在此
non-dumpable App 内实际返回 EACCES，但不妨碍本机此检测读取方式。

### 5.3 真机结果与含义

在无额外 guard 的普通检测线程中，注入成功、临时区完成回收后，5 次加载都输出：

```text
KNOWN_MANUAL base=7338c08000 exact_readonly_loads=1 anonymous_loads=1 registered=0
```

每次由控制端独立记录 KPM 的 resident 范围，再核对 App 报出的地址位于该范围。
最后一次 release 后输出 `KNOWN_GONE`；共 5 次出现、5 次消失。完整循环事件与
对应 KPM 状态见证据索引和原始运行目录。

这确认了已知内容确实可由普通 App 检测。它不证明镜像由哪一个内核模块创建，
也不证明所有可写数据未被修改、构造函数一定执行或未知 payload 一定会被发现。
构造执行的事实在测试中由另外的 marker 证据提供。

此规则适合驻留期确认；100 ms 轮询不保证捕获短暂 unload。已知 payload 改版、
只读段运行时变化、读取被策略禁止、并发映射变化都可能导致漏检。未命中含义为
“本轮没有确认这份已知镜像”，不能表述为干净或未注入。

## 6. 验证矩阵、反例和清理

| 用例 | 实测结果 |
| --- | --- |
| 方法 A：manual 驻留 | 5/5 在实际完成 syscall 处确认 |
| 方法 A：manual unload | 5/5 确认；init/fini 已发生 |
| 方法 A：linker 驻留 | 5/5 确认 |
| 方法 A：linker unload | 5/5 确认；init/fini 已发生 |
| 方法 B：manual 驻留 / release | 5/5 匹配；5/5 释放后消失 |
| 无注入、普通匿名 RX、完整 ELF 数据副本 | plain/normal/guard 三种基线均无误报 |
| 正常 dlopen 加载同一已知 payload | 未被方法 B 误判为手动镜像 |
| 普通 getpid API 与页内同偏移的匿名直接 syscall | 每个基线各调用 100 次；guard 的匿名直接 syscall 确认有 100 次 TRAP，0 次 KCLF_EXEC |
| 另一份有效 ELF 经当前 manual 后端驻留 | 未被方法 B 误认成已知 payload；方法 A 未在该用例启用 |

普通 API 是否真正进入内核取决于 libc 实现，不用 API 调用次数冒充 seccomp
事件次数。基线记录中有 100 次真实匿名 syscall trap，已确认过滤器实际工作。

测试 APK 中包含未执行的完整 trampoline 参考字节和 payload 参考文件，本身没有
引起误报。ELF 数据副本则专门验证“内存里存在 ELF 文件内容”不足以成立方法 B。

本次检测 App 未提权；ADB/root 控制端负责模块加载、发起测试注入和读取 App
已经产生的私有证据文件。没有把 root 读取 `/proc/<pid>/maps` 的能力当作普通
App 检测能力。测试未使用 `/proc/self/mem` 作为检测读取途径。

结束时 `quiesce=idle`、`kpm num=0`，测试包已卸载，boot ID 与 SELinux 状态
未变化，dmesg 前后差分没有新增 BUG/WARNING/Oops/panic。独立运行目录和
临时 KPM 文件保留用于复核，未改动生产框架源码。

复现入口与操作边界：[test/observability/README.md](test/observability/README.md)。
自动化不记录 superkey。证据 JSON 里保存全部已完成用例，而非只保留成功截图。

## 7. 已排除的方法及原因

下列项目保留供审阅，但**不作为本报告的独立阳性判据**。有些确实能观察到变化，
仍达不到本次要求的明确归因；另一些在默认后端根本没有覆盖。

| 方法 | 能说明什么 / 排除原因 |
| --- | --- |
| 仅发现匿名 RX、匿名 ELF、inode=0 | JIT、运行时生成代码、合法手动加载、ELF 数据副本均可能出现。匿名和 ELF 不是来源证明 |
| maps 有 ELF、dl_iterate_phdr 没有 | 合法自定义加载器同样不登记 soinfo；加载/卸载并发还会产生瞬时差异。必须附加明确内容与业务条件 |
| 对 RX 区调用 dladdr 失败 | 只能说明 linker 没有识别该地址；JIT/代码缓存同样如此 |
| 文件路径含 local/tmp、陌生 so、basename/SONAME 黑名单 | 路径和名称不证明内容及加载来源；允许的插件也会出现陌生路径，manual maps 通常没有原始文件路径 |
| linker 新增库、dlpi_adds/subs 变化、库数量变化 | 正常 dlopen、插件和 SDK 初始化都会触发；默认 manual 不登记 linker，单独依赖会漏检 |
| Hook dlopen/dlsym/android_dlopen_ext | 默认 manual 不经过这些 API；旧后端还可能直接调用 __loader_dlopen，单 Hook 公共入口覆盖不足；合法调用不能直接判注入 |
| Hook libc open/read/mmap/mprotect | 框架准备在内核上下文处理，未必经过 libc；payload 自身 API 行为又可能完全合法 |
| 仅匹配 svc/getpid、固定 syscall 号或异常 x0 | 普通 syscall、直接 syscall、未使用参数寄存器的任意残值都常见，不能确认来源 |
| 仅匹配 trampoline 短指令串或完成 PC 页内偏移 | 普通匿名代码可以具有相同指令或偏移；第 4 节反例实测同偏移 syscall 不报警 |
| 发现 11 页/44 KiB 空间、guard 或固定 VMA 数 | 线程栈和运行时也使用 guard；VMA 可合并、页大小可变，数量或大小没有唯一性 |
| VmSize/RSS/PSS、缺页计数或 VMA 数增加 | GC、堆扩展、JIT、线程和文件映射都影响这些统计，阈值无法可靠区分 |
| sleep 变长、EINTR、卡顿、wake、CPU 时间异常 | 调度、GC、真实信号和负载均可导致；最多是排障现象，不能明确归因 KCLF |
| 线程/fd 数、线程名、新文件、日志或 payload marker | 取决于 payload；正常业务也能产生，静默 payload 则可能没有。marker 仅用于受控测试证明构造执行 |
| TracerPid=0 或调试器检查 | 当前框架不 ptrace；零值无法排除注入。非零也可能是合法调试器，并非 KCLF 特征 |
| 发现 root、KernelPatch、kpatch 文件或完整性服务异常 | 只能说明设备环境，不能证明该进程被 KCLF 注入；文件可访问性/远程判定还有独立限制 |
| 读取 kpm 列表、内核 hook 地址、dmesg、任意目标 maps | 依赖 superkey/root、内核可见性或跨 UID 权限；不属于已经证明的普通 App 自检方案 |
| errno/TLS、异常栈回溯、CFI 或 JNI 状态异常 | payload 和异步插入可能影响这些状态，但没有唯一值/现场可确认来源；兼容性故障不是可靠指纹 |
| 一次事后 maps 扫描未发现镜像 | unload/成功清理后本来就可能不存在；只能报告未确认，不能证明从未执行 |
| 只看到 SIGSYS、getpid 被过滤或过滤器安装失败 | 其他策略/程序行为同样会触发。只有方法 A 的完整现场核验才产生本报告定义的阳性 |

## 8. 最终可支持的表述

- 当前 KCLF 1.4.1 的真实完成路径，可由事先配置好的普通 App 线程以完整
  trampoline 指纹确认；本机验证覆盖两种后端及驻留/unload。
- 已知 payload 的完整非可写加载段，可由普通 App 在其驻留期确认；本机验证
  在 non-dumpable、self/mem 不可读的情况下仍成立。
- 第 7 节各项单独使用均不满足本次报告的判定要求。没有将“存在异常现象”
  扩大成“KCLF 已被唯一识别”，也没有将有限反例测试扩大成普遍零误报保证。
