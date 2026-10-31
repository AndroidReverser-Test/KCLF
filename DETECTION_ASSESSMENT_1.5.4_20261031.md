# KCLF 1.5.4：普通 App 自检的准确性与业务影响

日期：2026-10-31（Asia/Shanghai）。对象是本地实际代码和原样 `kclf.kpm`，不是历史 1.5.0/1.5.1 的测试结论。本文仅分析与验证检测，不修改注入框架。

## 结论

**没有验证到同时满足“全进程高检出率、低误报、稳定且不影响正常业务”的通用方法。** 当前实现仍然可以被普通 App 检出，但必须附带适用条件：

- 跳板指令结构与运行上下文交叉核验：有明确实现证据，适合作为高置信告警；周期扫描存在短窗口漏检、自观察盲区和可观开销。
- x16 完整性：当前实现把原 PC 留在 x16，在自有 raw-syscall 边界可以准确检出该异常；不是全 App 监测，也不是执行前拦截。
- linker 库清单/可信库名单：只覆盖显式 linker 后端及仍驻留的库；判断未授权加载，不直接证明来源是 KCLF。
- 已知 payload 内容核验：可检测已知且足够久驻留的镜像；不是不依赖 payload 的框架通用检测。

“未捕获”“读取不支持”“注入未执行”和“未注入”必须分开。以下有限负对照无报警，不等于真实业务零误报；单设备测试也不是跨 ROM 稳定性认证。结论是否定当前验收已达标，不是证明任何未来检测方案都不可能。

## 1. 实际实现

| 阶段 | 源码入口 | 对普通 App 检测的影响 |
| --- | --- | --- |
| 控制请求 | `kclf.c:kclf_cmd_inject`，4 个请求槽 | superkey 只属于外部控制器；普通 App 不应依赖管理密钥/KPM 状态作检测 |
| 排队 | `kclf_queue_work`，prepare/hijack task_work | 默认等自然返回用户态；wake 可打断可中断阻塞；不依赖 ptrace、SIGSTOP 或创建新用户线程 |
| 准备 | `kclf_exec.c:kclf_exec_prepare` | 在目标上下文打开 SO，创建临时匿名 RX 代码、RW ABI/私有页；随机布局、优先借用目标栈，必要时独立 guard/栈 |
| 默认 manual | `kclf_manual.c:map_image/scrub_headers`，`kclf_elf.c` | 内核复制 PT_LOAD、解析已驻留依赖、重定位；默认擦 ELF/程序头，不注册 bionic soinfo；不经过用户态 dlopen |
| 显式 linker | `kclf_exec.c:kclf_resolve`，`kclf_codegen.c` | EL0 调用已解析的 loader API，存在正常 linker 加载记录；遵守目标 namespace |
| 劫持返回 | `kclf_exec.c:kclf_exec_hijack` | 保存原寄存器现场，重定向 PC/SP；拒绝部分不支持状态；syscall 白名单只是启发式，不证明用户锁安全 |
| 执行与恢复 | `kclf_codegen.c:kclf_prog_build` | 执行构造/析构/导入 IFUNC 或 linker 调用；清 ABI 页，恢复 FPSIMD、SP、NZCV 及除 x16 外的 GPR，发布 token，`RET x16` 返回原 PC |
| 完成清理 | `kclf.c:kclf_token_before/kclf_work_poll_body/kclf_work_cleanup_body` | 后续普通 syscall hook 或控制器触发的 poll 读 token，再执行 RELRO/解除临时映射；无需专门的 EL0 完成 syscall |

注意：“完成阶段不调用 libc/不执行 syscall”不等于整个注入不调用函数。构造函数、导入 IFUNC、显式 linker 后端及 payload 自身仍可能调用 libc/syscall。

关键源码：[请求控制](E:/KernelPatch/kpms/kclf/kclf.c:869)、[临时映射准备](E:/KernelPatch/kpms/kclf/kclf_exec.c:983)、[手动加载](E:/KernelPatch/kpms/kclf/kclf_manual.c:654)、[返回现场劫持](E:/KernelPatch/kpms/kclf/kclf_exec.c:1270)、[x16 恢复尾段](E:/KernelPatch/kpms/kclf/kclf_codegen.c:610)、[token 观察](E:/KernelPatch/kpms/kclf/kclf.c:647)。

1.5.4 相对旧版改为 `RET x16`（机器码 `d65f0200`），旧被动识别器只接受 `BR x16`（`d61f0200`），原样主机测试退出 1。此次只扩展检测器识别两种尾指令，仍要求完整结构和运行上下文成立，没有改变生成器或 KPM。

### 为什么常见方案不能独立满足要求

1. **hook dlopen/dlsym**：manual 不经过这些入口。`dl_iterate_phdr` 遍历的是 linker 的 soinfo 列表，不是任意映射。AOSP 的实现直接遍历 solist，支持这一边界。[AOSP linker.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker.cpp)
2. **ELF magic、库名、路径、RWX、TracerPid**：默认 ELF 头被擦，镜像/跳板可为匿名 RX，框架无需 RWX 常驻或 ptrace；单个异常映射也可能是合法 JIT/保护壳/插件。不能单凭这些报警。
3. **seccomp/SIGSYS 完成事件**：1.5.1 后没有旧版完成 syscall。过滤用户态 mmap/mprotect 也不覆盖此处内核直接调用 `vm_mmap` 和 syscall handler 的准备路径；见 `kernel/patch/common/syscall.c:raw_syscall3`。TRAP 会阻止原 syscall 并产生 SIGSYS，不是纯旁观，可能冲突已有处理器或影响业务。[Linux seccomp 文档](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html)
4. **周期信号扫栈、全线程 syscall 拦截、反调试**：可能增加采样，但改变调度/信号/调用语义；payload 可不发相应 syscall，且不能把迫使注入失败当作检测成功。本轮没有在业务进程安装这些机制。
5. **匿名 RX 与 linker 清单差集**：可用作弱风险信号；manual 的特征并不等于恶意或 KCLF 身份，需要已授权动态代码的业务基线。
6. **检测 root、KernelPatch 或远端完整性**：只能说明环境/请求风险，不能证明当前进程发生了此次注入。若威胁扩大到可任意伪造内核观测或篡改检测器的对手，普通 App 自检不是独立信任根。

这里不把“对手拥有内核权限”直接用作“当前框架不可检测”的论据：当前实现没有据此自动隐藏所有映射或伪造所有自读结果，实测可以找到它。只是当问题要求抵抗任意内核级主动篡改时，保证范围必须另行限定。

## 2. 检测器与测试隔离

复用并适配 `test/passive_v151`，历史包名与事件标签 `ctx_v151` 保留，但解析器已支持 1.5.4。检测代码与测试负载位于 `probe.c`，识别器位于 `signature.h`，x16 边界位于 `gate.S`。

测试 App 为新安装的 `com.kclf.passive151`：non-debuggable、dumpable=0、普通 UID、`untrusted_app`、CapEff=0，继承 seccomp=2，未添加过滤器，no_new_privs=0。root 仅用于安装、KPM 控制和取回日志；检测器不读取 superkey、KPM 状态、payload 标记或外部提供的注入地址。

扫描线程 nice=10，读取自身 maps，仅扫描可读、不可写、匿名可执行页；每周期代码读取上限 256 KiB。识别 136 字节恢复序列的寄存器/偏移关系，解出 ABI/私有页地址；进一步校验独立 RW 页、保存 PC/SP/NZCV、token、manual/linker ABI，并重复读取关键证据。读取失败计入覆盖损失，不直接解引用可能解除映射的远端地址，不使用 SIGSEGV 恢复器。maps 与内存读取不是原子快照，重复校验只能降低竞态风险，不能完全消除。[Linux procfs 文档](https://www.kernel.org/doc/html/latest/filesystems/proc.html)

x16 检查仅在夹具自有 guarded 线程的 raw nanosleep 汇编边界进行。预置哨兵，仅在返回后 x16 精确等于该边界 PC 或 syscall 重启 PC-4 时报警，其他异常记为未确认。AAPCS 的 caller-saved 约定只适用于函数调用边界，不表示任意异步中断点都可以丢弃 x16。把检查改为普通 C 函数调用前后比较会引入无效假设。

负对照包括：完整生成代码的匿名 RX 副本但无有效上下文、同代码 RW 数据副本、正常匿名 RX 函数调用、并发创建/销毁匿名 RX、正常 dlopen/dlsym/dlclose、线程创建、分配/数据校验、文件 I/O、Java UI 动画。

注入正例由独立 payload BEGIN/END/FINI 和框架完成状态双重核对；0/2/20/200 ms 仅表示构造函数人为增加的等待，0 仍包含标记 I/O。每例注入前加入可复现 0–250 ms 随机延迟，减少与扫描相位固定对齐；仍不是生产分布抽样。所有用例均使用 wake，只注入自建测试 App，没有碰现有业务 App；不把这些数据冒充 resume、Binder、回退栈或全部线程类型的覆盖结果。

## 3. 本次产物与验证

- KCLF 子仓库起点：`515a0f0fc8641dd3f00bb54ede8c6fab0c444b9b`，初始 clean。
- 原样 KPM SHA-256：`4c8049293cf36be3397a314cc43e44bb0d11031d28e22d1238a454e570d9ccf7`。
- Pixel 6 / Android 16 / ARM64 / Linux `6.1.134-android14-11-g66e758f7d0c0-ab13748739` / 4 KiB / SELinux Enforcing。
- probe：BTF=1，pt_regs=336，nofault=1，完成观察 70/70，VMA 路径 locked。
- 10 组现有主机测试通过；检测解析器 ASan/UBSan：4/16/64 KiB 各 10,000 个 RET x16 样本、对应 BR x16 兼容样本均正确解码，错误返回寄存器样本全部拒绝，10,000 随机反例零命中。这不是运行期捕获率。
- 主机日期按本次客户端日期记录。设备壁钟与主机不一致，事件先后/耗时使用 CLOCK_MONOTONIC，不用设备日期推导实验日。

两个正式矩阵合计 148 例；早期试跑另列，不混入正式分母。

## 4. 证据与结果

### 4.1 50 ms：3 轮，111 例

证据：[summary.json](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/summary.json)、[analysis.json](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/analysis.json)。APK SHA-256：`689b35a48c70fc87b1b8b048880845fcde08958aa6aa678612abc7e4311b76d1`。

| 条件 | 检出 / 确认执行 | 检测来源 |
| --- | ---: | --- |
| manual，主线程/普通工作线程，0 ms | 0/18 | 快速注入均被扫描漏掉；包含驻留与立即卸载 |
| manual，普通线程，2 ms | 0/3 | 短窗口漏检 |
| manual，主线程/普通工作线程，20 ms | 3/18 | 上下文扫描 |
| manual，主线程/普通工作线程，200 ms | 18/18 | 上下文扫描 |
| manual，扫描线程自身，0/20/200 ms | 0/18 | 自观察盲区 |
| manual，guarded 线程，0/20/200 ms | 18/18 | x16 全部命中；上下文扫描另命中其中 7 例 |
| linker，普通新线程，0 ms | 0/6 | 此处只算通用上下文检测，没有加入已知库名扫描 |
| linker，普通新线程，20 ms | 4/6 | 上下文扫描 |
| linker，普通新线程，200 ms | 6/6 | 上下文扫描 |
| **合计** | **49/111** | **62 例确认执行但未检出** |

111/111 均确认构造完成及进程存活；57/57 立即卸载例确认析构。上下文规则单独覆盖 38 例，x16 规则 18 例，两者有 7 例重叠，不能相加成为 56 个独立检出。

代表性原始证据：[快速注入漏检](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/001-main-0us-manual-resident.events.txt)、[x16 快速注入命中](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/009-guarded-0us-manual-resident.events.txt)、[200 ms 扫描命中](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/021-main-200000us-manual-resident.events.txt)、[扫描线程自身漏检](E:/KernelPatch/build/kclf-passive-03c22ff3bb90/027-scanner-200000us-manual-resident.events.txt)。

0 ms guarded 的首个检测约晚于构造开始 5.3–5.5 ms，发生在返回检查边界后，不是拦截首次执行。上下文命中可以发生在构造期间，同样无法撤销已经发生的副作用。

### 4.2 250 ms：1 轮，37 例

证据：[summary.json](E:/KernelPatch/build/kclf-passive-74cb9ead2ae6/summary.json)、[analysis.json](E:/KernelPatch/build/kclf-passive-74cb9ead2ae6/analysis.json)。APK SHA-256：`d5d3cd593712d4bcfbc884d2d02a95be420db669dcc49c06148ec55222d4972a`。

| 条件 | 检出 / 确认执行 |
| --- | ---: |
| manual，主线程/普通线程，0 ms | 0/6 |
| manual，普通线程，2 ms | 0/1 |
| manual，主线程/普通线程，20 ms | 0/6 |
| manual，主线程/普通线程，200 ms | 3/6 |
| manual，扫描线程自身，0/20/200 ms | 0/6 |
| manual，guarded 线程，0/20/200 ms | 6/6 |
| linker，普通线程，0/20/200 ms | 0/2、0/2、1/2 |
| **合计** | **10/37** |

37/37 构造完成且存活；19/19 立即卸载例确认析构。两组正式矩阵共 **59 检出、89 漏检**；x16 在受保护边界 24/24，扫描线程自身 0/24。这个矩阵比例不是自然业务分布上的“准确率”，更不是 24/24 全 App 可靠检测。

### 4.3 性能与负对照

基准没有加载 KPM；同一 App 进程按 `0,1,1,0,1,0,0,1` 开关扫描，每段预热 1 秒、计量 4 秒，每种状态约 16 秒。CPU 为扫描段的线程 CPU 时间除以墙钟时间，以一个逻辑核为 100%，不是整机占比，也未计入全部间接系统成本。

| 指标 | 50 ms 周期 | 250 ms 周期 |
| --- | ---: | ---: |
| 开扫描的 CPU | **单核 29.47%** | **单核 6.91%** |
| 平均每次扫描 CPU | 14.88 ms | 17.27 ms |
| 工作循环吞吐：关 → 开 | 181.80 → 170.04 次/秒 | 182.23 → 179.55 次/秒 |
| 观察到的吞吐变化 | −6.47% | −1.47% |
| UI 帧间隔 p99 所在桶上界 | 各阶段 12 ms | 各阶段 12 ms |

这些是带并发 maps churn 的当前夹具测量，不是所有扫描实现的下界，也未控制设备调频/温度。吞吐差异没有额外统计显著性检验。两轮平均耗时不能在不同调度状态下直接等同比较。UI p99 未变化不等于无功耗、长尾或实际业务影响。

扫描耗时 p99 均进入直方图末桶，工作耗时在 50 ms 开扫描的四段也均进入末桶。**末桶饱和，不能说“扫描 p99 ≤12.8 ms”或“工作 p99 ≤6.4 ms”**。已修正汇总器，单独标注饱和，不把末桶当上界。

两个无 KPM 压力基线各运行约 10 秒：197/41 次扫描均拒绝完整指令模板假阳性；正常业务循环 1,758/1,781 次、匿名映射 churn 3,542/3,782 次、guarded 正常调用 1,973/1,920 次，检测阳性和业务校验错误均为 0。两组 8 段配对基准同样无阳性/业务错误。没有大规模真实 App 负样本，因此不计算生产误报率或精确率。

148 个注入用例的保留健康快照合计：业务循环 39,744 次、映射 churn 86,074 次、guarded 调用 42,755 次、业务错误 0、未确认 x16 变化 0、maps 解析错误/扫描预算饱和 0。自读失败 **782 次**，明确保留为覆盖损失；快照不是进程退出前的精确总计。

主线程注入 200 ms 等待 payload 时，帧间隔最大观察到约 322 ms（50 ms 组）/289 ms（250 ms 组）；这是包含 payload 主线程阻塞和调度的注入实验，不应混同于“纯检测器开销”。

### 4.4 稳定性、清理与失败记录

- 当前正式两组逐例确认执行后 PID 仍存在，没有业务校验错误。
- 前后 main/crash 的 libc fatal、DEBUG fatal、AndroidRuntime error 日志均为空；保留的 App 退出记录仅见测试驱动主动 FORCE STOP。退出记录有容量上限，不据此承诺捕获任意历史故障。
- 每例停止自建 App 后检查 dmesg，与起始日志比较，未发现新增 BUG/WARNING/Oops/panic/lockup/RCU stall 匹配；没有清空系统日志。正则检查不是全面内核认证，也不说明历史 `dec_rlimit_ucounts` 风险已经解决。
- 每轮结束停止且卸载本轮测试 App，`reap`、明确 `quiesce=idle` 后卸载本轮 KPM；各轮保存的终态均为 `kpm num=0`、无测试进程，轮内 SELinux/boot_id 不变。
- 完成实验后的另一次只读复核发现 boot_id 已改变，系统报告 `sys.boot.reason=shutdown,userrequested`、`ro.boot.bootreason=reboot`，pstore 目录为空。助手没有执行重启，也不能仅凭属性确认操作者或归因；因此只声明**各保存实验窗口内未重启**，不声明整段对话设备从未重启。该复核仍为 KPM=0、测试包/进程不存在、SELinux Enforcing。详见[末次核对记录](E:/KernelPatch/build/kclf-detection-1.5.4-20261031/FINAL_VERIFICATION.md)。
- 只删除本轮精确命名的远端 KPM 文件和空目录。APK、源码快照、原样 KPM 副本、日志和 JSON 全部保留在主机，测试 App 可由这些 APK 重新安装。
- 初始试跑 [877dc682d3df](E:/KernelPatch/build/kclf-passive-877dc682d3df/summary.json) 完成 1 个正例后，日志检查把 `binder_debug` 中的 `bug:` 子串误报为 BUG，按安全策略终止。核查原文后添加单词边界，不是删掉真实告警；这次记录不算正式通过矩阵。
- 修正后的 [06bb4dead406](E:/KernelPatch/build/kclf-passive-06bb4dead406/summary.json) pilot 为 6/6 执行存活、3 检出/3 漏检、清理正常；也没有混入正式分母。

### 4.5 哪些结论没有在本轮直接实测

| 方法 | 证据层级 | 尚不能声称 |
| --- | --- | --- |
| 跳板上下文识别、x16 受控边界 | 当前 1.5.4 真机 + 当前生成器主机解析测试 | 全线程/全部 ROM/任意 payload 高召回、零误报 |
| linker 清单 + 授权名单 | 当前加载路径源码与 AOSP 枚举实现 | 本轮已经测出该方案的检出率、误报率或 loader 锁成本 |
| 无头已知 payload 全段内容比对 | 当前 PT_LOAD 复制实现及历史研究；本轮未新增此检测器 | 未知 payload 通用识别、自动归因 KCLF |
| 旧版 seccomp 完成签名失效 | 当前生成器无完成 syscall、主机检查；另有 1.5.1 历史自检数据 | 把历史 45/45 或 0/45 当作本轮 1.5.4 真机结果 |
| 禁止用户态 executable mmap/mprotect 不能覆盖本路径 | 当前内核直接映射/调用 handler 源码；历史旧版测试 | 本轮已经部署这种过滤器或证明所有执行保护无效 |

## 5. 复现

只修改检测夹具、汇总和文档，生产 `.c/.h` 与 `kclf.kpm` 未改。运行前要求设备 KPM 数量为 0、测试包不存在；不要为了满足条件卸载他人的模块或覆盖现有包。

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
    python -B E:/KernelPatch/kpms/kclf/test/passive_v151/run.py --serial 25091FDF60063J --suite full --rounds 3 --period-ms 50 --jitter-ms 250 --extended-linker
    python -B E:/KernelPatch/kpms/kclf/test/passive_v151/run.py --serial 25091FDF60063J --suite full --rounds 1 --period-ms 250 --jitter-ms 250 --seed 154250 --extended-linker
} finally {
    Remove-Item Env:KCLF_SUPERKEY -ErrorAction SilentlyContinue
}
```

`--suite bench` 只做无 KPM 压力与开关配对基准；`--build-only` 不操作设备。`summarize.py <证据目录>` 只离线分析。驱动新增源码/原样 KPM 快照、随机延迟和内核告警停止条件；密钥不保存到源码或证据。

## 6. 面向真实业务的取舍

如果“不会影响业务”指绝对零开销、零副作用，并同时要求任意线程/短窗口高检出，当前没有合格方案。如果允许可量化且经过业务验收的轻微成本，可以采用：

- 低优先级、限预算的多证据只读检测；阳性记录为“匹配当前实现的运行上下文”，不是恶意来源的数学证明。
- 对显式 linker 库、允许的动态代码和已知 payload 增加业务白名单/可信内容校验，但分别标注适用范围。
- 初期只上报，不杀进程、不拒绝 syscall、不改 libc/ART、不因单个匿名 RX/root 信号阻断正常用户。将不支持、读失败和预算不足作为独立状态。
- x16 检查仅考虑可控制、已验证的自有 native 边界；不能通过单独开一个 guarded 线程保护所有线程。
- 若已有服务端敏感交易，可把设备/应用完整性作为另一个风险维度，不称为 KCLF 检测。Play Integrity 评估 app、设备和请求环境，不能从其 verdict 推导具体注入来源。[Android 官方说明](https://developer.android.com/google/play/integrity/overview)

低频扫描可以减少成本，但会进一步降低短窗口检出；多扫描线程可减少某个自观察盲区但增加开销，不能消灭窗口遗漏。未测试的替代算法可能改善效率，不能把本夹具性能外推为所有实现的性能下界。

从采样角度，若检测证据仅存在 W 时间、扫描周期为 T，且理想化为独立均匀相位与瞬时采样，命中概率约为 `min(1, W/T)`。实际扫描耗时、线程调度、预算、读取失败使该模型更加不乐观；构造函数 hold 时间也不等于真实 W，不能用此公式替代实测。驻留 payload 并不意味着用于识别框架的跳板仍然驻留。

建议对外接口至少区分：`MATCHED_CONTEXT`（多证据匹配）、`SUSPICIOUS_MAPPING`（弱信号）、`NOT_OBSERVED`（本轮没有观察到）、`UNSUPPORTED_OR_READ_FAILED`（没有有效覆盖）。不要把后两者命名为 CLEAN；初期只记录，在真实业务压测、误报语料和分机型灰度通过后才考虑响应策略。

如果明确只关心某个已知长期驻留 SO，可信参考内容 + 映射权限/段布局交叉核验更契合需求：按可信 ELF 的多个不可变可执行/只读段校验，处理被擦的头以及重定位/可变范围，再核验 linker 注册状态。不能用一段 32 字节通用代码或字符串作最终阳性；合法加载同一镜像仍需产品授权语义。此处给出的是适用方案边界，并非本轮已验证的新 SDK。

如果只关心 linker 后端，优先正常 `dl_iterate_phdr`/加载清单与受信库策略，而不是逆向私有 soinfo 结构；回调只复制有界元信息、重计算移到回调之外，避免延长 loader 锁持有时间。它同样只能观察仍在清单中的库，且不能覆盖 manual 或已经卸载的短窗口。有关锁的判断来自 [AOSP dlfcn.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/dlfcn.cpp)，尚未作为本轮性能数据。

生产验收仍需真实 APK、ART/JIT/WebView/动态功能/保护壳、不同 ROM 和页大小、长期功耗、信号重入、崩溃/ANR 与误报语料；本轮不宣称完成这些认证。
