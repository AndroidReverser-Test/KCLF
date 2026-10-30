# KCLF 1.4.2/1.4.3 可观测性加固报告

报告日期：2026-10-30（Asia/Shanghai）。对象为当前 `kpms/kclf` 的 ARM64 实现。
本文说明 1.4.2 针对 [1.4.1 可观测性报告](OBSERVABILITY_REPORT.md) 第 4、5 节两个
已真机确认的检测点所做的修改，以及 1.4.3 对静态标记和临时映射布局的追加加固，
并给出真机验证结果和仍然存在的残余暴露。

## 1. 结论

- 1.4.1 报告里的两种方法（方法 A：完整跳板指纹；方法 B：已知 payload 的
  ELF 头与加载段内容）在 1.4.2 上**不再产出阳性**；1.4.3 上仍然如此。这两种
  方法的判定条件本身没有变化，变的是被观测对象。
- 1.4.3 另外消除了 1.4.2 生成代码中的固定 `KCLFBAIL` 字面量和固定临时映射布局：
  恢复 token、延迟 RELRO 的系统调用号和入口重启指令都改为每请求随机，四个映射块
  随机排序并填充随机数据。
- 注入本身、manual/linker 两种后端、`wake`/`unload`/引用计数/`release`/
  `quiesce` 语义均保持不变；真机回归通过。
- **不是不可观测**。payload 的只读/可执行内容只要还在本进程可读映射里，持有
  参考内容的普通 App 仍然可以按内容扫描确认；临时映射、时序和 payload 自身
  行为也仍然可见。第 5 节把这些残余面单独列出，不把“旧规则不再命中”扩大成
  “无法检测”。

## 2. 被绕过的两个检测点（1.4.1）

1. 方法 A：被保护线程安装 `getpid` 的 seccomp `SECCOMP_RET_TRAP`。KCLF 的
   EL0 跳板在构造/析构后执行 `svc` 完成自陷；SIGSYS 现场 PC 减去固定偏移
   得到页对齐的代码基址，再逐字节比较 548 字节固定跳板、解码 movz/movk
   参数指针、核验参数页前缀已清零。
2. 方法 B：把已知 payload 的 ELF 头放在匿名可读映射的**起点**，要求各
   `PT_LOAD` 被匿名可读映射覆盖、至少一个可执行段、非可写段文件内容逐字节
   相同，且该基址不在 `dl_iterate_phdr` 中。

## 3. 加固设计

### 3.1 每次请求生成 EL0 程序

`kclf_tramp.S` 已删除，改为 `kclf_codegen.c` 在目标上下文生成 AArch64 程序：

- 代码页先整体填入随机字，不再由零字节围出固定 blob。
- 入口偏移每次随机（16–128 字节、16 字节对齐）；`svc` 完成点因此不在固定
  页内偏移，`pc - N` 类的锚点不再成立。
- 十个通用寄存器角色（参数页、私有页、向量游标、计数、返回码、临时量、
  候选游标、cookie）随机分配到 `x19`–`x28` 的一个随机置换。
- 32 个 FPSIMD 寄存器随机配对、按随机顺序写入随机的 32 字节槽位，恢复时
  使用同一映射；FPCR/FPSR 也使用随机临时寄存器。
- 在多个安全点插入 0–5 条随机填充指令（movz/movk、add、eor、nop 等），
  只写死临时寄存器，不改变最终状态。
- 参数页地址用完整 movz/movk 序列生成；程序里没有字面系统调用号。

完成协议也改了：

- 只有一个 `svc` 站点；`x8` 在运行时从私有参数页（第二页）读取，并与每请求
  随机的 32 位 key 异或。代码中没有可静态提取的完成系统调用号。
- 内核从候选池中为每个请求随机挑选 2–3 个**不同的**完成系统调用写入私有页。
  候选池为 `read`、`write`、`futex`、`clock_gettime`、`ioctl`、`epoll_pwait`、
  `nanosleep`、`sched_yield`。刻意排除 `getpid`/`gettid`/`getuid` 等信息类
  调用：它们正是探测器可以无副作用 trap 的集合，1.4.1 也把 `getpid` 用作固定
  完成点。候选都按“参数错误时在触碰用户内存前失败”的方式传参（EBADF/EFAULT/
  EINVAL），即使内核 hook 未消费也不会产生真实副作用。
- 若某个候选被 seccomp 转成信号（或在旧宿主上未被消费），EL0 程序继续下一个
  候选；全部失败时写入 `KCLF_BAIL_MAGIC`，从私有页恢复 `x0`–`x30`、`sp`、`pc`
  和 NZCV，直接跳回被中断的 PC，而不是挂死线程。`x16`（IP0，ABI 调用者保存）
  是该应急路径唯一不恢复的寄存器。
- 内核在目标下一次进入任一候选系统调用时读取私有页 marker，回收临时映射并把
  请求标记为完成（`err` 字段说明完成被阻断）。清理用 `TWA_SIGNAL`，避免目标
  正阻塞在 `epoll_pwait` 时无法排空。
- 临时映射布局随机：`[RX code][可选 gap][RW ABI 参数页][RW 私有页]
  [PROT_NONE guard][RW 栈 6–14 页]`。1.4.1 的“11 页 / 44 KiB、参数紧跟代码
  页”的关系不再固定。

### 3.2 manual 镜像

- 映射长度增加 1–8 页随机前导 pad 和 ELF 对齐空洞；pad 与第一个 `PT_LOAD`
  使用相同权限做 `mprotect`，由 `vma_merge` 合并成一个 VMA。于是 ELF 头页是
  某个映射的**中间**，而不是任何 VMA 的起点。1.4.1 方法 B 的候选枚举以
  `maps` 区域起点为锚，这一步就已经失效。
- 默认擦除 ELF 头（64 字节）和程序头表。manual loader 在映射后已经消费完
  这些元数据；本后端拒绝 payload TLS、payload IFUNC/IRELATIVE、textrel 和
  GNU property，不登记 bionic soinfo，运行时没有任何路径重新读取它们。这样
  即使探测器逐页扫描，也找不到已知 ELF 头。
- 需要读取自身 `__ehdr_start`/ELF 头的 payload 可以显式使用 `keepelf`：保留
  头内容，但仍有随机 pad，旧的“区域起点”锚点依然不成立。
- 可写段、RELRO、依赖解析、构造/析构和引用计数行为不变。

### 3.3 控制接口

- `inject` 新增 `keepelf` 选项。
- `status` 增加 `compl=`（本请求实际使用的完成候选列表）、`hdr=`（驻留
  manual 镜像的头是否保留）和运行期的随机布局字段
  `map=<base>+<len> code=<addr> guard=<addr>`。
- `probe` 输出 `hook=random syscall_wrapper=1 pool=8`。
- `images` 的镜像行增加 `hdr=kept/scrubbed`。
- 源码内置两个仅编译期生效的自检开关（默认关闭）：
  `-DKCLF_TEST_COMPLETION_FIRST_MISS` 让第一次完成尝试必然不被消费，验证
  重试；`-DKCLF_TEST_COMPLETION_ALL_MISS` 让全部尝试失败，验证 EL0 恢复
  与内核回收。

### 3.4 1.4.3 追加：静态标记与临时布局

1.4.2 的 EL0 程序虽然整体随机，但恢复路径仍嵌入固定的 8 字节 ASCII 标记
`KCLFBAIL`。探测器不需要 payload 参考，只要在匿名可执行内存中搜索该字面量就能
确认框架。1.4.3 的修改：

- 内核在准备阶段生成每请求随机 64 位 bail token，写入私有参数页
  `KCLF_PV_BAILTOK`；EL0 恢复路径把它复制到 bail 槽，内核按 token 而不是固定
  常量判断恢复路径。生成代码和私有页都不再含框架字面量。
- 延迟 RELRO 使用的 `__NR_mprotect` 不再是代码里的 `movz` 立即数，而是和完成
  候选列表一样用每请求 key 加密后从私有页读取。
- 入口前的“syscall 重启”填充指令改为随机选择的安全指令（nop/movz/eor/add/orr，
  只写死临时寄存器），不再固定为 `b .+0`。
- 私有页布局修正了候选列表 16 项与结果字段的重叠（实际只写 2–3 项，但定义现已
  自洽），新增 `BAILTOK`/`MPROT` 字段。

临时映射布局也进一步随机化：

- 四个块 `RX 代码 / ABI 参数页 / 私有参数页 / PROT_NONE guard + 栈` 按随机顺序
  排列，块之间插入 0–2 页随机填充页。
- 代码页不再固定在映射起点，参数页不再总是紧跟代码页，guard 位置和总大小
  （10–25 页）不再可预测。
- 所有不会被立即覆盖的页（填充页、栈、参数页未用部分、私有页未用部分）用随机
  数据填充，映射不再呈现“新分配的零页”形态，1.4.1 方法 A 中的“参数前缀全零”
  条件也不再成立。
- 随机填充要求所有分支字段显式初始化：验证中发现并修复了 linker 请求的
  `KCLF_P_MANUAL` 选择字段未显式清零、导致随机值把 linker 请求送进 manual 路径
  并解引用垃圾向量的问题。

## 4. 真机验证

设备与 1.4.1 报告相同：Redmi rubens，Android 12 / API 31，ARM64，
Linux 5.10.66，4 KiB 页，SELinux Enforcing。测试夹具 `com.kclf.obsprobe`
仍为 non-debuggable、`untrusted_app`、`Seccomp: 2`、`dumpable=0`、
`CapEff=0`。

夹具（`test/observability/probe.c`）实现四条内容规则加一个 syscall guard：

| 规则 | 判据 | 预期 |
| --- | --- | --- |
| `KNOWN_MANUAL` | 与 1.4.1 方法 B 相同：区域起点处逐字节相同的已知 ELF 头、加载段覆盖为匿名、未登记 linker | 1.4.2+ 不再出现 |
| `KNOWN_HEADER` | 更强的页级锚点：在匿名可读内存中任意位置找完整已知 ELF 头 | 默认不出现；`keepelf` 时出现 |
| `RESIDUAL_TEXT` | 不需要 ELF 元数据：在匿名可执行内存中找已知 `.text` 签名 | 驻留期预期出现（残余面） |
| `RESIDUAL_TAG` | 在匿名可执行内存中搜索 1.4.2 生成代码里的固定 `KCLFBAIL` 字面量 | 1.4.3 不再出现 |
| `SYS_TRAP` | 对 `getpid/gettid/getuid/geteuid/getgid/getegid/getppid/getpgid/ sched_getscheduler/getpriority` 安装 `SECCOMP_RET_TRAP`；按现场 PC 是否在预采集的文件后端可执行映射中分类 | 注入期间 `kind=unexpected` 必须为 0 |

夹具自己的参考副本地址被排除在扫描之外；guard 在被保护的观察线程上安装，
其余线程不受影响。

1.4.2 真机结果（`--rounds 2`，`build/kclf-observability-f9f49af39e98`）：

| 用例 | 结果 |
| --- | --- |
| 无 KPM：plain / guard / normal 基线 | 无 `KNOWN_MANUAL`/`KNOWN_HEADER`/`ERROR`；guard 的匿名 stub 100/100 被 trap（`control_traps=100`），说明 guard 确实生效 |
| manual 驻留、manual unload、linker 驻留（各 2 次） | 全部 `state=done`；`kind=unexpected` 为 0；`KNOWN_MANUAL`/`KNOWN_HEADER` 为 0；payload `init` marker（unload 组含 `fini`）存在；App 未退出 |
| plain + manual 驻留（2 次） | `hdr=scrubbed`；`KNOWN_MANUAL=0`、`KNOWN_HEADER=0`；`RESIDUAL_TEXT` 命中且地址落在 KPM 记录的 `resident=` 范围内 |
| plain + manual `keepelf`（2 次） | `hdr=kept`；`KNOWN_MANUAL=0`（VMA 起点锚点失效）；`KNOWN_HEADER` 命中（页级扫描仍能找到保留的头） |
| 完成候选随机性 | 各次注入的 `compl=` 至少两种组合，例如 `113,22,64`、`64,22,101` |

1.4.3 真机结果（`--rounds 2` 14 个 case，`--rounds 3` 19 个 case，均为
`result=passed`；最终证据 `build/kclf-observability-218be64b3fb7`）：

| 用例 | 结果 |
| --- | --- |
| plain / guard / normal 基线 | 四条内容规则全部为 0；guard 匿名 stub 100/100 被 trap |
| guard + manual 驻留 / manual unload / linker 驻留（各 2/3 次） | 全部 `state=done`；`kind=unexpected=0`；`KNOWN_MANUAL`/`KNOWN_HEADER`/`RESIDUAL_TAG` 为 0；init/fini marker 存在；App 未退出 |
| plain + manual 驻留（2/3 次） | `hdr=scrubbed`；头规则为 0；`RESIDUAL_TAG=0`；`RESIDUAL_TEXT` 命中且落在 `resident=` 范围内（残余面如实保留） |
| plain + manual `keepelf`（2/3 次） | `hdr=kept`；`KNOWN_MANUAL=0`；`KNOWN_HEADER` 命中；`RESIDUAL_TAG=0` |
| 完成候选随机性 | `--rounds 3` 出现 `63,113`、`98,29`、`113,124,22` 等组合 |
| 清理 | `kpm num=0`、测试包卸载、boot ID/SELinux 不变 |

构建期自检（同一源码、真机）：

- 1.4.2 `FIRST_MISS`：`compl=174,101`，第一次尝试（getuid，未被 hook 消费）返回后
  由第二个候选完成，`state=done`，进程继续运行。
- 1.4.2 `ALL_MISS`：`compl=174,174`，EL0 写 marker 并恢复寄存器返回；目标下一次进入
  候选系统调用时内核回收临时映射，`state=done` 且
  `err="completion blocked; EL0 restored the original register file"`，进程和
  目标线程继续运行，`hdr=scrubbed` 的镜像正常驻留。
- 1.4.3 重跑同一路径（固定 marker 已改为 per-request token）：
  `FIRST_MISS` 得到 `compl=174,29`、`state=done`；
  `ALL_MISS` 得到 `compl=174,174,174`、`state=done`、
  `err="completion blocked; EL0 restored the original register file"`，
  目标进程存活，`unload=ok`，模块可正常排空卸载。bail token 匹配与 EL0 恢复
  均实际执行。

其它真机回归：

- 对 App 的 `kclf-fp` 线程注入后，`fp_<pid>` 中 `fp-state-failure=0` 持续出现，
  FPSIMD 随机化保存/恢复没有破坏 q0/q8/q31 和 FPCR/FPSR。
- `test/app/device-test.ps1` 的 linker 后端用例（主线程、Java sleeper、Binder）
  全部通过；1.4.3 的临时映射断言已改为按运行期 `map/code/guard` 和 maps 中的
  `r-xp`/`---p`/`rw-p` 关系检查，不再假设固定 11 页布局。
- 结束时 `kpm num=0`，boot ID 与 SELinux 状态未变，dmesg 前后差分无新增
  BUG/WARNING/Oops/panic。

产物与证据：

| 项目 | 值 |
| --- | --- |
| KPM SHA-256（1.4.2） | `e88b717398cc196dcc2ebe3b9c27c8de13c25275eece192b47838908e1c1f8a9` |
| KPM SHA-256（1.4.3） | `9c12b67088215f88078d4092e75941851aa7683862d635ede219605c4d412890` |
| 参考 payload SHA-256 | `1aca043f7c8cdb3856495c6aaedfa9bd03d9dad01cfc6cacb66f5e62a452a651` |
| 夹具事件（1.4.2） | `build/kclf-observability-f9f49af39e98/` |
| 夹具事件（1.4.3，rounds=2） | `build/kclf-observability-0067e4513c69/` |
| 夹具事件（1.4.3，rounds=3） | `build/kclf-observability-218be64b3fb7/` |
| App 回归（1.4.3） | `build/kclf-app-e16319480ea0/` |

测试 APK 每次重新构建都会因签名/构建时间产生不同哈希，因此以各次
`summary.json` 中记录的 `apk_sha256` 为准，不在文档中固定一个跨运行值。

参考 payload 哈希与 1.4.1 报告相同，说明检测规则和目标内容没有变化，只是
1.4.2/1.4.3 不再满足这些规则的前提。

## 5. 仍然可观测的残余面

| 现象 | 是否仍可观测 | 说明 |
| --- | --- | --- |
| 已知 payload 的只读/可写数据内容 | 可（找到基址后） | 代码必须可执行且通常可读；本版本不改变这一点 |
| 已知 payload 的**可执行**内容 | 可（实测 `RESIDUAL_TEXT`） | 只要 payload 驻留且本进程可读 RX 映射，内容扫描就能确认；与“是否 KCLF”无关 |
| 未知 payload 的匿名 RX/ELF 形态 | 可 | 匿名可执行映射、代码页存在本身可能被看到；1.4.1 报告已把这类单独现象排除为无效判据 |
| 临时映射的出现/消失 | 可（窗口内轮询 maps） | 块顺序、填充页、guard 位置和总大小已随机，但存在性、页数量和时序仍可见 |
| 完成系统调用的 PC | 只有在探测器 trap 了候选调用时才可见 | 候选是 libc 常用调用，trap 它们会破坏探测器自身常用路径；即使看到，也没有固定指纹可对 |
| `getpid` 等完成自陷 | 不再出现 | 1.4.2 不在注入路径上使用这些调用 |
| 固定 `KCLFBAIL` 标记 | 不再出现 | 1.4.3 用内核写入私有页的每请求随机 token；代码和私有页都没有框架字面量 |
| payload 自己的行为、日志、文件、线程 | 取决于 payload | 与 1.4.1 相同 |
| 内核模块、dmesg、目标 maps 的跨进程读取 | 需要 root/superkey | 不属于普通 App 自身检测能力 |

因此本版本的准确表述是：**1.4.1 报告定义的两个检测点不再命中；1.4.2/1.4.3
进一步消除了固定框架字面量和固定临时布局；已知内容在驻留期仍可被本进程读取。**
不能表述为“注入不可检测”。

## 6. 兼容性、边界与运维

1. **seccomp**：完成不再依赖 `getpid`。候选池中的调用都是普通 App 常用调用；
   若某个 App 对全部候选安装 trap/kill，EL0 会恢复寄存器返回，KPM 在目标下一
   次进入候选调用时回收临时映射并给出 `completion blocked` 错误。目标自身的
   seccomp 策略仍不被修改。
2. **keepelf**：适用于运行期读取自身 ELF 头/`__ehdr_start` 的 payload；此时
   页级头扫描仍可确认已知头，但 1.4.1 方法 B 的区域起点锚点仍不成立。
3. **ELF 头擦除**：默认擦除，依赖 `__ehdr_start` 或运行时解析自身程序头的
   payload 需要用 `keepelf`。C++ 异常展开、payload TLS/IFUNC 本来就未实现。
4. **卸载**：`quiesce`/`release`/`unload` 的排空要求不变；EL0 恢复路径会把
   请求标记为 done 并排入 `TWA_SIGNAL` 清理，不再依赖目标自然返回。
5. **旧测试**：`test/observability/run.py` 验证四条内容规则（含
   `RESIDUAL_TAG`）和 syscall guard；`kclf_tramp.S`/固定 548 字节参考已删除，
   `test/app/device-test.ps1` 的 probe 断言改为 `hook=random`，临时映射断言
   改为按运行期 `map/code/guard` 与 maps 检查。
6. **参数页随机填充**：ABI 参数页和私有页不再整页清零，所有生成程序会分支的
   字段必须显式写入。1.4.3 在真机验证中发现并修复了 linker 请求的
   `KCLF_P_MANUAL` 未显式清零、被随机值送入 manual 路径的问题；以后新增字段
   必须同时初始化，不能依赖匿名页的零值。
7. **没有覆盖所有内核**：与 1.4.1 相同，只在 Android 12 / 5.10.66 / 4 KiB /
   ARM64 上实测。16 KiB 页、无 syscall wrapper 的宿主、SVE/SME 目标等未验证。
