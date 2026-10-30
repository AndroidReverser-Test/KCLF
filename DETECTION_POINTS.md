# KCLF 1.5.0：普通 App 检测点与稳定性评估

审计日期：2026-10-30（Asia/Shanghai）。对象为当前 ARM64 实现，默认 manual 后端。
1.5.0 针对 1.4.3 审计确认的稳定完成协议做了结构性重写：生成页中不再存在任何
`svc`，完成调用改为经过真实 libc 包装函数；私有参数页布局每请求随机化，并优先借用
被中断线程自己的栈。本文是**当前结论入口**；1.4.1/1.4.2/1.4.3 的报告保留为历史证据，
不是 1.5.0 的验收记录。

## 1. 结论：已知的“稳定完成尾段”事件检测点已消失，但仍不是不可检测证明

1.4.3 的强检测点 A 依赖两个同时成立的事实：

1. 目标线程在匿名可执行页里执行 `svc`，因此 seccomp/SIGSYS 现场 PC 落在临时映射内；
2. 从该 `svc` 现场可以归一化出固定的 52 条指令、208 字节完成/恢复尾段，并用私有页
   基址寄存器、ABI 页清零区和候选调用号做交叉校验。

1.5.0 已移除这两个事实：

- 完成路径调用 `usleep()` 或 `open()` 的真实 libc 入口。syscall 由 libc 内部的
  `nanosleep`/`__openat` 发出，SIGSYS 现场的 PC 和 LR 都属于文件映射的 libc，而不是
  生成页；生成页内没有任何 `svc`，RELRO 的 `mprotect` 也改为调用 libc。
- 完成 cookie 放在 `x6/x7`（`seccomp_data.args[]` 只暴露 x0–x5），内核 hook 按 cookie
  而不是“代码页地址 + svc 位置”消费完成调用。
- 私有页不再与 ABI 页相邻；两页是独立随机块。私有页的保存寄存器、FPSIMD、cookie、
  函数表、密钥、结果槽和 bail token 每个字段都有独立随机偏移；ABI 页在完成前整页清零。
- 生成程序在完成调用前把 x19–x29 恢复成被中断线程的原值；SIGSYS 现场不再有指向
  私有页的 callee-saved 基址寄存器。
- 优先把 trampoline 栈借到被中断线程自身的 `[stack]`/线程栈 VMA（可用空间足够时）；
  此时 SP 以及 `usleep()` 的 timespec 指针都落在正常线程栈内，不再指向临时匿名栈。
  空间不足或找不到 pt_regs 时仍回退到临时栈块。
- 入口、寄存器角色、FPSIMD 槽位、完成候选顺序、恢复寄存器顺序、填充指令和页内偏移
  仍按请求随机化。

因此，**当前没有已知的、只依赖普通 App 自身权限且与 1.4.3 判据等价的稳定阳性**。
这不等同于“不可检测”：方案 B/C、payload 自身内容、临时映射、构造函数副作用和时序
仍然可观测；也不排除未在本文列出的新检测思路。

| 方案 | 1.5.0 状态 | 说明 |
| --- | --- | --- |
| A：真实完成事件 + 208 字节尾段 + ABI | **已失效（针对 1.4.3 判据）** | 完成现场 PC/LR 在 libc；生成页无 svc；私有布局随机且与 ABI 分离 |
| B：无 ELF 头锚点的已知镜像全段校验 | 仍可能 | 只针对已知、内容未变、驻留的 payload；不归因 KCLF |
| C：linker 库清单与业务允许内容比对 | 仅 linker 后端 | 默认 manual 不注册 linker 记录；不能替代 manual 检测 |
| 匿名 RX、dladdr 失败、异常 syscall 来源、卡顿等单项 | 不能独立确认 | 仍存在合法 JIT/插件/直接 syscall/信号/调度反例 |

## 2. 权限、产物与信任边界

- 普通 App 指**被注入进程自身**，包含其 native 检测组件，不要求 root、debuggable
  或 capabilities；不是另一个 UID 的 App 跨进程扫描。
- 本轮产物 `kpms/kclf/kclf.kpm` 的 SHA-256 为
  `f272f9cc5bd83a17ceec8a2de67d2105409af172269a35c0ef7a8fe87165e106`（2026-10-30
  最终构建，Android 12 / 5.10.66 / 4 KiB 实测）。
- 假定内核仍正常提供 seccomp、信号现场和本进程内存读取。若额外内核组件任意伪造
  这些观测，普通 App 无法以同一信任层证明真实状态；本文不把当前 KCLF 与任意内核
  对手等同。
- 所有失败读取、未覆盖线程、安装失败、解析失败均应报告“未覆盖/无法判断”，而非
  “未注入”。一次扫描未命中不能证明从未执行。
- 1.5.0 的完成依赖目标进程中已加载的 libc 的 `usleep`/`open`/`mprotect` 符号。找不到
  这些符号时 prepare 明确失败，不回退到页内 `svc`。

## 3. 源码确认的可观测事实（1.5.0）

1. `kclf_exec_prepare` 分配正常匿名 VMA；代码页最终 RX。manual 的可执行加载段也必须
   可读，`ke_file_layout` 拒绝不可读 PT_LOAD。未发现 KCLF 隐藏自身 maps 条目、禁止
   目标自读或伪造 linker 查询结果的实现。
2. 临时区由 **3 个块**组成：代码页、ABI 参数页、私有参数页；可用目标线程栈时不再
   映射 guard/stack 块，否则额外映射 `PROT_NONE` guard + 栈。块顺序和 0–2 页随机
   pad 仍随机；私有页与 ABI 页不再相邻，`priv_addr = param_addr + page` 不成立。
   总大小随块数/pad 变化，借用栈时 3–11 页，回退专用栈时 10–28 页。
3. 私有页字段偏移每请求随机：`struct kclf_priv_layout`（`kclf_codegen.h`）。保存的
   x0–x30、SP、PC、NZCV、q0–q31、FPCR/FPSR、cookie、完成函数地址/参数、候选调用号
   XOR key、结果槽、bail token 和 RELRO 的 libc `mprotect` 地址都在独立槽位。
   ABI 页在完成前被整页清零，包括路径、loader 指针和 manual 数组。
4. 完成候选只包含真实 libc 包装函数：
   - `usleep(0)` → libc 内部 `nanosleep@plt`，svc #101；
   - `open(<random /proc/self/fd/.../x>)` → libc 内部 `__openat`，svc #56。
   每个请求随机选择二者的顺序并尝试全部；单一候选被目标 seccomp 拦截时仍可尝试另一
   候选。生成页不嵌入 syscall 号；私有页中的候选号用每请求 key 加密。
5. `mprotect` RELRO 站点也调用 libc `mprotect`，生成页不含 `svc`。因此 1.4.3 的
   “页内至少一个完成 svc，另有一个条件 mprotect svc”事实不再成立。
6. 完成调用前恢复 x19–x29 为原值；cookie 仅放 x6/x7（seccomp BPF 不可见）。内核 hook
   匹配 `(x6==cookie || x7==cookie)` 且 `x8` 属于本请求候选表，不再比较 PC。
7. 程序尾仍保留一条 EL0 bail 路径：所有候选都未被消费时写随机 token、从私有页恢复
   全部 GPR/FPSIMD/SP/PC/NZCV，然后 `br x16` 返回被中断 PC。该路径不经过 syscall。

## 4. 方案 A：1.4.3 完成尾段识别为何不再成立

### 4.1 事件现场

假设检测线程对完成候选安装 `SECCOMP_RET_TRAP`，并在 SIGSYS handler 中读取
`ucontext.uc_mcontext`：

- PC = libc `nanosleep`（或 `__openat`）内 `svc` 的下一条指令；PC−4 仍是 libc 的
  `svc`，但 PC−44 起是 libc 的普通指令，不是 1.4.3 的 52 条尾段。
- LR = libc `usleep`（或 `open`）内部的返回地址，不是生成页地址。
- SP 在借用成功时位于线程自身栈 VMA；`usleep` 的 x0（timespec 指针）也在该栈。
- x19–x29 是恢复后的原值；没有寄存器指向私有页。
- x6/x7 是本请求随机 cookie；seccomp BPF 不能读取 x6/x7，但 SIGSYS ucontext 能看到。

因此 1.4.3 完整阳性条件中的第 2 项（读取并解码 208 字节尾段）直接失败；第 3–5 项
（私有页基址/相邻关系、固定 count/key/list、零区交叉校验）也没有可用的基址寄存器。
即使检测器只检查“PC−4 是 svc 且 PC 在匿名 RX”，也会看到 PC 在 libc 文件映射内。

### 4.2 主机验证

[test_observability_signature.c](test/test_observability_signature.c) 保留 1.4.3 的
逐指令尾段识别器，并用独立随机布局生成 30,000 个程序（4/16/64 KiB 页各 10,000）：

- 生成程序内 `svc` 数：0；
- 1.4.3 尾段识别命中：0；
- 3,000 个随机反例页：0 命中；
- 入口/长度/寄存器不变量全部通过。

[test_codegen.c](test/test_codegen.c) 另对每个 seed 检查生成页无 `svc`、入口随机、
未用代码页仍为随机字节。

### 4.3 真机 seccomp 现场

[test/seccomp_probe.c](test/seccomp_probe.c) 在普通 native 进程内安装
`SECCOMP_RET_TRAP`（openat），并在 SIGSYS handler 记录真实现场。2026-10-30
Android 12 / 5.10.66 / 4 KiB 设备上，向该进程注入 manual payload 后得到：

```text
TRAP nr=0x38 pc=0x7d0b774e38 lr=0x7d0b732300 sp=0x7fff584fb0
     in_libc=11 in_stack=1 x6=0x42b04dd94a02d9c4 x7=0x42b04dd94a02d9c4
```

`nr=0x38` 是 openat；PC 落在 libc `__openat` 的 `svc` 之后，LR 落在 libc `open`
的调用点，SP 在线程栈；x6/x7 是本次请求 cookie。KPM 的内核 hook 在 seccomp 之后
才运行，因此这次现场没有被内核 hook 消费，但检测器看到的是正常 libc/栈现场，而不是
KCLF 尾段。

同一设备还用普通 `kclf_target` 验证了 manual、linker、`unload`、RELRO payload 和
`wake`/默认路径；`status` 记录的完成现场满足
`PC ∈ libc r-xp`、`LR ∈ libc r-xp`、`SP ∈ [stack]`，例如：

```text
state=done svc=7c5d56a378 lr=7c5d52ea60 sp=7fdbaa2bb0 stack=task/6
```

`stack=task/6` 表示成功借用线程栈（状态 6 为成功码）。

## 5. 方案 B/C 与残余暴露

### 5.1 方案 B：无头已知镜像内容核验

默认 manual 仍擦除 ELF 头，但 payload 的可执行/只读内容在驻留期间仍可被目标读取。
拥有可信参考文件和足够驻留时间的检测器，仍可按 1.4.3 报告第 5 节的多锚点、全 PT_LOAD
内容比较找到**已知、未修改**的 payload；这不是 KCLF 身份，也不适用于未知 payload。
`unload` 模式可缩短驻留窗口，但不能保证所有引用计数归零或构造函数不留下线程。

### 5.2 方案 C：linker 记录

默认 manual 后端不注册 bionic soinfo/linker 记录；`linker` 后端仍会产生正常
`dlopen` 记录，可被 `dl_iterate_phdr` 等枚举。两者不能互相替代。

### 5.3 仍然存在的可观测面

- **匿名 RX 代码页**：注入窗口内存在一块短驻留匿名可执行映射；并发扫描或高频信号
  采样可能看到其地址/内容。它不再是完成事件现场，但仍是 shellcode/JIT 类异常项。
- **私有页与 ABI 页**：私有页保存寄存器/FPSIMD/cookie/函数地址；ABI 页保存 loader
  参数并在完成前清零。两者是匿名 RW，扫描整个地址空间仍可能发现高熵状态页。
- **payload 内容与副作用**：构造/析构、线程、fd、库映射和时序由 payload 决定。
- **SIGSYS ucontext**：若检测器同时 trap 完成候选，可以看到 x6/x7 cookie、x0 timespec
  指针和调用时的 SP；这些是普通调用现场的一部分，但仍是本框架产生的额外状态。
- **open 候选的路径指针**：x1 指向私有页中的 `/proc/self/fd/...` 随机路径；若检测器
  用 process_vm_readv 读取该指针，可看到该字符串。它是合法路径，不唯一归因 KCLF。
- **回退栈**：线程栈空间不足/找不到 pt_regs 时回退到临时栈块，此时 SP 在匿名映射内，
  回到 1.4.3 的较弱暴露面；`status` 的 `stack=transient` 可用于验收。
- **seccomp 拒绝服务**：检测器若对全部完成候选返回 KILL/TRAP，KCLF 可能无法完成并
  走 bail；这是拒绝服务/功能失败，不等于检测成功。1.4.3 报告中的“候选池可破坏检测器
  自身”假设仍成立，但不再是唯一路径。
- **内核对手**：能任意伪造 seccomp/信号/内存观测的内核组件不受本文约束。

## 6. 已完成的验证与未完成项

| 验证项 | 1.5.0 结果 |
| --- | --- |
| 主机：30,000 随机生成程序 | 0 svc、0 个 1.4.3 尾段命中、3,000 随机页 0 命中 |
| 主机：入口/长度/随机填充 | `test_codegen.c` 通过 |
| 真机：manual 默认/wake/unload | 通过，完成现场 PC/LR ∈ libc，SP ∈ [stack] |
| 真机：linker 后端 | 通过，`via=__loader_dlopen`，完成现场同上 |
| 真机：manual RELRO/IFUNC 入口 | RELRO payload 通过；payload 自定义 IFUNC 仍按设计拒绝 |
| 真机：EL0 bail 路径 | `KCLF_TEST_COMPLETION_ALL_MISS` 构建下 `completion blocked; EL0 restored`，目标继续运行 |
| 真机：seccomp trap 单候选 | openat 被 trap 后回退 usleep 完成；SIGSYS 现场在 libc/栈 |
| 真机：普通 untrusted_app | 本机仅验证了 native shell 进程；未安装新的普通 App 探针 |
| 真机：主线程/Binder/TSYNC/并发 mmap | 本轮未重新验收 |
| 真机：16/64 KiB 页 | 仅主机生成验证；未在 16/64 KiB Android 设备回归 |

### 6.1 标注“普通 App 稳定不可检测”之前仍需完成

1. 在 non-debuggable、dumpable=0、CapEff=0、SELinux Enforcing 的真实 App 中，
   验证主线程、Binder/native 工作线程和过滤器安装后新线程的覆盖与借用栈回退。
2. 用实际 App 的 seccomp 策略和 SIGSYS handler 测试完成候选、bail、清理和并发
   mmap/munmap；记录未覆盖/失败，不把“未触发”写成“干净”。
3. 16/64 KiB 页设备和不同 bionic 版本上验证 `usleep`/`open` 的嵌套 svc 与 LR 形态；
   libc 实现变化时 `kclf_resolve_completion` 必须显式失败，不得静默回退。
4. 已知 payload 的方案 B 全段比较、payload 驻留/卸载窗口与 payload 自身副作用仍按
   1.4.3 报告第 5 节和第 8 节验收。
5. 对完成候选全部 trap、信号处理器重入、备用栈、SP 借用边界（深栈/altstack）逐项
   测试；本轮已观察到“持续 trap nanosleep + SIGSYS handler”场景下 hijack 可能失败，
   属于拒绝服务/未覆盖，不应写成检测阳性。

## 7. 复现

主机：

```sh
gcc -std=c11 -O2 -Wall -Wextra -Werror -DKCLF_CODEGEN_HOST \
  -fsanitize=address,undefined -g \
  kpms/kclf/test/test_observability_signature.c kpms/kclf/kclf_codegen.c \
  -o /tmp/kclf-signature-audit
/tmp/kclf-signature-audit

gcc -std=c11 -O2 -Wall -Wextra -Werror -DKCLF_CODEGEN_HOST \
  kpms/kclf/test/test_codegen.c kpms/kclf/kclf_codegen.c -o /tmp/kclf-codegen
/tmp/kclf-codegen 4096
```

真机（需要 NDK clang、adb、KernelPatch）：

```powershell
$env:Path = 'D:\arm_gnu\14.2 rel1\bin;' + $env:Path
make -C kpms/kclf TARGET_COMPILE=aarch64-none-elf- -j4
# 将 kclf.kpm、test/kclf_target、test/libkclf_payload.so、test/seccomp_probe 推到设备
# 加载 KPM 后注入 kclf_target；seccomp_probe 用于观察 SIGSYS 现场
```

## 8. 最终可支持的说法

1.5.0 移除了 1.4.3 已确认的固定完成尾段/ABI 事件锚点，并把完成调用放到 libc 的
正常 syscall 现场；主机随机样本和本机真机 seccomp 现场都没有再出现旧判据。它仍保留
匿名 RX/私有状态页、payload 内容/副作用和回退栈等可观测面，**不能**据此声明对所有
普通 App 不可检测，也不能替代 16/64 KiB、真实 App 和并发场景的验收。
