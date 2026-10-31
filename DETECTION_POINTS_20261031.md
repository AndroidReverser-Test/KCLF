# KCLF 1.5.1：普通 App 检测点与稳定性评估

审计日期：2026-10-31（Asia/Shanghai）。对象：`kpms/kclf` 默认 manual 后端，ARM64
Android 12 / Linux 5.10.66 / 4 KiB 页。本文是 1.5.1 的结论入口；
[DETECTION_POINTS.md](DETECTION_POINTS.md) 保留为 1.5.0 历史基线。

## 1. 结论

1.5.0 存在一条可稳定复现的事件型检测链：框架在 payload 之后**必然**通过真实 libc
`usleep()`/`open()` 发一个完成 syscall；检测器只要对自己的 `nanosleep`/`openat`
安装 `SECCOMP_RET_TRAP`，就能在 SIGSYS 现场用 libc 帧里的返回地址找到跳板代码页，
再核验固定的 72 字节调用结构、`[sp,#0x80]` 私有页指针、x6/x7 cookie 和 libc 入口。
`test/selfcheck_v15` 在 1.5.0 上 45/45 用例检出，每例 2 个事件（`nr=0x65`、`nr=0x38`）。

1.5.1 删除了生成程序的整条完成调用路径：**完成不再产生 syscall、信号、库调用或
缺页**。程序在 EL0 恢复被中断线程的寄存器文件（x16/IP0 除外，见第 5 节），把每请求
随机 token 写入私有页，然后直接 `br` 回被中断 PC。框架只在目标线程之后的普通系统
调用入口（70 项只读观察点）或控制器 `status`/`reap`/`quiesce` 排队的 poll 回调里
读取 token；命中后由目标上下文的 cleanup task_work 应用延迟 RELRO 并回收映射。

因此，1.5.0 的检测证据在 1.5.1 中均不存在：

| 1.5.0 的检测证据 | 1.5.1 状态 |
| --- | --- |
| 完成 syscall（`nanosleep`/`openat`） | 不存在：框架完成路径不发任何 syscall |
| libc 帧中指向跳板代码页的返回地址 | 不存在：没有任何从代码页发出的完成调用 |
| 固定 72 字节完成结构（末 56 字节固定） | 已从生成器删除 |
| `[sp,#0x80]` 的私有页指针 | 已删除：不再使用栈槽传递私有页 |
| x6/x7 cookie 与私有页 cookie 交叉校验 | 两者均已删除 |
| 完成现场的 libc 函数地址/参数校验 | 不存在：没有完成调用现场 |

这仍不是“不可检测”证明。匿名 RX 代码页、随机私有 RW 页、payload 自身内容/副作用、
payload 运行期间的 syscall 栈、时序和回收窗口仍然可观测；专门针对未知 payload 的
通用行为检测也不在本文覆盖范围内。

## 2. 精确产物与设备

- 默认构建 `kpms/kclf/kclf.kpm` SHA-256：
  `fa378fcdeece9725b61d10ae89c4a4133c43c52e5200d440fd1057c9fc4450b8`。
- 设备：Android 12；`Linux 5.10.66-android12-9-00001-gd262b276948e-ab8291727`；
  MT6895Z；arm64；4 KiB 页；SELinux Enforcing。
- KernelPatch：kpatch 1.1.58，`/data/local/tmp/kpatch`。
- `probe`：`btf=0`、`pt_regs=ok size=336`、`thread_size=16384`、
  `syscall_wrapper=1`、完成观察安装 70/70。
- 测试 App：non-debuggable、`dumpable=0`、`CapEff=0`、`untrusted_app`、继承 zygote
  seccomp；检测器不使用 root、ptrace、`/proc/self/mem` 或 KPM 状态。

## 3. 1.5.1 完成协议

1. prepare 阶段分配随机布局的临时匿名区：RX 代码页、RW ABI 参数页、RW 私有页，
   需要时再加 `PROT_NONE` guard 和专用栈；私有页每个字段独立随机偏移。
2. hijack 保存整份 EL0 寄存器/FPSIMD/SP/PC/NZCV 到私有页，把目标线程重定向到
   随机入口的生成程序。
3. 生成程序只执行 payload 的 IFUNC/构造/析构和必要的 `blr`，**不含 `svc`**；
   manual RELRO 不在 EL0 执行。
4. 完成后恢复 FPSIMD、SP、NZCV 和除 x10/x16 外的全部 GPR；x10 最后恢复为原值，
   x16 装入被中断 PC；写随机 token 后 `br x16` 直接回原 PC。
5. 观察点 1：70 个普通系统调用的 before hook 只读私有页 token，不 skip、不改返回值、
   不改寄存器。命中后 `done=syscall`。
6. 观察点 2：控制器在 `status`/`reap`/`quiesce` 中向目标线程排 poll task_work；
   回调在目标上下文读 token。命中后 `done=poll`。同一请求的 poll head 用
   `poll_queued` 防止重复入队。
7. cleanup task_work 读取结果、应用延迟 RELRO（内核侧 `mprotect`）并 `munmap`
   临时映射；失败最多重排 8 次并保留可诊断状态。

## 4. 验证结果

### 4.1 普通 App 自检（关键验收）

命令：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/selfcheck_v15/run.py --serial '<SERIAL>' --suite full --rounds 5
Remove-Item Env:KCLF_SUPERKEY
```

`build/kclf-selfcheck-bd20c95e8a63/`：

| 项 | 1.5.0 基线 | 1.5.1 |
| --- | ---: | ---: |
| 注入用例 | 45 | 45 |
| detections | 45/45（每例 2 事件） | **0/45** |
| 完成路径 | 2 个 libc 完成 syscall | 45/45 `done=syscall` |
| payload 构造/析构 | 45/45 | 45/45 |
| 目标存活 | 45/45 | 45/45 |
| 清理 | `quiesce=idle` | `quiesce=idle`，`kpm num=0` |

基线（observe/denyexec）各 1800 次合法 libc 调用全部被过滤器观察、detections=0；
注入后各用例 1800 次对照调用（合计 81,000 次）未出现阳性。`denyexec` 模式仍然
无法阻止 manual 的 EL1 `vm_mmap`/`mprotect`，这与 1.5.0 结论一致，属于注入不受
用户态可执行映射策略约束，不是新增检测点。

### 4.2 控制器 poll 路径

用 `CFLAGS=-DKCLF_TEST_NO_TOKEN_HOOK` 构建（`5ea0faf7…`），hooks 仅用于学习
pt_regs，不观察 token。pilot 用例结果：

```text
constructor_ran=true finalizer_ran=true framework_done=true detections=0
status: ... state=done stage=restore handle=1 done=poll stack=task/6 ... unload=ok rc=0
quiesce=idle final_kpm_num=0
```

证据 `build/kclf-selfcheck-d1e2ffc81c6c/`。

### 4.3 旧规则回归

`test/observability/run.py --rounds 2` 通过（`build/kclf-observability-306d19a346c4/`）：
旧方法 A/B、ELF 头页级扫描、`KCLFBAIL` 字面量扫描、guard syscall、`keepelf` 对照
均未产生新阳性；`KNOWN_MANUAL`/`KNOWN_HEADER` 在默认擦头模式下保持 0，`keepelf`
对照按预期找到保留头，`RESIDUAL_TEXT` 仍能读到已知 payload 内容（历史残余规则）。

### 4.4 主机结构审计

`test_observability_signature.c`：30,000 个随机生成程序（4/16/64 KiB 页各 10,000）
内 0 条 `svc`、0 个 1.4.3 尾段命中、0 个 1.5.0 完成 stub 命中；3,000 个随机反例页
0 命中。`test_codegen.c` 8 个 seed 全部通过，生成页无 `svc`、入口随机、未用字节
仍为随机数据。

### 4.5 native / manual 回归

`test/manual-device-test.py --app` 全部通过（`build/kclf-manual-a7529dd12051/`）：
manual 注入/驻留/重复引用/release/unload、RELRO（`libmanual_relr`）、IFUNC 拒绝、
FPSIMD、seccomp 目标、失败回滚、目标退出回收、取消、quiesce 语义和普通 App 主线程
均正常；所有完成的 `status` 都是 `done=syscall stack=task/6`。

## 5. 残余可观测面与代价

1. **匿名 RX 代码页 + 匿名 RW 私有页/ABI 页**：窗口从 EL0 完成延长到目标线程下一次
   被观察 syscall 或控制器下一次 poll。并发扫描 `/proc/self/maps` 仍可能看到一块
   短驻留匿名可执行映射；它不再是完成事件现场。
2. **payload 自身的 syscall 现场**：构造函数/析构函数的 `blr` 返回地址在跳板代码页；
   如果 payload 在运行期间发 syscall，检测器扫栈仍可能看到匿名 RX 指针。这是 EL0
   跳板方案的固有属性，与完成协议无关。
3. **私有页内容**：完成前保存整份寄存器/FPSIMD/结果；token 是随机 64 位值。字段
   偏移随机，没有固定签名。
4. **x16/IP0 不恢复**：`br` 必须占用一个 GPR 承载目标 PC；x16 是 ABI 的 caller-saved
   scratch。其余 30 个 GPR、SP、NZCV、FPSIMD 精确恢复。需要精确恢复 x16 的场景
   不在支持范围内。
5. **观察点依赖**：宿主若把 per-syscall hook 按 UID 门控，普通 App 上 `watch=off`，
   请求只能靠控制器 poll 收尾，回收窗口更长；没有 BTF 时也无法定位 pt_regs，注入
   会明确拒绝。
6. **payload 内容/副作用**：已知镜像全段比对（方案 B）、linker 记录（方案 C，仅
   `,linker`）、线程/fd/时序由 payload 决定，不属于完成协议能消除的范围。
7. **RELRO 时序**：构造函数执行期间 RELRO 页仍可写，cleanup 时才变为只读；只影响
   payload 自身安全性，不影响 App。

## 6. 可支持的说法与边界

可以支持：1.5.1 删除了 1.5.0 已由普通 App 自检稳定复现的完成 syscall/libc 帧/
72 字节结构检测链；在本机 full 套件中该链的 45/45 阳性降为 0，且两条完成观察
路径、构造/析构、清理和卸载均正常。

不能支持：对任意 payload、任意 App、任意 ROM 或任意内核对手“不可检测”；也不能
据本文否定方案 B/C、匿名 RX 扫描、payload 副作用或未列出的新检测思路。16/64 KiB
页、其它 bionic/内核、BTI 强制设备、真实业务负载和并发 mmap 尚未在 1.5.1 上复测。
