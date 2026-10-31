# KCLF 1.5.2：5.x / 6.x 兼容性实现与验证

日期：2026-10-31（Asia/Shanghai）。代码基线：KCLF 子仓库 `f6f5936` / 1.5.1。

## 结论

原版已经采用运行时兼容设计，不是只能运行于某一个内核版本；但版本范围检查
`5.0 <= kver < 7.0` 不是 ABI 兼容证明。本次修复了明确的版本/能力缺口，产物升级为
1.5.2，保留 stock KernelPatch 宿主和现有控制接口，不修改系统 SELinux/seccomp 设置。

最终设备验收范围是 Pixel 6 / Android 16 / ARM64 / Linux 6.1.134 / 4096 字节页。
**不能宣称全部 5.x / 6.x 内核可用**：当前没有连接 5.x、6.6、6.12、6.16+ 或大页设备。
跨版本主机模拟、上游源码核对和禁用能力的测试构建，不能替代这些设备的运行验证。

## 实现梳理

| 文件 | 职责与关键边界 |
| --- | --- |
| `kclf.c` | superkey 保护的 KPM `ctl0` 控制面；四个请求槽；固定 PID 身份、校验 mm 身份；task_work 排队、取消、完成观察、排空卸载 |
| `kclf_compat.c` / `kclf_btf.h` | 从运行内核解析符号和 BTF；验证 mm/VMA/锁/寄存器布局；选择 task_work ABI、线程标志掩码和回退路径 |
| `kclf_exec.c` | 在目标 task_work 上下文操作用户内存、遍历 VMA、分配临时映射、选择栈、校验并重定向 `pt_regs` |
| `kclf_manual.c` / `kclf_elf.c` | 默认 manual 后端：快照 ELF、解析已驻留依赖、重定位、记录构造/析构与 IFUNC 调用、W^X/RELRO、镜像引用与释放 |
| `kclf_codegen.c` | 生成目标用户态执行程序，保存/恢复 FPSIMD 和用户寄存器，执行所选后端的用户态步骤；本轮不修改生成器 |

请求由 `ARMED` 经目标线程的 `PREPARING`、`READY` 进入 `RUNNING`。
准备阶段使用目标上下文完成文件/VMA/映射操作，随后改写真实返回帧的 PC/SP，
不是在内核执行 SO。默认 manual 只解析已加载依赖；显式 `linker` 才调用目标 bionic
loader。EL0 完成后写入请求 token 并返回，普通 syscall hook 或控制端排队的 poll
观察 token，然后 cleanup task_work 应用延迟 RELRO、回收临时映射。驻留 manual
镜像另有引用表，需要 `release`；请求槽释放并不代表驻留镜像已释放。

跨版本基础机制原本就包括：

- 可用 BTF 时验证字段偏移，不复制固定的 `task_struct` / VMA / mmap lock 布局。
- 无 BTF 时用 `get_task_mm`，VMA 通过目标自己的 `/proc/thread-self/maps` 遍历；
  有完整布局时用加锁的 `find_vma`。不依赖 rb-tree/maple-tree 私有布局。
- 寄存器帧大小由 BTF 或真实 syscall wrapper 参数学习，不能仅使用构建头的 `sizeof(pt_regs)`。
- 读取 `TCR_EL1` 得到页大小和用户地址范围；保留 4K/16K/64K 路径。
- 用户内存读写使用内核 accessor；旧 procfs `->read` 使用真实用户缓冲，不使用 `set_fs`。

## 本次修改

### 线程标志与函数 ABI

1. arm64 `TIF_UPROBE` 在上游 6.16 从 bit 4 移到 bit 5。固定使用仓库旧头会把新内核
   `FOREIGN_FPSTATE` 当成 UPROBE，同时漏掉真正 UPROBE。本版选择运行时 trace mask；
   SVE/SME 的 bit 23/27 始终拒绝，包含 SME 被回移到旧版本的情况。TIF 是宏，普通
   BTF 不包含这些值，厂商跨版本回移位号仍需单独核对。
   依据：[6.15 线程标志](https://raw.githubusercontent.com/torvalds/linux/v6.15/arch/arm64/include/asm/thread_info.h)、
   [6.16 线程标志](https://raw.githubusercontent.com/torvalds/linux/v6.16/arch/arm64/include/asm/thread_info.h)。

2. `task_work_add` 优先检查 BTF 的第三个参数：bool 禁用 wake；int 按上游 5.8 分界；
   enum 必须包含兼容的 RESUME/SIGNAL 数值，明确不兼容则拒绝加载。这样不会仅因为
   厂商版本号而对一个 bool 函数传入 SIGNAL。BTF 缺失时仍只能使用上游版本基线，
   不能自动判断没有类型信息的 int ABI 回移。
   依据：[5.0 bool API](https://raw.githubusercontent.com/torvalds/linux/v5.0/include/linux/task_work.h)、
   [5.8 int API](https://raw.githubusercontent.com/torvalds/linux/v5.8/include/linux/task_work.h)、
   [6.18 enum API](https://raw.githubusercontent.com/torvalds/linux/v6.18/include/linux/task_work.h)。

3. 取消操作优先 `task_work_cancel_match`，其次 `task_work_cancel_func`。
   两者都不可用时，不能直接把同名 `task_work_cancel` 强转为旧类型：BTF 校验返回值、
   参数、typedef/qualifier 链后，分别使用旧“函数参数→指针返回”或新“work 参数→bool
   返回”接口。无 BTF 时只对上游尚未引入 match 的 5.0–5.12 使用旧 ABI；较新内核
   缺少明确符号/类型证据时返回 `-EOPNOTSUPP`。这比错误调用导致内核崩溃更可控。
   依据：[5.12 API](https://github.com/torvalds/linux/blob/v5.12/include/linux/task_work.h)、
   [5.13 match API](https://github.com/torvalds/linux/blob/v5.13/include/linux/task_work.h)、
   [6.12 两种取消接口](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/task_work.c)。
   当前设备的真实 BTF 已包含新 object/bool 形态，实际正常运行选择 `cancel=match`。

4. BTF 存在 `thread_info` 时额外确认 `flags` 位于 offset 0，避免未经验证的字段访问。

### 缺失能力与回收

- `copy_from_user_nofault` / `probe_user_read` 都不可用时，原版的 hook 和 poll 都读取
  失败，导致已经执行完的请求一直停留在 RUNNING。本版仅在可睡眠 task_work 的 poll
  中使用 GUP；hook 始终保持 nofault。结果三字段完整读取后才发布完成，读失败可重试。
- poll 可能在 token store 与最后一条返回分支之间运行。若真实返回 PC 仍在临时映射
  内，或无法确认寄存器帧，就推迟完成/回收。这覆盖该直接中断窗口，不是对嵌套信号
  帧、任意外部修改/异步重入的完整安全证明。
- `vmalloc`/`vmalloc_noprof` 和 `vfree` 在两种后端都会被调用，改为加载必需能力；
  原版仅 manual 检查它们，linker 可能在缺符号时调用空地址。
- auxv 回退显式检查 `vfs_read`，缺失时返回错误，不调用空指针。
- 原有头部清理函数的约 3.7KB 栈数组改为 256 字节分块处理，清理范围不变。
  全模块通过 `-Wframe-larger-than=2048 -Werror`；这只是单函数栈帧门槛，不代表总调用链栈上限。
- `probe` 新增 `wake_abi`、`trace_mask`、`vector_mask`、`nofault`、`poll_io`。

## 兼容矩阵

| 内核/配置 | 实现策略 | 本轮证据与边界 |
| --- | --- | --- |
| 5.0–5.7 | 默认 bool/RESUME；可验证 enum 回移时允许 wake；旧取消 ABI | 主机模拟、上游源码；没有真机 |
| 5.8–5.12 | int/enum SIGNAL；旧取消 ABI 或明确接口；BTF/无 BTF 双路径 | 主机模拟、源码；没有本版真机 |
| 5.13–5.19 | 优先 match/func；模糊名称需要 BTF 证明 | 主机模拟、源码；没有真机 |
| 6.0–6.15 | 运行时 BTF/accessor/procfs；不依赖 maple-tree 布局 | 6.1.134 / 4K 真机；其他版本未认证 |
| 6.16–6.18 | 上述机制，加新 UPROBE 位号 | 主机模拟、上游源码；没有真机 |
| 更新的 6.x / 厂商自定义 ABI | 仍有版本范围门槛和能力检查 | 未逐版审计，不因版本号通过就宣称兼容 |
| 无 BTF 且无 nofault | syscall wrapper 学习帧；accessor/procfs；控制端 GUP poll | 在同一 6.1 设备禁用能力的专用测试构建；不等于 5.x 内核运行 |
| 16K / 64K 页 | 运行时页参数；生成器按页容量工作 | 主机生成测试通过；无对应硬件/完整 ELF 装载验收 |

所有路径仍要求 KernelPatch 宿主自身支持目标内核及其 hook、stack/current 元数据、
RCU、符号导出与 CFI/LTO 配置。模块兼容不能弥补宿主不兼容。32 位、SVE/SME、
调试/跟踪仍不支持；BTI 强制设备、MTE/tagged SP、复杂信号重入仍未完整验收。
缺少 BTF 且无法安装 syscall wrapper hook 时不能安全定位帧，注入会失败。
只有 poll 可用时必须持续调用 `status`/`reap`/`quiesce`，且目标必须再次经过返回点。

**卸载仍需先排空。** stock 宿主不尊重模块 exit 的错误返回；必须 `quiesce`、释放
全部驻留引用、等待回调/映射回收，再确认 `quiesce=idle` 后卸载。本轮未强卸载活动模块。

## 产物、验证与复现

正式产物：`kclf.kpm`，版本 1.5.2；SHA256：

```text
297BA573A544FD13C864C5EC1A07606A93C71E19655748E20D8BFD633DB370C5
```

主机严格构建、ASan/UBSan 辅助函数/ELF/maps/compat/BTF/符号/完成逻辑测试全部通过；
真实设备 BTF 为 `pt_regs=336`、`task.mm=1440`、`mmap_lock=96`、VMA `0/8`。
`nm -u` 只有宿主接口，没有新增 libc / outline atomic 依赖。
主机记录在仓库 `build/kclf-compat-20261031/host-final.txt`，大页生成和构建记录同目录保留。

最终设备回归及结果索引见本文末尾“最终验收记录”。测试只针对本轮自建 native 进程
和自建非 debuggable App；不操作第三方 App。设备报告 Android 16、内核
`6.1.134-android14-11-g66e758f7d0c0-ab13748739`、`kpver=c00`。设备日志墙钟不同于
主机，因此日志中的 09-27 不作为本文测试日期；boot ID 用于核对没有重启。

主机复现（WSL/Linux，从仓库根目录）：

```sh
make -B -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4 \
  CFLAGS="-Wformat=2 -Wframe-larger-than=2048"
python3 kpms/kclf/test/test_helpers.py
python3 kpms/kclf/test/test_maps.py
python3 kpms/kclf/test/test_compat.py
python3 kpms/kclf/test/test_symbols.py
python3 kpms/kclf/test/test_completion.py
python3 kpms/kclf/test/test_manual_elf.py
python3 kpms/kclf/test/test_provider.py
```

`test_compat.py` 可以追加真实 BTF 文件。本轮新增 fixture 覆盖 bool/int/enum、
两种取消 ABI/不兼容原型、5.12/5.13 与 6.15/6.16 边界。真实内核取消调度和并发仍
不能只靠主机模拟证明。

设备复现（先按 README 编译测试目标/SO；密钥只置于当前进程环境，不写入文件）：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
  python kpms/kclf/test/manual-device-test.py --serial '<SERIAL>' --clang '<NDK clang.exe>'
} finally { Remove-Item Env:KCLF_SUPERKEY }
```

可另建源文件副本，用 `-DKCLF_TEST_NO_BTF -DKCLF_TEST_NO_NOFAULT` 编译专用测试产物，
并传给驱动 `--kpm <单独产物路径> --expect-poll`。不要把测试产物当正式发布文件。
驱动现在等待自有目标进入 nanosleep 空闲点，避免仍在 dlopen/stdio 启动阶段就注入。

## 保留的失败与未通过项

早期 App full 一轮共 9 项，8 项实际完成且构造函数/目标存活有独立记录；3 个即时
unload 用例还记录了析构执行。第 8 项 denyexec 没有进入注入：目标 PID 10243 已退出，
控制端返回 `no such task`。日志显示测试规则阻止 `mapper.pixel.so` 可执行段加载，
Gralloc/HWUI 随后触发运行时 abort。该项记为夹具/环境失败，**不能报告 9/9 成功**。
证据：`build/kclf-selfcheck-51bc2c6a6d1b/summary.json` 和
`build/kclf-compat-20261031/app-denyexec-log.txt`。本轮不扩大修改测试 App 的图形/过滤器逻辑。

最终 native 复测的一次启动竞态触发 `unsafe return boundary; retry later`，没有强制
绕过检查；证据保留于 `build/kclf-manual-5c00b9f09f78/results.json`。随后修正驱动
初始化等待，再完整复测。另一次主机命令引用临时目录中已不存在的测试程序失败，
改用持久证据目录重建并成功重跑，早期 `host-tests.txt` 不作为最终验收日志。

## 最终验收记录

| 项目 | 结果 | 仓库内证据 |
| --- | --- | --- |
| 正式 1.5.2 native 全套 | 136/136 断言通过 | `build/kclf-manual-7d05f22d8daf/results.json` |
| 同源码，无 BTF + 无 nofault 专用构建，全套 | 183/183 断言通过，其中 47 次成功请求显式验证 `done=poll` | `build/kclf-manual-b1f9916c0af6/results.json` |
| 正式 1.5.2 非 root / non-dumpable / untrusted_app 冒烟 | 构造、析构、完成、目标存活均确认 | `build/kclf-selfcheck-fb3be89b221f/summary.json` |
| 主机 ASan/UBSan 与严格编译 | 全部通过 | `build/kclf-compat-20261031/host-final.txt`、`symbols-final.txt` |
| 4K/16K/64K 生成器结构测试 | 全部通过；不等于大页内核实测 | `build/kclf-compat-20261031/build-and-btf.txt`、`final-build.txt` |

136/183 是断言数量，不是内核或独立场景数量；包括新增的 21 次“自有目标已初始化并
进入 nanosleep”检查。两套 native 都覆盖 ELF 重定位/依赖/失败回滚、manual 和 linker、
引用复用、析构回收、FPSIMD、seccomp、取消、目标退出、镜像分页和 quiesce 后释放。
最终两套 native 日志比较未发现新增 BUG/WARNING/Oops/panic，模块均已安全卸载。

正式产物 hash 与最终 native/App 证据一致。禁用能力专用产物 hash 为
`46E3AA879D955F5CB7078130A60197AEA5C05A5BACC69ACD4B7F16BFDA442D7A`，不是发布产物。
旧 115/162 断言记录和 8/9 App 测量保留，不冒充最终完整验收。

最终设备 `kpm num=0`，SELinux 仍为 Enforcing，boot ID 未变化；本轮新建测试 App
已卸载，其临时部署文件已删除，APK/日志保留于本地证据目录。native 测试进程均已
停止，各次独立测试目录保留用于复查。未刷机、未重启、未提交 Git，也未改动已有的
`test/passive_v151/` 用户文件。
