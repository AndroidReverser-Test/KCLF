# KCLF 1.5.5

1.5.5 将已加载提供库表改为按需倍增（初始 64、上限 4096）；分配失败或超过
上限时明确停止 prepare 并回滚，避免用不完整的表误选同名库。已加载对象仅在
`e_ident[8..15]` 精确匹配 `ldr x16,#8; br x16` 时，允许该跳板覆盖
`e_type/e_machine/e_version`；其他头字段和数据边界仍校验，payload 保持严格
ELF64/AArch64/ET_DYN 校验。最终代码审计、产物及验证范围见
[1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)。

[受保护 App 注入失败分析与修复](REAL_APP_INJECTION_20261101.md) 保留了两类失败
的根因和审计前 1.5.5 快照的第三方 App 实测；该快照与最终发布产物不同，历史结果
不代表最终产物已完成同样的实测。

1.5.4 的普通 App 检测、准确性与业务影响评估见
[1.5.4 检测分析与 Pixel 6 实测](DETECTION_ASSESSMENT_1.5.4_20261031.md)。
148 次正式用例确认执行，通用上下文扫描/受控 x16 两规则共 59 检出、89 漏检；
50/250 ms 扫描占单核约 29.47%/6.91%。未达到全进程高检出且零业务影响的要求，
不代表框架不可检测。此次只改检测夹具与文档，原样 KPM 未修改。

2026-10-31 小米 13 / Android 13 / **5.15.74 / ARM64 / 4K** 实测发现 1.5.3
在 BTI 设备上会在构造完成后返回 libc 时触发 SIGILL。1.5.4 将 EL0 尾部的
`br x16` 改为 `ret x16`，使返回中断指令时的 BTYPE 为 00，并保留原 x30。
修复后普通 App 的 manual / linker / 无 BTF+nofault 回退三套回归通过
（236 / 219 / 178 项断言），没有新增内核告警或 App fatal signal。
实现梳理、跨版本边界、原始失败及产物见 [1.5.4 兼容性报告](COMPATIBILITY_1.5.4.md)。
历史 Pixel 6 / 6.1 证据仍保留在下文；其他版本与 16K/64K 页没有因此获得认证。

1.5.3 历史设备复核（2026-10-31，Pixel 6 / 6.1.134）：已修复 **完成 poll 无法唤醒再次阻塞的 wake 目标**，以及
status 自身排队 poll 导致运行映射信息被遮蔽的问题。自建普通 App 的正式 manual / linker
两套回归和无 BTF/nofault 的 manual 回退回归均通过（236 / 219 / 178 项断言）。
此次未发现新增内核告警，但此前 ucounts 告警的根因仍未确定，不能解释为风险已消除。
实现分析、兼容边界、失败复现和最终产物见 [本次设备兼容性复核](DEVICE_COMPATIBILITY_20261031.md)。

1.5.3 是代码规范与错误处理修订：修复 RELRO 失败仍提交成功、结果字段未初始化、
控制面冲突选项被忽略等问题，加入统一主机测试入口与更严格的编译检查。
实现梳理、修改依据、未解决风险及本轮设备证据见 [代码审查报告](CODE_REVIEW_1.5.3.md)。

此前代码审查轮次 **10 组主机测试通过，设备 148 项功能断言通过，但设备总体验收未通过**：
清理测试进程时出现 `dec_rlimit_ucounts` 内核 WARNING，原因尚未确定。
已完成 `quiesce=idle` 和模块卸载，不能将功能通过解释为无内核风险。

以下 1.5.2 兼容性与 1.5.1 可观测性测试记录为历史证据，不是 1.5.3 的全面认证。

1.5.2 是内核兼容性修订：修正 6.16+ 的 UPROBE 标志位；用 BTF 验证 task_work
通知/取消 ABI；缺少 nofault accessor 时使用可睡眠 GUP 轮询；补齐必需符号检查，
降低内核栈用量，并避免轮询在返回 PC 尚处于临时映射时回收它。
详见 [5.x / 6.x 兼容性实现与验证](COMPATIBILITY_1.5.2.md)。

**不是所有 5.x / 6.x 均已认证。** 该轮真机是 Android 16 / 6.1.134 / ARM64 / 4K。
5.x、其他 6.x、16K/64K 页仍需同一产物的设备回归。无 BTF/nofault 测试构建验证了
回退机制，但它仍运行在 6.1 上，不等于 5.x 实测。下文的 1.5.1 测试数字是历史结果。

1.5.1 的普通 App 检测结论见 [1.5.1 检测点与稳定性评估](DETECTION_POINTS_20261031.md)。1.5.1 的完成路径
是纯 EL0：生成页不执行任何 `svc`、不调用任何库函数、不产生故障或信号。程序恢复被
中断线程的整份寄存器（唯一例外是作为分支寄存器的 x16/IP0）、FPSIMD、SP 和 NZCV，
向私有参数页写入每请求随机 token，然后直接 `br` 回被中断 PC。内核只在 70 个普通
系统调用入口的 before hook，或控制器 `status`/`reap`/`quiesce` 排队的 poll 回调里
观察 token；随后由目标上下文的 cleanup task_work 应用延迟 RELRO 并回收临时映射。

1.5.0 的“真实 libc `usleep()`/`open()` 完成调用 + x6/x7 cookie + 72 字节调用结构”链
已被删除。`test/selfcheck_v15` 的 full 套件在 1.5.0 上 45/45 用例检出；1.5.1 为
45/45 **detections=0**，45/45 `done=syscall`，构造函数/析构函数正常执行、目标存活、
`quiesce=idle`、`kpm num=0`。另用 `KCLF_TEST_NO_TOKEN_HOOK` 构建验证了 `done=poll`
的控制器轮询路径。**这仍不是“不可检测”证明**。

* 生成页没有 `svc`、没有库调用、没有故意缺页的写；完成不产生 syscall、信号或库
  调用现场，因此不存在可被 seccomp/SIGSYS 捕获的完成事件。
* 私有参数页与 ABI 页是独立随机块；保存寄存器、FPSIMD、token、结果槽每个字段都有
  独立随机偏移；ABI 页完成前整页清零。程序不再嵌入 `KCLFBAIL` 等固定字面量。
* 私有页只保存恢复现场和结果；生成程序不再保留完成候选表、cookie、函数表或栈槽。
  `status` 的 `done=syscall|poll` 记录 token 由哪条观察路径命中。
* manual 的 GNU_RELRO 由内核在 cleanup 回调里调用 `mprotect` 应用，生成程序不再
  调用 libc `mprotect`；构造函数执行期间 RELRO 页仍可写。
* 临时映射优先借用目标线程自己的栈；找不到 pt_regs 或栈空间不足时回退到专用临时栈
  （`status` 显示 `stack=transient`）。
* 入口前的重启填充指令、寄存器角色、FPSIMD 槽位和恢复顺序继续随机化。

1.4.2 已改变 1.4.1 两项检测规则所依赖的固定跳板/getpid 和 ELF 头锚点；1.4.x 夹具
只保留旧方法 B，旧方法 A 的完整实现已删除，不能把无事件当作它的重新实测。1.4.3
继续收紧静态标记和部分布局锚点。检测边界和
残余可观测面见 [1.4.2/1.4.3 加固报告](OBSERVABILITY_HARDENING_20261030.md) 与
[1.4.2/1.4.3 进度](HARDENING_PROGRESS_20261030.md)。**本框架仍不承诺“不可检测”**。

1.4.0 起默认使用 **manual 手动 ELF 加载后端**：由模块完成文件快照、映射、符号解析、
重定位、权限/RELRO 和驻留生命周期管理，目标线程只执行 IFUNC resolver、构造/析构
及必要的直接 syscall。框架不再依赖目标用户态的 `dlopen`、`dlsym`、`dlclose` 或
`android_dlopen_ext`；payload 仍可正常导入和使用系统库。

前提是 payload 的全部 `DT_NEEDED`（包括传递依赖）已经加载且保持驻留。缺失依赖或
不支持的 ELF 特性会明确失败，不自动回退。旧后端通过 `,linker` 显式启用。
使用方式、实现细节及兼容边界见 [手动加载说明](MANUAL_LOADER.md)。这不是完整 bionic
linker 的替代品；导入 IFUNC 时仍需执行提供库中的 resolver，不能称为“零系统函数调用”。

1.4.1 修复了真实 App 目标上的两个 manual 后端缺陷：

* 同名 `DT_NEEDED`（典型是 Android 12 中四份 `libc++.so`）不再一律报
  `ambiguous loaded SONAME`。提供库按映射路径确定加载来源，再按
  “同路径/同目录/同 APEX/同分区/平台默认”选择；仍无法区分的不同来源会明确失败。
* IFUNC 所需 `AT_HWCAP`/`AT_HWCAP2` 改由内核 `cpu_get_elf_hwcap()` 读取，不再
  依赖非 dumpable App 读不到的 `/proc/thread-self/auxv`；旧 auxv 路径仅作后备。

`/data/local/tmp/libtest.so` 注入 `com.miHoYo.Nap` 已实测通过，构造函数输出
`Perfare : start dump.....`。这次实测、失败分析和 payload 侧的
`/proc/self/mem` 限制见 [2026-10-29 libtest 实测](LIBTEST_NAP_20261029.md)。

1.3.1 已补齐无 BTF 的内核路径：`get_task_mm` accessor + 目标上下文 proc maps
迭代器；开启 upstream 5.8–5.10 已有的 `TWA_SIGNAL`，兼容旧 procfs `read` ABI。
1.3.1 当时在 Android 12 / 5.10.66 / ARM64 / 4K 设备完成普通 App 全流程与 native 回归。
没有新增包名、UID、签名、授权名单等注入策略限制；原有架构/状态检查保持不变。
完整变更、审计和验证边界见 [1.3.1 审计](COMPATIBILITY_1.3.1.md)。

KCLF 是一个 ARM64 Android 的 KernelPatch 模块：在目标线程下一次返回用户态时重定向
`pt_regs`，用一段按请求生成的 EL0 程序在目标进程里完成所选后端的用户态步骤。完成后
程序在 EL0 恢复被中断线程的寄存器/FPSIMD/SP/NZCV，向私有页写入每请求随机 token，并
直接 `br` 回被中断 PC；框架完成路径不发出 syscall、不产生信号、不调用库函数。token
由目标线程之后的普通 syscall 入口观察，或由控制器 `status`/`reap`/`quiesce` 的 poll
观察。它不使用 ptrace、不暂停目标、不安装信号处理器、不在注入路径上调用 `getpid`。

1.3.0 起支持**普通 64 位 Android 应用进程**：zygote fork 出来、带 seccomp 过滤器、
运行在 `untrusted_app` 域里的第三方应用可以直接作为目标；同时也仍然支持自有 native
测试进程。它只用于自己控制并获授权的进程，不承诺“不可检测”或“对任意应用无副作用”。

## 与 KernelPatch 宿主的关系

1.3.0 不再需要、也不再包含 KernelPatch 宿主补丁。仓库里的 `patches/` 已删除。
构建和运行时使用 stock KernelPatch；控制端仍是 `/data/local/tmp/kpatch`（superkey 保护）。

stock 宿主在 `kpm unload` 时即使模块 exit 回调返回错误也会释放模块代码。因此卸载流程
必须由控制端保证：先 `quiesce`，用 `release` 排空手动驻留镜像，等临时映射和回调均已
回收、再次 `quiesce` 返回 `idle`，再 `unload`。仅 `status` 显示 `no requests` 不够。
模块自身会在 exit 里尝试取消排队 work、做有限等待并移除完成 hook，但无法替代控制端的
排空，也无法保护已经排队的 task_work 回调。

## 构建

在 WSL/Linux shell 或装有 ARM64 GCC 的环境中，从仓库根目录执行：

```sh
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

产物为 `kpms/kclf/kclf.kpm`。必须保留 Makefile 中的 freestanding、通用寄存器、
禁止 outline atomics 和禁止 unwind tables 等选项；模块不链接运行时 libc。

## 加载与基础检查

```sh
adb push kpms/kclf/kclf.kpm /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf probe
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf sym
```

`probe` 会打印内核版本、BTF 布局、`pt_regs` 大小、页大小、wake 能力、完成观察状态
（`completion=el0 watch=on|off installed=<n>/<m> tokens=<n>`）。有 BTF 时验证结构
偏移；没有 BTF 时通过内核 accessor 和目标自身的 `/proc/thread-self/maps` 读取，
不猜结构偏移。无 BTF 的 `pt_regs` 大小由实际 syscall wrapper 帧学习。必需符号/
宿主能力仍需满足。

1.5.2 另显示 `wake_abi=btf|version`、`trace_mask`、`vector_mask`、`nofault`、
`poll_io=gup`。`nofault=0` 时普通 syscall hook 仅用于学习寄存器帧，完成依赖控制端
调用 `status`/`reap`/`quiesce` 排队的目标线程 poll；不会在 hook 内调用可睡眠 GUP。
显式 `wake` 请求的 poll 也会使用 `TWA_SIGNAL`，防止目标再次阻塞后无法观察完成；
这可能再次打断构造函数或原程序的可中断 syscall。默认 resume 请求仍等待自然返回点。

## 控制接口

```text
probe
inject,<tid>,<absolute-so-path>[,manual|linker][,force][,wake][,unload]
images[,cursor]
release,<tid>,<image-id>[,wake][,force]
status
cancel,<slot>
reap
quiesce
sym
help
```

调用形式：

```sh
adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf inject,<tid>,/path/to/lib.so,wake
```

| 选项 | 含义 |
| --- | --- |
| 默认（`manual`） | 自行加载 ELF，只解析已驻留依赖；不调用 bionic loader API |
| `linker` | 显式使用旧版 `__loader_dlopen`/`dlopen` 后端 |
| 默认（`resume`） | 用 `TWA_RESUME` 排队，等目标自然返回用户态；适合会周期性进内核的线程 |
| `wake` | 用 `TWA_SIGNAL` 通知目标（upstream 5.8+），可打断 `epoll_pwait`/`futex`/`ioctl`/`nanosleep` 等阻塞；会改变被中断系统调用的时序 |
| `force` | 跳过 linker/系统调用白名单启发式；不绕过 32 位、SVE/SME、跟踪器等硬性拒绝 |
| `unload` | manual：新镜像构造后析构并回收；linker：调用 `__loader_dlclose`/`dlclose` |
| `keepelf` | manual：保留内存中的 ELF 头和程序头（默认擦除）；供运行期读取自身 `__ehdr_start` 的 payload 使用 |

手动驻留镜像由 `images` 单独列出；如有 `next=N`，继续执行 `images,N`。
重复加载同一进程的同一完整路径只增加引用，不重跑构造函数。`release` 每次减少一个
引用，最后一次运行析构并解除映射。`image=<十进制 ID>` 不是可传给 `dlclose` 的句柄。

`status` 里如果请求长时间停在 `armed`，会显示 `hint=blocked(use wake)`：目标线程正在
睡眠且默认 `resume` 不会主动唤醒它。此时取消后改用 `wake` 重试。

路径必须是绝对路径、长度小于 256 字节，且不能包含逗号、制表符、空格等控制面分隔符；
模块在 `prepare` 阶段用**目标进程的凭据**打开并校验 ELF。

1.5.3 起重复选项、`wake,resume`、`manual,linker`、`linker,keepelf` 会返回错误，
不再静默忽略。`release` 仅接受 `wake` / `resume` / `force`；`resume` 与 `wake`
互斥。整数只接受十进制数字，TID 必须为正且不超过 `INT_MAX`，image ID 为非零 u64，
槽号和分页游标按实际表容量检查。控制命令支持 CRLF，拒绝其他非分隔控制字符。

## 注入普通 app

### 1. 选择进程和线程

```sh
adb shell pidof com.example.app
adb shell ls /proc/<pid>/task
```

主线程的 tid 等于 pid，通常阻塞在 `epoll_pwait` 的 Looper 中；注入主线程时使用
`wake`。也可以选择 binder 线程（`ioctl`）、`kclf-sleeper` 这类周期性休眠
线程（默认 `resume` 即可；Java `Thread.sleep` 的底层 syscall 由 ART 决定）。

普通应用进程有两点与自有 native 测试进程不同：

* **seccomp**：1.5.1 的框架完成路径不发出任何 syscall，因此不依赖某个 syscall
  被过滤器允许；payload 自己的调用仍受 zygote 过滤器和应用附加过滤器约束。
  1.3.0 起不因为 `TIF_SECCOMP` 拒绝普通 app。
* **VMA 很多**：app 常有 2000+ 个 VMA，扫描上限已提高，并会扫描到高地址的
  `/apex/.../linker64` 与 `libc.so`。

### 2. 准备 payload 路径

两种后端都要求目标上下文能够读取 SO，且设备策略允许所需的可执行映射。
manual 额外要求依赖已加载；linker 额外要求通过 app linker namespace 的路径检查。
手动模式使用匿名镜像，不会调用 linker，也不会绕过文件访问、SELinux 或 seccomp 检查。

对于 **linker 后端**，SO 必须同时满足：

1. 目标 app 的 UID 能读；
2. 能通过 app linker namespace 的路径检查，并能被映射为可执行；
3. 模块的 `prepare` 能打开（它同样运行在目标上下文）。

最稳妥的位置是 app 自己的 native library 目录，例如：

```text
/data/app/~~<hash>/<pkg>-<hash>/lib/arm64/libpayload.so
```

可以从 Java 的 `ApplicationInfo.nativeLibraryDir` 获取，或由 `pm path <pkg>` 的
`base.apk` 路径推出同级的 `lib/arm64`。把 payload 放进 APK 的 `lib/arm64-v8a/` 并
以 `android:extractNativeLibs="true"` 安装，会由系统解压到该目录并带上 `apk_data_file`
标签，这是最省事的方式。

旧 linker 后端实测 `/data/local/tmp` 对普通 `untrusted_app` 通常不可用：`prepare` 可以打开文件，
但 linker 会以 `dlopen failed: ... Permission denied` 拒绝映射，请求会安全失败并清理。

### 3. 示例

```sh
KEY=<superkey>
PKG=com.example.app
PID=$(adb shell pidof $PKG | tr -d '\r')
LIB=/data/app/~~.../$PKG-.../lib/arm64/libpayload.so

adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf inject,$PID,$LIB,wake
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf status
```

成功后 `status` 类似：

```text
#0 id=1 pid=7844(com.example.app) state=done stage=restore handle=1 done=syscall via=manual image=1 refs=1 resident=...+...
```

### 4. payload 约束

manual 的构造函数在目标线程直接执行，不持有 bionic loader 锁；这不意味着被打断的
线程没有持有其他用户态锁。只支持不依赖 argc/argv/envp 参数的构造函数。

只有 linker 后端的构造函数在 `dlopen` 内部执行。AOSP bionic 的 linker 使用递归锁，
不能断言同线程再次 `dlopen`/`dlsym`/`dlclose` 必然自死锁；但是异步插入点的
用户态锁、重入与跨线程等待仍未被框架证明安全。
参见 [AOSP linker 锁实现](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/dlfcn.cpp)。

* 不要依赖 JNI/Java 线程状态、不要调用 `JNIEnv`（注入线程不一定是 Java 线程）；
* 不要长时间阻塞、不要在构造函数里等待其他线程；
* manual 的导入从已加载 `DT_NEEDED` 闭包解析，依赖必须始终保持驻留；不要求 payload 无 libc 依赖；
* linker 后端遵循目标 app 命名空间规则；
* 需要后台线程时，自行保证线程生命周期与 `unload` 的竞态。

### 5. 卸载

```sh
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf quiesce
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf images
# 按 images 列表选择同进程的存活线程，逐次释放所有引用
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf release,<tid>,<image-id>,wake
# 等 status 中该请求完成后继续；按需用 images,<next> 翻页
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf reap
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf quiesce
# 必须明确看到 quiesce=idle
adb shell /data/local/tmp/kpatch $KEY kpm unload kclf
```

`quiesce` 之后模块不再接收新注入，但仍接收 `release`，已经在 trampoline 里的请求也会
继续完成。释放前必须由 payload 使用方停止后台线程和回调；引用计数不代表代码无人执行。
在 stock 宿主上不能在 `running`/`preparing`/`ready` 或仍有 cleanup 回调时卸载。

RELRO 或资源清理最多重试 8 次；耗尽或无法排队时报告 `state=failed stage=restore`
和 `mapping retained`，保留资源所有权，`quiesce` 不会返回 idle。此时不要强制卸载：
应由使用方停止对应的自有目标进程，再 `reap`、确认 `quiesce=idle` 后卸载。
不要只根据 `state=done` 判断完成，仍须确认没有 `pending=`、`map=` 或错误信息。

## 限制

1. **仅 64 位目标**。32 位 app 在 hijack 阶段以 `32-bit target unsupported` 拒绝。
2. **不绕过调试/跟踪**。`TIF_SYSCALL_TRACE`、`SYSCALL_EMU`、`SINGLESTEP`、`UPROBE`
   仍拒绝；ptrace 调试器、strace 等场景不支持。
3. **seccomp 允许，但不是任意过滤器的保证**。1.5.1 的框架完成路径本身不再发出
   syscall，因此不可能被 seccomp 拦截；payload 自己的系统调用仍受目标策略约束。
   `SECCOMP_RET_KILL_*` 或未处理的致命 SIGSYS 只会影响 payload/目标，不会把框架的
   token 观察变成检测阳性。框架不绕过、不修改目标的 seccomp 策略。
4. **SVE/SME 状态仍拒绝**；FPSIMD（q0–q31、FPCR/FPSR）在 EL0 程序中保存恢复。
5. **注入是异步的**：目标线程可能停在任意内核返回点。安全点判断只是启发式，不能
   证明用户态锁未被持有；`force` 只用于排障。
6. **不冻结进程**：其他线程仍可并发 `mmap`/`munmap`、修改 linker 状态或发信号。
7. **不保证不可观测**：临时/驻留映射、linker 模式的 loader 记录、构造函数副作用和
   时序都可被目标观察；manual 不注册到 bionic 的 soinfo/调试/展开元数据。1.5.1
   消除了 1.5.0 的完成 syscall、libc 调用帧、x6/x7 cookie 和 72 字节固定调用结构，
   但仍保留匿名 RX 代码页、随机私有状态页、可读 payload 内容和回退栈暴露面。
   完成回收窗口延长到目标线程下一次被观察系统调用或控制器下一次 poll。EL0 完成
   路径不恢复 x16/IP0（分支寄存器），其余 30 个 GPR 和 FPSIMD/SP/NZCV 精确恢复。
   **x16 的 caller-saved 属性只适用于调用边界，不适用于任意异步中断点。** 当前启发式
   无法证明 x16 不存活；即使未使用 `force`，也必须由目标提供可协作的安全边界。
   不能把这个实现称为完整透明的异步上下文恢复。
   遇到持续 trap 或过滤掉框架观察点的环境时，请求可能停留到控制器 poll，属于功能
   失败/未覆盖，不应写成检测阳性。
8. **目标退出时**：请求持有 `struct pid` 身份但不长期持有 `mm`，避免延后 `exit_mmap`
   导致 ActivityManager 收不到进程死亡；目标消失后由 `reap` 清槽，旧 mm 中的临时映射
   随最后使用者退出。
9. **没有宿主 exit-veto**：卸载安全性依赖控制端先 `quiesce` 排空；模块 exit 的
   `-EBUSY` 在 stock 宿主上不会被尊重。
10. **手动加载不是完整动态链接器**：拒绝 payload TLS、payload IFUNC/IRELATIVE、
    textrel、GNU property 等未实现 ABI；不保证 C++ 异常展开、JNI 自动初始化和跨 DSO CFI。
    依赖选择使用映射路径的来源启发式（同目录/APEX/分区/平台默认），不是对 bionic
    namespace 与全局符号插入顺序的完整重建；同名不同来源且无法区分时明确失败。
11. **不绕过 non-dumpable/ptrace 策略**：App 被系统标记为 non-dumpable 时，
    `/proc/self/auxv`、`/proc/self/mem` 对 App 自身凭据也可能是 `EACCES`。框架用
    内核 accessor 解决自己的 `AT_HWCAP` 需求，但不会替 payload 打开这些文件。
12. **没有覆盖所有内核**：1.5.4/1.5.5 的最新真机为 Android 13 / 5.15.74 / 4K；
    其他 5.x、6.x、16K/64K 页仍需同一产物的真机回归。历史 5.10.66 / 6.1.134
    结果不能当作 1.5.5 验收。厂商回移 TIF 位号、隐藏必需符号、宿主不支持该内核
    时，仍可能需要适配；不推测未知函数 ABI 或结构偏移。
13. **借用栈有回退**：只有能找到 pt_regs、栈 VMA 足够大且距 guard 有余量时才借用
    线程栈；否则回退到临时栈块，`status` 会显示 `stack=transient`。深栈、altstack
    或找不到 syscall 帧的目标可能走回退路径。
14. **扩展返回状态有边界**：1.5.4 已在 BTI/PAC libc 的 5.15.74 设备上验证
    `ret x16` 返回；仍不恢复 x16，也未验证 GCS（Guarded Control Stack）。启用
    GCS 的线程不在支持范围，RET 不能被解释为完整的异步上下文恢复协议。
15. **提供库发现是启发式**：manual 以 VMA 起点的 ELF 魔数枚举已加载对象，
    提供库表初始 64、按需倍增、硬上限 4096；分配失败或超过上限时停止准备并回滚，
    不在不完整的候选表中选择依赖。已加载对象仅在 `e_ident[8..15]` 精确匹配
    `ldr x16,#8; br x16` 时允许该跳板覆盖 `e_type/e_machine/e_version`；
    无此签名的非 ARM64/非法类型和版本头仍拒绝。魔数或 `phnum/phoff/phentsize`
    等结构字段被破坏时仍无法识别。
16. **释放前必须停止 payload 线程**：`release`/`unload` 只处理框架的引用，不证明
    没有线程正在镜像代码中执行。payload 自己创建的后台线程未停止时释放，会出现
    执行已解除映射的 SIGSEGV；2026-11-01 的一次测试误用正是这种情形，不是注入
    失败。证据见 [受保护 App 注入失败分析与修复](REAL_APP_INJECTION_20261101.md)。

## 测试

主机回归统一入口（Linux/WSL，需 Python 3、GCC 与 ASan/UBSan）：

```sh
make -C kpms/kclf test
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

主机测试不连接设备、不需要 superkey；覆盖生产解析/兼容性/完成逻辑、故障注入以及
4K/16K/64K 跳板结构检查。后者不是对应页大小的真机验收。
1.5.3 代码审查轮次仅运行 `test/manual-device-test.py` 的自有 native 进程用例；
测试记录和 WARNING 说明见代码审查报告。1.5.4 本轮运行普通 App 双后端及能力回退
回归，见兼容性报告；未重跑以下历史可观测性用例。
1.5.5 的主机入口为 **11 组**；新增 `test_provider_table.py`（提供库表倍增、容量
契约、分配失败/上限停止扫描）和 `test_manual_elf.c` 的已加载对象头校验用例。真机侧新增
`test/realapp-inject.py`（需要 `KCLF_SUPERKEY`）：对已安装且运行中的 App 注入任意
可读 SO，轮询 `status`、保存 logcat/crash buffer，并在默认观察 12 秒后 `release`
检查 App 存活。2026-11-01 的两个受保护 App 历史结果见
[受保护 App 注入失败分析与修复](REAL_APP_INJECTION_20261101.md)，对应审计前快照；
最终发布产物的验证见 [1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)。

1.5.1 普通 App 自检（关键验收；full 45 个用例，期望 `detections=0`、
`done=syscall`、构造函数/析构函数执行、`quiesce=idle`、`kpm num=0`）：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/selfcheck_v15/run.py --serial '<SERIAL>' --suite full --rounds 5
Remove-Item Env:KCLF_SUPERKEY
```

说明见 [test/selfcheck_v15/README.md](test/selfcheck_v15/README.md)。

防检测回归（旧方法 A/B、ELF 头页级扫描、残余内容扫描、`KCLFBAIL` 字面量扫描、
系统调用 guard、`keepelf` 对照）：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/observability/run.py --serial '<SERIAL>' --rounds 5
Remove-Item Env:KCLF_SUPERKEY
```

说明与规则边界见 [test/observability/README.md](test/observability/README.md)。

1.5.1 主机结构审计（生成页无 `svc`、1.4.3 尾段/1.5.0 完成 stub 0 命中、随机布局）：

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

真机 seccomp 现场探针：

```powershell
# 普通 native 进程；安装 openat SECCOMP_RET_TRAP，记录 SIGSYS 的 PC/LR/SP
& '<NDK clang>' --target=aarch64-linux-android31 -O2 -fPIE -pie `
  kpms/kclf/test/seccomp_probe.c -o build/seccomp_probe
adb push build/seccomp_probe /data/local/tmp/kclf-v15-test/
```

注入后读取 `/data/local/tmp/kclf-seccomp.log`。1.5.1 不应产生框架完成 syscall；
探针只用于确认目标自身/payload 的 `openat` 现场是普通 libc 帧，且不存在 1.5.0 的
72 字节完成 stub。

默认 manual 后端（需要先构建 KPM；`--app` 仅使用已安装且停止的自有测试 App）：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
  python kpms/kclf/test/manual-device-test.py --adb '<ADB>' --serial '<SERIAL>' --clang '<NDK clang>' --app
} finally { Remove-Item Env:KCLF_SUPERKEY }
```

用户提供 SO 的真实 App 实测（2026-10-29，manual 后端，`libtest.so` →
`com.miHoYo.Nap`）的完整命令、Perfare 输出和失败分析见
[LIBTEST_NAP_20261029.md](LIBTEST_NAP_20261029.md)；驱动和证据在
`build/kclf-libtest-20261029-final/`。

历史 native 回归已显式选择 `linker` 后端（默认返回点、wake、unload、seccomp、取消、目标退出、映射回收、
reload/unload 等）：

```powershell
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' -Adb '<ADB>'
```

历史 linker 普通 app 测试需要先构建测试 APK，再运行 app 测试脚本；说明见
[test/app/README.md](test/app/README.md)。

已安装的普通 ARM64 app 可以使用 `test/package-test.py` 做 linker 后端独立标记测试：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/package-test.py `
  --package com.miHoYo.Nap --package com.yhhy.neon.mi `
  --serial '<SERIAL>' `
  --clang 'D:/androidSDK/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/clang.exe'
Remove-Item Env:KCLF_SUPERKEY
```

脚本要求选中的 App 测试前未运行，并且设备尚未加载 `kclf`。它会启动和停止这些
App，在各自 native library 目录临时部署独立命名的测试 SO，验证主线程重复
加载/卸载、Binder 线程、驻留、失败恢复和重启；最后删除测试 SO/标记并排空卸载
KPM，恢复 App 停止状态。测试不清空 App 数据。证据保存在 `build/kclf-packages-*/`。
本机两个目标包的完整结果见 [2026-10-28 App 实测](APP_INJECTION_TEST_20261028.md)。

主机侧辅助函数测试（WSL/Linux，GCC + Python 3）：

```sh
python3 kpms/kclf/test/test_helpers.py
python3 kpms/kclf/test/test_maps.py
python3 kpms/kclf/test/test_compat.py
python3 kpms/kclf/test/test_symbols.py
python3 kpms/kclf/test/test_completion.py
python3 kpms/kclf/test/test_manual_elf.py
python3 kpms/kclf/test/test_provider.py
python3 kpms/kclf/test/test_provider_table.py
# 可选：末尾传入保存的 vmlinux BTF 文件，验证其真实布局选择
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  kpms/kclf/test/test_btf.c -o /tmp/kclf-test-btf
/tmp/kclf-test-btf
```

## 文档

- [COMPATIBILITY_1.5.5.md](COMPATIBILITY_1.5.5.md)：最终 1.5.5 代码审计、发布产物与验证范围。
- [REAL_APP_INJECTION_20261101.md](REAL_APP_INJECTION_20261101.md)：受保护 App 的两类
  prepare 失败、原始字节对比及审计前 1.5.5 快照的历史真机结果。
- [COMPATIBILITY_1.5.4.md](COMPATIBILITY_1.5.4.md)：1.5.4 实现、5.15 BTI 返回故障修复及普通 App 实测。
- [COMPATIBILITY_1.5.2.md](COMPATIBILITY_1.5.2.md)：历史 5.x/6.x 兼容修订、真机证据与未验证范围。
- [DETECTION_POINTS_20261031.md](DETECTION_POINTS_20261031.md)：历史 1.5.1 检测点、
  纯 EL0 完成协议、45/45 自检结果、poll 路径、残余可观测面与边界。
- [DETECTION_POINTS.md](DETECTION_POINTS.md)：1.5.0 历史基线（libc 完成调用、
  主机 30,000 样本审计、真机 SIGSYS 现场），不代表当前实现。
- [HARDENING_PLAN_20261031.md](HARDENING_PLAN_20261031.md)：1.5.1 改造方案、
  逐项实现进度、真机证据与代价。
- [test/seccomp_probe.c](test/seccomp_probe.c)：真机 openat SIGSYS 现场探针
  （用于确认 1.5.1 不再出现框架完成调用/72 字节 stub）。
- [MANUAL_LOADER.md](MANUAL_LOADER.md)：手动加载、依赖来源选择、随机 pad/ELF 头擦除、
  `keepelf`、边界与验证记录。
- [OBSERVABILITY_HARDENING_20261030.md](OBSERVABILITY_HARDENING_20261030.md)：1.4.2/1.4.3
  对 1.4.1 两个检测点的加固设计、真机验证与残余暴露（历史）。
- [HARDENING_PROGRESS_20261030.md](HARDENING_PROGRESS_20261030.md)：1.4.2/1.4.3
  防检测改造的计划、逐项进度、验证和未完成事项（历史）。
- [OBSERVABILITY_REPORT.md](OBSERVABILITY_REPORT.md)：1.4.1 普通 App 可观测性报告，
  包含两项真机确认方法、正反例、检测副作用及被排除的方法；其方法 A/B 对 1.4.2+
  不再适用，保留作为历史基线。
- [LIBTEST_NAP_20261029.md](LIBTEST_NAP_20261029.md)：libtest.so 注入
  com.miHoYo.Nap 的实测、两个缺陷的根因、Perfare 输出与 payload 侧限制。
- [COMPATIBILITY_1.3.1.md](COMPATIBILITY_1.3.1.md)：历史内核兼容修改、设备测试与未验证项。
- [COMPATIBILITY_AUDIT.md](COMPATIBILITY_AUDIT.md)：1.3.0 的历史实现、兼容性、设备结果与限制。
- `IMPLEMENTATION.md`、`HARDENING.md`：历史版本资料，
  不代表当前实现；其中关于宿主补丁、seccomp 拒绝和默认行为的段落已过时。
