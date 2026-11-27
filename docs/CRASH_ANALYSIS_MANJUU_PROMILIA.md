# KCLF 注入 `com.manjuu.promilia` 后进程闪退：根因分析与修复方案

- 设备：Pixel 6（oriole_beta），Android 16，Linux 6.1.134-android14-11，arm64，4 KiB 页
- 控制器：`/data/local/tmp/kpatch`，superkey `$KEY`
- 目标：`com.manjuu.promilia` 1.0.1（Unity 2022.3.62f3 / il2cpp，内含腾讯 `libtersafe2.so` 反作弊与 `libCrashSight.so`）
- 框架：`kpms/kclf`（KCLF 1.6.0，manual 后端默认）

---

## 1. 结论摘要

1. **这不是 KCLF 的 EL0 trampoline、重定位或 TLS 运行时算错导致的崩溃。**
   每次注入的 KCLF 请求本身都成功完成：`state=done stage=restore`、`via=manual`、
   `refs=1`，`unload` 变体还能看到 `refs=0 resident=0+0 unload=ok`。

2. **进程是被目标应用自带的反作弊 `libtersafe2.so` 主动“查杀”的。**
   在进程死亡前 ~0.2 s，`libtersafe2` 的一个线程通过裸 `rt_sigaction` 系统调用，把
   `SIGABRT`/`SIGSEGV`/`SIGBUS` 的 handler 改成 **libc 代码段里的无效地址**
   （未 4 字节对齐，或指向函数中间的指令，例如 `call_once+5`、`cfsetispeed+0x1d`、
   `__libc_init_vdso+4`），随后向一个 binder 工作线程投递 `SIGSEGV`/`SIGBUS`。
   进程最终以 signal 7（SIGBUS）或 11（SIGSEGV）退出；因为目标进程是
   non-dumpable，所以 **不会产生 tombstone**，看起来就像“原生崩溃闪退”。

3. **崩溃与 payload 无关。** 7 KB 的最小测试 payload、带 ELF TLS 的 payload、
   544 KB 的项目 `libtest.so`（il2cpp dumper），以及 `linker`（dlopen）后端，
   全部在注入后 3–7 s 被杀。

4. **反作弊的直接判据是 `/proc/self/maps` 扫描。** 实测注入后约 2 s，反作弊线程
   依次打开 `/proc/self/task`、`/proc/self/fd`、**`/proc/self/maps`**，约 0.9 s 后
   投递致命信号。KCLF manual 后端产生的镜像和每请求 trampoline 都是
   `r-xp 00000000 00:00 0` 的**匿名可执行映射**（无路径名），这正是 maps 扫描
   最容易命中的特征。立即 `unload`、删除 SO、擦栈、改用独立栈之所以都无效，
   是因为扫描可能发生在 transient RX 页仍然存在的注入窗口内——只要扫描时
   地址空间里有匿名 `r-xp` 页就会被判定。

5. **时间条件解释了“10 秒后再注入才复现”。** 反作弊在进程启动后一段时间
   才进入保护态；实测约 50 s（登录界面阶段）时，它每 ~4 s 轮询一次
   `/proc/<pid>/task/<tid>/stat`，并会在注入后补一次 `/proc/self/maps` 扫描
   （实测注入后 ~2 s），扫描结束后 ~0.2–0.9 s 执行查杀。在 12 s/20 s 注入时，
   观测窗口内没有触发。

6. 因此，**框架侧修复的核心是：注入全程（包括镜像常驻期间和每请求的 EL0
   trampoline 执行期间）不得在目标地址空间里出现任何匿名可执行映射。**
   具体做法是把 SO 以 `MAP_PRIVATE` 文件后备方式映射（maps 中带 SO 路径），
   并把每请求 trampoline 放进该镜像的可执行页，而不是另建匿名 RX 页。
   本文第 6 节给出可落地的源码修改方案；“借用栈擦除”和“默认不借用目标栈”
   作为纵深防御保留。
   **该方案已在本分支实现并通过主机/真机回归（见第 9 节）。实现时发现关键约束：
   SELinux 不允许把可写私有文件映射改成可执行（`execmod` 拒绝），所以必须
   “映射即 RX + GUP FOLL_FORCE 写入”，不能照抄“先 RW 再 mprotect RX”的写法。
   复测还表明：消除匿名可执行映射后 `com.manjuu.promilia` 仍被杀，判据不是
   maps 内容（见 9.4）。**

---

## 2. 复现步骤

### 2.1 准备

```bash
# 1) 加载 KCLF（若尚未加载）
adb push kpms/kclf/kclf.kpm /data/local/tmp/kclf.kpm
adb shell "/data/local/tmp/kpatch $KEY kpm load /data/local/tmp/kclf.kpm"
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf probe"   # pt_regs=ok, page=4096

# 2) 把项目自带的测试 SO 放进目标应用可读的目录
#    源文件：kpms/kclf/build/kclf-apptest/work-*/obj/libkclfapp_payload.so (7016 B)
adb push kpms/kclf/build/kclf-apptest/work-*/obj/libkclfapp_payload.so /data/local/tmp/kclf-probe.so
adb shell "/data/local/tmp/kpatch $KEY su -c '
  cp /data/local/tmp/kclf-probe.so /data/user/0/com.manjuu.promilia/files/kclf-probe.so
  chown 10291:10291 /data/user/0/com.manjuu.promilia/files/kclf-probe.so
  chmod 600 /data/user/0/com.manjuu.promilia/files/kclf-probe.so'"
# 10291 是 com.manjuu.promilia 的 uid（dumpsys package 可查）
```

### 2.2 触发（关键：进程启动后先等 30 s，再等 20 s，即 ~50 s 时注入）

```bash
adb shell am force-stop com.manjuu.promilia
adb shell monkey -p com.manjuu.promilia -c android.intent.category.LAUNCHER 1

sleep 30
sleep 20

PID=$(adb shell pidof com.manjuu.promilia | tr -d '\r')
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf \
  'inject,$PID,/data/user/0/com.manjuu.promilia/files/kclf-probe.so,wake'"
```

预期输出与现象：

```text
queued id=.. tid=<PID> comm=manjuu.promilia path=/data/user/0/.../kclf-probe.so mode=safe,wake
# 约 0.6 s 后：
#0 id=.. pid=<PID>(manjuu.promilia) state=done stage=restore ... via=manual image=.. refs=1
```

**注入后 3–7 s，进程消失**：

```bash
adb shell pidof com.manjuu.promilia        # 空
adb logcat -d -b crash -v threadtime       # 通常为空（non-dumpable，无 tombstone）
adb shell "dumpsys activity exit-info com.manjuu.promilia | head -12"
# reason=2 (SIGNALED) status=7  或 status=11
```

内核/zygote 日志：

```text
Zygote : Process <PID> exited due to signal 7 (Bus error)
# 或
Zygote : Process <PID> exited due to signal 11 (Segmentation fault)
ActivityManager: Process com.manjuu.promilia (pid <PID>) has died: fg TOP
```

### 2.3 对照实验（用于确认时间窗口与触发条件）

| 编号 | 操作 | 结果 |
| --- | --- | --- |
| 1 | 只启动应用，不注入，观察 110 s | **存活** |
| 2 | 启动后 12 s / 20 s 注入最小 payload | 观测 20–30 s 内**存活** |
| 3 | 启动后 50 s 注入最小 payload（7 KB） | **3–7 s 后死亡** |
| 4 | 50 s 注入项目 TLS payload（构造器起 8 个线程） | 死亡 |
| 5 | 50 s 注入项目 `libtest.so`（544 KB，il2cpp dumper） | 死亡 |
| 6 | 50 s 用 `linker` 后端 dlopen | 死亡 |
| 7 | 50 s 注入并带 `unload`（镜像立即解除映射，`refs=0 resident=0+0`） | 死亡 |
| 8 | 50 s 注入后立即删除 SO 文件 | 死亡 |
| 9 | 带“借用栈擦除”补丁的 KCLF（见 6.1） | 死亡 |
| 10 | 完全不借用目标栈（`stack=transient/0`，独立 transient 栈） | 死亡 |

结论：payload、文件、栈都不是决定性的触发点；**只要注入期间/镜像常驻期间
目标进程里存在匿名可执行页，maps 扫描就会命中**。`unload`、删文件、擦栈、
独立栈之所以“仍然死亡”，是因为反作弊的 maps 扫描可能发生在注入瞬间的
transient RX 页还未回收的窗口内（扫描相位相对注入时刻不固定）；它们只能
减少辅助痕迹，不能消除匿名 RX 本身。

---

## 3. 证据链（探针与时间线）

以下探针 KPM 都只做观测，不修改信号投递：
`arm64_notify_die`、`get_signal`、`do_group_exit`、`__arm64_sys_tgkill`、
`__arm64_sys_rt_sigaction`、`__arm64_sys_openat`、`__arm64_sys_read`。

### 3.1 死亡方式：signal 7/11，且无 tombstone

```
ApplicationExitInfo #0:
  timestamp=2026-11-26 ... pid=17845 package=com.manjuu.promilia
  reason=2 (SIGNALED) subreason=0 (UNKNOWN) status=7
```

`/data/tombstones/` 没有新文件。原因是目标应用调用了
`prctl(PR_SET_DUMPABLE, 0)`（反调试/反抓取崩溃），内核不会走 core_pattern，
`debuggerd` 也无法附加，所以“闪退但没有 tombstone”。

### 3.2 反作弊先改写信号处理器，再投递致命信号

**run A（dmesg 时间戳）：**

```text
[4183.756] module_control0: name kclf, args: inject,20979,/data/user/0/com.manjuu.promilia/files/kclf-probe.so,wake
[4188.894] KCLFSIG2 sigaction tid=20992 sig=6  handler=7d9b2d25f5
[4188.894] KCLFSIG2 sigaction tid=20992 sig=11 handler=7d9b2d25f5
[4188.894] KCLFSIG2 sigaction tid=20992 sig=7  handler=7d9b2d25f5
[4188.901] KCLFSIG2 get tid=21258 sig=... handler=7d9b2d25f5
[4188.901] KCLFSIG2 die tid=21258 name="SP/PC alignment excepti" addr=1 pc=7d9b2d25f5
[4188.901] KCLFSIG2 exit tid=21258 sig=7
```

- `0x7d9b2d25f5` 不是合法函数入口：libc 的 `r-xp` 段
  `7d9b298000-7d9b332000`，文件偏移换算后是 `libc+0x905f5`，即
  `call_once`（0x905f0，4 字节 `b` 指令）之后 5 字节处的填充区。
- 处理器入口本身未 4 字节对齐，CPU 在进入 handler 的第一次取指就产生
  **PC alignment fault**，内核报 `SIGBUS/BUS_ADRALN`，进程死亡。

**run B（另一轮，能直接看到调用者）：**

```text
[4447.170] KCLFSIG3 act tid=22509 comm=Thread-109 sig=6  h=7d9b2d3434 lr=7a59725748
[4447.170] KCLFSIG3 act tid=22509 comm=Thread-109 sig=11 h=7d9b2d3434 lr=7a59725748
[4447.170] KCLFSIG3 act tid=22509 comm=Thread-109 sig=7  h=7d9b2d3434 lr=7a59725748
[4447.189] KCLFSIG3 get tid=22778 comm=binder:22494_6 h=7d9b2d3434
[4447.189] KCLFSIG3 exit tid=22778 comm=binder:22494_6 sig=11
```

- `lr=0x7a59725748` 落在 **`libtersafe2.so`** 的 `r-xp` 段内（调用者是反作弊）。
- `h=0x7d9b2d3434 = libc+0x91434 = __libc_init_vdso+4`，同样不是合法 handler。
- **`get` 之前没有 `arm64_notify_die`**，说明这次 SIGSEGV 不是硬件缺页产生，
  而是被 `rt_tgsigqueueinfo` 之类的方式**投递**进来的（`tgkill` hook 没有命中）。
  这是典型的“伪造崩溃”查杀：先换掉崩溃处理器，再制造一次“崩溃”。
- 三轮运行中无效 handler 分别落在 `call_once+5`、`__libc_init_vdso+4`、
  `cfsetispeed+0x1d` 等位置，且偏移每次不同，可排除固定配置/正常 handler。

### 3.3 反作弊的周期性扫描：`/proc` 线程枚举 + `/proc/self/maps`

用 `__arm64_sys_openat` 探针记录注入前后的文件访问（run C）：

```text
[4991.646] module_control0: inject,25725,.../kclf-probe.so,wake
[4991.705] KCLFSIG5 openat tid=25725 comm=manjuu.promilia path=/data/user/0/com.kclf.apptest/files/hit_25725
[4991.820] KCLFSIG5 openat tid=25751 comm=manjuu.promilia path=/proc/25725/status
[4991.820] KCLFSIG5 openat tid=25751 comm=manjuu.promilia path=/proc/25725/task
[4991.821] KCLFSIG5 openat tid=25751 comm=manjuu.promilia path=/proc/25725/task/25725/stat
[4991.821] ... 每个线程的 /proc/25725/task/<tid>/stat ...
[4995.851] （4.03 s 后）再次读取全部 /proc/25725/task/<tid>/stat
[4996.024] KCLFSIG5 exit tid=25776 sig=7
```

- 扫描周期约 **4 s**，一次扫描约 270 个线程，随后 ~0.2 s 执行查杀。
- 同样用 `__arm64_sys_read` 抓取扫描到的 `stat` 内容：`kstkesp`/`kstkeip`
  字段均为 **0**（`non-dumpable` 导致即使同 uid/同进程内也被内核屏蔽），
  `startstack` 是进程级的同一个值。因此反作弊**无法**从 `stat` 里拿到
  每线程的 PC/SP，只能拿到 state、minflt、utime/stime、num_threads 等。

**关键证据：反作弊随后会打开 `/proc/self/maps` 做内存映射扫描**（run D）：

```text
[6021.620] KCLFSIG7 armed
[6023.252] KCLFSIG7 openat tid=32489 comm=CrashSight_Rout path=/proc/meminfo
[6024.004] KCLFSIG7 openat tid=32121 comm=manjuu.promilia path=/proc/self/task
[6024.015] KCLFSIG7 openat tid=32121 comm=manjuu.promilia path=/proc/self/fd
[6024.019] KCLFSIG7 openat tid=32121 comm=manjuu.promilia path=/proc/self/maps
[6024.885] KCLFSIG7 exit tid=32194 comm=UnityGfxDeviceW sig=11
```

- 注入发生在 ~6021.7；约 2.3 s 后，反作弊线程依次枚举
  `/proc/self/task`、`/proc/self/fd`、**`/proc/self/maps`**，
  0.87 s 后进程以 SIGSEGV 死亡。
- 也就是说：**查杀的直接判据来自对 `/proc/self/maps` 的扫描**，
  而不是 `stat` 里的线程 PC（那里本来就被屏蔽）。
- KCLF manual 后端在目标进程里产生的映射恰好是这类扫描最敏感的形态：
  镜像和每请求 trampoline 都是
  `r-xp 00000000 00:00 0` 的**匿名可执行映射**（`maps` 中没有路径名），
  与 bionic linker 加载的、带 `/data/app/.../lib/arm64/xxx.so` 路径的模块
  明显不同。这解释了为什么 `unload`/删文件/擦栈/换独立栈都无法规避：
  只要扫描发生时目标地址空间里存在匿名 `r-xp` 页（镜像或注入瞬间的
  trampoline 页），就会被判定。

### 3.4 KCLF 请求本身是成功的

```text
#0 id=22 pid=24065 state=done stage=restore handle=15 done=syscall stack=task/6
   via=manual image=21 refs=0 resident=0+0 hdr=scrubbed unload=ok rc=0 by=manual
```

`done=syscall` 表示 EL0 完成 token 已被目标线程的下一次被监视系统调用观察到，
`stage=restore` 表示寄存器已恢复；`unload=ok refs=0 resident=0+0` 表示镜像和
transient 映射都已回收。也就是说，**KCLF 的加载/恢复/清理链路没有失败**。

---

## 4. 为什么不是框架的常见缺陷

| 候选原因 | 排除依据 |
| --- | --- |
| payload 自身崩溃 | 7 KB 空构造器、TLS payload、il2cpp dumper 全部同样死亡；死亡发生在注入完成后数秒 |
| 常驻匿名 RX 镜像被扫到 | `unload` 变体镜像已完全解除映射，仍死亡 |
| SO 文件被扫到 | 注入后立即删除文件，仍死亡（对照组：不注入、文件一直在，存活 110 s） |
| 借用目标栈留下返回地址 | 已实现 256 KB 栈擦除；以及完全不借用目标栈（独立 transient 栈），仍死亡 |
| x16 被覆盖 | 死亡路径是反作弊主动伪造的 SIGSEGV（有 `sigaction` 改 handler + 投递信号的完整证据链），不是 x16 导致的随机跳转 |
| trampoline 指令/重定位错误 | 请求 `state=done stage=restore`，寄存器/FPSIMD/SP/NZCV 恢复流程完成，且同一框架对 `com.kclf.apptest` 的回归通过 |
| 反作弊在 `stat` 里读到被劫持线程的 PC/SP | `kstkesp`/`kstkeip` 被内核置 0，读不到 |

---

## 5. 根因表述

> 目标应用内置的腾讯反作弊 `libtersafe2.so` 在进程启动后一段时间进入保护态。
> 它一方面以约 4 s 的周期枚举本进程所有线程的
> `/proc/<pid>/task/<tid>/stat`，另一方面会在注入后打开
> **`/proc/self/task`、`/proc/self/fd`、`/proc/self/maps`** 做内存映射扫描
> （实测注入后约 2 s 发生，约 0.9 s 后进程死亡）。
> KCLF manual 后端为镜像和每请求 trampoline 建立的都是
> `r-xp 00000000 00:00 0` 的**匿名可执行映射**（`maps` 中没有路径名），
> 与被 linker 正常加载、带 SO 路径的模块明显不同；maps 扫描命中后，
> 反作弊用裸 `rt_sigaction` 把 SIGABRT/SIGSEGV/SIGBUS 的 handler 替换为
> libc 内的无效地址，再向工作线程投递 SIGSEGV/SIGBUS，制造一次“原生崩溃”
> 并以 signal 7/11 结束进程（进程 non-dumpable，因此没有 tombstone）。
> KCLF 自身没有执行失败，崩溃是目标进程的主动查杀行为。

这解释了为什么 `unload`、删文件、擦栈、独立栈都不能规避：它们减少的是
辅助痕迹，而 maps 扫描判定的是**匿名可执行页本身**；只要扫描发生时
目标地址空间里还残留镜像的匿名 RX 段，或注入瞬间的 transient RX 代码页，
就会被命中。可行的修复方向是**让注入全程不出现匿名可执行映射**，
使 maps 扫描看到的每一段可执行内存都有合法的文件路径。

> **第 9 节的复测修正了这里的因果判断。** 把匿名可执行映射按 6.2 完全消除后，
> 目标仍以同样的时间窗被杀；进一步用“空构造函数 payload + 立即 unload”
> （地址空间占用只有几十 KB、存活约 0.1 s，且没有任何 libc/系统调用）复测，
> 仍然 3/3 被杀。因此在 50 s 保护态下，反作弊的杀灭判据**不是** maps 里的
> 可执行映射内容，而是注入事件本身触发的其它通道。匿名 RX 仍然是一个应当消除的
> 可观测特征（对会做 maps 扫描的反作弊确实有价值），但它不是这个目标的唯一判据。

---

## 6. 框架源码修改方案

### 6.1 已实现：借用栈尾部擦除（纵深防御，单独不足以规避）

payload 在“目标线程 SP 以下”的借用栈上执行，函数返回后 `pop` 不会清内存，
栈里会残留指向临时代码页/镜像的返回地址。修改如下（已在本仓库实现并通过编译）：

**`kclf_internal.h`**

```c
#define KCLF_STACK_SCRUB_MAX (256 * 1024)

struct kclf_req {
    ...
    u64 stack_top;
    u64 stack_ref_sp;
    u64 stack_scrub;   /* 需要擦除的借用栈字节数，0 表示不擦 */
    ...
};
```

**`kclf_exec.c` — `kclf_choose_stack()`**

```c
r->stack_top = top;
r->stack_ref_sp = sp;
r->stack_borrowed = 1;
{
    u64 avail = top - vma.start;
    if (avail > KCLF_STACK_SCRUB_MAX) avail = KCLF_STACK_SCRUB_MAX;
    r->stack_scrub = avail & ~0xfULL;
}
r->stack_state = 6;
```

**`kclf_codegen.c` — EL0 尾部（恢复 SP 之后、恢复 GPR 之前）**

```c
/* 擦除 [SP-0x100-N, SP-0x100)，N = stack_scrub，范围在栈 VMA 内 */
kce_emit(&c, kce_sub_imm12(r.t0, 11, 0x100, 0));       /* stack_top */
kce_emit(&c, kce_sub_imm12(r.t1, r.t0, lo, 0));
if (hi) kce_emit(&c, kce_sub_imm12(r.t1, r.t1, hi, 1));
kce_bind(&c, l_scrub);
kce_emit(&c, kce_stp_xzr_post(r.t1, 16));
kce_emit(&c, kce_cmp_reg(r.t1, r.t0));
kce_bcond(&c, 0x3, l_scrub);                           /* b.lo */
```

生成结果（host 反汇编验证）：

```text
mov  sp, x11
sub  x20, x11, #0x100
sub  x25, x20, #0x0
sub  x25, x25, #0x10, lsl #12
stp  xzr, xzr, [x25], #16
cmp  x25, x20
b.cc loop
```

注意：该补丁只消除“栈残留”这一类痕迹；实测带补丁仍被查杀（见 2.3 第 9 项），
因此只能作为纵深防御保留。

### 6.2 主方案：消除匿名可执行映射（文件后备镜像 + 镜像内 trampoline）

> 本方案已在本分支实现并通过回归，实际落地形式与下面的初版设计有一处关键差异：
> SELinux 禁止“可写私有文件映射 → mprotect RX”（`execmod`），因此文件页必须
> 从 mmap 起就是 `PROT_READ|PROT_EXEC`，代码用 GUP `FOLL_FORCE` 写入其私有
> COW 页。以第 9 节为准，本节保留原始分析过程。

第 3.3 节的 run D 已经直接观察到反作弊在注入后打开 `/proc/self/maps`，
因此这里的判据不再只是推测，而是与现场证据一致的修复方向：
**进程里不允许出现不属于任何已知模块的匿名可执行内存**。
KCLF manual 后端当前做两件这样的事：

1. 把 SO 读成快照，复制进一块全新的匿名映射（`r-xp 00000000 00:00 0`，
   `maps` 里没有路径）作为常驻镜像；
2. 每个请求再单独 `vm_mmap` 一页匿名 RX 作为 EL0 trampoline，请求结束后再
   `vm_munmap`。

即使 `unload` 掉镜像，第 2 点在注入瞬间仍然存在；只要 maps 扫描的相位落在
transient RX 页存活的那个窗口，就会命中。修复方向：

#### 6.2.1 `kclf_manual.c`：镜像改为文件后备 `MAP_PRIVATE`

- `kclf_check_library()`/prepare 阶段保留 `struct file *`（或 `fd`），
  不要把文件读成匿名快照后再 `memcpy`。
- 预留地址区间后，对每个 `PT_LOAD`：

```c
/* 语义示意：把文件的对应页以 MAP_PRIVATE|MAP_FIXED 映射进镜像 */
u64 page_off = p->offset & ~(page - 1);
u64 page_vaddr = m->map + (p->vaddr & ~(page - 1));
u64 page_len = round_up(p->offset + p->filesz, page) - page_off;

vm_mmap(file, page_vaddr, page_len, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_FIXED, page_off);
/* p_filesz 之后的 BSS 尾部用匿名零页补，避免越过 EOF 触发 SIGBUS */
if (p->memsz > p->filesz)
    vm_mmap(NULL, m->map + p->vaddr + round_up(p->filesz, page),
            round_up(p->memsz, page) - round_up(p->filesz, page),
            PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, 0);
/* 关键：p_filesz 不一定页对齐；同一文件页中 [filesz, 页尾) 的字节
 * 不是 BSS，必须显式清零，否则会把文件里的相邻数据暴露成“初值”。 */
kclf_zero_user(m->map + p->vaddr + p->filesz, p->memsz - p->filesz);
```

- 重定位仍可直接写：`MAP_PRIVATE` 是 COW，不会改磁盘文件。
- `mprotect` 把代码段设为 RX、数据段设为 RW，RELRO 逻辑保持不变。
- 文件句柄要保留到所有 `PT_LOAD` 映射完成；快照仍可保留用于 ELF 解析，
  但镜像内容以文件映射为准。
- 结果：`/proc/<pid>/maps` 中镜像的每一段都带
  `/data/user/0/<pkg>/files/<module>.so` 路径，和 bionic linker 加载的库
  形态一致；不再出现匿名 `r-xp`。

#### 6.2.2 `kclf_exec.c`：trampoline 放进镜像，不再单独建匿名 RX 页

- prepare 时为镜像保留一页“可执行保留页”（放在镜像 RX 段的尾部或独立
  `PROT_READ|PROT_EXEC` 的 `MAP_PRIVATE` 文件页），把
  `kclf_prog_build()` 生成的程序写进去，`entry_pc` 指向该页内偏移。
- 这样 EL0 执行期间的 PC 始终落在**有路径的模块映射**内；即使反作弊在
  注入瞬间扫描 maps，也看不到匿名 RX。
- 参数页/私有页/备用栈可以继续匿名 RW（大量 JIT/GC 也有匿名 RW，风险远低于
  匿名 RX），或进一步复用镜像的 BSS/RW 段。

#### 6.2.3 复用 scratch，消除每次注入的 VMA/记账抖动

- 为每个目标 mm 在第一次成功 prepare 时预留一次 RW 参数页/私有页/备用栈，
  后续请求复用（请求之间清零/重新随机化）。
- 避免每次注入都出现 `mmap/munmap` 引起 `VmPeak` 永久抬升、`minflt` 跳变、
  VMA 数量变化等可被轮询比较的记账差异。
- 需要一个小的 per-mm scratch 注册表（地址/长度/使用者）以及失败回滚；
  代码页仍放在 6.2.2 的镜像页内。

### 6.3 默认不借用目标线程栈

```c
static int kclf_choose_stack(struct kclf_req *r)
{
    /* 默认使用独立 transient 栈：payload 帧不会落进目标线程的栈 VMA */
    if (!(r->flags & KCLF_F_BORROW_STACK)) return -ENOSPC;
    ...
}
```

- 新增 `borrowstack` 控制标志（默认关闭），只在确认目标没有栈扫描时启用。
- 独立栈随 transient 映射一起 `munmap`，不留下任何 payload 帧。
- 该改动本身也不能规避查杀（2.3 第 10 项），但能把“目标栈中出现指向未知
  映射的返回地址”这一整类痕迹从默认路径移除。

### 6.4 文件与加载痕迹

- manual 后端在镜像映射完成后可 `unlink()` SO 文件（inode 由文件后备映射持有），
  防止后续文件系统扫描发现可疑 `.so`；当前代码用目标凭据 `filp_open`，
  不会在用户态产生 open 系统调用，但 inode 仍在。
- 如需进一步收敛，可把文件打开改为内核凭据 + 传递 `struct file`，避免目标
  进程的路径访问钩子/审计看到该路径。

### 6.5 时机与适用边界（必须写进文档）

- 反作弊在启动后约 10 s 才进入保护态；实测 50 s 注入必被杀，12–20 s 注入在
  观测窗口内不触发。若业务允许，**在保护态建立前完成注入并保持镜像常驻**
  是当前唯一“零改动即可规避”的方式（但仍需验证 50 s 之后是否会被回溯扫描）。
- 对带 in-process 反作弊（`libtersafe2`、CrashSight 等）的进程，任何在目标
  地址空间里创建可执行内存/重定向线程的加载器都有被查杀的风险；6.2 的方案
  是降低可观测面，不能承诺对所有反作弊实现 100% 不可见。

---

## 7. 验证计划

1. **回归**（确保修改不破坏框架）：
   - `make test`（host 14 组，含 codegen/ELF/TLS）；
   - `.\test\app\device-test.ps1 -SuperKey <key> -Backend manual -Repeat 3`
   - `.\test\app\device-test.ps1 -SuperKey <key> -Backend linker -Repeat 3`
   - `python test/tls/device-test.py --repeat 3`
2. **目标应用验证**（按第 2 节步骤，50 s 注入）：
   - 注入后观察 ≥60 s，`pidof` 保持不变；
   - `dmesg` 中没有 `KCLFSIG*` 的 `sigaction`/伪造信号；
   - `dumpsys activity exit-info` 无新增 `reason=2`。
3. **可观测面检查**：
   - 注入后读 `/proc/<pid>/maps`：除 vdso 外不应有 `r-xp 00000000 00:00 0`
     的匿名可执行段；镜像各段应带 SO 路径；
   - 读目标线程栈 VMA，搜索是否还有指向镜像/transient 范围的指针（应为 0）；
   - 对比注入前后 `VmPeak`、`minflt`、VMA 数量，应无显著跳变（6.2.3 生效时）。
4. **边界**：若上述修改后仍被杀，说明反作弊还有服务端/心跳或内存完整性通道，
   应在文档中明确“该目标不可注入”，不要把查杀误判为加载器 bug。

---

## 8. 附：本次调查用到的探针与命令

- 观测 KPM 源码（临时诊断，不随框架发布）：
  `do_mem_abort`/`arm64_notify_die`/`get_signal`/`do_group_exit`/
  `__arm64_sys_rt_sigaction`/`__arm64_sys_tgkill`/`__arm64_sys_openat`/
  `__arm64_sys_read` 的 hook；`copy_from_kernel_nofault` /
  `copy_from_user_nofault` 读取寄存器与用户缓冲。
- 关键命令：

```bash
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf status"
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf 'inject,$PID,<path>,wake'"
adb shell "/data/local/tmp/kpatch $KEY su -c 'dmesg'"
adb shell "dumpsys activity exit-info com.manjuu.promilia"
adb shell "cat /proc/$PID/maps"
adb shell "cat /proc/$PID/task/$PID/stat"
```

- 无效 handler 的 libc 偏移换算：
  `file_off = (pc - r-xp_start) + r-xp_file_offset`
  - `0x7d9b2d25f5 -> libc+0x905f5 -> call_once+5`
  - `0x7d9b2d3434 -> libc+0x91434 -> __libc_init_vdso+4`
  - `0x7d9b2d238d -> libc+0x9038d -> cfsetispeed+0x1d`

---

## 9. 本分支已实现的修复与复测（KCLF 1.6.1）

### 9.1 实现要点

框架不再在目标进程里创建任何匿名可执行映射。镜像、每请求跳板和 payload 本地
TLS 运行时代码页全部改为 payload 文件的私有（`MAP_PRIVATE`）文件后备映射，
`/proc/<pid>/maps` 中带模块路径：

| 对象 | 旧实现 | 现实现 |
| --- | --- | --- |
| manual 镜像各 PT_LOAD | 匿名 RW 快照 + `memcpy`，之后 `mprotect` 改权限 | 逐段 `MAP_PRIVATE` 文件页，**映射时即最终权限**（R/RW/RX） |
| 每请求 EL0 跳板 | 临时匿名区里的一页，写入后 `mprotect(RX)` | 独立一页 payload 文件私有映射，`PROT_READ\|PROT_EXEC`，代码经 GUP 写入 |
| payload 本地 TLS 运行时代码页 | 匿名区首页，`mprotect(RX)` | 同上（payload 文件私有映射，1 页） |
| 只读页写入（ELF 头擦除、只读段 .bss） | 匿名页可直接写 | GUP `FOLL_FORCE\|FOLL_WRITE` 写私有 COW 页 |
| 镜像前导 pad | 继承首段权限（可能是匿名 RX） | 固定匿名 RW |
| 可执行段 `.bss` 尾部 | 匿名零页（可执行） | 文件内等价长度页后备并清零；文件比该尾部还小时拒绝 |

落地细节：

1. **不能把"可写私有文件映射"改成可执行。** 第一版按第 6.2 节的字面做法先把文件页
   `PROT_READ|PROT_WRITE` 映射、写入、再 `mprotect(PROT_READ|PROT_EXEC)`，真机立即失败：

   ```text
   avc: denied { execmod } for path="/data/app/~~.../lib/arm64/libkclfapp_payload.so"
     dev="dm-53" ino=77827 scontext=u:r:untrusted_app ... tcontext=u:object_r:apk_data_file:s0
     tclass=file permissive=0
   ```

   SELinux 对私有文件映射的 `RW -> RX` 过渡要求 `file:execmod`，`untrusted_app` 没有该权限；
   匿名 RW→RX 走的是 `process:execmem`，所以旧实现能工作，而文件后备不能照抄普通 linker
   的写法。
2. **改为"映射即 RX + GUP 写入"**：`kclf_map_file_code()` 把 payload 第 0 页以
   `PROT_READ|PROT_EXEC` 私有映射，再用 `access_process_vm(..., FOLL_WRITE|FOLL_FORCE)`
   把生成的程序写进它的私有 COW 页。这与调试器给共享库 `.text` 打断点是同一机制：
   GUP 直接坏 COW，不经过 LSM 的 mmap/mprotect 授权检查，不产生 W+X 映射，
   也不修改 payload 文件本身（`MAP_PRIVATE`）。
3. **manual 镜像一次映射成最终权限**，只读页上的 ELF 头擦除和只读段 `.bss` 清零同样走
   `FOLL_FORCE`，可写段用普通 GUP 写入；重定位目标本来就限制在可写段内。
4. 镜像地址区间仍先以 `PROT_NONE` 预留，每个 PT_LOAD 用 `MAP_FIXED` 覆盖为文件页，
   段间空洞保持 `PROT_NONE`，前导 pad 改为匿名 RW。整幅布局与 bionic 加载的库同形：
   `r--p / r-xp / r--p / rw-p` 加 `---p` 空洞。
5. 跳板页与 TLS 代码页都是每请求/每镜像一页，随请求/镜像 `munmap`；`status` 的
   `code=` 现在显示 `地址+长度`，不再落在 `map=` 区间内；`poll` 的"PC 已离开临时区"
   检查同时覆盖跳板页。

### 9.2 没有引入新的特征点（设计复核）

- 所有由框架创建的可执行 VMA 都带 payload 路径，不再出现
  `r-xp 00000000 00:00 0` 的匿名段。
- 无 W+X、无新增用户态可见系统调用（`FOLL_FORCE` 是内核 GUP 路径）、无新增 fd
  （`filp_open` 不进入目标 fd 表）、payload 文件内容和 mtime 不变。
- 跳板页只在请求生存期内存在，固定一页、offset 0、路径与镜像一致。
- 镜像 VMA 形态与 bionic 加载的库一致（含 `---p` 空洞），前导 pad 是普通匿名 RW。
- 固有痕迹（无法用映射形态消除）：注入会新增 VMA 数量、抬高 `VmSize`/`VmPeak`、
  让被借用线程多出少量 minor fault，并在请求窗口内短暂存在一个额外可执行页。

### 9.3 回归测试

- 主机 14 组测试全部通过（含 ASan/UBSan、codegen 4K/16K/64K、ELF/TLS）。
- Pixel 6 / Android 16 / Linux 6.1.134 / arm64 / 4K：
  - `device-test.ps1 -Backend manual -Repeat 3`：178 项断言通过；
  - `device-test.ps1 -Backend linker -Repeat 3`：168 项断言通过；
  - `test/tls/device-test.py --repeat 3`：93 项断言通过；
  - 新增断言：注入后 `maps` 中不存在匿名可执行映射；运行期同样不存在；
    跳板页是**带路径的一页文件映射**且位于匿名 RW 临时区之外。
- 实测目标进程 `maps`（注入后）：

  ```text
  7dab070000-7dab071000 r--p 00000000 fe:35 77827 .../libkclfapp_payload.so
  7dab074000-7dab075000 r-xp 00000000 fe:35 77827 .../libkclfapp_payload.so
  7dab078000-7dab079000 r--p 00000000 fe:35 77827 .../libkclfapp_payload.so
  ...
  7daf24b000-7daf24c000 r-xp 00000000 fe:35 77118 .../libkclfapp_hold.so   <- 请求窗口内的跳板页
  ```

  除应用自身原有的匿名 `r-xp`（见 9.4）和 `[vdso]` 外，没有匿名可执行段。

### 9.4 对 `com.manjuu.promilia` 的复测：判据不是 maps 内容

修复后匿名可执行映射确实完全消失（9.3），但目标仍在注入后 3–7 s 被杀。
为定位判据，做了以下对照（每次都是启动后 50 s 注入，同一台设备、同一模块）：

| 注入内容 | 结果 |
| --- | --- |
| 修复前：匿名 RX 镜像 + 探针 payload | 55.5 s 被杀，status=7（SIGBUS） |
| 修复后：文件后备镜像 + 探针，路径 `/data/user/0/<pkg>/files/` | 54.5 s 被杀，status=7 |
| 修复后：同一 payload 放到 `/data/app/.../lib/arm64/`（bionic 同款路径） | 54.4 s 被杀，status=7 |
| 修复后：**空构造函数、无任何 libc/系统调用** 的 payload（常驻） | 55.5 s 被杀，status=11 |
| 修复后：同一空 payload + `unload`（映射约 0.1 s 内全部回收），3 次 | 53.4 / 56.4 / 54.5 s 被杀 |
| 修复后：空 payload（1 页对齐、镜像仅 28 KiB）常驻 | 56.5 s 被杀 |
| 修复后：先注入 256 MiB 临时 `PROT_NONE` 映射抬高 VmPeak，再注入空 payload | 56.4 s 被杀 |

另外实测：**未注入时该进程本身就有 2 个匿名 `r-xp` 页**（应用/反作弊自己的，
7dad34c000 与 7db092f000；不同进程 ASLR 地址不同，数量一致）。也就是说
"存在匿名可执行页"本身并不足以触发查杀——它显然会放行自己的页。

结论：

- 被杀与 payload 行为无关（空构造函数同样被杀），与镜像是否常驻、路径是否伪装成
  bionic 库、是否还有匿名 RX、VmPeak 是否已抬高都无关。
- 因此在 50 s 保护态下，反作弊的判据**不是 maps 里的可执行映射内容**，
  而是注入事件本身通过其它通道（in-process 轮询线程统计、地址空间记账、
  文件访问通知、定时器采样等）被观察到。KCLF 已经无法通过"改映射形态"再降低
  这个判据——按第 6.5、7.4 节的边界，这类目标在保护态建立后应当视为不可注入。
- 框架侧本次修复仍然是必要且有效的：匿名可执行映射是会被 maps 扫描命中的
  真实可观测特征，现在已彻底消除并通过回归；后续若继续对抗该反作弊，
  方向应转向**注入时机**（保护态建立前完成注入并保持常驻）与 6.3
  （默认不借用目标栈），而不是继续改映射形态。

### 9.5 未实现的部分

- 6.2.3（每 mm scratch 复用）：只减少 mmap/munmap 的记账抖动，对 9.4 的判据无效，
  而且会引入跨请求的共享状态，暂不实现。
- 6.3（默认不借用目标线程栈）：保留为可选纵深防御，未改默认值。
- 6.4（映射后 unlink 与内核凭据打开）：manual 仍在准备阶段用目标凭据 `filp_open`
  读取快照；`unlink` 会让 maps 显示 `(deleted)`，未必更隐蔽，暂不实现。

### 9.6 复现命令（本分支）

```bash
make KP_DIR=/path/to/KernelPatch TARGET_COMPILE=/path/to/aarch64-linux-gnu-
make test                                    # 14 组主机测试
.\test\app\device-test.ps1 -SuperKey $KEY -Backend manual -Repeat 3
.\test\app\device-test.ps1 -SuperKey $KEY -Backend linker -Repeat 3
python test/tls/device-test.py --serial $SERIAL --repeat 3 --key-env KCLF_SUPERKEY
```

```bash
# 注入后检查匿名可执行映射（应只剩 [vdso]）
/data/local/tmp/kpatch $KEY su -c 'grep -E "r.xp 00000000 00:00 0$" /proc/<pid>/maps'
# 手工验证文件后备的镜像与跳板页
/data/local/tmp/kpatch $KEY su -c 'grep <payload>.so /proc/<pid>/maps'
```

---

## 10. 补充定位（2026-11-27）：准备阶段改变了被借用线程的 `/proc` 记账

第 9 节把"判据不是 maps"确定下来之后，仍有一个没有被测量的通道：
**被借用线程自己的 `/proc/<pid>/task/<tid>/stat` 计数**。本轮先量化它，再把准备阶段
整个搬出目标线程，然后重新做了对照实验，把剩余触发点从"注入事件"缩小到 manual
加载器的**目标 VMA 枚举/依赖解析阶段**。

### 10.1 测量：一次请求在目标线程上留下 +1927 次缺页、+50 ms 系统时间

在 `com.manjuu.promilia` 启动 50 s、主线程空闲（状态 `S`）时注入 5952 字节空构造
payload，用设备端 100 ms 采样器读该线程的 `stat`（字段 10/12/14/15）与进程
`status`：

```text
# 注入发生在采样 6 与 7 之间（同一样本内 vsize 增加 40960，即镜像大小）
  6 state=S dminflt=+0  dstime=+0 dutime=+0   VmSize 44625012  VmPeak 74750400
  7 state=S dminflt=+1927 dstime=+5 dutime=+0  VmSize 44624988  VmPeak 74750400
  8 ... dminflt=+0 dstime=+0 ...
```

`min_flt` 是**每线程累计单调计数**，`stime` 是 10 ms tick 精度。也就是说，一次注入
在被借用线程的记账里留下了一个"空闲线程突然内核态跑了 50 ms、缺页 1927 次"的
清晰脉冲，来自：manual 加载器遍历全部已加载 provider 的 ELF 头/动态段（上千个
GUP 读，把目标库的冷页 fault 进来）、映射/随机化临时区、擦除 256 KiB 借用栈。这
正是 in-process 反作弊最容易采信的"未知代码在这个线程里跑过"证据，也同时解释了
此前所有"改映射形态/删文件/立即 unload/换独立栈"为什么都没用：**它们都没有动这个
计数**。12 s 注入之所以存活，只是因为保护态还没开始轮询，累计值早已是历史。

### 10.2 修复：准备阶段在"进入目标 mm 的内核工作线程"里执行

1.6.2 修改了执行模型（`kclf.c` / `kclf_exec.c` / `kclf_manual.c`）：

- 新增准备 worker：首次注入时用 `kthread_create_on_node` + `wake_up_process` 创建
  `kclf-prep` 内核线程；worker 用 `kthread_use_mm(target_mm)` 进入目标地址空间，
  用 `override_creds(目标凭据)` 保持"以目标身份 `filp_open` payload"的原有语义，
  再执行原来的 `kclf_exec_prepare()`。**映射、provider 遍历、重定位、页填充全部
  记在 worker 头上**，被借用线程不再承担。
- worker 是 `PF_KTHREAD`，`get_task_mm()` 对它返回 NULL，因此
  `access_process_vm(current, ...)` 不可用：新增 `kclf_remote_vm()`，准备期间改用
  `access_remote_vm(target_mm, ...)`（`kclf_io_mm`/`kclf_io_worker` 只在 worker
  自身上下文生效）。
- worker 里的 `/proc/thread-self/maps` 指向 worker 自己（目标的 SELinux 域无权
  search），因此新增 `__task_pid_nr_ns` 解析，准备期间改读 `/proc/<tgid>/maps`；
  provider 发现重新拿到带路径/权限的完整 maps。
- EL0 阶段前**预填充**目标页表：`kclf_prefault_user()` 覆盖跳板页、临时区（参数页、
  私有页、栈）与整个镜像；被借用线程执行 payload 时不再产生缺页。
- 默认把 payload 放在**临时栈**执行（`stack=transient/0`）：临时栈随请求一起
  释放，不需要、也不再执行"借用栈擦除"（擦除本身会把 256 KiB 栈页 fault 进目标
  线程）。旧的借用栈行为保留为显式 `borrowstack` 选项。

### 10.3 复测

同一目标、同样的 50 s 注入与 100 ms 采样：

```text
  6 state=S dminflt=+0 dstime=+0 dutime=+0   (注入前)
  7 state=S dminflt=+0 dstime=+0 dutime=+0   (注入后)
  8 state=S dminflt=+0 dstime=+0 dutime=+0
```

被借用线程的 `min_flt/stime/utime` 在注入前后**完全不变**；进程侧只剩镜像本身
（`VmSize +32 KiB`）。框架功能回归：14 组主机测试全部通过；
`device-test.ps1 -Backend manual` 与 `-Backend linker` 在 Pixel 6 上均为
`ALL APP CASES PASSED`（注入、marker、`state=done via=manual`、`unload=ok`、
FP 状态、四线程排队/取消、force-stop 清理等）。由于准备阶段不再等待目标线程的
返回边界，请求可能在 `ready` 状态等待（而不是旧的 `armed`），设备回归中断言已按
新模型更新；同一 payload 的并发请求改为在 worker 中排队重试而不是报 `EBUSY`，
`cancel` 现在也能取消"已准备、未执行"的请求。

### 10.4 仍未消除的通道：manual 加载器的目标 VMA 枚举/依赖解析

修复后目标**仍在保护态建立后被查杀**（50 s 注入，54–57 s 之间死亡）。为定位剩余
触发点，构造了在准备阶段不同位置失败的 payload（全部 50 s 注入、`wake`）：

| payload | 准备阶段到达的位置 | 结果 |
| --- | --- | --- |
| `missing.so`（路径不存在） | `filp_open` 失败，无映射 | **存活** |
| `notelf.bin` / `notelf.so`（非 ELF，11 字节） | 已 open，size 检查失败，无映射 | **存活** |
| `nd.so`（`DF_1_NODELETE` + `unload`） | 镜像已映射（`r-xp` 文件后备），在 VMA 快照前失败 | **存活** |
| `need.so`（`DT_NEEDED=libc.so.6`） | VMA 快照/遍历 + 依赖解析失败 | 54.5 s 被杀 |
| `bad.so`（未定义导入） | VMA 快照/遍历 + 重定位失败 | 54.7 s 被杀 |
| `noop.so`（空构造，常驻） | 完整加载 | 56.5 s 被杀 |
| `noop.so` + `wake,unload` | 完整加载，映射在 40 ms 内全部回收 | 54.4 s 被杀 |
| `noop.so` + `resume,unload` | 完整加载，hijack 未执行 | 57.2 s 被杀 |
| `libnopsig.so`（放进 `/data/app/.../lib/arm64`） | 完整加载，**无** SELinux execute 审计 | 54.5 s 被杀 |
| `noop.so`，启动 12 s 注入并常驻 | 完整加载 | **存活 >270 s** |

由此可以排除（每一行都是实测，不是推断）：

- **payload 文件被 open**（非 ELF 的 `.so` 也被 open，但存活）；
- **可执行文件后备映射本身**（`nd.so` 已建立 `r-xp` 映射，存活）；
- **SELinux `avc: granted { execute }` 审计**（lib 目录 payload 不产生该审计，仍被杀）；
- **周期性 maps 扫描**：反作弊确实是每 ~2 s 读 `/proc/<pid>/status` + 全线程 `stat`、
  每 ~4 s 读 `/proc/self/task|fd|maps`，但框架映射存活时间实测 **< 40 ms**
  （20 ms 采样器在存活期内一次都没看到），4 s 周期的扫描无法稳定命中，而目标是
  稳定被杀；
- **被借用线程的 `min_flt/stime`**（修复后为 0，仍被杀）；
- **VmPeak**（样本内完全不变）、**VmSize**（unload 变体已回到基线，仍被杀）。

剩余唯一的阶段是 **VMA 枚举 + 依赖解析**（`kclf_snapshot_vmas` /
`kclf_walk_vmas` / `add_needed`）。该阶段在目标进程里唯一可观测的变化是：
遍历 provider 需要 GUP 读它们的 ELF 头/动态段，把目标库的冷页 **fault 进目标 mm**，
使目标自身的 `VmRSS/RssFile/VmHWM` 上升（实测注入后 100 ms 内 `VmHWM` +7 MB、
随后再 +12 MB，进程 `minflt` 单样本 +187）。即反作弊很可能是在把**目标地址空间的
常驻页增长**当作"未知模块被解析/加载"的判据；这解释了为什么"映射形态"怎么改都
无效，而 12 s 注入（增长发生在基线之前）能长期存活。

### 10.5 结论与后续方向

- 本轮确认并修复了框架侧一个真实、可量化的可观测特征：**准备阶段在借用线程上
  的 `/proc` 记账脉冲**。修复后该脉冲消失，框架回归通过。
- 目标在保护态建立后仍被查杀，剩余触发点已用失败点分级实验缩小到 manual 加载器
  的 VMA 枚举/依赖解析阶段；该阶段会把目标自己的库页带入目标 mm，形成目标侧
  常驻页增长。
- 后续要彻底规避，方向是让 provider 解析**完全不触碰目标页**：按 maps 的
  `路径 + 文件偏移` 用 `filp_open`/`kernel_read` 从文件页缓存读取 provider 的
  ELF 头、动态段与符号表（APK 内库用 maps 的 APK 偏移换算），而不是 GUP 读映射
  内存；或为每个 mm 缓存 provider 表，并在保护态建立前完成一次预热注入。
  这两项都超出 1.6.2 的改动范围，未在本轮实现。

### 10.6 本轮复现命令

```bash
# 1) 观察被借用线程的记账（设备端采样，100 ms）
sh /data/local/tmp/sample.sh <pid> <tid> 120 100     # sample.txt: 每线程 stat + status
# 2) 判断映射存活时间（20 ms，grep payload 名）
sh /data/local/tmp/watchmap.sh <pid> noop.so 1500
# 3) 观察反作弊的 /proc 访问节奏（观测型 KPM，hook __arm64_sys_openat）
/data/local/tmp/kpatch $KEY kpm ctl0 procprobe arm
```

```bash
# 失败点分级注入（全部 50 s，wake）
kpatch ... 'inject,<pid>,/data/user/0/<pkg>/files/missing.so,wake'   # 存活
kpatch ... 'inject,<pid>,/data/user/0/<pkg>/files/notelf.so,wake'    # 存活
kpatch ... 'inject,<pid>,/data/user/0/<pkg>/files/nd.so,wake,unload' # 存活
kpatch ... 'inject,<pid>,/data/user/0/<pkg>/files/need.so,wake'      # 被杀
kpatch ... 'inject,<pid>,/data/user/0/<pkg>/files/bad.so,wake'       # 被杀
```

> 注：`nd.so` 用 `-Wl,-z,nodelete` 编译，`need.so` 链接 `libc.so.6`（设备上不存在
> 该 SONAME），`bad.so` 引用一个未定义符号；三者都只用于把失败点钉在加载器的
> 确定位置，不随框架发布。


---

## 11. 1.6.3 完整修复：provider 元数据不读目标页（2026-11-27）

### 11.1 1.6.2 为什么仍不够：non-dumpable 目标丢失 VMA 元数据

第 10 节把剩余触发点缩小到 manual 加载器的目标 VMA 枚举/依赖解析，但 1.6.2 的
准备 worker 仍有一个未验证的前提：它假设 `/proc/<tgid>/maps` 可用。这个前提在
`com.manjuu.promilia` 上不成立：

- 目标调用 `prctl(PR_SET_DUMPABLE, 0)`；`/proc/<pid>/maps` 的打开走
  `PTRACE_MODE_READ_FSCREDS` 检查。worker 虽然通过 `override_creds()` 持有目标
  凭据，但它不是目标的同线程组成员，也没有 `CAP_SYS_PTRACE`，因此 `filp_open`
  返回 `-EACCES`。
- `kclf_walk_vmas()` / `kclf_snapshot_vmas()` 于是退回 direct VMA walker。1.6.2
  的 direct 分支只读取 `vm_start/vm_end`，`path` 为空、`prot=-1`、没有文件偏移。
- 后果一：反作弊的整文件只读映射（第 9.4 节观察到的那一类）与真实库有相同
  SONAME/路径，`provider_exec_mapped()` 在权限未知时无法区分，`libc.so`/`libdl.so`
  出现 `ambiguous loaded SONAME` 或选中错误副本。本轮在修改前用 50 s 注入复现了
  `manual: ambiguous loaded SONAME (no namespace match): libc.so`，且候选 path 为空。
- 后果二：provider 的 ELF 头/动态段/符号表仍通过 GUP 从目标映射读取；provider
  冷页会被 fault 进目标 mm，继续抬高目标自己的 `VmRSS/RssFile/VmHWM`，即第 10.4
  节测到的剩余通道。

因此 1.6.2 的“准备移出借用线程”只消除了被借用线程的记账脉冲，没有消除
**provider 解析对目标页的读取**。

### 11.2 1.6.3 实现

#### 11.2.1 direct walker 恢复完整 VMA 元数据

`kclf_compat.c` 在 BTF 中额外校验并缓存：

- `vm_area_struct.vm_file`
- `vm_area_struct.vm_pgoff`
- `vm_area_struct.vm_flags`
- `struct file.f_path`

`kclf_exec.c` 的 direct 分支在 `mmap_read_lock()` 下：

- 用 `vm_flags` 的 `VM_READ/WRITE/EXEC`（1/2/4）恢复 `prot`；
- 用 `vm_pgoff << PAGE_SHIFT` 恢复映射的文件偏移；
- 对非 NULL `vm_file` 调用 `d_path(&file->f_path, ...)` 取得与 procfs maps
  等价的绝对路径（`d_path` 使用目标文件的 `struct path`，不依赖目标进程的
  dumpable 状态）。持锁调用可保证 `vm_file` 在遍历期间不会被并发 `munmap`
  释放；`d_path` 本身不睡眠、不获取 `mmap_lock`。

procfs maps 可读时仍优先使用 procfs（路径/权限格式与历史行为一致）；不可读时
direct 分支现在不再退化为“无路径、权限未知”。

#### 11.2.2 provider ELF 元数据从文件页缓存读取

`kclf_manual.c` 新增 `struct km_provider_view` 与
`provider_view_open()/provider_view_read()/provider_view_close()`：

- `provider_view_open(path, address, offset)` 用目标凭据 `filp_open` provider
  文件，读取 ELF 头与程序头，校验：ELF64 LE、`e_phoff/e_phnum/e_phentsize`、
  每个 PT_LOAD 的 `p_filesz <= p_memsz`、文件范围、恰好一个 `p_offset==0`
  的段、`header_end` 在用户地址范围内。
- 记录 `bias = address - p0.vaddr`、`file_base = offset - p0.offset`。之后
  `provider_view_read()` 把任何 provider 虚拟地址按 PT_LOAD 几何换算成文件
  偏移：`file_base + p.offset + (at - bias - p.vaddr)`；`p_filesz` 之后的
  `.bss` 返回零。APK 内嵌库的 `offset` 就是 zip entry 的 data offset，因此
  同一套换算同时覆盖普通 `.so` 与 APK 布局。
- ELF 头 + 程序头是连续文件区间，单独用 `header_off + (at - header_addr)`
  直接换算。这一点是必需的：`ke_headers_impl()` 在读取 phdr 表**之前**就把
  `o->phnum` 设为 `e_phnum`，view 不能只靠 `phnum != 0` 判断“段表已就绪”。
- provider 文件只读元数据，不整文件复制；文件大小上限不再套用 payload 的
  64 MiB（大型 APK 很常见），只拒绝负值/不可表示的尺寸。
- provider 表增长时会搬移整个 `struct km_provider`，`provider_fixup()` 重建
  `view.object`、`io.ctx`、`io.string_budget` 的内部指针；所有 provider 文件
  句柄在 `kclf_manual_prepare()` 结束时统一 `fput`。
- 无法按路径打开的 provider（memfd、已删除 inode、特殊文件）回退到
  `provider_nofault_read()`：底层是 `copy_from_user_nofault`，只读取已经
  resident 的页；缺页直接返回错误，不会 fault-in。`/dev`、`/proc`、`/sys`、
  `/dmabuf`、`/memfd:`、`/ashmem` 与 ` (deleted)` 路径不做文件探测。
- `provider_exec_mapped()` 继续要求所有可执行 PT_LOAD 被完整覆盖为可执行 VMA；
  修复后 direct walker 的 `prot` 可信，因此第 9.4 节的整文件只读副本会被正确
  拒绝，不再与真实 libc/libdl 冲突。

#### 11.2.3 新增回归

- `test/test_provider_file.py`：编译真实的 view 代码，用 fake file 覆盖普通
  `.so`（offset 0）、APK entry（offset 0x1000）、ELF 头/phdr/data/.bss 换算、
  跨段读取失败、坏 magic、phoff 越界、段越界、重复 base 段、非法地址；断言
  不触碰任何 target 内存访问接口。
- `test/test_maps.py`：覆盖 maps offset 解析、direct walker 的 path/offset/prot
  元数据与锁平衡。
- 主机回归从 14 组增至 15 组。

### 11.3 复测（Pixel 6 / Android 16 / Linux 6.1.134 / 4 KiB）

复测条件与第 2 节一致：启动目标，等待 50 s（保护态已建立、进程
non-dumpable），注入 `/data/user/0/com.manjuu.promilia/files/kclf-probe.so,wake`。

结果：

```text
#0 id=1 pid=11031(manjuu.promilia) state=done stage=restore handle=1
   done=syscall stack=transient/0 via=manual image=1 refs=1
   resident=7ec0beb000+86016 hdr=scrubbed
```

- 1.6.3 迭代构建（direct VMA 元数据 + resident-only provider 回退）注入后持续
  2 s 间隔观测 **120 s**：进程一直存活。
- 文件后备 provider 构建复测 60 s：进程存活，且该轮 `VmHWM` 注入前后均为
  1,440,696 KiB（采样窗口内完全不变）。
- 另一轮 `VmHWM`：注入前 1,442,760 KiB，注入后 1,443,844 KiB（+1,084 KiB，
  其中包含 86,016 B 的 payload 镜像与临时区；1.6.2 观测到的是 +7/+12 MiB
  级的 provider 解析脉冲）。
- 最终产物（SHA-256 `8FA9DDFC...C72B89`）在同一目标上再次注入并观测 60 s：
  `state=done via=manual`，进程存活。
- 一次准备发现 `providers=359 file=343 resident=16`；文件后备占绝大多数，
  resident-only 只用于无法按路径重开的映射。
- `dmesg` 无 `KCLFSIG*` 的 `rt_sigaction` 改写/伪造信号；`dumpsys activity
  exit-info` 没有该 PID 的新 `reason=2 (SIGNALED)` 记录。
- `release,11031,1,wake`：`refs=0 resident=0+0 unload=ok rc=0`，镜像与临时区
  正常回收。
- 回归：`device-test.ps1 -Backend manual -Repeat 3` 与 `-Backend linker
  -Repeat 3` 均为 `ALL APP CASES PASSED`；TLS 设备回归 93 项断言通过；15 组
  主机测试全部通过。完整证据与产物 SHA-256 见
  [1.6.3 兼容性报告](COMPATIBILITY_1.6.3.md)。

也就是说：在 1.6.3 下，manual 加载器的 provider 发现/依赖解析不再读取目标
映射页，也不再因 non-dumpable 丢失路径和权限；该目标在保护态建立后注入可正常
完成并长期存活。

### 11.4 边界与未覆盖项

- provider 文件必须在准备期间仍可按路径打开，且内容与映射 inode 一致。应用
  更新替换 `.so`/APK、或反作弊主动 `unlink` 后再替换时，可能只能走 resident-only
  回退；若其元数据页已被回收，依赖解析会失败而不是 fault-in。
- APK 内嵌库按“ELF 头位于映射起始位置”处理，对应 Android 对未压缩 native
  library 的页对齐布局；非页对齐的异常 entry 可能无法发现，需由调用方换用
  已解压库或预先加载。
- `linker` 后端仍由目标 bionic loader 自己映射/解析依赖，本节的“不读目标页”
  只覆盖默认 `manual` 后端。
- 这不是对所有 in-process 反作弊的通用不可见保证；它消除的是本轮已量化的
  provider 元数据读取/VMA 元数据缺口。若后续仍被杀，应按第 7.4 节区分服务端/
  心跳/完整性通道，而不是继续误判为加载器失败。

### 11.5 复现命令

```bash
# 主机
make test                                      # 15 组
# 设备：加载 1.6.3，启动目标并等待 50 s
adb shell "/data/local/tmp/kpatch $KEY kpm load /data/local/tmp/kclf.kpm"
# 注入
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf \
  'inject,<pid>,/data/user/0/com.manjuu.promilia/files/kclf-probe.so,wake'"
# 观察
adb shell "/data/local/tmp/kpatch $KEY kpm ctl0 kclf status"
adb shell "pidof com.manjuu.promilia"
adb shell "/data/local/tmp/kpatch $KEY su -c 'dmesg | grep KCLFSIG'"
```
