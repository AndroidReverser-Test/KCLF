# 受保护 App 的 KCLF 注入失败分析与修复（2026-11-01）

> 本文的第三方 App 设备结果对应**审计前 1.5.5 快照**，SHA-256 为
> `e9af06bad92c95cacdbd2dba103de334b5fe4116df7f7946077df08890463887`。
> 最终代码随后收紧了提供库表失败处理和已加载头校验；本文“修复”部分已按最终
> 语义更新，历史设备记录保留原样。最终发布产物与验证范围见
> [1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)，下列历史结果不构成最终产物认证。

## 结论

KCLF 1.5.4 在 `com.chinamworld.main`（建设银行 7.6.0）和
`com.ss.android.ugc.aweme`（抖音 40.8.0）上都在 **manual 后端的 prepare 阶段**
失败，但根因不同，均与 payload 自身无关：

| 目标 | 1.5.4 失败输出 | 根因 |
| --- | --- | --- |
| `com.ss.android.ugc.aweme` | `state=failed stage=prepare err="manual: provider scan limit exceeded"` | 固定 512 项“已加载提供库”表不够用；该进程实际有 **540–549** 个带 `DT_SONAME` 的已加载 ELF 对象 |
| `com.chinamworld.main` | `state=failed stage=prepare err="manual: DT_NEEDED is not already loaded: libc.so"` | App 的加固/反调试引擎把 **libc.so 已加载映像的 ELF 头前 24 字节**改写成跳板（`ldr x16,#8; br x16; <addr>`），`e_type/e_machine/e_version` 被破坏，严格头校验因此拒绝 libc 作为提供库 |

1.5.5 修复了两处：

1. **提供库表按需增长**（初始 64，倍增，硬上限 4096）。仍有容量时继续收集；
   分配失败或超过上限时明确停止 prepare 并回滚，避免不完整候选表中的错误来源选择。
2. **已加载对象只接受一种明确的头改写**：仅在 `e_ident[8..15]` 精确匹配
   `ldr x16,#8; br x16` 时，允许后续地址覆盖 `e_type/e_machine/e_version`。
   没有该签名时仍要求 ET_DYN/EM_AARCH64/version。`ELF64/小端` 魔数、
   `ehsize/phentsize/phnum/phoff` 及段/动态表/符号表边界始终校验，payload 保持严格校验。

审计前快照上，两个 App 的**主线程和 Binder 线程**都注入成功，libtest.so 构造函数实际执行
（`Perfare : start dump.....` / `game dir:...`），App 在释放镜像后仍存活。
该历史快照的 SHA-256 为
`e9af06bad92c95cacdbd2dba103de334b5fe4116df7f7946077df08890463887`。

## 设备与产物

| 项目 | 值 |
| --- | --- |
| 设备 | 2211133C / fuxi（小米 13） |
| Android / 内核 | 13（API 33）/ `5.15.74-android13-8-00049-g8945ccdb2203-ab9500309` |
| ABI / 页大小 | arm64-v8a / 4096 |
| SELinux | Enforcing（测试前后一致） |
| KernelPatch | `c00`，`kver=50f4a` |
| 目标 App | `com.chinamworld.main` 7.6.0（PID/TID 20150 等）<br>`com.ss.android.ugc.aweme` 40.8.0（PID/TID 21899 等） |
| payload | `/data/local/tmp/libtest.so`，SHA-256 `e7ae1f3c72658798ea6176e5993e438d0690f91d885842d5982d3f60a40be931` |
| 修复前模块 | `kclf-1.5.4.kpm`，SHA-256 `4c8049293cf36be3397a314cc43e44bb0d11031d28e22d1238a454e570d9ccf7` |
| 修复后模块（审计前历史快照） | `kclf.kpm` 1.5.5，SHA-256 `e9af06bad92c95cacdbd2dba103de334b5fe4116df7f7946077df08890463887` |
| boot ID | `17373dba-3c00-454f-bf6e-97670514877c`（前后相同，未重启） |

构建：

```sh
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
make -C kpms/kclf test
```

主机使用 WSL Ubuntu 24.04、AArch64 GCC 13.3.0；设备端用
`/data/local/tmp/kpatch <KEY> kpm ...` 管理模块，密钥只从环境变量/交互读取。

## 失败复现

以下两段是 1.5.4 原产物、同一设备、同一 payload 的实测输出（原始记录：
`build/kclf-apps-20261101/fail-1.5.4-douyin.txt`、
`fail-1.5.4-boc.txt`）：

```text
# 抖音主线程
queued id=1 tid=21899 comm=droid.ugc.aweme path=/data/local/tmp/libtest.so mode=safe,wake
#0 id=1 ... state=failed stage=prepare err="manual: provider scan limit exceeded"

# 建行主线程
queued id=2 tid=20150 comm=hinamworld.main path=/data/local/tmp/libtest.so mode=safe,wake
#1 id=2 ... state=failed stage=prepare err="manual: DT_NEEDED is not already loaded: libc.so"
```

两次请求都完成回滚：`pending=0`、`map=0`，App 保持存活。失败发生在
`kclf_exec_prepare()` → `kclf_manual_prepare()`，此时尚未映射 payload 的构造函数，
也尚未修改目标线程的 `pt_regs`；`hijack`/EL0 阶段根本没有进入。

## 根因一：固定 512 项提供库表（抖音）

manual 后端在 prepare 时枚举目标进程的 VMA，对每个 VMA 起点尝试解析 ELF，
把所有带 `DT_SONAME` 的已加载对象登记为依赖提供库。旧实现是：

```c
#define KM_PROVIDERS 512
...
struct km_provider providers[KM_PROVIDERS];
...
if (c->nproviders == KM_PROVIDERS) {
    report(c, "provider scan limit exceeded", "");
    return -E2BIG;   /* 中止整次扫描 → 整个请求失败 */
}
```

设备上的实际数量（独立诊断工具 `elfscan` 按同一规则读取目标 `/proc/<pid>/maps`
和 `/proc/<pid>/mem`，源码见 [test/elfscan.c](test/elfscan.c)，头部字节对比见
[test/rdmem.c](test/rdmem.c)）：

| 进程状态 | VMA 数 | ELF 魔数起点 | 可解析 | 带 SONAME | 坏头 |
| --- | --- | --- | --- | --- | --- |
| 抖音冷启动后 | 8770 | 522 | 522 | **516** | 0 |
| 抖音运行一段时间 | 9760 | 549 | 549 | **543** | 0 |
| 抖音（复现失败时） | 10706 | 546 | 546 | **540** | 0 |
| 建行（复现失败时） | 4326 | 403 | 402 | 396 | **1** |

抖音的已加载 SONAME 数量稳定超过 512，所以扫描到第 513 个对象就返回 `-E2BIG`，
即使 payload 真正需要的 `liblog/libm/libdl/libc` 早就在表里。这个上限是历史遗留的
固定容量假设，现代加固 App（大量插件化/监控/媒体库）很容易超过它。

## 根因二：已加载 libc 的 ELF 头被改写（建行）

同一诊断工具在目标内存中读到：libc.so 的映射起点确实是
`/apex/com.android.runtime/lib64/bionic/libc.so`，但内容与磁盘文件不一致：

```text
磁盘 /apex/.../bionic/libc.so：
7f 45 4c 46 02 01 01 00  00 00 00 00 00 00 00 00
03 00 b7 00 01 00 00 00  00 00 00 00 00 00 00 00
40 00 00 00 00 00 00 00  a0 a3 14 00 00 00 00 00
00 00 00 00 40 00 38 00  0d 00 40 00 1e 00 1c 00

建行进程内同一地址（0x79b3a9a000）：
7f 45 4c 46 02 01 01 00  50 00 00 58 00 02 1f d6
fc 3c f0 a4 78 00 00 00  00 00 00 00 00 00 00 00
40 00 00 00 00 00 00 00  a0 a3 14 00 00 00 00 00
00 00 00 00 40 00 38 00  0d 00 40 00 1e 00 1c 00
```

偏移 `+8` 起的 16 字节被写成：

```text
50 00 00 58   ldr x16, #8
00 02 1f d6   br  x16
fc 3c f0 a4 78 00 00 00   .quad 0x00000078a4f03cfc（每次启动随机）
```

即一个典型的加固跳板。它覆盖了 `e_ident[8..15]`、`e_type`、`e_machine`、
`e_version`；用 `elfscan` 观察到的字段是 `type=15612 mach=42224 ver=120`，
而合法值是 `type=3 mach=183 ver=1`。`ke_headers()` 的严格条件因此拒绝该对象，
`collect()` 直接跳过 libc，后续 `DT_NEEDED` 查找自然报
`DT_NEEDED is not already loaded: libc.so`。

关键点是：**被破坏的只有头部的非结构字段**。`e_phoff=0x40`、`e_phentsize=56`、
`e_phnum=13`、`e_ehsize=64` 仍然正确；`base+0x40` 的程序头、
`base+0x107340` 的 `PT_DYNAMIC`、`.dynsym/.dynstr/.gnu.hash` 都完好。
libdl.so 作为对照，头部完全正常；只有 libc 被改写。

同一引擎还把 libc 的前三个段合并成 `rwxp` 映射（正常应为 `r--p`/`r-xp`），
并改变了部分段的权限。这只影响“能否读取”，不影响 manual 后端的符号解析；
框架只需要以正确的方式识别它。

## 为什么不是其他原因

| 可能原因 | 证据 |
| --- | --- |
| SELinux 不允许读 `/data/local/tmp` | 两次失败都发生在 `read_snapshot()` 之后（错误文本不是 `open library failed`），说明目标凭据已成功打开并读取 SO；logcat 中也没有针对 `libtest.so` 的 `avc: denied` |
| seccomp | 失败发生在内核 prepare 阶段，尚未进入 EL0，也没有完成 syscall；两个 App 的 `Seccomp=2` 在 1.3.0 起就不是拒绝条件 |
| BOC 的 `TracerPid=361`（自 ptrace 反调试） | 修好提供库后发现，被测主线程/Binder 线程并未设置 `TIF_SYSCALL_TRACE`，`hijack` 正常通过；真正被 syscall tracer 跟踪的线程仍按设计拒绝 |
| 32 位目标 | 两包 `primaryCpuAbi=arm64-v8a`，`pt_regs` 为 EL0t |
| payload 依赖缺失/构造失败 | `libtest.so` 的 `DT_NEEDED` 只有 `liblog/libm/libdl/libc`，失败时还未进入映射和重定位 |

## 修复（含最终审计收紧）

### 1. 提供库表按需增长（`kclf_manual.c`）

```c
#define KM_PROVIDERS_INIT 64
#define KM_PROVIDERS_MAX 4096
struct km_context {
    struct km_provider *providers; /* vmalloc'ed, grown on demand */
    unsigned nproviders, provider_cap;
    ...
};
```

`provider_reserve()` 以倍增方式 `vmalloc` 新表并复制已有项，旧表 `vfree`。
`collect()` 在表满时：

- 还能增长就增长；
- 分配失败时报 `provider table allocation failed` 并返回 `-ENOMEM`；
- 超过硬上限时报 `provider table limit exceeded` 并返回 `-ENOSPC`；
- 映射遍历器传播错误，prepare 在依赖选择前停止并走统一回滚。

审计前快照曾在表截断后继续扫描。该策略可能保留系统库、丢弃后面的同名同 APEX
库，随后静默选到错误来源，因此最终代码改为明确失败。`provider_reserve()` 对
`need > 4096` 也直接失败，避免报告成功却没有提供足够容量。

按 `sizeof(struct km_provider)`（`ke_object` 约 4.1 KiB 为主）估算，540 项有效数据
约 2.5 MiB，实际倍增容量为 1024 项、约 4.5 MiB；增长时新旧表短暂并存。
表在 `kclf_manual_prepare()` 退出时无条件释放，不驻留。

### 2. 已加载对象的特定跳板头兼容（`kclf_elf.c`）

`ke_headers()` 拆成 `ke_headers_impl(io, header, o, loaded)`：

- `loaded=0`（文件快照/payload）：保持原严格条件（`ET_DYN`、`EM_AARCH64`、
  `version==1`、结构字段）。
- `loaded=1`（目标 loader 已映射的对象）：通常仍要求 ET_DYN/EM_AARCH64/version；
  仅在 `e_ident[8..15]` 精确等于 `50 00 00 58 00 02 1f d6`
  （`ldr x16,#8; br x16`）时，允许紧随其后的地址覆盖这三个字段。
  `\177ELF\2\1\1`、`ehsize/phentsize/phnum/phoff` 与后续所有
  `PT_LOAD`/`PT_DYNAMIC`/符号表边界在两种情况下均强制校验。
- `ke_open(..., payload)` 据此选择模式：提供库 `payload=0` 可以识别该特定跳板，
  payload 始终严格。没有该签名的非 ARM64、非法类型/版本头仍拒绝，结构字段损坏
  和数据越界也不会因为该例外而放行。

审计前快照对所有已加载对象跳过 type/machine/version 检查；最终代码收紧为上述
精确签名例外，避免把任意非 ARM64 映像误认为依赖提供库。

这不会放过结构上不可解析的假对象：`phoff/phnum/phentsize` 非法、没有
offset-0 `PT_LOAD`、没有 `PT_DYNAMIC`、动态表越界、hash/符号表非法等情况仍失败。

### 3. 回归测试

- `test/test_manual_elf.c` 新增 `loaded_header_tests()`：正常头两种模式均通过；
  写入现场观察到的 16 字节跳板后，`payload=1` 必须拒绝、`payload=0` 必须成功且
  SONAME/符号数与正常解析一致；`phnum/phentsize/phoff/魔数` 损坏仍然拒绝。
- 新增 `test/test_provider_table.py`：验证 64→128→…→4096 的倍增、超过上限的容量
  契约、旧项保持，以及真实 `collect()` 在首次/增长分配失败和上限耗尽时返回错误；
  特别覆盖后续同名较优来源不能被静默丢弃的场景。
- 主机入口从 10 组增加到 **11 组**；最终测试结果见
  [1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)。

## 设备验证（审计前 1.5.5 历史快照）

以下历史快照测试使用 `test/realapp-inject.py` 驱动；默认观察 12 秒（覆盖 payload 自己
10 秒工作线程），随后 release 并检查存活：

| 目标 | 注入线程 | 请求结果 | 耗时 | 镜像 | 释放后 |
| --- | --- | --- | --- | --- | --- |
| 建行（PID 20150） | 主线程 20150 | `state=done stage=restore handle=1 done=syscall via=manual image=1` | 0.321 s | `790e948000+536576` | App 存活，`images` 为空 |
| 抖音（PID 21899） | 主线程 21899 | `state=done stage=restore handle=2 done=syscall via=manual image=2` | 0.343 s | `787f377000+532480` | App 存活，`images` 为空 |
| 建行 | Binder 20164 | `state=done ... image=3 refs=1` | 0.338 s | `790e946000+544768` | App 存活，`images` 为空 |
| 抖音 | Binder 21915 | `state=done ... image=4 refs=1` | 0.340 s | `787f375000+540672` | App 存活，`images` 为空 |

构造函数与 payload 自身线程的 logcat 证据（节选）：

```text
11-01 11:23:08.054 20150 20150 I Perfare : start dump.....
11-01 11:23:08.054 20150 20150 I Perfare : game dir:/data/data/com.chinamworld.main
11-01 11:23:18.064 20150 25341 I Perfare : libil2cpp.so not found in thread 25341

11-01 11:23:22.051 21899 21899 I Perfare : start dump.....
11-01 11:23:22.052 21899 21899 I Perfare : game dir:/data/data/com.ss.android.ugc.aweme
11-01 11:23:32.056 21899 25535 I Perfare : libil2cpp.so not found in thread 25535

11-01 11:23:38.684 20150 20164 I Perfare : start dump.....     # Binder 线程
11-01 11:23:53.183 21899 21915 I Perfare : start dump.....     # Binder 线程
```

即构造函数确实在所选线程执行；Perfare 找不到 IL2CPP 是 payload 自身目标
（这两个 App 不是 Unity/IL2CPP），不属于注入链路。

其他状态：

- 四个请求的 `alive_after=True`、`alive_after_release=True`、crash buffer 无对应
  pid 的条目。
- `images` 最终为 `no manual images`；`release` 显示 `refs=0 resident=0+0
  unload=ok rc=0 by=manual`。
- 模块仍可 `probe`：`kernel=50f4a btf=1 ... completion=el0 watch=on 70/70`。
- 测试前后 boot ID 相同，SELinux 保持 Enforcing；dmesg 无新增
  `BUG:/WARNING:/Oops/panic`。

## 过程中发现的一次测试误用（提前 release）

在一轮早期证据收集中，驱动把“观察 3 秒”当成安全等待，随后 release，结果：

- 抖音（PID 14954，镜像 base `0x7885d1b000`、长度 0x85000）在 release 后约 2 秒
  崩溃；`/data/tombstones/tombstone_23` 显示 `tid 20009` 的 `pc=0x7885d46f20`
  **正好位于刚被解除的镜像内**。这是 payload 自己创建、仍在执行镜像代码的工作线程。
- 建行（PID 14923）在同一时间窗口 `am_proc_died`，没有 tombstone；其加固进程
  可能在故障处理路径中直接结束进程，具体终止路径未被证明。

这不是注入失败，而是违反了 README/MANUAL_LOADER 已写明的释放前提：
**释放前必须由使用方停止 payload 的后台线程/回调，引用计数不代表代码无人执行。**
把观察时间改为 12 秒（大于 libtest 的 10 秒工作线程）后，两个 App 在 release 后
均保持存活。`test/realapp-inject.py` 的默认 `--observe` 因此改为 12 秒。

## 保留边界

- 提供库识别仍以 **VMA 起点的 ELF 魔数** 为锚点。最终代码只兼容本文记录的精确
  跳板签名；如果某个引擎把魔数也擦掉，当前实现仍会漏掉该库（本轮未观察到）。
  这需要“按 maps 路径读磁盘文件重建头”的更复杂回退，未在本次实现。
- 提供库表硬上限 4096；分配失败或超过时停止 prepare 并回滚，不对截断表做依赖选择。
- 特定跳板例外只用于“目标 loader 已映射”的对象；没有该签名时仍校验原始类型、
  架构与版本。payload 必须是严格 ELF64/AArch64/ET_DYN，TLS/REL/CFI 等拒绝条件不变。
- BOC 的自 ptrace 反调试仍在运行；如果某线程真的设置了 `TIF_SYSCALL_TRACE`，
  框架仍按设计拒绝注入（不绕过调试/跟踪）。本轮被测线程未触发该状态。
- 抖音的 ByteHook PLT trampoline、BOC 的 RWX 安全库等 App 自身内存修改不在框架
  控制范围内；本次只证明注入链路可以完成，不证明目标的反注入检测不会被触发。
- 仍只在这台 5.15.74 / 4K 页设备上实测；16K/64K 页与其他内核版本未因此获得认证。
- payload 若依赖 `/proc/self/mem` 等 non-dumpable 目标不可读的文件，仍会自行失败；
  框架不修改 non-dumpable、SELinux 或 ptrace 策略。

## 复现

```sh
# 构建与主机回归
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
make -C kpms/kclf test

# 设备：加载修复产物
adb push kpms/kclf/kclf.kpm /data/local/tmp/kclf-1.5.5.kpm
adb shell "/data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/kclf-1.5.5.kpm"
adb shell "/data/local/tmp/kpatch <KEY> kpm ctl0 kclf help"
```

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/realapp-inject.py --serial 3bb96edd `
  --package com.chinamworld.main --package com.ss.android.ugc.aweme `
  --so /data/local/tmp/libtest.so --thread main --repeat 1 --observe 12
Remove-Item Env:KCLF_SUPERKEY
```

`--thread binder` 可复现 Binder 线程用例；驱动会保存每次注入的 request/status、
logcat、crash buffer、images、release 记录和 `summary.json`。

## 证据目录

以下路径均为审计前快照的历史证据，最终产物的证据见 [1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)。

- `build/kclf-apps-20261101/`：1.5.4 失败状态、`elfscan` 输出、BOC libc 头对比、
  映射片段、dmesg 前后。
- `build/kclf-realapp-20261101-1.5.5-main/`：1.5.5 两个 App 的主线程注入证据。
- `build/kclf-realapp-20261101-1.5.5-binder/`：1.5.5 两个 App 的 Binder 线程证据。
- `build/kclf-realapp-20261101-final*/`：1.5.5 版本号前一构建的同流程结果，
  用于交叉检查（镜像地址/耗时不同，结论一致）。

失败与修复的完整对照也保留在 `build/kclf-apps-20261101/fail-1.5.4-*.txt` 与
`build/kclf-realapp-20261101-1.5.5-*/summary.json`。
