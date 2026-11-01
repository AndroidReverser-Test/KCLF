# KCLF 1.5.7

Kernel Controlled Loading Framework — Android ARM64 / KernelPatch KPM

[中文](#中文) · [English](#english) · [实现 / Implementation](IMPLEMENTATION.md)

## 中文

KCLF 通过内核 `task_work` 借用目标线程，在 EL0 执行 SO 的构造/析构函数。
默认 `manual` 后端自行映射和重定位 ELF；显式 `linker` 后端调用目标 bionic loader。
`main` 维护框架、构建配置、测试 App 和当前版本兼容性报告；历史报告、检测实验及
完整主机/设备回归夹具在 `dev`。

### 1.5.7 更新与验证

- manual 按 DT_STRSZ 和可读 PT_LOAD 边界读取、完整比较符号名，解除原有 255 字节
  符号名限制；SONAME、DT_NEEDED 和版本名仍保留该限制。
- payload 内定义的 compiler-rt emutls 允许使用，但镜像标记 `nodelete=emutls`，
  必须驻留到目标 mm 退出；首次 `unload` 和显式 `release` 拒绝执行。
- 未新增内核 ABI/符号依赖，既有 BTF、task_work、procfs/accessor/GUP 回退路径未改。
  12 组主机测试全部通过；真实设备 BTF 解析回归通过。
- Pixel 6 / Android 16 / Linux 6.1.134 / ARM64 / 4K 页：正式产物通过 186 项
  原生及自有普通 App 断言；关闭 BTF/nofault 的独立测试构建通过 243 项断言。
  两轮均安全卸载且无新增内核告警；其他内核及 16K/64K 页设备未在本轮实测。
- 1.5.6 的动态提供库表和已映射提供库结构解析保持不变。名称缓冲最多 64 MiB
  （含 NUL），累计字符串读取预算 256 MiB；超限或分配失败会明确停止并回滚。

实现、审计依据、产物 SHA-256 和证据范围见
[1.5.7 兼容性报告](COMPATIBILITY_1.5.7.md)；产物见
[GitHub Release](https://github.com/AndroidReverser-Test/KCLF/releases/tag/v1.5.7)。

### 编译

模块需要 GNU Make、AArch64 bare-metal GCC/binutils，以及一份 KernelPatch 源码。
在本仓库根目录运行（Linux/WSL 示例，路径按实际环境替换）：

```sh
make KP_DIR=/path/to/KernelPatch TARGET_COMPILE=/path/to/bin/aarch64-none-elf-
```

产物为 `kclf.kpm`；`make clean` 清理模块产物。位于 KernelPatch 的
`kpms/kclf` 时可省略 `KP_DIR`（默认 `../..`）。本仓库不内置 KernelPatch 头文件。

测试 App 需要 Windows PowerShell、JDK（`java/javac/keytool` 在 PATH 中）、
Android SDK platform 35 或更新、build-tools 和 NDK：

```powershell
.\test\app\build.ps1 -SdkRoot D:\androidSDK -NdkRoot D:\androidSDK\ndk\27.0.12077973
```

生成 `build/kclf-apptest/app.apk`，包名 `com.kclf.apptest`，包含普通、FP 状态破坏、
延时构造三种 payload。可用 `-OutDir` 指定输出目录；调试签名密钥会在输出目录复用。

### 使用

设备需已安装可用的 KernelPatch，且能用 superkey 调用 `kpatch`。
仅支持 64 位 ARM64 目标；代码适配范围为 Linux 5.x/6.x，实际可用性取决于运行时 ABI、
符号和设备配置，不能据此认为全部内核或 16K/64K 页设备已通过测试。

```sh
adb install -r -t build/kclf-apptest/app.apk
adb shell am start -W -n com.kclf.apptest/.MainActivity
adb shell pidof com.kclf.apptest
adb shell logcat -d -s KCLFAPP:I
adb push kclf.kpm /data/local/tmp/kclf.kpm
```

以下命令在主机 shell 执行：先将 `KEY` 设为你的 superkey（不要提交到仓库），
`TID` 设为目标线程 ID（主线程即 PID），`LIBDIR` 设为上述日志中的 `libdir`。

```sh
adb shell /data/local/tmp/kpatch "$KEY" kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf probe
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,$LIBDIR/libkclfapp_payload.so,wake"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf status
adb shell run-as com.kclf.apptest cat /data/user/0/com.kclf.apptest/files/hit_$TID
```

此例注入主线程，因此 marker 文件后缀也是 PID。重复查看 `status`，
直到出现 `state=done`、`via=manual`、`refs=1` 且没有 `pending=` / `map=`。
此例让 SO 保持驻留；需要卸载时按下文 `images` / `release` 流程释放。
命令返回 `queued` 只表示已排队。追加 `,linker` 可选择 bionic 后端。

#### SO 路径要求

`,$LIBDIR/libkclfapp_payload.so` 中的逗号是命令参数分隔符，后面才是 SO 路径。
`LIBDIR` 是**设备上的目录**，由主机 shell 展开；本示例应填写测试 App 日志中的
`libdir`，例如 `/data/app/~~.../com.kclf.apptest-.../lib/arm64`，并确认其中已有
由测试 APK 安装的 `libkclfapp_payload.so`。注入其他 SO 时替换为实际完整路径。

- 展开后的路径必须是设备端绝对路径，最多 255 字节，不能包含逗号、空格、制表符、
  换行等分隔符；给命令加引号也不能让这些字符成为路径的一部分。
- SO 必须是框架支持的 64 位小端 AArch64 ELF 共享库（`ET_DYN`）。
- 准备阶段使用**目标进程的凭据**打开文件；目标需能读取 SO、访问各级目录，
  并满足 SELinux 策略。控制端取得 root 不等于目标 App 获得文件访问权限。
- `manual` 不强制使用 App 的 native library 目录，也可使用目标有权读取的
  `/data/user/0/<包名>/files/<模块>.so`；依赖仍需预先加载，映射权限仍受设备策略限制。
  `linker` 还要求路径属于目标 linker namespace 允许的范围，并允许文件的可执行映射；
  本示例使用安装后的 native library 目录。`/data/local/tmp` 不能视为普通 App 通用可用的路径。

常用控制字符串（作为 `kpm ctl0 kclf` 的最后一个参数）：

| 命令 | 含义 |
| --- | --- |
| `inject,<tid>,<绝对路径>[,manual\|linker][,wake][,unload][,keepelf][,force]` | 默认 manual；设备端路径最多 255 字节，不支持逗号或空白分隔符 |
| `status` / `probe` / `sym` | 请求状态 / 兼容性 / 内核符号诊断 |
| `images[,cursor]` | 枚举 manual 驻留镜像；有 `next=N` 时继续 `images,N` |
| `release,<tid>,<image-id>[,wake][,force]` | 释放一个 manual 引用；最后一次执行析构并解除映射 |
| `cancel,<slot>` / `reap` | 取消尚未执行的排队请求 / 回收完成槽及死亡目标记录 |
| `quiesce` | 禁止新加载并检查能否卸载；重新加载 KPM 才恢复接收 |

`wake` 可唤醒可中断睡眠；省略时等待线程自然返回用户态。
`unload` 用于一次性加载：manual 新镜像在构造函数返回后执行析构并解除映射；
linker 在加载后调用 `dlclose` 释放本次引用，实际卸载取决于 linker 的引用计数等规则。
省略 `unload` 则保持驻留。它控制的是注入 SO 的生命周期。

**`unload` 的副作用：框架不会自动等待 SO 创建的后台线程退出，也不会注销其异步回调、
定时器或 hook。** 构造函数返回时这些任务可能仍在执行；解除映射后继续使用其中的代码、
数据或函数指针，可能导致崩溃、死锁或 App 卡住。仅在所有工作已同步完成、没有后续使用者时
使用 `unload`。需要后台任务或持续回调的 SO 应保持驻留，先通过 payload 自身的机制停止任务、
注销回调并确认不再执行，再释放。已有 manual 驻留镜像应通过 `release` 释放引用；
重复 `inject,...,unload` 不会替代这一步。

`keepelf` 只用于 manual，保留内存 ELF 头。
`force` 仅跳过安全点启发式。**恢复路径会改写 x16/IP0，必须选择 x16 不再使用的协作边界**；
系统调用白名单无法证明这一点，也无法证明目标未持有锁。
manual 要求全部依赖已加载且在 payload 存活期间保持加载，不支持 ELF PT_TLS、
完整 C++/JNI loader 集成。详见[实现与限制](IMPLEMENTATION.md)。

`nodelete=emutls` / `nodelete=elf` 镜像在目标 mm 存活期间不能 release；必须先让
目标进程退出，再 `reap` 并确认 `quiesce=idle`。完全不在 dynsym 中的隐藏 emutls
无法自动识别，payload 使用方仍需自行保证生命周期安全。

卸载前先 `quiesce`；驻留模式需要通过 `images` / `release` 排空所有引用，
并先停止 payload 线程和异步回调。再执行：

```sh
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf reap
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf quiesce
# 必须确认 quiesce=idle 后再执行：
adb shell /data/local/tmp/kpatch "$KEY" kpm unload kclf
```

自动 App 回归（会安装并重启本仓库测试 App、加载和排空 KPM）：

```powershell
.\test\app\device-test.ps1 -SuperKey (Read-Host 'KernelPatch superkey') -Serial '<SERIAL>' -Backend manual -Repeat 10
# -Backend linker 测试另一后端；-Apk / -Kpm 可指定产物
```

## English

KCLF borrows a target thread through kernel `task_work` to run SO constructors and
finalizers in EL0. The default `manual` backend maps and relocates ELF itself;
the explicit `linker` backend calls the target bionic loader.
`main` contains the framework, build configuration, test app and current compatibility report.
Historical reports, detection experiments and full host/device regression fixtures remain on `dev`.

### 1.5.7 changes and validation

- Manual loading reads and compares complete symbol names within DT_STRSZ/readable PT_LOAD
  bounds, removing the 255-byte symbol-name limit. SONAME, DT_NEEDED and version names remain bounded.
- Payload-defined compiler-rt emutls is supported with `nodelete=emutls`: its image stays mapped
  until the target mm exits. First-load `unload` and explicit `release` are rejected.
- No new kernel ABI or symbol dependency; BTF, task_work and procfs/accessor/GUP fallbacks are
  unchanged. All 12 host suites and a real-device BTF parser regression passed.
- Pixel 6 / Android 16 / Linux 6.1.134 / ARM64 / 4K: 186 native/self-owned app assertions passed
  with the release artifact; 243 passed with a separate no-BTF/no-nofault test build. Both runs
  drained and unloaded safely without new kernel diagnostics. Other kernels and 16K/64K devices
  were not tested in this round.
- The 1.5.6 provider table and mapped-provider structural parsing are unchanged. Name storage
  is capped at 64 MiB including NUL, with a 256 MiB cumulative string-read budget; resource
  exhaustion explicitly fails and rolls back.

See the [1.5.7 compatibility report](COMPATIBILITY_1.5.7.md) for implementation, audit evidence,
artifact SHA-256 and validation limits, and the
[GitHub Release](https://github.com/AndroidReverser-Test/KCLF/releases/tag/v1.5.7) for downloads.

### Build

The module requires GNU Make, AArch64 bare-metal GCC/binutils and a KernelPatch
source tree. Run from this repository root (Linux/WSL; replace the paths):

```sh
make KP_DIR=/path/to/KernelPatch TARGET_COMPILE=/path/to/bin/aarch64-none-elf-
```

Output: `kclf.kpm`. Run `make clean` to remove module outputs.
`KP_DIR` defaults to `../..`, suitable for a checkout at KernelPatch's
`kpms/kclf`. KernelPatch headers are external dependencies.

The test app requires Windows PowerShell, a JDK with `java/javac/keytool` on PATH,
Android SDK platform 35 or newer, build-tools and an NDK:

```powershell
.\test\app\build.ps1 -SdkRoot D:\androidSDK -NdkRoot D:\androidSDK\ndk\27.0.12077973
```

Output: `build/kclf-apptest/app.apk`, package `com.kclf.apptest`.
It includes normal, FP-clobbering and delayed-constructor payloads.
`-OutDir` changes the output location; the debug signing key is reused there.

### Use

The device must already run KernelPatch and allow superkey-authenticated
`kpatch` commands. Targets must be 64-bit ARM64. The implementation addresses
Linux 5.x/6.x ABIs; availability still depends on runtime ABI, symbols and device
configuration. This does not certify all kernels or 16K/64K devices.

```sh
adb install -r -t build/kclf-apptest/app.apk
adb shell am start -W -n com.kclf.apptest/.MainActivity
adb shell pidof com.kclf.apptest
adb shell logcat -d -s KCLFAPP:I
adb push kclf.kpm /data/local/tmp/kclf.kpm
```

For the host-shell commands below, set `KEY` to your superkey (never commit it),
`TID` to the target thread ID (PID for the main thread), and `LIBDIR` to the
`libdir` printed in the app log.

```sh
adb shell /data/local/tmp/kpatch "$KEY" kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf probe
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,$LIBDIR/libkclfapp_payload.so,wake"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf status
adb shell run-as com.kclf.apptest cat /data/user/0/com.kclf.apptest/files/hit_$TID
```

This example targets the main thread, so the marker suffix is also the PID.
Poll `status` until it reports `state=done`, `via=manual`, `refs=1`, with no
`pending=` or `map=`. This example keeps the SO resident; use the `images` /
`release` procedure below when it is ready to unload. A `queued` response only
acknowledges scheduling. Append `,linker` for bionic loading.

#### SO path requirements

In `,$LIBDIR/libkclfapp_payload.so`, the comma separates command arguments; the
SO path follows it. `LIBDIR` is a **directory on the device**, expanded by the
host shell. For this example, use the test app's logged `libdir`, such as
`/data/app/~~.../com.kclf.apptest-.../lib/arm64`, and verify that it contains
`libkclfapp_payload.so` installed by the test APK. Replace the full path when
injecting another SO.

- The expanded path must be absolute on the device, at most 255 bytes, and
  contain no commas, spaces, tabs, newlines or other argument separators.
  Quoting the command does not make these characters valid within the path.
- The SO must be a supported 64-bit little-endian AArch64 ELF shared object
  (`ET_DYN`).
- Preparation opens the file using **the target process's credentials**. The
  target must be able to read the SO, traverse its parent directories and
  satisfy SELinux policy. Root access for the controller does not grant file
  access to the target app.
- `manual` also accepts a target-readable path such as
  `/data/user/0/<package>/files/<module>.so`; dependencies must already be loaded
  and mapping permissions remain subject to device policy. `linker` additionally
  requires an allowed path in the target linker namespace and permission for
  executable file mappings. This example uses the installed native library
  directory. Do not assume `/data/local/tmp` is usable by an ordinary app.

Common control strings, passed as the last argument to `kpm ctl0 kclf`:

| Command | Meaning |
| --- | --- |
| `inject,<tid>,<absolute-path>[,manual\|linker][,wake][,unload][,keepelf][,force]` | Defaults to manual; device path is at most 255 bytes and cannot contain commas or whitespace separators |
| `status` / `probe` / `sym` | Requests / compatibility / kernel-symbol diagnostics |
| `images[,cursor]` | List resident manual images; follow `next=N` with `images,N` |
| `release,<tid>,<image-id>[,wake][,force]` | Release one manual reference; the last release runs finalizers and unmaps |
| `cancel,<slot>` / `reap` | Cancel queued work before execution / reclaim finished slots and dead-target records |
| `quiesce` | Disable new loads and check drain status; reload the KPM to accept loads again |

`wake` wakes interruptible waits; otherwise work waits for a natural return to EL0.
`unload` requests a one-shot load: a new manual image runs finalizers after its
constructors return and is then unmapped. The linker backend calls `dlclose` to
release this load's reference; actual unloading depends on linker reference
counts and other rules. Omitting `unload` keeps the SO resident. This option
controls the injected SO's lifetime.

**Side effects of `unload`: the framework does not automatically wait for SO-created
threads to exit or unregister asynchronous callbacks, timers or hooks.** These may
outlive the constructors. Accessing unmapped code, data or function pointers can
crash, deadlock or freeze the app. Use `unload` only when all work has completed
synchronously and no later users remain. Keep SOs with background work or persistent
callbacks resident; stop their work and unregister callbacks through the payload's
own mechanism, then confirm execution has ended before releasing them. Use
`release` for existing resident manual references; repeating `inject,...,unload`
does not release those references.

`keepelf` retains in-memory ELF headers for manual images.
`force` only bypasses safe-point heuristics. **The restore tail overwrites x16/IP0:
use a cooperative boundary where x16 is dead.** The syscall allowlist cannot prove
this or the absence of held locks. Manual loading requires every dependency to
already be loaded and remain resident; ELF PT_TLS and full C++/JNI loader
integration are unsupported. See [implementation and limits](IMPLEMENTATION.md).

Images marked `nodelete=emutls` or `nodelete=elf` cannot be released while their
target mm is alive. Let the target process exit, then `reap` and confirm
`quiesce=idle` before unloading the module. Hidden emutls absent from dynsym
cannot be detected automatically; callers still own payload lifetime safety.

Before unloading, issue `quiesce`. For resident manual images, drain every
reference using `images` / `release`, after stopping payload threads and callbacks.
Then:

```sh
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf reap
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf quiesce
# Continue only after quiesce=idle:
adb shell /data/local/tmp/kpatch "$KEY" kpm unload kclf
```

Automated app regression installs/restarts this test app and loads/drains the KPM:

```powershell
.\test\app\device-test.ps1 -SuperKey (Read-Host 'KernelPatch superkey') -Serial '<SERIAL>' -Backend manual -Repeat 10
# Use -Backend linker for bionic; -Apk / -Kpm select custom outputs.
```
