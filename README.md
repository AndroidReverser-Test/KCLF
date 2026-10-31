# KCLF 1.5.4

Kernel Controlled Loading Framework — Android ARM64 / KernelPatch KPM

[中文](#中文) · [English](#english) · [实现 / Implementation](IMPLEMENTATION.md)

## 中文

KCLF 通过内核 `task_work` 借用目标线程，在 EL0 执行 SO 的构造/析构函数。
默认 `manual` 后端自行映射和重定位 ELF；显式 `linker` 后端调用目标 bionic loader。
`main` 只维护框架、构建配置和测试 App；历史报告、检测实验及原有测试在 `dev`。

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
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,$LIBDIR/libkclfapp_payload.so,wake,unload"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf status
adb shell run-as com.kclf.apptest cat /data/user/0/com.kclf.apptest/files/hit_$TID
```

此例注入主线程，因此 marker 文件后缀也是 PID。重复查看 `status`，
直到出现 `state=done`、`via=manual`、`unload=ok` 且没有 `pending=` / `map=`。
命令返回 `queued` 只表示已排队。追加 `,linker` 可选择 bionic 后端，
其路径需满足目标 linker namespace 和 SELinux 策略。

常用控制字符串（作为 `kpm ctl0 kclf` 的最后一个参数）：

| 命令 | 含义 |
| --- | --- |
| `inject,<tid>,<绝对路径>[,manual\|linker][,wake][,unload][,keepelf][,force]` | 默认 manual；路径最多 255 字节，不支持逗号 |
| `status` / `probe` / `sym` | 请求状态 / 兼容性 / 内核符号诊断 |
| `images[,cursor]` | 枚举 manual 驻留镜像；有 `next=N` 时继续 `images,N` |
| `release,<tid>,<image-id>[,wake][,force]` | 释放一个 manual 引用；最后一次执行析构并解除映射 |
| `cancel,<slot>` / `reap` | 取消尚未执行的排队请求 / 回收完成槽及死亡目标记录 |
| `quiesce` | 禁止新加载并检查能否卸载；重新加载 KPM 才恢复接收 |

`wake` 可唤醒可中断睡眠；省略时等待线程自然返回用户态。
`unload` 在本次加载后立即释放；省略则保持驻留。
`keepelf` 只用于 manual，保留内存 ELF 头。
`force` 仅跳过安全点启发式。**恢复路径会改写 x16/IP0，必须选择 x16 不再使用的协作边界**；
系统调用白名单无法证明这一点，也无法证明目标未持有锁。
manual 要求全部依赖已加载且在 payload 存活期间保持加载，不支持 payload TLS、
完整 C++/JNI loader 集成。详见[实现与限制](IMPLEMENTATION.md)。

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
`main` contains the framework, build configuration and test app.
Historical reports, detection experiments and the original tests remain on `dev`.

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
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,$TID,$LIBDIR/libkclfapp_payload.so,wake,unload"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf status
adb shell run-as com.kclf.apptest cat /data/user/0/com.kclf.apptest/files/hit_$TID
```

This example targets the main thread, so the marker suffix is also the PID.
Poll `status` until it reports `state=done`, `via=manual`, `unload=ok`, with no
`pending=` or `map=`. A `queued` response only acknowledges scheduling.
Append `,linker` for bionic loading; its path must satisfy the target namespace
and SELinux policy.

Common control strings, passed as the last argument to `kpm ctl0 kclf`:

| Command | Meaning |
| --- | --- |
| `inject,<tid>,<absolute-path>[,manual\|linker][,wake][,unload][,keepelf][,force]` | Defaults to manual; path is at most 255 bytes and cannot contain commas |
| `status` / `probe` / `sym` | Requests / compatibility / kernel-symbol diagnostics |
| `images[,cursor]` | List resident manual images; follow `next=N` with `images,N` |
| `release,<tid>,<image-id>[,wake][,force]` | Release one manual reference; the last release runs finalizers and unmaps |
| `cancel,<slot>` / `reap` | Cancel queued work before execution / reclaim finished slots and dead-target records |
| `quiesce` | Disable new loads and check drain status; reload the KPM to accept loads again |

`wake` wakes interruptible waits; otherwise work waits for a natural return to EL0.
`unload` releases immediately after loading; omitting it keeps the library resident.
`keepelf` retains in-memory ELF headers for manual images.
`force` only bypasses safe-point heuristics. **The restore tail overwrites x16/IP0:
use a cooperative boundary where x16 is dead.** The syscall allowlist cannot prove
this or the absence of held locks. Manual loading requires every dependency to
already be loaded and remain resident; payload TLS and full C++/JNI loader
integration are unsupported. See [implementation and limits](IMPLEMENTATION.md).

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