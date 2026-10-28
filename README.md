# KCLF 1.3.0

KCLF 是一个 ARM64 Android 的 KernelPatch 模块：在目标线程下一次返回用户态时重定向
`pt_regs`，用一小段 EL0 trampoline 调用目标自己的动态链接器加载 SO，再通过 `getpid`
自陷把寄存器完整恢复。它不使用 ptrace、不暂停目标、不安装信号处理器。

1.3.0 起支持**普通 64 位 Android 应用进程**：zygote fork 出来、带 seccomp 过滤器、
运行在 `untrusted_app` 域里的第三方应用可以直接作为目标；同时也仍然支持自有 native
测试进程。它只用于自己控制并获授权的进程，不承诺“不可检测”或“对任意应用无副作用”。

## 与 KernelPatch 宿主的关系

1.3.0 不再需要、也不再包含 KernelPatch 宿主补丁。仓库里的 `patches/` 已删除。
构建和运行时使用 stock KernelPatch；控制端仍是 `/data/local/tmp/kpatch`（superkey 保护）。

stock 宿主在 `kpm unload` 时即使模块 exit 回调返回错误也会释放模块代码。因此卸载流程
必须由控制端保证：先 `quiesce`，等 `status` 显示无活动请求且映射已回收，再 `unload`。
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

`probe` 会打印内核版本、BTF 布局、`pt_regs` 大小、页大小、wake 能力和 hook 状态。
不同厂商内核如果没有可验证的 BTF/结构偏移或必需符号，模块会拒绝加载，而不是猜偏移。

## 控制接口

```text
probe
inject,<tid>,<absolute-so-path>[,force][,wake][,unload]
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
| 默认（`resume`） | 用 `TWA_RESUME` 排队，等目标自然返回用户态；适合会周期性进内核的线程 |
| `wake` | 用 `TWA_SIGNAL` 通知目标（5.11+），可打断 `epoll_pwait`/`futex`/`ioctl`/`nanosleep` 等阻塞；会改变被中断系统调用的时序 |
| `force` | 跳过 linker/系统调用白名单启发式；不绕过 32 位、SVE/SME、跟踪器等硬性拒绝 |
| `unload` | 构造函数返回后调用 `__loader_dlclose`/`dlclose` |

`status` 里如果请求长时间停在 `armed`，会显示 `hint=blocked(use wake)`：目标线程正在
睡眠且默认 `resume` 不会主动唤醒它。此时取消后改用 `wake` 重试。

路径必须是绝对路径、长度小于 256 字节，且不能包含逗号、制表符、空格等控制面分隔符；
模块在 `prepare` 阶段用**目标进程的凭据**打开并校验 ELF。

## 注入普通 app

### 1. 选择进程和线程

```sh
adb shell pidof com.example.app
adb shell ls /proc/<pid>/task
```

主线程的 tid 等于 pid，通常阻塞在 `epoll_pwait` 的 Looper 中；注入主线程时使用
`wake`。也可以选择 binder 线程（`ioctl`）、`kclf-sleeper` 这类周期性 `nanosleep`
线程（默认 `resume` 即可）。

普通应用进程有两点与自有 native 测试进程不同：

* **seccomp**：zygote 给每个 app 安装的过滤器允许 `getpid`，所以完成自陷可以工作；
  1.3.0 不再因为 `TIF_SECCOMP` 拒绝普通 app。
* **VMA 很多**：app 常有 2000+ 个 VMA，扫描上限已提高，并会扫描到高地址的
  `/apex/.../linker64` 与 `libc.so`。

### 2. 准备 payload 路径

SO 必须同时满足：

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

`/data/local/tmp` 对普通 `untrusted_app` 通常不可用。设备实测：`prepare` 可以打开文件，
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
#0 id=1 pid=7844(com.example.app) state=done stage=restore handle=... via=__loader_dlopen
```

### 4. payload 约束

构造函数在目标线程的 `dlopen` 内部执行，此时 linker 锁已被持有：

* 不要在构造函数里再次 `dlopen`/`dlsym`/`dlclose`（会自死锁）；
* 不要依赖 JNI/Java 线程状态、不要调用 `JNIEnv`（注入线程不一定是 Java 线程）；
* 不要长时间阻塞、不要在构造函数里等待其他线程；
* payload 只能链接目标 app 命名空间可见的系统库；自包含的 native 代码最稳；
* 需要后台线程时，自行保证线程生命周期与 `unload` 的竞态。

### 5. 卸载

```sh
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf quiesce
# 等 status 中所有请求完成/回收，quiesce=idle
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf reap
adb shell /data/local/tmp/kpatch $KEY kpm unload kclf
```

`quiesce` 之后模块不再接收新请求，但已经在 trampoline 里的请求仍会继续完成。
在 stock 宿主上不能在 `running`/`preparing`/`ready` 或仍有 cleanup 回调时卸载。

## 限制

1. **仅 64 位目标**。32 位 app 在 hijack 阶段以 `32-bit target unsupported` 拒绝。
2. **不绕过调试/跟踪**。`TIF_SYSCALL_TRACE`、`SYSCALL_EMU`、`SINGLESTEP`、`UPROBE`
   仍拒绝；ptrace 调试器、strace 等场景不支持。
3. **seccomp 允许，但不是任意过滤器的保证**。标准 zygote app 策略允许完成用的
   `getpid`；若目标自己安装了杀死/拒绝 `getpid` 的过滤器，完成自陷无法到达，属于
   不支持场景。框架不绕过、不修改目标的 seccomp 策略。
4. **SVE/SME 状态仍拒绝**；FPSIMD（q0–q31、FPCR/FPSR）在 trampoline 中保存恢复。
5. **注入是异步的**：目标线程可能停在任意内核返回点。安全点判断只是启发式，不能
   证明用户态锁未被持有；`force` 只用于排障。
6. **不冻结进程**：其他线程仍可并发 `mmap`/`munmap`、修改 linker 状态或发信号。
7. **不保证不可观测**：临时映射、loader 记录、构造函数副作用和时序都可被目标观察。
8. **目标退出时**：请求持有 `struct pid` 身份但不长期持有 `mm`，避免延后 `exit_mmap`
   导致 ActivityManager 收不到进程死亡；目标消失后由 `reap` 清槽，旧 mm 中的临时映射
   随最后使用者退出。
9. **没有宿主 exit-veto**：卸载安全性依赖控制端先 `quiesce` 排空；模块 exit 的
   `-EBUSY` 在 stock 宿主上不会被尊重。
10. **没有覆盖所有内核**：BTF/符号/结构布局必须可验证；5.x、其他 6.x、16K/64K 页
    仅有源码适配，未在本设备矩阵外实测。

## 测试

自有 native 目标（默认、wake、unload、seccomp、取消、目标退出、映射回收、
reload/unload 等）：

```powershell
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' -Adb '<ADB>'
```

普通 app 测试需要先构建测试 APK，再运行 app 测试脚本；说明见
[test/app/README.md](test/app/README.md)。

主机侧辅助函数测试（WSL/Linux，GCC + Python 3）：

```sh
python3 kpms/kclf/test/test_helpers.py
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  kpms/kclf/test/test_btf.c -o /tmp/kclf-test-btf
/tmp/kclf-test-btf
```

## 文档

- [COMPATIBILITY_AUDIT.md](COMPATIBILITY_AUDIT.md)：1.3.0 的实现、兼容性、设备结果与限制。
- `IMPLEMENTATION.md`、`HARDENING.md`、`OBSERVABILITY_AUDIT.md`：历史版本资料，
  不代表 1.3.0；其中关于宿主补丁、seccomp 拒绝和默认行为的段落已过时。
