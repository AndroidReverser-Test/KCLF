# KCLF 1.2.0

ARM64 Android 的 KernelPatch 模块：通过目标线程的 `task_work`、EL0 跳板和系统动态链接器加载 SO。
仅用于自己控制并获授权的测试进程。它不是不可观测的加载器，也不是任意应用/内核均可用的通用注入方案。

当前实现、问题修复、版本矩阵、设备证据和限制见 [兼容性与代码审计](COMPATIBILITY_AUDIT.md)。
独立仓库所需的 KernelPatch 宿主修复见 [配套补丁](patches/README.md)；构建时将本仓库放在 KernelPatch 的 `kpms/kclf` 下，或设置 `KP_DIR`。
`IMPLEMENTATION.md`、`HARDENING.md`、`OBSERVABILITY_AUDIT.md` 保留为历史文档，不代表 1.2.0。

## 构建

在仓库根目录的 WSL/Linux shell 执行，要求 ARM64 GCC/binutils：

```sh
make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
```

产物为 `kpms/kclf/kclf.kpm`。必须保留 Makefile 中的 freestanding、通用寄存器、禁止 outline atomics
和禁止 unwind tables 等选项。模块不使用运行时 libc；它通过 KernelPatch 和内核符号解析调用接口。

## 自有测试进程

Windows PowerShell，示例使用本次设备测试的 NDK：

```powershell
$KclfClang = 'D:/androidSDK/ndk/27.0.12077973/toolchains/llvm/prebuilt/windows-x86_64/bin/aarch64-linux-android26-clang.cmd'
& $KclfClang -Wall -Wextra -Werror -O2 kpms/kclf/test/target.c kpms/kclf/test/fpsimd.S -ldl -o kpms/kclf/test/kclf_target
& $KclfClang -Wall -Wextra -Werror -O2 -shared -fPIC kpms/kclf/test/payload.c -o kpms/kclf/test/libkclf_payload.so
```

不要将 root 密钥写进源码或脚本。从交互输入取得密钥，选择自己的测试设备：

```powershell
$KclfKey = Read-Host 'KernelPatch test key'
./kpms/kclf/test/device-test.ps1 -SuperKey $KclfKey -Serial '<DEVICE_SERIAL>' -Adb 'D:/androidSDK/platform-tools/adb.exe'
```

脚本不编译源码；运行前先完成上面的构建。它拒绝覆盖已加载的 `kclf`，每次创建独立测试目录，
只启动/注入/终止自己的测试程序，保留日志与构造函数 marker。结果存到 `build/kclf-test-<id>/`。
若设备 `probe` 报告不支持 wake，脚本检查该命令被拒绝。
本脚本的主路径已在 6.1.134/4K 设备执行；其他配置不能据此视为已验证。

宿主单元测试（WSL/Linux，GCC + Python 3）：

其中 `checks/test_module_lifecycle.py` 来自配套宿主补丁；尚未应用补丁的父仓库不会包含该文件。

```sh
python3 kpms/kclf/test/test_helpers.py
python3 checks/test_module_lifecycle.py
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  kpms/kclf/test/test_btf.c -o /tmp/kclf-test-btf
/tmp/kclf-test-btf
# 可选：附加从自己设备获得的原始 /sys/kernel/btf/vmlinux 文件路径。
```

## 控制接口与安全卸载

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

调用形式为 `adb shell /data/local/tmp/kpatch <KEY> kpm ctl0 kclf <COMMAND>`。
默认 `resume` 等待目标自然返回用户态；`wake` 仅在支持路径启用；`force` 只跳过安全点启发式，
不绕过架构、信号、seccomp、跟踪或资源安全检查。路径必须为绝对路径，少于 256 字节且不含分隔符/空白。
`unload` 表示构造函数返回后调用 `dlclose`，不保证任意库的依赖、NODELETE、后台线程或副作用都被移除。

卸载顺序：停止发送 inject → `quiesce` → 等待完成并按需 `status`/`reap` → 确认 `quiesce=idle` →
`kpm unload kclf`。`quiesce` 不可恢复接收新请求，需要安全卸载并重载模块。

特别注意：旧 KernelPatch 可能忽略模块 exit 的错误返回并释放代码。
此时直接卸载繁忙模块会破坏仍在执行的回调/跳板，不能依赖 `-EBUSY` 保护。
本仓库已附带宿主修复，但本次未刷写设备；旧宿主仅支持单控制端、严格排空后的受控测试。

这不是普通 Android 应用的即插即用注入器：当前主动拒绝 seccomp 过滤/被跟踪线程、32 位目标以及
已有 SVE/SME 状态。目标必须是合作的 ARM64 测试程序，并在可控空闲点加载。
