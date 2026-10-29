# libtest.so 注入 com.miHoYo.Nap 实测（2026-10-29，KCLF 1.4.1）

## 结论

默认 **manual 后端**已能把用户提供的 `/data/local/tmp/libtest.so` 注入
`com.miHoYo.Nap` 并执行构造函数。目标线程在 `getpid` 自陷后完整恢复，
`status` 为：

```text
#0 id=1 pid=16488(com.miHoYo.Nap) state=done stage=restore handle=1 via=manual image=1 refs=1 resident=704bab4000+548864
```

payload 自己用 `Perfare` 标签输出的前两行可见：

```text
10-29 22:53:24.412 16488 16488 I Perfare : start dump.....
10-29 22:53:24.412 16488 16488 I Perfare : game dir:/data/user/0/com.miHoYo.Nap
```

随后 payload 报告 IL2CPP API 缺失并取消 dump。**这不是注入失败**；同一 payload
用旧 `,linker` 后端加载到 App 自己的 native library 目录时也得到完全相同的结果。
原因是该 App 的 `libil2cpp.so` 在磁盘上没有可解析的 IL2CPP 导出符号，而 payload
自行解析内存 ELF 时需要 `/proc/self/mem`；Android 把 App 标记为 non-dumpable，
该文件对 App 自身凭据返回 `EACCES`。框架不修改 non-dumpable、SELinux 或 ptrace
策略，因此不会替 payload 绕过这一限制。详见“payload 侧限制”。

本次同时修复了两个会影响真实 App 的 manual 后端缺陷：

1. 多个同名 `libc++.so` 一律报 `ambiguous loaded SONAME`；
2. 非 dumpable App 的 `/proc/thread-self/auxv` 不可读，导致所有 IFUNC 导入失败。

## 设备与产物

| 项目 | 值 |
| --- | --- |
| 设备 | 22041211AC / rubens |
| ADB serial | LVLNINYXKR4L6HAE |
| Android / 内核 | 12 / 5.10.66-android12-9-00001-gd262b276948e-ab8291727 |
| 页大小 / 架构 | 4096 / arm64-v8a |
| 目标 | com.miHoYo.Nap，测试 PID 16488（主线程 TID 16488） |
| KCLF | 1.4.1，`kclf.kpm` SHA-256 `8749c287f1243d433f26e6b0a6e86b32a7136860adc9c4369fe5db881ebd7f59` |
| payload | `/data/local/tmp/libtest.so` SHA-256 `944efd09c1e031237ffbdcca4eda5c919e0ea616fa97e4b0c545ec33c0c3abea` |
| 构建 | WSL Ubuntu 24.04，AArch64 GCC 13.3.0，`make -B -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4` |

## 修复一：同名 SONAME 的来源选择

修复前失败：

```text
inject,11519,/data/local/tmp/libtest.so,manual,wake
#0 id=1 ... state=failed stage=prepare err="manual: ambiguous loaded SONAME: libc++.so"
```

`libtest.so` 的直接依赖 `liblog.so` 的 `DT_NEEDED` 包含 `libc++.so`。目标进程同时映射了：

```text
/apex/com.android.vndk.v31/lib64/libc++.so
/apex/com.android.conscrypt/lib64/libc++.so
/apex/com.android.art/lib64/libc++.so
/system/lib64/libc++.so            （两个独立 load bias，同一路径/文件）
```

旧实现只按全进程 SONAME 建表，看到第二个同名提供库就报错，没有利用映射路径
所携带的加载来源。1.4.1 在 VMA 扫描时解析 `/proc/thread-self/maps` 的 pathname，
并为每个提供库保存路径；每条 `DT_NEEDED` 用**导入库自身的来源**评分后选择：

```text
完全相同路径 > 同目录 > 同 APEX 模块 > 同分区 > vendor/ODM 的 VNDK >
平台默认 /system > 默认 runtime APEX > 最长公共前缀
```

最高分仍有多个**不同路径**时仍明确失败；同一路径的多个映射（如本设备的两个
`/system/lib64/libc++.so`）只选一个，避免同一文件被重复加入闭包。这样
`/system/lib64/liblog.so` 的 `libc++.so` 会选 `/system/lib64/libc++.so`，
而不是 vndk / conscrypt / art 实例。

修复后同一请求进入准备、重定位、构造并完成，`via=manual image=1`。

## 修复二：非 dumpable App 的 AT_HWCAP

修复一之后失败变为：

```text
#0 ... state=failed stage=prepare err="manual: IFUNC HWCAP read failed rc=-2"
```

`libtest.so` 从 bionic libc 导入 `memcpy`/`memcmp`/`strlen` 等，其中多项是
IFUNC；manual 后端必须在 EL0 调用提供库的 resolver，并传入目标 AArch64
`AT_HWCAP`/`AT_HWCAP2`。旧实现打开 `/proc/thread-self/auxv`：

```c
f = filp_open("/proc/thread-self/auxv", 0, 0);
if (!f || (unsigned long)f >= (unsigned long)-4095) return -ENOENT;
```

Android 的 App 进程是 non-dumpable，`/proc/<pid>/auxv` 和 `/proc/<pid>/mem`
由 root 拥有（`-r-------- root root`），即使使用目标自己的凭据也会被拒绝。
`filp_open` 的实际 `-EACCES` 又被折叠成 `-ENOENT`，所以只看到 `rc=-2`。

1.4.1 改用内核导出的 `cpu_get_elf_hwcap()` / `cpu_get_elf_hwcap2()`；它们是
arm64 `ELF_HWCAP`/`ELF_HWCAP2` 的正式取值来源，与进程无关。旧 auxv 路径保留
为 accessor 不存在时的后备。`probe` 现在显示：

```text
hwcap=119fff hwcap2=0 source=kernel
```

一个独立诊断 SO 在目标进程内调用 libc `getauxval()` 得到相同的
`hwcap=119fff`，同时确认：

```text
kclf-probe mem=-1 errno=13 auxv=-1 errno=13 maps=203 errno=13
```

即 `/proc/self/mem` 与 `/proc/self/auxv` 均为 `EACCES`，`/proc/self/maps` 可读。

## 生命周期与复用验证

| 步骤 | 结果 |
| --- | --- |
| 首次 manual 注入 | `id=1 state=done via=manual image=1 refs=1 resident=704bab4000+548864` |
| 同路径再次注入 | `id=2 state=done refs=2`，未重跑构造函数（`start dump` 计数仍为 1） |
| `release,16488,1,wake` | `id=3 state=done ... refs=1 unload=ok rc=0` |
| 再次 `release` | `id=4 state=done ... refs=0 resident=0+0 unload=ok rc=0`，`images` 返回 `no manual images` |
| 注入地址回收 | `maps` 中 `704bab4000-...` 的匿名代码页在最终 `maps` 中消失 |
| 目标存活 | 结束仍为 PID 16488，无 crash buffer 记录 |
| 卸载 | `quiesce=idle`，`kpm unload kclf` 成功，最终 `kpm list` 为空 |
| 内核 | 无新增 `BUG:/WARNING:/Oops/panic` |

重复注入只增加引用、不重跑构造函数，符合 1.4.0 已记录的“同路径驻留镜像”语义；
这次额外验证了在存在多个同名 `libc++.so` 的目标里该路径仍然成立。

## payload 侧限制

`libtest.so` 的构造函数已经执行；之后的 IL2CPP dump 在目标进程内失败：

```text
required IL2CPP API missing: il2cpp_domain_get
...
IL2CPP API initialization failed; dump cancelled
```

独立验证表明这不是 manual 后端的问题：

1. `libil2cpp.so` 已映射（4 个 VMA，路径为 App 的 `lib/arm64`）。
2. 一个诊断 SO 在目标进程内执行 `dlopen("libil2cpp.so")` 和
   `dlsym(handle, "il2cpp_domain_get")`，`dlopen` 返回非空，`dlsym` 报
   `undefined symbol: il2cpp_domain_get`；用完整路径 `dlopen` 结果相同。
3. 设备上直接 `grep -a il2cpp_domain_get libil2cpp.so` 为 0 次，说明磁盘 ELF
   不包含常规 IL2CPP 导出符号；payload 需要解析解密后的内存映像，而它依赖
   `/proc/self/mem`，该文件对 non-dumpable App 返回 `EACCES`。
4. 把同一 `libtest.so` 放进 App 的 `/data/app/.../lib/arm64/` 并用
   `,linker` 后端注入（payload 因此已注册到 bionic），`Perfare` 输出与 manual
   后端逐行相同，仍报全部 API 缺失。

因此本次验收的是**注入链路**：ELF 解析、依赖选择、重定位、IFUNC、构造/析构、
引用和回收全部通过，构造函数及 payload 自己创建的线程都已实际运行。若要让该
payload 完成完整 dump，需要它自己能读取解密后的 `libil2cpp` 内存，或由调用方
显式接受修改 non-dumpable/ptrace 策略；KCLF 当前不这样做。

## 复现

```sh
make -B -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4
adb push kpms/kclf/kclf.kpm /data/local/tmp/kclf.kpm
adb push <libtest.so> /data/local/tmp/libtest.so
adb shell "/data/local/tmp/kpatch <KEY> kpm load /data/local/tmp/kclf.kpm"
adb shell "/data/local/tmp/kpatch <KEY> kpm ctl0 kclf probe"
PID=$(adb shell pidof com.miHoYo.Nap | tr -d '\r')
adb shell "/data/local/tmp/kpatch <KEY> kpm ctl0 kclf inject,$PID,/data/local/tmp/libtest.so,manual,wake"
adb shell "/data/local/tmp/kpatch <KEY> kpm ctl0 kclf status"
adb shell "logcat -d -v threadtime --pid=$PID | grep Perfare"
```

无显式 `unload` 时镜像是驻留的；按 README 的 `images`/`release`/`reap`/
`quiesce` 步骤回收后再 `kpm unload kclf`。

## 证据目录

`E:/KernelPatch/build/kclf-libtest-20261029-final/`：

- `summary.json`、`results.json`：完整控制交互和断言结果；
- `probe.txt`、`status-inject1.txt`、`images-*.txt`：状态与引用计数；
- `logcat-inject1.txt`、`logcat-reuse.txt`：Perfare 输出与复用前后计数；
- `maps-inject1.txt`、`maps-final.txt`：注入地址和回收；
- `dmesg-before.txt`/`dmesg-after.txt`、`crash-after.txt`、`boot-id.txt`、
  `selinux.txt`：设备状态；
- `kclf.kpm`、`libtest.so`、`run.py`：最终产物和可复测驱动。
