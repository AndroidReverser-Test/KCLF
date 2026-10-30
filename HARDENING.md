# KCLF 可观测性收敛改动（1.1 历史文档）

> 版本说明（2026-10-28）：本文为历史记录；其中“整页擦除”、扫描 pt_regs、40 KB 映射和卸载超时等
> 描述不适用于 1.2.0。当前参数仅擦已使用区，临时映射为 11 页，布局不再扫描猜测，卸载必须排空。
> 1.3.0 进一步支持普通 64 位 app，并删除全部 KernelPatch 宿主补丁；本文提到的宿主排空保护不再存在。
> 当前实现和本轮实测见 [COMPATIBILITY_AUDIT.md](COMPATIBILITY_AUDIT.md)。

日期：2026-10-27。对应源码：`kpms/kclf`，模块版本 `1.1.0`。本文记录针对
原 2026-10-27 历史可观测性审计所做修改、设备实测结果和仍然
存在的特征；不把“减少特征”表述成“不可检测”。旧审计文件已替换删除，
当前版本结论见 [1.4.1 可观测性报告](OBSERVABILITY_REPORT.md)。

## 1. 改动摘要

| 审计中的可观察点 | 本次修改 | 效果 |
| --- | --- | --- |
| 临时跳板映射 34 页 / 约 136 KB | 改为 2 页代码与参数 + 8 页栈，共 40 KB；实测为 1 个 `r-xp` 4 KB VMA 加 1 个 `rw-p` 36 KB VMA | 临时映射的虚存占用降到原来的约 29%，VMA 仍为 2 个 |
| 参数页在加载后仍保留库路径、cookie、loader 指针 | trampoline 在 `getpid` 完成陷阱前用 `stp xzr` 清零整页 | 目标内存中不再保留本次请求的路径/cookie/loader 地址 |
| `dlerror()` 文本被拷进目标参数页 | 只把字符串指针放入 `x2`，内核在 cleanup（目标上下文、可睡眠）里读取 | 目标地址空间不再写入错误文本 |
| handle 从参数页读回 | trampoline 把 handle 放 `x1`，`getpid` hook 直接取寄存器 | 参数页可在陷阱前完全擦除 |
| 默认注入会伪造 pending signal、打断 `nanosleep`、触发系统调用重启 | 默认改为 `TWA_RESUME`，不调用 `signal_wake_up_state`；新增 `wake` 选项保留旧的低延迟路径 | 目标 5 秒 `nanosleep` 实测无异常；`wake` 路径实测变为约 5.886 秒 |
| `dlopen` 留下持久库映射和 linker 记录 | 新增 `unload` 选项：构造函数返回后调用 `__loader_dlclose` / `dlclose` | 一次性 payload 在目标 maps 中完全消失，VmSize 回到基线 |
| `vm_munmap` 失败也清空映射字段、`finished` 不能证明回收 | `kclf_exec_finish()` 只在成功（或 `EINVAL`，说明区间已不存在）时清空；cleanup 最多重试 8 次并在失败时保留映射信息、报告错误 | 不再把失败的回收伪装成成功；失败槽位不会被静默复用 |
| 卸载时先移除完成 hook，仍在运行的 trampoline 会执行真实 `getpid` 后死循环 | 先取消排队 work、等待 `busy/completing/loading_num` 排空，再 `unhook_syscalln`；同时取消 cleanup work | 降低卸载竞态；仍不能等待永不返回的目标 |
| `test/payload.c` 默认写 hit 文件并打印 | 默认构造函数完全静默；只有 `KCLF_TEST_VERBOSE=1` 才写文件/打印 | 测试 payload 默认不产生文件或 stdout 副作用 |
| 老内核 `vm_flags` 偏移不一致，导致找不到 `ld-android.so` | 不再依赖 `vm_flags`；对每个 VMA 起始地址直接试读 ELF 头并由头部字段校验 | 实测改用 `__loader_dlopen`，不依赖 `libdl.so` 是否已加载 |
| `__arch_copy_from_user` 遇到未驻留的文件页会失败 | 读 ELF/符号前用 `fault_in_pages_readable` 逐页预缺页；失败时回退 `access_process_vm` | 冷页/老内核下 loader 解析稳定 |
| 老 KernelPatch 不导出 `_task_pt_reg`、缺少 `__aarch64_ldadd*` | 改为扫描 `pt_regs` 帧；编译加 `-mno-outline-atomics` | 可在 Android 12 / kernel 5.10 / kpatch c02 上加载 |
| 64 位原子 libcall、Makefile 本地头文件路径 | Makefile 修复 `-I.` 并加入架构编译选项 | 直接 `make TARGET_COMPILE=aarch64-none-elf-` 可构建 |

另外修正了 syscall 白名单：arm64 的 `nanosleep` 是 101，原列表误写为 35
（35 实际是 `unlinkat`）。这会让默认注入在 `nanosleep` 边界反复 `-EAGAIN`。

## 2. 控制面变化

```text
kpatch <KEY> kpm ctl0 kclf inject,<tid>,<path>[,force][,wake][,unload]
```

- 默认：`TWA_RESUME`，不设置 `TIF_SIGPENDING`，不唤醒睡眠中的目标。目标在
  `nanosleep`/`epoll_wait` 里时，请求会停在 `armed`，直到该调用自然返回。
- `wake`：旧行为。用 `signal_wake_up_state(task, 0)` + `TWA_SIGNAL` 主动打断
  可中断睡眠；低延迟，但会改变系统调用重启和耗时语义。
- `unload`：`dlopen` 成功后调用 `__loader_dlclose`；只适用于“构造函数完成即
  自洽”的 payload。若 payload 的线程还会执行库内代码，卸载会使其崩溃。
- `force`：跳过安全点启发式。
- `resume`：仍被接受，作为默认行为的兼容写法。
- `status` 新增 `unload=ok|failed rc=... by=__loader_dlclose`。

## 3. 新参数页布局（`kclf_param.h`）

| 偏移 | 内容 |
| --- | --- |
| `0x00` | `dlopen` / `__loader_dlopen` |
| `0x08` | `dlerror` / `__loader_dlerror` |
| `0x10` | caller（命名空间解析） |
| `0x18` | handle 暂存 |
| `0x20` | cookie |
| `0x28` | `dlopen` flags |
| `0x30` | `dlclose` / `__loader_dlclose` |
| `0x38` | unload 标志 |
| `0x40` | 库路径（256 字节） |
| `0x140` | `dlerror()` 字符串指针 |
| `0x148` | 页内参数区结束 |

trampoline 在完成陷阱前把 `0x00..0x14f` 全部清零，然后把结果放入
`x1=handle`、`x2=dlerror 指针`、`x3=dlclose 返回值`，最后执行
`getpid(cookie)`。内核 hook 只把这三个值记到请求对象，cleanup 再读取
`x2` 指向的字符串。

## 4. 设备实测（OnePlus/Android 12，kernel 5.10.66，`/data/local/tmp/kpatch`）

以下均为单次观察，不是统计结论，也不能证明目标无法检测。

### 4.1 默认（quiet）注入

- 目标 `kclf_target` 的 `nanosleep` 为 20 ms，注入在数百毫秒内完成，状态
  `done`，`via=__loader_dlopen`。
- 目标 `nanosleep(5s)` + `KCLF_TEST_VERBOSE=1`：注入后请求保持 `armed`，直到
  5 秒睡眠自然结束才变成 `done`；日志没有 `sleep anomaly` 行。
- 同一目标改用 `wake`：约 0.5 秒内完成，日志出现
  `sleep anomaly ... elapsed_us=5885786`，即 5 秒睡眠变成约 5.886 秒。

### 4.2 临时映射

payload 构造函数用 `KCLF_TEST_HOLD_MS=5000` 保持 5 秒，期间读取目标 maps：

```text
71a3838000-71a3839000 r-xp 00000000 00:00 0      <- 代码页 4 KB
71a3839000-71a3842000 rw-p 00000000 00:00 0      <- 参数页 + 8 页栈 36 KB
```

即临时映射共 40 KB、2 个 VMA。改前为 136 KB（2 + 32 页）。构造函数返回后
再次读取，匿名 `r-xp` 4 KB 已消失，VmSize 回到基线附近。

### 4.3 `unload`

在新目标上只注入一次 `...,unload`：

```text
#2 id=11 ... state=done ... via=__loader_dlopen unload=ok rc=0 by=__loader_dlclose
no-payload
```

目标 maps 不再包含 `libkclf_payload.so`；VmSize 与注入前相同。对同一目标先做
一次普通持久加载再做 `unload` 时，`dlopen` 引用计数为 2，`dlclose` 只减到 1，
映射仍存在；这是正常的 linker 引用计数语义，不是 `unload` 失败。

目标自身的 `dl_iterate_phdr`（`KCLF_TEST_PHDR_EVERY=100`）也能反映差异：默认
持久加载后列表中包含 `name=/data/local/tmp/libkclf_payload.so`；`unload` 后
周期性枚举不再包含该条目。这验证的是 linker 记录，不是“目标无法枚举”。

### 4.4 错误路径

对截断的 ELF 注入，`dlerror` 文本经 `x2` 指针由内核读取，状态为：

```text
state=failed stage=loader err="dlopen failed: \"/data/local/tmp/libkclf_bad.so\" has invalid phdr offset/size: 64/504"
```

目标继续运行。

## 5. 仍然存在的特征

1. **默认持久加载**仍会在目标 maps 中留下 payload 及其依赖的文件映射，并通过
   `dl_iterate_phdr` 可见。只有 `unload` 模式能移除这些记录，且要求 payload
   可在构造函数返回后独立存在。
2. **临时映射不是不可见的**：从 `vm_mmap` 到 cleanup 之间仍存在 40 KB、2 个
   VMA；其他线程可并发读取 maps。payload 构造函数/析构函数耗时越长，窗口越大。
   模块卸载时若还有排队中的 cleanup，会取消该 work 以避免回调进入已释放模块；
   此时临时映射可能残留到目标进程退出。
3. **路径**：默认加载的 payload 路径仍会出现在 `/proc/<pid>/maps` 和
   `dl_iterate_phdr` 的 `dlpi_name` 中。`unload` 后消失；本次未实现 memfd 或
   手工 ELF 映射来隐藏路径。
4. **文件描述符/线程/TracerPid**：框架不 ptrace、不创建用户线程；linker 仍会
   短暂打开 payload 文件，payload 自身仍可创建线程/文件。
5. **时间**：默认路径不再主动唤醒或重启系统调用，但 `dlopen` 本身、文件读取、
   页错误和 linker 锁仍会占用目标线程时间。
6. **内核侧**：KPM 名称、模块文件、init/exit 日志对 root/可读 klog 的观察者
   可见；这些不在目标进程的普通观察范围内，但未做隐藏。
7. **不提供针对检测方的保证**：本次只减少若干审计中列出的特征，没有消除
   linker 记录、映射枚举、时序差异或 payload 自身副作用。
8. **卸载仍有边界**：`kclf_exit` 会先取消排队 work、等待 `busy/completing/
   loading_num` 和待回收映射，再移除完成 hook；但 KPM 卸载路径不会因 exit
   返回非零而保留模块。若目标在等待窗口内仍执行 trampoline（例如 payload
   构造函数长时间阻塞），完成陷阱可能丢失，目标线程可能停在 trampoline 末尾。
   卸载前应先确认 `status` 中没有 `running`/`armed`/`preparing` 请求。

## 6. 测试开关

```bash
# 默认静默 payload；需要证据时：
adb shell 'KCLF_TEST_VERBOSE=1 /data/local/tmp/kclf_target 3000 >/data/local/tmp/t.log 2>&1 &'

# 让构造函数保持临时映射 5 秒，便于观察
adb shell 'KCLF_TEST_SLEEP_MS=1000 KCLF_TEST_HOLD_MS=5000 /data/local/tmp/kclf_target 20 ...'

# 周期性打印目标自己的 dl_iterate_phdr 列表（每 250 个循环）
adb shell 'KCLF_TEST_PHDR_EVERY=250 /data/local/tmp/kclf_target 3000 ...'
```
