# libhybridclr_dumper.so 加载失败分析与修复

初始对照验证：2026-11-27，小米 13（fuxi / 2211133C），Android 13，
Linux 5.15.74-android13-8，ARM64，4 KiB 页，SELinux Enforcing。
源码基线为 KCLF 1.6.4（`5884a9f`），本修复尚未发布。
后续在 Pixel 6 上对目标游戏的实际注入结果见文末。

本文记录自动 tmpfs 加载实现之前的复现结果；当前版本对默认 manual 后端增加了
`/data/local/tmp/` 自动后备文件机制，最新行为与验证见 [自动加载说明](TMP_SO_LOADING.md)。

## 实现与失败位置

`kclf.c` 接收 superkey 保护的控制命令，持有目标 PID/mm/凭据引用后提交准备 worker。
worker 借用目标 mm 并切换到目标凭据；`kclf_manual.c` 读取 ELF 快照，映射 PT_LOAD，
通过 `kclf_exec.c` 的 VMA 迭代器收集依赖库路径和权限，再解析符号及重定位。
准备完成才通过目标线程的 task_work 重定向返回现场，在 EL0 跳板执行初始化函数；
完成 token 被观察后恢复/清理临时映射，登记驻留镜像。

设备保留的两次失败均在 prepare 阶段，尚未调用 payload 构造函数。
同一个 SO 在普通测试 App 中可以正常加载，因此本次失败不是其 ELF 格式或重定位不支持。

## 原因一：源路径不能被目标 App 执行

原请求使用 `/data/local/tmp/libhybridclr_dumper.so`，文件标签是
`u:object_r:shell_data_file:s0`。内核日志直接记录：

```text
avc: denied { execute } for comm="kclf-prep"
path="/data/local/tmp/libhybridclr_dumper.so"
scontext=u:r:untrusted_app:... tcontext=u:object_r:shell_data_file:s0
tclass=file permissive=0
```

因此 `vm_mmap(PROT_READ|PROT_EXEC)` 返回 `-EACCES`（-13）。文件原本已经是 0666，
继续放宽 Unix 权限没有作用；控制端 root 也不等于 worker 的目标凭据拥有执行权限。
需将 SO 放在该目标策略允许执行的位置，例如安装后的 native library 目录。
App 私有 files 目录是否允许执行取决于目标 SDK/设备策略，不能通用保证。

设备已有 `/data/data/com.manjuu.promilia/files/libhybridclr_dumper.so` 副本，
其标签是 `app_data_file`；已有日志显示这个路径获准 execute，随后才遇到原因二。
初始对照验证阶段仅核对它与原文件内容一致，没有修改该 App 的文件或启动该 App。
两者 SHA-256 均为：

```text
a2e0bfe8336b883e4ada471c9565a47ecfef35a951304653f5d9827518a0fe94
```

修复增加了 PT_LOAD 段号、prot、原始错误码和权限提示。对拒绝的路径现在返回：

```text
manual: PT_LOAD[1] mmap prot=5 rc=-13; check target file access/SELinux execute permission
```

## 原因二：find_vma 缺失使直接 VMA 回退失效

这台内核的 kallsyms 中没有独立 `find_vma`，但存在 `find_vma_prev`、`down_read`、
`up_read`。BTF 验证的 `vm_start=0`、`vm_end=8`、`mm.mmap_lock=104` 均可用。
旧代码却把 `find_vma != NULL` 作为直接遍历的必要条件，因而显示
`vma_backend=proc_maps`。

准备 worker 与目标不是同一个线程组。目标设置 `PR_SET_DUMPABLE=0` 后，worker
对 `/proc/<tgid>/maps` 的访问会受到 procfs/ptrace 权限检查；本设备表现为 `-ENOENT`。
旧框架无法退回已验证的直接遍历，于是报 `mapping permission snapshot failed rc=-2`。
这不代表 payload 路径不存在，也不是目标必然已经退出。

修复优先保留 `find_vma`，缺失时精确解析 `find_vma_prev`，使用正确的三个参数，
为 `prev` 提供实际可写的指针。两个 accessor 均要求既有 BTF 布局验证及成对 mmap 读锁，
不猜测红黑树/Maple Tree 布局，也不扫描未知符号后缀。
`find_vma_prev` 与 `find_vma` 的返回范围语义相同，额外写入前一个 VMA；可核对
[Linux 5.15 实现](https://github.com/torvalds/linux/blob/v5.15/mm/mmap.c#L2166-L2184)。

修复版 probe：

```text
vma_backend=locked mm_access=offset vma_meta=1 dpath=1 vma_find=find_vma_prev
```

## 对照验证

下表的注入均针对本仓库 `com.kclf.apptest` 或独立 native 测试进程。
SO 保持驻留，不对带后台线程的 payload 使用 `unload`；测试结束后停止测试进程并 reap。

| 条件 | 旧版 | 修复版 |
| --- | --- | --- |
| App，原 `/data/local/tmp` 路径 | ELF mapping rc=-13 | 同样拒绝，增加明确权限诊断 |
| App，可执行的 native library 路径，dumpable | done | done |
| App，同一路径，`PR_SET_DUMPABLE=0` | snapshot rc=-2，进程仍活着 | 连续 3 个新进程 done，均存活 |
| shell native host，原 `/data/local/tmp` 路径 | dumpable/non-dumpable 均 done | 原路径失败与目标访问策略相关 |

修复版的四次 App 加载均看到 HybridCLRDump 的后台启动日志，以及测试 App 没有
`hybridclr_dump.conf`、未开始 dump 的消息。因此验证覆盖 SO 映射、重定位、构造函数、
后台线程启动和框架清理；未验证目标游戏中的 HybridCLR 数据导出功能。

主机 16 suites（ASan/UBSan）通过；新增 accessor 选择与符号回归随后单独通过。
包括 procfs ENOENT/EACCES、地址空洞、EOF、路径/权限保留、锁平衡、缺锁/无 BTF 时拒绝
直接遍历，并使用该设备实际 BTF 验证兼容性分支。严格告警 KPM 构建通过。

设备完整 App 回归使用 `-NonDumpable -Repeat 3`，结果及原始证据见
`build/hybridclr-fix/`，manual 回归 189 项、linker 回归 174 项断言通过。
两个 suite 均确认 boot ID 和 SELinux 模式不变，无该 suite 新增的测试 App 致命信号、
Java 崩溃或保留的内核 BUG/WARNING/Oops/panic 日志。
测试工具新增 `-NonDumpable` 和可选控制端 `-RootContext`；用法见 [USAGE](USAGE.md)。

本地修复产物 `kclf.kpm` SHA-256：

```text
f71f757eb76f669083e2d9bc79d1631800fa2f71152fac02a5aaed80a510148a
```

关键证据：`baseline-dmesg.txt`、`symbols.txt`、`baseline-app.txt`、`fixed-app.txt`、
`fixed-probe.txt`、`payload-logcat.txt`、`host-tests.log`、`device-btf-test.log`、
`app-regression-manual.log`、`app-regression-linker.log`。
原始日志和 payload 保留在忽略的 build 目录，密钥不写入文件。

小米设备的修复版位于 `/data/local/tmp/kclf-fixed.kpm`，初始回归结束时已加载，`quiescing=0`、
请求表及镜像表为空，测试 App 已停止。原 `/sdcard/kclf.kpm` 保留为旧版，后续加载请
选择修复版路径。使用原目标时，可继续使用上文已获 execute 权限的私有目录副本；
该 SO 创建后台线程并被识别为 `nodelete=emutls`，不要给请求加 `unload`。

## Pixel 6：目标游戏中的框架验证

2026-11-27，更换为 Pixel 6（oriole），Android 16，Linux 6.1.134，ARM64，
4 KiB 页，SELinux Enforcing。目标 `com.manjuu.promilia` 版本 1.0.1，
targetSdk 33。加载上述相同 SHA-256 的修复产物，设备路径为
`/data/local/tmp/kclf-pixel-dump-20261127/kclf.kpm`。

此内核具有 `find_vma`，probe 为 `vma_backend=locked vma_find=find_vma`，
`installed=70/70`、`quiescing=0`。因此本设备验证原 accessor 分支；
`find_vma_prev` 回退分支由前述小米设备及主机测试覆盖。

### 同一原始 SO 的路径对照

在游戏完成启动后的同一个 PID 27242 中，使用设备原有的
`/data/local/tmp/libhybridclr_dumper.so`，未修改 SO 内容。其私有目录副本与原文件
SHA-256 均为 `a2e0bfe8336b883e4ada471c9565a47ecfef35a951304653f5d9827518a0fe94`。

| 路径 | 标签 | 实测结果 |
| --- | --- | --- |
| `/data/local/tmp/libhybridclr_dumper.so` | `shell_data_file` | 请求 3：prepare 阶段 PT_LOAD[1] RX 映射返回 -13；有对应 SELinux execute denied 日志 |
| `/data/data/com.manjuu.promilia/files/libhybridclr_dumper.so` | `app_data_file`，目标 UID，0600 | 请求 4：`state=done stage=restore via=manual`；SO 后台启动日志出现，目标进程继续存活 |

成功请求的 `stack=transient/0`、`loading=0`，没有 `pending=` 或 `map=`，
镜像登记为 `state=live refs=1 nodelete=emutls`。原 SO 随后报告配置项
`discovery_mode` 不受支持并返回 -1；这发生在 SO 自身后台线程内，注入已经完成。
结束时 PID 27242 仍存活，该 PID 的 crash 日志为空，启动稳定后的注入时段内
保留的 dmesg 没有 BUG/WARNING/Oops/panic/call-trace 记录，boot ID 未变。

### 已区分的 payload 行为

此前还用现有 dumper 源码构建的 auto 版本进行过验证，未修改该模块源码。
冷启动过早注入时，请求已 done，随后其后台线程在调用 `il2cpp_domain_get`
期间崩溃，tombstone 的调用点对应 `src/dumper.cpp:908`。
重新启动并等待运行时初始化后，同一 auto 版本请求 2 done，构造函数、后台线程、
运行时查询及 manifest 写入均执行完成，游戏保持存活。
该次 dump 返回 `result=1, complete=false`：发现的原始数据前缀为 `CDPH`，
未通过 dumper 的 PE/PDB 格式验证，没有导出 DLL。

按用户后续限定，本次在框架验证结束后停止 payload 诊断/修复。
结论是修复版 KCLF 在此设备及目标进程的已测注入链路正常；
`/data/local/tmp` 的执行权限拒绝仍然存在，且不代表框架兼容性修复失败。
这不等同于确认 dumper 的导出功能成功，也不保证所有设备都允许从 App files 目录执行。

测试后已从备份恢复 `hybridclr_dump.conf` 的原始内容、所有者和 Unix 权限，
恢复内容 SHA-256 为 `71501d2e94cf691eaee251f2d79f205d99fdd4d54362764bce48e2bf0499c7a2`。
KPM 和两个成功加载的镜像继续驻留，未对运行中的 payload 执行 release/unload。

证据保存在忽略的 `build/promilia-pixel-20261127/`：
`tmp-path-status.txt`、`tmp-path-dmesg.txt`、`same-payload-hashes.txt`、
`same-payload-status.txt`、`same-payload-logcat.txt`、`same-payload-images.txt`、
`final-status.txt`、`final-pid.txt`、`final-target-crash-log.txt`、
`final-kernel-check.txt`、`final-artifact-state.txt`、`config-restored.txt`。
