# /data/local/tmp SO 自动加载

## 用法

默认 `manual` 后端接受原始 tmp 路径，无需复制到 App 目录：

```sh
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf "inject,<TID>,/data/local/tmp/libhybridclr_dumper.so,wake"
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf probe
adb shell /data/local/tmp/kpatch "$KEY" kpm ctl0 kclf images
```

`probe` 中 `tmp_load=shmem (manual)` 表示自动后备文件可用；成功后的镜像显示
`backing=shmem`，`path=` 仍记录提交的源路径。显式 `linker` 后端保持原有 bionic
路径及 namespace 语义，不使用此机制。

## 实现和生命周期

准备阶段仍用目标凭据读取 SO。对于 `/data/local/tmp/` 前缀下的文件，完整读取不超过
64 MiB 的快照后，通过普通 `shmem_file_setup` 创建内存文件，用 `kernel_write`
分块复制，检查短写、错误和文件位置推进，再按原有 ELF 校验、映射和重定位流程加载。
不改变源文件、Unix 权限、SELinux 标签或设备策略，不在目标安装 fd。
tmpfs 文件的建立与执行映射仍接受目标凭据下的权限检查。

PT_LOAD、TLS runtime 和每次请求的跳板共享这个后备文件。镜像表持有一个文件引用，
VMAs 持有各自的引用；重复加载和 release 直接借用已有文件，不重新打开源路径。
因此已驻留镜像在源文件删除后仍能增加引用、运行析构和释放。
最后一次 release、准备失败、目标退出/reap 以及 KPM shutdown 都有对应释放路径，
`fput` 在镜像表锁外执行；忙碌或仍存活的镜像不被 reap。

所有代码映射保持 RX，写入使用既有私有 COW 路径，未引入 RWX。
`/proc/<pid>/maps` 中名称为 `/kclf:<文件名> (deleted)`，带非零 inode；
`deleted` 表示该内存文件没有目录项，不表示文件引用失效。
原有普通路径继续使用源文件后备映射。

源文件仍须对目标可读，目录须可遍历；依赖预加载、ELF/TLS、NODELETE 等限制不变。
若设备策略拒绝 tmpfs 执行，框架会保留错误并回滚，不保证所有 Android 策略都接受该路径。

## 多内核适配

只使用精确名称的可选 `shmem_file_setup`、`kernel_write` 和既有 `fput`/`vm_mmap`，
不访问 inode、file 引用计数或文件表的版本相关偏移，也不使用 `S_PRIVATE` 后备文件。

| 条件 | 行为 |
| --- | --- |
| Linux 5.x–6.16，所需符号齐全，BTF 未提供相关原型 | 使用已核对的三参数 shmem 和指针位置参数 write ABI |
| BTF 同时验证两个原型 | 可启用，包括更高的 6.x 版本标签 |
| BTF 发现参数数量、标量宽度、指针或 flags 类型不匹配 | 禁用此可选路径，避免错误调用 |
| 6.17+ 缺少完整的匹配 BTF 原型，或任一所需符号缺失 | 显示 `tmp_load=unavailable`，保留普通文件加载能力 |

普通加载回退仍可能遇到原来的 tmp 文件执行拒绝（-13），不能把 unavailable 当作
tmp 自动加载成功。整体框架仍只面向已有的 ARM64 Linux 5.x/6.x ABI 家族。

上游依据：
[Linux 5.0 shmem](https://github.com/torvalds/linux/blob/v5.0/mm/shmem.c)、
[Linux 6.16 shmem](https://github.com/torvalds/linux/blob/v6.16/mm/shmem.c)、
[Linux 5.0 kernel_write](https://github.com/torvalds/linux/blob/v5.0/fs/read_write.c)、
[Linux 6.16 kernel_write](https://github.com/torvalds/linux/blob/v6.16/fs/read_write.c)。
此外已核对 5.4、5.10、5.15、6.1、6.6、6.12 的相同接口；BTF 校验优先于版本号判断。

## 验证记录（2026-11-27）

生产构建通过严格告警；17 个主机 suite（ASan/UBSan）通过。
新增测试覆盖短写/写失败、映射拒绝、引用所有权、reap/shutdown、缺少符号、BTF
不兼容原型、5.x–6.18 版本选择以及 4K/16K/64K 页长。
使用此前保存的小米 5.15.74 BTF 和当前 Pixel 6.1.134 BTF 验证了真实接口原型。
这些是主机/ABI 检查，不能替代其他内核与页大小的真机认证。

当前真机为 Pixel 6，Android 16 / Linux 6.1.134 / 4 KiB，SELinux Enforcing：

| 回归 | 结果 |
| --- | --- |
| manual + tmp 路径 + non-dumpable，重复 3 次 | 201 项断言通过 |
| 禁用 BTF 的单独构建，manual + tmp 路径，重复 1 次 | 177 项断言通过；procfs/accessor/版本基线回退 |
| 原 linker 后端 + non-dumpable，重复 1 次 | 152 项断言通过 |

测试覆盖构造/析构、FP/SIMD、取消、并发排队、无效文件、忙碌卸载保护、进程退出、
源文件删除后的重复引用、最终 release、无 RWX 和映射回收。上述最终回归均保持 boot ID
及 SELinux 模式不变，没有新增保留的内核警告或测试 App 崩溃。

中间回归曾在收尾遇到 `dec_rlimit_ucounts` 警告，未计为完整通过。
时间线显示 KCLF 在 8936.600666 秒成功卸载，警告发生于 8936.801494 秒，
位于提权 shell 的 `wait4 -> release_task` 路径；没有 KCLF 调用帧。
该日志原样保留，未修改宿主 KernelPatch 的提权实现，不能据后续通过声称整机从未出现警告。

目标游戏 `com.manjuu.promilia` 的原始 SO 实测：

```text
path=/data/local/tmp/libhybridclr_dumper.so
state=done stage=restore done=syscall stack=transient/0 via=manual
loading=0
image=1 state=live refs=1 nodelete=emutls backing=shmem
```

最终构建在 PID 1130 注入后持续存活，SO 输出后台启动日志；源文件仍为 shell 所有、0666、
`shell_data_file`，SHA-256 保持
`a2e0bfe8336b883e4ada471c9565a47ecfef35a951304653f5d9827518a0fe94`。
该 SO 自身随后拒绝配置项 `discovery_mode`，未验证 dump 成功；按用户要求未修改 dumper。
它被识别为 `nodelete=emutls`，本次保留驻留，未强制 release/unload。

生产 KPM SHA-256：

```text
4c57296bc0e6f336cfffb7ccbd787d739cfeeb27cbeb348c71bc3a20296c7cba
```

设备已加载 `/data/local/tmp/kclf-tmp-auto-20261127/kclf.kpm`。
原始证据位于忽略的 `build/tmp-auto-20261127/`：`host-tests.log`、
`file-backing-final.log`、`pixel-btf.log`、`fuxi-btf.log`、`app-regression-final.log`、`app-no-btf.log`、
`app-linker.log`、`game-probe.txt`、`game-request.txt`、`game-status.txt`、
`game-images.txt`、`game-logcat.txt`、`game-mappings.txt`、`game-source-after.txt`。
