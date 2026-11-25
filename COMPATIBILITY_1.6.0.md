# KCLF 1.6.0：payload 本地 ELF TLS 审计与验证

审计及设备测试：2026-11-24–25（Asia/Shanghai）。基线为 main `eb30b39` / v1.5.7，
此次将工作区未提交的 TLS 实现修复、测试后纳入 main，发布版本为 v1.6.0。

## 结论

在明确支持的 ARM64 / bionic / payload 本地 TLSDESC 范围内，修复后的实现通过本轮
主机与连接设备回归，可以发布。**不能将此解释为全部 Android、5.x/6.x 内核或
16K/64K 页设备的兼容认证。** 本轮只有 Pixel 6 / Android 16 / Linux 6.1.134 / 4K
真机；其他内核标签与页大小只做了主机模拟和代码审计。

执行链为 superkey 控制 → 目标线程 prepare task_work → ELF 快照/映射/重定位 →
TLS 运行时准备 → EL0 IFUNC、key 创建、构造函数 → 寄存器恢复/token → RELRO 和登记。
TLS 地址解析不再次进入 KPM；一个镜像拥有一个 pthread key，每线程按需匿名映射，
线程退出由 key 析构函数 munmap。镜像、key 和析构代码必须驻留到目标 mm 退出。

## 本轮发现与修复

1. **TLS 指针初值错误。** 原实现从原始文件快照复制 PT_TLS，遗漏 .tdata 中的
   RELATIVE/其他普通重定位。现在从完成重定位的映射复制，并校验 PT_TLS 初始字节与
   可读 PT_LOAD 的文件偏移/虚拟地址对应关系。新增含 `int *` 初值的真实 TLSDESC
   payload，在构造线程和八个新线程中验证地址与内容。模板中的延迟 IFUNC 明确拒绝，
   防止在模板快照之后再修改原映射造成不同线程得到旧值。
2. **线程分配上限不完整。** 之前只分别限制 memsz/align，现在限制
   `memsz + max(align,1) + 16 <= 256 MiB`，包括头部和对齐余量。
   .tbss 不必存在于 PT_LOAD 文件字节中；仅初始化模板需要匹配可读 PT_LOAD。
3. **提供库权限检查低效且不完整。** 原实现每个可执行段都重新打开/扫描 maps，
   仅检查段首地址，并在读取出错时接受候选。现在一次缓存最多 16,384 个区间，
   二分查找后验证整个段的连续可执行覆盖；读错、超限、分配失败终止准备。
   缓存最多约 384 KiB。procfs 不可打开而使用原有 direct walker 时，权限仍为未知；
   保留这个兼容回退，但不声称它能排除所有不可执行候选。
4. **模板复制开销。** EL0 首次访问按 16 字节复制，余数按字节复制，保留全寄存器
   保存/恢复和屏蔽信号后再次查询 key 的逻辑。
5. **回归脚本误报。** PowerShell 忽略大小写的 `BUG:` 匹配误命中系统的
   `binder_debug:` 行。加入单词边界后重跑，真实内核故障关键字仍被检测。

原实现的 NODELETE、创建 key 先于构造函数、失败时不执行构造、模板/参数 RELRO、
TLSDESC 16 字节写入边界和两个映射的所有权保留经过复核。key 分配失败、复制失败、
mprotect 失败、munmap 重试和 registry lock 重试都不会提前丢失待回收映射。
进入用户代码后结果不可信的镜像保持 abandoned，等待进程退出。

## 效率与支持边界

- 热路径调用一次 pthread_getspecific，没有系统调用、内存分配或全局锁；为遵守
  TLSDESC 调用约定，每次仍保存 GPR、完整 FPSIMD、FPCR/FPSR/NZCV，栈帧为 800 字节。
  Pixel 6 单线程一百万次调用样本约 **20.6–42.1 ns/次**，包含测试调用开销，受调频和
  系统负载影响。没有与 bionic 静态 TLS 做同条件对照，不能声称与原生静态 TLS 等速。
- 首次访问包含 rt_sigprocmask、mmap、模板复制和 pthread_setspecific；每个线程/镜像
  一块映射，资源消耗随接触该镜像的线程数增长。key 资源耗尽时加载返回错误；
  地址解析期间分配、设置 key 或信号掩码失败不能通过 TLSDESC 返回 errno，因而 abort。
- 只支持 payload 内定义的 TLS 及 TLSDESC。外部 TLS、TLS_DTPMOD/DTPREL/TPREL、
  IE/LE、`__cxa_thread_atexit*` 不支持；不注册 bionic TLS 模块、soinfo 或 unwind 信息。
- SVE/SME 调用者、绕过 bionic 的 raw-clone 线程、其他 pthread-key 析构函数在退出时
  再访问 payload TLS，不在支持范围。析构顺序可能导致 TLS 被释放后重建；受 pthread
  析构迭代次数限制，这类重建块可能驻留到进程退出。
- 首次 `unload` 和显式 `release` 拒绝；复用已有镜像不再次创建 key，也不重跑构造。
  先结束目标进程，再 reap、确认 quiesce=idle，最后卸载 KPM。
- maps 快照不能防止依赖并发 dlclose；调用方须保持依赖驻留。原有 x16 恢复限制、
  任意线程借用可能重入应用锁、SELinux/seccomp 限制和强制卸载风险仍存在。

## 内核兼容性

| 项目 | 本轮证据与边界 |
| --- | --- |
| KPM 导入 | 与 v1.5.7 `nm -u` 完全相同，无新直接导入 |
| 内核布局 | TLS 未增加 task/mm/VMA 偏移或版本猜测；权限来自 procfs |
| 通知、取消、BTF | 5.0–6.18 标签的模拟选择、缺失/歧义符号、BTF backport 和引用平衡通过 |
| 真机 BTF | 当前设备重新导出的 vmlinux BTF 解析通过；SHA-256 `ef6ffa2e5d2f10ad1438a89a77d42747e80c7b78367c1d191140c5e623ff4970` |
| 无 BTF/nofault | 独立构建真机验证 proc_maps、get_task_mm、GUP/poll；仍是同一 6.1 内核 |
| 页大小 | 主机验证 4K/16K/64K 生成器及 TLS 元数据；真机只有 4K |
| 用户 ABI | 使用 AArch64 Linux 的 mmap/munmap/rt_sigprocmask 和 bionic 公共 pthread API，不读取私有 DTV/soinfo 偏移 |
| 复制汇编 | `kclf_tls.o` 没有重定位项，位置无关代码可整体复制到 EL0 |

## 测试结果

`make test`：**14 组通过**。主机 C 夹具使用 ASan/UBSan，UBSan 报错即失败。
历史 12 组主机夹具从 dev 纳入 main 并更新接口；ELF 输入在运行时由交叉 GCC 从源码
生成，无需跟踪测试二进制。新增 TLS ELF 和生产 prepare/finish 故障注入测试。
另运行 `test/test_compat.py` 解析本轮从设备导出的 BTF。

| 真机运行 | 断言 | 本地证据目录（独立仓库内） |
| --- | ---: | --- |
| 正式 KPM，TLS 原生进程 + 普通 App，分别三轮 | 93 | `build/kclf-tls-260eee679fc9/` |
| 正式 KPM，普通 App manual，Repeat=10 | 236 | `build/kclf-app-1f9e92a77eb2/` |
| 正式 KPM，普通 App linker，Repeat=10 | 219 | `build/kclf-app-9295d4848c06/` |
| 无 BTF/nofault，TLS 原生进程 + 普通 App，分别三轮 | 106 | `build/kclf-tls-1e2cbcaa2964/` |
| 无 BTF/nofault，普通 App manual，Repeat=10 | 255 | `build/kclf-app-e8a192a241df/` |

正式 KPM 合计 **548** 项，回退构建合计 **361** 项。两种产物分别使用相同 TLS 模块
测试模板/BSS、64K 对齐、指针初值、线程隔离、引用复用、NODELETE、key 耗尽回滚。
普通 App 回归包括 FPSIMD、引用/释放、延时构造、取消、退出、reload 和映射回收。
全部成功运行最终均完成 quiesce/unload，boot ID 与 SELinux Enforcing 不变，无新增
保留在 dmesg 中的 BUG/WARNING/Oops/panic；普通 App 无新增致命信号/Java 崩溃。

独立 `tls-runtime` 还验证八个预存线程与八个新线程、32 次线程退出回收、全部寄存器、
信号重入、key 创建失败和 setspecific 失败。随后增加 seccomp 拒绝 mmap 和
rt_sigprocmask 的故障注入并再次通过；这些用例有意让隔离子进程 SIGABRT，不能把其
崩溃日志视为普通 App 故障。结果保存在 `build/audit-1.6.0/runtime-final.log`。

测试过程遇到旧测试 APK 签名不同，保留旧 APK 后重装自有测试 App。首次普通 App 回归
因上述 binder_debug 匹配误报失败，修正脚本后完整重跑。TLS 自动化开发时出现的状态
字段解析错误也已修复并重跑；表格仅统计最终成功运行。未测试任何第三方 App。

## 可重复构建与发布

- KernelPatch 头文件：`406c85ce79a5e1c19b53be34c04baadc1ec68bc5` 的未修改快照；
  不依赖父工作区的未提交改动。
- WSL Ubuntu 24.04，AArch64 GCC 13.3.0、GNU binutils 2.42。
- `make -B KP_DIR=<clean-KernelPatch> TARGET_COMPILE=aarch64-linux-gnu- -j4`，
  既有 `-Werror`、2048 字节内核栈帧告警、general-regs-only、fixed-x18 保持启用。
- 正式 `kclf.kpm`：151312 字节，ELF64 little-endian AArch64 ET_REL。
- 从独立目录再次编译，产物逐字节一致；汇编对象没有待修正的重定位项。
- SHA-256：`b2b8e8e451425552ddf6e6c9fdc8a03222d466211ddeb3289ffbcd5d66e233b7`。
- 仅测试的无 BTF/nofault 产物 SHA-256：
  `013d44bf949076160cdf5a53b94741c211ad5f2036f1f56acf109386dff0b300`，不上传到 Release。
- Android 测试夹具：NDK 27.0.12077973，TLS payload 使用 `-fno-emulated-tls`。
  构建/运行步骤见 [TLS 回归说明](test/tls/README.md)。

Releases 发布正式 `kclf.kpm` 与 SHA256SUMS，源码由 v1.6.0 tag 标识。原始设备日志、
凭据、调试签名和本地构建目录均不进入提交或 Release。

## 规范核对

TLSDESC 的返回值和寄存器约定参考
[AOSP ARM64 TLS resolver](https://android.googlesource.com/platform/bionic/+/4f3b7e1f97b8e298a29e85e5987c30621cac0f12/linker/arch/arm64/tlsdesc_resolver.S)。
pthread key 的创建/查询/线程退出迭代行为参考
[AOSP pthread_key.cpp](https://android.googlesource.com/platform/bionic/+/refs/heads/main/libc/bionic/pthread_key.cpp)。
KCLF 使用自己的 key 与模板，不参与
[bionic TLS 模块注册](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/linker_tls.cpp)；
因此以上 ABI 子集的验证不等于完整动态链接器兼容性。
