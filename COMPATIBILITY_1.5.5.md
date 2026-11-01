# KCLF 1.5.5 实现与兼容性审计（2026-11-01）

## 结论

审计和修正后，未发现本次修改新增跨内核 ABI、符号、私有布局或页大小依赖，
可以同步到 main 并发布。此结论是相对 1.5.4 的回归审查，**不是所有 5.x/6.x
内核的设备认证**。最终发布构建已在 Android 13 / ARM64 / 5.15.74 / 4K 页设备
完成原生进程及普通 App 回归；其他内核与 16K/64K 页设备未在本轮真机验证。

审计前工作区存在两项通用正确性回退，均已修正，详见下文。原工作区的
`e9af06bad92c95cacdbd2dba103de334b5fe4116df7f7946077df08890463887`
不是最终发布文件；dev 中的第三方 App 历史记录不能作为最终构建的验收结果。

## 框架实现

1. `kclf.c` 提供控制命令、4 个请求槽、状态机、task_work 排队和完成观察。
   `inject` 以 TID 定位目标，准备回调运行在目标线程的可睡眠上下文。
2. `kclf_compat.c` 通过 BTF、内核 accessor、受约束的回退机制解析 task/mm/VMA
   及 task_work ABI；缺少关键符号或无法确认 ABI 时拒绝相关操作。
3. `kclf_exec.c` 检查目标、读取映射并准备临时 EL0 程序，在返回用户态的边界修改
   `pt_regs`。默认 manual 后端进入 `kclf_manual_prepare`；linker 后端显式选择。
4. `kclf_elf.c` 是受边界约束的 ELF64/AArch64 解析、符号和重定位实现。
   `kclf_manual.c` 负责文件快照、依赖提供库收集、来源选择、映射、重定位和驻留引用。
   依赖必须已驻留；它不重建 bionic 的完整 namespace 状态。
5. `kclf_codegen.c` 生成目标 EL0 执行程序，完成 IFUNC/构造/析构等步骤并恢复现场。
   完成 token 由已有 syscall hook 或可睡眠 poll 观察，再由 cleanup task_work
   应用延迟 RELRO、回收临时映射。manual 驻留库通过 `release` 管理最后一次卸载。

## 本次生产源码变化

相对开始审计时的 main `6d53c294b552f6ac8ab5c5730a3e8149f545f535`，
生产源码仅修改四个文件：

| 文件 | 修改 | 兼容性判断 |
| --- | --- | --- |
| `kclf_manual.c` | 固定 512 项表改为初始 64、倍增、最多 4096 项的临时表；统一释放 | 复用已有必需 `vmalloc/vfree`，未新增内核 API |
| `kclf_elf.c` | 文件/payload 严格校验；VMA 候选仅接受一种明确的头覆写签名例外 | 纯 ELF 数据解析，不依赖内核结构 |
| `kclf_elf.h` | 明确上述输入契约 | 未改变 `ke_object` 布局或公共函数签名 |
| `kclf_internal.h` | 版本号 1.5.4 → 1.5.5 | 其他 ABI 定义不变 |

`kclf.c`、`kclf_compat.c`、`kclf_exec.c`、`kclf_codegen.c/.h`、
`kclf_btf.h`、`kclf_maps.h`、`kclf_param.h` 均与上述 main 相同。
没有改变 TIF 位号、task_work 通知/取消 ABI、GUP、mmap/procfs 迭代器、
内核版本分支或 EL0 指令生成方式。新旧 KPM 的未定义导入符号集合相同，
且无 `__aarch64_*` outline atomic libcall。

### 审计修正一：不完整提供库表必须失败

原工作区在分配失败或容量用尽时停止记录后续提供库，却继续按已有前缀选择依赖。
这可能漏掉更优先的同名库，或把本应报歧义的两个来源变为唯一来源，进而绑定错误符号。
单纯检查“需要的 SONAME 是否已经在表中”不能证明选择正确。

最终实现中，首次/增长分配失败返回 `-ENOMEM`，超过 4096 返回 `-ENOSPC`；
`collect` 将错误传给 VMA walker，prepare 在 `add_needed` 前进入统一清理。
`provider_reserve` 不再对 `need > 4096` 返回容量不足的成功结果。扩容失败保留原表，
成功时先复制已有项再释放旧表，prepare 所有退出路径释放最终表。

扩容只在提供库收集阶段发生，依赖闭包和符号解析在收集完成后进行，不持有跨扩容指针。
分配时不持有 image registry 锁或 mmap 锁，仍在原本允许睡眠的 task_work 路径。
倍增时新旧表会短暂并存；最大表占用约 18 MiB，每请求独立，内存不足会明确失败。
这增加了大进程的临时内存上限，不构成新增内核版本要求。

### 审计修正二：不能对所有 VMA 放宽架构检查

扫描 VMA 的 ELF 魔数不能证明该对象已被 bionic 接受。原工作区在 loaded 模式下
无条件忽略 `e_type/e_machine/e_version`，因此连完整的 x86_64 ELF 都可能成为候选库。

最终默认仍要求 `ET_DYN / EM_AARCH64 / version=1`。仅当 loaded 模式且
`e_ident[8..15]` 精确为 `50 00 00 58 00 02 1f d6`（AArch64
`ldr x16,#8; br x16`）时，允许后续地址覆盖这些字段。payload/file 始终严格。
ELF64/小端标识、程序头尺寸/数量/偏移、段边界、动态表、哈希和字符串表校验均保留。
该签名是限定的格式兼容规则，不能证明 linker 来源；未知头改写仍会拒绝。

## 验证结果

### 构建

- 主机：WSL Ubuntu 24.04，AArch64 GCC 13.3.0 / GNU Binutils 2.42，Python 3.12.3。
- KernelPatch 头文件基线：`406c85ce79a5e1c19b53be34c04baadc1ec68bc5`。
- 命令：`make -B TARGET_COMPILE=aarch64-linux-gnu- -j4`。
- 保留 `-Werror`、`-Wframe-larger-than=2048`、`-mgeneral-regs-only`、
  `-ffixed-x18` 和 `-mno-outline-atomics`，完整构建无警告。
- 产物为 ELF64 little-endian AArch64 ET_REL，137448 字节。
- 最终 `kclf.kpm` SHA-256：
  `ee17d3d982f2b54ac052c410b171a045fddd9654f3a7532480ab678a5e1918bf`。

### 主机

dev 的 `make test`：**11 组全部通过**，C 夹具使用 ASan/UBSan。
新增测试直接提取生产 `provider_reserve/collect`，覆盖扩容数据保持、首次/增长失败、
超过上限、重复 VMA，以及后续较优同名来源无法收录时必须失败的场景。
生产 ELF 解析测试覆盖错误架构/类型/版本、任意坏头、签名逐字节损坏和结构/表越界。
另完成 20,000 个确定性 ELF 变异输入检查，无 ASan/UBSan 异常。
兼容测试模拟了 5.0–6.18 的版本与 BTF ABI 组合；模拟测试不等于相应设备实测。

### 设备

设备：小米 13 / 2211133C / fuxi，Android 13，
`5.15.74-android13-8-00049-g8945ccdb2203-ab9500309`，ARM64，4096 字节页。

| 测试 | 结果 | 本地证据目录（KernelPatch 根目录下） |
| --- | --- | --- |
| 最终发布 KPM，原生进程完整 manual 回归，含显式 linker | 148 项断言通过，结果 PASS | `build/kclf-manual-50a88fffa96b/` |
| 最终发布 KPM，自带普通 App，manual 完整回归，连续 10 次加载/释放 | 236 项断言通过，结果 PASS | `build/kclf-app-9aa18a65cbb8/` |
| 同源测试构建，禁用 BTF 与 nofault，原生 smoke，强制确认 poll 完成 | 34 项断言通过，结果 PASS | `build/kclf-manual-76d3f4e6bd4a/` |

普通 App 回归包含主线程、自然恢复 sleeper、Binder、FPSIMD 状态恢复、取消/满槽、
坏文件、驻留引用、目标退出、RELRO/临时映射与安全卸载。三次设备测试均未发现新的
留存内核 BUG/WARNING/Oops/panic，普通 App 无新增 fatal signal/Java crash；
boot ID 和 SELinux enforcing 状态未改变。测试构建已排空并卸载。
最终发布 KPM 的设备证据与上列 SHA-256 对应；回退构建是独立文件，不作为发布附件。

本轮只操作自带测试进程与测试 App。历史第三方 App 结果保留在 dev，未在最终构建上重测。
日志只保存在本地 build 目录，superkey 未写入源码、报告或 release。

## 仍然适用的边界

- 框架已有的 Linux 5.x/6.x 范围、运行时符号/BTF/ABI 检查与拒绝条件继续适用。
  厂商回移、隐藏符号、宿主 KernelPatch 支持范围会影响实际可用性。
- 缺少 BTF/nofault 的设备路径在同一台 5.15 设备上验证，不等于其他内核认证。
- 16K/64K 只完成主机 codegen 测试，未完成相应页大小设备的加载认证。
- 依赖必须保持驻留；来源选择是显式近似模型。完整候选表也不等于重建 bionic namespace。
- 未新增权限绕过、未知 ELF 特性支持或生命周期保证；payload 创建的异步工作仍需自行结束。

内存 API 的接口与上下文依据可参考官方
[Linux 5.10 文档](https://docs.kernel.org/5.10/core-api/mm-api.html#virtually-contiguous-mappings)
和 [Linux 6.1 文档](https://docs.kernel.org/6.1/core-api/mm-api.html#virtually-contiguous-mappings)。
它们支持本次使用既有 vmalloc/vfree 契约的判断，不替代厂商内核实测。
