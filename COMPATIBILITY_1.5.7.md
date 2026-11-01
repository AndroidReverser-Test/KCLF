# KCLF 1.5.7：manual 长符号名与 emutls 驻留修复（2026-11-01）

> 前文保留开发阶段的实现分析和设备记录。本文末尾“发布前独立复核”是本次
> 提交、合并和发布前重新执行的审计/回归；不把既有第三方 App 记录当成本轮重测。

## 修改原因

对 `/data/local/tmp/libtest.so` 注入 `cn.gov.tax.its` 的 manual 后端在 prepare 阶段
连续暴露了两个独立阻塞点：

1. **1.5.6：合法长符号名被固定 256 字节缓冲区拒绝。**
   一条 `R_AARCH64_JUMP_SLOT` 引用 payload 内部定义的 285 字节 C++ 模板符号；
   `resolve_import()` 在判断 `st_shndx` 之前无条件把完整名称复制进 `char[KE_NAME]`，
   于是先报 `ELF symbol/SONAME/version name exceeds 255 bytes`，永远不会走到
   “payload 已定义，地址 = bias + st_value”的分支。
2. **长名称修复后的中间构建：payload 自带的 compiler-rt emutls 被当成 loader 集成 TLS 拒绝。**
   长名称修复后，同一 payload 在 prepare 阶段报
   `loader-integrated TLS destructor/cross-DSO CFI unsupported: __emutls_get_address`。
   该 payload 实际定义了 `__emutls_get_address`（WEAK FUNC）和本地
   `__emutls_v.*` 控制对象；它使用 compiler-rt 的 pthread-key 实现，不是 ELF
   `PT_TLS`，也不依赖 bionic 的 dlclose 回调。

两者都是加载器兼容性问题，与目标 App 的加固、SELinux、seccomp、线程选择或 payload
构造失败无关。

## 长符号名支持

`kclf_elf.c` 不再用 `KE_NAME` 承载符号名：

- `ke_string_size()` 从 `st_name` 开始，以 `DT_STRSZ - st_name` 为硬边界，
  按 64 字节对齐块读取并由 `DT_STRSZ`、可读 `PT_LOAD` 和 `io->limit` 三重限界；
  只接受在字符串表内出现的 NUL，截断、越界、读取失败和无 NUL 都返回负 errno。
- `ke_string_copy()` 仅在调用方容量足够时复制完整名称；`ke_string_equal()`
  逐字节比较预期的完整名称，不分配临时缓冲区，也不把截断前缀当作匹配。
- `candidate()` 改用 `ke_string_equal()`，因此 **提供库中的长符号名** 也按完整
  名称参与 SysV/GNU hash 与版本匹配，而不是截断到 255 字节。
- `kclf_manual.c` 的 `read_symbol_name()` 先用 `ke_string_size()` 得到精确长度，
  再由 `km_context` 持有的 `vmalloc` 缓冲区按需倍增并复用；名称不在内核栈上，
  也不为每个符号单独分配。名称长度上限为 64 MiB（与文件快照上限一致），
  总扫描量由 `KM_STRING_BUDGET`（256 MiB）约束。
- `resolve_import()` 现在先读取符号元数据并保留原 errno，再按 `st_shndx`
  选择“payload 内定义”或“提供库导入”；已定义符号不需要把名称装入固定数组。
  `ke_symbol()`、名称读取和重定位步骤各自返回原始错误，不再一律折叠为
  `-ENOEXEC`。
- 已定义符号的 SHN_ABS、保留 section index、地址溢出、PT_LOAD 边界和可执行权限
  检查保持不变；GNU_UNIQUE、TLS、payload IFUNC、`__cxa_thread_atexit*` 和
  跨 DSO CFI 的拒绝条件也保持不变。

`KE_NAME` 仍用于 SONAME、`DT_NEEDED`、版本名和诊断文本。这些名称继续有
256 字节上限；本文只声明**符号名**支持任意合法长度。

## emutls 驻留策略

`__emutls_get_address` 不是 bionic 导出的普通函数（本设备
`/apex/com.android.runtime/lib64/bionic/libc.so` 只有本地隐藏的
`__emutls_unregister_key`）。payload 使用 thread_local 时通常把 compiler-rt
emutls 静态链接进来，由 payload 自己创建 pthread key；key 的 destructor 是
payload 内的代码，可能在任意线程退出时运行。

因此 1.5.7 的规则是：

- payload 定义 `__emutls_get_address`（普通函数，绑定 LOCAL/GLOBAL/WEAK）且地址位于
  可执行 `PT_LOAD` 时，允许导入/调用，但把镜像标记为 `nodelete=emutls`。
  镜像、控制对象和模板一直驻留到目标 mm 退出；`release` 明确返回
  `-EOPNOTSUPP`，首次加载的 `unload` 也在 prepare 阶段拒绝。
- payload 没有定义该实现、却引用 `__emutls_get_address` 或导入
  `__emutls_v.*` 时，继续明确拒绝；这类组合没有可验证的驻留代码。
- payload 只有 `__emutls_v.*` 控制对象、没有可见运行时，也明确拒绝。
- 该策略不改变 `PT_TLS`、TLS 重定位、`__cxa_thread_atexit_impl` 等既有拒绝。

驻留不是泄漏：目标进程退出后由 `reap` 释放登记；控制端仍须先让目标退出，
再 `reap`、`quiesce=idle`、卸载模块。

## 源码变更

- `kclf_elf.c/.h`：字符串读取/比较接口、长名称限界、`candidate()` 完整比较、
  `ke_io.string_budget`。
- `kclf_manual.c`：`symbol_name` 缓冲、`read_symbol_name()`、emutls 预扫描与
  驻留策略、`resolve_import()` 顺序/错误传播、NODELETE 诊断和状态显示。
- `kclf_internal.h`：版本号 1.5.7。
- `test/test_manual_elf.c`：255/256/285/4096/65537 字节名称、SysV/GNU hash、
  越界/无 NUL/读取失败、预算耗尽。
- `test/test_manual_symbols.py`：生产 `resolve_import()` 的真实 JUMP_SLOT、
  已定义/导入/弱符号、长名称缓存、emutls 驻留/拒绝、分配失败和错误 errno。
- `test/run_host_tests.py`：主机入口 11 → 12 组。

## 构建

- WSL Ubuntu 24.04，AArch64 GCC 13.3.0。
- `make TARGET_COMPILE=aarch64-linux-gnu- -j4`，保留既有严格编译选项，通过。
- `kclf.kpm`：142168 字节，ELF64 little-endian AArch64 ET_REL。
- SHA-256：`8398bd98e72b5395e1ad4430fe474a5fb3e1008967bbacf0c2560a47f93593bf`。

## 验证

### 主机

`make test`：**12 组全部通过**，C 测试使用 ASan/UBSan。新增用例覆盖：

- 真实 `R_AARCH64_JUMP_SLOT` 引用 285 字节的定义符号，写入 `bias + st_value`；
- 255/256/285/4096/65537 字节的已定义、未定义、弱符号和提供库符号；
- SysV 与 GNU hash、完整名称比较、截断不匹配；
- 字符串偏移越界、表内无 NUL、读取失败、预算耗尽和分配失败；
- emutls 已定义/未定义、LOCAL/GLOBAL/WEAK、非可执行地址、`unload` 冲突、
  控制对象缺少运行时、`prepare_tls_policy()` 无重定位也能标记驻留。

### 设备

| 项目 | 值 |
| --- | --- |
| 设备 | Pixel 6 / oriole，ADB serial `25091FDF60063J` |
| Android / 内核 | Android 16 / `6.1.134-android14-11-g66e758f7d0c0-ab13748739` |
| ABI / 页大小 | AArch64 / 4096 |
| SELinux | Enforcing（测试前后相同） |
| boot ID | `156f57af-226b-493b-bdba-ce92398be02d`（前后相同） |
| 目标 | `cn.gov.tax.its` 2.3.5 |
| payload | `/data/local/tmp/libtest.so`，2484536 字节，SHA-256 `159c30c0c99d611fd85c13b42511fd8bf0f218b266b9bc5e7afd15255e92a865` |
| KPM | 1.5.7，142168 字节，SHA-256 `8398bd98e72b5395e1ad4430fe474a5fb3e1008967bbacf0c2560a47f93593bf` |

测试使用 `inject,<tid>,/data/local/tmp/libtest.so,manual,wake`，分别在两个重新启动的
App 进程中注入；同一进程内另做了镜像复用验证：

| 线程 | 请求结果 | 镜像 |
| --- | --- | --- |
| Binder `10517`（`binder:10508_1`） | `state=done stage=restore handle=1 done=syscall via=manual image=1 refs=1` | `7c15cbe000+1183744`，`nodelete=emutls` |
| 主线程 `11043` | `state=done stage=restore handle=1 done=syscall via=manual image=1 refs=1` | `7c162e3000+1196032`，`nodelete=emutls` |

同一进程再次从主线程注入 Binder 线程已加载的同一路径时，返回同一 `image=1`、
`refs=2`，不重跑构造函数。随后 `release,10517,1,wake` 按设计失败：

```text
state=failed stage=prepare
err="manual: image 1 is NODELETE (emutls); resident until the process exits"
```

构造证据不依赖 App 日志（该 App 把 `__android_log_print` 的首 16 字节改写成
`ldr x16,#8; br x16; <shield-address>`，所以 `Perfare` 输出被目标自身的 hook
吞掉，这不是加载器失败）。直接从 `/proc/<pid>/mem` 读取注入镜像：

- `_ZZ10start_dumpvE7started` 从 0 变为 1；
- `game_path` 缓冲区由构造函数写成 `/data/user/0/cn.gov.tax.its`。

即 `start_dump()` 已执行到写入 `game_path` 的路径；后续才是等待
`libil2cpp.so` 的工作线程创建。两次测试中 App 均保持存活，
`logcat -b crash` 没有对应 PID 的新条目，最新 tombstone 仍为测试前的 2025-10-15。

收尾：`am force-stop` 后 `reap` 回收全部请求、`images` 为空、`quiesce=idle`、
`kpm unload kclf` 成功、`kpm list` 为空；dmesg 无新增
`BUG:/WARNING:/Oops/panic`。证据目录：`build/kclf-tax-20261101/final-1.5.7/`。

## 范围与边界

- 本文只认证这台 Pixel 6 / Android 16 / 6.1.134 / 4K 设备上的这一个 payload 和
  `cn.gov.tax.its`；其他 5.x/6.x、16K/64K 页和第三方 App 仍需同一产物回归。
- 提供库 SONAME、`DT_NEEDED`、符号版本名仍受 `KE_NAME=256` 限制；符号名本身不再
  受该限制。
- `nodelete=emutls` 镜像在目标进程存活期间不能 `release`；要卸载模块必须先结束
  目标进程，再 `reap` 并确认 `quiesce=idle`。这是 compiler-rt emutls key
  destructor 的生命周期要求，不是可忽略的引用计数。
- emutls 判定依赖动态符号表中的 `__emutls_get_address` / `__emutls_v.*`。如果
  payload 用 hidden/local 可见性把这些符号完全从 `.dynsym` 移除，加载器无法识别；
  此时使用方仍须在释放前确认没有线程析构残留，或不要 release。
- 目标 App 对 `__android_log_print` 等函数的改写属于 App 自身加固；框架只按映射
  内存解析已加载提供库，不恢复、不绕过这些 hook。
- 未验证目标的反注入检测、non-dumpable、ptrace 或 SELinux 策略变化；框架仍不
  承诺“不可检测”。

## 发布前独立复核（2026-11-01，Asia/Shanghai）

### 源码范围与实现链

审计基线为 main `1e12047` / dev `2f9ce68`（1.5.6），本次实现提交为 dev
`ade4c68`。框架源码仅修改 `kclf_elf.c`、`kclf_elf.h`、`kclf_manual.c` 和
`kclf_internal.h`（版本号）。控制面、task_work、内核兼容层、用户内存访问、
EL0 生成器、共享参数 ABI 的源码与 main 基线一致。

执行链仍为：superkey 控制命令 → 目标线程 prepare task_work → 文件快照和
ELF 映射 → emutls 策略预扫描 → 已驻留依赖闭包/重定位 → 权限和调用表 →
hijack task_work 修改 pt_regs → EL0 初始化/恢复/token → 完成观察和 cleanup。
名称分配、GUP 字符串读取、预扫描和回滚都在原有可睡眠 prepare 路径，不进入
普通 syscall hook 的不可睡眠完成观察路径。

### 跨内核兼容性结论

**未发现本次修改破坏既有跨内核适配路径的阻断问题，可以同步 main。**
这是相对 1.5.6 的差分审计结论，不是全版本、全厂商配置认证。

| 检查项 | 结果 |
| --- | --- |
| 内核符号/模块导入 | 与 1.5.6 的 `nm -u` 结果完全一致；无新直接导入。动态解析代码未改，复用既有 vmalloc/vfree 和 access_process_vm |
| 内核结构/ABI | 未增加结构偏移、内核版本分支或依赖新内核类型；`ke_io` 是模块内部接口，不是内核或持久化 ABI |
| task_work / BTF / nofault | 通知和取消 ABI、BTF 验证、procfs/accessor/GUP 回退代码未改；对应主机测试和设备回退回归通过 |
| 页大小/内核栈 | 字符串使用 64 字节对齐小块，长名称位于 vmalloc 堆；没有新增 4K 假设。原有 2048 字节栈帧告警作为错误执行 |
| 边界/预算 | DT_STRSZ、可读 PT_LOAD、地址溢出、完整 NUL、分配失败、名称缓冲扩容和扫描预算用例通过 |
| 生命周期 | 本地 emutls 在初始化前标记 NODELETE；首次 unload 和显式 release 被拒绝，失败准备可回滚，目标 mm 退出后沿原有 reap 路径释放登记 |

ELF 字符串规范没有 255 字节通用上限，完整名称读取有其依据；compiler-rt
使用 pthread key 注册 emutls 析构函数，因此保留 payload 代码到 mm 退出是必要
的生命周期约束。参考 [ELF 字符串表规范](https://gabi.xinuos.com/elf/04-strtab.html)
和 [LLVM compiler-rt emutls 实现](https://github.com/llvm/llvm-project/blob/main/compiler-rt/lib/builtins/emutls.c)。

### 本轮重新执行的验证

- `make test`：12 组全部通过；C 测试使用 ASan/UBSan，UBSan 遇错即停止。
  包含 5.0–6.18 **模拟**版本/BTF ABI 选择、255/256/285/4096/65537 字节名称、
  emutls 策略和失败路径，以及 4K/16K/64K 生成器用例；这些不是相应内核的真机实测。
- 从当前设备读取真实 `/sys/kernel/btf/vmlinux`，重新运行 `test/test_compat.py`：
  布局选择、缺失符号回退、mm 引用平衡通过；BTF SHA-256 为
  `ef6ffa2e5d2f10ad1438a89a77d42747e80c7b78367c1d191140c5e623ff4970`。
- 正式 KPM：Pixel 6 / Android 16 / Linux 6.1.134 / ARM64 / 4096，
  `manual-device-test.py --app` **186 项断言通过**。包含原生进程和自有普通 App、
  manual/linker、引用与释放、ELF 重定位、错误回滚、FPSIMD、seccomp、目标退出、
  分页、取消和 quiesce。`probe`：`btf=1`、`pt_regs=336`、`vma_backend=locked`、
  `nofault=1`。
- 独立测试构建（不用于发布）：
  `CFLAGS='-DKCLF_TEST_NO_BTF -DKCLF_TEST_NO_NOFAULT'`，
  SHA-256 `94fb41cb75d6d375ffd5a656d7adda5fe3b7ebc4c56d4c949ed271ef5c6d7f36`。
  同设备 `manual-device-test.py --app --expect-poll` **243 项断言通过**；
  `probe` 确认为 `btf=0`、`vma_backend=proc_maps`、`mm_access=get_task_mm`、
  `nofault=0`，成功请求均检查 `done=poll`。
- 两轮最终结果均为 PASS；没有新增 retained dmesg BUG/WARNING/Oops/panic，
  boot ID 和 SELinux Enforcing 不变。只启动/结束本轮自有夹具；测试 App 已停止，
  KCLF 在 `quiesce=idle` 后卸载，最终模块列表为空。

本地证据（不包含 superkey）：

| 运行 | 证据目录（相对 KernelPatch 根目录） | results.json SHA-256 |
| --- | --- | --- |
| 正式产物 | `build/kclf-manual-582fd3865f73/` | `306498e6050bf9847be422b5447faf0a3102979139c2738cb1fa3264a5aeaf16` |
| 无 BTF/nofault | `build/kclf-manual-bb39f93c4c1d/` | `6ae561653eee08fc85ccdc83cbf82189692d91a6706f067db2d611e92ccb165e` |

### 可重复构建与发布边界

使用 KernelPatch `406c85ce79a5e1c19b53be34c04baadc1ec68bc5` 的未修改头文件、
WSL Ubuntu 24.04 / AArch64 GCC 13.3.0 / GNU binutils 2.42，执行
`make -B TARGET_COMPILE=aarch64-linux-gnu- -j4`。产物为 142168 字节的 ELF64
little-endian AArch64 ET_REL；SHA-256 与前文正式 1.5.7 完全一致：
`8398bd98e72b5395e1ad4430fe474a5fb3e1008967bbacf0c2560a47f93593bf`。

发布不包含关闭 BTF/nofault 的测试构建。main 保留精简源码、测试 App 和双语文档；
完整主机/原生设备夹具及开发分析保留在 dev。

尚存限制：本轮没有其他 5.x/6.x 或 16K/64K 真机；回退测试仍是在 6.1 上。
新增预扫描会遍历动态符号表，完整名称最多 64 MiB（含 NUL），累计字符串读预算
256 MiB；预算耗尽或额外内存不足会明确失败，不能宣称任意大小合法 ELF 均可加载。
SONAME/NEEDED/版本名仍限制为 255 字节。隐藏且不在 dynsym 中的 emutls 无法自动
识别；驻留依赖必须由调用者保证；x16、异步锁重入、强制卸载等原有风险没有消失。
