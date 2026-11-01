# KCLF 手动加载后端（1.4.3 起，1.5.7 修订）

## 目标与结论

本次修改处理的是**注入框架对目标用户态系统库函数的依赖**，不是要求 payload 不使用
系统库。约定 payload 的全部 `DT_NEEDED`（含传递依赖）已经存在于目标进程。

旧路径会在目标映射中解析 `__loader_dlopen` / `dlopen`、`__loader_dlclose` / `dlclose`
和 `dlerror`，由 EL0 trampoline 调用这些入口完成加载/卸载。它本来就不是通过
`dlsym` 查地址，但仍把 ELF 加载交给 bionic linker。

现在默认路径由 KPM 自行实现 ELF 映射和重定位，不查找、不调用上述 loader API；
也不调用 `android_dlopen_ext`、`dl_iterate_phdr` 或修改私有 `soinfo` 链表。
旧路径保留为显式 `,linker`，手动路径失败时**绝不自动回退**。

这不等于零系统依赖：

- 内核侧仍依赖 KernelPatch 和已解析的内核 VFS、内存管理、task_work、用户内存访问等入口。
- 用户态普通导入只写入目标已有库的符号地址，不调用 libc 的 `mmap`、`mprotect`、
  `open`、`read`、`memcpy` 等函数来完成框架加载。
- **导入 IFUNC 是例外**：例如本次设备的 libc `strlen` 是 IFUNC，必须执行提供库的
  resolver，才能得到实际函数地址。它在 EL0 调用，绝不从内核执行用户代码。
  若完全禁止此类调用，就只能拒绝这些导入，不能保持当前 payload 兼容性。
- payload 自己的构造/析构和运行时仍可调用已解析的系统库函数。

## 源码与执行过程

| 组件 | 职责 |
| --- | --- |
| `kclf_elf.c` / `.h` | 与内核布局无关的有界 ELF64/AArch64 解析、哈希/版本符号查询、RELA/APS2/RELR 重定位 |
| `kclf_manual.c` | 文件快照、匿名镜像（随机前导 pad）、已加载依赖收集、ELF 调度、权限、引用计数和驻留镜像登记 |
| `kclf_exec.c` | 选择后端、建立随机化临时映射、改写及恢复寄存器、统一清理 |
| `kclf_codegen.c` / `.h` | 每请求生成的 EL0 AArch64 程序（IFUNC、延迟 RELRO、构造/析构、随机完成候选）与共享 ABI |
| `kclf_param.h` | 参数页布局；私有页保存寄存器、候选系统调用和恢复 token |

加载顺序如下：

1. 用原有 task_work 在目标线程上下文准备；默认自然返回，`wake` 可唤醒阻塞线程。
2. 按 TGID 的 `struct pid` 身份和地址空间选择登记项。同一进程只允许一个活动手动
   镜像事务，争用返回错误，控制端可重试；不冻结其他线程。
3. 以目标凭据打开 SO，读取有界文件快照。校验 ELF、各 PT_LOAD、偏移/长度/对齐，
   分配匿名 RW 区（长度含 1–8 页随机前导 pad 和 ELF 对齐空洞），按段复制文件内容；
   BSS 由匿名页零填充。
4. 扫描目标 VMA 中的 ELF 动态元数据，同时读取 maps pathname，按 SONAME 建立提供库
   表。每条 `DT_NEEDED` 按导入库自身的来源选择提供库（完全相同路径 > 同目录 >
   同 APEX 模块 > 同分区 > 平台默认 `/system` > 默认 runtime APEX > 最长公共前缀），
   再按顺序广度优先展开依赖闭包。同一路径的多个映射只算一个实例；最高分仍有多个
   不同路径时明确失败。缺失依赖同样明确失败。
5. 用 ELF 哈希/符号版本解析函数和数据导入，处理重定位；未定义弱符号可取零。
   IFUNC 写入工作表，暂不执行。
6. 验证并保存初始化/析构调用表，将空洞和对齐余量置为 `PROT_NONE`，按 PT_LOAD
   设置 R/RW/RX，禁止 W+X。无 IFUNC 时此处应用 RELRO；有 IFUNC 时延迟至其完成后。
   默认擦除内存中的 ELF 头和程序头表（`keepelf` 可保留）；pad 与第一个 PT_LOAD
   使用相同权限合并，使 ELF 头页位于某个 VMA 的中间而不是起点。
7. 重定向到 EL0：保存全部 FPSIMD，执行提供库 IFUNC 并写入地址，用直接 `svc mprotect`
   应用延迟 RELRO，然后运行 `DT_INIT` 和正序 `DT_INIT_ARRAY`。IFUNC 的
   `AT_HWCAP`/`AT_HWCAP2` 在准备阶段从内核 `cpu_get_elf_hwcap()` accessor 读取；
   只有 accessor 不可用时才回退到目标 auxv。
8. `unload` 新镜像时紧接着运行逆序 `DT_FINI_ARRAY` 和 `DT_FINI`。完成后通过候选池
   中随机选出的普通系统调用交回内核并恢复原始通用寄存器/PC/SP；统一清理回收临时区，
   并提交引用或解除镜像映射。1.4.2 起注入路径不再使用 `getpid`。

快照防止同次准备反复读取变化的文件，但不代表原子文件系统快照。调用方不要在加载期间
修改文件。读取目标提供库也没有取得 bionic loader 锁，**提供库必须在整个准备及 payload
存活期间保持加载**，不能与其 `dlclose`/`munmap` 并发。手动路径不会增加 linker 引用计数。

## ELF 支持范围

支持 ELF64、小端、AArch64、ET_DYN；动态元数据来自 program headers，不依赖 section
headers。目前支持：

- `R_AARCH64_RELATIVE`、`ABS64`、`GLOB_DAT`、`JUMP_SLOT`，以及 `R_AARCH64_NONE`。
- 常规 RELA、Android APS2 packed RELA、标准及 Android 标签的 RELR，允许常见混合配置。
- SysV/GNU hash、函数/数据/绝对符号、弱导入、`DT_VERSYM`/`VERNEED`/`VERDEF` 版本匹配。
- 符号名按 `DT_STRSZ` 和可读 `PT_LOAD` 分段读取并完整比较；payload 内定义、外部导入
  和提供库中的长符号名不受 256 字节限制。SONAME、`DT_NEEDED` 和版本名仍使用
  `KE_NAME=256` 的显式上限。
- 本地定义优先；未定义符号只在稳定顺序的 `DT_NEEDED` 闭包中查找。
- 同名 SONAME 的已加载提供库按映射路径的加载来源选择；Android 12 的四份
  `libc++.so`（vndk/conscrypt/art/system）可以区分，同一路径的重复映射只选一个。
- 已加载提供库的 ELF 头可能被加固/反调试引擎改写：实测某 App 的 libc.so 在偏移 8
  处被写入 `ldr x16,#8; br x16; <addr>`，破坏
  `e_ident[8..15]`/`e_type`/`e_machine`/`e_version`，但
  `e_phoff`/`e_phentsize`/`e_phnum`、程序头、动态表和符号表仍然有效。1.5.6 按原版
  契约通用处理这类情况：提供库的这些非结构性身份字段可以是任意内容，不匹配任何
  指令签名；ELF64/小端标识、结构字段和全部数据边界仍校验。1.5.5 的特定指令例外已移除。
  payload 自身始终严格校验 ET_DYN/EM_AARCH64/version，不因此放宽 TLS/REL 等拒绝条件。
  VMA 扫描与结构解析不能证明 linker 来源或恢复被覆写的原始架构，框架仍只支持 ARM64 目标。
- 从已加载库导入 IFUNC：按 Android arm64 ABI 传入目标 `AT_HWCAP`/`AT_HWCAP2`；
  多个对应重定位可重复调用同一个 resolver，不保证任意带副作用的 resolver 安全。
  HWCAP 来自内核 accessor，不要求目标 App 可读自己的 auxv。
- `DT_INIT`、`INIT_ARRAY`、`FINI_ARRAY`、`DT_FINI`、RELRO、`DF_1_NODELETE`。

以下情况明确拒绝或不提供完整语义：

- **拒绝** payload `PT_TLS`、TLS 重定位、线程析构注册入口；payload 自带的
  compiler-rt emutls（定义 `__emutls_get_address`）例外：允许运行，但镜像按
  `nodelete=emutls` 驻留到目标 mm 退出。未定义/跨 DSO 的 emutls 运行时或控制对象
  仍明确拒绝。
- **拒绝**需要解析的 payload 自定义 IFUNC、IRELATIVE、GNU_UNIQUE；IFUNC 重定位若写入
  init/fini 数组也拒绝，因为调用表在进入 EL0 前已经验证和保存。
- **拒绝** REL/textrel、PT_INTERP、可执行栈、PT_GNU_PROPERTY、共享/重叠 PT_LOAD 页、
  非可读或 W+X 的 PT_LOAD，以及未实现的动态标志/过滤器/preinit 语义。
- 初始化/析构地址必须在 payload 自身可执行段；不接受外部库函数作为初始化入口。
  构造函数的 argc/argv/envp 传零，只支持不依赖这三个参数的 payload。
- 不复制 bionic namespace、全局组插入/符号抢占规则。依赖选择是“映射路径来源”的
  启发式，不是 namespace 的完整重建；多个同名不同来源且启发式无法区分时明确失败。
  需要精确 bionic 语义时显式使用 linker 后端。框架不改变目标 non-dumpable 状态，
  因此 payload 自己打开 `/proc/self/mem` 等文件的结果与直接调用系统 API 相同。
- 不注册 TLS 模块、异常展开或 debugger 元数据，不自动调用 `JNI_OnLoad`；
  跨 DSO CFI 导入明确拒绝，不保证 C++ 异常、栈展开、JNI/ART 集成。
- 手动镜像不出现在 linker 的加载列表中，不能用 `dlsym`/`dlclose` 管理；
  `dladdr`、`dl_iterate_phdr`、payload 自己再执行的 `dlopen` 的调用者 namespace 等
  不保证识别该镜像。框架不拦截 payload 对这些 API 的调用。

资源上限是显式失败条件：64 MiB 文件快照，256 MiB 虚拟 ELF 跨度/最大对齐，
256 MiB 符号名称读取预算（单名称 64 MiB，复用同一缓冲区），64 个 program headers，
每对象 64 个 NEEDED，已加载候选提供库表按需倍增
（初始 64，硬上限 4096；分配失败或超过上限时明确停止 prepare 并回滚，避免
在不完整的同名库集合中选择错误来源），128 个闭包成员，
50 万动态符号，100 万累计解码重定位，16 MiB APS2 数据，128 个初始化与128 个析构，
64 个 IFUNC fixup。调用/IFUNC/RELRO 表还必须共同装入一页参数区。
镜像为对齐额外预留一段空间，因此 `resident` 大小可大于 ELF 跨度。

## 控制接口与生命周期

以下是 `kpatch <KEY> kpm ctl0 kclf` 的命令字符串；密钥不要写进脚本或文档：

```text
inject,<tid>,/absolute/path/libpayload.so[,manual][,wake][,force][,unload][,keepelf]
inject,<tid>,/absolute/path/libpayload.so,linker[,wake][,force][,unload]
status
images[,cursor]
release,<tid>,<image-id>[,wake][,force]
cancel,<slot>
reap
quiesce
```

`manual` 是默认值。`status` 中成功加载会出现：

```text
state=done ... via=manual compl=64,22,113 image=12 refs=1 resident=<hex-base>+<decimal-size> hdr=scrubbed
```

`compl=` 是该请求实际使用的随机完成候选（`read/write/futex/clock_gettime/ioctl/
epoll_pwait/nanosleep/sched_yield` 的子集）；`hdr=scrubbed` 表示 ELF 头已擦除，
`keepelf` 时为 `hdr=kept`。请求运行期间还会显示随机布局的
`map=<base>+<len> code=<addr> guard=<addr>`。

`image` 是十进制框架 ID，**不是 bionic handle**。请求表仅有4个槽；独立的32项
镜像表在请求 `reap` 后仍保存驻留映像。`images` 输出有 `next=N` 时继续 `images,N`；
分页是实时视图，控制端应在无并发增删时枚举。

- 同进程重复加载**完全相同路径字符串**复用镜像、refs 加一，不重跑构造函数；不按
  inode/符号链接/SONAME 去重，不感知同一路径文件内容更新。
- `release` 的 tid 可为该进程中任一满足注入条件的存活线程，必须匹配登记的 TGID 与 mm；
  `original_tid` 只是首次加载线程的历史信息，不保证它仍存活。
- 非最后引用的 release 只减少 refs；最后引用运行析构并解除整段镜像映射。
- 新镜像 `inject,...,unload` 在一次事务中构造、析构、回收；对已存在镜像执行此命令
  相当于临时借用并归还，不重跑初始化，也不消耗已有引用。
- `DF_1_NODELETE` 或 `nodelete=emutls` 镜像拒绝显式 release 和首次加载的 `unload`；
  需目标进程退出后 reap，才能排空模块。
- 准备/重定位/安全点失败会回滚新映射；IFUNC/延迟 mprotect 返回可报告错误时，构造函数
  尚未执行，会安全回滚。resolver 异常、seccomp 杀进程等不会被当作普通返回值处理。
- **ELF 头擦除**：manual 加载在映射后已经消费完头和程序头；本后端不会在运行期重新
  读取它们。依赖 `__ehdr_start`/自身 ELF 头的 payload 需要显式 `keepelf`；此时页级
  扫描仍能找到保留的头。
- **随机 pad 与布局**：每次加载的镜像长度/基址不同，临时区域（代码、参数、私有页、
  guard+栈）按随机顺序和随机填充页布置；不能假设固定页数、固定相对位置或单页起点。
- 目标退出或 exec 后，由原 mm 释放映射，reap 只移除登记，不在控制进程 mm 中 munmap。
  不长期持有 `mm_users`，避免拖延进程地址空间和 Binder 的退出清理。
- 已进入用户代码却没有可信完成结果时，不擅自卸载可能被回调/线程引用的镜像，登记为
  abandoned；若借用线程独自退出而进程仍存活，也需要进程退出后才能最终排空。

引用数只表示框架的加载引用，**不证明没有线程正在执行 payload**。释放前调用方必须
停止 payload 后台线程、注销异步回调并保证没有活跃代码指针。`force` 不能解决这些竞态。

卸载 KPM 必须按以下顺序：

1. `quiesce`，停止新 inject；已运行请求等待完成，release 仍允许。
2. `images` 枚举并逐个 release 所有引用，等待对应 status 完成；处理 NODELETE/abandoned
   时需让其目标退出。
3. `reap`，再次 `quiesce`，必须看到 `quiesce=idle`。
4. 才执行 `kpatch <KEY> kpm unload kclf`。

stock KernelPatch 不尊重模块 exit 的 `-EBUSY`，所以不能强行卸载。当无回调但仍有驻留
镜像时被强制卸载，模块仅释放内核登记引用、报告 orphan，不从活进程背后强拆代码；
这些镜像只能随目标退出回收。有在途回调时强卸载仍可能产生内核 use-after-free。

## 1.4.2 / 1.4.3 防检测加固

- 每次请求由 `kclf_codegen.c` 生成 EL0 程序：入口/完成偏移、十个寄存器角色、
  FPSIMD 保存顺序和填充指令随机；完成系统调用从 8 个普通调用中随机选 2–3 个，
  代码中没有字面系统调用号。
- 1.4.3 去掉固定 `KCLFBAIL` 标记，EL0 恢复路径使用内核写入私有页的每请求随机
  token；延迟 RELRO 的 `mprotect` 号也用同一 key 加密；入口前的重启填充指令随机化。
- 临时映射的四个块（代码、ABI 参数、私有参数、guard+栈）随机排序并插入 0–2 页
  随机填充；ABI 参数页、私有页未用部分和栈页随机填充。
- manual 镜像增加 1–8 页随机前导 pad，并默认擦除 ELF 头/程序头。
- 以上修改不改变加载、重定位、构造/析构和引用计数语义；检测边界和残余可观测面
  见 [加固报告](OBSERVABILITY_HARDENING_20261030.md)。

## 验证与可复现性

### 1.5.7：长符号名与 compiler-rt emutls

2026-11-01，Pixel 6 / Android 16 / 6.1.134 / ARM64 / 4K、SELinux Enforcing，目标
`cn.gov.tax.its`，payload `/data/local/tmp/libtest.so`（SHA-256
`159c30c0c99d611fd85c13b42511fd8bf0f218b266b9bc5e7afd15255e92a865`）：

- 1.5.6 在 prepare 阶段拒绝 payload 内定义的 285 字节符号；1.5.7 按完整名称读取，
  并按 `bias + st_value` 完成该 `R_AARCH64_JUMP_SLOT`。
- 修复长名称后，payload 自带的 `__emutls_get_address`（WEAK FUNC）曾被当作
  loader 集成 TLS 拒绝；1.5.7 允许该定义，并把镜像标记为 `nodelete=emutls`。
- 主线程和 Binder 线程各自在全新进程中完成注入，`state=done stage=restore
  via=manual`；构造函数 `_Z10start_dumpv` 的 `started` 标志和 `game_path` 缓冲区
  （`/data/user/0/cn.gov.tax.its`）通过 `/proc/<pid>/mem` 独立确认。
- 同路径再次注入复用镜像、`refs=2`；`release` 按 NODELETE 语义返回
  `manual: image 1 is NODELETE (emutls); resident until the process exits`。
- 目标退出后 `reap`、`quiesce=idle`、`kpm unload` 成功；无新增
  BUG/WARNING/Oops/panic，boot ID 和 SELinux 状态不变。

App 自身把 `__android_log_print` 改写成 `ldr x16,#8; br x16; <shield-address>`，
因此 payload 的 `Perfare` 日志被目标 hook 吞掉；这不是加载器失败，验证以镜像内
构造函数副作用和 `status`/`images` 为准。完整产物、证据目录和边界见
[1.5.7 兼容性报告](COMPATIBILITY_1.5.7.md)。

### 1.5.6：通用头覆写兼容

生产解析器已验证 256 种重复字节内容、各身份字段单独改写及任意混合内容；
payload 严格拒绝不合法身份，provider 结构解析仍拒绝坏结构/越界。
设备夹具 `manual_rewritten_provider.c` 是实际编译的 ARM64 库：它自行用全零、
重复字节、单独改写 machine、混合字节四种方式修改头部，随后验证 manual payload
能导入并调用其函数、读取其数据及安全释放。当前产物和设备结果见
[1.5.6 兼容性报告](COMPATIBILITY_1.5.6.md)。

### 1.5.5 审计前快照：受保护 App（2026-11-01）

本节结果对应审计前快照，SHA-256 为
`e9af06bad92c95cacdbd2dba103de334b5fe4116df7f7946077df08890463887`。
最终代码随后收紧了表截断处理和头校验，最终发布产物及其验证范围见
[1.5.5 兼容性报告](COMPATIBILITY_1.5.5.md)；下列第三方 App 结果不能代替最终产物实测。

同一台小米 13 / Android 13 / 5.15.74 / ARM64 / 4K 设备，两个真实 App：

- 抖音 `com.ss.android.ugc.aweme` 40.8.0 有 540–549 个带 `DT_SONAME` 的已加载
  对象，超过 1.5.4 固定的 512 项表；旧产物报
  `manual: provider scan limit exceeded`。提供库表改为按需倍增后主线程和
  Binder 线程均注入成功。
- 建行 `com.chinamworld.main` 7.6.0 的加固引擎把已加载 libc.so 的
  `e_ident[8..15]/e_type/e_machine/e_version` 改写成跳板，旧产物报
  `manual: DT_NEEDED is not already loaded: libc.so`。审计前的头校验修订后注入成功。

两个 App 的构造函数实际执行（`Perfare : start dump.....`），release 后 App 存活、
`images` 为空，无新增内核告警。完整字节对比、原因排除、主机测试和证据目录见
[受保护 App 注入失败分析与修复](REAL_APP_INJECTION_20261101.md)。释放前必须确保
payload 的后台线程已停止；本轮一次“观察 3 秒就 release”的测试误用导致执行已解除
映射的 SIGSEGV，改回 12 秒观察后不再出现。

### 1.4.1：真实 App + 用户提供的 SO

2026-10-29，同一台 Android 12/API31、ARM64、4K、无 BTF 的 Linux 5.10.66 设备，
目标为正在运行的 `com.miHoYo.Nap`（PID 16488），payload 为
`/data/local/tmp/libtest.so`（SHA-256
`944efd09c1e031237ffbdcca4eda5c919e0ea616fa97e4b0c545ec33c0c3abea`）：

- 修复同名 `libc++.so` 选择后，manual 请求从 `state=failed stage=prepare`
  变为 `state=done stage=restore via=manual`；构造函数实际执行并输出
  `Perfare : start dump.....` 和 `game dir:/data/user/0/com.miHoYo.Nap`。
- 修复 HWCAP 后，`probe` 报告 `hwcap=119fff hwcap2=0 source=kernel`；与目标内
  libc `getauxval()` 的结果一致。
- 同路径再次 inject 只把 `refs` 从 1 加到 2，不重跑构造函数；两次
  `release,...,wake` 依次得到 `refs=1`、`refs=0`，`images` 最终为
  `no manual images`，注入地址从 `maps` 消失。
- 目标 PID 保持存活；`quiesce=idle` 后 `kpm unload kclf` 成功，最终 `kpm list`
  为空；无新增内核故障，boot ID 和 SELinux 状态未变。
- payload 随后因自身依赖 `/proc/self/mem` 而报 IL2CPP API 缺失；该 App 是
  non-dumpable，`/proc/self/mem` 对自身凭据返回 `EACCES`。把同一 SO 放进 App
  native library 目录并改用 `,linker` 后端，输出逐行相同，证明不是 manual
  后端回归。完整证据和分析见 [libtest 实测](LIBTEST_NAP_20261029.md)。
- 主机侧 `test_helpers.py`、`test_maps.py`、`test_compat.py`、
  `test_manual_elf.py`、新增的 `test_provider.py` 全部通过；其中
  `test_maps.py` 新增了 maps pathname 解析断言，`test_provider.py` 覆盖
  同目录/APEX/分区/平台/vendor 选择、同路径去重、无法区分时失败和缺失依赖。
  1.4.1 只针对本场景和这些主机测试重新验收，没有重跑 1.4.0 的完整
  native/App 回归套件。

对应 1.4.1 `kclf.kpm` SHA-256：

```text
8749c287f1243d433f26e6b0a6e86b32a7136860adc9c4369fe5db881ebd7f59
```

证据目录：`E:/KernelPatch/build/kclf-libtest-20261029-final/`。

### 1.4.0 基线

2026-10-29，Android 12/API31、ARM64、4K、无 BTF 的 Linux 5.10.66 设备：

- freestanding `-Wall -Wextra -Werror` 构建通过；trampoline 对象 `readelf -r` 无重定位。
  KPM 未定义符号检查没有额外 libc 导入，保留的是 KernelPatch/内核接口。
- 原 helper、maps、compat 主机测试通过。实际 ELF 解析器的 ASan+UBSan 测试覆盖
  hash/版本/数据符号、重定位、负加数、IFUNC 延迟、错误回调、截断/越界与拒绝路径。
- 最终手动回归证据：[results.json](../../build/kclf-manual-2f2c338117a8/results.json)。
  包含原有 payload 无修改加载、5种重定位/hash 配置、构造/析构顺序、数据和弱导入、
  W^X、精确解除映射、引用复用、立即卸载、FPSIMD、seccomp、失败回滚、目标退出、
  排队取消、分页超过请求槽数、quiesce 后 release，以及自有普通 App 的主线程测试。
- 普通 App 在 `untrusted_app`、Seccomp=2 下完成手动加载与释放并保持存活；没有安装/更新
  App、清空 App 数据或修改 SELinux/seccomp。测试结束恢复其停止状态。
- 手动回归结束无新增 BUG/WARNING/Oops/panic，设备 boot ID 和 SELinux 状态未改变，
  模块已排空卸载。设备与本地的独立命名测试目录/证据保留。
- 同一最终产物的旧 linker native 全套回归也通过，含取消/4槽/目标死亡/guard/W^X/
  quiesce/reload；证据见 [results.txt](../../build/kclf-test-4be6116e1923/results.txt)。
  最终卸载成功，无新增内核故障。

对应 1.4.0 `kclf.kpm` SHA-256：

```text
ccf9cf1cc4d9f445c2d897ab5f13430552b2a27c096760008bbae05fa68fc82d
```

复现命令和旧后端测试入口见 [README](README.md)。`test/manual-device-test.py` 用环境变量
`KCLF_SUPERKEY` 接收密钥；不会把密钥写入结果记录。`--app` 要求事先安装并停止仓库自有
`com.kclf.apptest`，不操作其他应用。历史 device/app/package 脚本显式选择 `linker`，
不能拿它们的通过替代 manual 验证。

这次验证不包括其他 Android/内核组合、16K/64K 真机、复杂 C++/JNI payload、动态卸载
依赖、不同 namespace 的符号互抢、任意 seccomp、任意并发程序或全部资源极限。1.4.1
新增的来源选择只在这台设备的 system/vndk/conscrypt/art `libc++.so` 组合上实测，
没有覆盖 vendor/product namespace 的任意同名库；payload 自己打开
`/proc/self/mem` 的失败属于目标 non-dumpable 策略，不在框架修复范围。

实现参考：Android 12 的 [arm64 IFUNC ABI](https://android.googlesource.com/platform/bionic/+/refs/heads/android12-release/libc/include/sys/ifunc.h)
和 [APS2 relocation iterator](https://android.googlesource.com/platform/bionic/+/refs/heads/android12-release/linker/linker_reloc_iterators.h)。
