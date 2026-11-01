# KCLF 1.5.6 manual 注入 cn.gov.tax.its 失败分析与修改方法

> 2026-11-01 后续：本文记录的是 1.5.6 的直接触发点。修复长名称后又发现 payload
> 自带 compiler-rt emutls 的驻留问题；最终实现（1.5.7）、完整测试和真机验证见
> [1.5.7 兼容性报告](COMPATIBILITY_1.5.7.md)。以下第 1–7 节保留当时的分析记录。

测试日期：2026-11-01，Asia/Shanghai。本文只分析 manual 后端。

## 1. 结论

**当前提供的 libtest.so 在重定位阶段触发了框架的 255 字节符号名限制。**
主线程和 Binder 线程得到同一错误，发生在 prepare 阶段，尚未重定向目标的
`pt_regs`、执行 IFUNC 或调用 payload 的构造函数：

```text
#0 id=3 pid=7437(cn.gov.tax.its) state=failed stage=prepare
  err="manual: ELF symbol/SONAME/version name exceeds 255 bytes"
#1 id=4 pid=7445(binder:7437_1) state=failed stage=prepare
  err="manual: ELF symbol/SONAME/version name exceeds 255 bytes"
```

直接触发条件是一条 `R_AARCH64_JUMP_SLOT` 重定位引用了 **285 字节**的 C++
模板符号。该符号已经定义在 payload 内部，本可按加载偏移计算地址，但
`resolve_import()` 在判断 `st_shndx` 前无条件复制完整名称，导致提前失败。

这是 manual 加载器的兼容性限制和解析顺序问题。本次错误不能通过更换线程、
增加 `wake`、使用 `force` 或 `keepelf` 解决。这些选项不改变该名称解析路径。

## 2. 本次正式测试的输入

| 项目 | 实测值 |
| --- | --- |
| 设备 | Pixel 6 / oriole，序列号 25091FDF60063J |
| Android / 内核 | Android 16 / 6.1.134-android14-11-g66e758f7d0c0-ab13748739 |
| ABI / 页大小 | AArch64 / 4096 |
| SELinux | Enforcing |
| 目标 | cn.gov.tax.its 2.3.5，versionCode=20305 |
| 正式 manual 请求 | 主进程主线程 7437；同进程 Binder 线程 7445 |
| KPM | 当前工作区 kclf.kpm，`kpm info` 确认版本 1.5.6，137328 字节 |
| KPM SHA-256 | b34ba7754f79d3cb988f793e81dfe7b440df091adcb0186e5a5892a028345589 |
| payload | 用户就位的 /data/local/tmp/libtest.so，2484536 字节 |
| payload SHA-256 | 159c30c0c99d611fd85c13b42511fd8bf0f218b266b9bc5e7afd15255e92a865 |

设备日志时钟为 2025-09-28，与本次工作日期不一致；未修改设备时间。
初始检查时设备路径上的旧 kclf.kpm 为未加载的 1.3.0 文件，本次正式测试使用的是
上表中的 1.5.6。测试期间先前使用过另一份 499624 字节的历史 payload，随后已
释放其镜像；它的成功结果不计入本次用户 payload 的验证。

## 3. manual 的实现流程及本次失败位置

1. **控制面**：`kclf.c` 的 `kclf_cmd_inject()` 解析请求，固定 PID/mm 身份，
   从四个请求槽分配一个槽，并向指定线程排队 `work_prepare`。
2. **目标上下文准备**：`kclf_work_prepare_body()` 调用 `kclf_exec_prepare()`。
   该阶段在目标线程的 task_work 中运行，可睡眠，使用目标的地址空间和凭据。
   `wake` 负责通知阻塞线程处理 task_work。
3. **临时执行环境**：`kclf_exec_prepare()` 分配临时映射、参数页、私有现场页，
   选择借用线程栈或使用临时栈，然后进入 `kclf_manual_prepare()`。
4. **ELF 映射**：读取 SO 文件快照，严格校验 ELF64/AArch64/ET_DYN，复制
   PT_LOAD，准备 BSS，并按选项处理内存中的 ELF/程序头。
5. **依赖提供库**：枚举目标 VMA，解析已映射 ELF 的动态表和 SONAME，建立
   提供库表；按映射来源选择 DT_NEEDED 及其传递依赖。不会自动加载缺失依赖。
6. **重定位**：`ke_relocate()` 依次处理支持的重定位，调用
   `resolve_import()` 获取符号地址。**本次在这里失败。**
7. **后续步骤**：若重定位成功，再准备 IFUNC/初始化/析构调用表、保护段和
   延迟 RELRO，生成 EL0 程序；排队 hijack，在返回用户态时修改 `pt_regs`。
   目标随后执行 IFUNC/构造函数，恢复现场，写入完成 token；内核观察 token，
   提交驻留镜像并回收临时映射。

相关源码位置：

- `kclf.c:403`：prepare 回调及失败回滚。
- `kclf_exec.c:983`：目标上下文执行环境。
- `kclf_manual.c:693`：manual 准备事务。
- `kclf_manual.c:744`：重定位入口。
- `kclf_exec.c:1270`：hijack，位于本次错误之后。
- `kclf_codegen.c:380`：EL0 程序生成。

## 4. 285 字节符号的精确证据

对从设备拉取的原文件进行独立 ELF 分析，结果为：

| 字段 | 值 |
| --- | --- |
| .dynsym 项数 | 2286 |
| .dynstr 长度 | 115685 字节 |
| 名称至少 256 字节的动态符号 | 1 个 |
| 该符号索引 | 1718 |
| 名称长度 | 285 字节，不含 NUL |
| 属性 | STB_WEAK / STT_FUNC，st_shndx=15，已在 payload 内定义 |
| st_value / st_size | 0x8094c / 104 |
| 引用位置 | .rela.plt 第 69 项，即从零计数 index=68 |
| 重定位 | offset=0x117a30，R_AARCH64_JUMP_SLOT，addend=0 |

名称以 `_ZNSt6__ndk112__tuple_impl...` 开头，是 C++ 标准库线程参数相关的模板
实例。完整名称和重定位记录在 `build/kclf-tax-20261101/payload-analysis.json`。

这里的“长名称”是符号名，不是 SO 文件名、包名或文件系统路径。
ELF 使用字符串表偏移引用 NUL 结尾的符号名称，255 并非 ELF 的通用符号名上限。
见 [ELF 字符串表规范](https://gabi.xinuos.com/elf/04-strtab.html) 和
[ELF 符号表规范](https://gabi.xinuos.com/elf/05-symtab.html)。

### 直接失败链

`kclf_elf.h:18` 把多类名称共用的缓冲区设为：

```c
#define KE_NAME 256
```

`kclf_elf.c:134` 的 `ke_string()` 最多检查 256 字节；没有在其中读到 NUL 就
报告上述错误并返回 `-E2BIG`。

`kclf_manual.c:336` 的顺序是：

```c
if (ke_symbol(&c->io, o, index, &s) ||
    ke_string(&c->io, o, s.name, name))
    return -ENOEXEC;
/* 之后才检查类型、受限入口和 s.shndx。 */
```

因此对 index=1718：读取 `Elf64_Sym` 成功 → 复制 285 字节名称失败 →
直接返回。`s.shndx != 0` 的地址计算分支根本没有机会执行。
原本按当前 manual 的“内部定义优先”语义，这个普通函数的地址应为
`load_bias + 0x8094c`，重定位将该地址写入 `load_bias + 0x117a30`。

另一个诊断缺陷是：这里把 `ke_string()` 的 `-E2BIG` 合并成了 `-ENOEXEC`，
虽然 `report()` 保留了首个错误文本，却丢失了精确 errno 和符号上下文。

## 5. 修改方法

### 5.1 针对本例的结构调整

修改 `kclf_manual.c` 的 `resolve_import()`，将“读取符号元数据”和“按名称查找”
拆开。处理流程应为：

```text
读取 Elf64_Sym
  → 验证索引、绑定、类型、名称范围及既有受限入口规则
  → 已在 payload 内定义：按 SHN_ABS 或 bias + st_value 计算地址并验证段边界
  → 未定义：读取完整名称，检查版本，在 DT_NEEDED 闭包中查找
  → 缓存解析结果
```

对内部已定义的普通函数，不应为了取得其地址而要求名称能装进固定数组。
仍需保留以下检查，不能仅将整个 `s.shndx` 分支机械移动到所有校验之前：

- GNU_UNIQUE、TLS、payload 自定义 IFUNC 的拒绝条件。
- SHN_ABS、保留 section index、地址溢出、PT_LOAD 边界及可执行权限检查。
- 原有 TLS 析构注册、emutls、跨 DSO CFI 等受限入口规则；可用受边界约束的
  字符串比较判断这些固定短名称，无须把任意完整长名称复制到栈上。
- 名称偏移及终止符的结构有效性检查。

这项调整解决本次“内部定义名称过长”的直接触发点；若外部导入仍沿用旧接口，
则外部长符号仍受 255 字节限制，不能宣称已经完整支持长符号。

### 5.2 长符号的完整支持

推荐同步修改 `kclf_elf.c/.h` 和 `kclf_manual.c`：

1. **分离符号名与短名称接口**。符号解析不再共用 `KE_NAME`；SONAME、路径和
   诊断输出可以保留各自明确的容量契约。
2. **按字符串表边界读取**。从 `st_name` 开始，以 `DT_STRSZ - st_name` 为边界
   分块寻找 NUL，继续验证可读 PT_LOAD、地址运算和读取结果；无 NUL、越界或
   读取失败明确报错。
3. **避免内核栈大数组**。内部符号使用名称引用/分块比较；外部导入若需要连续
   C 字符串，由 `km_context` 持有 `vmalloc` 的名称缓冲区，按需增长并复用。
   在 prepare 的统一退出路径释放，分配失败传播 `-ENOMEM`。同时设置明确的
   内存与扫描工作量预算，避免畸形输入造成无界消耗。
4. **同步修改候选比较**。`kclf_elf.c:338` 的 `candidate()` 也有
   `char actual[KE_NAME]`，并调用 `ke_string()`。仅放宽 payload 侧仍不够；应
   将此处改为受边界约束的完整名称比较。GNU/SysV hash 和版本匹配仍保持完整
   名称语义，不能用截断字符串比较。
5. **保留错误信息**。将 `ke_symbol()`、字符串读取和其他步骤拆成独立返回值
   判断，传播原 errno。错误中记录 symbol index、名称长度、重定位类型/偏移；
   名称可以在日志中截断展示，但用于解析和比较的名称不能截断。

不要在 freestanding 的 `kclf_elf.c` 中直接硬编码内核分配器；可由调用方管理
缓冲区，或使用不分配内存的名称引用/流式比较接口，保留现有主机测试能力。

### 5.3 临时缓解与 payload 侧选择

把 `KE_NAME` 从 256 改为 512 可以容纳本次的 285 字节名称，但只是扩大上限。
它还会同时增加提供库记录、名称/版本/候选的栈数组；错误文本中的固定 `255`
也必须同步修改。需要检查编译栈告警及嵌套调用的栈开销，不能视为通用修复。

如果持有 payload 源码，也可以通过隐藏内部 C++ 实现符号、使用导出表仅保留
必要接口，减少动态符号和 PLT 引用。这属于 payload 构建层面的缓解，不能替代
加载器支持合法长符号。单独执行 strip 通常不能删除仍被动态重定位引用的符号。

## 6. 修订后的验证方法

建议验证以下真实 ELF 场景，而不只是测试字符串复制函数：

- 使用本次 SHA-256 为 `159c30c0...` 的原始 payload，确认 index=1718 和
  offset=0x117a30 不再触发名称容量错误。
- 长度 255、256、285 及更长的内部已定义符号和外部导入/提供符号，分别覆盖
  GNU hash、SysV hash、弱符号和版本匹配。
- 名称偏移越界、字符串表末尾无 NUL、读取失败、分配失败、工作量超限仍明确
  失败并回滚；原有 TLS/IFUNC/GNU_UNIQUE/CFI 拒绝条件保持有效。
- 在主线程与 Binder 线程复测；确认完成 token、构造函数独立证据、目标存活、
  临时映射回收和驻留镜像登记。只有跨过重定位阶段还不足以证明注入完整成功。
- 释放前按 payload 实际生命周期确认后台线程和回调已结束；不能把
  `state=done` 当作后台工作已结束。

**本次仅完成分析和修改方案，未修改生产源码、重建修复版 KPM，或声称修复后通过。**

## 7. 证据与收尾

原始证据位于 `build/kclf-tax-20261101/`：

- `module-info.txt`、`probe.txt`：运行中的 1.5.6 和内核能力。
- `remote-files-recheck.txt`、`libtest-user.so`：正式 payload 的设备哈希及原文件。
- `inject-7437-manual-wake-*.txt`、`inject-7445-manual-wake-*.txt`：主线程和
  Binder 的请求、失败、目标存活及回滚结果。
- `payload-analysis.json`、`analyze_payload.py`：285 字节名称与重定位的独立分析。
- `quiesce-final.txt`、`images-final.txt`、`module-num-final.txt`：收尾证据。

两次 manual 失败后目标均存活，`images` 为空，`loading=0`，没有遗留临时映射。
本轮测试结束时已 `quiesce=idle` 并卸载 KCLF，最终 KPM 数为 0，App 已重新启动。
设备 boot ID 未变化，SELinux 仍为 Enforcing，留存 dmesg 对比未发现新增
BUG/WARNING/Oops/panic。上述状态不代替未来修复版的设备验证。

## 8. 1.5.7 修复与验证补充

第 5 节的方案已实现为 1.5.7：

- 符号名改为按 `DT_STRSZ`/可读 `PT_LOAD` 分段读取；`read_symbol_name()` 使用
  `km_context` 持有的可增长 `vmalloc` 缓冲，已定义符号不再先复制名称；
  `candidate()` 用完整名称比较，提供库长符号也覆盖。
- 修复长名称后，同一次注入暴露第二个独立问题：payload 定义了 compiler-rt
  `__emutls_get_address`，旧检查把它当作 loader 集成 TLS 拒绝。1.5.7 允许这种
  定义，但把镜像标记为 `nodelete=emutls`，驻留到目标 mm 退出；未定义/跨 DSO
  emutls 仍拒绝。
- 主机入口增加到 12 组；新增真实 JUMP_SLOT、255/256/285/4096/65537 字节名称、
  SysV/GNU hash、越界/无 NUL/读取失败、预算/分配失败和 emutls 策略用例。
- 设备复测在同一台 Pixel 6 / Android 16 / 6.1.134 上分别对主线程和 Binder 线程
  完成 `state=done ... via=manual`；构造函数写入的 `started` 和 `game_path` 通过
  `/proc/<pid>/mem` 直接确认。目标 App 自身 hook 了 `__android_log_print`，所以
  没有 `Perfare` 日志，不能据此判定构造失败。
- 目标退出后 `reap`、`quiesce=idle`、卸载模块；无新增内核告警。

完整产物 SHA-256、证据目录、生命周期限制和未验证范围见
[1.5.7 兼容性报告](COMPATIBILITY_1.5.7.md)。
