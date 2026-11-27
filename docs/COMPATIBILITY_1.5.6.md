# KCLF 1.5.6：已映射提供库的通用头覆写兼容（2026-11-01）

## 修改原因

1.5.5 将提供库 ELF 头的兼容规则限定为一种固定 ARM64 指令序列。它只能处理
当时观察到的一种覆写方式，不能解决“已映射库的身份字段被改写，但结构与表仍有效”
这一类问题。1.5.6 删除该指令匹配，恢复原工作区的通用 provider/payload 区分。

此前把 `e_machine` 看起来不是 AArch64 一概认定为错误架构输入，忽略了该字段自身
也可能被改写。已映射对象的这几个字节无法可靠证明原始代码架构，固定指令也无法
证明 linker 来源。对该输入，解析器应验证仍用于解析的结构，而不是识别某个补丁内容。

## 当前输入契约

| 检查 | 待加载文件 / 新 payload | ARM64 目标内的提供库候选 |
| --- | --- | --- |
| ELF 魔数、ELF64、小端及标识版本 | 必须有效 | 必须有效 |
| `e_ident[8..15]` | 保持既有处理 | 内容任意，不匹配指令 |
| `e_type / e_machine / e_version` | 必须为 ET_DYN / EM_AARCH64 / 1 | 允许任意覆写，不依赖原值 |
| `e_ehsize / e_phentsize / e_phnum / e_phoff` | 必须有效 | 必须有效 |
| PT_LOAD / PT_DYNAMIC、地址计算、哈希、动态/符号/字符串表边界 | 必须有效 | 必须有效 |
| 新 payload 的 TLS/重定位/ABI 等既有拒绝条件 | 保留 | 沿用既有 provider 语义 |

没有包名、库名或加固方案白名单。全零、随机/混合字节、不同跳板、单独改写身份字段
均遵循同一规则；结构损坏、ELF32/大端、读取失败和越界仍拒绝。

该规则只改变已映射 provider 的结构解析。框架仍支持 ARM64 目标，待加载 payload
仍要求 AArch64 文件。VMA 扫描不证明候选已经被 bionic 加载，也不恢复被覆写的原始
架构；不能把一次结构解析成功解释为 linker 来源或任意机器码的认证。

## 源码与内核兼容性

生产源码相对 1.5.5 只修改：

- `kclf_elf.c`：移除固定指令例外，只有 file/payload 模式检查 type/machine/version。
- `kclf_elf.h`：写明通用解析契约及其信任边界。
- `kclf_internal.h`：版本号变为 1.5.6。

未修改内核符号解析、私有结构偏移、BTF、task_work、mmap、GUP、VMA 迭代器或
EL0 指令生成。与 1.5.5 相比，新旧 KPM 的未定义导入符号集合相同。
提供库表的按需扩容、分配失败/4096 上限明确失败及统一释放处理保持不变。
未发现本次修改引入新的跨内核版本依赖。

## 构建

- WSL Ubuntu 24.04，AArch64 GCC 13.3.0，GNU Binutils 2.42。
- KernelPatch 头文件：`406c85ce79a5e1c19b53be34c04baadc1ec68bc5`。
- `make -B TARGET_COMPILE=aarch64-linux-gnu- -j4`，保留全部既有严格编译选项，通过。
- ELF64 little-endian AArch64 ET_REL，137328 字节。
- `kclf.kpm` SHA-256：
  `b34ba7754f79d3cb988f793e81dfe7b440df091adcb0186e5a5892a028345589`。

## 验证

### 主机

`make test`：11 组全部通过，C 测试使用 ASan/UBSan。

生产 ELF 解析器的新增/修订测试覆盖：

- 256 种重复字节覆写（包含全零），以及偏移 8–23 的逐字节变动。
- type、machine、version 独立改写；包括真实 ARM64 库可能被写成其他架构编号的情况。
- provider 仍能读取 SONAME、解析符号和得到正确函数地址；不合法 payload/file 均拒绝。
- 任意覆写后，坏程序头、段尺寸、动态指针、哈希、魔数、ELF32/大端仍拒绝。

### 设备

设备为小米 13 / fuxi / Android 13 / ARM64 / 4096 字节页，内核
`5.15.74-android13-8-00049-g8945ccdb2203-ab9500309`。

| 测试 | 结果 | 本地证据目录（KernelPatch 根目录下） |
| --- | --- | --- |
| 原生进程完整 manual 回归，含显式 linker 和四种真实提供库头覆写 | 176 项通过，0 失败，PASS | `build/kclf-manual-1c6c385011fc/` |
| 普通测试 App 完整 manual 回归，连续 10 次加载/释放 | 236 项通过，PASS | `build/kclf-app-f5c6584e5a1d/` |

新增夹具 `test/manual_rewritten_provider.c` 编译为真实 AArch64 DSO，先由目标正常
dlopen，再在自己的构造函数中分别执行全零填充、0xa5 填充、只改 machine、混合字节
四种头修改。随后 KPM manual 加载另一个 payload，后者必须从该 DSO 导入并调用函数、
读取导出数据，输出预期的 `13579bdf`，最后释放并确认手动镜像登记表为空。
四种场景均通过。这验证了真实提供库行为，不依赖特定指令序列。

两套设备回归未发现新增留存内核 BUG/WARNING/Oops/panic，普通测试 App 无新增
fatal signal/Java crash；boot ID 和 SELinux 状态不变，测试模块均安全排空并卸载。
证据的 KPM hash 与上述最终文件一致，密钥未写入源码或报告。

## 范围

本轮没有测试第三方 App；其旧版历史记录不作为 1.5.6 认证。其他 5.x/6.x 内核与
16K/64K 页设备未在本轮实测。11 组主机测试中的版本/ABI 模拟和大页 codegen 检查
不能替代对应设备的认证。原有依赖驻留、来源选择和 payload 生命周期限制仍适用。
