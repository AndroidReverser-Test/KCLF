# KCLF 1.4.2/1.4.3 防检测改造：计划与进度

文档日期：2026-10-30（Asia/Shanghai）。
状态：**1.4.2 的随机跳板/完成池/布局/manual 镜像加固与 1.4.3 的静态标记清理已完成；
真机回归通过；本节最后更新于 1.4.3。**
工作区：`E:\KernelPatch`，模块目录 `kpms/kclf`（未提交 git）。

---

## 1. 背景与目标

`kpms/kclf` 是 Android ARM64 上的 KernelPatch 模块，在目标线程下一次返回用户态时
重定向 `pt_regs`，用 EL0 程序在目标进程里完成 manual/linker 两种后端的加载。

`OBSERVABILITY_REPORT.md`（1.4.1）在真机上确认了两种普通 App 可用的检测方法：

- 方法 A：对 `getpid` 安装 `SECCOMP_RET_TRAP`，用 SIGSYS 现场 PC 减去固定偏移
  （544）得到页对齐代码基址，再逐字节比对 548 字节跳板、解码 movz/movk 参数指针、
  核验参数页前缀已清零。
- 方法 B：利用已知 payload 的 ELF 头在匿名可读映射**起点**、各 `PT_LOAD` 内容
  逐字节相同、且不在 `dl_iterate_phdr` 中，确认“已知 payload 的手动驻留镜像”。

本次改造目标：**让上述两个检测点不再产生阳性，同时保持注入功能、
manual/linker 后端、生命周期和既有控制接口语义不变**，并如实记录仍无法隐藏的
残余可观测面。明确不追求“不可检测”的表述。

---

## 2. 总体计划

| 阶段 | 内容 | 状态 |
| --- | --- | --- |
| P1 | 用“每次请求生成的随机 EL0 程序”替换固定 `kclf_tramp.S` 跳板 | 完成 |
| P2 | 把完成自陷从固定 `getpid` 改为随机候选系统调用池 + 重试 + EL0 恢复 | 完成 |
| P3 | 随机化临时映射布局（代码/参数/私有页/guard/栈） | 完成 |
| P4 | manual 镜像：随机前导 pad 让 ELF 头不在任何 VMA 起点；默认擦除 ELF 头/程序头 | 完成 |
| P5 | 新增 `keepelf` 兼容选项、`status`/`probe`/`images` 诊断字段 | 完成 |
| P6 | 真机验证：加载/注入/FPSIMD/unload/release/重试/EL0 恢复/观测夹具 | 完成 |
| P7 | 更新 `test/observability`（已重写）与 `test/app/device-test.ps1` 布局断言 | 完成 |
| P8 | 文档更新（README、观测报告、manual loader、测试说明） | 完成 |
| P9 | 清理（删除 `kclf_tramp.S`、最终 clean 构建、哈希复核、diff review） | 完成 |
| P10 | 1.4.3 追加加固（bail token、加密 mprotect 号、随机重启指令、随机块顺序/填充、`RESIDUAL_TAG`） | 完成 |

---

## 3. 已完成的具体修改

### 3.1 新增 `kclf_codegen.h` / `kclf_codegen.c`（约 700 行）

替代固定跳板，内核在目标上下文按请求生成 AArch64 程序：

- **代码页**：先填满随机 32 位字，不再用零字节围出固定 blob。
- **随机入口**：入口偏移 16–128 字节、16 字节对齐；完成 `svc` 偏移随之变化，
  `pc - N` 类锚点失效。
- **随机寄存器角色**：参数页基址、私有页基址、向量游标、计数、返回码、
  三个临时量、候选游标、cookie 共 10 个角色随机映射到 `x19`–`x28` 的随机置换；
  不使用 `x18`/`x29`。
- **随机 FPSIMD 布局**：32 个 q 寄存器随机配对、随机槽位顺序保存/恢复；
  FPCR/FPSR 使用随机临时寄存器；栈帧仍为 528 字节。
- **随机填充指令**：多个安全点插入 0–5 条 `movz/movk/add/eor/nop` 等，
  只写死临时寄存器。
- **参数页地址**用完整 movz/movk 序列生成。
- **完成协议**：只有一个 `svc` 站点；`x8` 运行时从私有参数页读取并与每请求
  32 位 key 异或，代码中没有字面系统调用号；候选数量与顺序由内核写入。
- **重试**：若完成系统调用未被内核消费（被 seccomp 转信号、或旧宿主未支持
  skip），EL0 继续下一个候选。
- **EL0 恢复（应急）**：全部候选失败时写 `KCLF_BAIL_MAGIC`，从私有页恢复
  `x0`–`x30`、`sp`、`pc`、NZCV 并跳回被中断 PC，避免挂死；`x16`（IP0）
  是该路径唯一不恢复的寄存器，已在文档中注明。
- 新增私有参数页布局常量 `KCLF_PV_*`（保存寄存器、NZCV、bail marker、
  候选 key/count/list、结果暂存），与 ABI 参数页分离，避免被擦除。
- 宿主侧自检 `test/test_codegen.c`：生成 8 个种子、检查结构不变量并输出
  二进制供 `aarch64-linux-gnu-objdump` 人工复核（已复核通过）。

### 3.2 `kclf_exec.c`

- `kclf_exec_prepare` 重写：
  - 随机布局 `[RX code][gap 0–1 页][RW ABI 参数页][RW 私有页]
    [PROT_NONE guard][RW 栈 6–14 页]`；gap 页填随机数据；
  - 调用 `kclf_prog_build` 生成程序并写入代码页；
  - 记录 `entry_pc`、`compl_pc`；
  - 把随机候选系统调用列表（异或 key）写入私有页；
  - 代码页 `mprotect(RX)`、guard `mprotect(PROT_NONE)`、刷新 icache。
- 新增完成候选池（`kclf_compl_pool`）：
  `read(63) / write(64) / futex(98) / clock_gettime(113) / ioctl(29) /
  epoll_pwait(22) / nanosleep(101) / sched_yield(124)`；
  每请求随机选 2–3 个不同候选。**刻意排除 `getpid`/`gettid`/`getuid` 等
  信息类调用**（探测器可无副作用 trap 的集合）。
- 新增 `kclf_pick_completion()` / `kclf_export_completion()`。
- `kclf_exec_hijack`：新增 `kclf_export_saved()` 把原始寄存器文件写入私有页，
  供 EL0 恢复路径使用；入口 PC 改为 `r->entry_pc`。
- 完成候选在参数错误时均在触碰用户内存前失败（EBADF/EFAULT/EINVAL），
  即使 hook 未消费也无真实副作用。
- 保留 `kclf_exec_restore()`（正常完成路径的 ERESTART 处理不变）。

### 3.3 `kclf.c`

- 删除 `kclf_getpid_before/after`，改为 `kclf_completion_before/after`，
  对候选池全部 8 个系统调用注册完成 hook；
  - 匹配条件：`pc == r->compl_pc`、`x0 == cookie`、`x8` 属于本请求候选列表、
    `current` 的 mm 等于请求 mm；
  - 命中后 `skip_origin`/`ret` 语义与 1.4.1 相同；正常路径仍由
    `kclf_exec_restore()` 恢复寄存器并排队 cleanup。
- 新增 `kclf_completion_bailed()`：目标下一次进入候选系统调用时，如果私有页
  有 bail marker，则读取结果、标记 `state=done`（`err` 说明完成被阻断）、
  递减 `loading` 并用 `TWA_SIGNAL` 强制排空 cleanup（避免目标正阻塞在
  `epoll_pwait` 时无法回收）。
- hook 安装改用 `hook_syscalln`（见“风险与注意”：设备宿主较旧，不导出
  `hook_syscalln_override`）；`skip_origin` 在新宿主上仍会被尊重。
- 新增 `keepelf` 注入选项；`status` 增加 `compl=`、`hdr=`；
  `probe` 输出 `hook=random syscall_wrapper=1 pool=8`；`images` 增加 `hdr=`。
- `kclf_exit` 统一走 `kclf_hook_remove()`。
- 版本号 `KCLF_VER` 改为 `1.4.2`。

### 3.4 `kclf_manual.c`

- `map_image()`：映射长度增加 `1–8` 页随机 pad，`bias` 相应按 ELF 对齐上取整；
  记录 map/length 不变，回滚路径不变。
- `protect_image()`：pad + 对齐空洞使用第一个 `PT_LOAD` 的相同权限
  `mprotect`，由 `vma_merge` 合并，使 ELF 头页位于 VMA 中间而非起点。
- 新增 `scrub_headers()`：默认擦除 ELF 头 64 字节与程序头表；
  仅在头页范围内、长度受限时执行；`keepelf` 时跳过。
- 镜像结构新增 `hdr_kept`，请求新增 `image_hdr_kept`，`images`/`status`
  显示 `hdr=kept/scrubbed`。
- 其余依赖解析、重定位、RELRO、构造/析构、引用计数逻辑未改。

### 3.5 其他源码/构建

- `kclf_internal.h`：新字段、常量、extern；移除 `codebuf`/`KCLF_CODE_MAX`。
- `kclf_param.h`：更新注释，移除 `KCLF_COMPLETION_NR`。
- `Makefile`：`kclf_tramp.o` → `kclf_codegen.o`。
- `kclf.kpm`：已重新构建（当前 SHA-256
  `e88b717398cc196dcc2ebe3b9c27c8de13c25275eece192b47838908e1c1f8a9`）。

### 3.6 测试与验证夹具

- `test/observability/probe.c` 重写：
  - `KNOWN_MANUAL`：1.4.1 方法 B 原规则（区域起点 + 完整 ELF 头 + 覆盖 +
    未登记 linker）；
  - `KNOWN_HEADER`：更强的页级扫描（匿名可读、非可写内存中任意位置找完整
    已知 ELF 头）；
  - `RESIDUAL_TEXT`：不需要 ELF 元数据，扫描匿名 RX 中的已知 `.text` 签名
    （驻留期预期命中，作为残余面证据）；
  - syscall guard：对 10 个信息类调用安装 `SECCOMP_RET_TRAP`，按现场 PC
    是否在预采集的“文件后端可执行映射”中分类为 `file` / `unexpected`；
    匿名 stub 的 100 次 getpid 作为 guard 有效性对照；
  - 扫描器带游标/预算/最大 1024 个已知代码区间，跳过夹具自身参考副本；
  - `maps` 解析容忍超长路径行。
- `test/observability/run.py` 重写：
  - 验证基线、三类规则、guard 100/100、manual/linker × 驻留/unload、
    `keepelf`、残余文本命中落在 KPM `resident=` 范围内、完成候选列表变化、
    清理后 `kpm num=0`、boot ID/SELinux 未变；
  - 不再依赖 `kclf_tramp.S` 参考字节。
- `test/app/device-test.ps1`：probe 断言从 `hook=getpid` 改为 `hook=random`
  （已完成）；临时映射的固定布局断言尚未改（见第 5 节）。

### 3.7 文档

- 新增 `OBSERVABILITY_HARDENING_20261030.md`：加固设计、真机验证结果、
  残余暴露、兼容边界、产物哈希。
- `README.md`、`OBSERVABILITY_REPORT.md`、`MANUAL_LOADER.md`、
  `test/observability/README.md` 尚未更新（见第 5 节）。

---

## 4. 已完成真机验证

设备：Redmi rubens，Android 12 / API 31，ARM64，Linux 5.10.66，4 KiB 页，
SELinux Enforcing；`/data/local/tmp/kpatch Test6666` 控制。

### 4.1 模块与注入

- 模块加载成功；`probe`：`hook=random syscall_wrapper=1 pool=8`。
- manual 后端：`state=done ... via=manual compl=<随机列表> image=1 refs=N
  resident=... hdr=scrubbed`；payload 构造 marker 存在。
- linker 后端：`via=__loader_dlopen`；`unload` 时 `by=__loader_dlclose`。
- `unload` 模式：`unload=ok rc=0`，构造/析构 marker 均存在。
- 连续 14 次不同线程注入全部 `state=done`；完成候选出现
  `98,113,29`、`29,124`、`113,63,29`、`63,98`、`101,98` 等多种组合。
- 对 `kclf-fp` 线程注入后 `fp_<pid>` 持续 `fp-state-failure=0`（FPSIMD 保持）。
- 引用释放 15 次后 `images` 为空、`reap` 清空、`quiesce=idle`、卸载成功。

### 4.2 编译期自检（同一源码）

- `-DKCLF_TEST_COMPLETION_FIRST_MISS`（第一次候选必然未被消费）：
  `compl=174,101`，第二次候选完成，`state=done`，进程继续运行。
- `-DKCLF_TEST_COMPLETION_ALL_MISS`（全部候选失败）：
  `compl=174,174`，EL0 写 marker 并恢复寄存器返回；目标下一次候选系统调用时
  内核回收临时映射，`state=done` 且
  `err="completion blocked; EL0 restored the original register file"`，
  进程/线程继续运行，镜像正常驻留（refs=1）。

### 4.3 观测夹具（`run.py --rounds 2`，14 个 case）结果：**passed**

证据目录：`build/kclf-observability-f9f49af39e98/`。

| 用例 | 结果 |
| --- | --- |
| 无 KPM：plain / guard / normal 基线 | 无旧规则阳性；guard 匿名 stub 100/100 被 trap |
| guard：manual 驻留 / manual unload / linker 驻留（各 2 次） | 全部 done；`kind=unexpected` 0；`KNOWN_MANUAL`/`KNOWN_HEADER` 0；init/fini marker 存在；App 未退出 |
| plain：manual 驻留（2 次） | `hdr=scrubbed`；两个头规则 0；`RESIDUAL_TEXT` 命中且在 resident 范围内 |
| plain：manual `keepelf`（2 次） | `hdr=kept`；`KNOWN_MANUAL` 0（VMA 起点锚点失效）；`KNOWN_HEADER` 命中（页级扫描仍有） |
| 完成候选随机性 | 至少两种组合：`113,22,64`、`64,22,101` |
| 清理 | `kpm num=0`、测试包卸载、boot ID/SELinux 不变 |

产物哈希：

- KPM：`e88b717398cc196dcc2ebe3b9c27c8de13c25275eece192b47838908e1c1f8a9`
- 观测 APK：`b6bff55911b11673e16bc504fba4b6c877b763622cad75b3ebb917d30bdc6b73`
- 参考 payload：`1aca043f7c8cdb3856495c6aaedfa9bd03d9dad01cfc6cacb66f5e62a452a651`
  （与 1.4.1 相同，说明检测规则未变、变的是被观测对象）

### 4.4 App 回归（`test/app/device-test.ps1`）

重新构建的测试 APK（当前源码，含 kclf-fp/kclf-idle 线程）后已通过：

- 模块加载、probe 断言；
- 主线程 / Java sleeper / Binder 线程 linker 注入 + `dlclose` + marker +
  映射回收；
- FPSIMD sentinel 构造器破坏后 q0/q8/q31 + FPCR/FPSR 恢复；
- 四线程排队、重复请求、满槽、取消、reap；
- 缺失 SO、截断 ELF 的失败恢复；
- 连续加载/卸载；
- 完成未 reap / 排队中 / 构造函数中 force-stop 的旧进程退出与新进程启动；
- 运行中 target 死亡释放 loading 计数；
- `quiesce` 清理。

**当时的唯一失败点**：`CASE: transient mapping/guard and busy quiesce` 之后的
断言仍按 1.4.1 固定布局检查，不是功能回归；断言之前执行的 case 全部 PASS。
1.4.3 已把该断言改为随机布局检查并重跑通过（见 7.1）。

### 4.5 主机侧辅助测试

`test_helpers.py`、`test_maps.py`、`test_compat.py`、`test_manual_elf.py`、
`test_provider.py` 全部 PASS。`test_btf.c` 需要真实 vmlinux BTF，本次未运行。

---

## 5. 未完成事项（按优先级）

1. ~~更新 `test/app/device-test.ps1` 的临时映射断言~~：已完成。断言改为从运行期
   `status` 读取 `map/code/guard`，再用 maps 验证：恰好一个 RX 页在随机 code
   偏移、恰好一个 `---p` 页在随机 guard 偏移、栈紧接 guard 之上、无 `rwxp`、
   总大小 10–25 页。
2. ~~删除 `kclf_tramp.S`~~：已完成（`git rm` 并删除 `.o/.d`）。
3. ~~更新 `README.md`~~：已完成（1.4.3、随机跳板/完成池/EL0 恢复/keepelf、
   seccomp 候选、检测边界、测试入口）。
4. ~~更新 `OBSERVABILITY_REPORT.md`~~：已在开头加 1.4.2/1.4.3 说明，声明第 4/5 节
   两种方法对当前版本不再适用，指向加固报告与新夹具。
5. ~~更新 `MANUAL_LOADER.md`~~：已更新随机 pad、ELF 头擦除、`keepelf`、
   `hdr=`/`compl=` 字段和 1.4.2/1.4.3 加固小节。
6. ~~更新 `test/observability/README.md`~~：已更新四条内容规则 + syscall guard、
   预期结果、guard 分类原理、残余文本扫描的意义。
7. ~~最终 clean 构建~~：已完成；clean 构建与增量构建哈希相同
   （`9c12b67088215f88078d4092e75941851aa7683862d635ede219605c4d412890`）。
8. ~~回归复跑~~：已完成。`run.py --rounds 3` 与
   `device-test.ps1 -Repeat 2` 均通过，结果见第 9 节。
9. ~~diff review~~：已确认旧布局注释、`kclf_tramp.S` 引用和调试打印清理完毕。
10. `KCLF_TEST_COMPLETION_*` 自检宏保留为维护开关，已在加固报告中说明。

---

## 6. 风险、兼容性与注意事项

1. **旧宿主 ABI**：设备上的 `/data/local/tmp/kpatch` 比当前源码树旧，
   不导出 `hook_syscalln_override`（模块加载时报 unknown symbol）。
   已改用最老的 `hook_syscalln`：新宿主上 `skip_origin` 仍生效，旧宿主上
   完成系统调用会真实执行一次，但参数设计为 EBADF/EFAULT/EINVAL，
   不触碰用户内存。若未来只面向新宿主，可恢复 `hook_syscalln_override`
   以获得“从不执行”语义。
2. **完成候选被全部 trap**：目标 App 若对 `read/write/futex/clock_gettime/
   ioctl/epoll_pwait/nanosleep/sched_yield` 全部安装 trap/kill，EL0 会走恢复
   路径返回，不会挂死；KPM 在目标下一次候选调用时回收映射并报告
   `completion blocked`。该场景下注入的构造函数已经执行，镜像按成功驻留
   处理（handle/errptr/rc 由私有页带回）。
3. **EL0 恢复路径**：`x16` 不恢复（IP0，ABI 调用者保存）；`pstate` 只恢复
   NZCV（其他位在跳板中未被修改）。这是应急路径，正常完成路径仍由内核
   `kclf_exec_restore()` 精确恢复完整 `pt_regs` 并处理 ERESTART。
4. **ELF 头擦除**：依赖 `__ehdr_start`/自行解析程序头的 payload 需要
   `keepelf`；C++ 异常展开、payload TLS/IFUNC 本来就未实现。
5. **残余可观测性**：payload 的可执行内容在驻留期仍可被本进程按内容扫描
   （夹具 `RESIDUAL_TEXT` 实测），临时映射存在性、时序、payload 自身行为
   也仍可见。本次只消除 1.4.1 使用的两个稳定锚点，不改变“内容可读”事实。
6. **测试夹具注意**：
   - guard 捕获的 `getpid` 来自 libc 时 PC 在文件后端映射中，分类为 `file`；
     payload 自己调用 `getpid/gettid` 也会被 trap，同样分类为 `file`，
     不计为 `unexpected`；
   - bionic 可能缓存 `getpid` 结果，负对照的 100 次 libc 调用未必产生
     100 次 trap；guard 有效性以匿名 stub 的 100/100 为准；
   - `build/kclf-apptest/app.apk` 曾经是 2026-10-28 的旧构建（不含
     kclf-fp/kclf-idle 线程），已用 `build.ps1` 重建；以后改 `test/app/jni`
     后必须重建 APK。
7. **未覆盖**：16 KiB/64 KiB 页、无 syscall wrapper 的宿主、SVE/SME 目标、
   其他 Android 版本/内核均未实测；结论仅限本机 Android 12 / 5.10.66 /
   4 KiB / ARM64。

---

## 7. 复现与证据

```powershell
# 构建 KPM
wsl -d Ubuntu-24.04 bash -lc "cd /mnt/e/KernelPatch && make -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4"

# 主机侧生成器测试（结构检查；产物可 objdump 复核）
wsl -d Ubuntu-24.04 bash -lc "cd /mnt/e/KernelPatch/kpms/kclf && gcc -std=c11 -Wall -Wextra -Werror -g -DKCLF_CODEGEN_HOST -I. test/test_codegen.c kclf_codegen.c -o /tmp/test_codegen && cd /tmp && ./test_codegen"

# 观测夹具（普通 App，需环境变量传 superkey）
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
python kpms/kclf/test/observability/run.py --serial LVLNINYXKR4L6HAE --rounds 3
Remove-Item Env:KCLF_SUPERKEY

# App 回归（会安装/停止测试 APK）
powershell -ExecutionPolicy Bypass -File kpms/kclf/test/app/device-test.ps1 `
  -SuperKey <KEY> -Serial LVLNINYXKR4L6HAE -Apk build/kclf-apptest/app.apk -Repeat 2
```

证据目录（1.4.3）：

- `build/kclf-observability-0067e4513c69/`：`--rounds 2` 通过的观测夹具
  （`summary.json`、`probe.txt`、逐 case events/status/payload）。
- `build/kclf-observability-218be64b3fb7/`：最终 `--rounds 3` 运行（19 个 case，
  `result=passed`）。
- `build/kclf-app-e16319480ea0/`：`-Repeat 2` 通过的 app 回归运行记录。
- `build/apptest-regression-1.4.3.log`、`build/obs-run-1.4.3b.log`：
  本轮控制台输出。
- `OBSERVABILITY_HARDENING_20261030.md`：加固设计/验证/残余面的正式报告。

---

## 7.1 1.4.3 追加修改（本轮）

### 7.1.1 源码

- `kclf_codegen.h` / `kclf_codegen.c`：
  - 私有页布局重排：`HANDLE/ERRPTR/RC` 移到 `0x160/0x168/0x170`，新增
    `BAILTOK`（`0x178`）和 `MPROT`（`0x180`），修复候选列表 16 项与结果字段
    的重叠；`PV_SIZE` 改为 `0x188`。
  - 删除 `KCLF_BAIL_MAGIC`。EL0 恢复路径从私有页读取每请求随机 token 写入
    bail 槽；内核按 token 匹配。
  - 延迟 RELRO 的 `mprotect` 系统调用号改为 `MPROT ^ NRKEY`，代码中无立即数。
  - 入口前的重启填充指令随机化（nop/movz/eor/add/orr），不再固定 `b .+0`。
- `kclf_exec.c`：
  - 临时映射的四个块随机排序，块间插入 0–2 页填充页；总大小 10–25 页。
  - 新增 `kclf_fill_random()`；映射后先随机填充，参数页/私有页/栈页不再零填充。
  - `kclf_pick_completion()` 生成随机 `bail_token`；`kclf_export_completion()`
    写入 token、加密 mprotect 号并随机填充私有页尾部。
  - 参数页随机填充后显式清零 `KCLF_P_MANUAL`，修复 linker 请求被随机值送入
    manual 路径的问题（真机验证中发现）。
- `kclf.c` / `kclf_internal.h`：
  - 版本 1.4.3；`status` 增加运行期 `code=`/`guard=`。
  - bail 判断改为 `bail == r->bail_token`。
- `test/test_codegen.c`：检查随机重启指令形态，并确认生成页中无 `KCLFBAIL`。
- 删除 `kclf_tramp.S`、`kclf_tramp.o`、`kclf_tramp.d`。
- `test/observability/probe.c` / `run.py`：新增 `RESIDUAL_TAG` 规则与断言。
- `test/app/device-test.ps1`：临时映射断言改为运行期 `map/code/guard` + maps
  关系检查。

### 7.1.2 验证

- 主机侧生成器自检：8 个种子全部 `ok`，重启指令均为随机安全指令、无固定 tag。
- clean 构建：`kclf.kpm` SHA-256
  `9c12b67088215f88078d4092e75941851aa7683862d635ede219605c4d412890`。
- 观测夹具 `--rounds 3`：19 个 case 全 PASS（`result=passed`，证据
  `build/kclf-observability-218be64b3fb7`）；`RESIDUAL_TAG=0`；
  `RESIDUAL_TEXT` 仍按预期命中 resident 范围；完成候选出现
  `63,113`、`98,29`、`113,124,22` 等组合。
- App 回归 `-Repeat 2`：全部 case PASS（证据
  `build/kclf-app-e16319480ea0`），包括新的随机布局断言、运行中 force-stop、
  FPSIMD、取消/满槽、失败恢复和最终 `quiesce=idle` 卸载。
- 构建期自检（1.4.3，`CFLAGS=-DKCLF_TEST_COMPLETION_*`）：
  `FIRST_MISS` 得到 `compl=174,29`、`state=done`；
  `ALL_MISS` 得到 `compl=174,174,174`、`state=done` 且
  `err="completion blocked; EL0 restored the original register file"`，
  目标进程存活并在 `unload` 后正常排空。per-request bail token 的 EL0
  恢复路径已实测。

### 7.1.3 剩余

- 源码未提交 git。
- 已知 payload 的驻留内容仍可被本进程按内容扫描（`RESIDUAL_TEXT`）；ARM64
  没有 execute-only 页，代码可执行即必然可读，本版本不改变这一事实。
- 对“trap 所有系统调用并检查现场 PC 是否在匿名可执行内存”的更强探测器，
  正常完成路径仍会暴露一次来自临时代码页的系统调用；当前候选池只保证普通
  探测器无法在不破坏自身的情况下 trap 它。这一残余面已在加固报告中记录，
  不在本轮消除范围内。

---

## 8. 当前状态速览

| 项目 | 状态 |
| --- | --- |
| 随机跳板生成器 | ✅ 1.4.2 实现并真机验证（含重试/EL0 恢复自检）；1.4.3 去掉固定 bail 标记 |
| 随机完成系统调用池（无 getpid） | ✅ 实现并验证 |
| 临时映射随机布局 | ✅ 1.4.2 随机块长度；1.4.3 随机块顺序/填充页/随机数据 |
| manual 镜像 pad + ELF 头擦除 | ✅ 实现并验证（含 keepelf 对照） |
| 观测夹具重写与通过 | ✅ `--rounds 2` 与 `--rounds 3` 均 passed，新增 `RESIDUAL_TAG` 规则 |
| App 回归 | ✅ 1.4.3 已更新布局断言并通过（见 7.1） |
| README / 观测报告 / manual loader / 测试说明 | ✅ 已更新到 1.4.3 |
| 删除 `kclf_tramp.S` / clean 构建 | ✅ 已删除并从 git 移除；clean 构建哈希已复核 |
| git 提交 | ⏳ 未提交（工作区改动保留） |
