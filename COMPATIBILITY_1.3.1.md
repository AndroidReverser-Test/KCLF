# KCLF 1.3.1：兼容性修改与测试验收

日期：2026-10-28。基线：本子仓库 `f079e7c`（1.3.0）。

## 结论

本轮发现的无 BTF / Linux 5.10 兼容缺口已修复，最终同一份 1.3.1 模块在当前
Android 12、ARM64、5.10.66、4K 页设备上通过普通 App 完整回归（包含连续
100 次加载/卸载，706 项断言）及 native 回归（59 项断言）。这两个数字是断言数，
不是不同场景数。

不能据此宣布整个 Linux 5.x / 6.x 系列完成真机认证。其他版本目前只有源码核对、
兼容分支模拟和保存的 6.1 BTF 布局验证；旧版 1.3.0 的 6.1 测试不是新版验收。

没有新增包名、UID、签名、授权名单或目标类型等注入策略限制；保留原有架构、
寄存器状态和生命周期检查。未修改 KernelPatch 宿主，未更改设备 SELinux/seccomp，
未刷机、重启或清空测试 App 数据。

## 实现与本次修改

控制命令经 KPM `ctl0` 进入四槽请求表；请求固定 `struct pid` 身份，仅借用 `mm`
地址做身份核对，不为整个请求生命周期持有 `mm_users`。目标线程的 `task_work`
执行 ELF 检查、VMA/动态符号解析与映射准备，再保存并改写返回用户态的 `pt_regs`。
EL0 trampoline 保存 FPSIMD，调用目标自身的 Android linker，按选项调用 `dlclose`，
通过携带 cookie 的 `getpid` 完成自陷。完成 hook 恢复原寄存器，并安排目标上下文
cleanup 回收临时映射；`reap` 最后清理槽位。它不是内核直接执行用户 SO。

| 原问题 | 1.3.1 修改 | 验证 |
| --- | --- | --- |
| 无 BTF 时依赖未知 `task_struct.mm` 偏移，当前设备原版加载返回 `-95` | `kclf_task_mm()` 使用验证过的 BTF 偏移，否则 `get_task_mm()` 后立即 `mmput_async()`；不读取旧宿主可能不存在的新 offset 表成员 | 当前无 BTF 设备成功加载、注入、退出回收；主机检查引用平衡 |
| 无 BTF / 无 callable mmap lock 时无法扫描 VMA | 有完整 BTF/锁能力时保留 locked `find_vma`；否则在目标回调内打开 `/proc/thread-self/maps` | 当前设备实际使用 `proc_maps`；主机验证 direct 分支 |
| 一些 5.10 procfs 文件只有 `->read`，`kernel_read` 不支持 | 用 `vfs_read` 写入目标尚为 RW 的参数页，再经 `access_process_vm` 读取；不使用 `set_fs` 或猜测 `struct file` | 实际失败后修正；普通 App/native 均通过 |
| BTF 部分类型缺失导致整体失败 | mm、VMA、锁和寄存器布局分别选择 fallback；已有但不合法的 `pt_regs` 布局仍不冒险使用 | partial BTF、保存的 6.1 BTF、缺少锁/find_vma 的主机测试 |
| 错把所有 5.11 前内核都判为不支持 wake | 5.8 起使用已有的整数 `TWA_SIGNAL=2`；5.0–5.7 保留 bool ABI 的 `TWA_RESUME=1` | 5.10 普通 App 主/Binder/pipe-read 线程 wake；版本分支模拟 |
| VMA 获取错误可能被当成“映射已消失” | 区分 EOF/无映射与 I/O/解析错误，清理失败保留待回收状态 | 实际迭代函数注入错误测试 |
| maps 分片、长路径与边界缺少测试 | 新增可移植地址解析器及实际迭代函数测试 | 1/2/7/31/47/48/511/512 字节短读、3000 字节路径、无换行 EOF、溢出/空洞 |
| 旧 nofault 符号名称不同 | `copy_from_user_nofault` 缺失时查找 `probe_user_read` | 源码核对与构建；当前主用户内存路径仍为 `access_process_vm` |

临时区域仍为运行时页大小的 11 页：1 页 RX 代码、1 页 RW 参数、1 页 PROT_NONE
guard、8 页栈。先分配再解析 loader，为旧 procfs 提供真实用户缓冲；错误路径也走
统一回收。不会读取或维护 rb-tree/maple-tree 内部布局。

原有取消函数适配保留：优先 `task_work_cancel_match` / `task_work_cancel_func`，
最后才使用旧函数形态的 `task_work_cancel`。新版同名函数已改变参数和返回类型，
不能只按名称强转所有内核。参见 [Linux 6.12 task_work 实现](https://raw.githubusercontent.com/torvalds/linux/v6.12/kernel/task_work.c)。

## 内核兼容矩阵

| 内核范围 | 当前设计覆盖 | 本轮证据 | 状态 |
| --- | --- | --- | --- |
| 5.0–5.7 | bool task_work ABI；自然 resume；BTF 或 accessor/procfs | 5.0/5.4/5.7 标签的主机分支模拟、上游源码 | 未真机验证；没有 upstream wake ABI |
| 5.8–5.10 | 整数 TWA_SIGNAL；旧 procfs read；无 BTF fallback | 5.8/5.10 模拟；5.10.66 实际设备 | 仅表列 5.10.66 设备已通过 |
| 5.11–5.19 | TWA_SIGNAL、锁/VMA 双路径、取消函数探测 | 5.11/5.15 模拟和源码 | 未真机验证 |
| 6.x | 同上；通过内核接口抽象 maple-tree；BTF 验证/缺失 fallback | 6.1/6.6/6.12 模拟；保存的 6.1.134 BTF 真实布局解析 | 最终 1.3.1 未在 6.x 真机运行；未逐版核对全部 6.x |
| 16K / 64K 页 | 模块使用运行时页大小；App SO 链接采用 16K 段对齐 | 源码/构建检查 | 无设备验证，ELF 对齐不等于整机兼容 |

模块的版本范围判断不是能力证明。所有行仍依赖宿主提供 syscall wrapper/hook、
stack/thread 元数据、可解析的必需内核符号和 RCU accessor；厂商回移、裁剪、CFI/LTO、
隐藏符号以及自行修改的线程标志布局可能需要额外适配。procfs fallback 需要目标
上下文可读取自己的 `/proc/thread-self/maps`。不支持 32 位目标，原有 SVE/SME/跟踪
状态检查保持不变；完成所用 `getpid` 必须能通过目标自己的 seccomp 策略。

ABI 依据：旧 [5.7 task_work.h](https://raw.githubusercontent.com/torvalds/linux/v5.7/include/linux/task_work.h)
为 bool 参数，[5.8 task_work.h](https://raw.githubusercontent.com/torvalds/linux/v5.8/include/linux/task_work.h)
已包含 TWA_SIGNAL；[5.10 task_work.c](https://raw.githubusercontent.com/torvalds/linux/v5.10/kernel/task_work.c)
采用 JOBCTL_TASK_WORK，不能因尚未使用后来的 notify-signal 机制就一概禁用 wake。

procfs 路径依据：[5.10 read_write.c](https://raw.githubusercontent.com/torvalds/linux/v5.10/fs/read_write.c)
和 [task_mmu.c](https://raw.githubusercontent.com/torvalds/linux/v5.10/fs/proc/task_mmu.c)。
[seq_file.c](https://raw.githubusercontent.com/torvalds/linux/v5.10/fs/seq_file.c) 在复制给用户前
调用迭代器 stop，maps 迭代锁不会跨用户缓冲缺页复制一直持有。

## 代码规范审计与剩余风险

本轮改善了未经验证的结构偏移、必需/可选能力划分、资源错误传播、诊断、主机测试与
可重复的设备测试。严格编译和 sanitizer 测试通过，但这不构成“代码已无风险”的结论。

| 级别 | 剩余问题 | 影响/处理边界 |
| --- | --- | --- |
| P1 | 宿主 `unload_module()` 不尊重模块 exit 的错误返回 | exit 返回 `-EBUSY` 后仍释放模块代码；活动 task_work/hook 可能访问已释放代码。必须先 quiesce 到 idle，并串行执行控制和卸载。本轮验证了正确卸载流程，没有修改宿主，也没有故意执行可能导致内核崩溃的强卸载测试 |
| P2 | 控制面与回调共享状态的内存序尚未全面形式化 | `busy`、`completing`、`kclf_unloading` 等混用普通/volatile 和原子访问；`pending`/state/finished 已有引用与发布规则，但当前压力测试不证明所有竞态不存在。仍需 KCSAN/专门竞争测试及统一同步规则 |
| P2 | 用户态安全点只是启发式 | 任意异步插入可能遇到 malloc、ART、loader 或应用自己的锁；信号、其他线程 mmap/munmap 和 payload 逻辑不受框架控制，不能承诺任意构造函数无副作用 |
| P2 | 固定 8 页 payload 栈 | 当前简单构造函数足够；深调用、大栈或复杂 TLS/JNI 使用未充分覆盖，guard 只能发现越界，不能自动扩栈 |
| P2 | 多内核/硬件矩阵尚缺 | 当前只有一台连接设备；缺少其他 5.x、6.x、16K/64K、SVE/SME、特殊厂商内核的运行结果 |

同时修正文档中“构造函数再次 dlopen/dlsym 必然自死锁”的过度断言：
[AOSP bionic linker](https://android.googlesource.com/platform/bionic/+/refs/heads/main/linker/dlfcn.cpp)
使用递归 mutex，同线程重入不能直接等同于自死锁；跨线程等待和异步切入时的其他锁
依然有风险。本轮没有针对复杂重入 payload 做认证。

## 最终设备与产物

- 设备：Xiaomi rubens / 22041211AC，serial `LVLNINYXKR4L6HAE`。
- Android 12，ARM64；`5.10.66-android12-9-00001-gd262b276948e-ab8291727`。
- `page=4096`，无 BTF；`pt_regs=336`，`thread_size=16384`。
- 实际诊断：`vma_backend=proc_maps mm_access=get_task_mm`；`cancel=func`；
  `wake=task_work_signal`；`hook=getpid syscall_wrapper=1`。
- 普通测试 App UID 非 root，`untrusted_app`，`Seccomp: 2`；SELinux 始终 Enforcing。

最终模块：[kclf.kpm](kclf.kpm)，66,352 字节，SHA256：

```text
B5483B9384A6D79795B9322FF3C02A621FB81421B5E7931D964090BAFC0FBC66
```

最终安装测试 APK：[app.apk](../../build/kclf-20261028-5x/app/app.apk)，21,192 字节，SHA256：

```text
0477473DD3ADF3FF0D6B362DF9AA43973B6833228F29A131A5D44F899E660E17
```

严格全量重编译后的模块 hash 与两套最终设备测试记录一致。`nm -u` 未发现运行时 libc /
outline atomic 依赖；trampoline 对象无 relocation。测试 App 使用持久 debug keystore，
可原地覆盖安装，不卸载或清数据；每次构建使用独立 staging 目录并验证 APK 签名。

## 最终测试证据

| 测试 | 结果 | 证据 |
| --- | --- | --- |
| 普通 App 完整回归，`-Repeat 100` | 706 PASS，脚本退出码 0 | [results.txt](../../build/kclf-app-046a6a731e8b/results.txt) |
| native 完整回归 | 59 PASS，脚本退出码 0 | [results.txt](../../build/kclf-test-02b1ae6da4b3/results.txt) |
| ASan/UBSan 主机辅助函数、maps、compat、BTF | 全部通过，退出码 0 | [host-final-tests.txt](../../build/kclf-20261028-5x/host-final-tests.txt) |
| 全量严格构建 | `-Wall -Wextra -Werror -Wformat=2 -Wframe-larger-than=2048` 通过 | [module-build.txt](../../build/kclf-20261028-5x/module-build.txt) |

普通 App 测试实际覆盖：主线程 wake、Java sleeper 自然 resume、Binder wake、
四个 pipe-read 线程排队/取消/满槽/重复请求、阻塞线程 wake、指定 PID/TID 的构造函数
marker、FPSIMD 哨兵恢复、SO 驻留、dlclose 后 SO 映射消失、缺失 SO 与截断 ELF
失败恢复、100 次连续加载/卸载、完成未 reap/排队中/构造函数运行中强停、旧进程退出与
新进程启动、RX 代码/PROT_NONE guard/11 页区域完整回收、busy quiesce 后完成和模块重载。

最后三次重启的 Activity `TotalTime` 为 215/208/226ms；旧 PID 逐一消失并换成新 PID。
测试最后无请求、`loading=0`、`quiesce=idle`，模块已卸载；APK、测试 marker 和最终
App 进程保留（验收时 PID 21678）。boot ID 仍为
`54291ce0-bc87-4675-bbee-ee7be81366ba`。未发现新增测试 App crash，保留的内核日志中
未出现新增 BUG/WARNING/Oops/panic；这不等同于覆盖日志环形缓冲之外的所有历史事件。

### 保留的失败记录

最终模块的首轮 100 次复测在强停后的 `LaunchState: COLD` 断言处停止，
[失败记录](../../build/kclf-app-2f2b8fe0ff09/results.txt) 未删除。
[ActivityManager 日志](../../build/kclf-app-2f2b8fe0ff09/activity-process-lifecycle.txt)
显示旧进程 19428 被杀死，替代进程 19498 在 shell 的 `am start` 前已由系统创建，
所以该次 UI 启动被分类为 WARM。没有观察到该轮新增测试 App crash 或内核 fault。

测试脚本随后改为检查 `/proc/<旧PID>` 消失、启动成功以及新 PID 不同，不再把 UI
分类当作进程是否真正重建的依据；之后对同一模块/APK 重跑全套，得到上面的 706 PASS。
更早的开发中间产物结果不计入最终验收数。

## 复现

WSL/Linux（从仓库根目录）：

```sh
make -B -C kpms/kclf TARGET_COMPILE=aarch64-linux-gnu- -j4 \
  CFLAGS="-Wframe-larger-than=2048 -Wformat=2"
python3 kpms/kclf/test/test_helpers.py
python3 kpms/kclf/test/test_maps.py
python3 kpms/kclf/test/test_compat.py
# 可选：test_compat.py 末尾传入保存的设备 vmlinux BTF
gcc -std=c11 -Wall -Wextra -Werror -fsanitize=address,undefined -g \
  kpms/kclf/test/test_btf.c -o /tmp/kclf-test-btf
/tmp/kclf-test-btf
```

PowerShell；两套设备测试应串行运行，测试开始前不能加载同名 kclf：

```powershell
./kpms/kclf/test/app/build.ps1 -SdkRoot D:\androidSDK `
  -NdkRoot D:\androidSDK\ndk\27.0.12077973 -Platform android-36
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' `
  -Apk 'E:\KernelPatch\build\kclf-apptest\app.apk' -Repeat 100
./kpms/kclf/test/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>'
```

脚本只操作测试 App、测试 native 目标及本次加载的模块；失败时尝试安全排空，不强行
卸载仍有活动回调的模块。实际 superkey 不保存在源码、文档或测试结果中。
