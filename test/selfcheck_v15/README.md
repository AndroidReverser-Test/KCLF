# KCLF 普通 App 自检真机验证

本夹具只验证被注入进程自身的检测能力，不跨 UID 读取其他 App，不修改注入器。
测试包为 `com.kclf.selfcheckv15`。

## 1.5.1 结果（2026-10-31）

最终构建：KPM SHA-256
`fa378fcdeece9725b61d10ae89c4a4133c43c52e5200d440fd1057c9fc4450b8`。
`--suite full --rounds 5` 共 45 个用例：

| 项 | 1.5.0 | 1.5.1 |
| --- | ---: | ---: |
| detections | 45/45（每例 2 事件） | **0/45** |
| 完成路径 | libc `nanosleep`/`openat` 完成调用 | 45/45 `done=syscall` |
| 构造函数/析构函数 | 45/45 | 45/45 |
| 目标存活 | 45/45 | 45/45 |
| 清理 | `quiesce=idle`、`kpm num=0` | `quiesce=idle`、`kpm num=0` |

基线 observe/denyexec 各 1800 次合法调用仍全部被过滤器观察、detections=0；
注入后各用例 1800 次对照调用无阳性。本夹具的 `completion_match()`（72 字节结构、
`[sp,#0x80]` 私有页指针、x6/x7 cookie、libc 入口）没有改动；1.5.1 只是不再产生
它要匹配的完成 syscall/libc 帧，因此检测器看到的是普通 payload/目标调用现场。

另用 `CFLAGS=-DKCLF_TEST_NO_TOKEN_HOOK` 构建（SHA `5ea0faf7…`）跑 pilot：
`constructor_ran=true`、`finalizer_ran=true`、`framework_done=true`、
`done=poll`，证明控制器 poll 路径可独立收尾。

证据：

- `build/kclf-selfcheck-bd20c95e8a63/`（full，45/45 detections=0）
- `build/kclf-selfcheck-d1e2ffc81c6c/`（poll 路径）

## 1.5.0 基线（历史）

日期：2026-10-30（Asia/Shanghai）。1.5.0 **仍有可稳定复现的事件检测点**：
完成 syscall 的 SIGSYS 上下文可以经 libc 栈帧取得跳板返回地址，核验 72 字节调用
结构（其中末尾 56 字节固定），再从栈槽找到私有页，交叉核验 cookie、libc 函数地址
和参数。这不是只凭匿名 RX、系统调用号或 payload 字符串报警。

但是，**本检测发生在构造函数之后，不是首次执行前的拦截**。
检测后退出进程可以停止后续运行，不能撤销已经执行的代码或副作用。
1.5.0 没有证明不存在其他事前防护方法，也没有证明能防住任意内核级对手。

> 以下“环境与精确产物”“完整测试结果”“检测机制与观察干扰”等小节均为 1.5.0
> 基线记录，不是 1.5.1 验收；1.5.1 结果见本文开头。

## 环境与精确产物

- Android 12，ARM64，Linux 5.10.66，4 KiB 页，SELinux Enforcing。
- KCLF 提交：`ad1a5903a61da159d3735e7a20422c9b140a56fc`。
- 原样加载工作区 `kclf.kpm`，没有重新构建或修改模块。
- KPM SHA-256：`f272f9cc5bd83a17ceec8a2de67d2105409af172269a35c0ef7a8fe87165e106`。
- libc SHA-256：`30368f441c546a8b622f060d7ac4e0e67db1ed47db104bdf1887f194ac3f48e8`。
- 测试 APK SHA-256：`c46deafd225a922f26cd6e715517a410079afc710a03ded76dd3919fc5334a8b`。
- 测试 App：non-debuggable，`dumpable=0`，`CapEff=0`，`untrusted_app`，
  继承 zygote seccomp；主线程安装附加过滤器时 TSYNC 成功。
- root 只用于安装、KPM 控制和收集 App 自己写出的日志。检测器不使用 superkey、
  KPM 状态、root、ptrace 或 `/proc/self/mem`。

## 完整测试结果

原始证据目录：工作区 `build/kclf-selfcheck-0b55c0844795/`。
`summary.json` 含每个用例、产物哈希、控制命令和清理结果；各用例有独立事件及状态文件。
预先执行的单次试运行另存于 `build/kclf-selfcheck-d38305116531/`，不计入下表。

| 用例 | 次数 | 检出 | 构造函数先于检测 |
| --- | ---: | ---: | ---: |
| manual，主线程/已存在线程/新线程，驻留和立即卸载 | 30 | 30 | 30 |
| linker，新工作线程，驻留 | 5 | 5 | 5 |
| 禁止用户态 executable mmap/mprotect，manual 立即卸载 | 5 | 5 | 5 |
| 检出后 exit_group，manual 驻留请求 | 5 | 5 | 5 |
| 合计 | 45 | 45 | 45 |

- 40 个非退出用例均捕获两个候选，共 80 个事件，目标仍存活，KPM 最终 `state=done`。
- 5 个退出用例在第一个阳性后退出，共 5 个事件，目标进程已结束。
- 85 个阳性事件全部位于实际注入线程；没有排除或重试失败用例。
- 2 个独立无 KPM 基线，加每次注入前的对照，合计 47 × 1,800 = 84,600 次调用，
  全部被过滤器观察且正常完成，检测阳性为 0。
- 对照包含正常 libc `open`、正常 libc `usleep`、合法匿名代码调用 libc `usleep`，
  覆盖主线程、安装过滤器前创建的线程和安装后创建的线程。
- 该数字仅是测试集结果，不是所有真实 App 的误报率估计。

立即卸载用例的真实日志顺序是：

```text
PAYLOAD_INIT ...
PAYLOAD_FINI ...
DETECT ... nr=0x38 ... evidence=code72+stack+cookie+libc
DETECT ... nr=0x65 ... evidence=code72+stack+cookie+libc
```

候选顺序随机，可能先 `0x65`。本检测不需要 payload 在完成后继续驻留。

退出用例的真实顺序是：

```text
PAYLOAD_INIT ...
DETECT ...
RESPONSE exit_group AFTER completion detection
```

因此不能把 `framework_done=false` 或进程退出算作“阻止 payload 首次执行”。

## 检测机制与观察干扰

1. `PR_SET_NO_NEW_PRIVS` 后安装 seccomp filter，使用 `SECCOMP_FILTER_FLAG_TSYNC`。
2. 对 libc 发起的 `openat` / `nanosleep` 返回 `SECCOMP_RET_TRAP`。
3. handler 从保存的 x29 所指 libc 帧读取返回地址，匹配完整 72 字节结构。
4. 解码三个随机字段偏移，读取栈中私有页指针，再核验 x6/x7、私有页 cookie、
   真实 libc 入口和调用参数；任一读取/核验失败不报阳性。
5. handler 使用自身受控 syscall gateway 重发正常调用，避免信号递归；gateway
   清空 x6/x7，避免内核把 handler 内的调用误当成 KCLF 完成。
6. `observe` 模式不终止进程。由于两个原始完成调用都被 TRAP，框架通过 EL0 bail
   恢复，并在后续正常 syscall 上清理；状态明确记录 `completion blocked; EL0 restored`。

所以这是主动插桩检测，不是完全无干扰的旁观。`SECCOMP_RET_TRAP` 阻止原 syscall、
TSYNC 的覆盖/失败语义可参考 [seccomp(2)](https://man7.org/linux/man-pages/man2/seccomp.2.html)。

## 对“禁止新增可执行映射”的验证

`denyexec` 附加拒绝用户态 `mmap/mprotect` 的 PROT_EXEC，返回 EPERM。
每个用例都先执行真实探测并记录：

```text
EXEC_GUARD mprotect_rc=-1 errno=1 mmap_blocked=1 mmap_errno=1
```

但 5 次 manual 注入的构造函数仍全部执行。原因与源码一致：准备阶段在 EL1 调用
`vm_mmap` 和 `raw_syscall3(__NR_mprotect,...)`，不经过用户态 syscall 的 seccomp
入口。此测试没有修改全局 SELinux，也没有授予 App root/capabilities。

这只能否定本次所测的“用户态 executable mmap/mprotect 过滤即能阻止此注入”方案，
不是所有内存执行策略的穷尽性评估。

## 适用范围与未覆盖项

- 专门针对当前 KCLF 1.5.0 生成器与本机 bionic 栈帧。启动时验证 libc 序言；
  其他 bionic 不匹配时报告未支持，而不声称未注入。
- 只验证一个设备、4 KiB 页；未验证其他 ROM、16/64 KiB 页、Binder 线程、深栈或回退栈。
- payload 是无主动对抗逻辑的构造/析构标记库。检测器必须在 payload 执行后仍完整有效。
  这不是任意 payload 或任意内核级篡改下的安全边界证明。
- 没有真实业务负载、性能开销或生产 SIGSYS handler 兼容性验收。
- 运行期读取依赖 `process_vm_readv(self)`；失败时不产生阳性。不得把读取失败、
  TSYNC 失败、目标退出、未触发注入当作阴性或防护成功。
- 自检不使用 payload 身份；标记仅用于控制端独立核对首次执行与检测的时间顺序。
- 过滤器和 handler 是本进程共享状态。普通用户态自检不能据此获得高于内核的信任级别。

## 复现与清理

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
    python kpms/kclf/test/selfcheck_v15/run.py --serial '<SERIAL>' --suite full --rounds 5
} finally {
    Remove-Item Env:KCLF_SUPERKEY
}
```

默认 Windows SDK/NDK 路径与现有仓库夹具一致。`--build-only` 只构建；
`--suite pilot` 先运行单个 manual/unload 用例。

驱动要求设备初始没有 KPM、测试包没有安装，不覆盖现有 App。
每个用例停止本轮测试进程后 reap。最终只有看到 `quiesce=idle` 才卸载 KPM，
否则保留并报告。仅删除本轮精确命名的远端 KPM 文件和空目录，不做递归删除。
本轮最终确认 KPM 数量为 0、测试包已卸载、远端临时文件已删除、boot_id 和
SELinux 状态不变；APK、测试源码及证据保留在主机，可重新构建/安装复现。
