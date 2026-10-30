# 防检测可观测性验证

> 1.5.0 说明：本目录的 Android 夹具仍是 1.4.x 的旧规则回归，未跟随新的 libc 完成
> 路径更新。1.5.0 的主机验证见 `test/test_observability_signature.c`，真机
> SIGSYS 现场验证见 `test/seccomp_probe.c`；当前结论以
> [1.5.0 检测点](../../DETECTION_POINTS.md) 为准。

当前结论以 [1.5.0 检测点与稳定性评估](../../DETECTION_POINTS.md) 为准。此目录的
Android 夹具仍是有限旧规则回归，**未实现新的 208 字节尾段/运行期 ABI 检测**。
本轮主机验证器为 [test_observability_signature.c](../test_observability_signature.c)，
结果索引为 [EVIDENCE_1_4_3_AUDIT_20261030.json](EVIDENCE_1_4_3_AUDIT_20261030.json)。

对应 [1.4.1 可观测性报告](../../OBSERVABILITY_REPORT.md)、
[1.4.2 加固报告](../../OBSERVABILITY_HARDENING_20261030.md) 和
[1.4.2/1.4.3 进度](../../HARDENING_PROGRESS_20261030.md)。这是独立的、非 debuggable
普通 App 测试夹具，包名为 `com.kclf.obsprobe`，不使用原来的 AppTest 或其他应用。

## 规则

夹具实际实现四条内容规则和一个信息类 syscall guard：

1. `KNOWN_MANUAL`（历史方法 B）：已知 payload 的 ELF 头位于匿名映射**起点**、
   全部非可写 PT_LOAD 内容相同、至少一个代码段可执行且不在 linker 登记表。
   manual 后端默认擦除 ELF 头并增加随机前导 pad，此规则不再产生阳性。
2. `KNOWN_HEADER`：在可读、非可写匿名区域搜索已知 ELF 头。
   默认 `hdr=scrubbed` 时必须为 0；`keepelf` 时预期出现（对照）。
3. `RESIDUAL_TEXT`：搜索参考 ELF 首个可执行 PT_LOAD 开头 32 字节。它证明内容
   可读，但不是唯一身份签名：libobspayload.so 与 libobsother.so 的该片段相同，
   历史“另一份 ELF”对照也报警，驱动的该负例断言却未检查此事件。
4. `RESIDUAL_TAG`：在匿名可执行内存中搜索 1.4.2 生成代码里的固定 `KCLFBAIL`
   字面量。1.4.3 改为每请求随机 token，预期为 0。

`SYS_TRAP` 对 `getpid/gettid/getuid/geteuid/getgid/getegid/getppid/getpgid/
sched_getscheduler/getpriority` 安装 `SECCOMP_RET_TRAP`，按 SIGSYS 现场 PC 是否位于
预采集的文件后端可执行映射分类为 `control`/`file`/`unexpected`。KCLF 1.4.2+ 不在
注入路径上使用这些调用，因此 `kind=unexpected` 必须为 0。匿名 stub 的 100 次
`getpid` 用于证明 guard 确实生效。

该 guard 不覆盖 1.4.3 的 8 项实际完成候选；`unexpected=0` 不能排除按候选调用和
instruction_pointer 检测。旧 `KCLF_EXEC` 完整 548 字节识别器已从当前 probe.c
删除，run.py 仅残留基线无事件断言，不能声称当前仍实现并执行该检测。

检测代码均在 App UID 下运行。控制端 root 只负责部署、发起注入、收集已经由 App
产生的证据和清理。安全读取使用 `process_vm_readv(self)`，不依赖
`/proc/self/mem`；目标平台若不支持该读取方式，测试会失败而非改用猜测规则。

## 复现

需要本仓库现有 WSL ARM64 GCC、Android SDK/NDK、JDK、ADB，以及连接设备。
使用环境变量传密钥，不将密钥写入文件：

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
    python kpms/kclf/test/observability/run.py --serial '<SERIAL>' --rounds 5
} finally {
    Remove-Item Env:KCLF_SUPERKEY
}
```

默认 SDK 为 `D:/androidSDK`，NDK 为 `D:/androidSDK/ndk/27.0.12077973`；
可用 `--sdk`、`--ndk`、`--adb` 覆盖。`--build-only` 仅构建，不操作设备。
构建和原始证据放在工作区 `build/kclf-observability-<run-id>/`。

驱动在独立输出目录重新构建 KPM，并检查工作区 KPM 与新构建是否一致；不覆盖工作区
或设备已有的 `kclf.kpm` 文件。开始时必须没有已加载 KPM，且测试包必须尚未安装。

测试包含普通基线（plain/guard/normal）、正常 dlopen、100 次普通 getpid API 调用、
100 次匿名代码直接 getpid syscall、ELF 数据副本、另一份有效手动加载 ELF，以及
manual 驻留/unload、linker 驻留、`keepelf` 对照和完成候选列表随机性检查。
当前驱动跳过 linker+unload；观察线程也作为注入目标，100 ms 轮询无法保证捕获短暂映射。
guard 通过 prctl 安装在线程 `kclf-observe` 上，只过滤该线程；没有测试 TSYNC。
夹具不 fork；这一返回处理不能未经适配直接用于会 fork 的进程或已有 SIGSYS
处理器的大型应用。

正常结束时停止并卸载本轮新安装的测试 App，reap 后确认 `quiesce=idle`，再卸载
本轮 KPM。若不能确认 idle，会保留模块并记录错误。独立临时模块文件和主机证据保留。

## 已保存的验证记录

[EVIDENCE_20261030.json](EVIDENCE_20261030.json) 是 1.4.1 基线的证据索引；
1.4.2/1.4.3 的运行结果和产物哈希记录在加固报告与
`build/kclf-observability-*/summary.json` 中。

这些是限定条件下的有限样本结果，不能据此估计所有 ROM、所有 payload 或全部
实际应用的准确率，也不把本来就合法的同代码手动加载行为标记为恶意。
