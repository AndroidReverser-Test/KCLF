# KCLF 1.5.1 普通 App 被动检测夹具

本目录只测试检测能力和开销，不修改注入器。测试包 `com.kclf.passive151` 为 non-debuggable、普通 App UID、无 capabilities、继承 zygote seccomp。

当前结论与 128 例最终矩阵见 [真机报告](E:/KernelPatch/kpms/kclf/test/passive_v151/REPORT_20261031.md)。仍有短窗口/扫描线程自身漏检，未达到全进程可靠且零业务影响的验收要求。

## 两条规则

`ctx_v151`：低优先级线程周期读取自己的 maps 和内存，匹配 136 字节恢复结构，解码生成页中的 ABI/私有页地址，并交叉校验匿名 RX/RW 映射、保存的 PC/SP/NZCV、随机 token 与运行期 ABI。关键证据重复读取，读取失败/不一致只记录覆盖损失，不判阳性。没有 payload 签名，也不读取控制器/KPM 状态。

`x16_boundary`：只在夹具自有 `guarded` 线程的汇编 raw-nanosleep 边界检查 x16。只有哨兵被替换成该边界的精确返回 PC（含 syscall 重启的 PC-4）才报告匹配；其他不一致是 `INCONCLUSIVE`。不修改 libc/ART/其他线程。它验证当前实现的恢复异常，不证明其他线程没有注入，也不能单独归因于恶意 KCLF。

两条规则都只记录，不阻断系统调用、不安装 seccomp、不安装信号处理器、不 ptrace、不暂停目标。扫描仍会消耗 CPU/内存带宽并读取 maps；只读不等于零性能影响。

## 对照与负载

- 完整生成代码的匿名 RX 副本，但其私有/ABI 页不存在：结构识别应命中，最终检测必须拒绝。
- 相同代码的 RW 数据副本、合法匿名 RX 函数调用、随机 RX 映射并发创建/销毁。
- 正常 dlopen/dlsym/dlclose、线程创建与回收、分配/数据校验/文件读取。
- Java UI 动画、周期运算和帧间隔统计。
- 无 KPM 基线，以及扫描关/开顺序 `0,1,1,0,1,0,0,1` 的成对基准。

独立 payload 只写执行标记，检测器不会读取标记。0/2/20/200 ms 指的是构造函数额外等待时间，0 仍包含标记 I/O；不等于整个注入持续时间。

## 使用

```powershell
$env:KCLF_SUPERKEY = Read-Host 'KernelPatch superkey'
try {
    python kpms/kclf/test/passive_v151/run.py --serial '<SERIAL>' --suite full --rounds 3
} finally { Remove-Item Env:KCLF_SUPERKEY }
```

`--suite pilot` 做小矩阵；`--suite bench` 仅做无 KPM 的负对照与性能基准；`--period-ms 50|100|250` 控制扫描周期；`--build-only` 不操作设备。

要求初始 KPM 数量为 0、测试包不存在。不会覆盖已有包。原样加载工作区 `kclf.kpm`，记录哈希，不重新构建注入器。每轮仅停止自己启动的测试 App；最后 reap/quiesce，明确 idle 后才卸载。失败时保留诊断；不安全则保留模块，不能强行卸载。

主机结构解析测试可由 GCC/ASan/UBSan 编译 `test_signature.c` 与 `../../kclf_codegen.c`，定义 `KCLF_CODEGEN_HOST`。同一解析器在 4/16/64 KiB 页各 10,000 样本中验证地址/偏移解码，并测试 10,000 个随机反例。

结果在 `build/kclf-passive-<id>/`，含 APK、原始日志、逐例状态、JSON 摘要；后期运行另保存源码快照。`summarize.py <目录>` 只分析已保存证据，不连接设备。

## 必须保留的边界

- 未捕获、未支持、读取失败、注入失败与未注入不是同一种结果；只有构造函数和框架状态都证实执行后才计算漏检。
- 短驻留跳板可能在两次扫描之间消失；检测线程被注入时不能同时自扫描。
- 受控 x16 边界只覆盖那个线程/窗口，不得通过选择该线程注入宣称全 App 100% 检出。
- 不使用任意匿名 RX、单条分支或共享 32 字节内容作为最终阳性依据。
- 有限负对照零报警不证明生产环境零误报。该规则只匹配当前代码版本；合法相同上下文切换代码也可能触发，需要产品授权语义判断。
- 性能数据含设备调频/调度噪声；p99 是直方图桶上界。扫描桶 100 us、工作/UI 桶 50 us、帧桶 1 ms；最末桶饱和，不是最大值。
- 没有真实业务 APK、OEM/ROM 全覆盖、对抗性 payload 或跨设备验收，不承诺“不会影响正常业务”。
