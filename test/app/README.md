# 普通 app 注入测试目标

这是 KCLF 用来验证“普通 64 位 Android 应用进程”的临时测试 APK，不是产品示例。
它故意保持普通 app 的特征：

- 第三方包 `com.kclf.apptest`，debuggable，targetSdk 35；
- 由 zygote fork，运行在 `untrusted_app` 域，带 zygote seccomp 过滤器；
- 主线程回到 Looper 后阻塞在 `epoll_pwait`；
- 有一个名为 `kclf-sleeper` 的 Java 线程每 50ms 做一次 `Thread.sleep`；
  具体 syscall 由 ART 决定，本次设备实际为 futex；
- `kclf-idle0`–`kclf-idle3` 阻塞于 pipe read，供四槽排队、取消、wake 和退出测试；
- `kclf-fp` 在真实 nanosleep 两侧检查 q0/q8/q31、FPCR/FPSR；
- 另外打包 `libkclfapp_fp.so`（故意改写 FP 状态）与 `libkclfapp_hold.so`
  （构造函数等待两秒），用于寄存器恢复和 running 生命周期测试；
- `lib/arm64-v8a/libkclfapp_payload.so` 随 APK 安装到
  `/data/app/~~.../com.kclf.apptest-.../lib/arm64/`，这正是 app linker
  namespace 允许的路径；
- payload 构造函数只写 app 自己的 `files/hit_<pid>`，不调用 JNI/ART/dlopen。

## 构建

需要 Android SDK（aapt2/d8/zipalign/apksigner）和 NDK。默认自动使用
`ANDROID_HOME`/`ANDROID_SDK_ROOT` 或 `D:\androidSDK`，也可以显式指定：

```powershell
powershell -ExecutionPolicy Bypass -File kpms\kclf\test\app\build.ps1
# 或
powershell -ExecutionPolicy Bypass -File kpms\kclf\test\app\build.ps1 `
  -SdkRoot D:\androidSDK -Platform android-36 `
  -NdkRoot D:\androidSDK\ndk\27.0.12077973
```

产物：`build/kclf-apptest/app.apk`。

构建目录中的 `debug.keystore` 会复用，不再每次重建密钥，保证同一输出目录
构建的 APK 能通过 `adb install -r -t` 更新而不丢数据。每次使用独立 work 目录，
失败时保留编译诊断，不递归删除用户指定的输出目录。SO 使用 16K ELF 段对齐；
这不等于已经在 16K 页设备实测。

## 自动完整回归

```powershell
$KclfKey = Read-Host 'KernelPatch superkey'
./kpms/kclf/test/app/device-test.ps1 -SuperKey $KclfKey -Serial '<SERIAL>' `
  -Apk '<absolute APK path>' -Repeat 100
```

脚本安装测试 APK，测试普通应用主线程 / Java sleeper / Binder / native probe，
校验 payload marker 的 PID/TID、FPSIMD、正常驻留、dlclose、缺失/截断 SO 错误恢复、
四槽排队与取消、重复请求、连续加载卸载、完成未 reap / 排队中 / 构造函数中
force-stop 后旧进程消失与新进程启动、RX/guard/临时映射完整回收，以及 busy quiesce / reload。
最后核对 boot ID、SELinux、crash buffer 和内核告警，安全排空并卸载测试模块。

每轮证据保存在 `build/kclf-app-<runid>/`。脚本不清空 logcat/dmesg、不修改
SELinux/seccomp、不触碰其他 App；结束后保留测试 APK、marker 和最终测试进程。
测试前不能已经加载同名 kclf，以免卸载用户原有模块。

本次完整回归及 100 轮连续测试结果见 [当前审计](../../COMPATIBILITY_1.3.1.md)。

## 手工验证

以下 `KEY` 为 KernelPatch superkey；不要把它写进脚本或仓库。

```sh
adb install -r -t build/kclf-apptest/app.apk
adb shell am start -W -n com.kclf.apptest/.MainActivity
adb shell pidof com.kclf.apptest
adb shell logcat -d -s KCLFAPP:I | tail -2
```

日志会给出 `pid=... libdir=/data/app/.../lib/arm64`。加载模块并注入主线程：

```sh
adb push kpms/kclf/kclf.kpm /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch $KEY kpm load /data/local/tmp/kclf.kpm
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf inject,<PID>,<LIBDIR>/libkclfapp_payload.so,wake
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf status
adb shell run-as com.kclf.apptest cat /data/user/0/com.kclf.apptest/files/hit_<PID>
```

应看到 `state=done ... via=__loader_dlopen`，marker 中的 `pid/tid` 与注入线程一致。
主线程在 `epoll_pwait`，必须带 `wake`；不带时 `status` 会给出
`hint=blocked(use wake)`。改注入 `kclf-sleeper` 的 tid 时可以省略 `wake`。

验证“目标在请求完成但未 reap 时被系统杀死”不会卡住 ActivityManager（1.3.0 修复）：

```sh
adb shell am force-stop com.kclf.apptest
adb shell am start -W -n com.kclf.apptest/.MainActivity   # Status: ok，核对旧 PID 已消失、新 PID 不同
```

本次设备可能在 `am start` 前由 ActivityManager 预先创建替代进程，从而报告
`LaunchState: WARM`。这不等于旧进程没有退出；自动测试直接检查 `/proc/<旧PID>`
消失和 PID 更换，不以 UI 启动分类代替进程生命周期验证。

验证 `unload`：

```sh
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf inject,<NEWPID>,<LIBDIR>/libkclfapp_payload.so,wake,unload
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf status   # unload=ok
```

需要确认映射消失时，以 root 读取 `/proc/<NEWPID>/maps`，检查没有
`libkclfapp_payload.so`。`/data/local/tmp` 里的 payload 对 `untrusted_app` 不可用：
设备实测 `prepare` 能打开，但 linker 会返回
`dlopen failed: ... Permission denied`，这是预期失败路径。

卸载模块：

```sh
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf reap
adb shell /data/local/tmp/kpatch $KEY kpm ctl0 kclf quiesce   # 需要 quiesce=idle
adb shell /data/local/tmp/kpatch $KEY kpm unload kclf
```

测试 APK 只用于自己控制的设备；不要把它当作任何通用注入/隐藏方案的示例。
