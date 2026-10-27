# KernelPatch 宿主配套修复

`kernelpatch-lifecycle.patch` 基于本次工作区的 KernelPatch 提交
`406c85ce79a5e1c19b53be34c04baadc1ec68bc5`，包含：

- 模块操作串行化、可睡眠 ctl/event/exit、exit veto、RCU 发布/回收。
- synchronize_rcu 分派修正及两个宿主能力标识。
- `checks/test_module_lifecycle.py` 主机 ASan/UBSan 回归。

在对应的 KernelPatch 仓库根目录检查后应用：

```sh
git apply --check kpms/kclf/patches/kernelpatch-lifecycle.patch
git apply kpms/kclf/patches/kernelpatch-lifecycle.patch
python3 checks/test_module_lifecycle.py
```

如果当前工作区已包含这些修改，不要重复应用。其他基线需要先人工核对差异，不要强行覆盖。
补丁不修改 preset ABI；独立 KCLF 仓库不会自动提交/推送父仓库。

本次 ARM64 宿主构建已通过，但没有刷写设备。要启用 exit-veto 等宿主行为，需要按正常固件升级流程
部署重新构建的 KernelPatch；仅加载新版 KPM 不会升级宿主。旧宿主必须单控制端并先 quiesce=idle 才卸载。
