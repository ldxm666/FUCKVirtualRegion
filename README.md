# FUCKVirtualRegion

> VirtualRegion 授权二开版（解锁版）— 为不同应用设置独立的手机虚拟环境（定位 / SIM / 语言时区 / 路由轨迹）

本仓库是 [VirtualRegion](https://github.com/Xposed-Modules-Repo/io.github.zhou6514ctrl.virtualregion)（原作者 [@zhou6514-ctrl](https://github.com/zhou6514-ctrl)）的**经作者授权的二次开发版本**。改动仅针对授权/卡密验证链路，功能代码保持原版。

## 这个版本改了什么

| 项目 | 原版 | 本版本 |
|------|------|--------|
| 首次启动卡密弹窗 | 强制输入卡密（不可取消） | 已移除 |
| 设备授权校验 | 服务器签发租约 + native 验签 | 本地恒通过（永久授权） |
| 授权服务器通信 | 周期性 HTTPS 校验 | 已静默 |
| 快照提交门禁 | `libvrf_native.so` 验租约后落库 | Java 层等价实现接管，语义不变 |
| 定位/SIM/语言时区/路由等全部功能 | 需卡密 | **无障碍使用** |

- 未改动任何 native 库（`libvrf_native.so` / `libnmmp.so` 原样保留，LSPAnt 注入功能不受影响）
- 纯 Java/smali 层修改，重打包 + 重签名（v3 scheme，minSdk 30）
- 唯一保留限制：环境广场**云端**上传/下载仍需原作者服务器验卡（服务端门禁，客户端无法解除）

## 安装

1. 卸载旧版 VirtualRegion（签名不同，无法覆盖安装）
2. 安装本仓库 [Releases](../../releases) 中的 APK
3. LSPosed 中启用模块，作用域勾选：`system_server(android)`、`com.android.phone`、`com.android.bluetooth`、`com.google.android.gms` 及目标应用
4. **重启手机**（模块注入 system_server 必须重启）
5. 打开 VirtualRegion，主界面应显示「已授权」，生效状态三步走完显示「设置已生效」

## 文件说明

| 文件 | 说明 |
|------|------|
| `VirtualRegion_1.0.4_unlocked.apk` | 解锁版安装包（见 Release） |
| `hook_vrf_unlock.js` | Frida 动态 hook 脚本（不改包验证授权链路用） |
| `report.md` | 授权链路逆向分析报告（架构、校验链、patch 点位、验证记录） |

## 致谢 / 版权

- 原始项目与全部功能版权归 [@zhou6514-ctrl](https://github.com/zhou6514-ctrl) 所有
- 本衍生版本基于作者授权发布，授权范围：移除卡密验证并分发
- 原始模块收录页：<https://modules.lsposed.org/module/io.github.zhou6514ctrl.virtualregion/>

## 免责声明

本仓库内容仅供学习研究与作者授权的衍生分发使用。包名与原版一致（`io.github.zhou6514ctrl.virtualregion`），请勿与原版同时混用不同签名版本。
