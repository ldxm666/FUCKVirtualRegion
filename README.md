# FUCKVirtualRegion

> VirtualRegion 授权二开版（解锁版）— 为不同应用设置独立的手机虚拟环境（定位 / SIM / 语言时区 / 路由轨迹）
> 当前适配：**1.0.8（versionCode 109）**

## 这个版本改了什么

| 项目 | 原版 | 本版本 |
|------|------|--------|
| 首次启动卡密弹窗 | 强制输入卡密（不可取消） | 已移除 |
| 设备授权校验 | 服务器签发租约 + native 验签 | 本地恒通过（授权有效 / 2100 年到期） |
| 授权服务器通信 | 周期性 HTTPS 校验 | 已静默 |
| 快照提交门禁 | `libvrf_native.so` 验租约后落库 | Java 层等价实现接管（`Lvr/Store;` 内存 store），语义不变 |
| 定位/SIM/语言时区/路由等全部功能 | 需卡密 | **无障碍使用** |

- 未改动任何 native 库（`libvrf_native.so` / `libnmmp.so` 原样保留，nmmp 抽取方法注册不受影响）
- 纯 Java/smali 层修改，重打包 + 重签名（v3 scheme，minSdk 30）
- 唯一保留限制：环境广场**云端**上传/下载仍需原作者服务器验卡（服务端门禁，客户端无法解除）

## 1.0.4 → 1.0.8 适配要点

新版把授权判定 `S()`、联网校验 `v()`、快照读取 `currentXXX()`、验签 `verifyRaw` 全部 **native 化**（nmmp 抽取），租约/元数据类重命名（`h3.D→E`、`h3.f→e`），并新增跨进程授权标志 `h3.D`。本版策略：**native 声明一个不碰，全部在 Java 调用点重定向**——详见 [report.md](report.md)。

## 安装

1. 卸载旧版 VirtualRegion（签名不同，无法覆盖安装）
2. 安装本仓库 [Releases](../../releases) 中的 APK
3. LSPosed 中启用模块，作用域勾选：`system_server(android)`、`com.android.phone`、`com.android.bluetooth`、`com.google.android.gms` 及目标应用
4. **重启手机**（模块注入 system_server 必须重启；不重启会停在"等待系统服务确认"）
5. 打开 VirtualRegion，主界面应显示「已授权」，生效状态三步走完显示「设置已生效」

## 从源码复现

```bash
apktool d VirtualRegion_1.0.8.apk -o apktool_108
python patch_vr108.py            # 幂等 + 命中断言
apktool b apktool_108 -o out_unsigned.apk
zipalign -f 4 out_unsigned.apk aligned.apk
apksigner sign --ks vrf-unlock.keystore --ks-pass pass:vrfunlock --ks-key-alias vrf aligned.apk
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `VirtualRegion_1.0.8_unlocked.apk` | 解锁版安装包（见 Release） |
| `hook_vrf_unlock.js` | Frida 动态 hook 脚本（1.0.8 点位，不改包验证用） |
| `patch_vr108.py` | smali 全量补丁脚本（幂等，可复现全部修改） |
| `vr_Store.smali` | 新增 helper 类源码（快照内存 store + 恒真判定） |
| `report.md` | 1.0.8 授权链路逆向分析报告（新架构、点位对照、踩坑记录、验证证据） |

## 免责声明

本仓库内容仅供学习研究与作者授权的衍生分发使用。包名与原版一致（`io.github.zhou6514ctrl.virtualregion`），请勿与原版同时混用不同签名版本。
