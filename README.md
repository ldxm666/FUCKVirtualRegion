# FUCKVirtualRegion

> VirtualRegion 授权二开版（解锁版）— 为不同应用设置独立的手机虚拟环境（定位 / SIM / 语言时区 / 路由轨迹）
> 当前适配：**1.0.8（versionCode 109）** · 解包补丁 + 重打包重签名 + Frida 动态 hook 双路线

## 1.0.8 改了什么

| 项目 | 原版 | 本版本 |
|------|------|--------|
| 首次启动卡密弹窗 | 强制输入卡密（不可取消） | 已去除，直接进入主界面 |
| 授权判定 `h3.u.S()Z` | native 验签（nmmp 抽取） | Java 调用点全部重定向为恒真 |
| 授权状态 | 服务器签发租约 | 内存伪造永久租约（`UNLOCKED-FRIDA`，到期 2100-01-01） |
| 授权服务器通信 `h3.u.x()` | 周期 HTTPS 校验 | 已静默 |
| 快照提交门禁 | `libvrf_native.so` 验租约后落库 | Java 层等价实现接管（`Lvr/Store;` 内存 store） |
| 定位 / SIM / 语言时区 / 路由等功能 | 需卡密 | **无障碍使用** |
| 目标应用作用域 | 需在 LSPosed 勾选 | **同样必须勾选**（见下文「必读」） |

- 未改动任何 native 库（`libvrf_native.so` / `libnmmp.so` 原样保留，nmmp 方法注册不受影响）
- 纯 Java/smali 层修改 + 重打包重签名（v3 方案，minSdk 30 / targetSdk 37，与原包一致）
- 唯一保留限制：环境广场**云端**上传/下载仍走原作者服务器验卡（服务端门禁，客户端无法解除）

## ⚠️ 必读：目标应用作用域必须勾选

VirtualRegion 的虚拟环境注入是**自带嵌入式 LSPosed 模块**实现的（APK 内 `META-INF/xposed/java_init.list`
→ `io.github.zhou6514ctrl.virtualregion.hook.core.ModuleEntry`）。模块只在被勾选作用域的应用进程内运行。

- 只装 APK + 开启模块 → **卡密与授权全解锁**（主界面显示「已授权」）
- 要让**某个应用**的定位/SIM/语言时区真正被改掉 → 在 LSPosed 的 VirtualRegion 模块页里，
  把这个应用（例如 QQ `com.tencent.mobileqq`）**也勾进作用域**，然后强停该应用重开

主界面上那句「以下功能需要勾选目标应用作用域」就是同一个意思。

## 安装

1. 卸载旧版 VirtualRegion（签名不同，无法覆盖安装）
2. 安装本仓库 [Releases](../../releases) 中的 APK（或仓库内 `VirtualRegion_1.0.8_unlocked.apk`）
3. LSPosed → 模块 → VirtualRegion → **启用模块**，作用域勾选：
   `system`、`android`、`com.android.phone`、`com.android.bluetooth`、`com.google.android.gms`
   **以及你要改环境的目标应用**（QQ / 微信 / 高德 / 抖音 …）
4. 重启手机（模块注入 system_server 只在开机阶段发生）
5. 打开 VirtualRegion → 显示「已授权」→ 建/选环境 → 选应用 → 确认生效

## 从源码复现

```bash
apktool d VirtualRegion_1.0.8.apk -o apktool_108
python patch_vr108.py apktool_108          # 幂等 + 命中断言，自动注入 Lvr/Store;
apktool b apktool_108 -o out_unsigned.apk
zipalign -f -p 4 out_unsigned.apk aligned.apk
apksigner sign --ks vrf-unlock.keystore --ks-pass pass:vrfunlock --ks-key-alias vrf \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true aligned.apk
adb push aligned.apk /data/local/tmp/vr.apk && adb shell "su -c 'pm install -r -d /data/local/tmp/vr.apk'"
```

补丁命中数（首次运行，重跑为 0 也接受）：

```
S() 调用点重定向   : 14
currentXXX 重定向  : 39   (34 Module + 3 TargetSim + 2 Regional)
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `VirtualRegion_1.0.8_unlocked.apk` | 解锁版安装包（v3 签名，CN=VR Unlock） |
| `patch_vr108.py` | smali 全量补丁脚本（可移植：`python patch_vr108.py <apktool_out>`，幂等） |
| `vr_Store.smali` | 新增 helper 类源码（快照内存 store + 恒真判定，编译进 `Lvr/Store;`） |
| `hook_vrf_unlock.js` | Frida 动态 hook 脚本（1.0.8 点位，不改包验证用） |
| `report.md` | 1.0.8 授权链路逆向分析报告（架构、点位对照、验证证据、踩坑记录） |

## 免责声明

本仓库内容仅供学习研究与作者授权的衍生分发使用。包名与原版一致（`io.github.zhou6514ctrl.virtualregion`），
请勿与原版同时混用不同签名版本。
