# FUCKVirtualRegion

> VirtualRegion 授权二开版（解锁版）— 为不同应用设置独立的手机虚拟环境（定位 / SIM / 语言时区 / 路由轨迹）
> 当前适配：**2.0.5（versionCode 205）** · 解包补丁（重打包重签名）+ LSPosed 模块 双路线
> 历史适配：**1.0.8（versionCode 109）** — 见 [报告](report.md) 第 0~7 节，文件仍保留在本仓库

## 2.0.5 改了什么

| 项目 | 原版 | 本版本 |
|------|------|--------|
| 首次启动「卡密授权」弹窗 | 强制输入卡密，不可取消 | **已去除**（`auth.v.Z()` 恒 false，弹窗 `c4.x` 的唯一前置条件） |
| 授权判定 `auth.w.a()/b()` | 状态枚举判定 | `a()` 恒真 / `b()` 恒假 |
| 授权状态机 `auth.v.c0(H)` | native Ed25519 验签（`libvrf_native.so#verifyRaw`，租约绑定 APK 签名） | Java 层短路为 `OK_OFFLINE` + 远期到期 |
| 授权视图 `auth.v.Q()` | 读租约失效时间 | 恒返回 `AUTHORIZED / expireTime=0` → 抽屉卡片 **「授权有效 / 永久有效」** |
| 授权状态写入口 `auth.v.b0()` | 网络/吊销失败会回写拒绝态 | 强制 `AUTHORIZED`，并**补一个自造租约**（发布器 `m3.h` 要求 `u.a()==true && v.t != null`） |
| 系统侧快照门禁 `NativeSnapshotGate.f/g/h` | native 重验租约，失败 → `REMOTE_RUNTIME_CLEARED` | Java 层缓存已解码快照 + 直接回「已提交」，`current*Snapshot()` 全部重定向到缓存 getter |
| 版本检测弹窗「发现新版本」 | 远端清单 versionCode > 205 即弹 | 远端清单 `f4.a` 构造期版本号置 0，**弹窗永不出现** |
| 定位 / SIM / 语言时区 / 路由等功能 | 需卡密 | **无障碍使用** |
| 目标应用作用域 | 需在 LSPosed 勾选 | **同样必须勾选**（见下文「必读」） |

- 未改动任何 native 库（`libvrf_native.so` 原样保留，NP/nmmedit 方法保护不受影响）
- 纯 Java/smali 层修改 + 重打包重签名（minSdk 30 / targetSdk 37，与原包一致）
- 唯一保留限制：环境广场**云端**上传/下载仍走原作者服务器验卡（服务端门禁，客户端无法解除）

## 两种交付形态

| 形态 | 产物 | 适合谁 | 卡密弹窗 | 版本弹窗 | 系统侧注入 |
|---|---|---|---|---|---|
| **A. 直接整合进 APK** | `VirtualRegion_2.0.5_unlocked.apk`（77 MB，v3 签名 CN=revx） | 想装完就用、不装额外模块 | 无 | 无 | 由 **APK 自带**的 LSPosed 模块完成 |
| **B. LSPosed 模块** | `VrfPermanent-lsp-v2.2.apk`（21 KB，libxposed API 102） | 想保留原版 APK 不动，只从外部注入 | 无 | 无 | 模块 + APK 自带模块共同完成 |

两者可同时存在（改的是同一批方法，互不冲突）。

### 方案 A 安装

```bash
adb uninstall io.github.zhou6514ctrl.virtualregion          # 签名不同，必须卸载
adb push VirtualRegion_2.0.5_unlocked.apk /data/local/tmp/vr.apk
adb shell su -c 'pm install -r -d /data/local/tmp/vr.apk'   # MIUI/HyperOS 用 root 装可绕「USB 安装被拦截」
```

装完必须在 LSPosed → 模块 → **VirtualRegion** 里：① 打开「启用模块」；② 右上角 ⋮ → **勾选推荐**
（会勾上 `system` / `android` / `com.android.phone` / `com.android.bluetooth` / `com.google.android.gms`），
③ **重启手机**（模块注入 system_server 只在开机阶段发生）。

### 方案 B 安装

```bash
adb install -r -d VrfPermanent-lsp-v2.2.apk
```

LSPosed → 模块 → **VirtualRegion 永久授权** → 启用模块 → 作用域里**手动勾选** `VirtualRegion`
（`io.github.zhou6514ctrl.virtualregion`），然后强停目标 App 重开。

> ⚠️ LSPosed 只在**模块首次启用**时把 `scope.list` 同步进它的数据库；后续更新 APK / 改 `scope.list`
> **不会重新同步**。所以「作用域里缺目标包」是本模块最常见的“不生效”原因——在管理器的作用域页手动勾一次即可。

## ⚠️ 必读：目标应用作用域必须勾选

VirtualRegion 的虚拟环境注入是**自带嵌入式 LSPosed 模块**实现的（APK 内 `META-INF/xposed/java_init.list`
→ `io.github.zhou6514ctrl.virtualregion.hook.core.ModuleEntry`）。模块只在被勾选作用域的应用进程内运行。

- 只装 APK + 开启模块 → **卡密与授权全解锁**（主界面抽屉显示「授权有效 / 永久有效」，无任何弹窗）
- 要让**某个应用**的定位/SIM/语言时区真正被改掉 → 在 LSPosed 的 VirtualRegion 模块页里，
  把这个应用（例如 QQ `com.tencent.mobileqq`）**也勾进作用域**，然后强停该应用重开

主界面「运行状态」页会把这件事显示出来：
`设置已发布；未运行的系统进程将在启动时自动加载` → `运行中`。

## 从源码复现（方案 A）

```bash
apktool d VirtualRegion_2.0.5.apk -o vr205
python patch_vr205.py vr205                    # 幂等，重跑不会重复注入
apktool b vr205 -o rebuilt.apk
zipalign -f -p 4 rebuilt.apk aligned.apk
apksigner sign --ks revx-test.jks --ks-pass pass:revx123456 --key-pass pass:revx123456 \
  --ks-key-alias revx --out VirtualRegion_2.0.5_unlocked.apk aligned.apk
adb push VirtualRegion_2.0.5_unlocked.apk /data/local/tmp/vr.apk
adb shell su -c 'pm install -r -d /data/local/tmp/vr.apk'
```

补丁命中（`patch_vr205.py` 的输出）：

```
patched auth.w#a / auth.w#b
patched auth.v#b0 (state coerced to AUTHORIZED + synthetic lease installed)
added   auth.v#revxLease() synthetic lease builder
patched auth.v#c0              (offline verify always OK)
patched auth.v#Q               (expireTime = 0 => permanent)
patched auth.v#Z               (卡密授权 dialog can never show)
patched NativeAuthCore#a       (native Ed25519 always OK)
patched f4.a                   (remote versionCode forced to 0 => no 发现新版本 dialog)
patched NativeSnapshotGate#f/g/h/e  + aCached()/bCached()/cCached() getters
retargeted current*Snapshot() call sites in 31 smali files
```

## 从源码复现（方案 B）

```bash
# 模块源码：VrfUnlockModule.java（本仓库根目录）+ libs/libxposed-api-102.0.0-classes.jar
javac --release 17 -classpath "libxposed-api-102.0.0-classes.jar;android.jar" \
  -d classes VrfUnlockModule.java
d8 --release --min-api 30 --lib android.jar --output . classes/**/*.class
aapt2 link -I android.jar --manifest AndroidManifest.xml -o unsigned.apk res.zip
# 把 classes.dex 与 META-INF/xposed/{java_init.list,module.prop,scope.list} 塞进 unsigned.apk
zipalign -f -p 4 unsigned.apk aligned.apk && apksigner sign --ks revx-test.jks ... aligned.apk
```

## 文件说明

| 文件 | 说明 |
|------|------|
| `VirtualRegion_2.0.5_unlocked.apk` | **方案 A**：2.0.5 解锁版安装包（v3 签名 CN=revx） |
| `VrfPermanent-lsp-v2.2.apk` | **方案 B**：外部 LSPosed 模块（libxposed API 102，作用域手工勾选） |
| `patch_vr205.py` | 2.0.5 smali 全量补丁脚本（`python patch_vr205.py <apktool_out>`，幂等） |
| `VrfUnlockModule.java` | 方案 B 模块源码（含 hook 点位注释与逆向链路说明） |
| `report.md` | 2.0.5 + 1.0.8 授权链路逆向分析报告（点位对照、验证证据、踩坑记录） |
| `patch_vr108.py` / `vr_Store.smali` / `hook_vrf_unlock.js` | 1.0.8 时代的补丁脚本 / helper / Frida 脚本（历史保留） |
| `VirtualRegion_1.0.8_unlocked.apk` | 1.0.8 解锁版（历史保留） |

## 免责声明

本仓库内容仅供学习研究与作者授权的衍生分发使用。包名与原版一致（`io.github.zhou6514ctrl.virtualregion`），
请勿与原版同时混用不同签名版本。
