# VirtualRegion 1.0.8 逆向分析与解锁报告

> 分析日期：2026-09-11
> 工具链：apktool 3.0.2 / jadx 1.5.5 / apksigner 0.9（build-tools 36.0.0）/ adb / Frida 17.15.3
> 真机：小米 2509FPN0BC（Android 16 / arm64-v8a / KernelSU + Zygisk-LSPosed 2.1.1 / API 102）

## 0. 结论速览

| 产物 | 路径 | SHA-256 |
|------|------|---------|
| 原始包 | `VirtualRegion_1.0.8.apk`（86,827,336 B） | `c51ced063930bb2346141877a0305bb3afb634ca21f68ebd14657c7d1c2c5035` |
| 未签名重打包 | `out_unsigned.apk`（86,676,179 B） | `9bddfbc27109ab18e890cdfb06be2497caf5587d3991cd6350960f7da4bfa085` |
| 解锁签名包 | `VirtualRegion_1.0.8_unlocked.apk`（86,819,399 B） | `230315116d119703bd3b9df41dc573fd493c30886cc4740542f43bb8065017a1` |

- 卡密弹窗：**已去除**，冷启动直接进主界面
- 授权状态：主界面右上 **「已授权」**（伪造租约：`UNLOCKED-FRIDA` / 到期 2100-01-01）
- 授权服务器通信：**已静默**（`h3.u.x()` 空实现）
- 快照链路：`commit` 全部走 Java 内存 store，`currentXXX` 读取全部重定向，**全进程零 VerifyError**
- 真机验证：安装成功 → 冷启动无弹窗 → 界面「已授权」→ 第 1/2 步（已保存 1 个环境 / 已启用 1 个应用）正常
- 保留限制：
  1. 环境广场**云端**上传/下载仍由服务端验卡（客户端不可解）
  2. **目标应用必须被勾进 LSPosed 作用域**，否则该应用的环境注入不生效（详见第 4 节）

## 1. 1.0.4 → 1.0.8 结构变化（关键）

新版对授权链做了**方法重排 + 扩大 native 化范围**（nmmp 方法抽取），1.0.4 的点位全部改名/搬移：

| 1.0.4 | 1.0.8 | 说明 |
|-------|-------|------|
| `h3.u.P()Z` 授权判定 | `h3.u.S()Z` | **native 化**（nmmp 抽取，`public native S()Z`） |
| `h3.u.W()Z` 弹窗判定 | 移除 | 弹窗改走 binder `auth/a.isAuthorized()` + UI 状态 |
| `h3.u.N()` AuthInfo | `h3.u.Q()L.../AuthInfo;` | 状态展示 |
| `h3.u.K()` 取租约 | `h3.u.N()Lh3/E;` | 租约类 `h3.D→E`，元数据 `h3.f→e` |
| `h3.u.v()V` 联网校验 | `private native v(Lh3/w;Lh3/o;)V` | 入口 `h3.u.x()V` |
| `h3.d.d0()Z` | 保留 | 判定 `h3.c` 是否为 `b(OK_ONLINE)` / `c(OK_OFFLINE)` |
| `h3.B.c0()Z` | 移除 | commit 结果改由 `h3.C(result, version)` 承载 |
| `NativeAuthCore.b(...6 参)` | `b(S,S,[B,[B)` 静态 4 参 | 两者都汇到 native `verifyRaw` / `nativeVerify` |
| `NativeSnapshotGate.c/d/e/f/a` Java 包装 | 读取直接 native：`currentModuleSnapshot()` / `currentTargetSimSnapshot()` / `currentRegionalSnapshot()` | 提交仍是 Java 包装 `c/d/e`，内部调 native `commit` |
| — | 新增 `h3.u.Z()Z` | 状态机授权判定 |
| — | 新增 `h3.D.a(Z)V` | **跨进程授权标志**（`AtomicBoolean a/b`），被 `hook/core/ModuleEntry` 与 `ipc/*` 共用 |
| — | 新增 `h3.C` | 提交结果包装 = `h3.d` + version |

枚举（1.0.8，md 名从 smali `const-string` 读出）：
`h3.v` = a INIT / b VERIFYING / **c AUTHORIZED_ONLINE** / d AUTHORIZED / e AUTHORIZED_OFFLINE / f NETWORK_ERROR / g EXPIRED / h REVOKED / i NOT_AUTHORIZED / j DEVICE_MISMATCH / k INTERNAL_ERROR
`h3.c` 枚举值 = b `OK_ONLINE` / c `OK_OFFLINE` / d..i 各类 ERR（`ERR_NO_LEASE`…`ERR_INTERNAL`）

## 2. 授权链路拆解（1.0.8）

```
VirtualRegionApplication ──► h3.u (授权状态机)
                              ├─ S()Z   native 授权判定      ← 14 处 Java 调用点
                              ├─ Z()Z   状态机判定
                              ├─ x()V   联网校验入口 → private native v(w,o)
                              ├─ c0(E)  租约校验   → h3.d(结果, 到期, …)
                              ├─ b0(v,S,S) 状态迁移
                              └─ N()Lh3/E; 取租约（空则签发）
                                    │
        ┌───────────────────────────┴────────────────────────────┐
        ▼                                                        ▼
NativeAuthCore.a(E,S,Z) / .b(S,S,[B,[B)              NativeSnapshotGate
   └─ private native verifyRaw / nativeVerify            ├─ c([B,ModuleSnapshot,J,…)Lh3/C;   kind=1 提交
                                                          ├─ e(String,TargetSimSnapshot,J,…)  kind=2 提交
                                                          ├─ d([B,RegionalSnapshot,J,…)       kind=3 提交
                                                          │    └─ private native commit(...)  ← 验租约后落库
                                                          ├─ b(I)J / a(IJ)Z  版本 / 清除
                                                          └─ native currentModuleSnapshot()/currentTargetSimSnapshot()/currentRegionalSnapshot()  ← 39 处读取
```

- nmmp 在 `<clinit>` 里通过 `NativeUtil.classesInit0(n)` 注册抽取方法（`NativeSnapshotGate` = 10 个），
  因此 **native 声明一个都不动**，解锁全部落在 Java 层。
- `hook/core/ModuleEntry` 是 APK 内自带的 **LSPosed 模块入口**（`META-INF/xposed/java_init.list`），
  它在 `onModuleLoaded` 里读 `h3.D.b`、在 `onPackageReady` 里安装各应用 hook。

## 3. 解锁策略（纯 smali，未改任何 .so）

### 3.1 patch 清单

| 文件 | 改法 |
|------|------|
| 新增 `smali/vr/Store.smali` | 双 `ConcurrentHashMap` 快照内存 store（kind→对象 / kind→版本）+ 恒真授权判定 `a(Lh3/u;)Z` + `currentXXX()` 替身 |
| `h3/D.smali`（=`D.smali`） | `clinit` 初值 `0x0→0x1`（a/b 两个 AtomicBoolean 恒 true）；`a(Z)V` 重写为忽略入参、双 `set(true)` |
| `h3/u.smali` | `Z()Z→true`；`x()V→return-void`（联网静默）；`c0(E)→ new h3.d(OK_ONLINE, FAR, FAR, FAR, true)`；`b0()` 首行强制 `p1 = Lh3/v;->c`（状态恒 AUTHORIZED_ONLINE）；`N()` 租约为空时伪造 `h3.e(2,"UNLOCKED-FRIDA","vrf-unlock","permanent",0,FAR,FAR,FAR,Long(FAR))` + `h3.E(meta,[32B],[64B])` 回填 `t` 字段 |
| `auth/NativeAuthCore.smali` | `a(E,S,Z)`、`b(S,S,[B,[B)` 直接返回 OK 结果，不触 `verifyRaw` / `nativeVerify` |
| `auth/NativeSnapshotGate.smali` | `c/d/e`（提交包装）→ `Lvr/Store;->put(kind, obj, ver)` + 返回 `h3.C(OK, ver)`；`b(I)J` → `Store.ver`；`a(IJ)Z` → `Store.clear` |
| `auth/AuthorizationRequiredReceiver.smali` | `onReceive` → `return-void`（授权失效广播失效化） |
| 全局 14 处 | `invoke-virtual {..}, Lh3/u;->S()Z` → `invoke-static {..}, Lvr/Store;->a(Lh3/u;)Z` |
| 全局 39 处 | `NativeSnapshotGate;->currentXXX()` → `Lvr/Store;->currentXXX()`（34 Module + 3 TargetSim + 2 Regional） |

`FAR = 4102444800`（2100-01-01 UTC）= smali 字面量 `0xf4865700L`；`ISSUED = 1577836800` = `0x5e0be100L`。

### 3.2 为什么用「调用点重定向」而不是「改 native 方法」

`S()`、`currentXXX()` 都是 nmmp 抽取的 native 方法：方法体已被抽走，Java 侧只剩声明；
直接改声明会破坏 `classesInit0(n)` 的注册计数 → 类初始化失败。所以在**消费方**（Java 调用点）重定向，
既保留 native 注册结构，又不依赖 so 内部实现。

### 3.3 重打包

```bash
python patch_vr108.py apktool_108
apktool b apktool_108 -o out_unsigned.apk
zipalign -f -p 4 out_unsigned.apk aligned.apk
apksigner sign --ks vrf-unlock.keystore --ks-pass pass:vrfunlock --ks-key-alias vrf \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true aligned.apk
adb shell "su -c 'pm install -r -d /data/local/tmp/aligned.apk'"     # MIUI 绕安装确认
```

签名证书：`CN=VR Unlock, OU=Unlock, O=FVR`，SHA-256 `f94edccb6aa3725e178f0d41a7a664d6114660e64af2a7eb4b2c15c3511cb010`。

## 4. 重点：目标应用作用域（本次踩到并定位的真问题）

**现象**：APK 装好、模块在 LSPosed 里启用、重启手机后，主界面「已授权」，但在 QQ 里改定位**不生效**。

**定位过程**（全部为真机取证）：

1. `LSPosed modules_config.db` 里 `io.github.zhou6514ctrl.virtualregion` 存在且 `enabled=1`，
   作用是 `system / android / com.android.phone / com.android.bluetooth / com.google.android.gms`。
2. 抓 LSPosed 运行日志（`/data/adb/lspd/log/verbose_*.log`）统计「实际被注入的 包[模块] 组合」：
   ```
   (com.autonavi.minimap)[io.github.ldxm666.amapenhancer, …]
   (com.tencent.mobileqq)[com.houvven.impad, …]
   (system)[org.frknkrc44.hma_oss, …]
   ```
   → **完全没有 VirtualRegion**；全文检索 `zhou6514ctrl` = 0 命中。
3. 结论：VirtualRegion 的环境注入宿主是它**自带的嵌入式 LSPosed 模块**，
   而模块只注入「被勾选作用域」的进程。QQ 没在作用域里 → QQ 进程里 ModuleEntry 从未运行 →
   定位 hook 根本没装 → 定位自然不变。

**正确姿势**：LSPosed → 模块 → VirtualRegion → 作用域里**把目标应用也勾上**（QQ `com.tencent.mobileqq`、
微信 `com.tencent.mm`、高德 `com.autonavi.minimap` 等），强停目标应用后重开。
主界面上那句「以下功能需要勾选目标应用作用域」即指此。

## 5. 真机验证记录

| 检查项 | 结果 |
|--------|------|
| 原包签名 | `CN=zhou`，v3 方案（`apksigner verify` 通过） |
| 重打包安装 | `Success`（v3 签名；MIUI 需 `su -c pm install` 绕 USER_RESTRICTED） |
| 冷启动 | 无卡密弹窗，无 FATAL / VerifyError |
| 主界面 | 右上 **「已授权」**；三步走卡片正常渲染 |
| 环境 / 应用 | 「已保存 1 个环境」「已启用 1 个应用」 |
| 生效状态 | 「设置正在同步到系统服务」→ 需把目标应用纳入作用域后完成第 3 步 |
| LSPosed | 模块 `enabled=1`，作用域 5 项系统侧；目标应用需手工补充 |
| Frida 动态版 | 5 个点位组全部 patch 成功（见下） |

Frida 注入日志（PID 实测）：

```
[VRF-Unlock][16292] script loaded (VR 1.0.8 / versionCode 109)
[VRF-Unlock][16292] NativeAuthCore.a(E,S,Z) / b(S,S,[B,[B) -> OK_ONLINE
[VRF-Unlock][16292] NativeSnapshotGate commit/read -> Java 内存 store
[VRF-Unlock][16292] h3.u S/Z/x/c0/b0/N -> 常授权 / 静默 / 永久租约
[VRF-Unlock][16292] AuthorizationRequiredReceiver.onReceive -> no-op
```

## 6. 踩坑实录

1. **寄存器 16 上限（本次新踩）**：`u.N()` 里同时用到 v0..v13 且需要 `p0`（`this`），
   若写 `.locals 16`，`p0 = v16` 超出非 range 指令可寻址的 v0..v15 →
   `apktool b` 直接报 `Invalid register: v16. Must be between v0 and v15`。
   压到 `.locals 15` 即解（p0 落到 v15，v0..v14 足够放下全部临时值）。
2. **NTFS 大小写不敏感**：apktool 用 `.1.smali` 后缀规避同名类（`c.1.smali=Lh3/c;`、`d.1.smali=Lh3/d;`），
   打补丁必须按 `.1.smali` 路径定位，不能按类名拼路径。新增类一律放全新包（本例 `Lvr/Store;`）。
3. **wide 参数占双槽**：`a(IJ)Z` 里 `invoke-static {p0, p1}` 少一个槽（J 占 p1/p2）→
   system_server / bluetooth 启动即 `VerifyError` → 必须 `{p0, p1, p2}`。
4. **模块"启用"≠"生效"**：`modules_state.enabled=1` 只代表开关打开；
   没有作用域进程时模块不会加载。判断依据只能是 LSPosed 运行日志里的 `(包名)[模块名,…]`。
5. **LSPosed 管理器 2.1.1 不自带 APK**：需要 `pm install /data/adb/modules/zygisk_lsposed/manager.apk`
   才能进 UI 管理（`org.lsposed.manager`）。

## 7. 遗留问题

1. 环境广场云端上传/下载：服务端验卡，客户端无法伪造。
2. 「输入新卡密」对话框保留原样，走已静默的链路，无副作用。
3. 若后续版本把 `S()` 的消费方判定内联进 nmmp VM（不再经 Java 调用点），
   需把 `Lvr/Store;->a` 的重定向换成 hook `h3.D` 标志消费位。
4. 快照 store 是**进程内**内存实现：提交与读取都发生在 VirtualRegion 自身进程的链路
   （`ipc/e` `ipc/r` `E3/k` `n3/f` 四个提交点、39 个读取点）已验证一致；
   若后续把「写入」与「跨进程读取」拆到不同进程，需要改成文件/共享内存后端。
5. 升级重装后需在 LSPosed 重新确认作用域并重启（签名变更属正常流程）。

## 8. Frida 动态版

`hook_vrf_unlock.js` 已按 1.0.8 点位重写（对齐解包 patch 的语义），任意进程可用，
类不可见时每 2s 重试，单点失败不影响其余点位：

| 点位 | 处理 |
|------|------|
| `h3.u` | `S()→true`、`Z()→true`、`x()→空`、`c0(E)→OK_ONLINE`、`b0(*)→状态强制 AUTHORIZED_ONLINE`、`N()→伪造永久租约回填 t` |
| `h3.D` | 静态标志位 + `a(Z)` 恒 `set(true)`（双 AtomicBoolean） |
| `NativeAuthCore` | `a(E,S,Z)` / `b(S,S,[B,[B)` → 直接返回 `h3.d(OK_ONLINE, FAR, FAR, FAR, true)` |
| `NativeSnapshotGate` | `c/d/e` 提交接 `PER_PROC` 内存存储并返回 `h3.C`；`b(I)I`/`a(IJ)Z` 走内存；`currentXXX()` 直接替换 native 实现返回内存对象 |
| `AuthorizationRequiredReceiver` | `onReceive → no-op` |

用法：

```bash
frida -U -p $(adb shell pidof io.github.zhou6514ctrl.virtualregion) -l hook_vrf_unlock.js   # 主进程 attach
frida -U -n system_server -l hook_vrf_unlock.js                                             # system_server
frida -U -n com.tencent.mobileqq -l hook_vrf_unlock.js                                      # 目标应用（模块注入后类可见时）
```

> 注：本机 `frida -U -f <pkg>` spawn 模式在 KernelSU 环境下会报
> `need Gadget to attach on jailed Android`，请用「先启动应用，再 `-p <pid>` attach」的方式。
