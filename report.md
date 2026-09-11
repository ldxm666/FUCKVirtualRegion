# VirtualRegion 1.0.8 逆向分析与解锁报告

> 分析日期：2026-09-11（1.0.4 报告迭代）
> 工具链：apktool 3.0.2 / jadx 1.5.5 / apksigner / adb（小米 Android 16 / arm64）

## 0. 结论速览

| 产物 | 路径 |
|------|------|
| 解锁签名包 | `VirtualRegion_1.0.8_unlocked.apk`（versionCode 109） |
| smali patch 脚本 | `patch_vr108.py`（幂等，带命中断言） |
| 新增 helper 类 | `vr_Store.smali`（快照内存 store，编译进 `Lvr/Store;`） |
| Frida 动态 hook | `hook_vrf_unlock.js`（已同步适配 1.0.8） |

- 卡密弹窗：**已去除**，主界面直接「已授权」
- 授权状态：**授权有效 / 授权到期 2100年1月1日**（伪造租约 FAR 时间戳）
- 快照链路：**设置已生效**（system_server 验收回执正常，三进程层全通）
- 全进程零 VerifyError / 零崩溃（system_server / bluetooth / phone / 目标 app 均验证）
- 保留限制：环境广场云端上传/下载仍为服务端门禁（同 1.0.4）

## 1. 1.0.4 → 1.0.8 结构变化（关键）

新版对授权链做了**方法重排 + 部分 native 化**（nmmp 方法抽取范围扩大），老点位全部改名/搬移：

| 1.0.4 | 1.0.8 | 说明 |
|-------|-------|------|
| `h3.u.P()Z` 授权判定 | `h3.u.S()Z` | **native 化**（nmmp 抽取） |
| `h3.u.W()Z` 弹窗判定 | 移除 | 弹窗改走 binder `auth/a.isAuthorized()` + UI 状态 |
| `h3.u.N()` AuthInfo | `h3.u.Q()` | 状态展示 |
| `h3.u.K()` 取租约 | `h3.u.N()Lh3/E;` | 租约类 `h3.D` → `h3.E`，元数据 `h3.f` → `h3.e` |
| `h3.u.v()V` 联网校验 | `h3.u.v(Lh3/w;Lh3/o;)V` **private native** | 入口 `x()V` |
| `h3.d.d0()Z` | 保留 | 语义不变 |
| `h3.B.c0()Z` | 移除 | 无对应点 |
| `NativeAuthCore.b(...6参)` | `b(S,S,[B,[B)` 静态 4 参 | 都汇到 native `verifyRaw` |
| `NativeSnapshotGate.c/d/e/f/a` Java 包装 | 读取直接 native：`currentModuleSnapshot/currentTargetSimSnapshot/currentRegionalSnapshot` | 提交走 native `commit(...)`，包装方法 `c/d/e` 仍是 Java |
| — | 新增 `h3.u.Z()Z` | 状态机授权判定 |
| — | 新增 `h3.D.a(Z)V` | **跨进程授权标志**（AtomicBoolean a/b，IPC 与 ModuleEntry 共用） |
| — | 新增 `h3.C` | 提交结果包装（result + version） |
| — | 新增 `h3.u.P()` → `AuthorizationSnapshot` | binder 快照服务（`auth/a` = IAuthorizationService.Stub） |

状态枚举 `h3.v`：a=INIT b=VERIFYING **c=AUTHORIZED_ONLINE** d=AUTHORIZED e=AUTHORIZED_OFFLINE f=NETWORK_ERROR g=EXPIRED h=REVOKED i=NOT_AUTHORIZED j=DEVICE_MISMATCH k=INTERNAL_ERROR l=UNAUTHORIZED。校验码 `h3.c`：b=OK_ONLINE c=OK_OFFLINE …（`h3.d.d0()` 判 b/c）。

## 2. 解锁策略（纯 smali，未改 so，native 声明一个不碰）

nmmp 在 `clinit` 里通过 `NativeUtil.classesInit0(n)` 注册抽取方法（含 `S()`、`v()`、`currentXXX()`、`verifyRaw`、`commit` 等），因此**所有 native 声明原样保留**，解锁全部在 Java 层：

### 2.1 patch 清单

| 文件 | 改法 |
|------|------|
| 新增 `Lvr/Store;` | 静态 `ConcurrentHashMap`×2 的快照内存 store：`put/get/ver/clear` + 三个 `currentXXX()` 替身 |
| `h3/D.smali` | `clinit` 初值 `0x0→0x1`；`a(Z)V` 重写为忽略参数、a/b 双 set(true) |
| `h3/u.smali` | `Z()Z→true`；`x()V→return`（联网静默）；`c0(E)→new h3.d(OK_ONLINE,FAR,FAR,FAR,true)`；`b0()` 开头强制 `p1=Lh3/v.c`（状态恒 AUTHORIZED_ONLINE）；`N()` 租约为空时伪造 `h3.e(2,"UNLOCKED-FRIDA","vrf-unlock","permanent",0,FAR,FAR,FAR,Long(FAR))` + `h3.E(meta,[32B],[64B])` 回填 `t` 字段 |
| `auth/NativeAuthCore.smali` | `a(E,S,Z)`、`b(S,S,[B,[B)` 直接返回 OK 结果，不触 `verifyRaw` |
| `auth/NativeSnapshotGate.smali` | `c/d/e`（commit 包装）→ 存 `Lvr/Store;` + 返回 `h3.C(OK, ver)`；`b(I)J` → `Store.ver`；`a(IJ)Z` → `Store.clear` |
| `auth/AuthorizationRequiredReceiver.smali` | `onReceive` → no-op |
| 全局 14 处 | `invoke-virtual {..}, Lh3/u;->S()Z` → `invoke-static {..}, Lvr/Store;->a(Lh3/u;)Z`（恒真） |
| 全局 39 处 | `NativeSnapshotGate;->currentXXX()` → `Lvr/Store;->currentXXX()`（34 Module + 3 TargetSim + 2 Regional） |

`FAR = 4102444800`（2100-01-01），smali 字面量 `0xf4865700L`。

### 2.2 重打包

```bash
python patch_vr108.py          # 应用全部补丁（幂等，命中数断言）
apktool b apktool_108 -o out_unsigned.apk
zipalign -f 4 out_unsigned.apk aligned.apk
apksigner sign --ks vrf-unlock.keystore --ks-pass pass:vrfunlock --ks-key-alias vrf \
  --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true aligned.apk
adb shell "su -c 'pm install -r /data/local/tmp/aligned.apk'"   # MIUI 绕安装确认
```

## 3. 踩坑实录（Windows 作业三连）

1. **NTFS 大小写不敏感**：`h3` 包里 `u.smali`（Lh3/u;）与新建 `U.smali`（Lh3/U;）互相覆盖——第一次写 helper 直接把 66KB 的 `u.smali` 干掉了。apktool 自身用 `.1.smali` 后缀规避（`c.1.smali=Lh3/c;`、`d.1.smali=Lh3/d;`）。新增类一律放全新包（本例 `Lvr/Store;`）。
2. **寄存器 16 上限**：`.locals 16` 时参数 `p0`=v16，非 range 指令只允许 v0-v15 → VerifyError。压到 `.locals 15`。
3. **wide 参数占双槽**：`a(IJ)Z` 里 `invoke-static {p0, p1}` 少了一个槽（J 占 p1/p2 两槽），system_server/bluetooth/phone 启动即 `VerifyError` 拒绝整个类 → 必须写 `{p0, p1, p2}`。主进程 UI 链路不踩这个点，只有重启后全进程注入才暴露——**验证必须重启**。

## 4. 真机验证（小米 / Android 16 / arm64）

| 检查项 | 结果 |
|--------|------|
| root 安装 | `Success`（v3 签名，MIUI 绕 USER_RESTRICTED） |
| 冷启动 | pid 存活，logcat 无 FATAL/VerifyError |
| 开屏 | 无卡密弹窗，主界面右上「**已授权**」 |
| 授权详情 | 当前状态：授权有效；到期：**2100年1月1日 08:00**；设备编号 vrf1_... |
| LSPosed | 模块 enabled=1，作用域 system/android/gms/phone/bluetooth 保留 |
| 重启后 | 配置概览「虚拟环境已配置」，步骤 3「**设置已生效**」 |
| 多进程 | system_server / bluetooth / phone 进程 NativeSnapshotGate 零 VerifyError |

## 5. 遗留问题

1. 环境广场云端上传/下载：服务端验卡，客户端无法伪造（同 1.0.4）。
2. 「输入新卡密」对话框保留原样，走已静默的链路，无副作用。
3. 若后续版本把 `S()` 的消费方判定内联进 nmmp VM（不再经 Java 调用点），需把 `Lvr/Store;->a` 的重定向换成 hook `h3.D` 标志消费位。
4. 升级重装后需在 LSPosed 重新确认作用域并重启（签名变更属正常流程）。

## 6. Frida 动态版

`hook_vrf_unlock.js` 已同步 1.0.8 点位（S/Z/c0/x/b0/N + D 标志 + NAC a/b + NSG commit/read + ARR no-op），用法不变：

```bash
frida -U -f io.github.zhou6514ctrl.virtualregion -l hook_vrf_unlock.js   # 主进程
frida -U -n system_server -l hook_vrf_unlock.js                          # system_server
```
