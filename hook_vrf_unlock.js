'use strict';
/*
 * VirtualRegion 1.0.8 — 授权链路 Frida Hook (适配新版)
 * 目标: io.github.zhou6514ctrl.virtualregion
 *
 * 1.0.4 → 1.0.8 点位变化对照:
 *   h3.u.P()Z(授权判定)        → h3.u.S()Z (native 化)
 *   h3.u.W()Z(弹窗判定)        → 移除, 弹窗走 binder auth/a.isAuthorized()+UI状态
 *   h3.u.N()AuthInfo           → h3.u.Q()AuthInfo (状态展示) / h3.u.P()AuthorizationSnapshot
 *   h3.u.K()租约                → h3.u.N()Lh3.E (租约类 D→E)
 *   h3.u.v()V(联网校验)        → h3.u.v(Lh3.w;Lh3.o;)V private native 化; 入口 x()V
 *   h3.u.d0?                    → h3.d.d0()Z 保留
 *   h3.B.c0()                   → 移除(1.0.8 无此点)
 *   h3.u.Z()Z 新增              → 新版授权判定(m.b 标志+状态机), 恒真
 *   NativeAuthCore.b(+String,boolean 参数) → 静态 4 参 b(S,S,[B,[B)
 *   NativeSnapshotGate.b/c/d/e/f/a → commit 包装 c/d/e(存取), b(I)J 版本, a(IJ)Z 清除,
 *                                    读取直接 native: currentModuleSnapshot 等
 *   h3.D.a(Z)V 新增             → 跨进程授权标志 AtomicBoolean 写入口(恒 set true)
 *
 * 覆盖点(1.0.8):
 *   h3.u          — S()/Z()/c0()/N()/x()/b0()
 *   h3.d          — d0() 布尔
 *   h3.D          — a(Z) 恒 set(true) + 静态初值
 *   NativeAuthCore— a()/b() native 租约验签绕过
 *   NativeSnapshotGate — c()/d()/e() 提交接管, b()/a() 版本/清除, currentXXX() 内存读
 *   AuthorizationRequiredReceiver — onReceive 失效化
 *
 * 用法(需要 root + frida-server):
 *   主进程:      frida -U -f io.github.zhou6514ctrl.virtualregion -l hook_vrf_unlock.js
 *   system_server: frida -U -n system_server -l hook_vrf_unlock.js
 *   目标 App:    frida -U -n <目标进程> -l hook_vrf_unlock.js
 * 脚本自动检测各进程内类可见性, 类未加载时每 2s 重试。
 */

var FAR = 4102444800;      // 2100-01-01 epoch seconds
var ISSUED = 1577836800;   // 2020-01-01
var PER_PROC = {};         // 快照内存存储 kind -> {s, v}
var done = {};

function log(msg) { console.log('[VRF-Unlock][' + Process.id + '] ' + msg); }

function okResult() { // h3.d(OK_ONLINE, FAR, FAR, FAR, true)
  var d = Java.use('h3.d'), c = Java.use('h3.c');
  return d.$new(c.b.value, FAR, FAR, FAR, true);
}

function patchAuthCore() {
  if (done.nac) return true;
  try {
    var NAC = Java.use('io.github.zhou6514ctrl.virtualregion.auth.NativeAuthCore');
    NAC.b.overload('java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function () { return okResult(); };
    NAC.a.overload('h3.E', 'java.lang.String', 'boolean').implementation =
      function () { return okResult(); };
    done.nac = true; log('NativeAuthCore.a/b -> OK_ONLINE');
    return true;
  } catch (e) { return false; }
}

function patchGate() {
  if (done.nsg) return true;
  try {
    var NSG = Java.use('io.github.zhou6514ctrl.virtualregion.auth.NativeSnapshotGate');
    var C = Java.use('h3.C');
    var ModuleSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.ModuleSnapshot');
    var TargetSimSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.TargetSimSnapshot');
    var RegionalSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.RegionalSnapshot');

    // c: kind=1 commit (canonical, ModuleSnapshot, ver, dev, key, lease, sig)
    NSG.c.overload('[B', 'io.github.zhou6514ctrl.virtualregion.model.ModuleSnapshot', 'long',
      'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (bytes, snap, ver, dev, key, lease, sig) {
        PER_PROC[1] = { s: Java.retain(snap), v: ver };
        return C.$new(okResult(), ver);
      };
    // d: kind=3 commit (RegionalSnapshot)
    NSG.d.overload('[B', 'io.github.zhou6514ctrl.virtualregion.model.RegionalSnapshot', 'long',
      'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (bytes, snap, ver, dev, key, lease, sig) {
        PER_PROC[3] = { s: Java.retain(snap), v: ver };
        return C.$new(okResult(), ver);
      };
    // e: kind=2 commit (TargetSimSnapshot)
    NSG.e.overload('java.lang.String', 'io.github.zhou6514ctrl.virtualregion.model.TargetSimSnapshot', 'long',
      'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (id, snap, ver, dev, key, lease, sig) {
        PER_PROC[2] = { s: Java.retain(snap), v: ver };
        return C.$new(okResult(), ver);
      };
    // b: 版本查询
    NSG.b.overload('int').implementation = function (kind) {
      var o = PER_PROC[kind]; return o ? o.v : -1;
    };
    // a: 清除
    NSG.a.overload('int', 'long').implementation = function (kind, ver) {
      delete PER_PROC[kind]; return true;
    };
    // 读取(native 方法, Frida 可直接替换 implementation)
    NSG.currentModuleSnapshot.implementation = function () {
      var o = PER_PROC[1]; return o ? Java.cast(o.s, ModuleSnapshot) : null;
    };
    NSG.currentTargetSimSnapshot.implementation = function () {
      var o = PER_PROC[2]; return o ? Java.cast(o.s, TargetSimSnapshot) : null;
    };
    NSG.currentRegionalSnapshot.implementation = function () {
      var o = PER_PROC[3]; return o ? Java.cast(o.s, RegionalSnapshot) : null;
    };
    done.nsg = true; log('NativeSnapshotGate commit/read -> Java 内存存储');
    return true;
  } catch (e) { return false; }
}

function patchU() {
  if (done.u) return true;
  try {
    var u = Java.use('h3.u');
    var v = Java.use('h3.v');
    var AUTHORIZED_ONLINE = v.c.value;

    // S(): 授权判定(native) -> 恒真
    u.S.implementation = function () { return true; };
    // Z(): 状态机判定 -> 恒真
    u.Z.implementation = function () { return true; };
    // c0(E): 租约验证 -> OK_ONLINE
    u.c0.overload('h3.E').implementation = function () { return okResult(); };
    // x(): 联网校验入口 -> 静默
    u.x.implementation = function () { };

    // b0(v, msg, code): 所有状态迁移强制 AUTHORIZED_ONLINE
    var origB0 = u.b0.overload('h3.v', 'java.lang.String', 'java.lang.String');
    u.b0.overload('h3.v', 'java.lang.String', 'java.lang.String').implementation =
      function (st, msg, code) { origB0.call(this, AUTHORIZED_ONLINE, msg, code); };

    // N(): 租约为空时伪造永久租约并回填 t 字段
    u.N.implementation = function () {
      var lease = this.t.value;
      if (lease === null) {
        var e = Java.use('h3.e');
        var E = Java.use('h3.E');
        var meta = e.$new(2, 'UNLOCKED-FRIDA', 'vrf-unlock', 'permanent',
          ISSUED, FAR, FAR, FAR, Java.use('java.lang.Long').valueOf(FAR));
        var b1 = Java.array('byte', new Array(32).fill(0x41));
        var b2 = Java.array('byte', new Array(64).fill(0x42));
        lease = E.$new(meta, b1, b2);
        this.t.value = lease;
      }
      return lease;
    };
    done.u = true; log('h3.u S/Z/c0/x/b0/N -> 常授权/静默/永久租约');
    return true;
  } catch (e) { return false; }
}

function patchFlag() {
  if (done.flag) return true;
  try {
    // h3.D: 跨进程授权标志, a(Z) 恒 set(true)
    var D = Java.use('h3.D');
    D.a.overload('boolean').implementation = function () {
      this.a.value.set(true);
      this.b.value.set(true);
    };
    D.a.value.set(true);
    D.b.value.set(true);
    done.flag = true; log('h3.D.a/b -> 恒 true');
    return true;
  } catch (e) { return false; }
}

function patchMisc() {
  if (done.misc) return true;
  try {
    var R = Java.use('io.github.zhou6514ctrl.virtualregion.auth.AuthorizationRequiredReceiver');
    R.onReceive.implementation = function () { };
    done.misc = true; log('AuthorizationRequiredReceiver -> no-op');
    return true;
  } catch (e) { return false; }
}

function patchResultBool() {
  if (done.res) return true;
  try {
    var d = Java.use('h3.d');
    d.d0.implementation = function () { return true; };
    done.res = true; log('h3.d.d0() -> true');
    return true;
  } catch (e) { return false; }
}

function applyAll() {
  Java.perform(function () {
    var pending = !done.nac || !done.nsg || !done.u || !done.flag || !done.misc || !done.res;
    if (!pending) return;
    patchAuthCore(); patchGate(); patchU(); patchFlag(); patchMisc(); patchResultBool();
    if (pending) setTimeout(applyAll, 2000); // 模块类尚未加载则重试
  });
}

setImmediate(applyAll);
log('script loaded (VR 1.0.8)');
