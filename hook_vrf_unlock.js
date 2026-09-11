'use strict';
/*
 * VirtualRegion 1.0.8 (versionCode 109) — 授权链路 Frida Hook
 * 目标包名: io.github.zhou6514ctrl.virtualregion
 *
 * ================================================================
 * 1.0.4 → 1.0.8 点位变化对照 (旧版脚本失效原因)
 * ================================================================
 *   h3.u.P()Z  授权判定         → h3.u.S()Z          (native 化, nmmp 抽取)
 *   h3.u.W()Z  弹窗判定         → 移除, 弹窗改走 binder auth/a.isAuthorized() + UI 状态
 *   h3.u.N()   AuthInfo         → h3.u.Q()AuthInfo (展示) / h3.u.P()AuthorizationSnapshot
 *   h3.u.K()   取租约           → h3.u.N()Lh3/E;     (租约类 h3.D→E, 元数据 h3.f→e)
 *   h3.u.v()V  联网校验         → h3.u.v(Lh3/w;Lh3/o;)V private native, 入口 h3.u.x()V
 *   h3.B.c0()Z commit 结果      → 移除, 改由 h3.C (result+version) 承载
 *   —                           → 新增 h3.u.Z()Z     状态机授权判定
 *   —                           → 新增 h3.D.a(Z)V   跨进程授权标志 (AtomicBoolean a/b)
 *   NativeAuthCore.b(6参)       → NativeAuthCore.b(S,S,[B,[B) 静态 4 参 → native verifyRaw
 *   NativeSnapshotGate.c/d/e/f/a Java 包装
 *                               → 读取直接 native: currentModuleSnapshot/currentTargetSimSnapshot/
 *                                 currentRegionalSnapshot; 提交仍走 Java 包装 c/d/e
 *
 * ================================================================
 * 本脚本覆盖点 (1.0.8)
 * ================================================================
 *   h3.u               S()/Z()/x()/c0(E)/b0(v,S,S)/N()
 *   h3.D               静态标志位 + a(Z) 恒 true (跨进程授权标志)
 *   NativeAuthCore     a(E,S,Z) / b(S,S,[B,[B) 租约验签绕过
 *   NativeSnapshotGate c/d/e 提交接管 + b/a 版本/清除 + currentXXX() 内存读取
 *   AuthorizationRequiredReceiver  onReceive 失效化
 *
 * 用法 (需 root + frida-server, 与本机 frida 版本一致):
 *   主进程注入:      frida -U -f io.github.zhou6514ctrl.virtualregion -l hook_vrf_unlock.js
 *   attach 现有进程: frida -U -n io.github.zhou6514ctrl.virtualregion -l hook_vrf_unlock.js
 *   system_server:   frida -U -n system_server -l hook_vrf_unlock.js   (作用域内含系统服务时)
 *   目标应用进程:    frida -U -n <目标进程名> -l hook_vrf_unlock.js    (LSPosed 注入后类可见时)
 *
 * 脚本在任意进程内自动探测类可见性, 未加载则每 2s 重试, 单点失败不影响其余点位。
 */

var FAR = 4102444800;      // 2100-01-01 epoch 秒
var ISSUED = 1577836800;   // 2020-01-01
var SNAP = {};             // 进程内快照存储 kind -> {obj, ver}
var done = {};

function log(m) { console.log('[VRF-Unlock][' + Process.id + '] ' + m); }

function okResult() {
  var d = Java.use('h3.d'), c = Java.use('h3.c');
  return d.$new(c.b.value, FAR, FAR, FAR, true);
}

function snapshotOf(kind) {
  var o = SNAP[kind];
  return o ? o.obj : null;
}

function patchAuthCore() {
  if (done.nac) return true;
  try {
    var NAC = Java.use('io.github.zhou6514ctrl.virtualregion.auth.NativeAuthCore');
    NAC.a.overload('h3.E', 'java.lang.String', 'boolean').implementation = function () {
      return okResult();
    };
    NAC.b.overload('java.lang.String', 'java.lang.String', '[B', '[B').implementation = function () {
      return okResult();
    };
    done.nac = true; log('NativeAuthCore.a(E,S,Z) / b(S,S,[B,[B) -> OK_ONLINE');
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

    var CMS = 'io.github.zhou6514ctrl.virtualregion.model.ModuleSnapshot';
    var CTS = 'io.github.zhou6514ctrl.virtualregion.model.TargetSimSnapshot';
    var CRS = 'io.github.zhou6514ctrl.virtualregion.model.RegionalSnapshot';

    NSG.c.overload('[B', CMS, 'long', 'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (bytes, snap, ver, dev, key, lease, sig) {
        SNAP[1] = { obj: Java.retain(snap), ver: ver };
        return C.$new(okResult(), ver);
      };
    NSG.d.overload('[B', CRS, 'long', 'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (bytes, snap, ver, dev, key, lease, sig) {
        SNAP[3] = { obj: Java.retain(snap), ver: ver };
        return C.$new(okResult(), ver);
      };
    NSG.e.overload('java.lang.String', CTS, 'long', 'java.lang.String', 'java.lang.String', '[B', '[B').implementation =
      function (id, snap, ver, dev, key, lease, sig) {
        SNAP[2] = { obj: Java.retain(snap), ver: ver };
        return C.$new(okResult(), ver);
      };

    NSG.b.overload('int').implementation = function (kind) {
      var o = SNAP[kind]; return o ? o.ver : -1;
    };
    NSG.a.overload('int', 'long').implementation = function (kind, ver) {
      delete SNAP[kind]; return true;
    };

    NSG.currentModuleSnapshot.implementation = function () {
      return snapshotOf(1) === null ? null : Java.cast(snapshotOf(1), ModuleSnapshot);
    };
    NSG.currentTargetSimSnapshot.implementation = function () {
      return snapshotOf(2) === null ? null : Java.cast(snapshotOf(2), TargetSimSnapshot);
    };
    NSG.currentRegionalSnapshot.implementation = function () {
      return snapshotOf(3) === null ? null : Java.cast(snapshotOf(3), RegionalSnapshot);
    };

    done.nsg = true; log('NativeSnapshotGate commit/read -> Java 内存 store');
    return true;
  } catch (e) { return false; }
}

function patchU() {
  if (done.u) return true;
  try {
    var u = Java.use('h3.u');
    var v = Java.use('h3.v');
    var AUTHORIZED_ONLINE = v.c.value;

    u.S.implementation = function () { return true; };
    u.Z.implementation = function () { return true; };
    u.x.implementation = function () { };

    u.c0.overload('h3.E').implementation = function () { return okResult(); };

    var b0 = u.b0.overload('h3.v', 'java.lang.String', 'java.lang.String');
    u.b0.overload('h3.v', 'java.lang.String', 'java.lang.String').implementation =
      function (st, msg, code) { return b0.call(this, AUTHORIZED_ONLINE, msg, code); };

    u.N.implementation = function () {
      var lease = this.t.value;
      if (lease === null) {
        var meta = Java.use('h3.e').$new(2, 'UNLOCKED-FRIDA', 'vrf-unlock', 'permanent',
          ISSUED, FAR, FAR, FAR, Java.use('java.lang.Long').valueOf(FAR));
        var b1 = Java.array('byte', new Array(32).fill(0x41));
        var b2 = Java.array('byte', new Array(64).fill(0x42));
        lease = Java.use('h3.E').$new(meta, b1, b2);
        this.t.value = lease;
      }
      return lease;
    };

    done.u = true; log('h3.u S/Z/x/c0/b0/N -> 常授权 / 静默 / 永久租约');
    return true;
  } catch (e) { return false; }
}

function patchFlag() {
  if (done.flag) return true;
  try {
    var D = Java.use('h3.D');
    D.a.overload('boolean').implementation = function () {
      this.a.value.set(true);
      this.b.value.set(true);
    };
    D.a.value.set(true);
    D.b.value.set(true);
    done.flag = true; log('h3.D 跨进程授权标志 -> 恒 true');
    return true;
  } catch (e) { return false; }
}

function patchReceiver() {
  if (done.arr) return true;
  try {
    Java.use('io.github.zhou6514ctrl.virtualregion.auth.AuthorizationRequiredReceiver')
      .onReceive.implementation = function () { };
    done.arr = true; log('AuthorizationRequiredReceiver.onReceive -> no-op');
    return true;
  } catch (e) { return false; }
}

function applyAll() {
  Java.perform(function () {
    if (done.nac && done.nsg && done.u && done.flag && done.arr) return;
    patchAuthCore(); patchGate(); patchU(); patchFlag(); patchReceiver();
    if (!(done.nac && done.nsg && done.u && done.flag && done.arr)) {
      setTimeout(applyAll, 2000);
    } else {
      log('全部点位已接管');
    }
  });
}

setImmediate(applyAll);
log('script loaded (VR 1.0.8 / versionCode 109)');
