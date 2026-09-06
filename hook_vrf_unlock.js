'use strict';
/*
 * VirtualRegion 1.0.4 — 授权链路 Frida Hook
 * 目标: io.github.zhou6514ctrl.virtualregion
 *
 * 覆盖点(与改包 patch 等价，动态版):
 *   h3.u          — P()/W()/N()/K()/v()  授权判定/弹窗触发/网络校验
 *   h3.d          — d0()                 校验结果布尔
 *   h3.B          — c0()                 commit 结果布尔
 *   NativeAuthCore— a()/b()              native 租约验签绕过
 *   NativeSnapshotGate — b()/c()/d()/e()/f()/a()  快照提交/读取接管(纯内存存储)
 *   AuthorizationRequiredReceiver — onReceive 失效化
 *
 * 用法(需要 root + frida-server):
 *   主进程:      frida -U -f io.github.zhou6514ctrl.virtualregion -l hook_vrf_unlock.js
 *   system_server: frida -U -n system_server -l hook_vrf_unlock.js   (模块作用域含 system_server 时)
 *   目标 App:    frida -U -n <目标进程>  -l hook_vrf_unlock.js       (LSPosed 注入后模块类可见时)
 * 脚本自动检测各进程内类可见性，类未加载时每 2s 重试。
 */

var FAR = 4102444800; // 2100-01-01 epoch seconds
var PER_PROC = {};    // 快照内存存储  kind -> {s, v}
var done = {};

function log(msg) { console.log('[VRF-Unlock][' + Process.id + '] ' + msg); }

function okResult() { // h3.d(OK_ONLINE, FAR, FAR, FAR, true)
  var d = Java.use('h3.d'), c = Java.use('h3.c');
  return d.$new(c.valueOf('OK_ONLINE'), FAR, FAR, FAR, true);
}

function patchAuthCore() {
  if (done.nac) return true;
  try {
    var NAC = Java.use('io.github.zhou6514ctrl.virtualregion.auth.NativeAuthCore');
    NAC.b.overload('java.lang.String', 'java.lang.String', '[B', '[B', 'java.lang.String', 'boolean').implementation =
      function () { return okResult(); };
    NAC.a.overload('h3.D', 'java.lang.String', 'boolean').implementation =
      function () { return okResult(); };
    done.nac = true; log('NativeAuthCore.b/a -> OK_ONLINE');
    return true;
  } catch (e) { return false; }
}

function patchGate() {
  if (done.nsg) return true;
  try {
    var NSG = Java.use('io.github.zhou6514ctrl.virtualregion.auth.NativeSnapshotGate');
    var B = Java.use('h3.B');
    var ModuleSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.ModuleSnapshot');
    var TargetSimSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.TargetSimSnapshot');
    var RegionalSnapshot = Java.use('io.github.zhou6514ctrl.virtualregion.model.RegionalSnapshot');

    NSG.b.implementation = function (kind, bytes, snap, mode, ver, dev, key, lease, sig) {
      PER_PROC[kind] = { s: Java.retain(snap), v: ver };
      var res = okResult();
      return B.$new(res, ver);
    };
    NSG.c.implementation = function () {
      var o = PER_PROC[1]; return o ? Java.cast(o.s, ModuleSnapshot) : null;
    };
    NSG.e.implementation = function () {
      var o = PER_PROC[2]; return o ? Java.cast(o.s, TargetSimSnapshot) : null;
    };
    NSG.d.implementation = function () {
      var o = PER_PROC[3]; return o ? Java.cast(o.s, RegionalSnapshot) : null;
    };
    NSG.f.implementation = function (kind) {
      var o = PER_PROC[kind]; return o ? o.v : -1;
    };
    NSG.a.implementation = function (kind, ver) {
      delete PER_PROC[kind]; return true;
    };
    done.nsg = true; log('NativeSnapshotGate 提交/读取链路 -> Java 内存存储');
    return true;
  } catch (e) { return false; }
}

function patchU() {
  if (done.u) return true;
  try {
    var u = Java.use('h3.u');
    u.P.implementation = function () { return true; };
    u.W.implementation = function () { return false; };          // 永不弹卡密框
    u.v.implementation = function () { /* 静默: 不再请求授权服务器 */ };

    var v = Java.use('h3.v');
    var AuthInfo = Java.use('io.github.zhou6514ctrl.virtualregion.auth.AuthInfo');
    u.N.implementation = function () {
      return AuthInfo.$new(v.valueOf('AUTHORIZED_ONLINE'), 0,
        Math.floor(Date.now() / 1000), 'AUTHORIZED');
    };

    var D = Java.use('h3.D'), f = Java.use('h3.f'), L = Java.use('java.lang.Long');
    var ISSUED = 1577836800;
    u.K.implementation = function () {
      var lease = this.t.value;
      if (lease === null) {
        var meta = f.$new(2, 'UNLOCKED-FRIDA', 'vrf-frida', 'permanent',
          ISSUED, FAR, FAR, FAR, L.valueOf(FAR));
        var b1 = Java.array('byte', new Array(32).fill(0x41));
        var b2 = Java.array('byte', new Array(64).fill(0x42));
        lease = D.$new(meta, b1, b2);
        this.t.value = lease;
      }
      return lease;
    };
    done.u = true; log('h3.u P/W/N/K/v -> 常授权/免弹窗/静默');
    return true;
  } catch (e) { return false; }
}

function patchMisc() {
  if (done.misc) return true;
  try {
    var R = Java.use('io.github.zhou6514ctrl.virtualregion.auth.AuthorizationRequiredReceiver');
    R.onReceive.implementation = function () {};
    done.misc = true; log('AuthorizationRequiredReceiver -> no-op');
    return true;
  } catch (e) { return false; }
}

function patchResultBool() {
  if (done.res) return true;
  try {
    var d = Java.use('h3.d'), B = Java.use('h3.B');
    d.d0.implementation = function () { return true; };
    B.c0.implementation = function () { return true; };
    done.res = true; log('h3.d.d0()/h3.B.c0() -> true');
    return true;
  } catch (e) { return false; }
}

function applyAll() {
  Java.perform(function () {
    var pending = !done.nac || !done.nsg || !done.u || !done.misc || !done.res;
    if (!pending) return;
    patchAuthCore(); patchGate(); patchU(); patchMisc(); patchResultBool();
    if (pending) setTimeout(applyAll, 2000); // 模块类尚未加载则重试
  });
}

setImmediate(applyAll);
log('script loaded');
