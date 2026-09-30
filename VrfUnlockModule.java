package io.github.revx.vrfpermanent;

import android.util.Log;

import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.lang.reflect.Method;

import io.github.libxposed.api.XposedInterface;
import io.github.libxposed.api.XposedModule;
import io.github.libxposed.api.XposedModuleInterface;

/**
 * VirtualRegion (io.github.zhou6514ctrl.virtualregion) full unlock — v2.0.
 *
 * <h2>Verified licence chain (v2.0.5 / versionCode 205, jadx tree .scratch/dumps/jadx)</h2>
 * <pre>
 *  VirtualRegionApplication:710   holder.m7555B()            &lt;- 启动即跑一次离线校验
 *  auth.D  (C4197D) = licence holder, field a = auth.v (state machine)
 *      B()  -> d = v.c0(v.t)                                 offline verify
 *              d.h0() true  -> v.b0(AUTHORIZED_OFFLINE,"设备已授权","AUTHORIZED_OFFLINE")
 *                              v.X(lease)                   <- 写回租约
 *              d.h0() false -> v.y=false; v.x=err.name(); v.J()
 *  auth.v  (C4224v)
 *      t    : auth.H      租约信封 (Ed25519 签名体 + sig + key)
 *      u    : auth.w      当前状态枚举
 *      m    : auth.z      f15203a = AtomicBoolean "首次安装必须授权"
 *      r    : List&lt;auth.C&gt; 观察者 (卡密弹窗 c4.x 注册在这里)
 *      Z()            -> !首次安装 || u.b() || u==EXPIRED   == true 就弹「卡密授权」
 *      Q()            -> AuthInfo(u, t.body.i, lastVerify, reason)
 *      N()            -> c0(t).h0() ? t : null              (只有验签通过才给租约)
 *      c0(H)          -> NativeAuthCore.a(H, appSig, false) -> native verifyRaw (Ed25519)
 *      b0(w,String,String,Z)  唯一状态写入口
 *  auth.w  (EnumC4225w)
 *      a() -> u in {AUTHORIZED_ONLINE, AUTHORIZED, AUTHORIZED_OFFLINE}   是「已授权」
 *      b() -> u in {REVOKED, NOT_AUTHORIZED, DEVICE_MISMATCH, UNAUTHORIZED}
 *  auth.NativeAuthCore.a(H,String,Z) -> d    Java 侧唯一的 native 验签入口
 *  c4.x (p194c4.C2139x) 卡密弹窗：Z()==true 时 a() 才会 show()
 *  m3.h (p270m3.C4569h) 发布器：u.a()==true 且 v.t!=null 时才向
 *      LSPosed RemotePreferences 组 "virtual_region_snapshot_v1" 推送授权/快照
 * </pre>
 *
 * <h2>v2.0 hook set (why each one)</h2>
 * <ul>
 *   <li>{@code auth.w#a()Z -> true}、{@code auth.w#b()Z -> false} — 所有"是否已授权/是否被拒"判断。</li>
 *   <li>{@code auth.v#c0(H)d -> OK_OFFLINE} — 掐掉 Java 侧唯一一次 native Ed25519 验签；native 层不可达
 *       则重签名后的 APK 也能过。</li>
 *   <li>{@code auth.v#Z()Z -> false} — 卡密授权弹窗永不出现（弹窗 show 的唯一前置）。</li>
 *   <li>{@code auth.v#Q()AuthInfo -> 永久} — 抽屉卡片显示「已授权 / 永久有效」。</li>
 *   <li>{@code auth.v#N()H -> this.t} — 解除"验签通过才给租约"的绑定。</li>
 *   <li>{@code auth.v#b0(...) -> 强制 AUTHORIZED} — 覆盖任何失败回写（网络错误/吊销/设备不符）。</li>
 *   <li>{@code auth.NativeAuthCore#a(H,String,Z)d -> OK_OFFLINE} — 兜底，防止别处直接调用 native 包装。</li>
 *   <li>{@code auth.D#B()V -> no-op} — 启动期离线校验直接短路，状态由 b0 决定。</li>
 *   <li>system 侧：{@code auth.NativeSnapshotGate} 的 commit/current* 走缓存 + 放行，使快照在
 *       系统进程内不再被 native 拒绝（否则 ipc 会 REMOTE_RUNTIME_CLEARED）。</li>
 * </ul>
 */
public final class VrfUnlockModule extends XposedModule {

    private static final String TAG = "VrfUnlock";

    private static final String PKG = "io.github.zhou6514ctrl.virtualregion";

    private static final String C_W = PKG + ".auth.w";                     // state enum
    private static final String C_V = PKG + ".auth.v";                     // state machine
    private static final String C_C = PKG + ".auth.c";                     // verify-code enum
    private static final String C_D = PKG + ".auth.d";                     // verify result
    private static final String C_H = PKG + ".auth.H";                     // lease envelope
    private static final String C_INFO = PKG + ".auth.AuthInfo";           // public AuthInfo
    private static final String C_NAC = PKG + ".auth.NativeAuthCore";      // native Ed25519
    private static final String C_GATE = PKG + ".auth.NativeSnapshotGate"; // native snapshot store
    private static final String C_F2 = PKG + ".auth.F";                    // commit result
    private static final String C_HOLD = PKG + ".auth.D";                  // licence holder
    private static final String C_IPCH = PKG + ".ipc.h";                   // deny / clear reporter
    private static final String C_IPCA = PKG + ".ipc.a";                   // per-process deny report

    /**
     * 远端版本清单（jadx {@code p219f4.C4036a}）。MainActivity 的更新弹窗只在
     * {@code manifest.a > 205} 时构造，构造期把版本号置 0 就永远不会弹「发现新版本」。
     */
    private static final String C_UPDATE = "f4.a";

    /** 2100-01-01T00:00:00Z — 永久。 */
    private static final long FAR_FUTURE = 4102444800L;

    private static final long INSTALL_DEADLINE_MS = 120_000L;

    private volatile String processName = "";
    private volatile ClassLoader vrfLoader;
    private volatile boolean installed = false;

    // system-side relay, written from binder threads
    private static volatile Object snapModule;
    private static volatile Object snapRegional;
    private static volatile Object snapSim;
    private static volatile Object snapHiddenApps;

    // ------------------------------------------------------------------ lifecycle

    @Override
    public void onModuleLoaded(XposedModuleInterface.ModuleLoadedParam param) {
        try {
            processName = param.getProcessName();
            log(Log.INFO, TAG, "event=module_loaded process=" + processName
                    + " systemServer=" + param.isSystemServer()
                    + " api=" + getApiVersion()
                    + " fw=" + getFrameworkName() + "/" + getFrameworkVersion());
            installLoaderRecorder();
            startInstaller(param.isSystemServer() ? 2000L : 500L);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "event=module_loaded_failed", t);
        }
    }

    @Override
    public void onPackageReady(XposedModuleInterface.PackageReadyParam param) {
        try {
            if (PKG.equals(param.getPackageName()) && param.getClassLoader() != null) {
                vrfLoader = param.getClassLoader();
                log(Log.INFO, TAG, "event=package_ready process=" + processName
                        + " pkg=" + PKG + " loader=" + param.getClassLoader().getClass().getName());
                startInstaller(100L);
            }
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "event=package_ready_failed", t);
        }
    }

    /**
     * 记录目标 App 的 ClassLoader。
     *
     * <p>宿主 APK 自己也是一个 libxposed 模块，在 system 侧进程里它的类由框架的 module
     * class loader 载入，所以必须抓到框架用的那一个 loader；自己 new 一个 PathClassLoader
     * 只会得到第二份类拷贝，hook 上去是空转。
     */
    private void installLoaderRecorder() {
        XposedInterface.Hooker record = chain -> {
            Object a0 = chain.getArg(0);
            if (a0 instanceof String) {
                String name = (String) a0;
                if (name.startsWith(PKG) && vrfLoader == null) {
                    Object self = chain.getThisObject();
                    if (self instanceof ClassLoader) {
                        vrfLoader = (ClassLoader) self;
                        log(Log.INFO, TAG, "event=loader_recorded process=" + processName
                                + " cls=" + name + " loader=" + self.getClass().getName());
                    }
                }
            }
            return chain.proceed();
        };

        hookByName(null, "java.lang.ClassLoader", "loadClass", 2, record, "cl_loadClass2");
        hookByName(null, "java.lang.ClassLoader", "loadClass", 1, record, "cl_loadClass1");
        hookByName(null, "java.lang.ClassLoader", "findClass", 1, record, "cl_findClass");

        XposedInterface.Hooker forName = chain -> {
            Object a0 = chain.getArg(0);
            Object a2 = chain.getArg(2);
            if (a0 instanceof String && ((String) a0).startsWith(PKG)
                    && a2 instanceof ClassLoader && vrfLoader == null) {
                vrfLoader = (ClassLoader) a2;
                log(Log.INFO, TAG, "event=loader_recorded via=Class.forName process=" + processName
                        + " cls=" + a0 + " loader=" + a2.getClass().getName());
            }
            return chain.proceed();
        };
        hookByName(null, "java.lang.Class", "forName", 3, forName, "class_forName3");

        // LSPosed 的 child-first module class loader —— 类名各版本不同，逐个试。
        for (String candidate : new String[]{
                "org.lsposed.lspd.impl.LSPosedModuleClassLoader",
                "org.lsposed.lspd.core.ModuleClassLoader",
                "org.lsposed.lspd.impl.ModuleClassLoader",
                "org.lsposed.lspd.core.LSPosedModuleClassLoader"}) {
            try {
                Class<?> cls = Class.forName(candidate, false, VrfUnlockModule.class.getClassLoader());
                ClassLoader owner = cls.getClassLoader();
                hookByName(owner, candidate, "loadClass", 2, record, "mcl_loadClass2");
                hookByName(owner, candidate, "loadClass", 1, record, "mcl_loadClass1");
                hookByName(owner, candidate, "findClass", 1, record, "mcl_findClass");
                log(Log.INFO, TAG, "event=module_cl_hooked name=" + candidate);
            } catch (Throwable ignored) {
                // 该 LSPosed 版本没有这个实现类
            }
        }
        log(Log.INFO, TAG, "event=loader_recorder_installed process=" + processName);
    }

    /** 反复重试到成功或超时：宿主模块的类可能在框架里晚于本模块才载入。 */
    private void startInstaller(long initialDelayMs) {
        Thread worker = new Thread(() -> {
            try {
                Thread.sleep(initialDelayMs);
                long deadline = System.currentTimeMillis() + INSTALL_DEADLINE_MS;
                while (!installed && System.currentTimeMillis() < deadline) {
                    ClassLoader loader = vrfLoader;
                    if (loader != null) {
                        try {
                            if (installHooks(loader)) {
                                return;
                            }
                        } catch (Throwable t) {
                            log(Log.WARN, TAG, "event=install_retry process=" + processName
                                    + " cause=" + t);
                        }
                    }
                    Thread.sleep(500L);
                }
                if (!installed) {
                    log(Log.WARN, TAG, "event=install_abandoned process=" + processName
                            + " loader=" + vrfLoader);
                }
            } catch (Throwable t) {
                log(Log.ERROR, TAG, "event=install_thread_failed", t);
            }
        }, "vrf-unlock-installer");
        worker.setDaemon(true);
        worker.start();
    }

    // ------------------------------------------------------------------ install

    private int hookCount = 0;

    private synchronized boolean installHooks(ClassLoader cl) throws Throwable {
        if (installed) {
            return true;
        }
        Class<?> v;
        try {
            v = cl.loadClass(C_V);
        } catch (Throwable t) {
            return false; // 目标类的 loader 还没就绪，等下轮
        }
        Class<?> w = cl.loadClass(C_W);
        Class<?> c = cl.loadClass(C_C);
        Class<?> d = cl.loadClass(C_D);
        Class<?> info = cl.loadClass(C_INFO);

        Object authorized = enumValue(w, "AUTHORIZED");
        Object okOffline = enumValue(c, "OK_OFFLINE");
        if (authorized == null || okOffline == null) {
            log(Log.ERROR, TAG, "event=enum_missing process=" + processName
                    + " authorized=" + authorized + " okOffline=" + okOffline);
            return false;
        }

        final Constructor<?> dCtor = d.getConstructor(c, long.class, long.class, long.class, boolean.class);
        final Constructor<?> infoCtor = info.getConstructor(w, long.class, long.class, String.class);
        final Object dOk = dCtor.newInstance(okOffline, FAR_FUTURE, FAR_FUTURE, FAR_FUTURE, Boolean.TRUE);

        // 租约信封构造器：发布器 (m3.h) 只在 u.a()==true 且 v.t != null 时才推 RemotePreferences，
        // 全新解锁的机器 v.t 恒为 null，系统侧收不到任何东西 —— 这里补一个自造的 H。
        Class<?> f2 = loadMaybe(cl, PKG + ".auth.f");
        Class<?> h2 = loadMaybe(cl, PKG + ".auth.H");
        final Constructor<?> bodyCtor = f2 == null ? null : f2.getConstructor(
                int.class, String.class, String.class, String.class,
                long.class, long.class, long.class, long.class, Long.class);
        final Constructor<?> envCtor = (h2 == null || f2 == null) ? null
                : h2.getConstructor(f2, byte[].class, byte[].class);
        final Field leaseField = v.getDeclaredField("t");
        leaseField.setAccessible(true);

        // ---- 状态枚举谓词 ----------------------------------------------------------------
        hookByName(cl, C_W, "a", 0, chain -> Boolean.TRUE, "w.a=true");      // isAuthorized
        hookByName(cl, C_W, "b", 0, chain -> Boolean.FALSE, "w.b=false");    // isDenied

        // ---- 卡密弹窗总闸 ----------------------------------------------------------------
        // auth.v#Z() 是 c4.x 弹窗 show 的唯一前置条件；恒 false => 「卡密授权」永不出现。
        hookByName(cl, C_V, "Z", 0, chain -> Boolean.FALSE, "v.Z=false");

        // ---- Java 侧唯一 native 验签入口 -------------------------------------------------
        hookByName(cl, C_V, "c0", 1, chain -> dOk, "v.c0=OK");
        hookByName(cl, C_NAC, "a", 3, chain -> dOk, "NativeAuthCore.a=OK");

        // ---- 启动期离线校验短路（把状态交给 b0 决定） --------------------------------------
        hookByName(cl, C_HOLD, "B", 0, chain -> null, "holder.B=noop");

        // ---- 状态唯一写入口：任何失败回写都被改成 AUTHORIZED -------------------------------
        hookByName(cl, C_V, "b0", 4, chain -> {
            ensureLease(chain.getThisObject(), leaseField, bodyCtor, envCtor);
            return chain.proceed(new Object[]{authorized, "", "AUTHORIZED", Boolean.FALSE});
        }, "v.b0=AUTHORIZED+lease");

        // ---- 对外的授权视图：永久有效 ------------------------------------------------------
        hookByName(cl, C_V, "Q", 0, chain ->
                infoCtor.newInstance(authorized, Long.valueOf(0L),
                        Long.valueOf(System.currentTimeMillis() / 1000L), "AUTHORIZED"),
                "v.Q=permanent");

        // ---- 解除「验签通过才给租约」的绑定 -------------------------------------------------
        hookByName(cl, C_V, "N", 0, chain -> {
            Object self = chain.getThisObject();
            ensureLease(self, leaseField, bodyCtor, envCtor);
            Object lease = chain.proceed();
            if (lease != null) {
                return lease;
            }
            Object fromField = self == null ? null : getField(self, "t");
            return fromField != null ? fromField : synthLease(bodyCtor, envCtor);
        }, "v.N=lease");

        // ---- 版本检测弹窗：远端清单的 versionCode 恒为 0，「发现新版本」不再出现 -------------
        hookCtorByName(cl, C_UPDATE, 7, chain -> {
            Object[] args = new Object[7];
            for (int i = 0; i < 7; i++) {
                args[i] = chain.getArg(i);
            }
            args[0] = Integer.valueOf(0);
            return chain.proceed(args);
        }, "update.versionCode=0");

        // ---- system 侧：快照 native 闸门放行 -----------------------------------------------
        installGateHooks(cl, dCtor, okOffline);

        // ---- 永不清除运行态 ----------------------------------------------------------------
        hookByName(cl, C_IPCH, "c", 1, chain -> null, "ipc.h.c=noop");
        hookByName(cl, C_IPCA, "a", 2, chain -> null, "ipc.a.a=noop");

        installed = true;
        log(Log.INFO, TAG, "event=hooks_installed process=" + processName
                + " hooks=" + hookCount + " loader=" + cl.getClass().getName());
        return true;
    }

    /**
     * system 侧（宿主模块自己被注入的进程）。{@code NativeSnapshotGate.f/g/h} 是
     * {@code private static native commit(...)} 的 Java 包装，内部会用 native Ed25519
     * 重验租约；验不过 -> ipc 判 REMOTE_RUNTIME_CLEARED。这里把已经解码好的快照对象
     * 缓存下来、直接回「已提交」，并让 {@code current*Snapshot()} 回放缓存。
     */
    private void installGateHooks(ClassLoader cl, Constructor<?> dCtor, Object okOffline) {
        Class<?> gate = loadMaybe(cl, C_GATE);
        if (gate == null) {
            return;
        }
        Class<?> f2 = loadMaybe(cl, C_F2);

        // module snapshot
        hookByName(cl, C_GATE, "f", 7, chain -> {
            snapModule = chain.getArg(1);
            return okCommit(f2, dCtor, okOffline, chain.getArg(2));
        }, "gate.f=commit");
        // regional snapshot
        hookByName(cl, C_GATE, "g", 7, chain -> {
            snapRegional = chain.getArg(1);
            return okCommit(f2, dCtor, okOffline, chain.getArg(2));
        }, "gate.g=commit");
        // target SIM snapshot
        hookByName(cl, C_GATE, "h", 7, chain -> {
            snapSim = chain.getArg(1);
            return okCommit(f2, dCtor, okOffline, chain.getArg(2));
        }, "gate.h=commit");
        // hidden-apps 校验提交
        hookByName(cl, C_GATE, "e", 6, chain -> {
            snapHiddenApps = chain.getArg(1);
            return okCommit(f2, dCtor, okOffline, chain.getArg(1 + 1));
        }, "gate.e=commit");

        hookByName(cl, C_GATE, "currentModuleSnapshot", 0, chain -> {
            Object cached = snapModule;
            return cached != null ? cached : chain.proceed();
        }, "gate.currentModule");
        hookByName(cl, C_GATE, "currentRegionalSnapshot", 0, chain -> {
            Object cached = snapRegional;
            return cached != null ? cached : chain.proceed();
        }, "gate.currentRegional");
        hookByName(cl, C_GATE, "currentTargetSimSnapshot", 0, chain -> {
            Object cached = snapSim;
            return cached != null ? cached : chain.proceed();
        }, "gate.currentTargetSim");

        // 版本 / 围栏探测：报一个健康的 native store，让调用方走 native 分支
        hookByName(cl, C_GATE, "a", 2, chain -> Boolean.TRUE, "gate.a=clearOk");
        hookByName(cl, C_GATE, "b", 0, chain -> Long.valueOf(0x7FFFFFFFL), "gate.b=rev");
        hookByName(cl, C_GATE, "c", 1, chain -> Long.valueOf(0x7FFFFFFFL), "gate.c=version");
    }

    private Object okCommit(Class<?> f2, Constructor<?> dCtor, Object okOffline, Object version) {
        try {
            if (f2 == null) {
                return null;
            }
            long rev = version instanceof Long ? Math.max(1L, (Long) version) : 1L;
            Object d = dCtor.newInstance(okOffline, FAR_FUTURE, FAR_FUTURE, FAR_FUTURE, Boolean.TRUE);
            return f2.getConstructor(dCtor.getDeclaringClass(), long.class).newInstance(d, rev);
        } catch (Throwable t) {
            log(Log.ERROR, TAG, "event=ok_commit_failed " + t);
            return null;
        }
    }

    // ------------------------------------------------------------------ helpers

    /** 自造一个格式合法的租约信封 {@code H(f(1,plan,keyId,subject,0,now,now,FAR,null), [], [])}。 */
    private static Object synthLease(Constructor<?> bodyCtor, Constructor<?> envCtor) {
        if (bodyCtor == null || envCtor == null) {
            return null;
        }
        try {
            long now = System.currentTimeMillis() / 1000L;
            Object body = bodyCtor.newInstance(1, "revx-permanent", "auth-ed25519-2026-01", "revx",
                    0L, now, now, FAR_FUTURE, null);
            return envCtor.newInstance(body, new byte[0], new byte[0]);
        } catch (Throwable t) {
            return null;
        }
    }

    /** 状态机实例上的租约字段为空时补一个 —— 发布器 (m3.h) 需要它非 null 才会推送。 */
    private static void ensureLease(Object stateMachine, Field leaseField,
                                    Constructor<?> bodyCtor, Constructor<?> envCtor) {
        if (stateMachine == null || leaseField == null) {
            return;
        }
        try {
            if (leaseField.get(stateMachine) != null) {
                return;
            }
            Object lease = synthLease(bodyCtor, envCtor);
            if (lease != null) {
                leaseField.set(stateMachine, lease);
            }
        } catch (Throwable ignored) {
        }
    }

    private static Object enumValue(Class<?> enumCls, String name) {
        try {
            return enumCls.getMethod("valueOf", String.class).invoke(null, name);
        } catch (Throwable t) {
            return null;
        }
    }

    private static Class<?> loadMaybe(ClassLoader cl, String name) {
        try {
            return cl.loadClass(name);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Object getField(Object target, String name) {
        if (target == null) {
            return null;
        }
        for (Class<?> k = target.getClass(); k != null; k = k.getSuperclass()) {
            try {
                Field f = k.getDeclaredField(name);
                f.setAccessible(true);
                return f.get(target);
            } catch (Throwable ignored) {
                // next level
            }
        }
        return null;
    }

    /**
     * 按 类名 + 构造器参数个数 定位。构造器不在 {@code getDeclaredMethods()} 里，必须单独走这条路径。
     */
    private void hookCtorByName(ClassLoader cl, String className, int arity,
                                XposedInterface.Hooker body, String id) {
        try {
            Class<?> owner = cl.loadClass(className);
            Constructor<?> found = null;
            for (Constructor<?> ctor : owner.getDeclaredConstructors()) {
                if (ctor.getParameterCount() == arity) {
                    found = ctor;
                    break;
                }
            }
            if (found == null) {
                log(Log.WARN, TAG, "event=ctor_missing owner=" + className
                        + " arity=" + arity + " process=" + processName);
                return;
            }
            found.setAccessible(true);
            hook(found).setId(id)
                    .setPriority(XposedInterface.PRIORITY_DEFAULT)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(body);
            hookCount++;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=ctor_hook_failed id=" + id + " owner=" + className
                    + " cause=" + t);
        }
    }

    /**
     * 按 类名 + 方法名 + 参数个数 定位。不断言参数/返回类型，混淆改动不会静默失效，
     * 只会打一行 {@code hook_missing} 诊断。
     */
    private void hookByName(ClassLoader cl, String className, String method, int arity,
                            XposedInterface.Hooker body, String id) {
        try {
            Class<?> owner = cl == null ? Class.forName(className, false, null) : cl.loadClass(className);
            Method found = null;
            for (Method m : owner.getDeclaredMethods()) {
                if (m.getName().equals(method) && m.getParameterCount() == arity && !m.isSynthetic()) {
                    found = m;
                    break;
                }
            }
            if (found == null) {
                log(Log.WARN, TAG, "event=hook_missing owner=" + className
                        + " name=" + method + " arity=" + arity + " process=" + processName);
                return;
            }
            found.setAccessible(true);
            hook(found).setId(id)
                    .setPriority(XposedInterface.PRIORITY_DEFAULT)
                    .setExceptionMode(XposedInterface.ExceptionMode.PROTECTIVE)
                    .intercept(body);
            hookCount++;
        } catch (Throwable t) {
            log(Log.WARN, TAG, "event=hook_failed id=" + id + " owner=" + className
                    + " name=" + method + " cause=" + t);
        }
    }
}
