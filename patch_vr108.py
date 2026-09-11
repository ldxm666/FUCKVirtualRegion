# -*- coding: utf-8 -*-
"""
VirtualRegion 1.0.8 (versionCode 109) — smali 解锁补丁 (可移植完整版)
====================================================================
用法:
    python patch_vr108.py <apktool_out_dir>
    python patch_vr108.py D:\\work\\apktool_108     # 目录内需含 smali/ 或 smali_classesN/

流程:
    apktool d VirtualRegion_1.0.8.apk -o apktool_108
    python patch_vr108.py apktool_108
    apktool b apktool_108 -o out_unsigned.apk

特性:
    * 幂等（重跑命中数为 0 也接受），每次替换都带命中数断言，不符即 abort
    * 自动注入 helper 类 Lvr/Store;（快照内存 store + 恒真授权判定）
    * 自动定位所有 smali*/ 根目录（含 apktool 的 .1.smali 大小写规避命名）
    * 结束后打印全局重定向统计，便于报告留证

生成物语义:
    授权判定      -> 恒真 (OK_ONLINE / 到期 2100-01-01)
    租约          -> 内存伪造永久租约 (UNLOCKED-FRIDA)
    快照 commit   -> Java 层内存 store 接管, 不再过 native 验签门禁
    快照读取      -> 内存 store
    卡密弹窗触发  -> 静默
"""
import os
import re
import sys

FAR = 4102444800           # 2100-01-01 00:00:00 UTC
ISSUED = 1577836800        # 2020-01-01 00:00:00 UTC
FARX = "0x%08xL" % FAR
ISSX = "0x%08xL" % ISSUED

STORE_SMALI = r'''.class public final Lvr/Store;
.super Ljava/lang/Object;
.source "VrfUnlockStore.java"


# static fields
.field private static final s:Ljava/util/concurrent/ConcurrentHashMap;

.field private static final w:Ljava/util/concurrent/ConcurrentHashMap;


# direct methods
.method static constructor <clinit>()V
    .locals 1

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    sput-object v0, Lvr/Store;->s:Ljava/util/concurrent/ConcurrentHashMap;

    new-instance v0, Ljava/util/concurrent/ConcurrentHashMap;

    invoke-direct {v0}, Ljava/util/concurrent/ConcurrentHashMap;-><init>()V

    sput-object v0, Lvr/Store;->w:Ljava/util/concurrent/ConcurrentHashMap;

    return-void
.end method

.method public constructor <init>()V
    .locals 0

    invoke-direct {p0}, Ljava/lang/Object;-><init>()V

    return-void
.end method

# 恒真授权判定 (接管 h3.u.S()Z 全部调用点)
.method public static a(Lh3/u;)Z
    .locals 1

    const/4 v0, 0x1

    return v0
.end method

# 存快照 + 版本
.method public static put(ILjava/lang/Object;J)V
    .locals 3

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    invoke-static {p2, p3}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v1

    sget-object v2, Lvr/Store;->s:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v2, v0, p1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v2, Lvr/Store;->w:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v2, v0, v1}, Ljava/util/concurrent/ConcurrentHashMap;->put(Ljava/lang/Object;Ljava/lang/Object;)Ljava/lang/Object;

    return-void
.end method

# 读原始快照
.method public static get(I)Ljava/lang/Object;
    .locals 2

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    sget-object v1, Lvr/Store;->s:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    return-object v0
.end method

# 读版本号, 无快照返回 -1
.method public static ver(I)J
    .locals 4

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    sget-object v1, Lvr/Store;->w:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->get(Ljava/lang/Object;)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Ljava/lang/Long;

    if-eqz v0, :cond_0

    invoke-virtual {v0}, Ljava/lang/Long;->longValue()J

    move-result-wide v0

    return-wide v0

    :cond_0
    const-wide/16 v0, -0x1

    return-wide v0
.end method

# 清除快照
.method public static clear(IJ)Z
    .locals 2

    invoke-static {p0}, Ljava/lang/Integer;->valueOf(I)Ljava/lang/Integer;

    move-result-object v0

    sget-object v1, Lvr/Store;->s:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    sget-object v1, Lvr/Store;->w:Ljava/util/concurrent/ConcurrentHashMap;

    invoke-virtual {v1, v0}, Ljava/util/concurrent/ConcurrentHashMap;->remove(Ljava/lang/Object;)Ljava/lang/Object;

    const/4 v0, 0x1

    return v0
.end method

# kind=1 ModuleSnapshot (替代 NativeSnapshotGate.currentModuleSnapshot)
.method public static currentModuleSnapshot()Lio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;
    .locals 2

    const/4 v0, 0x1

    invoke-static {v0}, Lvr/Store;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;

    return-object v0
.end method

# kind=2 TargetSimSnapshot
.method public static currentTargetSimSnapshot()Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;
    .locals 2

    const/4 v0, 0x2

    invoke-static {v0}, Lvr/Store;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;

    return-object v0
.end method

# kind=3 RegionalSnapshot
.method public static currentRegionalSnapshot()Lio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;
    .locals 2

    const/4 v0, 0x3

    invoke-static {v0}, Lvr/Store;->get(I)Ljava/lang/Object;

    move-result-object v0

    check-cast v0, Lio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;

    return-object v0
.end method
'''.strip() + "\n"

stats = {"s_redirect": 0, "snap_redirect": 0}


def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()


def write(p, s):
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s)


def fail(msg):
    print("FAIL " + msg)
    sys.exit(1)


def replace_method(src, sig, new_body, label):
    m = re.search(r"^\.method[^\r\n]*" + re.escape(sig) + r"[^\r\n]*\r?\n.*?^\.end method[ \t]*$",
                  src, re.M | re.S)
    if not m:
        fail("method not found: %s %s" % (label, sig))
    return src[:m.start()] + new_body.strip() + "\n" + src[m.end():]


def sub_expect(src, pattern, repl, n, label, flags=0):
    new, cnt = re.subn(pattern, repl, src, flags=flags)
    if cnt != n:
        fail("expect %d got %d for %s" % (n, cnt, label))
    return new


def sub_flag(src, pattern, repl, n, label, flags=0):
    """幂等变体: 接受 n 或 0（已打过）"""
    new, cnt = re.subn(pattern, repl, src, flags=flags)
    if cnt not in (0, n):
        fail("expect %d-or-0 got %d for %s" % (n, cnt, label))
    return new


def find_smali_roots(base):
    roots = []
    for name in sorted(os.listdir(base)):
        d = os.path.join(base, name)
        if os.path.isdir(d) and (name == "smali" or name.startswith("smali_classes")):
            roots.append(d)
    if not roots:
        fail("no smali/ dir found under " + base)
    return roots


def main():
    if len(sys.argv) > 1:
        base = sys.argv[1]
    else:
        base = r"D:\pojie应用\pojie3\VR108w\apktool"
    if not os.path.isdir(base):
        fail("apktool dir not found: " + base)

    roots = find_smali_roots(base)
    primary = roots[0]
    print("apktool dir :", base)
    print("smali roots :", ", ".join(os.path.basename(r) for r in roots))
    print("FAR literal :", FARX, " ISSUED literal:", ISSX)

    # ================================================== 注入 helper 类
    store_dir = os.path.join(primary, "vr")
    os.makedirs(store_dir, exist_ok=True)
    write(os.path.join(store_dir, "Store.smali"), STORE_SMALI)
    print("OK helper class Lvr/Store; -> smali/vr/Store.smali")

    # ================================================== h3/D 跨进程授权标志
    p = os.path.join(primary, "h3", "D.smali")
    s = read(p)
    s = sub_flag(s, r"const/4 v1, 0x0", "const/4 v1, 0x1", 1, "D.clinit init flags")
    s = replace_method(s, "a(Z)V", """
.method public static a(Z)V
    .locals 1

    sget-object v0, Lh3/D;->a:Ljava/util/concurrent/atomic/AtomicBoolean;

    const/4 p0, 0x1

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    sget-object v0, Lh3/D;->b:Ljava/util/concurrent/atomic/AtomicBoolean;

    invoke-virtual {v0, p0}, Ljava/util/concurrent/atomic/AtomicBoolean;->set(Z)V

    return-void
.end method
""", "D.a(Z)")
    write(p, s)
    print("OK h3/D (跨进程授权标志恒 true)")

    # ================================================== h3/u 授权状态机
    p = os.path.join(primary, "h3", "u.smali")
    s = read(p)

    s = replace_method(s, "Z()Z", """
.method public final Z()Z
    .locals 1

    const/4 p0, 0x1

    return p0
.end method
""", "u.Z")

    s = replace_method(s, "x()V", """
.method public final x()V
    .locals 0

    return-void
.end method
""", "u.x")

    s = replace_method(s, "c0(Lh3/E;)Lh3/d;", """
.method public final c0(Lh3/E;)Lh3/d;
    .locals 9

    new-instance v0, Lh3/d;

    sget-object v1, Lh3/c;->b:Lh3/c;

    const-wide v2, %s

    const-wide v4, %s

    const-wide v6, %s

    const/4 v8, 0x1

    invoke-direct/range {v0 .. v8}, Lh3/d;-><init>(Lh3/c;JJJZ)V

    return-object v0
.end method
""" % (FARX, FARX, FARX), "u.c0")

    # b0: 状态迁移强制 AUTHORIZED_ONLINE（幂等）
    if "sget-object p1, Lh3/v;->c:Lh3/v;" not in s:
        s = sub_expect(
            s,
            r"(\.method public final b0\(Lh3/v;Ljava/lang/String;Ljava/lang/String;\)V\r?\n    \.locals 5\r?\n)",
            r"\1\n    sget-object p1, Lh3/v;->c:Lh3/v;\n", 1, "u.b0 force state")
    else:
        print("skip u.b0 (already patched)")

    s = replace_method(s, "N()Lh3/E;", """
.method public final N()Lh3/E;
    .locals 15

    iget-object v0, p0, Lh3/u;->t:Lh3/E;

    if-eqz v0, :cond_0

    return-object v0

    :cond_0
    new-instance v0, Lh3/e;

    const/4 v1, 0x2

    const-string v2, "UNLOCKED-FRIDA"

    const-string v3, "vrf-unlock"

    const-string v4, "permanent"

    const-wide v5, %ISSUED%

    const-wide v7, %FAR%

    const-wide v9, %FAR%

    const-wide v11, %FAR%

    invoke-static {v11, v12}, Ljava/lang/Long;->valueOf(J)Ljava/lang/Long;

    move-result-object v13

    invoke-direct/range {v0 .. v13}, Lh3/e;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;JJJJLjava/lang/Long;)V

    new-instance v1, Lh3/E;

    const/16 v2, 0x20

    new-array v2, v2, [B

    const/16 v3, 0x41

    invoke-static {v2, v3}, Ljava/util/Arrays;->fill([BB)V

    const/16 v3, 0x40

    new-array v3, v3, [B

    const/16 v4, 0x42

    invoke-static {v3, v4}, Ljava/util/Arrays;->fill([BB)V

    invoke-direct {v1, v0, v2, v3}, Lh3/E;-><init>(Lh3/e;[B[B)V

    iput-object v1, p0, Lh3/u;->t:Lh3/E;

    return-object v1
.end method
""".replace("%ISSUED%", ISSX).replace("%FAR%", FARX), "u.N")

    write(p, s)
    print("OK h3/u (Z/x/c0/b0/N)")

    # ================================================== NativeAuthCore 租约验签
    p = os.path.join(primary, "io", "github", "zhou6514ctrl", "virtualregion", "auth", "NativeAuthCore.smali")
    s = read(p)
    s = replace_method(s, "a(Lh3/E;Ljava/lang/String;Z)Lh3/d;", """
.method public final a(Lh3/E;Ljava/lang/String;Z)Lh3/d;
    .locals 9

    new-instance v0, Lh3/d;

    sget-object v1, Lh3/c;->b:Lh3/c;

    const-wide v2, %F%

    const-wide v4, %F%

    const-wide v6, %F%

    const/4 v8, 0x1

    invoke-direct/range {v0 .. v8}, Lh3/d;-><init>(Lh3/c;JJJZ)V

    return-object v0
.end method
""".replace("%F%", FARX), "NAC.a")

    s = replace_method(s, "b(Ljava/lang/String;Ljava/lang/String;[B[B)Lh3/d;", """
.method public static b(Ljava/lang/String;Ljava/lang/String;[B[B)Lh3/d;
    .locals 9

    new-instance v0, Lh3/d;

    sget-object v1, Lh3/c;->b:Lh3/c;

    const-wide v2, %F%

    const-wide v4, %F%

    const-wide v6, %F%

    const/4 v8, 0x1

    invoke-direct/range {v0 .. v8}, Lh3/d;-><init>(Lh3/c;JJJZ)V

    return-object v0
.end method
""".replace("%F%", FARX), "NAC.b")
    write(p, s)
    print("OK NativeAuthCore (a/b 直接返回 OK_ONLINE, 不触 verifyRaw/nativeVerify)")

    # ================================================== NativeSnapshotGate 提交门禁
    p = os.path.join(primary, "io", "github", "zhou6514ctrl", "virtualregion", "auth", "NativeSnapshotGate.smali")
    s = read(p)

    def gate_commit(sig, kind):
        return """
.method public static %s
    .locals 10

    const/4 v0, 0x%d

    invoke-static {v0, p1, p2, p3}, Lvr/Store;->put(ILjava/lang/Object;J)V

    new-instance v0, Lh3/C;

    new-instance v1, Lh3/d;

    sget-object v2, Lh3/c;->b:Lh3/c;

    const-wide v3, %F%

    const-wide v5, %F%

    const-wide v7, %F%

    const/4 v9, 0x1

    invoke-direct/range {v1 .. v9}, Lh3/d;-><init>(Lh3/c;JJJZ)V

    invoke-direct {v0, v1, p2, p3}, Lh3/C;-><init>(Lh3/d;J)V

    return-object v0
.end method
""".replace("%F%", FARX) % (sig, kind)

    s = replace_method(
        s,
        "c([BLio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
        gate_commit("c([BLio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 1),
        "NSG.c")
    s = replace_method(
        s,
        "d([BLio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
        gate_commit("d([BLio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 3),
        "NSG.d")
    s = replace_method(
        s,
        "e(Ljava/lang/String;Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
        gate_commit("e(Ljava/lang/String;Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 2),
        "NSG.e")

    s = replace_method(s, "b(I)J", """
.method public static b(I)J
    .locals 3

    invoke-static {p0}, Lvr/Store;->ver(I)J

    move-result-wide v0

    return-wide v0
.end method
""", "NSG.b")

    s = replace_method(s, "a(IJ)Z", """
.method public static a(IJ)Z
    .locals 3

    invoke-static {p0, p1, p2}, Lvr/Store;->clear(IJ)Z

    move-result v0

    return v0
.end method
""", "NSG.a")
    write(p, s)
    print("OK NativeSnapshotGate (c/d/e 提交接管, b 版本, a 清除)")

    # ================================================== 授权失效广播
    p = os.path.join(primary, "io", "github", "zhou6514ctrl", "virtualregion", "auth",
                     "AuthorizationRequiredReceiver.smali")
    s = read(p)
    s = replace_method(s, "onReceive(Landroid/content/Context;Landroid/content/Intent;)V", """
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0

    return-void
.end method
""", "ARR.onReceive")
    write(p, s)
    print("OK AuthorizationRequiredReceiver (no-op)")

    # ================================================== 全局重定向
    s_total = snap_total = 0
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith(".smali"):
                    continue
                fp = os.path.join(dirpath, fn)
                if fp.endswith(os.path.join("vr", "Store.smali")):
                    continue
                s = read(fp)
                s2, n1 = re.subn(r"invoke-virtual \{([^}]+)\}, Lh3/u;->S\(\)Z",
                                 r"invoke-static {\1}, Lvr/Store;->a(Lh3/u;)Z", s)
                s2, n2 = re.subn(
                    r"invoke-static \{\}, Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->(currentModuleSnapshot|currentTargetSimSnapshot|currentRegionalSnapshot)\(\)(Lio/github/zhou6514ctrl/virtualregion/model/\w+;)",
                    r"invoke-static {}, Lvr/Store;->\1()\2", s2)
                if n1 or n2:
                    write(fp, s2)
                    s_total += n1
                    snap_total += n2

    print("S() 调用点重定向      :", s_total, "(首次 14, 重跑 0)")
    print("currentXXX 重定向     :", snap_total, "(首次 39 = 34 Module + 3 TargetSim + 2 Regional, 重跑 0)")
    if s_total not in (14, 0) or snap_total not in (39, 0):
        fail("redirect counts mismatch")

    # 残留 native 桥调用（仅提示）
    leftover = []
    for root in roots:
        for dirpath, _dirs, files in os.walk(root):
            for fn in files:
                if not fn.endswith(".smali"):
                    continue
                fp = os.path.join(dirpath, fn)
                s = read(fp)
                for m in re.finditer(
                        r"invoke-\w+ [^\r\n]*(NativeSnapshotGate;->commit\(|NativeSnapshotGate;->nativeVerifyAndCommitSnapshot|NativeSnapshotGate;->nativeCurrentSnapshot|NativeAuthCore;->verifyRaw|NativeAuthCore;->nativeVerify)", s):
                    leftover.append((os.path.relpath(fp, base), m.group(0).strip()[:120]))
    if leftover:
        print("NOTE 残留 native 桥 invoke (均在 native 抽取体内部, 不影响 Java 调用点):")
        for fp, line in leftover[:10]:
            print("   ", fp, "|", line)

    print("ALL-PATCHES-APPLIED")


if __name__ == "__main__":
    main()
