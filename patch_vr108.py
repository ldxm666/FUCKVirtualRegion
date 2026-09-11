# -*- coding: utf-8 -*-
"""
VirtualRegion 1.0.8 smali unlock patcher (complete).
Every replacement carries hit-count assertions; aborts on any mismatch.
"""
import re, sys, os

ROOT = r"D:\pojie应用\pojie3\VR108\apktool\smali"
FAR = 4102444800           # 2100-01-01 epoch
ISSUED = 1577836800        # 2020-01-01 epoch
FARX = "0x%08xL" % FAR     # const-wide 64-bit literal
ISSX = "0x%08xL" % ISSUED
print("FAR literal:", FARX, "ISSUED literal:", ISSX)

stats = {"s_redirect": 0, "snap_redirect": 0}

def read(p):
    with open(p, "r", encoding="utf-8") as f:
        return f.read()

def write(p, s):
    with open(p, "w", encoding="utf-8", newline="") as f:
        f.write(s)

def replace_method(src, sig, new_body, label):
    m = re.search(r"^\.method[^\r\n]*" + re.escape(sig) + r"[^\r\n]*\r?\n.*?^\.end method[ \t]*$",
                  src, re.M | re.S)
    if not m:
        print("FAIL method not found:", label, sig); sys.exit(1)
    return src[:m.start()] + new_body.strip() + "\n" + src[m.end():]

def sub_expect(src, pattern, repl, n, label, flags=0):
    new, cnt = re.subn(pattern, repl, src, flags=flags)
    if cnt != n:
        print("FAIL expect %d got %d for %s" % (n, cnt, label)); sys.exit(1)
    return new

def sub_flag(src, pattern, repl, n, label, flags=0):
    """idempotent variant: accept either fresh hit-count n or 0 (already patched)"""
    new, cnt = re.subn(pattern, repl, src, flags=flags)
    if cnt not in (0, n):
        print("FAIL expect %d-or-0 got %d for %s" % (n, cnt, label)); sys.exit(1)
    return new

def ok_d_direct(objreg, creg, base, zreg, ctor_targets, extra=""):
    """helper building an 'return new h3.d(OK_ONLINE,FAR,FAR,FAR,true)' body"""
    return """
    new-instance {obj}, Lh3/d;
    sget-object {c}, Lh3/c;->b:Lh3/c;
    const-wide {b0}, {far}
    const-wide {b1}, {far}
    const-wide {b2}, {far}
    const/4 {z}, 0x1
    invoke-direct/range {{"{r0} .. {r1}"}}, Lh3/d;-><init>(Lh3/c;JJJZ)V
{extra}
    return-object {obj}
""".format(obj=objreg, c=creg, b0=base, b1="v%d" % (int(base[1:]) + 2),
           b2="v%d" % (int(base[1:]) + 4), z=zreg, far=FARX,
           r0=objreg[1:], r1=zreg[1:], extra=extra)

# ================================================================ h3/D
p = os.path.join(ROOT, "h3", "D.smali")
s = read(p)
# clinit: both AtomicBooleans share the same const/4 v1, 0x0 -> set true once
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
print("OK h3/D")

# ================================================================ h3/u
p = os.path.join(ROOT, "h3", "u.smali")
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

# b0: force state param to AUTHORIZED_ONLINE (idempotent: skip if already inserted)
if "sget-object p1, Lh3/v;->c:Lh3/v;" not in s:
    s = sub_expect(s, r"(\.method public final b0\(Lh3/v;Ljava/lang/String;Ljava/lang/String;\)V\r?\n    \.locals 5\r?\n)",
                   r"\1\n    sget-object p1, Lh3/v;->c:Lh3/v;\n", 1, "u.b0 force state")
else:
    print("skip u.b0 (already patched)")

s = replace_method(s, "N()Lh3/E;", """
.method public final N()Lh3/E;
    .locals 16

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
print("OK h3/u")

# ================================================================ NativeAuthCore
p = os.path.join(ROOT, "io", "github", "zhou6514ctrl", "virtualregion", "auth", "NativeAuthCore.smali")
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
print("OK NativeAuthCore")

# ================================================================ NativeSnapshotGate
p = os.path.join(ROOT, "io", "github", "zhou6514ctrl", "virtualregion", "auth", "NativeSnapshotGate.smali")
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

s = replace_method(s, "c([BLio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
    gate_commit("c([BLio/github/zhou6514ctrl/virtualregion/model/ModuleSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 1), "NSG.c")

s = replace_method(s, "d([BLio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
    gate_commit("d([BLio/github/zhou6514ctrl/virtualregion/model/RegionalSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 3), "NSG.d")

s = replace_method(s, "e(Ljava/lang/String;Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;",
    gate_commit("e(Ljava/lang/String;Lio/github/zhou6514ctrl/virtualregion/model/TargetSimSnapshot;JLjava/lang/String;Ljava/lang/String;[B[B)Lh3/C;", 2), "NSG.e")

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
print("OK NativeSnapshotGate")

# ================================================================ AuthorizationRequiredReceiver
p = os.path.join(ROOT, "io", "github", "zhou6514ctrl", "virtualregion", "auth", "AuthorizationRequiredReceiver.smali")
s = read(p)
s = replace_method(s, "onReceive(Landroid/content/Context;Landroid/content/Intent;)V", """
.method public final onReceive(Landroid/content/Context;Landroid/content/Intent;)V
    .locals 0

    return-void
.end method
""", "ARR.onReceive")
write(p, s)
print("OK AuthorizationRequiredReceiver")

# ================================================================ global redirects
s_total = s_redirect = snap_total = snap_redirect = 0
for dirpath, _dirs, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith(".smali"):
            continue
        fp = os.path.join(dirpath, fn)
        s = read(fp)
        s2, n1 = re.subn(r"invoke-virtual \{([^}]+)\}, Lh3/u;->S\(\)Z",
                         r"invoke-static {\1}, Lvr/Store;->a(Lh3/u;)Z", s)
        s2, n2 = re.subn(r"invoke-static \{\}, Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->(currentModuleSnapshot|currentTargetSimSnapshot|currentRegionalSnapshot)\(\)(Lio/github/zhou6514ctrl/virtualregion/model/\w+;)",
                         r"invoke-static {}, Lvr/Store;->\1()\2", s2)
        if n1 or n2:
            write(fp, s2)
            s_total += n1; snap_total += n2

print("S() redirected:", s_total, "(expect 14 fresh, 0 if re-run)")
print("currentXXX redirected:", snap_total, "(expect 39 fresh: 34 Module + 3 TargetSim + 2 Regional)")
if s_total not in (14, 0) or snap_total not in (39, 0):
    print("FAIL redirect counts mismatch"); sys.exit(1)

# residual check: no java invoke into extracted natives that we bypassed
leftover = []
for dirpath, _dirs, files in os.walk(ROOT):
    for fn in files:
        if not fn.endswith(".smali"):
            continue
        fp = os.path.join(dirpath, fn)
        s = read(fp)
        for m in re.finditer(r"invoke-\w+ [^\r\n]*(NativeSnapshotGate;->commit\(|NativeSnapshotGate;->nativeVerifyAndCommitSnapshot|NativeSnapshotGate;->nativeCurrentSnapshot|NativeAuthCore;->verifyRaw|NativeAuthCore;->nativeVerify)", s):
            leftover.append((fp, m.group(0).strip()[:120]))
if leftover:
    print("NOTE residual native-bridge invoke sites (info only):")
    for fp, line in leftover:
        print("  ", os.path.relpath(fp, ROOT), "|", line)

print("ALL-PATCHES-APPLIED")
