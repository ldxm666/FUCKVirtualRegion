#!/usr/bin/env python3
"""Patch the VirtualRegion smali tree in place so the license is permanent and the
system-side snapshot gate stops depending on the native lease verification.

Targets (runtime names taken from the real bytecode, not from jadx's renaming):

  auth/w.smali        a()Z  -> true        b()Z  -> false
  auth/v.smali        b0(...) coerce state to AUTHORIZED
                      c0(...) return a successful verify result (OK_OFFLINE, far future)
                      Q()     return AuthInfo(AUTHORIZED, expireTime = 0)   <-- permanent
                      Z()     -> false  (the "卡密授权" dialog can never be shown)
  auth/NativeAuthCore.smali
                      a(H,String,Z) -> successful verify result (Java-side native entry point)
  auth/NativeSnapshotGate.smali
                      f/g/h  cache the already-parsed snapshot object, report success
                      e      report success
                      + aCached()/bCached()/cCached() getters that prefer the cached object
  all smali files     retarget currentModuleSnapshot()/currentRegionalSnapshot()/
                      currentTargetSimSnapshot() call sites at the cached getters

Idempotent: re-running on an already-patched tree is a no-op for the injected blocks.

usage: python scripts/tools/patch_apk_smali.py <apktool_project_dir>
"""
import io
import os
import re
import sys

AUTH = "smali/io/github/zhou6514ctrl/virtualregion/auth"
FAR = "0xf48a0b00L"          # 4102444800 == 2100-01-01T00:00:00Z seconds

W = "Lio/github/zhou6514ctrl/virtualregion/auth/w;"
C = "Lio/github/zhou6514ctrl/virtualregion/auth/c;"
D = "Lio/github/zhou6514ctrl/virtualregion/auth/d;"
F = "Lio/github/zhou6514ctrl/virtualregion/auth/F;"
INFO = "Lio/github/zhou6514ctrl/virtualregion/auth/AuthInfo;"
GATE = "Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;"


def replace_method(text, header_prefix, body, tag):
    """Replace a whole .method block whose declaration starts with header_prefix."""
    start = text.find(header_prefix)
    if start < 0:
        raise SystemExit("method not found: " + header_prefix)
    end = text.find("\n.end method", start)
    if end < 0:
        raise SystemExit("unterminated method: " + header_prefix)
    end += len("\n.end method")
    print("   patched", tag)
    return text[:start] + body.rstrip("\n") + "\n.end method" + text[end:]


def patch_w(path):
    p = os.path.join(path, AUTH, "w.smali")
    t = open(p, encoding="utf-8").read()
    t = replace_method(
        t, ".method public final a()Z",
        """.method public final a()Z
    .locals 1

    const/4 v0, 0x1

    return v0""", "auth.w#a (always usable)")
    t = replace_method(
        t, ".method public final b()Z",
        """.method public final b()Z
    .locals 1

    const/4 v0, 0x0

    return v0""", "auth.w#b (never blocked)")
    open(p, "w", encoding="utf-8", newline="\n").write(t)


def patch_v(path):
    p = os.path.join(path, AUTH, "v.smali")
    t = open(p, encoding="utf-8").read()

    # b0(w, String, String, Z) — overwrite the incoming state before the original body runs.
    header = ".method public final b0("
    start = t.find(header)
    if start < 0:
        raise SystemExit("auth.v#b0 not found")
    inject = (
        "    sget-object p1, %s->d:%s\n"
        "    const-string p2, \"\"\n"
        "    const-string p3, \"AUTHORIZED\"\n"
        "    const/4 p4, 0x0\n" % (W, W)
    )
    if inject in t:
        print("   auth.v#b0 already coerced, skipping")
    else:
        # The injected code must come AFTER the .locals directive, otherwise smali rejects the method.
        loc = t.find("\n    .locals ", start)
        if loc < 0:
            raise SystemExit("auth.v#b0 has no .locals directive")
        eol = t.find("\n", loc + 1) + 1
        # stays inside the original .locals 5 frame (v0/v1 only); the lease itself is built by revxLease()
        t = t[:eol] + LEASE_CALL + inject + t[eol:]
        print("   patched auth.v#b0 (state coerced to AUTHORIZED + synthetic lease installed)")

    if ".method private static revxLease()" not in t:
        t = t.rstrip("\n") + "\n" + LEASE_HELPER
        print("   added auth.v#revxLease() synthetic lease builder")

    t = replace_method(
        t, ".method public final c0(",
        """.method public final c0(Lio/github/zhou6514ctrl/virtualregion/auth/H;)Lio/github/zhou6514ctrl/virtualregion/auth/d;
    .locals 9

    new-instance v0, %s

    sget-object v1, %s->c:%s

    const-wide v2, %s

    const-wide v4, %s

    const-wide v6, %s

    const/4 v8, 0x1

    invoke-direct/range {v0 .. v8}, %s-><init>(%sJJJZ)V

    return-object v0""" % (D, C, C, FAR, FAR, FAR, D, C), "auth.v#c0 (offline verify always OK)")

    t = replace_method(
        t, ".method public final Q()",
        """.method public final Q()Lio/github/zhou6514ctrl/virtualregion/auth/AuthInfo;
    .locals 7

    new-instance v0, %s

    sget-object v1, %s->d:%s

    const-wide/16 v2, 0x0

    const-wide/16 v4, 0x0

    const-string v6, "AUTHORIZED"

    invoke-direct/range {v0 .. v6}, %s-><init>(%sJJLjava/lang/String;)V

    return-object v0""" % (INFO, W, W, INFO, W), "auth.v#Q (expireTime = 0 => permanent)")

    # Z() is the single precondition of the "卡密授权" AlertDialog (p194c4.C2139x#a).
    t = replace_method(
        t, ".method public final Z()Z",
        """.method public final Z()Z
    .locals 1

    const/4 v0, 0x0

    return v0""", "auth.v#Z (卡密授权 dialog can never show)")

    open(p, "w", encoding="utf-8", newline="\n").write(t)


def patch_native_auth_core(path):
    """NativeAuthCore.a(H, String, Z) is the only Java-visible entry into the Ed25519 verifier."""
    p = os.path.join(path, AUTH, "NativeAuthCore.smali")
    t = open(p, encoding="utf-8").read()
    t = replace_method(
        t, ".method public final a(",
        """.method public final a(Lio/github/zhou6514ctrl/virtualregion/auth/H;Ljava/lang/String;Z)Lio/github/zhou6514ctrl/virtualregion/auth/d;
    .locals 9

    new-instance v0, %s

    sget-object v1, %s->c:%s

    const-wide v2, %s

    const-wide v4, %s

    const-wide v6, %s

    const/4 v8, 0x1

    invoke-direct/range {v0 .. v8}, %s-><init>(%sJJJZ)V

    return-object v0""" % (D, C, C, FAR, FAR, FAR, D, C), "NativeAuthCore#a (native Ed25519 always OK)")
    open(p, "w", encoding="utf-8", newline="\n").write(t)


OK_F = """    move-wide/from16 v10, p2

    new-instance v1, %s

    sget-object v2, %s->c:%s

    const-wide v3, %s

    const-wide v5, %s

    const-wide v7, %s

    const/4 v9, 0x1

    invoke-direct/range {v1 .. v9}, %s-><init>(%sJJJZ)V

    new-instance v0, %s

    invoke-direct {v0, v1, v10, v11}, %s-><init>(%sJ)V

    return-object v0""" % (D, C, C, FAR, FAR, FAR, D, C, F, F, D)


# auth.v#b0 addition.  The publisher (p270m3.C4569h) only pushes to LSPosed RemotePreferences when
# u.a()==true AND v.t != null; a freshly unlocked install has no lease at all (the vendor server
# never issued one), so the whole system side would stay idle.  b0() keeps its original .locals 5 —
# the lease is built by a separate static helper so no frame widening is needed.
LEASE_CALL = """    iget-object v0, p0, Lio/github/zhou6514ctrl/virtualregion/auth/v;->t:Lio/github/zhou6514ctrl/virtualregion/auth/H;

    if-nez v0, :revx_lease_ok

    invoke-static {}, Lio/github/zhou6514ctrl/virtualregion/auth/v;->revxLease()Lio/github/zhou6514ctrl/virtualregion/auth/H;

    move-result-object v1

    iput-object v1, p0, Lio/github/zhou6514ctrl/virtualregion/auth/v;->t:Lio/github/zhou6514ctrl/virtualregion/auth/H;

    :revx_lease_ok
"""

#  H(f(1, plan, keyId, subject, 0, now, now, FAR, null), new byte[0], new byte[0])
LEASE_HELPER = """
.method private static revxLease()Lio/github/zhou6514ctrl/virtualregion/auth/H;
    .locals 16

    invoke-static {}, Ljava/lang/System;->currentTimeMillis()J

    move-result-wide v0

    const-wide/16 v2, 0x3e8

    div-long/2addr v0, v2

    new-instance v2, Lio/github/zhou6514ctrl/virtualregion/auth/f;

    const/4 v3, 0x1

    const-string v4, "revx-permanent"

    const-string v5, "auth-ed25519-2026-01"

    const-string v6, "revx"

    const-wide/16 v7, 0x0

    move-wide v9, v0

    move-wide v11, v0

    const-wide v13, %s

    const/4 v15, 0x0

    invoke-direct/range {v2 .. v15}, Lio/github/zhou6514ctrl/virtualregion/auth/f;-><init>(ILjava/lang/String;Ljava/lang/String;Ljava/lang/String;JJJJLjava/lang/Long;)V

    new-instance v3, Lio/github/zhou6514ctrl/virtualregion/auth/H;

    new-array v4, v15, [B

    new-array v5, v15, [B

    invoke-direct {v3, v2, v4, v5}, Lio/github/zhou6514ctrl/virtualregion/auth/H;-><init>(Lio/github/zhou6514ctrl/virtualregion/auth/f;[B[B)V

    return-object v3
.end method
""" % FAR


def patch_gate(path, versions):
    p = os.path.join(path, AUTH, "NativeSnapshotGate.smali")
    t = open(p, encoding="utf-8").read()

    # 1) cache fields
    anchor = ".field public static final a:Z"
    if anchor not in t:
        anchor = ".field public static final b:Z"
    if anchor not in t:
        anchor = ".method static constructor <clinit>()V"
    if "sMod:Ljava/lang/Object;" in t:
        print("   NativeSnapshotGate cache fields already present, skipping")
    else:
        t = t.replace(
            anchor,
            ".field private static sMod:Ljava/lang/Object;\n\n"
            ".field private static sReg:Ljava/lang/Object;\n\n"
            ".field private static sSim:Ljava/lang/Object;\n\n" + anchor, 1)

    # 2) f / g / h : cache the parsed snapshot, return success
    for name, field, tag in (("f", "sMod", "module"), ("g", "sReg", "regional"), ("h", "sSim", "sim")):
        head = ".method public static %s(" % name
        start = t.find(head)
        if start < 0:
            raise SystemExit("NativeSnapshotGate#%s not found" % name)
        end = t.find("\n.end method", start) + len("\n.end method")
        decl = t[start:t.find("\n", start)]
        body = (
            "%s\n    .locals 14\n\n"
            "    sput-object p1, %s->%s:Ljava/lang/Object;\n\n"
            "%s\n.end method" % (decl, GATE, field, OK_F)
        )
        t = t[:start] + body + t[end:]
        print("   patched NativeSnapshotGate#%s (cache %s snapshot + report success)" % (name, tag))

    # 3) e : hidden-apps commit -> success only
    head = ".method public static e("
    start = t.find(head)
    if start >= 0:
        end = t.find("\n.end method", start) + len("\n.end method")
        decl = t[start:t.find("\n", start)]
        ok_e = """    new-instance v1, %s

    sget-object v2, %s->c:%s

    const-wide v3, %s

    const-wide v5, %s

    const-wide v7, %s

    const/4 v9, 0x1

    invoke-direct/range {v1 .. v9}, %s-><init>(%sJJJZ)V

    new-instance v0, %s

    const-wide/16 v2, 0x1

    invoke-direct {v0, v1, v2, v3}, %s-><init>(%sJ)V

    return-object v0""" % (D, C, C, FAR, FAR, FAR, D, C, F, F, D)
        t = t[:start] + decl + "\n    .locals 12\n\n" + ok_e + "\n.end method" + t[end:]
        print("   patched NativeSnapshotGate#e (hidden-apps commit reports success)")

    # 4) cached getters
    if "aCached()" in t:
        print("   cached getters already present, skipping")
        open(p, "w", encoding="utf-8", newline="\n").write(t)
        return versions
    getters = ""
    for gname, field, ret in (("aCached", "sMod", "ModuleSnapshot"),
                              ("bCached", "sReg", "RegionalSnapshot"),
                              ("cCached", "sSim", "TargetSimSnapshot")):
        native = {"aCached": "currentModuleSnapshot",
                  "bCached": "currentRegionalSnapshot",
                  "cCached": "currentTargetSimSnapshot"}[gname]
        sig = "Lio/github/zhou6514ctrl/virtualregion/model/%s;" % ret
        getters += """
.method public static %s()%s
    .locals 1

    sget-object v0, %s->%s:Ljava/lang/Object;

    if-nez v0, :cond_0

    invoke-static {}, %s->%s()%s

    move-result-object v0

    return-object v0

    :cond_0
    check-cast v0, %s

    return-object v0
.end method
""" % (gname, sig, GATE, field, GATE, native, sig, sig)
    t = t.rstrip("\n") + "\n" + getters
    print("   added aCached()/bCached()/cCached() getters")
    open(p, "w", encoding="utf-8", newline="\n").write(t)
    return versions


def retarget_calls(path):
    mapping = [
        ("Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->currentModuleSnapshot()",
         "Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->aCached()"),
        ("Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->currentRegionalSnapshot()",
         "Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->bCached()"),
        ("Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->currentTargetSimSnapshot()",
         "Lio/github/zhou6514ctrl/virtualregion/auth/NativeSnapshotGate;->cCached()"),
    ]
    changed = 0
    for root, _dirs, files in os.walk(path):
        for fn in files:
            if not fn.endswith(".smali"):
                continue
            fp = os.path.join(root, fn)
            s = open(fp, encoding="utf-8").read()
            o = s
            for a, b in mapping:
                s = s.replace(a, b)
            if s != o:
                open(fp, "w", encoding="utf-8", newline="\n").write(s)
                changed += 1
    print("   retargeted snapshot getters in %d smali file(s)" % changed)


def patch_update_dialog(path):
    """f4.a is the parsed remote "new version" manifest (JADX: p219f4.C4036a).

    MainActivity#RunnableC0161a only builds the 发现新版本 AlertDialog when
    ``manifest.versionCode > 205``; zero the field at construction time and the check can never
    fire.  The object is used nowhere else (2 references in the whole app).
    """
    target = None
    for dirpath, _dirnames, filenames in os.walk(path):
        base = os.path.basename(dirpath)
        if (base == "f4" or base.startswith("f4.")) and "a.smali" in filenames:
            fp = os.path.join(dirpath, "a.smali")
            if io.open(fp, encoding="utf-8").read(200).startswith(".class public final Lf4/a;"):
                target = fp
    if target is None:
        raise SystemExit("update-manifest class Lf4/a; not found")
    t = io.open(target, encoding="utf-8").read()
    if "    const/4 p1, 0x0\n" in t and "->a:I" in t and "const/4 p1, 0x0" in t.split("->a:I")[0][-120:]:
        print("   update-dialog gate already zeroed, skipping")
        return
    anchor = "    invoke-direct {p0}, Ljava/lang/Object;-><init>()V\n"
    if anchor not in t:
        raise SystemExit("unexpected f4.a <init> shape")
    t = t.replace(anchor, anchor + "\n    const/4 p1, 0x0\n", 1)
    io.open(target, "w", encoding="utf-8", newline="\n").write(t)
    print("   patched %s (remote versionCode forced to 0 => no 发现新版本 dialog)"
          % os.path.relpath(target, path))


def main():
    if len(sys.argv) < 2:
        raise SystemExit(__doc__)
    path = sys.argv[1]
    print("[patch] apktool project:", path)
    patch_w(path)
    patch_v(path)
    patch_native_auth_core(path)
    patch_update_dialog(path)
    patch_gate(path, None)
    retarget_calls(path)
    print("[patch] done")


if __name__ == "__main__":
    main()
