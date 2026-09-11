.class public final Lvr/Store;
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
