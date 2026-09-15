# -*- coding: utf-8 -*-
"""Windows 事件日志分析统计层（分析层 / Layer 2）

职责：对「数据读取层」取回的统一事件记录 dict 列表做聚合统计，输出可供
界面直接渲染的汇总结构。本文件不依赖 PySide、不碰 Windows API，是纯函数，
因此极易单测（喂合成数据即可），也方便在后台线程里跑。

输入：list[dict]，每条字段见 eventlog_reader.parse_event_xml 的返回：
    time / time_iso / ts / source / event_id / level / level_num /
    channel / computer / record_id / keywords / description / xml

输出：analyze() 返回一个 dict，含：
    total                参与统计的事件总数
    by_level             各级别 {级别: {"count": n, "ratio": pct}}（含占比）
    by_level_order       级别展示顺序（严重→错误→警告→信息→详细）
    top_event_ids        出现最多的事件 ID（含级别、来源、次数）
    top_sources          出现最多的来源
    time_buckets         按时间桶的事件数（用于趋势柱状图）
    top_errors           高频错误/严重事件（级别∈{错误,严重}）Top N
    bucket_unit          时间桶单位（"小时"/"天"），界面据此画轴

另有独立纯函数（同样可单测）：
    boot_summary()       开机 / 关机 / 运行时长摘要（System 通道的 6005/6006/6013/12/13 等）
    boot_event_kind()    单条记录归类（开机/关机/运行时长/引导/关机重启请求）
    fmt_duration()       秒 → 中文时长（"3 天 4 小时"）
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone

# 与 eventlog_reader 保持一致；此处直接引用，避免两份定义漂移
from eventlog_reader import LEVEL_NUM_TO_NAME, UI_LEVELS

# 级别严重度排序：从严重到详细，用于「按严重度展示」与「高频错误」筛选
LEVEL_SEVERITY = {"严重": 0, "错误": 1, "警告": 2, "信息": 3, "详细": 4}
ERROR_LEVELS = ("严重", "错误")     # 视为「异常」的级别
WARN_LEVELS = ("警告",)
ERROR_LEVELS_SET = set(ERROR_LEVELS)


def _ratio(part: int, total: int) -> float:
    return round(part / total * 100, 2) if total else 0.0


def analyze(records: list[dict]) -> dict:
    """对取回的事件列表做全套汇总统计。records 为空也能安全返回（界面据此显示空）。"""
    total = len(records)

    # ---- 级别分布（数量 + 占比）----
    level_counter = Counter(r.get("level", "信息") for r in records)
    by_level = {}
    for lv in sorted(level_counter, key=lambda x: LEVEL_SEVERITY.get(x, 9)):
        c = level_counter[lv]
        by_level[lv] = {"count": c, "ratio": _ratio(c, total)}
    # 展示顺序固定为：严重、错误、警告、信息、详细（只列出现有的）
    by_level_order = [lv for lv in ["严重", "错误", "警告", "信息", "详细"]
                      if lv in by_level]

    # ---- 按事件 ID 聚合（记级别与代表来源，便于解释这条 ID 在说什么）----
    id_counter: Counter = Counter()
    id_meta: dict[int, dict] = {}
    for r in records:
        eid = r.get("event_id")
        if eid is None:
            continue
        id_counter[eid] += 1
        m = id_meta.setdefault(eid, {"level": r.get("level"), "source": r.get("source")})

    # ---- 按来源聚合 ----
    src_counter = Counter(r.get("source") or "(未知)" for r in records)

    # ---- 时间戳收集（用于时间分桶 / 趋势）----
    ts_list = [r.get("ts") for r in records if r.get("ts") is not None]
    bucket_unit, buckets = _time_buckets(records)

    # ---- 高频错误/严重：异常趋势的核心 ----
    err_counter: Counter = Counter()
    err_meta: dict[tuple, dict] = {}
    for r in records:
        if r.get("level") in ERROR_LEVELS_SET:
            key = (r.get("event_id"), r.get("source") or "")
            err_counter[key] += 1
            err_meta[key] = {"level": r.get("level"),
                             "event_id": r.get("event_id"),
                             "source": r.get("source") or ""}

    top_event_ids = [
        {"event_id": eid, "count": c, "level": id_meta[eid]["level"],
         "source": id_meta[eid]["source"]}
        for eid, c in id_counter.most_common(20)
    ]
    top_sources = [{"source": s, "count": c}
                   for s, c in src_counter.most_common(20)]
    top_errors = [
        {"event_id": k[0], "source": k[1], "count": c, "level": err_meta[k]["level"]}
        for k, c in err_counter.most_common(20)
    ]

    return {
        "total": total,
        "by_level": by_level,
        "by_level_order": by_level_order,
        "top_event_ids": top_event_ids,
        "top_sources": top_sources,
        "time_buckets": buckets,           # list[{"label","count","errors"}]
        "bucket_unit": bucket_unit,
        "top_errors": top_errors,
        "span_from": min(ts_list) if ts_list else None,
        "span_to": max(ts_list) if ts_list else None,
    }


def _time_buckets(records: list[dict]) -> tuple[str, list[dict]]:
    """把事件按时间分桶，返回 (单位, [{label,count,errors}, ...])。

    桶粒度自动选：跨度 ≤ 2 天用「小时」，否则用「天」。这样既能看一天内的波动，
    也能看跨周趋势。errors 字段供界面在趋势图上叠加错误数量。
    """
    ts_list = [r["ts"] for r in records if r.get("ts") is not None]
    if not ts_list:
        return "小时", []

    t_min, t_max = min(ts_list), max(ts_list)
    span_hours = (t_max - t_min) / 3600.0

    if span_hours <= 48:
        # 按小时：桶键 = YYYY-MM-DD HH:00
        unit = "小时"
        key_fmt = "%Y-%m-%d %H:00"
        sort_fmt = "%Y%m%d%H"
    else:
        # 按天：桶键 = YYYY-MM-DD
        unit = "天"
        key_fmt = "%Y-%m-%d"
        sort_fmt = "%Y%m%d"

    agg: dict[str, dict] = defaultdict(lambda: {"count": 0, "errors": 0})
    for r in records:
        ts = r.get("ts")
        if ts is None:
            continue
        dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
        key = dt.strftime(key_fmt)
        agg[key]["count"] += 1
        if r.get("level") in ERROR_LEVELS_SET:
            agg[key]["errors"] += 1

    # 输出按时间排序的桶（label 已是字典序，直接排）
    buckets = [{"label": k, "count": v["count"], "errors": v["errors"]}
               for k, v in sorted(agg.items(),
                                  key=lambda kv: kv[0])]
    return unit, buckets


def summarize_text(stats: dict) -> str:
    """把统计结果压成一段给状态栏/摘要用的中文文字（不含表格，便于快速概览）。"""
    if not stats or stats.get("total", 0) == 0:
        return "（该筛选条件下没有日志）"
    total = stats["total"]
    parts = [f"共 {total} 条"]
    bl = stats["by_level"]
    for lv in ("严重", "错误", "警告"):
        if lv in bl and bl[lv]["count"]:
            parts.append(f"{lv} {bl[lv]['count']} 条({bl[lv]['ratio']}%)")
    errs = stats.get("top_errors") or []
    if errs:
        top = errs[0]
        parts.append(f"最高频异常：事件 {top['event_id']}（{top['source']}）×{top['count']}")
    return " · ".join(parts)


# ==========================================================================
# 开机 / 关机 / 运行时长：回答「这台机器什么时候开机的、已经运行了多久」
# ==========================================================================
# Windows 把这些信息写在 System 通道的固定事件里（本机实测确认）：
#   EventLog 6005            事件日志服务已启动 —— 每次开机写一条，可作开机标记
#   EventLog 6006            事件日志服务已停止 —— 正常关机
#   EventLog 6008            上一次关机是意外的
#   EventLog 6009            启动版本信息（OS 版本 / Build）
#   EventLog 6013            系统已运行时间：第 5 个数据字段 = 已运行「秒」（实测：
#                            开机后 10 秒写入的记录里该值为 10）
#   Kernel-General 12        OS 启动，EventData.StartTime = 开机时刻（UTC）
#   Kernel-General 13        OS 关闭，EventData.StopTime  = 关机时刻（UTC）
#   Kernel-Boot 20/27/32     引导阶段（可辅助看引导耗时）
#   User32 1074              关机/重启由哪个进程发起
BOOT_EVENT_KINDS: dict[tuple[str, int], str] = {
    ("EventLog", 6005): "开机",
    ("EventLog", 6009): "开机版本",
    ("EventLog", 6013): "运行时长",
    ("EventLog", 6006): "正常关机",
    ("EventLog", 6008): "意外关机",
    ("Microsoft-Windows-Kernel-General", 12): "开机",
    ("Microsoft-Windows-Kernel-General", 13): "关机",
    ("Microsoft-Windows-Kernel-Boot", 20): "引导",
    ("Microsoft-Windows-Kernel-Boot", 27): "引导",
    ("Microsoft-Windows-Kernel-Boot", 32): "引导",
    ("User32", 1074): "关机/重启请求",
}

# 判定「此刻是否在运行」只用这两类事件，避免把「关机请求」当成已关机
_BOOT_KINDS = ("开机",)
_SHUTDOWN_KINDS = ("正常关机", "意外关机", "关机")

# 6013 的已运行秒数在 EventData 里的位置（无名 <Data> 从 1 起编号）
UPTIME_FIELD = "参数5"

# 「开机与运行」快捷筛选用到的来源与事件 ID（界面「开机与运行」按钮直接引用）
BOOT_FILTER_PROVIDERS = ["EventLog", "Microsoft-Windows-Kernel-General",
                         "Microsoft-Windows-Kernel-Boot", "User32"]
BOOT_FILTER_EVENT_IDS = [6005, 6006, 6008, 6009, 6013, 12, 13, 20, 27, 32, 1074]


def boot_event_kind(rec: dict) -> str | None:
    """把一条记录归类为 开机/关机/运行时长/引导/关机重启请求；否则返回 None。"""
    try:
        eid = int(rec.get("event_id"))
    except (TypeError, ValueError):
        return None
    return BOOT_EVENT_KINDS.get(((rec.get("source") or "").strip(), eid))


def parse_uptime_seconds(rec: dict) -> int | None:
    """从 6013「系统已运行时间」记录里取出已运行秒数；取不到返回 None。

    6013 属经典（classic）事件，没有 RenderingInfo 本地化消息，字段按位置给出：
    第 5 个 Data 即已运行秒数（开机后 10 秒写入的记录里该值为 10）。
    """
    if boot_event_kind(rec) != "运行时长":
        return None
    v = str((rec.get("event_data") or {}).get(UPTIME_FIELD, "")).strip()
    return int(v) if v.isdigit() else None


def boot_start_iso(rec: dict) -> str:
    """Kernel-General 12 的 StartTime（开机时刻，UTC ISO）；没有则空串。"""
    return str((rec.get("event_data") or {}).get("StartTime", "") or "").strip()


def boot_kind_text(rec: dict) -> str:
    """把开机类事件压成一句人话；非此类事件返回空串。

    列表「描述」列前缀与详情弹窗的「事件含义」行共用同一实现，保证两处口径一致。
    """
    kind = boot_event_kind(rec)
    if not kind:
        return ""
    if kind == "运行时长":
        sec = parse_uptime_seconds(rec)
        return (f"系统已运行 {sec} 秒（≈{fmt_duration(sec)}）" if sec is not None
                else "系统已运行时间")
    if kind == "开机":
        iso = boot_start_iso(rec)
        return f"开机（{iso}）" if iso else "开机 · 事件日志服务已启动"
    return {
        "开机版本": "开机版本信息（OS 版本与 Build）",
        "正常关机": "正常关机 · 事件日志服务已停止",
        "意外关机": "上一次关机是意外的",
        "关机": "关机 · OS 已停止",
        "引导": "引导阶段事件（BOOT）",
        "关机/重启请求": "关机/重启请求（由某进程发起）",
    }.get(kind, kind)


def fmt_duration(seconds) -> str:
    """秒数 → 中文时长（如「3 天 4 小时」「25 分 10 秒」）。非法输入返回空串。"""
    try:
        s = int(seconds)
    except (TypeError, ValueError):
        return ""
    if s < 0:
        return ""
    d, rem = divmod(s, 86400)
    h, rem = divmod(rem, 3600)
    m = rem // 60
    if d:
        return f"{d} 天 {h} 小时"
    if h:
        return f"{h} 小时 {m} 分"
    if m:
        return f"{m} 分 {rem % 60} 秒"
    return f"{s} 秒"


def boot_summary(records: list[dict], now: datetime | None = None) -> dict:
    """从事件列表里抽取「开机 / 关机 / 运行时长」摘要（纯函数，可单测）。

    返回：
      available               是否找到任何开机/关机的线索
      last_boot               最近一次开机 {time,ts,source,event_id,kind,start_utc}
      last_shutdown           最近一次关机（同形状）；无则 None
      running                 最近一条启停事件是「开机」为 True、是「关机」为 False，
                              没有线索为 None（不确定）
      current_uptime_seconds  已知最近开机时间时的「本次已运行秒数」（推断值）
      uptime_seconds          6013 日志自报的已运行秒数
      uptime_logged_at        上面这条 6013 的记录时间
      boots / shutdowns / requests   明细（新→旧），界面可展开查看
      summary                 一行中文摘要
    """
    now = now or datetime.now()
    boots: list[dict] = []
    shutdowns: list[dict] = []
    requests: list[dict] = []
    uptime_cand: list[tuple[float, int, str]] = []

    for r in records:
        kind = boot_event_kind(r)
        if not kind:
            continue
        item = {"time": r.get("time", ""), "ts": r.get("ts"),
                "source": r.get("source", ""), "event_id": r.get("event_id"),
                "kind": kind, "start_utc": boot_start_iso(r)}
        if kind in _BOOT_KINDS:
            boots.append(item)
        elif kind in _SHUTDOWN_KINDS:
            shutdowns.append(item)
        elif kind == "关机/重启请求":
            requests.append(item)
        else:                                   # 运行时长 / 开机版本 / 引导
            sec = parse_uptime_seconds(r)
            if sec is not None:
                uptime_cand.append((r.get("ts") or 0.0, sec, r.get("time", "")))

    _key = lambda it: it.get("ts") or 0.0       # noqa: E731
    boots.sort(key=_key, reverse=True)
    shutdowns.sort(key=_key, reverse=True)
    requests.sort(key=_key, reverse=True)
    last_boot = boots[0] if boots else None
    last_shutdown = shutdowns[0] if shutdowns else None

    running: bool | None = None
    current_uptime: int | None = None
    if last_boot is not None:
        running = (last_shutdown is None or
                   _key(last_boot) >= _key(last_shutdown))
        if running:
            # 由「最近一次开机时刻」推断本次已运行时长（与 6013 自报值互为校验）
            try:
                sec = (now - datetime.fromtimestamp(_key(last_boot))).total_seconds()
                current_uptime = max(int(sec), 0)
            except (OverflowError, OSError, ValueError):
                current_uptime = None

    uptime_s: int | None = None
    uptime_at = ""
    if uptime_cand:
        uptime_cand.sort(key=lambda x: x[0])
        _ts, uptime_s, uptime_at = uptime_cand[-1]

    # ---- 一行摘要 ----
    parts: list[str] = []
    if last_boot:
        parts.append(f"最近开机 {last_boot['time']}")
    if running is True:
        parts.append("当前状态：运行中（最近一条启停事件为「开机」）")
    elif running is False:
        parts.append("当前状态：已关机（最近一条启停事件为「关机」）")
    if current_uptime is not None:
        parts.append(f"本次已运行 ≈{fmt_duration(current_uptime)}")
    if uptime_s is not None:
        parts.append(f"日志自报已运行 {uptime_s} 秒（≈{fmt_duration(uptime_s)}，"
                     f"记录于 {uptime_at}）")
    if last_shutdown:
        parts.append(f"最近关机 {last_shutdown['time']}")

    return {
        "available": bool(boots or shutdowns or uptime_cand),
        "last_boot": last_boot,
        "last_shutdown": last_shutdown,
        "running": running,
        "current_uptime_seconds": current_uptime,
        "uptime_seconds": uptime_s,
        "uptime_logged_at": uptime_at,
        "boots": boots,
        "shutdowns": shutdowns,
        "requests": requests,
        "summary": " · ".join(parts),
    }
