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
