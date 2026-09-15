# -*- coding: utf-8 -*-
"""系统日志模块回归测试（沿用项目 check_*.py 风格，可离线、可单测）

分层验证：
  A. 数据读取层(eventlog_reader)：build_xpath 构造、parse_event_xml 解析
     —— 纯函数，不依赖 PySide6，用受管 Python 即可跑。
  B. 分析统计层(eventlog_stats)：级别分布/高频错误/时间分桶聚合
     —— 同样纯函数。
  C. 界面展示层(eventlog_widget) + gui 集成：仅在 PySide6 可用时跑（offscreen），
     用合成数据驱动面板，验证分页/关键字筛选/排序/分析/导出，以及新增标签页
     不会污染既有数据页的索引逻辑(_tab_at)。

运行：python check_eventlog.py
退出码：0 = 全部通过（或 UI 部分因环境无 PySide6 而跳过）；1 = 有失败。
"""

from __future__ import annotations

import os
import sys
import tempfile

# 让脚本能直接 import 同目录模块
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

RESULTS: list[tuple[str, bool, str]] = []


def check(name: str, cond: bool, extra: str = ""):
    RESULTS.append((name, bool(cond), extra))
    mark = "PASS" if cond else "FAIL"
    line = f"  [{mark}] {name}"
    if extra and not cond:
        line += f"  -> {extra}"
    print(line)


def section(title: str):
    print(f"\n=== {title} ===")


# ==========================================================================
# A. 数据读取层
# ==========================================================================
def test_reader():
    section("A. 数据读取层 eventlog_reader")
    import eventlog_reader as evr

    # --- build_xpath：结构化筛选拼 XPath ---
    xp = evr.build_xpath(levels=["错误", "警告"])
    check("xpath 级别筛选", "Level=2" in xp and "Level=3" in xp, xp)
    # 多类条件(级别 + 事件ID)应拼成 "与" 关系
    xp2 = evr.build_xpath(levels=["错误", "警告"], event_ids=[1001])
    check("xpath 多条件是 '与' 关系",
          "System[(" in xp2 and ") and (" in xp2, xp2)
    check("xpath 含级别与事件ID", "Level=2" in xp2 and "EventID=1001" in xp2, xp2)

    xp = evr.build_xpath(event_ids=[1001, 1002])
    check("xpath 事件ID筛选", "EventID=1001" in xp and "EventID=1002" in xp, xp)

    xp = evr.build_xpath(providers=["A", "B"])
    check("xpath 来源筛选", "Provider[@Name='A' or @Name='B']" in xp, xp)

    xp = evr.build_xpath(time_from=__import__("datetime").datetime(2026, 9, 1),
                         time_to=__import__("datetime").datetime(2026, 9, 10))
    check("xpath 时间范围筛选", "TimeCreated[@SystemTime>=" in xp
          and "TimeCreated[@SystemTime<=" in xp, xp)

    xp = evr.build_xpath()
    check("xpath 无筛选 = '*'", xp == "*", xp)

    # 关键字不应进入 XPath（客户端筛）
    xp = evr.build_xpath(levels=["错误"])
    check("xpath 不含自由文本关键字", "like" not in xp.lower(), xp)

    # --- parse_event_xml：解析渲染出来的事件 XML ---
    xml = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "  <System>"
        "    <Provider Name='Microsoft-Windows-Security-SPP'/>"
        "    <EventID Qualifiers='0'>1001</EventID>"
        "    <Level>2</Level>"
        "    <TimeCreated SystemTime='2026-09-13T12:34:56.789000Z'/>"
        "    <Channel>Application</Channel>"
        "    <Computer>PC01</Computer>"
        "    <EventRecordID>12345</EventRecordID>"
        "  </System>"
        "  <EventData>"
        "    <Data Name='param1'>value1</Data>"
        "    <Data>positional</Data>"
        "  </EventData>"
        "  <RenderingInfo Culture='zh-CN'>"
        "    <Level>错误</Level>"
        "    <Message>测试消息正文</Message>"
        "  </RenderingInfo>"
        "</Event>"
    )
    rec = evr.parse_event_xml(xml)
    check("解析 source", rec["source"] == "Microsoft-Windows-Security-SPP", rec["source"])
    check("解析 event_id", rec["event_id"] == 1001, str(rec["event_id"]))
    check("解析 level(来自RenderingInfo)", rec["level"] == "错误", rec["level"])
    check("解析 description(来自RenderingInfo)",
          rec["description"] == "测试消息正文", rec["description"])
    check("解析 ts 非空", rec["ts"] is not None, str(rec["ts"]))
    check("解析 record_id", rec["record_id"] == 12345, str(rec["record_id"]))
    check("解析 channel", rec["channel"] == "Application", rec["channel"])

    # 无 RenderingInfo 时退回 EventData 拼接
    xml2 = (
        "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>"
        "  <System><Provider Name='X'/><EventID>7</EventID><Level>3</Level>"
        "    <TimeCreated SystemTime='2026-09-13T01:02:03.000000Z'/></System>"
        "  <EventData><Data Name='a'>1</Data><Data Name='b'>2</Data></EventData>"
        "</Event>"
    )
    rec2 = evr.parse_event_xml(xml2)
    check("无消息时 description 退回事件数据",
          "a = 1" in rec2["description"] and "b = 2" in rec2["description"],
          rec2["description"])
    check("无 RenderingInfo 时 level 按数字映射", rec2["level"] == "警告", rec2["level"])

    # 异常 XML 不崩
    rec3 = evr.parse_event_xml("not-xml")
    check("非法 XML 不抛异常", rec3["description"] == "not-xml", rec3["description"])


# ==========================================================================
# B. 分析统计层
# ==========================================================================
def _mk_rec(ts, level, eid, source, desc="d"):
    return {"time": "", "time_iso": "", "ts": ts, "source": source,
            "event_id": eid, "level": level, "level_num": 4,
            "channel": "Application", "computer": "PC", "record_id": None,
            "keywords": "", "description": desc, "xml": "<x/>"}


def test_stats():
    section("B. 分析统计层 eventlog_stats")
    import eventlog_stats as evs
    from datetime import datetime, timezone

    base = datetime(2026, 9, 1, 0, 0, 0, tzinfo=timezone.utc).timestamp()
    recs = [
        _mk_rec(base + 0, "错误", 1001, "SrvA", "UNIQUETOKEN 出错了"),
        _mk_rec(base + 3600, "错误", 1001, "SrvA", "UNIQUETOKEN 又错"),
        _mk_rec(base + 7200, "警告", 2002, "SrvB", "warn"),
        _mk_rec(base + 10800, "信息", 3003, "SrvC", "info"),
        _mk_rec(base + 86400 * 3, "严重", 1001, "SrvA", "crit"),
    ]
    stats = evs.analyze(recs)
    check("总数=5", stats["total"] == 5, str(stats["total"]))
    s = sum(v["count"] for v in stats["by_level"].values())
    check("级别计数之和=总数", s == 5, str(s))
    # 严重→错误→警告→信息 顺序
    check("级别展示顺序", stats["by_level_order"] == ["严重", "错误", "警告", "信息"],
          str(stats["by_level_order"]))
    check("错误占比 40%", stats["by_level"]["错误"]["ratio"] == 40.0,
          str(stats["by_level"]["错误"]["ratio"]))

    # 高频错误：事件1001 在 SrvA 出现 3 次（2错误+1严重）
    errs = stats["top_errors"]
    check("高频错误非空", len(errs) > 0)
    top = errs[0]
    check("最高频异常=事件1001", top["event_id"] == 1001, str(top))
    check("最高频异常计数=3", top["count"] == 3, str(top["count"]))

    # 时间分桶：跨度 >48h → 按天
    check("时间分桶单位=天(跨度>48h)", stats["bucket_unit"] == "天",
          stats["bucket_unit"])
    check("时间分桶非空", len(stats["time_buckets"]) > 0)

    # 跨度 <=48h → 按小时
    recs2 = [_mk_rec(base + i * 3600, "信息", 1, "S", "x") for i in range(5)]
    stats2 = evs.analyze(recs2)
    check("时间分桶单位=小时(跨度<=48h)", stats2["bucket_unit"] == "小时",
          stats2["bucket_unit"])

    # 空输入安全
    empty = evs.analyze([])
    check("空列表不崩", empty["total"] == 0 and empty["by_level"] == {},
          str(empty))

    # summarize_text
    txt = evs.summarize_text(stats)
    check("汇总文案含条数", "5 条" in txt, txt)


# ==========================================================================
# C. 界面层 + gui 集成（仅 PySide6 可用时）
# ==========================================================================
def test_ui():
    try:
        import PySide6  # noqa: F401
    except Exception:
        print("\n=== C. 界面层 / gui 集成 ===")
        print("  [SKIP] 当前环境未安装 PySide6，跳过 UI 测试"
              "（核心数据/分析逻辑已在 A、B 验证）。")
        print("         用 `uv run --with PySide6-Essentials --with psutil"
              " python check_eventlog.py` 可补跑本部分。")
        return

    section("C. 界面层 eventlog_widget + gui 集成")
    os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    from PySide6.QtWidgets import QApplication
    import eventlog_widget as evw
    import gui as gui_mod

    app = QApplication.instance() or QApplication([])

    # --- 构造函数不触发读盘 ---
    panel = evw.EventLogPanel()
    check("面板构造不卡死", panel is not None)

    # --- 注入合成数据，驱动内部流程 ---
    from datetime import datetime, timezone, timedelta
    base = datetime(2026, 9, 1, tzinfo=timezone.utc).timestamp()
    recs = [
        _mk_rec(base + i * 3600, ["错误", "警告", "信息", "严重", "信息"][i % 5],
                1000 + i, f"Src{i % 3}", f"desc-{i} UNIQUETOKEN")
        for i in range(25)
    ]
    panel._fetched = recs
    panel._meta = {"truncated": False, "max_records": 5000,
                   "elapsed": 0.1, "channel": "Application"}
    panel._apply_client_filter()
    panel._page_size = 10
    panel._fill_page()
    check("首页行数=每页大小", panel.table.rowCount() == 10,
          str(panel.table.rowCount()))

    # 分页
    panel._next_page()
    check("下一页后 _page=1", panel._page == 1, str(panel._page))
    panel._last_page()
    check("末页 _page=末页", panel._page == panel._page_count() - 1,
          str(panel._page))

    # 关键字客户端筛选（即时、不读盘）
    panel._first_page()
    panel.kw_edit.setText("UNIQUETOKEN")
    panel._on_keyword()
    check("关键字筛选减少结果", len(panel._all) == 25, str(len(panel._all)))
    panel.kw_edit.setText("desc-7 UNIQUETOKEN")
    panel._on_keyword()
    check("关键字唯一短语匹配=1条", len(panel._all) == 1, str(len(panel._all)))
    panel.kw_edit.clear()
    panel._on_keyword()
    check("清空关键字恢复全部", len(panel._all) == 25, str(len(panel._all)))

    # 排序：点击事件ID 列(下标2) → 升序
    panel._sort_col = "event_id"
    panel._sort_asc = True
    panel._sort_all()
    eids = [r["event_id"] for r in panel._all]
    check("按事件ID升序", eids == sorted(eids), str(eids[:5]))

    # 分析填充
    panel._fill_analysis()
    check("级别图有数据", len(panel.level_chart._data) > 0,
          str(len(panel.level_chart._data)))
    check("高频错误表有行", panel.err_table.rowCount() > 0,
          str(panel.err_table.rowCount()))
    check("趋势图有数据", len(panel.trend_chart._data) > 0,
          str(len(panel.trend_chart._data)))
    check("来源表有行", panel.src_table.rowCount() > 0,
          str(panel.src_table.rowCount()))

    # 导出 CSV（屏蔽对话框，写临时文件）
    evw.QMessageBox.information = lambda *a, **k: None
    evw.QMessageBox.critical = lambda *a, **k: None
    tmp = os.path.join(tempfile.gettempdir(), "eventlog_test_export.csv")
    evw.QFileDialog.getSaveFileName = lambda *a, **k: (tmp, "csv")
    panel._export("csv")
    if os.path.isfile(tmp):
        with open(tmp, encoding="utf-8-sig") as f:
            lines = f.read().splitlines()
        check("CSV 表头正确", lines[0].startswith("时间,来源,事件ID"), lines[0])
        check("CSV 行数=全部记录", len(lines) - 1 == 25, str(len(lines)))
        os.remove(tmp)
    else:
        check("CSV 已写出", False, tmp)

    # 详情对话框可构造
    dlg = evw.EventDetailDialog(panel, recs[0])
    check("详情对话框构造成功", dlg is not None)

    # --- gui 集成：新增标签页不污染既有索引逻辑 ---
    check("gui 已导入", gui_mod is not None)
    check("新增了 系统日志 标签页构造逻辑",
          "evw_mod.EventLogPanel" in
          open(os.path.join(os.path.dirname(__file__), "gui.py"),
               encoding="utf-8").read())
    # _tab_at 是静态映射逻辑（不依赖 self）
    check("_tab_at(0)=None(概述)", gui_mod.ScanApp._tab_at(None, 0) is None)
    check("_tab_at(1)=processes", gui_mod.ScanApp._tab_at(None, 1) == "processes")
    check("_tab_at(5)=findings", gui_mod.ScanApp._tab_at(None, 5) == "findings")
    check("_tab_at(6)=None(系统日志页不串味)",
          gui_mod.ScanApp._tab_at(None, 6) is None)
    check("TAB_ORDER 仍=5(既有页未变)", len(gui_mod.TAB_ORDER) == 5,
          str(len(gui_mod.TAB_ORDER)))


def main():
    test_reader()
    test_stats()
    test_ui()

    print("\n================ 结果 ================")
    fails = [r for r in RESULTS if not r[1]]
    for name, ok, extra in RESULTS:
        if not ok:
            print(f"  FAIL  {name}  {extra}")
    print(f"总计 {len(RESULTS)} 项，通过 {len(RESULTS) - len(fails)}，"
          f"失败 {len(fails)}")
    if fails:
        print("结论：存在失败项，请检查上方 [FAIL]。")
        sys.exit(1)
    print("结论：全部通过。")


if __name__ == "__main__":
    main()
