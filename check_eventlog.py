# -*- coding: utf-8 -*-
"""系统日志模块回归测试（沿用项目 check_*.py 风格，可离线、可单测）

分层验证：
  A. 数据读取层(eventlog_reader)：build_xpath 构造、parse_event_xml 解析
     —— 纯函数，不依赖 PySide6，用受管 Python 即可跑。
  B. 分析统计层(eventlog_stats)：级别分布/高频错误/时间分桶聚合，
     以及开机/关机/运行时长摘要（boot_summary）—— 同样纯函数。
  C. 界面展示层(eventlog_widget) + gui 集成：仅在 PySide6 可用时跑（offscreen），
     用合成数据驱动面板，验证分页/关键字筛选/排序/分析/导出、详情区布局与
     缩放交互（分隔条 / 收起统计区 / 字号 / 右键菜单），以及新增标签页
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
    # 结构化事件数据：有名 Data 用其 Name，无名 Data 记 参数1..N（保留位置信息，
    # 供上层做非文本判定，例如 6013 的第 5 个字段 = 已运行秒数）
    ed = rec.get("event_data") or {}
    check("解析 event_data(有名+位置)",
          ed.get("param1") == "value1" and ed.get("参数1") == "positional", str(ed))

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
# B2. 开机 / 关机 / 运行时长（纯函数）
# ==========================================================================
def _mk_boot_rec(ts, source, eid, event_data=None, time_str="2026-09-01 00:00:00"):
    r = _mk_rec(ts, "信息", eid, source)
    r["time"] = time_str
    r["event_data"] = event_data or {}
    r["description"] = "参数1 = \n参数2 = \n参数3 = \n参数4 = \n参数5 = 10"
    return r


def test_boot_stats():
    section("B2. 开机/关机/运行时长 eventlog_stats.boot_summary")
    import eventlog_stats as evs
    from datetime import datetime

    base = datetime(2026, 9, 1, 8, 0, 0).timestamp()
    recs = [
        _mk_boot_rec(base, "EventLog", 6005, time_str="2026-09-01 08:00:00"),
        _mk_boot_rec(base + 10, "EventLog", 6013, {"参数5": "10"},
                     time_str="2026-09-01 08:00:10"),
        _mk_boot_rec(base + 86400 * 3, "EventLog", 6013, {"参数5": "259200"},
                     time_str="2026-09-04 08:00:00"),
        _mk_boot_rec(base + 90000, "Microsoft-Windows-Kernel-General", 13,
                     {"StopTime": "2026-09-02T00:00:00Z"},
                     time_str="2026-09-02 09:00:00"),
        _mk_boot_rec(base + 95000, "User32", 1074, time_str="2026-09-02 10:23:20"),
        _mk_rec(base + 96000, "信息", 9999, "SrvX", "普通事件"),
    ]
    s = evs.boot_summary(recs, now=datetime.fromtimestamp(base + 95000))
    check("boot_summary 可用", s["available"], str(s["available"]))
    check("最近开机 = EventLog 6005",
          s["last_boot"] and s["last_boot"]["event_id"] == 6005, str(s["last_boot"]))
    check("最近关机 = Kernel-General 13",
          s["last_shutdown"] and s["last_shutdown"]["event_id"] == 13,
          str(s["last_shutdown"]))
    check("关机晚于开机 → running=False", s["running"] is False, str(s["running"]))
    check("自报运行时长取最新的 6013", s["uptime_seconds"] == 259200,
          str(s["uptime_seconds"]))
    check("关机/重启请求单独归类", len(s["requests"]) == 1, str(len(s["requests"])))
    check("普通事件不算开机类", evs.boot_event_kind(recs[-1]) is None,
          str(evs.boot_event_kind(recs[-1])))
    check("摘要含「最近开机」", "最近开机" in s["summary"], s["summary"])

    # 只有开机、没有关机 → 正在运行，并推断出「本次已运行」
    s2 = evs.boot_summary(recs[:2], now=datetime.fromtimestamp(base + 3600))
    check("仅开机 → running=True", s2["running"] is True, str(s2["running"]))
    check("推断本次已运行=3600s", s2["current_uptime_seconds"] == 3600,
          str(s2["current_uptime_seconds"]))

    check("空输入安全", evs.boot_summary([])["available"] is False)
    check("fmt_duration(3天4小时)",
          evs.fmt_duration(86400 * 3 + 14400) == "3 天 4 小时",
          evs.fmt_duration(86400 * 3 + 14400))
    check("fmt_duration 非法输入→空串", evs.fmt_duration("abc") == "",
          evs.fmt_duration("abc"))
    check("parse_uptime_seconds 非 6013 → None",
          evs.parse_uptime_seconds(recs[0]) is None)
    check("parse_uptime_seconds 非数字 → None",
          evs.parse_uptime_seconds(_mk_boot_rec(base, "EventLog", 6013,
                                                {"参数5": "x"})) is None)
    check("boot_kind_text(6013) 是可读人话",
          "已运行 259200 秒" in evs.boot_kind_text(recs[2]),
          evs.boot_kind_text(recs[2]))
    check("boot_kind_text(普通事件)=空串", evs.boot_kind_text(recs[-1]) == "",
          evs.boot_kind_text(recs[-1]))
    check("快捷筛选清单不缺 6013/12",
          6013 in evs.BOOT_FILTER_EVENT_IDS and 12 in evs.BOOT_FILTER_EVENT_IDS,
          str(evs.BOOT_FILTER_EVENT_IDS))


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
    # offscreen 下也要给面板真实尺寸，几何/分隔条相关断言才有意义；
    # 先置 _loaded_once，避免 show() 触发 showEvent 里的「首次自动读盘」
    panel._loaded_once = True
    panel.resize(1100, 760)
    panel.show()
    app.processEvents()

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

    # ================= 详情区布局与交互（本次优化重点）=================
    from PySide6.QtCore import Qt as Q, QPoint
    evw.QMessageBox.warning = lambda *a, **k: None

    panel._apply_client_filter()
    panel._page = 0
    panel._fill_page()
    app.processEvents()

    sp = panel.split
    check("分隔条加宽可抓(9px)", sp.handleWidth() == 9, str(sp.handleWidth()))
    check("分隔条禁止把某侧拖成 0", sp.childrenCollapsible() is False,
          str(sp.childrenCollapsible()))
    sizes = sp.sizes()
    check("初始比例偏向日志列表", len(sizes) == 2 and sizes[0] > sizes[1], str(sizes))
    check("列表有最小高度(不会被压成两行)",
          panel.table.minimumHeight() == evw.LIST_MIN_H,
          str(panel.table.minimumHeight()))

    # 收起 / 展开统计区（把高度让给日志列表）
    panel.analysis.setVisible(True)
    panel._toggle_analysis()
    check("收起统计区 → 分析区隐藏", not panel.analysis.isVisible())
    check("收起后按钮文案=展开统计区",
          panel.btn_analysis_toggle.text() == "展开统计区",
          panel.btn_analysis_toggle.text())
    panel._toggle_analysis()
    check("再次点击 → 分析区显示", panel.analysis.isVisible())
    check("展开后按钮文案复原", panel.btn_analysis_toggle.text() == "收起统计区",
          panel.btn_analysis_toggle.text())

    # 列表字号缩放（A- / A+）
    pt0 = panel.table.font().pointSize()
    panel._zoom_list(+1)
    pt1 = panel.table.font().pointSize()
    check("A+ 放大列表字号", pt1 > pt0, f"{pt0} -> {pt1}")
    panel._zoom_list(-1)
    check("A- 复原字号", panel.table.font().pointSize() == pt0,
          str(panel.table.font().pointSize()))
    for _ in range(20):
        panel._zoom_list(-1)                 # 触到档位边界不应异常/越界
    check("字号有下限保护", panel.table.font().pointSize() >= 6,
          str(panel.table.font().pointSize()))

    # 右键菜单：此前只设了 ContextMenuPolicy 却没有接处理函数（死代码）
    class _FakeMenu:
        def __init__(self, *a, **k):
            pass

        def addAction(self, *a, **k):
            return object()

        def exec(self, *a, **k):
            return None

    real_menu = evw.QMenu
    evw.QMenu = _FakeMenu
    try:
        y = panel.table.rowViewportPosition(1) + 2
        row_hit = panel.table.rowAt(y)
        check("表格行命中测试可用", row_hit >= 0, str(row_hit))
        panel.table.clearSelection()
        panel.table.customContextMenuRequested.emit(QPoint(5, y))
        check("右键菜单已接上处理函数（命中行被选中）",
              panel.table.currentRow() == row_hit, str(panel.table.currentRow()))
    finally:
        evw.QMenu = real_menu

    rec0 = panel._rec_of_row(0)
    check("_rec_of_row 取回整条记录",
          isinstance(rec0, dict) and "source" in rec0, str(type(rec0)))
    panel._copy_text("剪贴板测试")
    check("复制到剪贴板可用", QApplication.clipboard().text() == "剪贴板测试",
          QApplication.clipboard().text())

    # 详情对话框：可放大 + 三块可拖拽 + 字号缩放
    boot_rec = _mk_boot_rec(base, "EventLog", 6013, {"参数5": "7586"},
                            time_str="2026-09-01 08:00:10")
    dlg = evw.EventDetailDialog(panel, boot_rec)
    check("详情对话框构造成功", dlg is not None)
    check("详情对话框可最大化",
          bool(dlg.windowFlags() & Q.WindowType.WindowMaximizeButtonHint),
          str(dlg.windowFlags()))
    check("详情对话框带拉伸手柄", dlg.isSizeGripEnabled(),
          str(dlg.isSizeGripEnabled()))
    dsp = dlg.findChild(evw.QSplitter)
    check("详情内三块由分隔条分隔",
          dsp is not None and dsp.count() == 3, str(dsp.count() if dsp else None))
    check("详情分隔条同样禁止拖成 0",
          dsp is not None and dsp.childrenCollapsible() is False)
    check("描述不再被限高（原来 max 140px）", dlg.desc.maximumHeight() >= 10000,
          str(dlg.desc.maximumHeight()))
    check("开机事件详情里有「事件含义」行",
          any(dlg.fields.item(r, 0) and dlg.fields.item(r, 0).text() == "事件含义"
              for r in range(dlg.fields.rowCount())))
    pt_b = dlg.desc.font().pointSize()
    dlg._zoom(+1)
    check("详情 A+ 放大正文字号", dlg.desc.font().pointSize() > pt_b,
          f"{pt_b} -> {dlg.desc.font().pointSize()}")
    dlg._zoom(-1)
    check("详情 A- 复原字号", dlg.desc.font().pointSize() == pt_b,
          str(dlg.desc.font().pointSize()))
    dlg.resize(880, 600)
    dlg.done(0)
    check("详情窗口尺寸被记住", evw.EventDetailDialog._last_size is not None,
          str(evw.EventDetailDialog._last_size))
    dlg2 = evw.EventDetailDialog(panel, boot_rec)
    check("下次打开沿用记忆尺寸", dlg2.size().width() == 880, str(dlg2.size()))

    # ================= 「开机与运行」：列表可读前缀 + 摘要条 + 一键预设 =========
    boot_6005 = _mk_boot_rec(base, "EventLog", 6005, time_str="2026-09-01 08:00:00")
    panel._fetched = [boot_rec, boot_6005]
    panel._meta = {"truncated": False, "max_records": 5000, "elapsed": 0.1,
                   "channel": "System"}
    panel._apply_client_filter()
    panel._page = 0
    panel._fill_page()
    # 不依赖排序顺序（此前的排序测试把排序留在了「事件ID 升序」），扫描整页
    cells = [(panel.table.item(r, 4).text() if panel.table.item(r, 4) else "")
             for r in range(panel.table.rowCount())]
    check("开机类记录在列表中带可读前缀（6013→已运行）",
          any("【系统已运行 7586 秒" in c for c in cells), str(cells))
    check("开机类记录在列表中带可读前缀（6005→开机）",
          any("【开机" in c for c in cells), str(cells))
    panel._update_boot_line()
    check("开机摘要条显示且有内容",
          panel.boot_lbl.isVisible() and "最近开机" in panel.boot_lbl.text()
          and "已运行" in panel.boot_lbl.text(), panel.boot_lbl.text())

    panel._fetched = recs                    # 换回普通日志 → 摘要条应自动隐藏
    panel._apply_client_filter()
    panel._page = 0
    panel._fill_page()
    panel._update_boot_line()
    check("普通日志不显示开机摘要条", not panel.boot_lbl.isVisible(),
          panel.boot_lbl.text())

    calls = []                               # 预设按钮：只验证筛选条件，不真读盘
    real_run = panel.run_query
    panel.run_query = lambda: calls.append(1)
    try:
        panel._preset_boot()
    finally:
        panel.run_query = real_run
    check("预设切到 System 通道", panel.channel_cb.currentText() == "System",
          panel.channel_cb.currentText())
    check("预设填入开机相关来源",
          "EventLog" in panel.src_edit.text()
          and "Kernel-General" in panel.src_edit.text(), panel.src_edit.text())
    check("预设填入 6013/6005 等事件ID",
          "6013" in panel.eid_edit.text() and "6005" in panel.eid_edit.text(),
          panel.eid_edit.text())
    check("预设时间范围=近30天", panel.time_cb.currentText() == "近30天",
          panel.time_cb.currentText())
    check("预设不勾掉任何级别（开机日志多为「信息」）",
          all(cb.isChecked() for cb in panel.level_boxes.values()))
    check("预设触发了一次查询", len(calls) == 1, str(len(calls)))

    # ================= 筛选变更 → 自动刷新（防抖 + 排队）=================
    import time as _time
    import eventlog_reader as evr

    calls2: list[int] = []
    real_run2 = panel.run_query
    panel.run_query = lambda: calls2.append(1)

    def _pump(seconds: float):
        """在 offscreen 下推进事件循环：定时器靠 processEvents 派发。"""
        end = _time.time() + seconds
        while _time.time() < end:
            app.processEvents()
            _time.sleep(0.02)

    def _wait_calls(expect: int, timeout: float = 4.0) -> bool:
        end = _time.time() + timeout
        while _time.time() < end:
            app.processEvents()
            if len(calls2) >= expect:
                return True
            _time.sleep(0.02)
        return False

    def _pick_other_channel() -> str:
        cur = panel.channel_cb.currentText()
        return next(c for c in evr.DEFAULT_CHANNELS if c != cur)

    try:
        check("默认开启自动刷新", panel.auto_cb.isChecked() and panel._auto_refresh)

        # 改「通道」→ 短防抖后自动查询
        panel._auto_timer.stop()
        calls2.clear()
        panel.channel_cb.setCurrentText(_pick_other_channel())
        check("改通道即启动防抖定时器", panel._auto_timer.isActive())
        check("离散控件防抖延时=350ms",
              panel._auto_timer.interval() == evw.AUTO_DEBOUNCE_PICK_MS,
              str(panel._auto_timer.interval()))
        check("防抖到点自动发起查询", _wait_calls(1) and len(calls2) == 1,
              str(len(calls2)))
        check("自动发起的查询被标记(_auto_triggered)", panel._auto_triggered)
        panel._auto_triggered = False

        # 连续变更（通道 + 级别 + 时间）应被合并成「一次」查询
        panel._auto_timer.stop()
        calls2.clear()
        panel.channel_cb.setCurrentText(_pick_other_channel())
        panel.level_boxes["信息"].setChecked(False)
        panel.level_boxes["信息"].setChecked(True)
        panel.time_cb.setCurrentText("近7天")
        _wait_calls(1)
        _pump(0.8)                                  # 超过防抖窗口再看有没有第二次
        check("连续变更被合并为一次查询", len(calls2) == 1, str(len(calls2)))

        # 「全选 / 清空」按钮点一下 = 5 个复选框连发，也只能算一次
        panel._auto_timer.stop()
        calls2.clear()
        panel.btn_level_none.click()
        panel.btn_level_all.click()
        _wait_calls(1)
        _pump(0.8)
        check("级别全选/清空只触发一次查询", len(calls2) == 1, str(len(calls2)))

        # 文本类筛选（事件ID/来源）用更长的防抖，把连续输入合并掉
        panel._auto_timer.stop()
        calls2.clear()
        panel.eid_edit.setText("6")
        check("文本筛选防抖延时更长=900ms",
              panel._auto_timer.interval() == evw.AUTO_DEBOUNCE_TYPE_MS,
              str(panel._auto_timer.interval()))
        panel.eid_edit.setText("60")
        panel.eid_edit.setText("6005")               # 逐字符输入只应查最后一次
        _wait_calls(1)
        _pump(1.0)
        check("逐字符输入合并为一次查询", len(calls2) == 1, str(len(calls2)))
        panel.eid_edit.clear()

        # 读盘途中改筛选 → 记 pending，读完立即按最新条件补一次（不丢用户操作）
        panel._auto_timer.stop()
        calls2.clear()
        panel._loading = True
        panel._pending_auto = False
        panel._auto_query()                          # 定时器到点但正在读盘
        check("读盘途中改筛选进排队(_pending_auto)",
              panel._pending_auto is True and not calls2, str(len(calls2)))
        panel._loading = False
        panel._resume_pending_auto()
        check("读完补查(pending 清空 + 定时器重启)",
              panel._pending_auto is False and panel._auto_timer.isActive())
        check("补查真的执行了", _wait_calls(1) and len(calls2) == 1, str(len(calls2)))

        # 自动刷新完成后的状态栏提示（含 ⟳ 前缀，让用户知道不是自己点的）
        panel._auto_timer.stop()
        panel._pending_auto = False
        panel._auto_triggered = True
        panel._on_finished([], {"truncated": False, "max_records": 5000,
                                "elapsed": 0.1, "channel": panel.channel_cb.currentText()})
        check("自动刷新后状态栏带 ⟳ 提示",
              "⟳ 已按新筛选条件自动刷新" in panel.status.text(), panel.status.text())
        check("提示用完即清标记", panel._auto_triggered is False)

        # 关掉开关 → 回到手动，改筛选不再读盘
        panel._auto_timer.stop()
        calls2.clear()
        panel.auto_cb.setChecked(False)
        check("关闭自动刷新后开关状态生效", panel._auto_refresh is False)
        check("关闭时状态栏有手动提示", "已关闭自动刷新" in panel.status.text(),
              panel.status.text())
        n_before = len(calls2)
        panel.channel_cb.setCurrentText(_pick_other_channel())
        panel.time_cb.setCurrentText("近1小时")
        _pump(0.8)
        check("关闭后改筛选不自动查询",
              len(calls2) == n_before and not panel._auto_timer.isActive(),
              str(len(calls2)))

        # 重新打开 → 立刻按当前筛选条件对齐一次
        n_before = len(calls2)
        panel.auto_cb.setChecked(True)
        check("重新开启立即对齐一次查询", _wait_calls(n_before + 1), str(len(calls2)))

        # 关键字仍然「输入即时、不读盘」
        panel._auto_timer.stop()
        calls2.clear()
        panel.kw_edit.setText("UNIQUETOKEN")
        _pump(1.0)
        check("关键字即时过滤不触发读盘", len(calls2) == 0, str(len(calls2)))
        panel.kw_edit.clear()

        # 程序化回填（重置筛选 / 开机预设）只查一次，不是「填 5 个字段查 5 次」
        panel._auto_timer.stop()
        calls2.clear()
        panel._reset_filters()
        _pump(0.8)
        check("重置筛选只触发一次查询", len(calls2) == 1, str(len(calls2)))
    finally:
        panel.run_query = real_run2
        panel._auto_timer.stop()
        panel._pending_auto = False

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
    test_boot_stats()
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
