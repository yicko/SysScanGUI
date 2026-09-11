# -*- coding: utf-8 -*-
"""「自动刷新（分层轻刷新）」功能的回归测试（不随产品发布，请保留）。

运行：
    python check_refresh.py            # 需要有 scan_result.json

覆盖点：
  1. 概览指标：live_lbl 有内容、定时器在跑，且不修改任何表格数据
  2. _fill_tab 的选中行 / 滚动位置保持（自动刷新和重扫共用的保底行为）
  3. 连接轻刷新：端到端采集 → 风险规则 → 合并（note / 手动风险标记保留，
     新连接出现、旧连接消失）、状态栏反馈、_conn_busy 复位
  4. 单飞守卫：scanning / _conn_busy / _ui_busy 时定时回调不启动新任务
  5. 操作后核实：kill（进程已退出→行被移除）、服务、计划任务禁用状态、
     启动项、启动文件夹文件的核实路径，全部只改状态栏与受影响行、不弹窗
  6. 退出时定时器停止
"""
from __future__ import annotations

import os
import sys
import traceback

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from PySide6.QtCore import Qt, QTimer          # noqa: E402
from PySide6.QtWidgets import QApplication     # noqa: E402
from PySide6.QtTest import QTest               # noqa: E402

import gui                                     # noqa: E402
import psutil                                  # noqa: E402

FAILS: list[str] = []


def check(cond: bool, msg: str):
    if not cond:
        FAILS.append(msg)
        print(f"    FAIL {msg}")
    else:
        print(f"    ok  {msg}")


def main() -> int:
    app = QApplication.instance() or QApplication([])
    win = gui.ScanApp()
    win.show()
    QTest.qWaitForWindowExposed(win)
    QTest.qWait(80)

    print("[1] 概览指标 ...")
    check(win._metric_timer.isActive() and
          win._metric_timer.interval() == gui.METRIC_INTERVAL_MS,
          f"指标定时器在跑（{gui.METRIC_INTERVAL_MS}ms）")
    check("CPU" in win.live_lbl.text() and "内存" in win.live_lbl.text(),
          f"状态栏实时指标已渲染：{win.live_lbl.text()!r}")
    n_procs = len(win.data.get("processes", []))
    win._refresh_metrics()
    check(len(win.data.get("processes", [])) == n_procs, "指标刷新不修改表格数据")

    print("[2] _fill_tab 选中行 / 滚动位置保持 ...")
    ptab = win.trees["processes"]
    target_row = min(5, ptab.rowCount() - 1)
    ptab.selectRow(target_row)
    rec0 = ptab.item(target_row, 0).data(Qt.ItemDataRole.UserRole)
    ptab.verticalScrollBar().setValue(120)
    win.refresh_all()
    rows = ptab.selectionModel().selectedRows()
    check(bool(rows), "重填后仍有选中行")
    if rows:
        rec1 = ptab.item(rows[0].row(), 0).data(Qt.ItemDataRole.UserRole)
        check(gui.id_key_of("processes", rec1) == gui.id_key_of("processes", rec0),
              f"同一记录仍被选中（{rec1.get('name')}）")
    check(ptab.verticalScrollBar().value() == 120, "滚动位置保持")

    print("[3] 连接轻刷新端到端 ...")
    old_n = len(win.data.get("connections", []))
    old_note_rec = None
    if old_n:
        old_note_rec = dict(win.data["connections"][0])
        old_note_rec["note"] = "测试备注-勿删"
        win.data["connections"][0] = old_note_rec
    win.conn_refresh_cb.setChecked(True)          # 开关：启动定时器 + 立即刷一次
    check(win._conn_timer.isActive() and
          win._conn_timer.interval() == gui.CONN_REFRESH_MS, "连接刷新定时器已启动")
    deadline = 15000
    while (win._conn_busy or "已自动刷新" not in win.status.text()) and deadline > 0:
        QTest.qWait(100)
        deadline -= 100
    # 必须等到成功路径的状态反馈，防止"数据没更新但条数恰好相同"的假通过
    check("网络连接已自动刷新" in win.status.text(),
          f"走到成功路径的状态反馈：{win.status.text()!r}")
    check(not win._conn_busy, "后台采集完成且 _conn_busy 复位")
    QTest.qWait(150)                              # 等 _poll_queue 处理完
    conns = win.data.get("connections", [])
    check(len(conns) > 0, f"连接数据已更新（{len(conns)} 条）")
    check(all("risk" in c and "reasons" in c for c in conns[:50]),
          "新数据已应用风险规则（risk/reasons 字段齐全）")
    check(all("_manual_risk" not in c or c.get("_manual_risk") is True
              for c in conns), "字段无异常")
    if old_note_rec is not None:
        key = (old_note_rec.get("proto"), old_note_rec.get("laddr"),
               old_note_rec.get("raddr"), old_note_rec.get("pid"))
        merged = next((c for c in conns
                       if (c.get("proto"), c.get("laddr"), c.get("raddr"), c.get("pid")) == key),
                      None)
        if merged:
            check(merged.get("note") == "测试备注-勿删", "同键连接的人工备注在刷新后保留")
        else:
            print("    -- 该连接已消失（正常现象），备注保留逻辑由 [3b] 覆盖")
    print("[3b] 合并逻辑单测 ...")
    win.data["connections"] = [
        {"proto": "TCP", "laddr": "127.0.0.1:1000", "raddr": "127.0.0.1:80",
         "status": "ESTABLISHED", "pid": 4242, "note": "保留我", "risk": "高危",
         "_manual_risk": True, "reasons": []},
        {"proto": "TCP", "laddr": "127.0.0.1:2000", "raddr": "", "status": "LISTEN",
         "pid": 4243, "reasons": [], "risk": "正常"},
    ]
    fresh = [
        {"proto": "TCP", "laddr": "127.0.0.1:1000", "raddr": "127.0.0.1:80",
         "status": "ESTABLISHED", "pid": 4242, "reasons": [], "risk": "正常"},
        {"proto": "TCP", "laddr": "127.0.0.1:3000", "raddr": "", "status": "LISTEN",
         "pid": 4244, "reasons": [], "risk": "正常"},
    ]
    win._merge_connections(fresh)
    by_laddr = {c["laddr"]: c for c in win.data["connections"]}
    check(len(win.data["connections"]) == 2, "消失的连接被移除、新连接加入")
    check(by_laddr["127.0.0.1:1000"].get("note") == "保留我", "人工备注保留")
    check(by_laddr["127.0.0.1:1000"].get("risk") == "高危" and
          by_laddr["127.0.0.1:1000"].get("_manual_risk") is True, "手动风险标记保留")
    check("127.0.0.1:2000" not in by_laddr, "未标记的旧连接正常被新数据替换")
    win.conn_refresh_cb.setChecked(False)
    check(not win._conn_timer.isActive(), "关闭开关后定时器停止")

    print("[4] 单飞守卫 ...")
    win.scanning = True
    win._auto_refresh_connections()
    check(win._conn_busy is False, "扫描进行中：定时回调不启动新任务")
    win.scanning = False
    win._conn_busy = True
    win._auto_refresh_connections()
    check(win._conn_busy is True, "上一次刷新未完成：不重入")
    win._conn_busy = False

    print("[5] 操作后核实 ...")
    # 5a kill：进程不存在 → 状态栏"已退出"，列表同步移除
    ghost = {"pid": 999999, "name": "ghost_proc_test.exe", "exe": "", "risk": "正常"}
    win.data["processes"].append(ghost)
    win._fill_tab("processes")
    win._verify_op({"kind": "kill", "pid": 999999, "name": "ghost_proc_test.exe"})
    QTest.qWait(50)
    check(all(p.get("name") != "ghost_proc_test.exe" for p in win.data["processes"]),
          "已退出进程从列表同步移除")
    check("已退出" in win.status.text(), f"状态栏核实反馈：{win.status.text()!r}")
    # 5b 服务：不存在的服务 → 只提示不崩溃
    win._verify_op({"kind": "service", "name": "__no_such_svc__", "op": "stop"})
    check("未能核实" in win.status.text(), "服务核实失败路径安全")
    # 5c 计划任务：不存在的任务 → 查询失败提示
    win._verify_op({"kind": "task_disable", "name": "__no_such_task__"})
    check("核实" in win.status.text(), "计划任务核实失败路径安全")
    # 5d 启动项：注册表值不存在 → 行被移除
    fake_runkey = {"type": "启动项", "name": "HKLM\\Run :: __zzz_test__",
                   "source": "HKLM\\Run\\__zzz_test__", "command": "x", "risk": "正常"}
    win.data["persistence"].append(fake_runkey)
    win._fill_tab("persistence")
    win._verify_op({"kind": "runkey", "source": "HKLM\\Run\\__zzz_test__"})
    QTest.qWait(50)
    check(all(it.get("source") != "HKLM\\Run\\__zzz_test__"
              for it in win.data["persistence"]), "已删除的启动项从列表移除")
    check("已从注册表移除" in win.status.text(), "启动项核实反馈正确")
    # 5e 启动文件夹文件：文件不存在 → 行被移除
    fake_file = {"type": "启动项", "name": "启动文件夹 :: __zzz_test__.lnk",
                 "source": "C:\\__zzz_no_such__.lnk", "command": "C:\\__zzz_no_such__.lnk",
                 "risk": "正常"}
    win.data["persistence"].append(fake_file)
    win._verify_op({"kind": "startupfile", "source": "C:\\__zzz_no_such__.lnk"})
    check(all(it.get("source") != "C:\\__zzz_no_such__.lnk"
              for it in win.data["persistence"]), "已移除的启动文件从列表移除")
    # 5f 服务禁用核实：注册表不存在的服务 → 走异常路径，不崩溃
    win._verify_op({"kind": "service_disable", "name": "__no_such_svc__"})
    check("核实" in win.status.text() or "未能核实" in win.status.text(),
          "服务禁用核实失败路径安全")
    # 5g 核实不弹窗：_verify_op 期间不应存在模态对话框
    check(QApplication.activeModalWidget() is None, "核实过程纯状态栏反馈，无弹窗")

    print("[6] 退出时停止定时器 ...")
    win.conn_refresh_cb.setChecked(True)
    win.close()
    app.processEvents()
    check(not win._metric_timer.isActive() and not win._conn_timer.isActive(),
          "closeEvent 已停止全部自动刷新定时器")

    print()
    if FAILS:
        print(f"CHECKS_FAILED: {len(FAILS)} 项未通过")
        for f in FAILS:
            print("  -", f)
        return 1
    print("ALL_CHECKS_PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
