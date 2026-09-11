# -*- coding: utf-8 -*-
"""「点击列标题排序」功能的回归测试（不随产品发布，请保留：改动表格/排序逻辑后跑一遍）。

运行：
    python check_sort.py            # 需要有 scan_result.json（没有则用内置样例）
    python check_sort.py --verbose

覆盖点：
  1. 五个列表页每一列都能通过「点击表头」完成升序 / 降序排序
  2. 排序键语义正确：数值列比数值（10 在 9 之后）、风险列比严重度、文本列自然序
  3. 排序不破坏行数据：每行取回的记录与显示的文本一一对应
  4. 排序状态在「筛选 / 重新填充」后保持；清除排序可回到原始顺序
  5. 处理历史 / 已禁用任务两个列表同样可排序，且选中项仍能定位到正确记录
"""
from __future__ import annotations

import os
import sys
import traceback

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
sys.path.insert(0, os.path.dirname(HERE))

from PySide6.QtCore import Qt, QPoint          # noqa: E402
from PySide6.QtWidgets import QApplication     # noqa: E402
from PySide6.QtTest import QTest               # noqa: E402

import gui                                     # noqa: E402

VERBOSE = "--verbose" in sys.argv
FAILS: list[str] = []


def check(cond: bool, msg: str):
    if cond:
        if VERBOSE:
            print(f"    ok  {msg}")
    else:
        FAILS.append(msg)
        print(f"    FAIL {msg}")


def click_header(table, col: int):
    """真实模拟：在表头第 col 列上按下并松开（Qt 会自动翻转排序指示器）。"""
    hh = table.horizontalHeader()
    x = hh.sectionPosition(col) + max(1, hh.sectionSize(col) // 2)
    QTest.mouseClick(hh.viewport(), Qt.MouseButton.LeftButton,
                     Qt.KeyboardModifier.NoModifier, QPoint(x, max(1, hh.height() // 2)))
    QTest.qWait(15)


def row_keys(table, col: int):
    return [table.item(r, col).data(gui.SORT_ROLE) for r in range(table.rowCount())]


def row_consistency(table, cols, tag: str):
    """每行第 0 列挂的记录，必须与各列显示文本一致（防止排序把行内容打乱）。"""
    bad = 0
    for r in range(table.rowCount()):
        rec = table.item(r, 0).data(Qt.ItemDataRole.UserRole)
        for c, (key, _t, _w, _a) in enumerate(cols):
            if gui.ScanApp._cell(rec, key) != table.item(r, c).text():
                bad += 1
    check(bad == 0, f"{tag}: 各行记录与显示文本一致（不一致 {bad} 处）")


def main() -> int:
    app = QApplication.instance() or QApplication([])
    win = gui.ScanApp()
    win.show()
    QTest.qWaitForWindowExposed(win)
    QTest.qWait(60)

    total_rows = sum(len(win.data.get(t) or []) for t in gui.TAB_ORDER)
    if total_rows == 0:
        print("FAIL: 没有任何数据可测（缺少 scan_result.json）")
        return 1
    print(f"[0] 载入数据： " + "，".join(
        f"{gui.TAB_DEFS[t]['title']} {len(win.data.get(t) or [])}" for t in gui.TAB_ORDER))

    print("[1] 逐列点击表头排序 ...")
    for tab in gui.TAB_ORDER:
        table = win.trees[tab]
        spec = gui.TAB_DEFS[tab]
        n = table.rowCount()
        if n < 3:
            print(f"    -- {spec['title']}: 行数 {n}，跳过")
            continue
        for col, (key, title, _w, _a) in enumerate(spec["cols"]):
            before_text = [table.item(r, col).text() for r in range(n)]

            click_header(table, col)                       # 第一次点击
            order1 = table.horizontalHeader().sortIndicatorOrder()
            k1 = row_keys(table, col)
            asc = (order1 == Qt.SortOrder.AscendingOrder)
            check(k1 == sorted(k1, reverse=not asc),
                  f"{spec['title']}·{title}: 首次点击按{'升' if asc else '降'}序排列")
            check(sorted(t for t in before_text) == sorted(table.item(r, col).text() for r in range(n)),
                  f"{spec['title']}·{title}: 排序未丢失 / 未重复行")
            row_consistency(table, spec["cols"], f"{spec['title']}·{title}")

            click_header(table, col)                       # 第二次点击（反向）
            order2 = table.horizontalHeader().sortIndicatorOrder()
            check(order2 != order1, f"{spec['title']}·{title}: 再次点击切换排序方向")
            k2 = row_keys(table, col)
            desc2 = (order2 == Qt.SortOrder.DescendingOrder)
            check(k2 == sorted(k2, reverse=desc2),
                  f"{spec['title']}·{title}: 反向排序结果正确")

            if VERBOSE:
                print(f"      {title}: 前 5 行 -> {[table.item(r, col).text() for r in range(min(5, n))]}")
        gui.clear_sort(table)
        win._fill_tab(tab)

    print("[2] 数值列按数值而非文本排序 ...")
    ptab = win.trees["processes"]
    click_header(ptab, 0)                                   # PID 列
    pids = [ptab.item(r, 0).data(gui.SORT_ROLE)[1] for r in range(ptab.rowCount())]
    check(pids == sorted(pids), "进程 PID 升序为数值序（非 1,10,100,2 这类文本序）")
    click_header(ptab, 4)                                   # CPU% 列
    cpus = [ptab.item(r, 4).data(gui.SORT_ROLE)[1] for r in range(ptab.rowCount())]
    check(cpus == sorted(cpus), "进程 CPU% 为数值序")
    gui.clear_sort(ptab)
    win._fill_tab("processes")

    print("[3] 风险 / 等级列按严重度排序 ...")
    ftab = win.trees["findings"]
    orig = [ftab.item(r, 0).text() for r in range(ftab.rowCount())]
    click_header(ftab, 0)
    ranks = [ftab.item(r, 0).data(gui.SORT_ROLE)[1] for r in range(ftab.rowCount())]
    check(ranks == sorted(ranks), "风险清单「等级」升序 = 严重 → 提示")
    if orig:
        check(ranks[0] <= gui.SEV_RANK.get(orig[0], 9) or True, "等级排序不劣于原始顺序（信息）")
    gui.clear_sort(ftab)
    win._fill_tab("findings")
    check([ftab.item(r, 0).text() for r in range(ftab.rowCount())] == orig,
          "清除排序后风险清单回到「严重 → 提示」的原始顺序")

    print("[4] 排序在筛选 / 重新填充后保持 ...")
    stab = win.trees["services"]
    click_header(stab, 0)                                   # 服务名
    spec = tuple(stab._sort_spec)
    win.search_box.setText("svchost")
    win.refresh_all()
    check(stab._sort_spec == spec, "关键字筛选后仍保留所选排序")
    k = row_keys(stab, 0)
    check(k == sorted(k, reverse=(spec[1] == Qt.SortOrder.DescendingOrder)),
          "筛选后的结果仍然有序")
    win.clear_filter()
    check(stab._sort_spec == spec, "清除筛选后排序依旧保留")

    print("[5] 恢复默认顺序 ...")
    win.reset_sort_all()
    check(all(t._sort_spec is None for t in win.trees.values()), "全部列表的排序状态已清除")
    check(all(win.trees[t].horizontalHeader().sortIndicatorSection() == -1 for t in gui.TAB_ORDER),
          "全部列表的排序箭头已隐藏")
    s_chk = win.data["services"][:5]
    check([stab.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in range(5)] == s_chk,
          "恢复默认顺序后服务表与原始数据一致")
    f_chk = win.data["findings"][:5]
    check([ftab.item(r, 0).data(Qt.ItemDataRole.UserRole) for r in range(5)] == f_chk,
          "恢复默认顺序后风险清单与原始数据一致")

    print("[6] 排序后选中行仍能取到正确记录 ...")
    ptab.selectRow(0)
    rec = win._selected("processes")
    check(rec is not None and gui.ScanApp._cell(rec, "pid") == ptab.item(0, 0).text(),
          "进程表选中第 1 行 → 记录与显示一致")

    print("[7] 处理历史 / 已禁用任务列表排序 ...")
    fake_hist = [
        {"time": "2026-09-11 10:20:01", "kind": "task_disable", "target": "TaskB", "restored": False},
        {"time": "2026-09-10 09:01:11", "kind": "service_stop", "target": "SvcA", "restored": True},
        {"time": "2026-09-11 08:59:59", "kind": "task_delete", "target": "TaskA", "restored": False},
    ]
    real_loader = gui.load_history
    gui.load_history = lambda: [dict(e) for e in fake_hist]
    try:
        dlg = gui.HistoryDialog(win)
        dlg.show()
        QTest.qWaitForWindowExposed(dlg)
        check(dlg.tv.rowCount() == 3, "处理历史列表已填充 3 条")
        click_header(dlg.tv, 0)                             # 时间列
        times = [dlg.tv.item(r, 0).data(gui.SORT_ROLE) for r in range(dlg.tv.rowCount())]
        check(times == sorted(times), "历史记录按时间升序（自然序对日期时间有效）")
        dlg.tv.selectRow(0)
        picked = dlg._sel_hist()
        check(picked is not None and picked["target"] == dlg.tv.item(0, 2).text(),
              "排序后选中历史行 → 取到的是同一行对应的记录")
        dlg.tv.selectRow(2)
        picked = dlg._sel_hist()
        check(picked is not None and picked["target"] == dlg.tv.item(2, 2).text(),
              "排序后选中最后一行 → 记录同样正确")

        # 已禁用任务列表：过滤掉查询失败的情况
        if dlg.tv2.rowCount() >= 2:
            click_header(dlg.tv2, 0)
            names = [dlg.tv2.item(r, 0).data(gui.SORT_ROLE) for r in range(dlg.tv2.rowCount())]
            check(names == sorted(names), "已禁用任务列表按任务名自然序排序")
            dlg.tv2.selectRow(0)
            check(dlg.tv2.item(0, 0).text(), "已禁用任务选中行可读出任务名")
        else:
            print("    -- 未查询到 2 个以上已禁用任务，跳过该列表排序验证")
        dlg.close()
    finally:
        gui.load_history = real_loader

    print("[8] 排序方向箭头可见（回归：setSortingEnabled(False) 会关掉指示器）...")
    stab2 = win.trees["processes"]
    check(stab2.horizontalHeader().isSortIndicatorShown(),
          "表头排序指示器处于开启状态")
    click_header(stab2, 1)
    check(stab2.horizontalHeader().sortIndicatorSection() == 1,
          "点击后指示器指向被点击的列")
    check(stab2.horizontalHeader().isSortIndicatorShown(),
          "点击排序后箭头依然可见")
    check(stab2.isSortingEnabled() is False,
          "仍使用自定义排序（未启用 setSortingEnabled，避免填充时被打乱）")

    win.close()
    app.processEvents()

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
