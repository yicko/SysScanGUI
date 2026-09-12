# -*- coding: utf-8 -*-
"""用户可见文案回归测试：python check_ui_text.py

改动「关于」弹窗、菜单或 README 的操作指引后跑一遍。
覆盖三类容易悄悄失效的文案问题：

  1. 弹窗接线：「帮助 → 关于」能取到、触发后不弹真窗也不卡死，正文只有一个副本
     （`gui.about_text()`）
  2. 文案自洽：「关于」里引用的菜单名、以及 **README 里每一处「菜单 X → Y」「工具栏 Z」
     的操作指引**，都必须在真实的菜单/工具栏里存在
     —— 菜单改名后文档不会报错，只会默默把用户指到一个不存在的菜单项上
  3. 面向用户：「关于」只讲能做什么 / 结果怎么带走 / 哪些动作要管理员权限 / 数据去哪了 /
     多开一个会怎样，**不写实现机制**（命名互斥体、锁文件、内核回收这类细节属于
     single_instance.py 的模块说明，放进用户弹窗没有信息量）

运行：
    python check_ui_text.py
    python check_ui_text.py --verbose
"""
from __future__ import annotations

import os
import re
import sys
import traceback

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

from PySide6.QtWidgets import QApplication     # noqa: E402

import gui                                     # noqa: E402

VERBOSE = "--verbose" in sys.argv
FAILS: list[str] = []

# 不该出现在用户弹窗里的实现词汇（机制说明的正确归宿是代码注释与文档）
JARGON = ["互斥体", "锁文件", "双保险", "内核自动释放", "flock", "CreateMutex",
          "onefile", "PyInstaller", "single_instance"]

# 用户真正关心的信息
NEEDED = ["不联网", "不上传", "管理员权限", "导出", "只允许运行一个实例", "MIT"]

RE_MENU_REF = re.compile(r"菜单 \*\*([^*→]+?) → ([^*]+?)\*\*")
RE_BAR_REF = re.compile(r"工具栏 \*\*([^*]+?)\*\*")


def check(cond: bool, msg: str, detail: str = ""):
    if cond:
        if VERBOSE:
            print(f"    ok  {msg}")
    else:
        FAILS.append(msg)
        print(f"    FAIL  {msg}" + (f"   ← {detail}" if detail else ""))


def norm(s: str) -> str:
    """归一化：去掉省略号与空白，便于「文档里写 X」与「界面里写 X…」相互包含。"""
    return re.sub(r"[\s…]+", "", s)


def collect_ui(win) -> tuple[dict[str, list[str]], list[str]]:
    menus: dict[str, list[str]] = {}
    for a in win.menuBar().actions():
        m = a.menu()
        if m is not None:
            menus[m.title()] = [x.text() for x in m.actions() if x.text()]
    buttons = [b.text() for b in win.findChildren(type(win.btn_scan)) if b.text()]
    return menus, buttons


def main() -> int:
    app = QApplication.instance() or QApplication([])
    win = gui.ScanApp()
    menus, buttons = collect_ui(win)
    if VERBOSE:
        print("    菜单:", menus)
        print("    工具栏:", buttons)

    print("[1] 「帮助 → 关于」接线")
    check("帮助" in menus, "存在「帮助」菜单", f"实际: {list(menus)}")
    help_items = menus.get("帮助", [])
    check("关于" in help_items, "帮助菜单含「关于」", f"实际: {help_items}")
    check("运行实例信息…" in help_items, "帮助菜单含「运行实例信息…」", f"实际: {help_items}")

    captured: dict = {}
    orig_info = gui._info
    gui._info = lambda parent, title, text: captured.update(title=title, text=text)
    try:
        about = None
        for a in win.menuBar().actions():
            if a.menu() is not None and a.menu().title() == "帮助":
                about = next((x for x in a.menu().actions() if x.text() == "关于"), None)
        check(about is not None, "取到了「关于」菜单动作")
        if about is not None:
            about.trigger()
        check(captured.get("title") == "关于", "弹窗标题为「关于」", repr(captured.get("title")))
        check(captured.get("text") == gui.about_text(),
              "弹窗正文与 about_text() 一致（文案没有第二份拷贝）")
    finally:
        gui._info = orig_info

    text = gui.about_text()

    print("[2] 关于文案：自洽与面向用户")
    check(gui.about_text() == text, "about_text() 是纯函数（两次调用结果相同）")
    check(text == text.strip(), "文案没有多余的首尾空白")
    for w in JARGON:
        check(w not in text, f"不含实现细节「{w}」")
    for w in NEEDED:
        check(w in text, f"含用户关心的「{w}」")
    for name in ("运行实例信息",):
        check(name in text, f"文案告诉用户去哪看实例信息（含「{name}」）")
        check(any(norm(name) in norm(i) for i in help_items),
              f"文案引用的「{name}」在帮助菜单里真实存在", f"实际: {help_items}")

    print("[3] 不泄露本机信息")
    check(re.search(r"[A-Za-z]:\\", text) is None, "不含盘符绝对路径")
    check("\\\\" not in text, "不含 UNC 路径")

    print("[4] README 操作指引与真实界面一致")
    readme = os.path.join(HERE, "README.md")
    doc = open(readme, encoding="utf-8").read()
    menu_refs = RE_MENU_REF.findall(doc)
    bar_refs = RE_BAR_REF.findall(doc)
    if VERBOSE:
        print("    菜单引用:", menu_refs)
        print("    工具栏引用:", bar_refs)
    check(len(menu_refs) >= 4, f"从 README 里提取到菜单引用（{len(menu_refs)} 处）")
    check(len(bar_refs) >= 2, f"从 README 里提取到工具栏引用（{len(bar_refs)} 处）")

    for menu_title, item in menu_refs:
        mt, it = menu_title.strip(), item.strip()
        if mt not in menus:
            check(False, f"README 引用的菜单「{mt}」存在", f"实际: {list(menus)}")
            continue
        hit = any(norm(it) in norm(x) for x in menus[mt])
        check(hit, f"README「{mt} → {it}」在界面上找得到",
              f"「{mt}」实际项: {menus[mt]}")

    for name in bar_refs:
        n = name.strip()
        check(any(norm(n) in norm(b) for b in buttons),
              f"README 引用的工具栏项「{n}」存在", f"实际: {buttons}")

    if VERBOSE:
        print("\n---- 关于文案 ----")
        print(text)
        print("------------------")

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
