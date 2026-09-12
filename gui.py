# -*- coding: utf-8 -*-
"""
系统进程与服务安全扫描器 · 桌面图形界面（PySide6 / Qt 版）

启动方式：
    python gui.py            # 直接打开主窗口
    python gui.py --smoke    # 冒烟测试：构建界面 1.5 秒后自动退出

数据兼容：
    与 scan.py / report.py 共用 scan_result.json（结构完全一致）；
    GUI 的人工标注仅新增 note / trusted 字段，不影响原有字段与消费方。
    旧 tkinter 版本已备份到 backup_tkinter_20260911/。
"""
from __future__ import annotations

import atexit
import csv
import ctypes
import json
import os
import queue
import re
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
import webbrowser
import winreg
import xml.etree.ElementTree as ET
from ctypes import wintypes
from datetime import datetime

import psutil
from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QFont, QIcon, QPalette
from PySide6.QtWidgets import (QAbstractItemView, QApplication, QCheckBox, QComboBox, QDialog,
                               QDialogButtonBox, QFileDialog, QFormLayout, QFrame, QGridLayout,
                               QHBoxLayout, QHeaderView, QLabel, QLineEdit, QMainWindow,
                               QMenu, QMessageBox, QPlainTextEdit, QProgressBar,
                               QPushButton, QStatusBar, QStyleFactory, QTableWidget,
                               QTableWidgetItem, QTabWidget, QTextEdit, QToolBar,
                               QTreeWidget, QTreeWidgetItem, QVBoxLayout, QWidget)

if getattr(sys, "frozen", False):
    HERE = os.path.dirname(os.path.abspath(sys.executable))
else:
    HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import metrics as metrics_mod    # noqa: E402
import report as report_mod      # noqa: E402
import scan as scan_mod          # noqa: E402
import single_instance as single_mod   # noqa: E402

APP_TITLE = "系统进程与服务安全扫描器"
DEFAULT_JSON = os.path.join(HERE, "scan_result.json")

# ---------------- 单实例守卫 ----------------
# 同一时间只允许一个实例运行：多开会同时读写同一份 scan_result.json、
# 同时对同一批服务/进程执行处置动作，互相覆盖与互相干扰。
# 机制（命名互斥体 + 锁文件双保险）、陈旧锁判定、跨平台处理、
# 以及与"以管理员身份运行"的交接约定，全部写在 single_instance.py 的模块说明里。
APP_ID = "SysScanGUI"
EXIT_ALREADY_RUNNING = single_mod.EXIT_ALREADY_RUNNING
SINGLE_INSTANCE_OFF_FLAGS = ("--smoke", "--allow-multi")


def single_instance_disabled() -> bool:
    """是否跳过单实例检测。

    `--smoke`（自检）与 `--allow-multi`（诊断）故意允许多开，
    环境变量 SYSSCAN_ALLOW_MULTI=1 等价 —— 自动化测试靠它并行跑。
    """
    if os.environ.get("SYSSCAN_ALLOW_MULTI") not in (None, "", "0", "false"):
        return True
    return any(f in sys.argv for f in SINGLE_INSTANCE_OFF_FLAGS)


def ui_allowed() -> bool:
    """是否允许弹窗（SYSSCAN_NO_UI=1 时改为只打印，供自动化测试使用）。"""
    return os.environ.get("SYSSCAN_NO_UI") not in ("1", "true", "yes")


_GUARD = None      # 本进程持有的单实例守卫（main() 中建立）


def release_instance_lock():
    """释放单实例锁。异常退出（崩溃/被强杀）时由操作系统内核自动回收。"""
    global _GUARD
    if _GUARD is not None:
        try:
            _GUARD.release()
        except Exception:
            pass
        _GUARD = None

# 静默执行外部命令用：不创建控制台窗口（Windows）
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0


def self_process_hint(rec: dict) -> str:
    """自身进程的说明文案；不是自身进程则返回空串。

    单文件（PyInstaller onefile）版运行时，进程表里必然有两个同名进程：
    引导器（解包 + 守护）和应用本体。用户看到两个"本程序进程"时最容易误会成
    "切到管理员模式后旧实例没退出"，所以在这里把话说明白。
    """
    if not rec.get("self_process"):
        return ""
    role = rec.get("self_note") or "本程序自身进程"
    return (f"{role}：单文件（PyInstaller onefile）版运行时会同时存在"
            "「引导器 + 应用本体」两个同名进程，两者命令行完全相同 —— "
            "这是单文件打包的固定结构，不是旧实例没退出。")


def about_text() -> str:
    """「关于」弹窗的正文（纯函数，便于单独核对文案）。

    只讲用户需要知道的事：能做什么、结果怎么带走、哪些动作要管理员权限、
    数据去哪了、以及"多开一个会怎样"。**不写实现机制** ——
    命名互斥体 / 锁文件 / 内核回收这类细节属于 `single_instance.py` 的模块说明，
    放在面向用户的弹窗里对用户没有任何信息量。
    """
    return (f"{APP_ID}（{APP_TITLE}）\n\n"
            "扫描本机进程 / 服务 / 网络连接 / 持久化项，按可解释的规则给出风险等级。\n"
            "结果可导出 JSON / HTML / CSV（JSON 与 scan_result.json 格式兼容）。\n"
            "扫描本身只读；终止进程、管理服务等处置动作需要管理员权限。\n\n"
            "程序不联网，不上传任何数据。\n"
            "同一时间只允许运行一个实例，重复启动会把已有窗口切到前台\n"
            "（查看实例与锁状态：帮助 → 运行实例信息）。\n\n"
            "开源许可：MIT · github.com/yicko/SysScanGUI")


def run_silent(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    """静默执行外部命令：不弹出任何控制台窗口，返回 (returncode, 输出文本)。"""
    try:
        r = subprocess.run(cmd, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        raw = (r.stdout or b"") + (r.stderr or b"")
        try:
            text = raw.decode("utf-8")
            if "\ufffd" in text:          # 中文 Windows 的 schtasks/sc 输出是 GBK
                text = raw.decode("gbk", errors="replace")
        except UnicodeDecodeError:
            text = raw.decode("gbk", errors="replace")
        return r.returncode, text.strip()
    except subprocess.TimeoutExpired:
        return -1, "命令执行超时。"
    except Exception as exc:
        return -1, str(exc) or exc.__class__.__name__


# ---------------- 管理员提权（ShellExecuteExW，全程无控制台窗口） ----------------
#
# 关键点：nShow 必须传 SW_SHOWNORMAL(1)。
# 传 0 等于 SW_HIDE —— 提权实例的进程会正常启动，但主窗口被置为不可见，
# 表现就是"点了以管理员身份运行，原窗口关掉后再也没有新窗口出现"。

ELEVATE_DIR = os.path.join(tempfile.gettempdir(), "sysscan_elev")
ELEVATE_VERB = "runas"           # 自测时可临时改为 "open" 以跳过 UAC 交互
SW_SHOWNORMAL = 1
SEE_MASK_NOCLOSEPROCESS = 0x00000040
SEE_MASK_NOASYNC = 0x00000100    # 同步等待，确保启动失败能立即拿到错误码
SEE_MASK_FLAG_NO_UI = 0x00000400  # 禁止 shell 弹系统错误框（卡住调用 / 干扰用户）
ERROR_CANCELLED = 1223
SE_ERR_ACCESSDENIED = 5
ELEVATE_TIMEOUT_MS = 15000

if os.name == "nt":
    _shell32 = ctypes.WinDLL("shell32", use_last_error=True)


class SHELLEXECUTEINFOW(ctypes.Structure):
    _fields_ = [("cbSize", wintypes.DWORD),
                ("fMask", ctypes.c_ulong),
                ("hwnd", wintypes.HWND),
                ("lpVerb", wintypes.LPCWSTR),
                ("lpFile", wintypes.LPCWSTR),
                ("lpParameters", wintypes.LPCWSTR),
                ("lpDirectory", wintypes.LPCWSTR),
                ("nShow", ctypes.c_int),
                ("hInstApp", wintypes.HINSTANCE),
                ("lpIDList", ctypes.c_void_p),
                ("lpClass", wintypes.LPCWSTR),
                ("hkeyClass", wintypes.HKEY),
                ("dwHotKey", wintypes.DWORD),
                ("hIcon", wintypes.HANDLE),
                ("hProcess", wintypes.HANDLE)]


def is_admin() -> bool:
    """当前进程是否已真正提权。

    注意：不能用 shell32.IsUserAnAdmin() —— 在开启 UAC 的系统上，属于管理员组
    但未提权的进程同样会返回 True，会造成"已是管理员，无需提权"的误判。
    这里读取进程令牌的 TokenElevation，结论才可靠。
    """
    try:
        advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.GetCurrentProcess.restype = wintypes.HANDLE
        advapi32.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                                              ctypes.POINTER(wintypes.HANDLE)]
        advapi32.OpenProcessToken.restype = wintypes.BOOL
        advapi32.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int,
                                                 ctypes.c_void_p, wintypes.DWORD,
                                                 ctypes.POINTER(wintypes.DWORD)]
        advapi32.GetTokenInformation.restype = wintypes.BOOL
        TOKEN_QUERY = 0x0008
        TOKEN_ELEVATION = 20
        handle = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), TOKEN_QUERY,
                                         ctypes.byref(handle)):
            return False
        try:
            need = wintypes.DWORD(0)
            advapi32.GetTokenInformation(handle, TOKEN_ELEVATION, None, 0,
                                         ctypes.byref(need))
            value = wintypes.DWORD(0)
            if not advapi32.GetTokenInformation(handle, TOKEN_ELEVATION,
                                                ctypes.byref(value),
                                                ctypes.sizeof(value),
                                                ctypes.byref(need)):
                return False
            return bool(value.value)
        finally:
            kernel32.CloseHandle(handle)
    except Exception:
        return False


def shell_execute_ex(path: str, params: str = "", directory: str = "",
                     verb: str = ELEVATE_VERB,
                     show: int = SW_SHOWNORMAL) -> tuple[bool, int]:
    """启动外部程序（verb='runas' 时请求提权）。返回 (是否成功, 错误码)。"""
    sei = SHELLEXECUTEINFOW()
    sei.cbSize = ctypes.sizeof(sei)
    sei.fMask = SEE_MASK_NOCLOSEPROCESS | SEE_MASK_NOASYNC | SEE_MASK_FLAG_NO_UI
    sei.hwnd = None
    sei.lpVerb = verb
    sei.lpFile = path
    sei.lpParameters = params
    sei.lpDirectory = directory or None
    sei.nShow = show
    ctypes.set_last_error(0)
    ok = bool(_shell32.ShellExecuteExW(ctypes.byref(sei)))
    err = ctypes.get_last_error()
    if sei.hProcess:
        try:
            ctypes.windll.kernel32.CloseHandle(sei.hProcess)
        except Exception:
            pass
    return ok, (0 if ok else err)


def clean_elevate_dir(max_age_sec: int = 86400):
    """清理历史遗留的启动确认文件。"""
    try:
        now = time.time()
        for name in os.listdir(ELEVATE_DIR):
            p = os.path.join(ELEVATE_DIR, name)
            if os.path.isfile(p) and now - os.path.getmtime(p) > max_age_sec:
                os.remove(p)
    except Exception:
        pass


# ---------------- 处理历史 / 备份（支持禁用项恢复与删除项还原） ----------------

HISTORY_FILE = os.path.join(HERE, "ops_history.json")
BACKUP_DIR = os.path.join(HERE, "task_backups")


def load_history() -> list[dict]:
    try:
        with open(HISTORY_FILE, encoding="utf-8") as fp:
            data = json.load(fp)
        return data if isinstance(data, list) else []
    except Exception:
        return []


def save_history(hist: list[dict]) -> None:
    try:
        with open(HISTORY_FILE, "w", encoding="utf-8") as fp:
            json.dump(hist, fp, ensure_ascii=False, indent=2)
    except Exception:
        pass


def add_history(entry: dict) -> None:
    hist = load_history()
    entry.setdefault("time", datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    entry.setdefault("restored", False)
    hist.insert(0, entry)
    save_history(hist[:500])          # 防止无限膨胀


def query_disabled_tasks() -> list[str]:
    """查询系统中当前处于“已禁用”状态的计划任务。"""
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
    out: list[str] = []
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            fp = os.path.join(dirpath, f)
            try:
                r = ET.parse(fp).getroot()
            except Exception:
                continue
            en = r.find(".//{http://schemas.microsoft.com/windows/2004/02/mit/task}Settings/"
                        "{http://schemas.microsoft.com/windows/2004/02/mit/task}Enabled")
            if en is not None and (en.text or "").strip().lower() == "false":
                out.append(os.path.relpath(fp, root))
    return sorted(out)


SEVS = ["严重", "高危", "中危", "低危", "正常"]
SEV_COLOR = {"严重": "#7f1d1d", "高危": "#d92d20", "中危": "#f79009", "低危": "#98a2b3"}
# 表格行底色 / 前景色（浅色主题）
SEV_ROW_BG = {"严重": "#fdecea", "高危": "#fdecea", "中危": "#fef7e8", "低危": "#f4f6f8"}
SEV_ROW_FG = {"严重": "#7f1d1d", "高危": "#b42318", "中危": "#7a4b00", "低危": "#4b5563"}

# ---------------- 表格点击排序 ----------------

# 严重度权重（越小越严重）：点击「等级 / 风险」列升序 = 最严重的排在最前
SEV_RANK = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "提示": 4, "正常": 5}

# 排序键存放的数据角色（UserRole 已被整条记录占用）
SORT_ROLE = int(Qt.ItemDataRole.UserRole) + 1

_NUM_SPLIT = re.compile(r"(\d+)")


def natural_key(text) -> list:
    """把文本切成「文字 / 数字」交替片段：让 10 排在 9 之后，日期时间也能正确比较。"""
    parts = _NUM_SPLIT.split(str("" if text is None else text))
    return [(1, p.lower()) if i % 2 == 0 else (0, int(p)) for i, p in enumerate(parts)]


def sort_key_of(rec: dict, key: str, text: str):
    """单元格排序键：数值列比数值、风险/等级比严重度、其余比自然序文本。"""
    raw = rec.get(key)
    if key == "real_file" and not raw:      # 该列显示为空时回落到 binpath
        raw = rec.get("binpath")
    if isinstance(raw, bool):
        return (1, 0.0, natural_key(text))
    if isinstance(raw, (int, float)):
        return (0, float(raw), "")
    if isinstance(raw, str) and raw in SEV_RANK:
        return (-1, float(SEV_RANK[raw]), "")
    return (1, 0.0, natural_key(text))


class SortItem(QTableWidgetItem):
    """带排序键的单元格：让表格按数值 / 严重度 / 自然序排序，而不是按显示文本逐字比较。"""

    def __init__(self, text: str, sort_key):
        super().__init__(text)
        self.setData(SORT_ROLE, sort_key)

    def __lt__(self, other):
        a = self.data(SORT_ROLE)
        b = other.data(SORT_ROLE) if other is not None else None
        if a is None or b is None or type(a) is not type(b):
            return str(a) < str(b)
        return a < b


def enable_click_sort(table: QTableWidget):
    """让表格支持「点击列标题排序」，返回表头点击处理函数。

    这里刻意不使用 setSortingEnabled(True)：那样会在逐行 setItem 的过程中
    立刻重排（把正在填入的数据打乱），并在启用的瞬间按第 0 列强制排序
    （丢掉扫描结果的原始顺序）。改为自行接管表头点击，填充完毕后再排序。
    """
    hh = table.horizontalHeader()
    # 注意顺序：setSortingEnabled(False) 内部会把 sortIndicatorShown 一并置为 False，
    # 所以必须先把排序关掉，再打开指示器，否则升／降序箭头不会显示。
    table.setSortingEnabled(False)
    hh.setSectionsClickable(True)
    hh.setSortIndicatorShown(True)
    hh.setSortIndicator(-1, Qt.SortOrder.AscendingOrder)   # 未排序时不显示方向箭头
    table._sort_spec = None                                # 用户选定的排序 (列, 方向)；None=原始顺序

    def on_section_clicked(col: int):
        # Qt 已按「同一列再点一次切换升降序」更新好指示器，直接照它执行
        table._sort_spec = (col, hh.sortIndicatorOrder())
        table.sortItems(col, hh.sortIndicatorOrder())

    hh.sectionClicked.connect(on_section_clicked)
    return on_section_clicked


def reapply_sort(table: QTableWidget):
    """数据重新填充后恢复用户选定的排序；没选过则保持原始顺序。"""
    spec = getattr(table, "_sort_spec", None)
    if spec:
        table.sortItems(spec[0], spec[1])


def clear_sort(table: QTableWidget):
    """清除该表格的排序，回到原始（扫描结果）顺序。"""
    table._sort_spec = None
    table.horizontalHeader().setSortIndicator(-1, Qt.SortOrder.AscendingOrder)


# ---------------- 自动刷新（分层轻刷新） ----------------

METRIC_INTERVAL_MS = 3000     # 概览指标（CPU/内存）：成本≈0，可常开
CONN_REFRESH_MS = 8000        # 网络连接轻刷新：默认关闭，工具栏开关控制
VERIFY_DELAY_MS = 1800        # 处理动作后的核实延迟（给系统一点生效时间）


def id_key_of(tab: str, rec: dict):
    """记录的身份键：刷新后回选选中行、合并人工标注、剔除已消失记录都靠它。

    连接用 (proto, laddr, raddr, pid) —— laddr 已含端口，足以唯一定位一条连接；
    进程用 pid、服务用 name、持久化用 (type, name)、风险项用 (category, target, title)。
    """
    if tab == "processes":
        return ("pid", rec.get("pid"))
    if tab == "services":
        return ("name", rec.get("name"))
    if tab == "connections":
        return ("conn", rec.get("proto"), rec.get("laddr"), rec.get("raddr"), rec.get("pid"))
    if tab == "persistence":
        return ("persist", rec.get("type"), rec.get("name"))
    if tab == "findings":
        return ("finding", rec.get("category"), rec.get("target"), rec.get("title"))
    return None


TAB_ORDER = ["processes", "services", "connections", "persistence", "findings"]

# 每类数据的表格列: (键, 标题, 宽度, 对齐)
TAB_DEFS = {
    "processes": {
        "title": "进程",
        "cols": [("pid", "PID", 70, "w"), ("name", "进程名", 130, "w"),
                 ("exe", "映像路径", 300, "w"), ("user", "运行身份", 130, "w"),
                 ("cpu", "CPU%", 70, "e"), ("mem_mb", "内存MB", 80, "e"),
                 ("started", "启动时间", 130, "w"), ("sig_status", "签名", 110, "w"),
                 ("risk", "风险", 60, "center")],
        "search_keys": ("name", "exe", "user", "cmdline"),
    },
    "services": {
        "title": "服务",
        "cols": [("name", "服务名", 150, "w"), ("display", "显示名", 180, "w"),
                 ("status", "状态", 80, "w"), ("start_value", "启动类型", 90, "w"),
                 ("user", "登录身份", 130, "w"), ("real_file", "映像/DLL", 300, "w"),
                 ("sig_status", "签名", 110, "w"), ("risk", "风险", 60, "center")],
        "search_keys": ("name", "display", "real_file", "binpath", "user"),
    },
    "connections": {
        "title": "网络连接",
        "cols": [("proto", "协议", 55, "w"), ("laddr", "本地地址", 150, "w"),
                 ("raddr", "远端地址", 150, "w"), ("status", "状态", 95, "w"),
                 ("pid", "PID", 70, "e"), ("proc", "进程", 120, "w"),
                 ("proc_path", "进程路径", 260, "w"), ("risk", "风险", 60, "center")],
        "search_keys": ("laddr", "raddr", "status", "proc", "proc_path"),
    },
    "persistence": {
        "title": "持久化",
        "cols": [("type", "类型", 75, "w"), ("name", "名称", 220, "w"),
                 ("command", "命令", 330, "w"), ("author", "作者/账户", 110, "w"),
                 ("sig_status", "签名", 110, "w"), ("risk", "风险", 60, "center")],
        "search_keys": ("type", "name", "command", "author"),
    },
    "findings": {
        "title": "风险清单",
        "cols": [("severity", "等级", 60, "center"), ("category", "类别", 70, "w"),
                 ("target_type", "对象类型", 80, "w"), ("target", "对象", 170, "w"),
                 ("title", "标题", 330, "w"), ("advice", "建议", 330, "w")],
        "search_keys": ("severity", "category", "target", "title", "detail", "advice"),
    },
}

# 每类数据可编辑字段: (键, 标题, 是否多行)
EDITABLE = {
    "processes": [("note", "人工备注", True), ("risk", "风险标记(严重/高危/中危/低危/正常)", False)],
    "services": [("note", "人工备注", True), ("risk", "风险标记(严重/高危/中危/低危/正常)", False)],
    "connections": [("note", "人工备注", True), ("risk", "风险标记(严重/高危/中危/低危/正常)", False)],
    "persistence": [("type", "类型", False), ("name", "名称", False), ("command", "命令", True),
                    ("note", "人工备注", True), ("risk", "风险标记(严重/高危/中危/低危/正常)", False)],
    "findings": [("title", "标题", False), ("detail", "说明", True),
                 ("advice", "建议", True), ("severity", "等级(严重/高危/中危/低危/提示)", False)],
}
NEW_FIELDS = {
    "processes": [("pid", "PID", False), ("name", "进程名", False), ("exe", "映像路径", True),
                  ("cmdline", "命令行", True), ("user", "运行身份", False), ("note", "备注", True),
                  ("risk", "风险标记", False)],
    "services": [("name", "服务名", False), ("display", "显示名", False), ("binpath", "映像路径", True),
                 ("user", "登录身份", False), ("note", "备注", True), ("risk", "风险标记", False)],
    "connections": [("proto", "协议(TCP/UDP)", False), ("laddr", "本地地址", False),
                    ("raddr", "远端地址", False), ("status", "状态", False),
                    ("note", "备注", True), ("risk", "风险标记", False)],
    "persistence": [("type", "类型(计划任务/启动项)", False), ("name", "名称", False),
                    ("command", "命令", True), ("note", "备注", True), ("risk", "风险标记", False)],
    "findings": [("category", "类别(进程/服务/网络/资源/持久化)", False), ("target_type", "对象类型", False),
                 ("target", "对象", False), ("title", "标题", False), ("detail", "说明", True),
                 ("advice", "建议", True), ("severity", "等级(严重/高危/中危/低危/提示)", False)],
}


def friendly(exc: BaseException) -> str:
    """把常见异常翻译成中文提示。"""
    s = str(exc)
    if "Access is denied" in s or "AccessDenied" in s or "拒绝访问" in s:
        return "权限不足：该操作需要以管理员身份运行本程序。"
    if "not found" in s.lower() or "没有找到" in s or "does not exist" in s.lower():
        return "目标不存在或已经退出。"
    if "timeout" in s.lower() or "超时" in s:
        return "操作超时，请稍后重试。"
    return s or exc.__class__.__name__


def _ask(parent, title: str, text: str) -> bool:
    """确认弹窗（是 / 否）。"""
    r = QMessageBox.question(parent, title, text,
                             QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No,
                             QMessageBox.StandardButton.No)
    return r == QMessageBox.StandardButton.Yes


def _info(parent, title: str, text: str):
    QMessageBox.information(parent, title, text)


def _warn(parent, title: str, text: str):
    QMessageBox.warning(parent, title, text)


def _error(parent, title: str, text: str):
    QMessageBox.critical(parent, title, text)


def _rec_label(rec: dict) -> str:
    return str(rec.get("name") or rec.get("title") or rec.get("display")
               or rec.get("target") or rec.get("pid") or "?")


# ---------------- 通用对话框 ----------------

class RecordForm(QDialog):
    """新增 / 编辑记录的通用表单对话框。"""

    def __init__(self, parent, title: str, fields: list[tuple[str, str, bool]],
                 values: dict, on_ok):
        super().__init__(parent)
        self.setWindowTitle(title)
        self.setMinimumWidth(560)
        self.fields = fields
        self.on_ok = on_ok
        self.edits: dict[str, QLineEdit] = {}
        self.texts: dict[str, QPlainTextEdit] = {}

        form = QFormLayout(self)
        form.setLabelAlignment(Qt.AlignmentFlag.AlignRight)
        form.setSpacing(8)
        for key, label, multiline in fields:
            if multiline:
                txt = QPlainTextEdit()
                txt.setFixedHeight(56)
                txt.setPlainText(str(values.get(key, "") or ""))
                form.addRow(label + "：", txt)
                self.texts[key] = txt
            else:
                e = QLineEdit(str(values.get(key, "") or ""))
                form.addRow(label + "：", e)
                self.edits[key] = e

        btns = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok
                                | QDialogButtonBox.StandardButton.Cancel)
        btns.button(QDialogButtonBox.StandardButton.Ok).setText("确定")
        btns.button(QDialogButtonBox.StandardButton.Cancel).setText("取消")
        btns.accepted.connect(self._ok)
        btns.rejected.connect(self.reject)
        form.addRow(btns)

    def _ok(self):
        out = {}
        for key, _label, multiline in self.fields:
            if multiline:
                out[key] = self.texts[key].toPlainText().strip()
            else:
                out[key] = self.edits[key].text().strip()
        try:
            self.on_ok(out)
        except Exception as exc:
            _error(self, "保存失败", friendly(exc))
            return
        self.accept()


class DetailDialog(QDialog):
    """记录详情窗口：全部字段 + 风险原因 + 操作按钮。"""

    def __init__(self, parent, tab: str, rec: dict, actions: list[tuple[str, object]]):
        super().__init__(parent)
        self.setWindowTitle(f"详情 · {TAB_DEFS[tab]['title']}")
        self.resize(800, 600)
        lay = QVBoxLayout(self)
        lay.setSpacing(8)

        head = rec.get("name") or rec.get("title") or rec.get("display") or str(rec.get("pid", ""))
        sev = rec.get("risk") or rec.get("severity") or ""
        bar = QHBoxLayout()
        lbl = QLabel(head)
        f = lbl.font()
        f.setBold(True)
        f.setPointSize(f.pointSize() + 2)
        lbl.setFont(f)
        bar.addWidget(lbl)
        if sev and sev != "正常":
            sev_lbl = QLabel(f"[{sev}]")
            sev_lbl.setStyleSheet(f"color:{SEV_COLOR.get(sev, '#333')}; font-weight:bold;")
            bar.addWidget(sev_lbl)
        bar.addStretch(1)
        lay.addLayout(bar)

        # 字段表
        tv = QTableWidget(0, 2)
        tv.setHorizontalHeaderLabels(["字段", "值"])
        tv.verticalHeader().setVisible(False)
        tv.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        tv.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tv.setColumnWidth(0, 160)
        tv.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for k, v in rec.items():
            if k in ("windows", "reasons", "extra") and isinstance(v, (list, dict)):
                continue
            row = tv.rowCount()
            tv.insertRow(row)
            tv.setItem(row, 0, QTableWidgetItem(k))
            tv.setItem(row, 1, QTableWidgetItem(v if not isinstance(v, (list, dict)) else str(v)))
        lay.addWidget(tv, 1)

        # 本程序自身进程：把"为什么有两个同名进程"说清楚（否则容易被当成旧实例没退出）
        hint = self_process_hint(rec)
        if hint:
            hl = QLabel("• " + hint)
            hl.setWordWrap(True)
            hl.setStyleSheet("color:#027a48;")
            hl.setIndent(12)
            lay.addWidget(hl)

        # 风险原因
        reasons = rec.get("reasons") or []
        if reasons:
            lay.addWidget(QLabel("风险原因："))
            for r in reasons:
                item = QLabel(f"• [{r.get('sev', '')}] {r.get('text', '')}")
                item.setStyleSheet("color:#b42318;")
                item.setIndent(12)
                lay.addWidget(item)
        note = rec.get("note")
        if note:
            nl = QLabel(f"人工备注：{note}")
            nl.setStyleSheet("color:#175cd3;")
            lay.addWidget(nl)

        # 操作按钮
        btns = QHBoxLayout()
        btns.addStretch(1)
        for label, fn in actions:
            b = QPushButton(label)
            b.clicked.connect(lambda _c=False, fn=fn: self._run(fn))
            btns.addWidget(b)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        btns.addWidget(close)
        lay.addLayout(btns)

    @staticmethod
    def _run(fn):
        try:
            fn()
        except Exception as exc:
            _error(None, "操作出错", friendly(exc))


class HistoryDialog(QDialog):
    """处理历史与恢复：列出本工具执行过的处理操作（禁用/删除/隔离），支持一键还原；
    也可查询系统中当前已禁用的计划任务并重新启用。"""

    KIND_TEXT = {
        "计划任务禁用": "禁用计划任务（可重新启用）",
        "计划任务删除": "删除计划任务（从备份还原）",
        "服务禁用": "禁用服务（还原启动类型）",
        "启动项删除": "删除注册表启动项（可还原）",
        "启动项文件隔离": "隔离启动项文件（可放回）",
    }

    def __init__(self, app):
        super().__init__(app)
        self.app = app
        self.setWindowTitle("处理历史 / 恢复")
        self.resize(920, 640)
        lay = QVBoxLayout(self)

        lay.addWidget(QLabel("■ 处理历史（本工具执行过的操作，选中后可恢复 · 点击列标题排序）"))
        self.tv = QTableWidget(0, 4)
        self.tv.setHorizontalHeaderLabels(["时间", "操作", "对象", "状态"])
        self.tv.verticalHeader().setVisible(False)
        self.tv.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tv.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tv.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        enable_click_sort(self.tv)
        self.tv.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        self.tv.setColumnWidth(0, 140)
        self.tv.setColumnWidth(1, 240)
        self.tv.setColumnWidth(3, 80)
        lay.addWidget(self.tv, 3)

        hb = QHBoxLayout()
        for text, fn in [("↩ 恢复选中项", self._restore_sel), ("删除该记录", self._del_sel),
                         ("打开备份文件夹", self._open_backup), ("刷新", self._load_hist)]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            hb.addWidget(b)
        hb.addStretch(1)
        lay.addLayout(hb)

        lay.addWidget(QLabel("■ 系统当前已禁用的计划任务（实时查询，可重新启用 · 点击列标题排序）"))
        self.tv2 = QTableWidget(0, 1)
        self.tv2.setHorizontalHeaderLabels(["任务名"])
        self.tv2.verticalHeader().setVisible(False)
        self.tv2.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.tv2.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.tv2.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        enable_click_sort(self.tv2)
        self.tv2.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Stretch)
        lay.addWidget(self.tv2, 2)

        db = QHBoxLayout()
        for text, fn in [("🔍 查询已禁用的任务", self._query_disabled), ("▶ 启用选中任务", self._enable_sel)]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            db.addWidget(b)
        self.dcount = QLabel("")
        self.dcount.setStyleSheet("color:#6b7280;")
        db.addWidget(self.dcount)
        db.addStretch(1)
        lay.addLayout(db)

        self._load_hist()
        self._query_disabled()

    # ---- 历史区 ----

    def _load_hist(self):
        self.tv.setRowCount(0)
        self.hist: list[dict] = load_history()
        for e in self.hist:
            row = self.tv.rowCount()
            self.tv.insertRow(row)
            state = "已恢复" if e.get("restored") else "未恢复"
            kind = self.KIND_TEXT.get(e.get("kind", ""), e.get("kind", ""))
            vals = [e.get("time", ""), kind, e.get("target", ""), state]
            for col, v in enumerate(vals):
                it = SortItem(str(v), natural_key(v))
                # 排序后行序会变，原记录挂在单元格上，供选中时直接取用
                it.setData(Qt.ItemDataRole.UserRole, e)
                if e.get("restored"):
                    it.setForeground(QBrush(QColor("#98a2b3")))
                self.tv.setItem(row, col, it)
        reapply_sort(self.tv)

    def _sel_hist(self) -> dict | None:
        rows = self.tv.selectionModel().selectedRows()
        if not rows:
            _info(self, "提示", "请先选择一条处理记录。")
            return None
        it = self.tv.item(rows[0].row(), 0)
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def _restore_sel(self):
        entry = self._sel_hist()
        if entry is None:
            return
        if entry.get("restored"):
            _info(self, "已恢复", "该记录已经恢复过了。")
            return
        kind_txt = self.KIND_TEXT.get(entry.get("kind", ""), entry.get("kind", ""))
        if not _ask(self, "确认恢复",
                    f"确定要恢复以下操作吗？\n\n操作：{kind_txt}\n"
                    f"对象：{entry.get('target', '')}\n时间：{entry.get('time', '')}"):
            return
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            ok, msg = self.app._do_restore(entry)
        except Exception as exc:
            ok, msg = False, friendly(exc)
        finally:
            QApplication.restoreOverrideCursor()
        if ok:
            entry["restored"] = True
            save_history(self.hist)
            self._load_hist()
            _info(self, "恢复成功", msg + "\n\n建议重新扫描核实最新状态。")
        else:
            _error(self, "恢复失败", msg)

    def _del_sel(self):
        entry = self._sel_hist()
        if entry is None:
            return
        if not _ask(self, "确认删除", "确定要从历史中删除该记录吗？\n（不影响系统状态，仅移除记录）"):
            return
        try:
            self.hist.remove(entry)
        except ValueError:
            pass
        save_history(self.hist)
        self._load_hist()

    def _open_backup(self):
        os.makedirs(BACKUP_DIR, exist_ok=True)
        subprocess.Popen(["explorer", os.path.normpath(BACKUP_DIR)])

    # ---- 已禁用任务查询区 ----

    def _query_disabled(self):
        QApplication.setOverrideCursor(Qt.CursorShape.WaitCursor)
        try:
            names = query_disabled_tasks()
        except Exception as exc:
            names = []
            _error(self, "查询失败", friendly(exc))
        finally:
            QApplication.restoreOverrideCursor()
        self.tv2.setRowCount(0)
        for n in names:
            row = self.tv2.rowCount()
            self.tv2.insertRow(row)
            self.tv2.setItem(row, 0, SortItem(str(n), natural_key(n)))
        reapply_sort(self.tv2)
        self.dcount.setText(f"共 {len(names)} 个")

    def _enable_sel(self):
        rows = self.tv2.selectionModel().selectedRows()
        if not rows:
            _info(self, "提示", "请先选择一个任务。")
            return
        name = self.tv2.item(rows[0].row(), 0).text()
        if not name or not _ask(self, "确认启用", f"确定要重新启用计划任务「{name}」吗？"):
            return
        rc, out = run_silent(["schtasks", "/Change", "/TN", name, "/ENABLE"])
        if rc == 0:
            _info(self, "启用成功", f"计划任务「{name}」已重新启用。")
            self._query_disabled()
        else:
            _error(self, "启用失败",
                   f"schtasks 返回码 {rc}：{out[-250:] or '无输出'}\n"
                   "常见原因：需要管理员权限或任务已不存在。")


# ---------------- 实时硬件指标（概览页卡片 + 状态栏） ----------------

# 指标卡片的配色：正常偏蓝、偏高琥珀、危险红（与风险等级用色保持一致）
METRIC_OK = "#175cd3"
METRIC_MID = "#b54708"
METRIC_HIGH = "#b42318"
METRIC_NA = "#98a2b3"

METRIC_CARD_QSS = """
QFrame#metricTile{background:#ffffff;border:1px solid #e5e7eb;border-radius:8px;}
QFrame#metricTile QLabel{background:transparent;}
"""


def _grade(pct: float | None, mid: float, high: float) -> str:
    """按阈值给指标上色。拿不到数值时用灰色，绝不用绿色假装“一切正常”。"""
    if pct is None:
        return METRIC_NA
    if pct >= high:
        return METRIC_HIGH
    if pct >= mid:
        return METRIC_MID
    return METRIC_OK


def _live_status_text(m: dict) -> str:
    """状态栏那行实时读数（CPU · 内存 · GPU · 显存 · 温度）。

    独立成纯函数：一是便于回归测试注入合成数据后精确断言格式，
    二是避免测试退化成"碰运气"——只能等真实读数恰好落进期望区间。
    """
    parts = []
    if m.get("cpu_pct") is not None:
        parts.append(f"CPU {_fmt_pct(m['cpu_pct'])}")
    if m.get("mem_pct") is not None:
        parts.append(f"内存 {_fmt_pct(m['mem_pct'])}")
    if m.get("gpu_util") is not None:
        parts.append(f"GPU {_fmt_pct(m['gpu_util'])}")
    if m.get("gpu_mem_used_gb") is not None:
        parts.append(f"显存 {m['gpu_mem_used_gb']:.2f} GB")
    if m.get("cpu_temp_c") is not None:
        parts.append(f"CPU {m['cpu_temp_c']:.0f}°C")
    if m.get("gpu_temp_c") is not None:
        parts.append(f"GPU {m['gpu_temp_c']:.0f}°C")
    return " · ".join(parts)


def _fmt_pct(v: float | None) -> str:
    """百分比格式化：小数值保留一位小数。

    直接用 %.0f 会把 0.2% 的真实活动显示成 0%，看起来像没数据；
    而原始 float 又会印出 0.20401180464183236% 这种噪声。
    """
    if v is None:
        return "—"
    return f"{v:.1f}%" if v < 10 else f"{v:.0f}%"


def _fmt_gb(v: float | None, digits: int = 2) -> str:
    return "—" if v is None else f"{v:.{digits}f} GB"


class MetricTile(QFrame):
    """单个指标卡片：名称 / 大号数值 / 进度条 / 来源说明。"""

    def __init__(self, title: str, parent=None):
        super().__init__(parent)
        self.setObjectName("metricTile")
        self.setStyleSheet(METRIC_CARD_QSS)
        self.setMinimumHeight(92)
        v = QVBoxLayout(self)
        v.setContentsMargins(12, 9, 12, 9)
        v.setSpacing(5)

        self.title_lbl = QLabel(title)
        self.title_lbl.setStyleSheet("color:#6b7280;font-size:12px;")

        self.value_lbl = QLabel("—")
        self.value_lbl.setStyleSheet(
            f"color:{METRIC_NA};font-size:21px;font-weight:600;")

        self.bar = QProgressBar()
        self.bar.setRange(0, 100)
        self.bar.setTextVisible(False)
        self.bar.setFixedHeight(6)
        self.bar.setStyleSheet("QProgressBar{background:#eef1f6;border:none;border-radius:3px;}"
                               "QProgressBar::chunk{background:#175cd3;border-radius:3px;}")

        self.sub_lbl = QLabel("")
        self.sub_lbl.setStyleSheet("color:#98a2b3;font-size:11px;")
        self.sub_lbl.setWordWrap(True)

        v.addWidget(self.title_lbl)
        v.addWidget(self.value_lbl)
        v.addWidget(self.bar)
        v.addWidget(self.sub_lbl)
        v.addStretch(1)

    def set_metric(self, text: str, pct: float | None, color: str, sub: str = ""):
        self.value_lbl.setText(text)
        self.value_lbl.setStyleSheet(
            f"color:{color};font-size:21px;font-weight:600;")
        if pct is None:
            self.bar.setVisible(False)          # 没有可靠分母就不画进度条
        else:
            self.bar.setVisible(True)
            self.bar.setValue(max(0, min(100, int(round(pct)))))
            self.bar.setStyleSheet(
                "QProgressBar{background:#eef1f6;border:none;border-radius:3px;}"
                f"QProgressBar::chunk{{background:{color};border-radius:3px;}}")
        self.sub_lbl.setText(sub)


class MetricsPanel(QWidget):
    """概览页顶部的实时指标面板：CPU / 内存 / GPU / 显存 / CPU 温度 / GPU 温度。

    只在原地更新数值，不重建控件，所以不会打断滚动或选中。
    """

    KEYS = ("cpu", "mem", "gpu", "vram", "ctemp", "gtemp")
    TITLES = ("CPU 使用率", "内存占用", "GPU 使用率", "显存占用",
              "CPU 温度", "GPU 温度")

    def __init__(self, parent=None):
        super().__init__(parent)
        self.tiles: dict[str, MetricTile] = {}
        g = QGridLayout(self)
        g.setContentsMargins(0, 0, 0, 0)
        g.setSpacing(10)
        for i, (key, title) in enumerate(zip(self.KEYS, self.TITLES)):
            t = MetricTile(title)
            self.tiles[key] = t
            g.addWidget(t, i // 3, i % 3)
        self.hint = QLabel("")
        self.hint.setStyleSheet("color:#6b7280;font-size:12px;")
        self.hint.setWordWrap(True)
        g.addWidget(self.hint, 2, 0, 1, 3)

    def update_from(self, m: dict):
        """用一次采样结果刷新 6 张卡片。任何一项拿不到就显示 “—” 并说明原因。"""
        t = self.tiles

        cpu = m.get("cpu_pct")
        t["cpu"].set_metric(_fmt_pct(cpu), cpu,
                            _grade(cpu, 60, 85), "全核平均，3 秒刷新")

        mem = m.get("mem_pct")
        if m.get("mem_used_gb") is not None and m.get("mem_total_gb"):
            mem_sub = f"{m['mem_used_gb']:.1f} / {m['mem_total_gb']:.1f} GB"
        elif mem is None:
            mem_sub = "系统内存信息不可读"
        else:
            mem_sub = ""
        t["mem"].set_metric(_fmt_pct(mem), mem, _grade(mem, 75, 90), mem_sub)

        gpu = m.get("gpu_util")
        gname = m.get("gpu_name") or "未识别显卡"
        t["gpu"].set_metric(_fmt_pct(gpu), gpu, _grade(gpu, 60, 85), gname)

        # 显存：只有拿到可靠总量时才画百分比条，否则只报占用绝对值
        used = m.get("gpu_mem_used_gb")
        total = m.get("gpu_mem_total_gb")
        pct = m.get("gpu_mem_pct")
        if pct is None and used is not None and total:
            pct = min(used / total * 100, 100)
        if used is None:
            t["vram"].set_metric("—", None, METRIC_NA, "本机无可用显存计数器")
        else:
            txt = _fmt_gb(used) if not total else f"{used:.2f} / {total:.1f} GB"
            parts = []
            if m.get("gpu_mem_dedicated_gb") is not None:
                parts.append(f"独立 {m['gpu_mem_dedicated_gb']:.2f} GB")
            if m.get("gpu_mem_shared_gb") is not None:
                parts.append(f"共享 {m['gpu_mem_shared_gb']:.2f} GB")
            if not total:
                parts.append("总量未知（集成显卡动态共享系统内存）")
            t["vram"].set_metric(txt, pct, _grade(pct, 75, 90), " · ".join(parts))

        ct, cs = m.get("cpu_temp_c"), (m.get("cpu_temp_src") or "")
        if ct is None:
            t["ctemp"].set_metric("—", None, METRIC_NA,
                                  "主板未导出温度传感器；运行 LibreHardwareMonitor 可读")
        else:
            src = "LHM（封装温度）" if cs == "LHM" else f"ACPI 热区 {cs.split(':', 1)[-1]}"
            t["ctemp"].set_metric(f"{ct:.1f}°C", ct, _grade(ct, 70, 85), src)

        gt, gs = m.get("gpu_temp_c"), (m.get("gpu_temp_src") or "")
        if gt is None:
            t["gtemp"].set_metric("—", None, METRIC_NA,
                                  "需 nvidia-smi 或运行 LibreHardwareMonitor")
        else:
            t["gtemp"].set_metric(f"{gt:.1f}°C", gt, _grade(gt, 75, 88),
                                  "nvidia-smi" if gs == "nvidia-smi" else "LHM")

    def set_hint(self, text: str):
        self.hint.setText(text)


# ---------------- 主窗口 ----------------

class ScanApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle(APP_TITLE)
        self.resize(1280, 800)
        self.setMinimumSize(1000, 640)

        self.data: dict = {"meta": {}, "summary": {},
                           "processes": [], "services": [], "connections": [],
                           "persistence": [], "findings": []}
        self.scanning = False
        self._conn_busy = False              # 连接轻刷新进行中（单飞守卫）
        self._msg_q: queue.Queue = queue.Queue()
        self._elev_timer: QTimer | None = None     # 提权实例启动确认轮询
        self._elev_marker = ""
        self._elev_waited = 0
        self._elev_timeout = ELEVATE_TIMEOUT_MS
        self._elev_closing = False
        # 单实例锁接管（仅提权实例使用；普通实例在 main() 里就已判定完毕）
        self._takeover_guard: single_mod.InstanceGuard | None = None
        self._takeover_timer: QTimer | None = None
        self._takeover_waited = 0
        self._takeover_timeout = single_mod.ELEVATE_HANDOFF_WAIT_MS

        self._build_menu()
        self._build_toolbar()
        self._build_tabs()
        self._build_statusbar()

        self._poll_timer = QTimer(self)
        self._poll_timer.timeout.connect(self._poll_queue)
        self._poll_timer.start(120)
        self._search_timer = QTimer(self)
        self._search_timer.setSingleShot(True)
        self._search_timer.timeout.connect(self.refresh_all)

        # 实时硬件指标：CPU / 内存 / GPU 使用率 / 显存 / CPU+GPU 温度，3 秒一次。
        # 全部走 Windows 性能计数器(PDH) 直连，不 spawn 子进程（单次 1~12ms），
        # 所以可以放心常开；只更新概览卡片与状态栏只读标签，不动任何表格。
        try:
            psutil.cpu_percent(interval=None)     # 预热：第一次调用只建立基线
        except Exception:
            pass
        self.sampler = metrics_mod.MetricsSampler()
        self._last_metrics: dict = {}
        self._src_lines: list[str] | None = None
        self._metric_timer = QTimer(self)
        self._metric_timer.timeout.connect(self._refresh_metrics)
        self._metric_timer.start(METRIC_INTERVAL_MS)

        # 网络连接轻刷新：默认关闭，工具栏「连接自动刷新」开关控制
        self._conn_timer = QTimer(self)
        self._conn_timer.timeout.connect(self._auto_refresh_connections)

        # 启动即加载已有扫描结果（无需命令行）
        if os.path.isfile(DEFAULT_JSON):
            try:
                self.load_json_file(DEFAULT_JSON, quiet=True)
            except Exception:
                pass
        self._refresh_metrics()

    # ---------------- UI 构建 ----------------

    def _build_menu(self):
        m = self.menuBar()
        fm = m.addMenu("文件")
        act_scan = QAction("▶ 开始扫描", self)
        act_scan.setShortcut("F5")
        act_scan.triggered.connect(self.do_scan)
        fm.addAction(act_scan)
        fm.addSeparator()
        fm.addAction("打开扫描结果 JSON…", self.open_json)
        fm.addAction("保存当前数据 JSON…", self.save_json)
        fm.addSeparator()
        fm.addAction("导出 HTML 报告…", self.export_html)
        fm.addAction("导出当前页 CSV…", self.export_csv)
        fm.addSeparator()
        fm.addAction("退出", self.close)

        om = m.addMenu("操作")
        om.addAction("新增记录（当前页）", self.add_record)
        om.addSeparator()
        om.addAction("处理历史 / 恢复…", lambda: HistoryDialog(self).exec())
        om.addSeparator()
        om.addAction("以管理员身份重新运行（提权后可管理服务）", self.run_as_admin)

        vm = m.addMenu("视图")
        vm.addAction("恢复默认排序（当前列表）", self.reset_sort_current)
        vm.addAction("恢复默认排序（全部列表）", self.reset_sort_all)
        vm.addSeparator()
        vm.addAction("清除关键字 / 风险筛选", self.clear_filter)
        vm.addSeparator()
        act_live = QAction("实时硬件指标刷新", self)
        act_live.setCheckable(True)
        act_live.setChecked(True)
        act_live.toggled.connect(self._toggle_metrics)
        vm.addAction(act_live)
        vm.addAction("指标数据来源…", self.show_metric_sources)
        self.act_live_metrics = act_live

        hm = m.addMenu("帮助")
        hm.addAction("运行实例信息…", self.show_instance_info)
        hm.addSeparator()
        hm.addAction("关于", lambda: _info(self, "关于", about_text()))

    def _build_toolbar(self):
        tb = QToolBar("工具栏")
        tb.setMovable(False)
        tb.setStyleSheet("QToolBar{spacing:6px; padding:6px;}")
        self.addToolBar(tb)

        self.btn_scan = QPushButton("▶ 开始扫描")
        self.btn_scan.clicked.connect(self.do_scan)
        tb.addWidget(self.btn_scan)
        tb.addSeparator()

        for text, fn in [("打开 JSON", self.open_json), ("保存 JSON", self.save_json),
                         ("导出 HTML", self.export_html), ("导出 CSV", self.export_csv)]:
            b = QPushButton(text)
            b.clicked.connect(fn)
            tb.addWidget(b)
        tb.addSeparator()

        tb.addWidget(QLabel("搜索："))
        self.search_box = QLineEdit()
        self.search_box.setPlaceholderText("关键字过滤…")
        self.search_box.setClearButtonEnabled(True)
        self.search_box.setFixedWidth(240)
        self.search_box.textChanged.connect(lambda _t: self._search_timer.start(250))
        tb.addWidget(self.search_box)

        tb.addWidget(QLabel("风险："))
        self.risk_combo = QComboBox()
        self.risk_combo.addItems(["全部", "严重", "高危", "中危", "低危", "正常"])
        self.risk_combo.setFixedWidth(90)
        self.risk_combo.currentTextChanged.connect(lambda _t: self.refresh_all())
        tb.addWidget(self.risk_combo)

        b_clear = QPushButton("清除筛选")
        b_clear.clicked.connect(self.clear_filter)
        tb.addWidget(b_clear)

        b_reset = QPushButton("恢复默认排序")
        b_reset.setToolTip("清除点击列标题产生的排序，回到扫描结果的原始顺序")
        b_reset.clicked.connect(self.reset_sort_all)
        tb.addWidget(b_reset)

        self.conn_refresh_cb = QCheckBox("连接自动刷新")
        self.conn_refresh_cb.setToolTip(
            "每 8 秒在后台重新采集「网络连接」页数据并应用风险规则。\n"
            "不影响其他列表；排序、筛选、选中行与人工备注都会保留。\n"
            "有对话框打开或正在扫描时自动暂停。")
        self.conn_refresh_cb.toggled.connect(self._set_conn_autorefresh)
        tb.addWidget(self.conn_refresh_cb)

        spacer = QWidget()
        from PySide6.QtWidgets import QSizePolicy
        spacer.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Preferred)
        tb.addWidget(spacer)

        self.progress_label = QLabel("")
        self.progress_label.setStyleSheet("color:#175cd3;")
        tb.addWidget(self.progress_label)
        self.progress = QProgressBar()
        self.progress.setFixedWidth(200)
        self.progress.setValue(0)
        tb.addWidget(self.progress)

    def _build_tabs(self):
        self.nb = QTabWidget()
        self.nb.setDocumentMode(True)
        self.setCentralWidget(self.nb)
        self.trees: dict[str, QTableWidget] = {}
        self.counts: dict[str, QLabel] = {}

        # 概览页 = 实时指标面板（不重建，原地刷新） + 扫描结果摘要（HTML）
        self.overview = QWidget()
        ov = QVBoxLayout(self.overview)
        ov.setContentsMargins(16, 14, 16, 8)
        ov.setSpacing(10)
        ov.addWidget(QLabel("■ 实时硬件指标"))
        self.metrics_panel = MetricsPanel()
        ov.addWidget(self.metrics_panel)
        self.overview_html = QTextEdit()
        self.overview_html.setReadOnly(True)
        self.overview_html.setStyleSheet(
            "QTextEdit{background:#f6f7fb; border:none; padding:4px 0; font-size:14px;}")
        ov.addWidget(self.overview_html, 1)
        self.nb.addTab(self.overview, "概览")

        for tab in TAB_ORDER:
            spec = TAB_DEFS[tab]
            page = QWidget()
            v = QVBoxLayout(page)
            v.setContentsMargins(6, 6, 6, 6)
            v.setSpacing(4)

            bar = QHBoxLayout()
            cnt = QLabel("0 条")
            cnt.setStyleSheet("color:#6b7280;")
            self.counts[tab] = cnt
            bar.addWidget(cnt)
            hint = ("点击列标题排序（默认按严重程度）· 右键执行处理动作" if tab == "findings"
                    else "点击列标题排序 · 双击行查看详情 · 右键更多操作")
            hint_lbl = QLabel(hint)
            hint_lbl.setStyleSheet("color:#6b7280;")
            bar.addWidget(hint_lbl)
            bar.addStretch(1)
            v.addLayout(bar)

            table = QTableWidget(0, len(spec["cols"]))
            table.setHorizontalHeaderLabels([c[1] for c in spec["cols"]])
            table.verticalHeader().setVisible(False)
            table.setAlternatingRowColors(True)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setWordWrap(False)
            table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
            table.customContextMenuRequested.connect(lambda pos, t=tab: self._popup_menu(pos, t))
            table.cellDoubleClicked.connect(lambda _r, _c, t=tab: self.show_detail(t))
            hh = table.horizontalHeader()
            hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
            hh.setStretchLastSection(True)
            for col, (_key, _text, width, _anchor) in enumerate(spec["cols"]):
                table.setColumnWidth(col, width)
            enable_click_sort(table)          # 点击列标题排序（填充时再恢复所选排序）
            v.addWidget(table, 1)
            self.trees[tab] = table
            self.nb.addTab(page, spec["title"])

    def _build_statusbar(self):
        sb = QStatusBar()
        self.setStatusBar(sb)
        self.status = QLabel("就绪。点击「▶ 开始扫描」采集本机数据，或打开已有 scan_result.json。")
        sb.addWidget(self.status, 1)
        self.live_lbl = QLabel("")                      # 实时 CPU/内存（3 秒刷新，只读不改表）
        self.live_lbl.setStyleSheet("color:#175cd3;")
        sb.addPermanentWidget(self.live_lbl)
        self.meta_lbl = QLabel("")
        self.meta_lbl.setStyleSheet("color:#6b7280;")
        sb.addPermanentWidget(self.meta_lbl)

    # ---------------- 数据填充 ----------------

    @staticmethod
    def _align(flag: str) -> Qt.AlignmentFlag:
        return {"w": Qt.AlignmentFlag.AlignLeft, "e": Qt.AlignmentFlag.AlignRight,
                "center": Qt.AlignmentFlag.AlignCenter}.get(flag, Qt.AlignmentFlag.AlignLeft)

    @staticmethod
    def _cell(rec: dict, key: str):
        v = rec.get(key, "")
        if v is None:
            v = ""
        if key == "mem_mb" and isinstance(v, (int, float)):
            return f"{v:g}"
        if key == "cpu" and isinstance(v, (int, float)):
            return f"{v:g}"
        if key == "real_file" and not v:
            return rec.get("binpath", "")
        return str(v)

    def refresh_all(self):
        for tab in TAB_ORDER:
            self._fill_tab(tab)
        self._render_overview()
        self._render_meta()

    def _fill_tab(self, tab: str):
        table = self.trees[tab]
        spec = TAB_DEFS[tab]
        # 重填前记住选中记录的身份键与滚动位置，填完恢复（自动刷新/重扫时界面不跳）
        old_key = None
        sel = table.selectionModel().selectedRows() if table.rowCount() else []
        if sel:
            it0 = table.item(sel[0].row(), 0)
            rec0 = it0.data(Qt.ItemDataRole.UserRole) if it0 else None
            if rec0 is not None:
                old_key = id_key_of(tab, rec0)
        scroll_pos = table.verticalScrollBar().value()
        table.setRowCount(0)
        kw = self.search_box.text().strip().lower()
        risk = "" if self.risk_combo.currentIndex() == 0 else self.risk_combo.currentText()
        keys = spec["search_keys"]
        rows = self.data.get(tab, [])
        shown = 0
        for rec in rows:
            if kw:
                hay = " ".join(str(rec.get(k, "") or "") for k in keys).lower()
                if kw not in hay:
                    continue
            if risk:
                r = rec.get("risk") or rec.get("severity") or ""
                if r != risk:
                    continue
            row = table.rowCount()
            table.insertRow(row)
            sev = rec.get("risk") or rec.get("severity") or ""
            colored = sev in SEV_ROW_BG
            for col, (key, _t, _w, anchor) in enumerate(spec["cols"]):
                text = self._cell(rec, key)
                it = SortItem(text, sort_key_of(rec, key, text))
                it.setData(Qt.ItemDataRole.UserRole, rec)
                it.setTextAlignment(self._align(anchor) | Qt.AlignmentFlag.AlignVCenter)
                if colored:
                    it.setBackground(QBrush(QColor(SEV_ROW_BG[sev])))
                    it.setForeground(QBrush(QColor(SEV_ROW_FG.get(sev, "#111"))))
                table.setItem(row, col, it)
            shown += 1
        self.counts[tab].setText(f"{shown} 条 / 共 {len(rows)} 条")
        reapply_sort(table)               # 保持用户点击表头选定的排序
        if old_key is not None:           # 按身份键回选原先选中的记录
            for r in range(table.rowCount()):
                it = table.item(r, 0)
                rec = it.data(Qt.ItemDataRole.UserRole) if it else None
                if rec is not None and id_key_of(tab, rec) == old_key:
                    table.selectRow(r)
                    break
        table.verticalScrollBar().setValue(scroll_pos)

    def _render_overview(self):
        s = self.data.get("summary") or {}
        meta = self.data.get("meta") or {}
        risk = s.get("risk") or {}
        lines = ["<h2>■ 扫描概览</h2>"]
        if meta:
            lines.append(f"<p>主机：{meta.get('host', '-')}　系统：{meta.get('os', '-')}<br>"
                         f"账户：{meta.get('user', '-')}　"
                         f"{'管理员权限' if meta.get('admin') else '普通权限（服务管理/部分进程信息受限）'}<br>"
                         f"开机时间：{meta.get('boot_time', '-')}　扫描时间：{meta.get('scan_time', '-')}<br>"
                         f"CPU {meta.get('cpu_percent', '-')}%　"
                         f"内存 {meta.get('mem_used_pct', '-')}% / {meta.get('mem_total_gb', '-')} GB　"
                         f"逻辑核心 {meta.get('cpu_logical', '-')}</p>")
        lines.append("<h3>■ 数据统计</h3>")
        lines.append(f"<p>进程 {s.get('process_count', 0)}（窗口应用 {s.get('app_count', 0)}）　"
                     f"服务 {s.get('service_count', 0)}（运行中 {s.get('service_running', 0)}）<br>"
                     f"连接 {s.get('conn_count', 0)}（已建立 {s.get('conn_established', 0)}，"
                     f"监听 {s.get('conn_listen', 0)}）　持久化项 {s.get('persist_count', 0)}</p>")
        lines.append("<h3>■ 风险分布</h3><table cellspacing='2'>")
        for k in SEVS[:-1] + ["提示"]:
            n = risk.get(k, 0)
            color = {"严重": "#d92d20", "高危": "#e8553e", "中危": "#f79009"}.get(k, "#98a2b3")
            bar = f"<span style='color:{color}'>{'█' * min(n, 40)}</span>" if n else "—"
            lines.append(f"<tr><td width='50'>{k}</td><td width='50' align='right'>{n}</td>"
                         f"<td>{bar}</td></tr>")
        lines.append("</table>")
        lines.append("<p style='color:#6b7280'>提示：点击列标题即可排序（再点一次切换升／降序，"
                     "「视图 → 恢复默认排序」可还原）；双击任意表格行查看完整详情；"
                     "右键可执行终止进程、管理服务、风险处理等操作，处理成功后会自动核实结果；"
                     "工具栏「连接自动刷新」可每 8 秒后台刷新连接数据。<br>"
                     "上方实时指标每 3 秒更新（CPU / 内存 / GPU / 显存 / 温度）；"
                     "各项数据来源与不可用原因见「视图 → 指标数据来源…」。</p>")
        self.overview_html.setHtml("".join(lines))

    def _render_meta(self):
        meta = self.data.get("meta") or {}
        if not meta:
            self.meta_lbl.setText("")
            return
        self.meta_lbl.setText(f"{meta.get('host', '')} · {meta.get('scan_time', '')}")

    # ---------------- 扫描（后台线程） ----------------

    def do_scan(self):
        if self.scanning:
            _info(self, "正在扫描", "扫描正在进行中，请稍候。")
            return
        do_sig = _ask(self, "扫描选项",
                      "是否校验数字签名？\n\n"
                      "校验可显著提高准确率，但需要额外约 20~40 秒。\n（点「否」可快速扫描）")
        self.scanning = True
        self.btn_scan.setEnabled(False)
        self.progress.setValue(0)
        self.progress.setMaximum(6)
        self.status.setText("扫描中……")

        def progress_cb(step, total, msg):
            self._msg_q.put(("progress", step, total, msg))

        def worker():
            try:
                data = scan_mod.run_scan(progress_cb=progress_cb)
                self._msg_q.put(("done", data))
            except Exception as exc:
                self._msg_q.put(("error", exc, traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _poll_queue(self):
        try:
            while True:
                msg = self._msg_q.get_nowait()
                kind = msg[0]
                if kind == "progress":
                    _k, step, total, text = msg
                    self.progress.setValue(step)
                    self.progress.setMaximum(total)
                    self.progress_label.setText(f"{step}/{total} {text}")
                elif kind == "done":
                    self.data = msg[1]
                    self.scanning = False
                    self.btn_scan.setEnabled(True)
                    self.progress_label.setText("完成")
                    self.refresh_all()
                    s = self.data.get("summary", {})
                    self.status.setText(
                        f"扫描完成：进程 {s.get('process_count', 0)} / 服务 {s.get('service_count', 0)}"
                        f" / 连接 {s.get('conn_count', 0)} / 风险项 {s.get('risk_total', 0)}"
                        "（数据保存在内存中，可通过「文件 → 保存 JSON」持久化）")
                    rk = s.get("risk", {})
                    _info(self, "扫描完成",
                          f"扫描完成。\n\n风险项：{s.get('risk_total', 0)} 条"
                          f"（严重 {rk.get('严重', 0)}，高危 {rk.get('高危', 0)}，"
                          f"中危 {rk.get('中危', 0)}，低危 {rk.get('低危', 0)}）\n\n"
                          "详情请查看「风险清单」标签页。")
                elif kind == "error":
                    self.scanning = False
                    self.btn_scan.setEnabled(True)
                    self.progress_label.setText("失败")
                    self.status.setText("扫描失败。")
                    _error(self, "扫描失败", friendly(msg[1]))
                elif kind == "opdone":
                    _k, label, ok, opmsg, rec, verify = msg
                    if ok:
                        if rec is not None:
                            note = rec.get("note") or ""
                            rec["note"] = (note + "\n" if note else "") + \
                                f"[已处理 {datetime.now():%H:%M}] {label}：{opmsg.splitlines()[0]}"
                        self.refresh_all()
                        tail = ("稍后将自动核实结果。") if verify \
                            else ("建议重新扫描核实最新状态。")
                        _info(self, "处理成功",
                              f"「{label}」执行成功。\n\n{opmsg}\n\n已写入该项备注；{tail}")
                        if verify:
                            self._schedule_verify(verify)
                    else:
                        _error(self, "处理失败", f"「{label}」执行失败。\n\n{opmsg}")
                elif kind == "conns":
                    self._conn_busy = False
                    self._merge_connections(msg[1])
                    self._fill_tab("connections")
                    conns = msg[1]
                    est = sum(1 for c in conns if c.get("status") == psutil.CONN_ESTABLISHED)
                    lst = sum(1 for c in conns if c.get("status") == psutil.CONN_LISTEN)
                    self.status.setText(
                        f"网络连接已自动刷新（{datetime.now():%H:%M:%S}）："
                        f"共 {len(conns)} 条，已建立 {est}，监听 {lst}。")
                elif kind == "connfail":
                    self._conn_busy = False
                    self.status.setText("网络连接自动刷新失败：" + friendly(msg[1]))
        except queue.Empty:
            pass

    # ---------------- 详情 / 右键操作 ----------------

    def _selected(self, tab: str) -> dict | None:
        table = self.trees[tab]
        rows = table.selectionModel().selectedRows()
        if not rows:
            return None
        it = table.item(rows[0].row(), 0)
        return it.data(Qt.ItemDataRole.UserRole) if it else None

    def show_detail(self, tab: str):
        rec = self._selected(tab)
        if rec is None:
            _info(self, "提示", "请先在列表中选择一条记录。")
            return
        DetailDialog(self, tab, rec, self._actions_for(tab, rec)).exec()

    def _popup_menu(self, pos, tab: str):
        table = self.trees[tab]
        row = table.rowAt(pos.y())
        if row < 0:
            return
        table.selectRow(row)
        rec = table.item(row, 0).data(Qt.ItemDataRole.UserRole) if table.item(row, 0) else None
        if rec is None:
            return
        menu = QMenu(self)
        menu.addAction("查看详情", lambda: self.show_detail(tab))
        for label, fn in self._actions_for(tab, rec):
            menu.addAction(label, fn)
        menu.exec(table.viewport().mapToGlobal(pos))

    def _actions_for(self, tab: str, rec: dict) -> list[tuple[str, object]]:
        acts: list[tuple[str, object]] = []
        if tab == "findings":
            # 风险项：按建议映射出的实际处理动作放在最前
            acts.extend(self.remediation_actions(rec))
        acts.append(("编辑 / 备注", lambda: self.edit_record(tab, rec)))
        if tab == "processes" and rec.get("pid"):
            acts.append(("⛔ 终止该进程…", lambda: self.kill_process(rec)))
        if tab == "services" and rec.get("name"):
            running = (rec.get("status") or "").lower() == "running"
            if running:
                acts.append(("⏹ 停止该服务…", lambda: self.service_op(rec, "stop")))
            else:
                acts.append(("▶ 启动该服务…", lambda: self.service_op(rec, "start")))
        exe = rec.get("exe") or rec.get("real_file") or ""
        if tab == "persistence":
            exe = rec.get("command") or ""
            exe = exe.split(" -")[0].strip('" ') if exe else ""
        if exe and os.path.isfile(exe):
            acts.append(("📁 打开文件所在位置", lambda p=exe: self.open_location(p)))
        acts.append(("🗑 从数据中删除该记录…", lambda: self.delete_record(tab, rec)))
        return acts

    # ---------------- 系统操作（带确认 + 友好错误） ----------------

    def kill_process(self, rec: dict):
        pid = rec.get("pid")
        if not _ask(self, "确认终止进程",
                    f"确定要终止进程吗？\n\n进程：{rec.get('name')} (PID {pid})\n"
                    f"路径：{rec.get('exe') or '未知'}\n\n"
                    "终止系统关键进程可能导致蓝屏或数据丢失，请确认该进程用途！"):
            return
        try:
            p = psutil.Process(int(pid))
            p.terminate()
            try:
                p.wait(timeout=5)
            except psutil.TimeoutExpired:
                if _ask(self, "仍在运行", "进程未响应 terminate，是否强制杀死（kill）？"):
                    p.kill()
            self.status.setText(f"已发送终止指令：{rec.get('name')} (PID {pid})")
            _info(self, "完成", f"已向进程 {rec.get('name')} (PID {pid}) 发送终止指令。\n"
                                "稍后将自动核实结果并更新列表。")
            self._schedule_verify({"kind": "kill", "pid": pid,
                                   "name": rec.get("name") or ""})
        except psutil.NoSuchProcess:
            _warn(self, "进程不存在", "该进程已经退出了。")
        except psutil.AccessDenied:
            _error(self, "权限不足", "权限不足，无法终止该进程。\n请以管理员身份重新运行本程序。")
        except Exception as exc:
            _error(self, "操作失败", friendly(exc))

    def service_op(self, rec: dict, op: str):
        name = rec.get("name")
        verb = "停止" if op == "stop" else "启动"
        if not _ask(self, "确认操作", f"确定要{verb}服务「{name}」吗？\n\n"
                                     "误停关键系统服务可能影响系统功能。"):
            return
        try:
            svc = psutil.win_service_get(name)
            if op == "stop":
                svc.stop()
            else:
                svc.start()
            self.status.setText(f"已请求{verb}服务：{name}（稍后将自动核实状态）")
            _info(self, "已提交", f"已请求{verb}服务「{name}」。\n"
                                  "服务状态切换可能有几秒延迟，稍后将自动核实并更新列表。")
            self._schedule_verify({"kind": "service", "name": name, "op": op})
        except psutil.AccessDenied:
            _error(self, "权限不足", f"权限不足，无法{verb}服务。\n\n"
                                    "服务管理需要管理员权限：\n菜单「操作 → 以管理员身份重新运行」。")
        except Exception as exc:
            _error(self, "操作失败", friendly(exc))

    def open_location(self, path: str):
        try:
            subprocess.Popen(["explorer", "/select,", os.path.normpath(path)])
        except Exception as exc:
            _error(self, "打开失败", friendly(exc))

    # ---------------- 风险项处理动作（按建议映射，可实际执行） ----------------

    RUN_KEY_SUBS = {
        "HKLM\\Run": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM\\RunOnce": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKLM\\Run(x86)": r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\\Run": r"Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU\\RunOnce": r"Software\Microsoft\Windows\CurrentVersion\RunOnce",
    }

    def _exec_action(self, label: str, confirm: str, fn, rec: dict | None = None,
                     verify: dict | None = None):
        """处理动作统一入口：确认弹窗 → 后台线程执行 → 结果弹窗反馈 →（可选）延时核实。"""
        if confirm and not _ask(self, "确认处理", confirm):
            return
        def worker():
            try:
                ok, msg = fn()
            except Exception as exc:
                ok, msg = False, friendly(exc)
            self._msg_q.put(("opdone", label, ok, msg, rec, verify))
        threading.Thread(target=worker, daemon=True).start()

    # ---------------- 操作后自动核实（不弹窗，只更新状态栏与受影响行） ----------------

    def _schedule_verify(self, verify: dict, delay_ms: int = VERIFY_DELAY_MS):
        """动作生效需要一点时间，延迟后做单点核实；结果只写状态栏，不打断用户。"""
        QTimer.singleShot(delay_ms, lambda: self._verify_op(verify))

    def _verify_op(self, v: dict):
        kind = v.get("kind", "")
        try:
            if kind == "kill":
                self._verify_kill(v.get("pid"), v.get("name") or "")
            elif kind == "service":
                self._verify_service(v.get("name") or "", v.get("op") or "")
            elif kind == "service_disable":
                self._verify_service_disabled(v.get("name") or "")
            elif kind == "task_delete":
                self._verify_task_deleted(v.get("name") or "")
            elif kind == "task_disable":
                self._verify_task_state(v.get("name") or "", v.get("expect_disabled", True))
            elif kind == "runkey":
                self._verify_runkey(v.get("source") or "")
            elif kind == "startupfile":
                self._verify_startupfile(v.get("source") or "")
        except Exception as exc:
            self.status.setText(f"自动核实出错：{friendly(exc)}")

    def _verify_kill(self, pid, name: str):
        """核实进程是否已退出；已退出则从列表同步移除。

        名字对不上视为原进程已退出（PID 被复用）：绝不能只凭 PID 存活就断定没杀掉。
        """
        gone = True
        try:
            p = psutil.Process(int(pid))
            gone = (p.name() or "") != name
        except psutil.NoSuchProcess:
            gone = True
        except Exception:
            gone = False                      # 查询失败（如权限不足）时不轻率下结论
        if gone:
            procs = self.data.get("processes", [])
            keep = [p for p in procs
                    if not (str(p.get("pid")) == str(pid) and (p.get("name") or "") == name)]
            if len(keep) != len(procs):
                self.data["processes"] = keep
                self._fill_tab("processes")
            self.status.setText(f"✓ 已核实：进程 {name} (PID {pid}) 已退出，列表已同步。")
        else:
            self.status.setText(f"⚠ 核实：进程 {name} (PID {pid}) 仍在运行"
                                "（可能需要管理员权限，可提权后重试或强制结束）。")

    def _verify_service(self, name: str, op: str):
        try:
            st = (psutil.win_service_get(name).status() or "").lower()
        except Exception as exc:
            self.status.setText(f"未能核实服务「{name}」状态：{friendly(exc)}")
            return
        self._update_service_row(name, st)
        expect = "stopped" if op == "stop" else "running"
        mark = "✓" if st == expect else "·"
        self.status.setText(f"{mark} 已核实：服务「{name}」当前状态 {st.upper()}"
                            f"（预期 {expect.upper()}，状态切换可能有几秒延迟）。")

    def _update_service_row(self, name: str, st: str):
        for s in self.data.get("services", []):
            if s.get("name") == name:
                if st and s.get("status") != st:
                    s["status"] = st
                    self._fill_tab("services")
                return

    def _verify_service_disabled(self, name: str):
        try:
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                rf"SYSTEM\CurrentControlSet\Services\{name}", 0,
                                winreg.KEY_QUERY_VALUE) as k:
                start, _t = winreg.QueryValueEx(k, "Start")
            if int(start) == 4:
                self.status.setText(f"✓ 已核实：服务「{name}」启动类型已是「已禁用」。")
            else:
                self.status.setText(f"⚠ 核实：服务「{name}」启动类型为 {start}（预期 4 = 禁用）。")
        except Exception as exc:
            self.status.setText(f"未能核实服务「{name}」禁用状态：{friendly(exc)}")

    def _verify_task_deleted(self, name: str):
        rc, _out = run_silent(["schtasks", "/Query", "/TN", name])
        if rc != 0:
            if self._drop_persist(lambda it: it.get("type") == "计划任务"
                                  and it.get("name") == name):
                self._fill_tab("persistence")
            self.status.setText(f"✓ 已核实：计划任务「{name}」已不存在，列表已同步。")
        else:
            self.status.setText(f"· 已核实：计划任务「{name}」仍存在（可能被策略或程序重建）。")

    def _verify_task_state(self, name: str, expect_disabled: bool = True):
        rc, out = run_silent(["schtasks", "/Query", "/TN", name, "/V", "/FO", "LIST"])
        if rc != 0:
            self.status.setText(f"⚠ 核实：计划任务「{name}」查询失败或已不存在。")
            return
        # 「计划任务状态」行的取值随系统语言不同，逐行匹配中英文，避免"空闲时间: 已禁用"这类
        # 其他字段误报
        disabled: bool | None = None
        for ln in (out or "").splitlines():
            if ("计划任务状态" in ln) or ("scheduled task state" in ln.lower()):
                disabled = ("已禁用" in ln) or ("disabled" in ln.lower())
                break
        if disabled is None:                  # 输出格式不认识时，兜底读任务 XML 的 <Enabled>
            xml_enabled = self._task_xml_enabled(name)
            disabled = (xml_enabled is False)
        new_enabled = not disabled
        for it in self.data.get("persistence", []):
            if it.get("type") == "计划任务" and it.get("name") == name:
                if it.get("enabled") != new_enabled:
                    it["enabled"] = new_enabled
                    self._fill_tab("persistence")
                break
        state_txt = "已禁用" if disabled else "已启用"
        mark = "✓" if disabled == expect_disabled else "·"
        self.status.setText(f"{mark} 已核实：计划任务「{name}」当前为「{state_txt}」。")

    def _task_xml_enabled(self, name: str) -> bool | None:
        src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "Tasks", name)
        if not os.path.isfile(src):
            return None
        try:
            r = ET.parse(src).getroot()
            el = r.find(".//t:Settings/t:Enabled",
                        {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"})
            if el is None:
                return True
            return (el.text or "true").strip().lower() == "true"
        except Exception:
            return None

    def _verify_runkey(self, source: str):
        if not source or "\\" not in source:
            return
        label, val = source.rsplit("\\", 1)
        sub = self.RUN_KEY_SUBS.get(label)
        if not sub:
            return                            # 非 Run/RunOnce 位置，不监控
        hive = winreg.HKEY_CURRENT_USER if label.startswith("HKCU") else winreg.HKEY_LOCAL_MACHINE
        try:
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_QUERY_VALUE) as k:
                winreg.QueryValueEx(k, val)
            self.status.setText(f"⚠ 核实：启动项「{val}」仍在注册表中（可能被程序重新写回）。")
        except OSError:
            if self._drop_persist(lambda it: it.get("source") == source):
                self._fill_tab("persistence")
            self.status.setText(
                f"✓ 已核实：启动项「{val}」（{label}）已从注册表移除，列表已同步。")

    def _verify_startupfile(self, source: str):
        if not source:
            return
        if os.path.isfile(source):
            self.status.setText(f"⚠ 核实：启动项文件仍在原位置（可能被还原或重新创建）：{source}")
        else:
            if self._drop_persist(lambda it: it.get("source") == source):
                self._fill_tab("persistence")
            self.status.setText("✓ 已核实：启动项文件已不在原位置，列表已同步。")

    def _drop_persist(self, pred) -> int:
        """按条件从持久化数据中移除记录，返回移除条数。"""
        items = self.data.get("persistence", [])
        keep = [it for it in items if not pred(it)]
        removed = len(items) - len(keep)
        if removed:
            self.data["persistence"] = keep
        return removed

    def _op_kill_pid(self, pid, name: str):
        try:
            pid = int(pid)
        except (TypeError, ValueError):
            return False, f"无效的 PID：{pid}"
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=5)
        except psutil.TimeoutExpired:
            p.kill()
            try:
                p.wait(timeout=5)
            except psutil.TimeoutExpired:
                return False, f"已发送 kill 指令，但进程 {name} (PID {pid}) 5 秒内未退出。"
        return True, f"进程 {name} (PID {pid}) 已终止。"

    def _op_service_stop(self, name: str):
        svc = psutil.win_service_get(name)
        svc.stop()
        return True, f"已向服务「{name}」发送停止指令（状态切换可能有几秒延迟，重新扫描可核实）。"

    def _op_service_disable(self, name: str):
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            rf"SYSTEM\CurrentControlSet\Services\{name}", 0,
                            winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as k:
            try:
                old, _ = winreg.QueryValueEx(k, "Start")
            except OSError:
                old = None
            winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, 4)   # 4 = SERVICE_DISABLED
        old_txt = {0: "启动(0)", 1: "系统(1)", 2: "自动", 3: "手动"}.get(old,
                                                                     "未设置" if old is None else str(old))
        add_history({"kind": "服务禁用", "target": name, "old_start": old})
        return True, (f"服务「{name}」启动类型已设为「已禁用」（原值：{old_txt}）。\n"
                      "可在「操作 → 处理历史 / 恢复」中还原原启动类型。")

    def _op_task_disable(self, task_name: str):
        rc, out = run_silent(["schtasks", "/Change", "/TN", task_name, "/DISABLE"])
        if rc == 0:
            add_history({"kind": "计划任务禁用", "target": task_name})
            return True, f"计划任务「{task_name}」已禁用（可在「操作 → 处理历史 / 恢复」中重新启用）。"
        return False, (f"schtasks 返回码 {rc}：{out[-300:] or '无输出'}。\n"
                       "常见原因：需要管理员权限、任务名拼写变化或任务已不存在。")

    def _op_task_delete(self, task_name: str, prec: dict | None = None):
        # 删除前先备份任务定义 XML（用于恢复）
        backup = ""
        src = (prec or {}).get("source") or ""
        if not src:
            src = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                               "System32", "Tasks", task_name)
        if os.path.isfile(src):
            try:
                os.makedirs(BACKUP_DIR, exist_ok=True)
                stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                safe = task_name.replace("\\", "_").replace("/", "_")
                backup = os.path.join(BACKUP_DIR, f"{stamp}_{safe}.xml")
                with open(src, "rb") as a, open(backup, "wb") as b:
                    b.write(a.read())
            except Exception:
                backup = ""
        rc, out = run_silent(["schtasks", "/Delete", "/TN", task_name, "/F"])
        if rc == 0:
            add_history({"kind": "计划任务删除", "target": task_name, "backup": backup})
            if backup:
                return True, (f"计划任务「{task_name}」已删除。\n任务定义已备份到：\n{backup}\n"
                              "可在「操作 → 处理历史 / 恢复」中还原。")
            return True, (f"计划任务「{task_name}」已删除。\n"
                          "（删除前未能读取任务定义做备份，此项无法自动恢复）")
        return False, (f"schtasks 返回码 {rc}：{out[-300:] or '无输出'}。\n"
                       "常见原因：需要管理员权限或任务已不存在。")

    def _op_runkey_delete(self, prec: dict):
        label_val = prec.get("source") or ""
        if "\\" not in label_val:
            return False, f"无法解析启动项位置：{label_val}"
        label, val = label_val.rsplit("\\", 1)
        sub = self.RUN_KEY_SUBS.get(label)
        if not sub:
            return False, f"不支持的注册表位置：{label}"
        hive = winreg.HKEY_CURRENT_USER if prec.get("user") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
        with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, val)
        add_history({"kind": "启动项删除", "target": val,
                     "hive": "HKCU" if prec.get("user") == "HKCU" else "HKLM",
                     "sub": sub, "data": prec.get("command", "")})
        return True, (f"注册表启动项「{val}」（{label}）已删除。\n"
                      "可在「操作 → 处理历史 / 恢复」中还原该启动项。")

    def _op_startupfile_remove(self, prec: dict):
        path = prec.get("command") or ""
        if not path or not os.path.isfile(path):
            return False, "文件不存在，无需处理。"
        qdir = os.path.join(HERE, "_quarantine")
        os.makedirs(qdir, exist_ok=True)
        dest = os.path.join(qdir, f"{datetime.now():%H%M%S}_{os.path.basename(path)}")
        try:
            os.rename(path, dest)
        except PermissionError:
            return False, "文件被占用，无法移动（对应程序可能正在运行，请先终止该进程）。"
        add_history({"kind": "启动项文件隔离", "target": os.path.basename(dest),
                     "src": path, "dst": dest})
        return True, (f"启动项文件已隔离（未删除）到：\n{dest}\n"
                      "可在「操作 → 处理历史 / 恢复」中还原，或确认无问题后自行删除。")

    def _find_persist(self, ptype: str, pname: str) -> dict | None:
        for it in self.data.get("persistence", []):
            if it.get("type") == ptype and it.get("name") == pname:
                return it
        return None

    def remediation_actions(self, rec: dict) -> list[tuple[str, object]]:
        """根据风险项的类别 / 对象 / 建议文本，映射出可实际执行的处理动作。"""
        cat = rec.get("category", "")
        target = rec.get("target", "")
        title = rec.get("title", "")
        acts: list[tuple[str, object]] = []

        if cat in ("进程", "资源") and target.startswith("process:"):
            pid_s = target.split(":", 1)[1]
            name = title.split("：", 1)[-1]
            acts.append(("⛔ 终止该进程", lambda: self._exec_action(
                "终止该进程",
                f"确定要终止进程 {name} (PID {pid_s}) 吗？\n\n"
                "终止系统关键进程可能导致蓝屏或数据丢失，请确认用途！",
                lambda: self._op_kill_pid(pid_s, name), rec,
                verify={"kind": "kill", "pid": pid_s, "name": name})))

        elif cat == "服务" and target.startswith("service:"):
            name = target.split(":", 1)[1]
            acts.append(("⏹ 停止该服务", lambda: self._exec_action(
                "停止该服务",
                f"确定要停止服务「{name}」吗？\n\n误停关键系统服务可能影响系统功能。",
                lambda: self._op_service_stop(name), rec,
                verify={"kind": "service", "name": name, "op": "stop"})))
            acts.append(("🚫 禁用该服务（不再自启）", lambda: self._exec_action(
                "禁用该服务",
                f"确定要禁用服务「{name}」吗？\n\n"
                "禁用后该服务不再自动启动（注册表 Start=4），需要管理员权限。",
                lambda: self._op_service_disable(name), rec,
                verify={"kind": "service_disable", "name": name})))

        elif cat == "持久化" and target.startswith("persist:"):
            rest = target.split(":", 1)[1]
            ptype, _sep, pname = rest.partition(":")
            prec = self._find_persist(ptype, pname)
            if ptype == "计划任务":
                acts.append(("🗓 禁用该计划任务", lambda: self._exec_action(
                    "禁用该计划任务",
                    f"确定要禁用计划任务「{pname}」吗？\n\n"
                    "禁用后任务保留但不再运行，可随时重新启用。",
                    lambda: self._op_task_disable(pname), rec,
                    verify={"kind": "task_disable", "name": pname,
                            "expect_disabled": True})))
                acts.append(("🗑 删除该计划任务", lambda: self._exec_action(
                    "删除该计划任务",
                    f"确定要删除计划任务「{pname}」吗？\n\n删除前会自动备份任务定义 XML，"
                    "可从「处理历史 / 恢复」还原。",
                    lambda: self._op_task_delete(pname, prec), rec,
                    verify={"kind": "task_delete", "name": pname})))
            elif prec and prec.get("source", "").startswith(("HKLM\\Run", "HKCU\\Run")):
                acts.append(("🗑 删除该注册表启动项", lambda: self._exec_action(
                    "删除该注册表启动项",
                    f"确定要删除启动项「{pname}」吗？\n\n"
                    f"注册表位置：{prec.get('source', '')}\n"
                    "删除后该程序不再开机自启（程序本身不受影响）。",
                    lambda: self._op_runkey_delete(prec), rec,
                    verify={"kind": "runkey", "source": prec.get("source", "")})))
            elif prec:
                acts.append(("🗑 移除该启动文件夹项（隔离）", lambda: self._exec_action(
                    "移除该启动文件夹项",
                    f"确定要移除启动项文件吗？\n\n文件：{prec.get('command', '')}\n"
                    "文件不会被删除，而是移动到程序目录的 _quarantine 隔离文件夹。",
                    lambda: self._op_startupfile_remove(prec), rec,
                    verify={"kind": "startupfile",
                            "source": prec.get("source") or prec.get("command", "")})))

        elif cat == "网络":
            m = re.search(r"PID (\d+)", title)
            if m:
                pid, name = m.group(1), title.split("：", 1)[-1]
                acts.append(("⛔ 终止归属进程（断开该连接）", lambda: self._exec_action(
                    "终止归属进程",
                    f"确定要终止 {name} (PID {pid}) 吗？\n\n"
                    "终止后该进程发起的所有网络连接都会断开。",
                    lambda: self._op_kill_pid(pid, name), rec,
                    verify={"kind": "kill", "pid": pid, "name": name})))
        return acts

    # ---------------- 恢复（禁用的任务 / 删除的任务 / 其他处理操作） ----------------

    def _do_restore(self, entry: dict) -> tuple[bool, str]:
        """按历史记录还原一次处理操作，返回 (是否成功, 说明)。"""
        kind = entry.get("kind", "")
        target = entry.get("target", "")

        if kind == "计划任务禁用":
            rc, out = run_silent(["schtasks", "/Change", "/TN", target, "/ENABLE"])
            if rc == 0:
                return True, f"计划任务「{target}」已重新启用。"
            return False, (f"schtasks 返回码 {rc}：{out[-250:] or '无输出'}\n"
                           "常见原因：需要管理员权限或任务已不存在。")

        if kind == "计划任务删除":
            bk = entry.get("backup") or ""
            if not bk or not os.path.isfile(bk):
                return False, ("删除前未能创建任务定义备份（XML），无法自动恢复。\n"
                               "如需重建，请手动在任务计划程序中重新创建该任务。")
            rc, out = run_silent(["schtasks", "/Create", "/TN", target, "/XML", bk, "/F"])
            if rc == 0:
                return True, f"计划任务「{target}」已从备份还原（备份文件：{bk}）。"
            return False, f"schtasks 返回码 {rc}：{out[-250:] or '无输出'}\n常见原因：需要管理员权限。"

        if kind == "服务禁用":
            old = entry.get("old_start")
            if old is None:
                return False, "未记录该服务原来的启动类型，无法自动恢复（请手动在 services.msc 中设置）。"
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                                rf"SYSTEM\CurrentControlSet\Services\{target}", 0,
                                winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, "Start", 0, winreg.REG_DWORD, int(old))
            txt = {2: "自动", 3: "手动"}.get(old, str(old))
            return True, f"服务「{target}」启动类型已恢复为「{txt}」。"

        if kind == "启动项删除":
            hive = winreg.HKEY_CURRENT_USER if entry.get("hive") == "HKCU" else winreg.HKEY_LOCAL_MACHINE
            sub = entry.get("sub") or ""
            if not sub:
                return False, "记录中缺少注册表位置，无法自动恢复。"
            with winreg.OpenKey(hive, sub, 0, winreg.KEY_SET_VALUE) as k:
                winreg.SetValueEx(k, target, 0, winreg.REG_SZ, entry.get("data", ""))
            return True, f"注册表启动项「{target}」已还原。"

        if kind == "启动项文件隔离":
            src, dst = entry.get("src") or "", entry.get("dst") or ""
            if not dst or not os.path.isfile(dst):
                return False, "隔离文件已不存在（可能已被手动删除）。"
            if not src:
                return False, "记录中缺少原始位置，无法自动恢复。"
            if os.path.exists(src):
                return False, f"原位置已存在同名文件，未执行恢复：\n{src}"
            os.makedirs(os.path.dirname(src), exist_ok=True)
            os.rename(dst, src)
            return True, f"启动项文件已恢复到：\n{src}"

        return False, f"该记录类型（{kind}）暂不支持自动恢复。"

    def run_as_admin(self):
        """提权重启：只弹 UAC 授权框，无控制台窗口；新实例确认启动后本窗口才退出。"""
        if is_admin():
            _info(self, "已是管理员", "当前程序已以管理员权限运行，无需重复提权。")
            return
        try:
            # 先落盘，让提权后的新实例能读到手动的标注与本次修改
            try:
                scan_mod.save_json(self.data, DEFAULT_JSON)
            except Exception:
                pass

            os.makedirs(ELEVATE_DIR, exist_ok=True)
            marker = os.path.join(ELEVATE_DIR, uuid.uuid4().hex + ".ok")
            if os.path.isfile(marker):
                os.remove(marker)

            if getattr(sys, "frozen", False):
                exe, params = sys.executable, f'--elevated-token "{marker}"'
            else:
                exe = sys.executable
                pyw = os.path.join(os.path.dirname(sys.executable), "pythonw.exe")
                if os.path.isfile(pyw):
                    exe = pyw              # 用 pythonw 启动，新实例不会带控制台窗口
                params = f'"{os.path.join(HERE, "gui.py")}" --elevated-token "{marker}"'

            # nShow 传 SW_SHOWNORMAL：传 0(SW_HIDE) 会让新实例的窗口不可见
            ok, err = shell_execute_ex(exe, params, HERE, ELEVATE_VERB, SW_SHOWNORMAL)
            if not ok:
                if err in (ERROR_CANCELLED, SE_ERR_ACCESSDENIED):
                    _info(self, "已取消提权",
                          "未获得管理员授权（在 UAC 弹窗中选择了“否”）。\n"
                          "程序继续以普通权限运行。")
                else:
                    _error(self, "提权失败",
                           f"系统拒绝了提权请求（错误码 {err}）。\n"
                           "稍后也可关闭程序，右键程序图标选择“以管理员身份运行”。")
                return

            self._watch_elevated(marker)
        except Exception as exc:
            _error(self, "提权失败", friendly(exc))

    def _watch_elevated(self, marker: str, timeout_ms: int = ELEVATE_TIMEOUT_MS):
        """等待提权实例的启动确认；确认到手才关闭当前窗口。"""
        self._elev_marker = marker
        self._elev_waited = 0
        self._elev_timeout = timeout_ms
        if self._elev_timer is None:
            self._elev_timer = QTimer(self)
            self._elev_timer.setInterval(250)
            self._elev_timer.timeout.connect(self._tick_elevated)
        self._elev_timer.start()
        self.status.setText("已发出提权请求，正在等待管理员实例启动 …")

    def _tick_elevated(self):
        self._elev_waited += 250
        if self._elev_marker and os.path.isfile(self._elev_marker):
            self._elev_timer.stop()
            try:
                os.remove(self._elev_marker)
            except OSError:
                pass
            self._elev_closing = True       # 切换实例，不再询问“是否退出”
            self.close()
            return
        if self._elev_waited >= self._elev_timeout:
            self._elev_timer.stop()
            _info(self, "未确认提权实例",
                  "已发出提权请求，但 15 秒内没有收到新实例的启动确认。\n\n"
                  "请先看屏幕上是否已出现新的程序窗口：\n"
                  "    · 有 → 可直接关闭当前窗口，使用新窗口即可\n"
                  "    · 没有 → 提权未成功，当前窗口继续以普通权限运行，\n"
                  "      也可右键程序图标选择“以管理员身份运行”")
            self.status.setText("提权实例未确认，继续以普通权限运行。")

    # ---------------- 单实例锁的接管与查询（提权实例专用） ----------------

    def start_handoff_takeover(self, guard, timeout_ms: int | None = None):
        """提权实例接管单实例锁（延后执行，注意顺序）。

        为什么必须延后：前任实例唯一的退出触发条件是"交接标记文件出现"，
        而标记要等本窗口 show 之后才写。如果反过来先抢锁再起窗口，双方会互相
        等到超时（前任等不到标记 → 不退出；本实例等不到锁 → 接管失败），
        提权功能整体失效。所以顺序固定为：
            起窗口 → 写交接标记 → 前任退出并释放锁 → 本实例接管
        """
        self._takeover_guard = guard
        self._takeover_waited = 0
        self._takeover_timeout = (single_mod.ELEVATE_HANDOFF_WAIT_MS
                                  if timeout_ms is None else timeout_ms)
        if self._takeover_timer is None:
            self._takeover_timer = QTimer(self)
            self._takeover_timer.setInterval(single_mod.HANDOFF_POLL_MS)
            self._takeover_timer.timeout.connect(self._tick_takeover)
        self._takeover_timer.start()
        self.status.setText("已接管界面，正在等待前一个实例退出并交接单实例运行锁 …")

    def _tick_takeover(self):
        guard = self._takeover_guard
        self._takeover_waited += single_mod.HANDOFF_POLL_MS
        if guard is None:
            self._takeover_timer.stop()
            return
        if not guard.held:                      # 非阻塞试探：能拿到就拿，拿不到就等
            ok, _holder = guard.acquire()
            if ok and guard.held:
                self._takeover_timer.stop()
                self.status.setText("已接管单实例运行锁（前一个实例已退出）。")
                return
        else:
            self._takeover_timer.stop()
            return
        if self._takeover_waited >= self._takeover_timeout:
            # 前任卡死不能把用户主动发起的提权挡死：降级继续运行，但如实说明
            self._takeover_timer.stop()
            guard.degraded = True
            self.status.setText("未接管单实例运行锁：前一个实例似乎仍未退出，"
                                "已降级继续运行（此时可能出现两个实例）。")

    def show_instance_info(self):
        """查看当前单实例锁状态（排查"为什么说程序已在运行"）。

        顺带列出本程序自身的进程组：单文件（onefile）版运行时正常会有两个同名
        进程（引导器 + 应用本体），这是"切到管理员模式后看到两个本程序进程"的
        真正原因，在这里说清楚，免得被当成旧实例没退出。
        """
        info_lines = []

        def _append_self_group(lines):
            group = scan_mod.collect_self_group()
            if not group:
                return
            lines.append("")
            lines.append(f"本程序自身的进程（共 {len(group)} 个）：")
            for r in group:
                lines.append(f"    PID {r['pid']}　{r['role']}　{r['rss_mb']} MB"
                             + ("　← 当前窗口" if r.get("is_me") else ""))
            if len(group) > 1:
                lines.append("    说明：单文件（onefile）版运行时必然同时存在引导器与应用")
                lines.append("    两个同名进程（命令行完全相同），属正常结构，"
                             "不是旧实例没退出。")

        guard = self._takeover_guard or _GUARD
        if guard is None:
            info_lines.append("本次启动跳过了单实例检测（--smoke / --allow-multi /"
                              " SYSSCAN_ALLOW_MULTI），因此没有持锁。")
            _append_self_group(info_lines)
            _info(self, "运行实例信息", "\n".join(info_lines))
            return
        st = guard.status()
        info_lines.append(f"实例标识：{st['key']}")
        info_lines.append(f"锁文件：{st['lock_path']}")
        if st["held"]:
            info_lines.append("本进程状态：已持有互斥体（唯一实例）")
        elif st["degraded"]:
            info_lines.append("本进程状态：降级运行（未持有互斥体）")
        else:
            info_lines.append("本进程状态：尚未持有互斥体（正在接管中）")
        holder = st.get("holder")
        if holder:
            h = single_mod.InstanceInfo(**{k: v for k, v in holder.items()
                                           if k in single_mod.InstanceInfo.__dataclass_fields__})
            state = "陈旧残留（占用者已不存在）" if st["holder_stale"] else "运行中"
            info_lines.append("")
            info_lines.append(f"锁文件记录的占用者：{state}")
            info_lines.append(h.describe("    "))
        _append_self_group(info_lines)
        _info(self, "运行实例信息", "\n".join(info_lines))

    # ---------------- 记录管理：新增 / 编辑 / 删除 ----------------

    def _inject_defaults(self, tab: str, rec: dict):
        rec.setdefault("note", "")
        if tab != "findings":
            rec.setdefault("risk", "正常")
        else:
            rec.setdefault("severity", "提示")

    def add_record(self):
        tab = TAB_ORDER[self.nb.currentIndex() - 1] if self.nb.currentIndex() > 0 else None
        if tab not in NEW_FIELDS:
            _info(self, "提示", "请先切换到要新增记录的数据页（进程/服务/连接/持久化/风险清单）。")
            return
        fields = NEW_FIELDS[tab]

        def on_ok(vals):
            if tab == "processes":
                try:
                    vals["pid"] = int(vals.get("pid") or 0)
                except ValueError:
                    raise ValueError("PID 必须是数字。")
            elif tab == "findings":
                vals["severity"] = vals.get("severity") or "提示"
            self._inject_defaults(tab, vals)
            self.data.setdefault(tab, []).insert(0, vals)
            self.refresh_all()
            self.status.setText(f"已在「{TAB_DEFS[tab]['title']}」中新增 1 条记录。")

        RecordForm(self, f"新增记录 · {TAB_DEFS[tab]['title']}", fields, {}, on_ok).exec()

    def edit_record(self, tab: str, rec: dict):
        fields = EDITABLE.get(tab)
        if not fields:
            _info(self, "提示", "该类型记录不支持编辑。")
            return
        origin = dict(rec)

        def on_ok(vals):
            rec.update(vals)
            if tab == "findings":
                if rec.get("severity") not in ("严重", "高危", "中危", "低危", "提示"):
                    raise ValueError("等级只能是：严重 / 高危 / 中危 / 低危 / 提示")
            else:
                if rec.get("risk") not in SEVS:
                    rec["risk"] = "正常"
                if "risk" in vals:
                    rec["_manual_risk"] = True   # 人工标记：连接自动刷新合并时保留
            self.refresh_all()
            self.status.setText("记录已更新（保存在内存数据中，可另存 JSON）。")

        RecordForm(self, f"编辑记录 · {TAB_DEFS[tab]['title']}", fields, origin, on_ok).exec()

    def delete_record(self, tab: str, rec: dict):
        label = _rec_label(rec)
        if not _ask(self, "确认删除",
                    f"确定要从当前数据中删除这条「{TAB_DEFS[tab]['title']}」记录吗？\n\n"
                    f"{label}\n\n"
                    "（仅从数据集移除，不会修改系统本身；如需持久化请保存 JSON）"):
            return
        try:
            self.data.get(tab, []).remove(rec)
        except ValueError:
            pass
        self.refresh_all()
        self.status.setText("已删除 1 条记录（仅当前数据集）。")

    # ---------------- 文件操作 ----------------

    def open_json(self):
        path, _f = QFileDialog.getOpenFileName(self, "打开扫描结果", "",
                                               "JSON 文件 (*.json);;所有文件 (*.*)")
        if path:
            self.load_json_file(path)

    def load_json_file(self, path: str, quiet: bool = False):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key in ("processes", "services", "connections", "persistence", "findings"):
            if key not in data or not isinstance(data[key], list):
                raise ValueError(f"文件缺少必需的字段：{key}")
        for key in ("processes", "services", "connections", "persistence", "findings"):
            for rec in data[key]:
                self._inject_defaults(key, rec)
        self.data = data
        self.refresh_all()
        self.status.setText(f"已加载：{path}")
        if not quiet:
            _info(self, "加载完成", f"已加载扫描结果：\n{path}")

    def save_json(self):
        path, _f = QFileDialog.getSaveFileName(self, "保存扫描结果", "scan_result.json",
                                               "JSON 文件 (*.json)")
        if not path:
            return
        try:
            scan_mod.save_json(self.data, path)
            self.status.setText(f"已保存：{path}")
            _info(self, "保存成功", f"已保存到：\n{path}")
        except Exception as exc:
            _error(self, "保存失败", friendly(exc))

    def export_html(self):
        path, _f = QFileDialog.getSaveFileName(self, "导出 HTML 报告", "report.html",
                                               "HTML 文件 (*.html)")
        if not path:
            return
        try:
            html_str = report_mod.build_html(self.data)
            with open(path, "w", encoding="utf-8") as f:
                f.write(html_str)
            self.status.setText(f"已导出：{path}")
            if _ask(self, "导出成功", "HTML 报告已生成，是否立即在浏览器中打开？"):
                webbrowser.open("file:///" + path.replace("\\", "/"))
        except Exception as exc:
            _error(self, "导出失败", friendly(exc))

    def export_csv(self):
        tab = TAB_ORDER[self.nb.currentIndex() - 1] if self.nb.currentIndex() > 0 else None
        if tab not in TAB_DEFS:
            _info(self, "提示", "请先切换到要导出的数据页。")
            return
        path, _f = QFileDialog.getSaveFileName(self, f"导出 {TAB_DEFS[tab]['title']} CSV",
                                               f"{tab}.csv", "CSV 文件 (*.csv)")
        if not path:
            return
        try:
            cols = [c[0] for c in TAB_DEFS[tab]["cols"]]
            with open(path, "w", encoding="utf-8-sig", newline="") as f:
                w = csv.writer(f)
                w.writerow([c[1] for c in TAB_DEFS[tab]["cols"]])
                for rec in self.data.get(tab, []):
                    w.writerow([self._cell(rec, k) for k in cols])
            self.status.setText(f"已导出：{path}")
            _info(self, "导出成功", f"已导出当前页数据到：\n{path}")
        except Exception as exc:
            _error(self, "导出失败", friendly(exc))

    # ---------------- 杂项 ----------------

    def clear_filter(self):
        self.search_box.clear()
        self.risk_combo.setCurrentIndex(0)
        self.refresh_all()

    # ---------------- 排序 ----------------

    def _current_tab(self) -> str | None:
        i = self.nb.currentIndex()
        return TAB_ORDER[i - 1] if i > 0 else None

    def reset_sort_current(self):
        tab = self._current_tab()
        if not tab:
            _info(self, "提示", "当前页没有可排序的列表。")
            return
        clear_sort(self.trees[tab])
        self._fill_tab(tab)
        self.status.setText(f"已恢复「{TAB_DEFS[tab]['title']}」列表的默认顺序。")

    def reset_sort_all(self):
        for tab in TAB_ORDER:
            clear_sort(self.trees[tab])
            self._fill_tab(tab)
        self.status.setText("已恢复各列表的默认顺序（点击列标题可重新排序）。")

    # ---------------- 自动刷新（分层轻刷新） ----------------

    def _refresh_metrics(self):
        """实时指标：CPU / 内存 / GPU 使用率 / 显存 / CPU+GPU 温度。

        只读系统计数，不碰任何表格数据；单次采样 1~12ms（PDH 直连，零子进程），
        所以可以 3 秒跑一次而不影响交互。拿不到的项一律显示 “—” 并说明原因，
        不猜数字。
        """
        try:
            m = self.sampler.sample()
        except Exception:
            return
        self._last_metrics = m
        try:
            self.metrics_panel.update_from(m)
        except Exception:
            pass

        self.live_lbl.setText(_live_status_text(m))
        self.live_lbl.setToolTip(
            f"每 {METRIC_INTERVAL_MS // 1000} 秒刷新（数据来源见「视图 → 指标数据来源…」）")

        if self._src_lines is None:
            try:
                self._src_lines = self.sampler.source_summary()
            except Exception:
                self._src_lines = []
        if self._src_lines:
            ok = [x.split("：", 1)[0] for x in self._src_lines if "不可用" not in x]
            hard = [x.split("：", 1)[0] for x in self._src_lines if "不可用" in x]
            hint = "本机可用：" + "、".join(ok)
            if hard:
                hint += "　取不到：" + "、".join(hard)
            self.metrics_panel.set_hint(hint)

    def _toggle_metrics(self, on: bool):
        if on:
            self._metric_timer.start(METRIC_INTERVAL_MS)
            self._refresh_metrics()
            self.status.setText("已开启实时硬件指标刷新（CPU / 内存 / GPU / 显存 / 温度）。")
        else:
            self._metric_timer.stop()
            self.live_lbl.setText("")
            self.status.setText("已暂停实时硬件指标刷新。")

    def show_metric_sources(self):
        """把「每个数字是从哪来的、为什么某项是 —」讲清楚，避免误读温度。"""
        lines = ["■ 本机各指标的数据来源", ""]
        for x in self.sampler.source_summary():
            lines.append("  · " + x)
        ad = self.sampler.adapters or []
        lines += ["", "■ 识别到的显卡"]
        lines.append("  · " + ("、".join(a["name"] for a in ad) if ad else "未识别到"))
        for a in ad:
            if a.get("vram"):
                lines.append(f"    - {a['name']}：显存 {a['vram'] / 1024 ** 3:.1f} GB"
                             "（注册表 qwMemorySize，比 WMI AdapterRAM 可靠）")
        m = self._last_metrics or {}
        lines += ["", "■ 本次读数"]
        if m:
            lines.append(f"  · CPU {_fmt_pct(m.get('cpu_pct'))}　"
                         f"内存 {_fmt_pct(m.get('mem_pct'))}　"
                         f"GPU {_fmt_pct(m.get('gpu_util'))}")
            lines.append(f"  · 显存 已用 {_fmt_gb(m.get('gpu_mem_used_gb'))}"
                         f"（独立 {_fmt_gb(m.get('gpu_mem_dedicated_gb'))} / "
                         f"共享 {_fmt_gb(m.get('gpu_mem_shared_gb'))}）")
            ct, gt = m.get("cpu_temp_c"), m.get("gpu_temp_c")
            lines.append(
                f"  · CPU 温度 {'—' if ct is None else f'{ct:.1f}°C'}"
                f" [{m.get('cpu_temp_src') or '—'}]　"
                f"GPU 温度 {'—' if gt is None else f'{gt:.1f}°C'}"
                f" [{m.get('gpu_temp_src') or '—'}]")
        lines += [
            "", "■ 口径说明",
            "  · GPU 使用率对齐任务管理器：同一引擎类型下所有进程求和，再取最忙的引擎。",
            "  · 采样走 Windows 性能计数器(PDH) 直连，不调用 nvidia-smi / PowerShell，",
            "    单次 1~12ms；监控程序自己高频拉起子进程既费 CPU，也容易被杀软误判。",
            "  · CPU 温度若显示为「ACPI 热区」，那是主板/机身热区，不等于 CPU 核心温度；",
            "    要拿真实封装温度，运行 LibreHardwareMonitor 后本工具会自动改用它的读数。",
            "  · 拿不到的指标显示 “—”，不会用估算值或 0 填充。",
        ]
        _info(self, "指标数据来源", "\n".join(lines))

    def _set_conn_autorefresh(self, on: bool):
        if on:
            self._conn_timer.start(CONN_REFRESH_MS)
            self._auto_refresh_connections()      # 开启后立即刷一次
            self.status.setText(
                f"已开启网络连接自动刷新（每 {CONN_REFRESH_MS // 1000} 秒，"
                "有对话框打开或正在扫描时自动暂停）。")
        else:
            self._conn_timer.stop()
            self.status.setText("已关闭网络连接自动刷新。")

    def _ui_busy(self) -> bool:
        """有模态对话框或弹出菜单时暂停刷新，避免数据在用户交互时被换行。"""
        return (QApplication.activeModalWidget() is not None
                or QApplication.activePopupWidget() is not None)

    def _auto_refresh_connections(self):
        """定时回调：只重采「网络连接」一层，进程/服务/持久化/风险清单不受影响。"""
        if self.scanning or self._conn_busy or self._ui_busy():
            return
        self._conn_busy = True

        def worker():
            try:
                names: dict[int, str] = {}
                for p in psutil.process_iter(["pid", "name"]):
                    names[p.info["pid"]] = p.info["name"] or ""
                conns = scan_mod.collect_connections(names)
                # 风险规则复用 scan.py：只取每条连接的 risk/reasons，临时 Findings 丢弃，
                # 避免轻刷新悄悄改写「风险清单」页（那应是完整扫描的职责）
                pmap = {p.get("pid"): p for p in self.data.get("processes", [])}
                light = [{"pid": pid, "name": nm,
                          "exe": (pmap.get(pid) or {}).get("exe", ""),
                          "path_source": (pmap.get(pid) or {}).get("path_source", "")}
                         for pid, nm in names.items()]
                F = scan_mod.Findings()
                scan_mod.analyze_connections(conns, light, F)
                self._msg_q.put(("conns", conns))
            except Exception as exc:
                self._msg_q.put(("connfail", exc, traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _merge_connections(self, new_conns: list[dict]):
        """用新采集的连接替换旧数据，保留旧记录上的人工标注（note / 手动风险标记）。"""
        old = {(c.get("proto"), c.get("laddr"), c.get("raddr"), c.get("pid")): c
               for c in self.data.get("connections", [])}
        for c in new_conns:
            o = old.get((c.get("proto"), c.get("laddr"), c.get("raddr"), c.get("pid")))
            if o:
                if o.get("note"):
                    c["note"] = o["note"]
                if o.get("_manual_risk"):
                    c["risk"] = o.get("risk", "")
                    c["_manual_risk"] = True
        self.data["connections"] = new_conns

    def closeEvent(self, event):
        self._metric_timer.stop()
        self._conn_timer.stop()
        if self._takeover_timer is not None:
            self._takeover_timer.stop()
        try:
            self.sampler.close()            # 关掉 PDH 查询句柄，别留着系统计数器
        except Exception:
            pass
        if self._elev_closing:
            # 正在切换到提权实例：必须在这里交棒（释放单实例锁），
            # 否则新实例要一直等到接管超时才能拿到锁。
            release_instance_lock()
            event.accept()
            return
        if self.scanning and not _ask(self, "确认退出", "扫描正在进行中，确定要退出吗？"):
            event.ignore()
            return
        release_instance_lock()
        event.accept()


def _arg_value(name: str) -> str:
    """读取 `--name value` 形式的命令行参数。"""
    if name in sys.argv:
        i = sys.argv.index(name)
        if i + 1 < len(sys.argv):
            return sys.argv[i + 1]
    return ""


def main():
    global _GUARD

    # ---------------- 单实例守卫（必须在建窗口、写任何文件之前） ----------------
    token = _arg_value("--elevated-token")
    guard = None
    if not single_instance_disabled():
        # 键与锁目录都取自模块（可用 SYSSCAN_INSTANCE_KEY / SYSSCAN_LOCK_DIR 覆盖，
        # 测试因此能在隔离的锁目录里并行跑，不干扰你正在使用的实例）
        guard = single_mod.InstanceGuard(single_mod.current_key(), elevated=is_admin())
        if not token:
            # 普通启动：抢不到锁 = 已有实例在运行 → 把它的窗口切到前台 + 提示 + 退出。
            # 此处尚未创建 QApplication、尚未创建窗口、尚未写任何文件，
            # 退出是干净的（不留下半截状态，也不会覆盖别人的 scan_result.json）。
            ok, holder = guard.acquire()
            if not ok:
                single_mod.report_conflict(holder, APP_TITLE, interactive=ui_allowed())
                sys.exit(EXIT_ALREADY_RUNNING)
        # token 非空 = 提权实例，是用户主动发起的实例替换，不能拒绝。
        # 但接管必须等前任退出，而前任要看到交接标记才肯退出（标记在窗口显示后才写），
        # 所以这里先不抢锁，延后到 win.show() 之后 —— 见 start_handoff_takeover()
        _GUARD = guard
        # 兜底：正常路径由 closeEvent 释放；异常退出由内核回收；
        # 这里再挂一个 atexit，覆盖"没走到 closeEvent 就结束"的情况（如 app.exec() 抛异常）
        atexit.register(release_instance_lock)

    app = QApplication(sys.argv)
    app.setApplicationName(APP_TITLE)
    QApplication.setStyle(QStyleFactory.create("Fusion"))
    app.setFont(QFont("Microsoft YaHei", 10))

    try:
        win = ScanApp()
    except Exception as exc:
        _error(None, "启动失败", f"界面初始化失败：\n{friendly(exc)}")
        sys.exit(1)
    win.show()

    # 提权实例的启动确认：窗口真正显示后写标记，通知原实例“可以退出了”
    if token:
        try:
            os.makedirs(os.path.dirname(token), exist_ok=True)
            with open(token, "w", encoding="utf-8") as f:
                f.write(str(os.getpid()))
        except Exception:
            pass
        # 前任看到标记后会释放单实例锁并退出，这时才能轮到我们接管（延后 + 有上限）
        if guard is not None:
            win.start_handoff_takeover(guard)

    if is_admin():
        win.setWindowTitle(APP_TITLE + "（管理员）")
        win.status.setText("已以管理员权限运行：服务管理、系统级计划任务等操作可用。")
    else:
        clean_elevate_dir()
        win.status.setText(win.status.text() + "　（当前为普通权限，可右键程序图标"\
                                              "选择“以管理员身份运行”）")

    if "--smoke" in sys.argv:
        # 冒烟自检：等一次真实指标采样落地再退出，把结果落盘。
        # 冻结的 windowed 程序没有 stdout，所以结果写文件而不是打印；
        # 这样能验证 PDH 取数链路在打包环境下也通，而不只是“窗口能打开”。
        def _smoke_report():
            m = win._last_metrics or {}
            payload = {
                "cpu_pct": m.get("cpu_pct"), "mem_pct": m.get("mem_pct"),
                "gpu_util": m.get("gpu_util"),
                "gpu_mem_used_gb": m.get("gpu_mem_used_gb"),
                "cpu_temp_c": m.get("cpu_temp_c"), "gpu_temp_c": m.get("gpu_temp_c"),
                "gpu_name": m.get("gpu_name"),
                "engine_groups": len(m.get("gpu_engines") or {}),
                "sources": win.sampler.source_summary(),
                "rows": {k: len(win.data.get(k) or []) for k in TAB_ORDER},
                "tile_texts": {k: t.value_lbl.text()
                               for k, t in win.metrics_panel.tiles.items()},
                # 本程序自身的进程组：冻结的单文件 exe 正常情况下应是 2 个
                # （引导器 + 应用本体），用它能在打包环境下验证这条链路
                "self_group": scan_mod.collect_self_group(),
            }
            try:
                with open(os.path.join(HERE, "smoke_result.json"), "w",
                          encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, indent=2)
            except Exception:
                pass
            try:
                if sys.stdout is not None:
                    print("SMOKE_METRICS " + json.dumps(payload, ensure_ascii=False),
                          flush=True)
                    print("SMOKE_OK", flush=True)
            except Exception:
                pass
            app.quit()

        QTimer.singleShot(4000, _smoke_report)
        app.exec()
        return

    app.exec()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # 全局兜底：任何未捕获异常都给出友好提示，不静默崩溃
        try:
            _a = QApplication.instance() or QApplication(sys.argv)
            _error(None, "程序错误", "发生未处理的错误，程序即将退出。\n\n"
                                   + friendly(sys.exc_info()[1]))
        finally:
            sys.exit(1)
