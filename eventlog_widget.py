# -*- coding: utf-8 -*-
"""Windows 事件日志界面展示层（界面层 / Layer 3）

把「数据读取层(eventlog_reader)」与「分析统计层(eventlog_stats)」的结果，
用 PySide6 呈现为一个独立标签页(EventLogPanel)。本文件是唯一碰 UI 的地方，
读取与分析都在后台线程/纯函数里完成，界面线程只负责画与交互——这样即使
日志量很大、读取较慢，主窗口也不会卡住。

────────────────────────────────────────────────────────────────────────
界面布局（自上而下）
────────────────────────────────────────────────────────────────────────
  筛选栏  通道 / 级别 / 时间范围 / 事件ID / 来源 / 关键字  + 查询·重置·导出
  进度条  查询中显示读取进度
  分隔条(上下)
    上：日志列表表格(QTableWidget) + 底部分页导航(首页/上/下/末页 + 每页N)
    下：统计分析(QTabWidget)
          「级别与错误」：级别分布柱状图 + 高频异常表
          「趋势与来源」：时间趋势柱状图 + 来源 TOP 表
  状态栏  条数 / 截断提示 / 异常原因

────────────────────────────────────────────────────────────────────────
筛选的两段式（兼顾快与灵活）
────────────────────────────────────────────────────────────────────────
- 结构性筛选（通道 / 级别 / 时间 / 事件ID / 来源）走 XPath 在服务端做，
  「查询」按钮才会触发重新读取；XPath 表达不了的全字段模糊匹配（关键字）
  在已取回的数据上客户端秒筛，输入即过滤、不碰磁盘。
- 这样「级别/时间」等重筛选是快且省内存的；「关键字」是即时、无感的。
"""

from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta

from PySide6.QtCore import Qt, QThread, Signal, QSize, QDateTime
from PySide6.QtGui import (QColor, QBrush, QFont, QPainter, QPen, QPalette)
from PySide6.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout, QGroupBox,
                              QLabel, QLineEdit, QComboBox, QCheckBox, QPushButton,
                              QDateTimeEdit, QTableWidget, QTableWidgetItem,
                              QHeaderView, QAbstractItemView, QSplitter, QTabWidget,
                              QProgressBar, QFrame, QMessageBox, QFileDialog, QDialog,
                              QTextEdit, QSizePolicy)

import eventlog_reader as evr
import eventlog_stats as evs
from eventlog_reader import LEVEL_NUM_TO_NAME

# 级别 → 表格行底色 / 柱状图颜色（与 gui.py 风险配色风格一致的浅色调）
LEVEL_BG = {
    "严重": "#fde8e8", "错误": "#fdecea", "警告": "#fef3e6",
    "信息": "#f4f6f8", "详细": "#eef2f7",
}
LEVEL_FG = {
    "严重": "#7f1d1d", "错误": "#b42318", "警告": "#b45309",
    "信息": "#475569", "详细": "#6b7280",
}
LEVEL_SEVERITY = {"严重": 0, "错误": 1, "警告": 2, "信息": 3, "详细": 4}

TIME_PRESETS = ["全部", "近1小时", "近24小时", "近7天", "近30天", "自定义"]

PAGE_SIZE_DEFAULT = 200


# ==========================================================================
# 后台读取线程：把磁盘读取挪出 UI 线程，避免界面阻塞
# ==========================================================================
class LogLoadWorker(QThread):
    progress = Signal(int, bool)            # (已读取条数, 是否截断)
    finished = Signal(list, dict)           # (records, meta)
    error = Signal(str, str)                # (标题, 友好信息)

    def __init__(self, channel: str, filters: dict, max_records: int):
        super().__init__()
        self._channel = channel
        self._filters = filters
        self._max = max_records
        self._stop = False

    def cancel(self):
        self._stop = True

    def run(self):
        try:
            reader = evr.EventLogReader()
            records, meta = reader.query(
                self._channel, self._filters, max_records=self._max,
                stop=lambda: self._stop,
                on_progress=lambda n, tr: self.progress.emit(n, tr),
            )
            if self._stop:
                return
            self.finished.emit(records, meta)
        except evr.EventLogAccessDenied as e:
            self.error.emit("权限不足", str(e))
        except evr.EventLogChannelNotFound as e:
            self.error.emit("通道不存在", str(e))
        except evr.EventLogServiceUnavailable as e:
            self.error.emit("日志服务不可用", str(e))
        except evr.EventLogTimeout as e:
            self.error.emit("读取超时", str(e))
        except evr.EventLogUnavailable as e:
            self.error.emit("环境不支持", str(e))
        except evr.EventLogReadError as e:
            self.error.emit("读取失败", str(e))
        except Exception as e:                      # 兜底：不让线程静默崩溃
            self.error.emit("读取失败", f"{e.__class__.__name__}: {e}")


# ==========================================================================
# QPainter 横向柱状图（零依赖：不用 QtCharts，保持打包精简）
# ==========================================================================
class BarChartView(QWidget):
    """通用横向柱状图：传入 [(label, value, color), ...] 即可。

    级别分布、时间趋势共用这一个控件；避免了引入 QtCharts（PySide6-Essentials
    未含）或 matplotlib（打包体积与依赖都不划算）。
    """

    def __init__(self, parent=None, unit: str = ""):
        super().__init__(parent)
        self._data: list[tuple[str, int, str]] = []
        self._unit = unit
        self.setMinimumHeight(120)
        self._row_h = 26
        self._label_w = 96

    def setData(self, data: list[tuple[str, int, str]], unit: str = ""):
        self._data = data
        if unit:
            self._unit = unit
        n = max(len(data), 1)
        self.setMinimumHeight(n * self._row_h + 16)
        self.update()

    def paintEvent(self, ev):
        from PySide6.QtCore import QRect
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        w = self.width()
        h = self.height()
        p.fillRect(QRect(0, 0, w, h), QColor("#ffffff"))
        if not self._data:
            p.setPen(QColor("#9ca3af"))
            p.drawText(QRect(8, 0, w - 16, h), Qt.AlignmentFlag.AlignVCenter, "（无数据）")
            return

        maxv = max((v for _, v, _ in self._data), default=1) or 1
        bar_left = self._label_w
        bar_right = w - 64                  # 右侧留给数值
        bar_w = max(bar_right - bar_left, 10)

        p.setFont(QFont("Microsoft YaHei", 9))
        for i, (label, value, color) in enumerate(self._data):
            y = 8 + i * self._row_h
            # 左侧标签
            p.setPen(QColor("#374151"))
            p.drawText(QRect(4, y, self._label_w - 6, self._row_h),
                       Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter,
                       label)
            # 柱体
            bw = int(bar_w * (value / maxv)) if maxv else 0
            p.fillRect(QRect(bar_left, y + 4, max(bw, 1), self._row_h - 10),
                       QColor(color))
            # 数值
            p.setPen(QColor("#111827"))
            p.drawText(QRect(bar_right, y, 56, self._row_h),
                       Qt.AlignmentFlag.AlignLeft | Qt.AlignmentFlag.AlignVCenter,
                       f"{value:,}")
        p.end()


# ==========================================================================
# 单条事件详情对话框
# ==========================================================================
class EventDetailDialog(QDialog):
    def __init__(self, parent, rec: dict):
        super().__init__(parent)
        self.setWindowTitle(f"事件详情 · {rec.get('channel', '')}")
        self.resize(760, 560)
        lay = QVBoxLayout(self)
        lay.setSpacing(8)

        head = rec.get("source") or "?"
        eid = rec.get("event_id")
        title = f"{head}" + (f"  事件ID {eid}" if eid is not None else "")
        lbl = QLabel(title)
        f = lbl.font(); f.setBold(True); f.setPointSize(f.pointSize() + 2)
        lbl.setFont(f)
        lay.addWidget(lbl)
        if rec.get("level") and rec["level"] != "信息":
            lv = QLabel(f"[{rec['level']}]")
            lv.setStyleSheet(f"color:{LEVEL_FG.get(rec['level'], '#333')};font-weight:bold;")
            # 放到标题右侧
            hb = QHBoxLayout(); hb.addWidget(lbl); hb.addWidget(lv); hb.addStretch(1)
            lay.addLayout(hb)

        tv = QTableWidget(0, 2)
        tv.setHorizontalHeaderLabels(["字段", "值"])
        tv.verticalHeader().setVisible(False)
        tv.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.Fixed)
        tv.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        tv.setColumnWidth(0, 120)
        tv.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        for k in ("time", "level", "event_id", "source", "channel",
                  "computer", "record_id", "keywords"):
            v = rec.get(k, "")
            if v in (None, ""):
                continue
            row = tv.rowCount(); tv.insertRow(row)
            tv.setItem(row, 0, QTableWidgetItem(str(k)))
            tv.setItem(row, 1, QTableWidgetItem(str(v)))
        lay.addWidget(tv)

        lay.addWidget(QLabel("描述："))
        desc = QTextEdit()
        desc.setReadOnly(True)
        desc.setPlainText(rec.get("description", ""))
        desc.setMaximumHeight(140)
        lay.addWidget(desc)

        lay.addWidget(QLabel("原始 XML："))
        xml = QTextEdit()
        xml.setReadOnly(True)
        xml.setPlainText(rec.get("xml", ""))
        lay.addWidget(xml, 1)

        btns = QHBoxLayout()
        btns.addStretch(1)
        copy = QPushButton("复制 XML")
        copy.clicked.connect(lambda: self._copy(rec.get("xml", "")))
        btns.addWidget(copy)
        close = QPushButton("关闭")
        close.clicked.connect(self.accept)
        btns.addWidget(close)
        lay.addLayout(btns)

    @staticmethod
    def _copy(text: str):
        try:
            QApplication_clipboard(text)
        except Exception:
            pass


def QApplication_clipboard(text: str):
    from PySide6.QtWidgets import QApplication
    QApplication.clipboard().setText(text)


# ==========================================================================
# 主面板
# ==========================================================================
class EventLogPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._fetched: list[dict] = []      # 从磁盘取回的原始记录（未做关键字筛选）
        self._all: list[dict] = []          # 关键字筛选 + 排序后的记录（分页源）
        self._page = 0
        self._page_size = PAGE_SIZE_DEFAULT
        self._sort_col = "time"
        self._sort_asc = False              # 默认时间倒序（新→旧）
        self._loading = False
        self._worker: LogLoadWorker | None = None
        self._loaded_once = False

        # 状态标签必须先于 _build_body 创建（主体布局末尾会引用它）
        self.status = QLabel("点击「查询 / 刷新」加载所选日志通道。")
        self.status.setStyleSheet("color:#6b7280;")

        self._build_filter_bar()
        self._build_body()
        self._build_status()

    # ---------------- 构建：筛选栏 ----------------
    def _build_filter_bar(self):
        box = QGroupBox("筛选")
        lay = QVBoxLayout(box)
        lay.setSpacing(6)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("通道："))
        self.channel_cb = QComboBox()
        self.channel_cb.addItems(evr.DEFAULT_CHANNELS)
        self.channel_cb.setFixedWidth(280)
        row1.addWidget(self.channel_cb)

        row1.addWidget(QLabel("级别："))
        self.level_boxes: dict[str, QCheckBox] = {}
        for lv in ["信息", "警告", "错误", "严重", "详细"]:
            cb = QCheckBox(lv)
            cb.setChecked(True)
            self.level_boxes[lv] = cb
            row1.addWidget(cb)
        self.btn_level_all = QPushButton("全选")
        self.btn_level_all.setFixedWidth(56)
        self.btn_level_all.clicked.connect(lambda: self._set_levels(True))
        self.btn_level_none = QPushButton("清空")
        self.btn_level_none.setFixedWidth(56)
        self.btn_level_none.clicked.connect(lambda: self._set_levels(False))
        row1.addWidget(self.btn_level_all)
        row1.addWidget(self.btn_level_none)
        row1.addStretch(1)
        lay.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("时间范围："))
        self.time_cb = QComboBox()
        self.time_cb.addItems(TIME_PRESETS)
        self.time_cb.setCurrentText("近24小时")
        self.time_cb.setFixedWidth(110)
        self.time_cb.currentTextChanged.connect(self._on_time_preset)
        row2.addWidget(self.time_cb)
        self.dt_from = QDateTimeEdit(QDateTime.currentDateTime().addSecs(-24 * 3600))
        self.dt_to = QDateTimeEdit(QDateTime.currentDateTime())
        for dt in (self.dt_from, self.dt_to):
            dt.setDisplayFormat("yyyy-MM-dd HH:mm")
            dt.setCalendarPopup(True)
            dt.setFixedWidth(150)
            dt.setEnabled(False)           # 仅「自定义」时可用
        row2.addWidget(self.dt_from)
        row2.addWidget(QLabel("至"))
        row2.addWidget(self.dt_to)

        row2.addWidget(QLabel("事件ID："))
        self.eid_edit = QLineEdit()
        self.eid_edit.setPlaceholderText("逗号分隔，如 1001,1000")
        self.eid_edit.setFixedWidth(160)
        row2.addWidget(self.eid_edit)

        row2.addWidget(QLabel("来源："))
        self.src_edit = QLineEdit()
        self.src_edit.setPlaceholderText("逗号分隔 Provider 名")
        self.src_edit.setFixedWidth(180)
        row2.addWidget(self.src_edit)
        row2.addStretch(1)
        lay.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("关键字/搜索："))
        self.kw_edit = QLineEdit()
        self.kw_edit.setPlaceholderText("在已取回日志中按 描述/来源/事件ID 模糊匹配（即时）")
        self.kw_edit.textChanged.connect(self._on_keyword)
        row3.addWidget(self.kw_edit, 1)

        self.max_spin = QComboBox()
        self.max_spin.addItems(["1000", "5000", "20000", "50000"])
        self.max_spin.setCurrentText("5000")
        self.max_spin.setFixedWidth(90)
        row3.addWidget(QLabel("最多取回："))
        row3.addWidget(self.max_spin)
        row3.addWidget(QLabel("条"))

        self.btn_query = QPushButton("▶ 查询 / 刷新")
        self.btn_query.clicked.connect(self.run_query)
        row3.addWidget(self.btn_query)
        self.btn_reset = QPushButton("重置筛选")
        self.btn_reset.clicked.connect(self._reset_filters)
        row3.addWidget(self.btn_reset)
        self.btn_csv = QPushButton("导出 CSV")
        self.btn_csv.clicked.connect(lambda: self._export("csv"))
        row3.addWidget(self.btn_csv)
        self.btn_json = QPushButton("导出 JSON")
        self.btn_json.clicked.connect(lambda: self._export("json"))
        row3.addWidget(self.btn_json)
        lay.addLayout(row3)

        outer = QVBoxLayout()
        outer.addWidget(box)
        self._filter_box = box
        # 把筛选栏放进主布局由 _build_body 统一处理，这里把 box 直接用于布局
        self._filter_layout = outer

    def _set_levels(self, on: bool):
        for cb in self.level_boxes.values():
            cb.setChecked(on)

    def _on_time_preset(self, text: str):
        custom = text == "自定义"
        self.dt_from.setEnabled(custom)
        self.dt_to.setEnabled(custom)

    def _on_keyword(self):
        # 关键字只做客户端筛选，不重新读盘：即时、无感
        if not self._fetched:
            return
        self._apply_client_filter()
        self._page = 0
        self._fill_page()
        self._update_status()

    def _reset_filters(self):
        self.channel_cb.setCurrentIndex(0)
        self._set_levels(True)
        self.time_cb.setCurrentText("近24小时")
        self._on_time_preset("近24小时")
        self.eid_edit.clear()
        self.src_edit.clear()
        self.kw_edit.clear()
        self.run_query()

    # ---------------- 构建：主体（分隔条 + 表格 + 分析）----------------
    def _build_body(self):
        main = QVBoxLayout(self)
        main.setSpacing(6)
        main.addLayout(self._filter_layout)

        self.progress = QProgressBar()
        self.progress.setFixedHeight(10)
        self.progress.setValue(0)
        self.progress.setVisible(False)
        main.addWidget(self.progress)

        split = QSplitter(Qt.Orientation.Vertical)

        # ---- 上：列表 + 分页 ----
        top = QWidget()
        tv = QVBoxLayout(top)
        tv.setSpacing(4)
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["时间", "来源", "事件ID", "级别", "描述"])
        self.table.verticalHeader().setVisible(False)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.table.setWordWrap(False)
        self.table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.table.cellDoubleClicked.connect(
            lambda r, c: self._show_detail(r))
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        hh.setStretchLastSection(True)
        self.table.setColumnWidth(0, 150)
        self.table.setColumnWidth(1, 220)
        self.table.setColumnWidth(2, 80)
        self.table.setColumnWidth(3, 60)
        # 点击列标题排序（排序作用于完整数据集，再回到当前页）
        hh.sectionClicked.connect(self._on_header_clicked)
        hh.setSortIndicatorShown(True)
        tv.addWidget(self.table, 1)

        # 分页导航
        pg = QHBoxLayout()
        self.btn_first = QPushButton("首页")
        self.btn_prev = QPushButton("上一页")
        self.btn_next = QPushButton("下一页")
        self.btn_last = QPushButton("末页")
        for b, fn in [(self.btn_first, self._first_page),
                      (self.btn_prev, self._prev_page),
                      (self.btn_next, self._next_page),
                      (self.btn_last, self._last_page)]:
            b.clicked.connect(fn)
            pg.addWidget(b)
        pg.addWidget(QLabel("第"))
        self.page_label = QLabel("1 / 1")
        pg.addWidget(self.page_label)
        pg.addWidget(QLabel("页"))
        pg.addWidget(QLabel("每页"))
        self.page_size_cb = QComboBox()
        self.page_size_cb.addItems(["100", "200", "500", "1000"])
        self.page_size_cb.setCurrentText(str(self._page_size))
        self.page_size_cb.setFixedWidth(80)
        self.page_size_cb.currentTextChanged.connect(self._on_page_size)
        pg.addWidget(self.page_size_cb)
        pg.addWidget(QLabel("条"))
        pg.addStretch(1)
        tv.addLayout(pg)
        split.addWidget(top)

        # ---- 下：统计分析 ----
        self.analysis = QTabWidget()
        # 选项卡一：级别分布 + 高频异常
        tab1 = QWidget()
        t1 = QHBoxLayout(tab1)
        self.level_chart = BarChartView(unit="条")
        self.level_chart.setMinimumWidth(360)
        t1.addWidget(self.level_chart, 1)
        self.err_table = QTableWidget(0, 4)
        self.err_table.setHorizontalHeaderLabels(["事件ID", "来源", "次数", "级别"])
        self.err_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.err_table.verticalHeader().setVisible(False)
        self.err_table.horizontalHeader().setStretchLastSection(True)
        self.err_table.doubleClicked.connect(self._on_err_row_double)
        t1.addWidget(self.err_table, 1)
        self.analysis.addTab(tab1, "级别与错误")

        # 选项卡二：时间趋势 + 来源 TOP
        tab2 = QWidget()
        t2 = QHBoxLayout(tab2)
        self.trend_chart = BarChartView(unit="条")
        self.trend_chart.setMinimumWidth(360)
        t2.addWidget(self.trend_chart, 1)
        self.src_table = QTableWidget(0, 2)
        self.src_table.setHorizontalHeaderLabels(["来源", "次数"])
        self.src_table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.src_table.verticalHeader().setVisible(False)
        self.src_table.horizontalHeader().setStretchLastSection(True)
        t2.addWidget(self.src_table, 1)
        self.analysis.addTab(tab2, "趋势与来源")

        split.addWidget(self.analysis)
        split.setStretchFactor(0, 3)
        split.setStretchFactor(1, 2)
        main.addWidget(split, 1)
        main.addWidget(self.status)

    def _build_status(self):
        # 状态标签已在 __init__ 创建、在 _build_body 末尾加入布局；这里仅设初始文案。
        self.status.setText("点击「查询 / 刷新」加载所选日志通道。")

    # ---------------- 时间范围解析 ----------------
    def _time_range_from_ui(self):
        pres = self.time_cb.currentText()
        now = datetime.now()
        if pres == "全部":
            return None, None
        if pres == "自定义":
            return (self.dt_from.dateTime().toPython(),
                    self.dt_to.dateTime().toPython())
        if pres == "近1小时":
            return now - timedelta(hours=1), now
        if pres == "近24小时":
            return now - timedelta(hours=24), now
        if pres == "近7天":
            return now - timedelta(days=7), now
        if pres == "近30天":
            return now - timedelta(days=30), now
        return None, None

    def _levels_from_ui(self):
        chosen = [lv for lv, cb in self.level_boxes.items() if cb.isChecked()]
        return chosen if chosen else None        # 全空 = 不过滤（取全部级别）

    def _parse_ints(self, text: str) -> list[int] | None:
        out = []
        for part in text.split(","):
            part = part.strip()
            if part:
                try:
                    out.append(int(part))
                except ValueError:
                    pass
        return out or None

    def _parse_list(self, text: str) -> list[str] | None:
        out = [p.strip() for p in text.split(",") if p.strip()]
        return out or None

    # ---------------- 查询（读盘）----------------
    def run_query(self):
        if self._loading:
            return
        filters = {
            "levels": self._levels_from_ui(),
            "event_ids": self._parse_ints(self.eid_edit.text()),
            "providers": self._parse_list(self.src_edit.text()),
        }
        tf, tt = self._time_range_from_ui()
        if tf is not None:
            filters["time_from"] = tf
        if tt is not None:
            filters["time_to"] = tt

        try:
            maxv = int(self.max_spin.currentText())
        except ValueError:
            maxv = evr.DEFAULT_MAX_RECORDS

        self._loading = True
        self.btn_query.setEnabled(False)
        self.btn_query.setText("查询中…")
        self.progress.setVisible(True)
        self.progress.setValue(0)
        self.status.setText(f"正在读取「{self.channel_cb.currentText()}」日志…")

        self._worker = LogLoadWorker(self.channel_cb.currentText(), filters, maxv)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_finished)
        self._worker.error.connect(self._on_error)
        self._worker.start()

    def _on_progress(self, n: int, truncated: bool):
        self.progress.setValue(min(int(n / max(int(self.max_spin.currentText() or 1), 1)
                                            * 100), 100))
        self.status.setText(f"已读取 {n} 条…" + ("（已达上限，停止）" if truncated else ""))

    def _on_finished(self, records: list[dict], meta: dict):
        self._loading = False
        self._worker = None
        self.btn_query.setEnabled(True)
        self.btn_query.setText("▶ 查询 / 刷新")
        self.progress.setVisible(False)
        self._fetched = records
        self._meta = meta
        self._apply_client_filter()
        self._page = 0
        self._fill_page()
        self._fill_analysis()
        self._loaded_once = True
        self._update_status()

    def _on_error(self, title: str, msg: str):
        self._loading = False
        self._worker = None
        self.btn_query.setEnabled(True)
        self.btn_query.setText("▶ 查询 / 刷新")
        self.progress.setVisible(False)
        self.status.setText(f"❌ {title}：{msg}")
        self.status.setStyleSheet("color:#b42318;")
        # 权限场景给一次明确的「以管理员重新运行」引导
        if title == "权限不足":
            win = self.window()
            if hasattr(win, "run_as_admin"):
                if QMessageBox.question(self, title,
                        msg + "\n\n是否现在以管理员身份重新运行？",
                        QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.No
                        ) == QMessageBox.StandardButton.Yes:
                    win.run_as_admin()
                    return
        QMessageBox.warning(self, title, msg)
        self.status.setStyleSheet("color:#6b7280;")

    # ---------------- 客户端关键字筛选 + 排序 ----------------
    def _apply_client_filter(self):
        kw = self.kw_edit.text().strip().lower()
        if kw:
            self._all = [r for r in self._fetched
                         if kw in (str(r.get("description", "")).lower()
                                   or str(r.get("source", "")).lower()
                                   or str(r.get("event_id", "")).lower()
                                   or str(r.get("computer", "")).lower()
                                   or str(r.get("keywords", "")).lower())]
        else:
            self._all = list(self._fetched)
        self._sort_all()

    def _sort_key(self, rec: dict):
        col = self._sort_col
        asc = self._sort_asc
        if col == "time":
            v = rec.get("ts") if rec.get("ts") is not None else -1e18
            return (0 if asc else 1, v)
        if col == "level":
            return (0 if asc else 1, LEVEL_SEVERITY.get(rec.get("level"), 9))
        if col == "event_id":
            return (0 if asc else 1, rec.get("event_id") if rec.get("event_id") is not None else -1)
        # 文本列：自然序
        return (0 if asc else 1, str(rec.get(col, "")).lower())

    def _sort_all(self):
        self._all.sort(key=self._sort_key)

    def _on_header_clicked(self, col: int):
        keys = ["time", "source", "event_id", "level", "description"]
        if col < 0 or col >= len(keys):
            return
        if self._sort_col == keys[col]:
            self._sort_asc = not self._sort_asc
        else:
            self._sort_col = keys[col]
            self._sort_asc = (keys[col] == "time")   # 时间默认倒序，其它默认升序
        self.table.horizontalHeader().setSortIndicator(
            col, Qt.SortOrder.AscendingOrder if self._sort_asc else Qt.SortOrder.DescendingOrder)
        self._sort_all()
        self._fill_page()

    # ---------------- 分页 ----------------
    def _page_count(self) -> int:
        return max(1, (len(self._all) + self._page_size - 1) // self._page_size)

    def _on_page_size(self, text: str):
        try:
            self._page_size = int(text)
        except ValueError:
            return
        self._page = min(self._page, self._page_count() - 1)
        self._fill_page()

    def _first_page(self):
        self._page = 0; self._fill_page()

    def _prev_page(self):
        self._page = max(0, self._page - 1); self._fill_page()

    def _next_page(self):
        self._page = min(self._page_count() - 1, self._page + 1); self._fill_page()

    def _last_page(self):
        self._page = self._page_count() - 1; self._fill_page()

    # ---------------- 填充表格当前页 ----------------
    def _fill_page(self):
        self.table.setRowCount(0)
        if not self._all:
            self.page_label.setText("0 / 0")
            self.btn_first.setEnabled(False); self.btn_prev.setEnabled(False)
            self.btn_next.setEnabled(False); self.btn_last.setEnabled(False)
            return
        pc = self._page_count()
        self._page = min(self._page, pc - 1)
        start = self._page * self._page_size
        end = min(start + self._page_size, len(self._all))
        for i in range(start, end):
            rec = self._all[i]
            row = self.table.rowCount()
            self.table.insertRow(row)
            lv = rec.get("level", "信息")
            cells = [
                (rec.get("time", ""), "time"),
                (rec.get("source", ""), "source"),
                (str(rec.get("event_id")) if rec.get("event_id") is not None else "",
                 "event_id"),
                (lv, "level"),
                (_clip(rec.get("description", ""), 80), "description"),
            ]
            for col, (text, _k) in enumerate(cells):
                it = QTableWidgetItem(str(text))
                it.setData(Qt.ItemDataRole.UserRole, rec)     # 存整条，双击看详情
                if _k == "level":
                    it.setForeground(QBrush(QColor(LEVEL_FG.get(lv, "#111"))))
                    it.setBackground(QBrush(QColor(LEVEL_BG.get(lv, "#fff"))))
                elif lv in LEVEL_BG and lv in ("严重", "错误", "警告"):
                    it.setBackground(QBrush(QColor(LEVEL_BG.get(lv, "#fff"))))
                self.table.setItem(row, col, it)
        self.page_label.setText(f"{self._page + 1} / {pc}")
        self.btn_first.setEnabled(self._page > 0)
        self.btn_prev.setEnabled(self._page > 0)
        self.btn_next.setEnabled(self._page < pc - 1)
        self.btn_last.setEnabled(self._page < pc - 1)

    # ---------------- 填充分析 ----------------
    def _fill_analysis(self):
        stats = evs.analyze(self._all)
        # 级别分布柱状图
        lv_data = [(lv, stats["by_level"][lv]["count"],
                    LEVEL_FG.get(lv, "#888"))
                   for lv in stats["by_level_order"]]
        self.level_chart.setData(lv_data, unit="条")

        # 高频异常表
        self.err_table.setRowCount(0)
        for e in stats["top_errors"]:
            row = self.err_table.rowCount(); self.err_table.insertRow(row)
            self.err_table.setItem(row, 0, QTableWidgetItem(str(e["event_id"])))
            self.err_table.setItem(row, 1, QTableWidgetItem(str(e["source"])))
            self.err_table.setItem(row, 2, QTableWidgetItem(str(e["count"])))
            lc = QTableWidgetItem(e["level"])
            lc.setForeground(QBrush(QColor(LEVEL_FG.get(e["level"], "#111"))))
            self.err_table.setItem(row, 3, lc)
        for c, w in enumerate((90, 230, 70, 60)):
            self.err_table.setColumnWidth(c, w)

        # 时间趋势柱状图（事件数 + 错误数叠加信息用颜色区分：这里画总数，
        # 错误数在 tooltip/数值里体现；为简洁只画总数，单位随跨度变化）
        tb = stats["time_buckets"]
        if tb:
            maxc = max((b["count"] for b in tb), default=1) or 1
            trend = [(b["label"], b["count"], "#2563eb") for b in tb]
            self.trend_chart.setData(trend, unit=stats["bucket_unit"])
        else:
            self.trend_chart.setData([], unit="")

        # 来源 TOP
        self.src_table.setRowCount(0)
        for s in stats["top_sources"]:
            row = self.src_table.rowCount(); self.src_table.insertRow(row)
            self.src_table.setItem(row, 0, QTableWidgetItem(str(s["source"])))
            self.src_table.setItem(row, 1, QTableWidgetItem(str(s["count"])))
        for c, w in enumerate((300, 70)):
            self.src_table.setColumnWidth(c, w)

        self._last_stats = stats

    def _on_err_row_double(self, index):
        if not getattr(self, "_last_stats", None):
            return
        row = index.row()
        errs = self._last_stats.get("top_errors", [])
        if 0 <= row < len(errs):
            e = errs[row]
            # 在列表里跳到该事件ID的首条匹配，并打开详情
            for rec in self._all:
                if rec.get("event_id") == e["event_id"] and rec.get("source") == e["source"]:
                    self._open_detail(rec)
                    return

    # ---------------- 详情 ----------------
    def _show_detail(self, row: int):
        it = self.table.item(row, 0)
        rec = it.data(Qt.ItemDataRole.UserRole) if it else None
        if rec is not None:
            self._open_detail(rec)

    def _open_detail(self, rec: dict):
        EventDetailDialog(self, rec).exec()

    # ---------------- 导出 ----------------
    def _export(self, fmt: str):
        if not self._all:
            QMessageBox.information(self, "提示", "当前没有可导出的日志。")
            return
        chan = self.channel_cb.currentText()
        default = f"eventlog_{chan}.{fmt}"
        path, _f = QFileDialog.getSaveFileName(
            self, f"导出事件日志 {fmt.upper()}", default,
            f"{fmt.upper()} 文件 (*.{fmt})")
        if not path:
            return
        try:
            if fmt == "csv":
                with open(path, "w", encoding="utf-8-sig", newline="") as f:
                    w = csv.writer(f)
                    w.writerow(["时间", "来源", "事件ID", "级别", "计算机", "记录ID", "描述"])
                    for r in self._all:
                        w.writerow([r.get("time", ""), r.get("source", ""),
                                   r.get("event_id", ""), r.get("level", ""),
                                   r.get("computer", ""), r.get("record_id", ""),
                                   r.get("description", "")])
            else:
                with open(path, "w", encoding="utf-8") as f:
                    json.dump(self._all, f, ensure_ascii=False, indent=2,
                              default=str)
            QMessageBox.information(self, "导出成功", f"已导出到：\n{path}")
            self.status.setText(f"已导出：{path}")
        except Exception as e:
            QMessageBox.critical(self, "导出失败", f"{e.__class__.__name__}: {e}")

    # ---------------- 状态 ----------------
    def _update_status(self):
        meta = getattr(self, "_meta", None)
        n = len(self._all)
        total = len(self._fetched)
        base = f"共 {n} 条（已取回 {total} 条"
        if meta and meta.get("truncated"):
            base += f"，已达上限 {meta.get('max_records')}，结果可能不完整"
        base += f"）"
        if meta:
            base += f" · 用时 {meta.get('elapsed', 0):.1f}s"
        self.status.setText(base)
        self.status.setStyleSheet("color:#6b7280;")

    # ---------------- 首次显示时自动加载一次 ----------------
    def showEvent(self, ev):
        from PySide6.QtGui import QShowEvent
        super().showEvent(ev)
        if not self._loaded_once and not self._loading:
            self.run_query()


def _clip(text: str, n: int) -> str:
    text = (text or "").replace("\n", " ").strip()
    return text if len(text) <= n else text[:n] + "…"
