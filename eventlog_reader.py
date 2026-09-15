# -*- coding: utf-8 -*-
"""Windows 事件日志读取层（数据层 / Layer 1）

────────────────────────────────────────────────────────────────────────
为什么用 ctypes 直接调 wevtapi.dll，而不引第三方库
────────────────────────────────────────────────────────────────────────
- 本项目刻意「零额外依赖」：进程/服务/网络/资源/性能采集全部走 Windows 原生
  API（psutil、PDH、ctypes），不为了一个功能再塞一个 PyPI 包进打包体积。
- Windows 自 Vista 起提供统一的事件日志 API（wevtapi.dll）：
  EvtQuery / EvtNext / EvtRender / EvtFormatMessage。它比老式 advapi32 的
  ReadEventLogW 更结构化，且原生支持 XPath 查询——能「在系统侧」就完成
  通道 / 级别 / 时间 / 事件ID / 来源 的筛选，避免把整本日志搬回家再筛。
- wevtapi 是系统 DLL，PyInstaller onefile 下也能直接 LoadLibrary，无需 hiddenimport。

────────────────────────────────────────────────────────────────────────
三层划分
────────────────────────────────────────────────────────────────────────
- 本文件 = 数据读取层：负责「把一条条事件日志取出来，整理成统一 dict」。
- eventlog_stats.py = 分析统计层：对取回的 dict 列表做聚合。
- eventlog_widget.py = 界面展示层：筛选控件 / 分页表格 / 详情 / 图表 / 导出。
三者通过「统一事件记录 dict」这个数据结构解耦，互不依赖 PySide。

────────────────────────────────────────────────────────────────────────
性能与界面的关系
────────────────────────────────────────────────────────────────────────
- 读取在后台线程里分页进行（EvtNext 一次取一页，默认 256 条），天然「增量加载」，
  不会一次把百万条日志全读进内存；本层只负责「取」，取多少由调用方通过
  max_records 与分页节奏控制。界面层再把取回的列表分页展示，UI 线程不被阻塞。
"""

from __future__ import annotations

import ctypes
import re
import time
from ctypes import wintypes
from datetime import datetime, timezone
from xml.etree import ElementTree as ET

# --------------------------------------------------------------------------
# 级别：系统内部用数字（1=严重 2=错误 3=警告 4=信息 5=详细），但用户看到中文。
# 这里集中维护数字 ↔ 中文 的映射，分析层与界面层共用，避免各写一份导致不一致。
# --------------------------------------------------------------------------
LEVEL_NUM_TO_NAME = {
    1: "严重",
    2: "错误",
    3: "警告",
    4: "信息",
    5: "详细",
}
LEVEL_NAME_TO_NUM = {v: k for k, v in LEVEL_NUM_TO_NAME.items()}
# UI 上筛选用的有限级别集合（详细通常噪声太大，单独选项控制）
UI_LEVELS = ["信息", "警告", "错误", "严重"]

# 单次 EvtNext 取多少条事件句柄；分页越小占用越小、取消响应越快
EVT_PAGE_SIZE = 256
# EvtNext 单次等待（毫秒）：超时返回 0 条，用于检测「服务卡死 / 读取过慢」
EVT_NEXT_TIMEOUT_MS = 1500
# 单通道默认最多取回多少条参与界面展示与统计（防止超大日志把内存吃爆）。
# 超出后界面明确提示「仅统计前 N 条」，不假装看了全部。
DEFAULT_MAX_RECORDS = 5000

# wevtapi 常量
EVT_QUERY_CHANNEL_PATH = 0x1
EVT_QUERY_REVERSE_DIRECTION = 0x100      # 从新到旧（日志查看器最自然的顺序）
EVT_QUERY_TOLERATE_QUERY_ERRORS = 0x1000
EVT_RENDER_EVENT_XML = 0x1
# EvtFormatMessage 子命令
EVT_FORMAT_MESSAGE_EVENT = 0x1

# advapi32 常量（仅 Security 通道提权用）
SE_SECURITY_NAME = "SeSecurityPrivilege"
TOKEN_ADJUST_PRIVILEGES = 0x20
TOKEN_QUERY = 0x8
SE_PRIVILEGE_ENABLED = 0x2


# --------------------------------------------------------------------------
# 异常层级：把「Windows 错误码 / 各种失败」翻译成界面能直接说的话
# --------------------------------------------------------------------------
class EventLogError(Exception):
    """所有日志读取错误的基类。"""


class EventLogUnavailable(EventLogError):
    """本机没有 wevtapi（非 Windows / 极旧系统）。"""


class EventLogChannelNotFound(EventLogError):
    """指定的日志通道不存在（如拼错名字，或该通道未启用）。"""


class EventLogAccessDenied(EventLogError):
    """读 Security 等受限通道权限不足——通常需要以管理员身份运行。

    .channel 记录是哪个通道被拒，便于界面给出针对性提示。
    """

    def __init__(self, channel: str, msg: str):
        super().__init__(msg)
        self.channel = channel


class EventLogServiceUnavailable(EventLogError):
    """事件日志服务未运行 / RPC 不可达。"""


class EventLogTimeout(EventLogError):
    """读取超时（服务响应过慢或日志过大）。"""


class EventLogReadError(EventLogError):
    """其它读取失败（XPath 语法错误、渲染失败等）。"""


# --------------------------------------------------------------------------
# ctypes 绑定（懒加载：非 Windows 上 import 本模块不报错，只有真正查询才抛）
# --------------------------------------------------------------------------
def _load_wevt():
    try:
        dll = ctypes.windll.wevtapi
    except Exception:
        return None
    # 设置精确的函数签名，避免 32/64 位下参数错乱
    dll.EvtQuery.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                             wintypes.LPCWSTR, wintypes.DWORD]
    dll.EvtQuery.restype = wintypes.HANDLE

    dll.EvtNext.argtypes = [wintypes.HANDLE, wintypes.DWORD,
                            ctypes.POINTER(wintypes.HANDLE), wintypes.DWORD,
                            wintypes.DWORD, ctypes.POINTER(wintypes.DWORD)]
    dll.EvtNext.restype = wintypes.BOOL

    dll.EvtRender.argtypes = [wintypes.HANDLE, wintypes.HANDLE, wintypes.DWORD,
                              wintypes.DWORD, ctypes.c_void_p,
                              ctypes.POINTER(wintypes.DWORD),
                              ctypes.POINTER(wintypes.DWORD)]
    dll.EvtRender.restype = wintypes.BOOL

    dll.EvtOpenPublisherMetadata.argtypes = [wintypes.HANDLE, wintypes.LPCWSTR,
                                            wintypes.LPCWSTR, wintypes.LCID,
                                            wintypes.DWORD]
    dll.EvtOpenPublisherMetadata.restype = wintypes.HANDLE

    dll.EvtFormatMessage.argtypes = [wintypes.HANDLE, wintypes.HANDLE,
                                     wintypes.DWORD, wintypes.DWORD,
                                     ctypes.c_void_p, wintypes.DWORD,
                                     wintypes.LPWSTR,
                                     ctypes.POINTER(wintypes.DWORD)]
    dll.EvtFormatMessage.restype = wintypes.BOOL

    dll.EvtClose.argtypes = [wintypes.HANDLE]
    dll.EvtClose.restype = wintypes.BOOL
    return dll


_WEVT = _load_wevt()


# --------------------------------------------------------------------------
# 工具：时间 ↔ UTC（XPath 的 TimeCreated 是 UTC，用户筛选用本地时间）
# --------------------------------------------------------------------------
def _local_to_utc_iso(dt: datetime) -> str:
    """把（可能带时区的）本地时间转成 XPath 需要的 UTC ISO，形如
    2026-09-01T00:00:00.000Z。dt 为 naive 时按本机时区解释。"""
    if dt.tzinfo is None:
        # 当作本机本地时间；用 now 的偏移推算（同一天偏移通常一致，足够筛选用）
        local_tz = datetime.now().astimezone().tzinfo
        dt = dt.replace(tzinfo=local_tz)
    dt_utc = dt.astimezone(timezone.utc)
    # 截断到毫秒并补 Z
    return dt_utc.strftime("%Y-%m-%dT%H:%M:%S.") + \
        f"{dt_utc.microsecond // 1000:03d}Z"


def _parse_systemtime(iso: str) -> float | None:
    """TimeCreated 形如 2026-09-13T12:34:56.789000Z → UTC epoch 秒。"""
    if not iso:
        return None
    s = iso.strip()
    if s.endswith("Z"):
        s = s[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(s)
    except Exception:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.timestamp()


def _fmt_local(ts: float | None) -> str:
    if ts is None:
        return ""
    dt = datetime.fromtimestamp(ts, tz=timezone.utc).astimezone()
    return dt.strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------------
# 纯函数：构造 XPath（不碰 Windows，便于单测）
# --------------------------------------------------------------------------
def build_xpath(levels: list[str] | None = None,
                event_ids: list[int] | None = None,
                providers: list[str] | None = None,
                time_from: datetime | None = None,
                time_to: datetime | None = None) -> str:
    """把结构化筛选条件拼成 EvtQuery 的 XPath（* 表示匹配所有事件）。

    注意分工：
    - 通道(Channel) 不走 XPath，而是 EvtQuery 的 Path 参数（调用方传）；
    - 级别 / 时间 / 事件ID / 来源 用 XPath 在服务端过滤（快、省内存）；
    - 「关键字」是自由文本，XPath 表达不了全字段模糊匹配，交给界面层客户端筛。
    """
    conds: list[str] = []

    if levels:
        nums = sorted({LEVEL_NAME_TO_NUM.get(lv) for lv in levels if lv in LEVEL_NAME_TO_NUM})
        if nums:
            conds.append(" or ".join(f"Level={n}" for n in nums))

    if event_ids:
        ids = sorted({int(i) for i in event_ids if str(i).strip() != ""})
        if ids:
            conds.append(" or ".join(f"EventID={i}" for i in ids))

    if providers:
        provs = [p.strip() for p in providers if p and p.strip()]
        if provs:
            # Provider 的筛选看 @Name 属性
            expr = " or ".join(f"@Name='{_xpath_literal(p)}'" for p in provs)
            conds.append(f"Provider[{expr}]")

    if time_from is not None:
        conds.append(f"TimeCreated[@SystemTime>='{_local_to_utc_iso(time_from)}']")
    if time_to is not None:
        conds.append(f"TimeCreated[@SystemTime<='{_local_to_utc_iso(time_to)}']")

    if not conds:
        return "*"
    # 所有条件之间是「与」关系：*(System[(a) and (b) and ...])
    return "*[System[(" + ") and (".join(conds) + ")]]"


def _xpath_literal(s: str) -> str:
    """XPath 字符串字面量转义：单引号用 &apos; 兜底（避免破坏属性引号）。"""
    return s.replace("&", "&amp;").replace("'", "&apos;")


# --------------------------------------------------------------------------
# 纯函数：解析渲染出来的事件 XML（不碰 Windows，便于单测）
# --------------------------------------------------------------------------
def _strip_ns(tag: str) -> str:
    return tag.split("}", 1)[1] if "}" in tag else tag


def _event_data_pairs(root: ET.Element) -> list[tuple[str, str]]:
    """提取 <EventData>/<Data> 的 (Name, 值)；无名 Data 用位置序号。"""
    pairs: list[tuple[str, str]] = []
    ed = root.find("{*}EventData")
    if ed is None:
        ed = root.find("EventData")
    if ed is None:
        # 个别事件用 UserData
        ud = root.find("{*}UserData")
        if ud is None:
            ud = root.find("UserData")
        if ud is not None:
            for i, child in enumerate(ud):
                pairs.append((_strip_ns(child.tag), (child.text or "").strip()))
        return pairs
    idx = 0
    for d in ed:
        name = d.get("Name")
        val = (d.text or "").strip()
        if name:
            pairs.append((name, val))
        else:
            pairs.append((f"参数{idx + 1}", val))
            idx += 1
    return pairs


def _level_name_from_xml(num: int | None, render_text: str | None) -> str:
    if num in LEVEL_NUM_TO_NAME:
        return LEVEL_NUM_TO_NAME[num]
    if render_text and render_text in LEVEL_NAME_TO_NUM:
        return render_text
    # 兜底
    return "信息"


def parse_event_xml(xml: str) -> dict:
    """把 EvtRender 输出的事件 XML 整理成统一事件记录 dict（纯函数，可单测）。

    返回字段：
      time        本地显示时间 "YYYY-MM-DD HH:MM:SS"
      time_iso    UTC ISO 字符串
      ts          UTC epoch 秒（排序 / 时间分桶用）
      source      来源（Provider@Name）
      event_id    事件 ID（int，解析失败为 None）
      level       中文级别（信息/警告/错误/严重/详细）
      level_num   数字级别
      channel     通道名
      computer    计算机名
      record_id   事件记录 ID
      keywords    关键字（原始 0x... 串）
      description 可读描述（优先 RenderingInfo/Message，否则事件数据拼接）
      event_data  结构化事件数据 {字段: 值}（无名 Data 记为 参数1..N，保留位置）
      xml         原始 XML
    """
    rec: dict = {
        "time": "", "time_iso": "", "ts": None, "source": "", "event_id": None,
        "level": "信息", "level_num": 4, "channel": "", "computer": "",
        "record_id": None, "keywords": "", "description": "", "event_data": {},
        "xml": xml,
    }
    try:
        root = ET.fromstring(xml)
    except ET.ParseError:
        rec["description"] = xml
        return rec

    sys_el = root.find("{*}System")
    if sys_el is None:
        sys_el = root.find("System")
    if sys_el is not None:
        prov = sys_el.find("{*}Provider")
        if prov is None:
            prov = sys_el.find("Provider")
        if prov is not None:
            rec["source"] = prov.get("Name", "") or ""

        eid = sys_el.find("{*}EventID")
        if eid is None:
            eid = sys_el.find("EventID")
        if eid is not None and eid.text:
            try:
                rec["event_id"] = int(eid.text.strip())
            except ValueError:
                rec["event_id"] = None

        lvl = sys_el.find("{*}Level")
        if lvl is None:
            lvl = sys_el.find("Level")
        lvl_num = None
        if lvl is not None and lvl.text:
            try:
                lvl_num = int(lvl.text.strip())
            except ValueError:
                lvl_num = None

        tc = sys_el.find("{*}TimeCreated")
        if tc is None:
            tc = sys_el.find("TimeCreated")
        iso = tc.get("SystemTime", "") if tc is not None else ""
        rec["time_iso"] = iso
        rec["ts"] = _parse_systemtime(iso)
        rec["time"] = _fmt_local(rec["ts"])

        ch = sys_el.find("{*}Channel")
        if ch is None:
            ch = sys_el.find("Channel")
        rec["channel"] = (ch.text or "").strip() if ch is not None else ""

        comp = sys_el.find("{*}Computer")
        if comp is None:
            comp = sys_el.find("Computer")
        rec["computer"] = (comp.text or "").strip() if comp is not None else ""

        rid = sys_el.find("{*}EventRecordID")
        if rid is None:
            rid = sys_el.find("EventRecordID")
        if rid is not None and rid.text:
            try:
                rec["record_id"] = int(rid.text.strip())
            except ValueError:
                rec["record_id"] = None

        kw = sys_el.find("{*}Keywords")
        if kw is None:
            kw = sys_el.find("Keywords")
        rec["keywords"] = (kw.text or "").strip() if kw is not None else ""

        # RenderingInfo（带 publisher 上下文渲染时才有）——给出本地化级别与消息
        render_level = None
        render_msg = None
        ri = root.find("{*}RenderingInfo")
        if ri is None:
            ri = root.find("RenderingInfo")
        if ri is not None:
            rl = ri.find("{*}Level")
            if rl is None:
                rl = ri.find("Level")
            if rl is not None and rl.text:
                render_level = rl.text.strip()
            rm = ri.find("{*}Message")
            if rm is None:
                rm = ri.find("Message")
            if rm is not None and rm.text:
                render_msg = rm.text.strip()

        rec["level_num"] = lvl_num if lvl_num is not None else 4
        rec["level"] = _level_name_from_xml(lvl_num, render_level)

    # 描述：优先用 RenderingInfo 的本地化消息；否则把事件数据拼成可读文本
    pairs = _event_data_pairs(root)
    if render_msg:
        rec["description"] = render_msg
    elif pairs:
        rec["description"] = "\n".join(f"{k} = {v}" for k, v in pairs)
    else:
        rec["description"] = "(无附加数据)"
    # 结构化事件数据 {字段: 值}。无名 <Data> 已按位置命名为「参数1..N」，位置信息
    # 因此得以保留，上层可据此做非文本判定（例如 6013 的第 5 个字段 = 已运行秒数、
    # Kernel-General 12 的 StartTime = 开机时刻），不必去解析 description 文本。
    rec["event_data"] = {k: v for k, v in pairs}
    return rec


# --------------------------------------------------------------------------
# Security 通道提权：读安全日志需要「管理审核与安全日志」特权(SeSecurityPrivilege)
# --------------------------------------------------------------------------
def _enable_security_privilege() -> bool:
    """尝试在当前进程令牌上启用 SeSecurityPrivilege；成功返回 True。

    普通用户即便启用也会在 EvtQuery 时仍被拒（缺用户权利），这时由调用方
    捕获 ERROR_ACCESS_DENIED 提示「以管理员身份运行」。管理员用户启用后可读。
    """
    try:
        adv = ctypes.windll.advapi32
    except Exception:
        return False

    class LUID(ctypes.Structure):
        _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

    class LUID_AND_ATTRIBUTES(ctypes.Structure):
        _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

    class TOKEN_PRIVILEGES(ctypes.Structure):
        _fields_ = [("PrivilegeCount", wintypes.DWORD),
                    ("Privileges", LUID_AND_ATTRIBUTES * 1)]

    tok = wintypes.HANDLE()
    if not adv.OpenProcessToken(ctypes.windll.kernel32.GetCurrentProcess(),
                                TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                ctypes.byref(tok)):
        return False
    try:
        luid = LUID(0, 0)
        if not adv.LookupPrivilegeValueW(None, SE_SECURITY_NAME, ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        if not adv.AdjustTokenPrivileges(tok, False, ctypes.byref(tp),
                                         ctypes.sizeof(tp), None, None):
            return False
        # AdjustTokenPrivileges 即使成功也可能「并非所有特权都生效」，需看 GetLastError
        return ctypes.GetLastError() == 0
    finally:
        adv.CloseHandle(tok)


# --------------------------------------------------------------------------
# 读取主体
# --------------------------------------------------------------------------
def _map_winerror(err: int, channel: str) -> EventLogError:
    if err == 5:          # ERROR_ACCESS_DENIED
        return EventLogAccessDenied(
            channel,
            f"读取「{channel}」日志被拒绝：需要「管理审核与安全日志」权限，"
            f"请以管理员身份重新运行本程序（工具栏 → 以管理员身份重新运行）。")
    if err == 2:          # ERROR_FILE_NOT_FOUND：多半是通道不存在或服务没起来
        return EventLogChannelNotFound(
            channel,
            f"找不到日志通道「{channel}」：请确认名称是否正确，"
            f"或事件日志服务(EventLog)是否已启动。")
    if err in (1722, 1726, 1766):   # RPC 不可达 / 调用失败
        return EventLogServiceUnavailable(
            channel,
            f"无法连接事件日志服务（RPC 错误 {err}），请确认 EventLog 服务正在运行。")
    if err == 1067:
        return EventLogServiceUnavailable(
            channel, "事件日志服务异常终止，请检查系统服务状态后重试。")
    return EventLogReadError(f"读取「{channel}」日志失败（系统错误码 {err}）。")


class EventLogReader:
    """事件日志读取器：一次 query() 取回某个通道、符合筛选条件的事件列表。

    设计要点：
    - 纯 ctypes，无第三方依赖；
    - 分页(EvtNext) + 可取消(stop 回调) + 可超时(整体耗时)，避免界面卡死；
    - 先按 XPath 在服务端筛（级别/时间/事件ID/来源），关键字等自由文本由调用方
      客户端再筛（见 EventLogPanel.apply_client_filters）。
    """

    def __init__(self, dll=None):
        self._wevt = dll if dll is not None else _WEVT
        if self._wevt is None:
            raise EventLogUnavailable("本机不支持 wevtapi.dll（仅 Windows Vista+ 可用）。")

    @staticmethod
    def available() -> bool:
        return _WEVT is not None

    @staticmethod
    def list_channels() -> list[str]:
        """常用通道清单（也作为 UI 下拉项）。"""
        return ["Application", "System", "Security",
                "Setup", "Microsoft-Windows-TaskScheduler/Operational"]

    def query(self, channel: str,
              filters: dict | None = None,
              max_records: int = DEFAULT_MAX_RECORDS,
              stop: callable = None,
              on_progress: callable = None,
              overall_timeout: float = 60.0) -> tuple[list[dict], dict]:
        """读取指定通道的事件日志。

        参数：
          channel      通道名（如 "Application" / "System" / "Security"）
          filters      结构化筛选：levels / event_ids / providers / time_from /
                       time_to（均为可选；关键字不在此处，由调用方客户端筛）
          max_records  最多取回多少条（默认 5000，防内存爆炸）
          stop         返回 True 时立即中止（取消）
          on_progress  每取完一页回调 (fetched, truncated) 用于刷新进度
          overall_timeout 整体读取超时（秒）；超时抛 EventLogTimeout

        返回：
          (records, meta)
          records 按时间倒序（新→旧）；meta 含 channel / fetched / truncated /
          elapsed 等，供界面提示。
        """
        filters = filters or {}
        if channel == "Security":
            # 尝试启用读取安全日志所需的特权；失败也不影响后续（会由错误码提示）
            _enable_security_privilege()

        xpath = build_xpath(
            levels=filters.get("levels"),
            event_ids=filters.get("event_ids"),
            providers=filters.get("providers"),
            time_from=filters.get("time_from"),
            time_to=filters.get("time_to"),
        )

        flags = EVT_QUERY_CHANNEL_PATH | EVT_QUERY_REVERSE_DIRECTION | \
            EVT_QUERY_TOLERATE_QUERY_ERRORS

        t0 = time.time()
        query_h = self._wevt.EvtQuery(None, channel, xpath, flags)
        if not query_h or query_h == 0:
            raise _map_winerror(ctypes.GetLastError(), channel)

        pub_cache: dict[str, int] = {}        # provider 名 → publisher metadata 句柄
        records: list[dict] = []
        truncated = False
        try:
            events = (wintypes.HANDLE * EVT_PAGE_SIZE)()
            returned = wintypes.DWORD(0)
            while len(records) < max_records:
                if stop and stop():
                    break
                if time.time() - t0 > overall_timeout:
                    if records:
                        truncated = True
                    else:
                        raise EventLogTimeout(
                            f"读取「{channel}」超时（>{overall_timeout:.0f}s）。"
                            f"请缩小时间范围或加级别筛选后重试。")
                    break

                ok = self._wevt.EvtNext(query_h, EVT_PAGE_SIZE, events,
                                        EVT_NEXT_TIMEOUT_MS, 0,
                                        ctypes.byref(returned))
                if not ok:
                    err = ctypes.GetLastError()
                    if err == 0 or err == 259:    # 259 = ERROR_NO_MORE_ITEMS
                        break
                    if err == 1460:               # ERROR_TIMEOUT：服务慢但还能继续
                        if records:
                            continue
                        raise EventLogTimeout(
                            f"读取「{channel}」超时：事件日志服务响应过慢。")
                    raise _map_winerror(err, channel)

                n = int(returned.value)
                if n == 0:
                    break

                for i in range(n):
                    ev_h = events[i]
                    try:
                        xml = self._render_event(ev_h, pub_cache)
                    finally:
                        self._wevt.EvtClose(ev_h)
                    if not xml:
                        continue
                    rec = parse_event_xml(xml)
                    rec["channel"] = channel
                    records.append(rec)
                    if len(records) >= max_records:
                        truncated = True
                        break

                if on_progress:
                    on_progress(len(records), truncated)

                if truncated:
                    break
        finally:
            self._wevt.EvtClose(query_h)
            for h in pub_cache.values():
                try:
                    self._wevt.EvtClose(h)
                except Exception:
                    pass

        elapsed = time.time() - t0
        meta = {
            "channel": channel,
            "fetched": len(records),
            "truncated": truncated,
            "max_records": max_records,
            "elapsed": elapsed,
            "xpath": xpath,
        }
        return records, meta

    def _render_event(self, ev_h: int, pub_cache: dict) -> str | None:
        """用 publisher metadata 上下文把事件渲染成 XML（含本地化 Message）。

        先尝试按来源打开 publisher metadata 渲染；失败则退回 NULL 上下文（仍
        能得到原始 XML，只是没有 RenderingInfo 的本地化消息）。两种方式任一成功
        都返回字符串；都失败返回 None（该事件跳过）。
        """
        # 先渲染一次拿 provider 名（NULL 上下文足够取到 System/Provider）
        raw = self._render_xml(ev_h, None)
        provider = ""
        if raw:
            try:
                r = ET.fromstring(raw)
                p = r.find("{*}System/{*}Provider")
                if p is None:
                    p = r.find("System/Provider")
                if p is not None:
                    provider = p.get("Name", "") or ""
            except ET.ParseError:
                pass

        pub_h = None
        if provider:
            pub_h = pub_cache.get(provider)
            if pub_h is None:
                pub_h = self._wevt.EvtOpenPublisherMetadata(None, provider, None, 0, 0)
                if pub_h and pub_h != 0:
                    pub_cache[provider] = pub_h
                else:
                    pub_h = None

        # 优先带 publisher 上下文（有本地化消息）；失败退回 raw
        if pub_h:
            rich = self._render_xml(ev_h, pub_h)
            if rich:
                return rich
        return raw

    def _render_xml(self, ev_h: int, context: int | None) -> str | None:
        used = wintypes.DWORD(0)
        pc = wintypes.DWORD(0)
        # 先探缓冲区大小
        ok = self._wevt.EvtRender(context, ev_h, EVT_RENDER_EVENT_XML,
                                  0, None, ctypes.byref(used), ctypes.byref(pc))
        if not ok and ctypes.GetLastError() != 122:   # 122 = 缓冲不足，正常
            return None
        size = int(used.value)
        if size <= 0:
            return None
        buf = ctypes.create_unicode_buffer(size // 2 + 1)
        ok = self._wevt.EvtRender(context, ev_h, EVT_RENDER_EVENT_XML,
                                  size, buf, ctypes.byref(used), ctypes.byref(pc))
        if not ok:
            return None
        return buf.value


# 便于界面层直接拿常用通道
DEFAULT_CHANNELS = EventLogReader.list_channels()
