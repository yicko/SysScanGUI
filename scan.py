# -*- coding: utf-8 -*-
"""
系统进程与服务安全扫描器 (Windows)

采集层：进程 / 服务 / 网络连接 / 持久化(计划任务·启动项) / 顶层应用程序
规则层：基于路径可信度、数字签名、资源占用、父子关系、命令行特征、暴露面等判定风险
输出层：结构化 JSON + 控制台摘要（HTML 报告由 report.py 渲染）

用法：
    python scan.py [--json out.json] [--no-signature] [--top N]
"""
from __future__ import annotations

import argparse
import ctypes
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import winreg
import xml.etree.ElementTree as ET
from datetime import datetime

import psutil

# 静默调用外部命令（签名校验等）：不创建控制台窗口，避免扫描时弹黑框
CREATE_NO_WINDOW = 0x08000000 if os.name == "nt" else 0

try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass

# ----------------------------------------------------------------------------
# 常量与基线
# ----------------------------------------------------------------------------

SEV_ORDER = {"严重": 0, "高危": 1, "中危": 2, "低危": 3, "提示": 4}
SEV_KEY = {"critical": "严重", "high": "高危", "medium": "中危", "low": "低危", "info": "提示"}

SYS_ROOT = os.environ.get("SystemRoot", r"C:\Windows").lower()

# 可信区域前缀（优先级最高）：Windows 目录、Program Files、微软托管区
TRUSTED_PREFIXES = [
    SYS_ROOT,
    r"c:\windows",
    os.environ.get("ProgramFiles", r"C:\Program Files").lower(),
    os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)").lower(),
    r"c:\program files",
    r"c:\program files (x86)",
    r"c:\programdata\microsoft",
    r"c:\programdata\package cache",
    r"c:\program files\windowsapps",
]

# 高风险目录段（按路径分段精确匹配，避免 DesktopExtension.exe 之类的子串误伤）
HIGH_RISK_SEGMENTS = {"temp", "tmp", "downloads", "public", "$recycle.bin",
                      "perflogs", "desktop", "recycle.bin"}
MEDIUM_RISK_SEGMENTS = {"appdata", "programdata"}

# 系统进程名：出现在非系统目录即为伪装
SYSTEM_PROC_NAMES = {
    "svchost.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe", "winlogon.exe",
    "services.exe", "explorer.exe", "taskhostw.exe", "dwm.exe", "rundll32.exe",
    "regsvr32.exe", "dllhost.exe", "wmiprvse.exe", "spoolsv.exe", "lsaiso.exe",
    "conhost.exe", "sihost.exe", "ctfmon.exe", "searchindexer.exe", "audiodg.exe",
    "fontdrvhost.exe", "shellexperiencehost.exe", "startmenuexperiencehost.exe",
    "applicationframehost.exe", "systemsettings.exe", "wudfhost.exe", "unsecapp.exe",
    "msmpeng.exe", "nissrv.exe", "trustedinstaller.exe", "tiworker.exe",
}

# 常见正常软件（降低网络/资源类误报）
KNOWN_APP_TOKENS = [
    "chrome", "msedge", "firefox", "iexplore", "opera", "brave", "360", "sogou",
    "wechat", "weixin", "qq", "dingtalk", "wemeet", "feishu", "lark", "slack",
    "zoom", "teams", "telegram", "discord", "spotify", "neteasemusic", "cloudmusic",
    "kugou", "qqmusic", "bilibili", "thunder", "xunlei", "baidunetdisk", "aliyundrive",
    "wps", "et", "wpp", "notepad++", "code", "devenv", "node", "python", "java", "idea",
    "docker", "vmware", "virtualbox", "wsl", "steam", "epicgames", "riot", "obs",
    "everything", "snipaste", "listary", "teamviewer", "sunloginclient", "todesk",
    "rustdesk", "clash", "v2ray", "xray", "sing-box", "shadowsocks", "utools",
    "git", "obsidian", "typora", "potplayer", "vlc", "photoshop", "hh.exe",
    "workbuddy", "portablegit", "scoop", "chocolatey", "uv", "pip",
]

# 常见服务白名单（发行者/名称特征）
KNOWN_SERVICE_TOKENS = [
    "nvidia", "amd", "intel", "realtek", "broadcom", "dell", "hp", "lenovo", "asus",
    "logitech", "razer", "corsair", "steelseries", "microsoft", "windows", "google",
    "adobe", "bonjour", "vmware", "virtualbox", "docker", "mysql", "postgresql",
    "mongodb", "redis", "nginx", "apache", "java", "wps", "kingsoft", "baidu",
    "tencent", "alibaba", "aliyun", "sangfor", "sangforcs", "huorong", "360", "avast",
    "avira", "bitdefender", "kaspersky", "eset", "mcafee", "symantec", "norton",
    "toast", "wuauserv", "bits", "cryptsvc", "dhcp", "dnscache", "eventlog",
]

# 已知高危/常被滥用端口
RISKY_PORTS = {
    4444: "常见后门/反弹 Shell 端口",
    1337: "常见后门端口 (leet)",
    31337: "经典后门端口 (elite)",
    6666: "常被远控使用",
    6667: "IRC 端口，常见于僵尸网络 C2",
    12345: "常见后门端口",
    27374: "常见后门端口 (Sub7)",
    1080: "SOCKS 代理端口",
    1081: "SOCKS 代理端口",
    5900: "VNC 远程桌面端口",
    5901: "VNC 远程桌面端口",
    9001: "Tor 默认端口",
    9030: "Tor 目录端口",
    3389: "RDP 远程桌面端口",
    445: "SMB 共享端口",
    139: "NetBIOS 端口",
    135: "RPC 端点映射",
    23: "Telnet 明文远程登录",
    22: "SSH 远程登录",
}

# 常见良性监听端口（降低误报）
BENIGN_LISTEN_PORTS = {
    80, 443, 445, 135, 139, 137, 138, 53, 123, 161, 389, 636, 88, 464, 3268, 3269,
    5353, 5354, 5355, 5357, 5358, 1900, 3702, 2869, 10243, 5040, 7680, 5000, 4500,
    17500, 5222, 5228, 5229, 5230, 5938, 7070, 8080, 8888, 3306, 5432, 6379, 27017,
}

# 命令行可疑特征
CMD_PATTERNS = [
    (r"(?i)-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{25,}", "high",
     "PowerShell 加密命令 (-EncodedCommand)，常用于隐藏恶意脚本内容"),
    (r"(?i)(mimikatz|sekurlsa|lsadump|procdump|lazagne|cobalt|metasploit|meterpreter)", "critical",
     "命令行出现已知攻击/凭据窃取工具名称"),
    (r"(?i)regsvr32\s+.*\bscrobj\b", "high", "regsvr32 执行远程脚本对象（Squiblydoo 绕过技术）"),
    (r"(?i)certutil\s+.*-decode", "high", "certutil 解码文件，常被滥用于落地恶意载荷"),
    (r"(?i)bitsadmin\s+.*/transfer", "high", "bitsadmin 下载文件（LOLBAS 系统工具滥用）"),
    (r"(?i)mshta\s+.*(https?://|javascript:|vbscript:)", "high", "mshta 执行远程或脚本内容"),
    (r"(?i)rundll32\s+\S+,\S+\s+.*(https?://|\\\\)", "high", "rundll32 加载远程/共享资源"),
    (r"(?i)\bvssadmin\s+.*delete\s+shadows", "high", "删除卷影副本，典型勒索软件行为"),
    (r"(?i)\bnet\s+(user|localgroup)\s+.*(/add|\s/add)", "high", "创建本地账户/加入用户组"),
    (r"(?i)\bwmic\b.*process\s+call\s+create", "high", "wmic 远程/本地创建进程"),
    (r"(?i)powershell.*(-nop|-noprofile).*(-exec|-executionpolicy)\s+bypass", "high",
     "绕过 PowerShell 执行策略"),
    (r"(?i)\biex\b|invoke-expression", "medium", "动态执行脚本 (IEX/Invoke-Expression)"),
    (r"(?i)frombase64string", "medium", "Base64 解码执行特征"),
    (r"(?i)\b-w\s+hidden\b", "medium", "隐藏窗口执行"),
    (r"(?i)schtasks\s+.*/create", "medium", "创建计划任务（持久化手段）"),
    (r"(?i)sc\s+(create|config)\s+", "medium", "创建或修改服务"),
    (r"(?i)netsh\s+.*(firewall|advfirewall)\s+.*(add|set).*(enable|allow)", "medium",
     "修改防火墙规则放行"),
    (r"(?i)(curl|wget|invoke-webrequest|iwr)\s+.*(http|\.ps1|\.exe|\.bat)", "medium",
     "命令行下载远程文件"),
]

CPU_HIGH_THRESHOLD = 25.0     # 单进程整机 CPU 占用超过该值（%）
MEM_HIGH_THRESHOLD = 800      # MB
MEM_RATIO_THRESHOLD = 4.0     # 占总内存百分比

# ----------------------------------------------------------------------------
# 工具函数
# ----------------------------------------------------------------------------


def norm(p: str | None) -> str:
    return (p or "").strip().strip('"').lower()


def expand_path(p: str | None) -> str:
    """展开服务/注册表中常见的环境变量与相对写法。"""
    if not p:
        return ""
    s = p.strip().strip('"')
    # 去掉内核对象路径前缀 \??\
    s = re.sub(r"^\\\\\?\?\\|^\\[\?][\?]\\", "", s)
    s = re.sub(r"^[\\/]systemroot[\\/]", lambda _m: SYS_ROOT + "\\", s, flags=re.I)
    s = re.sub(r"^[\\/]?windows[\\/]", lambda _m: SYS_ROOT + "\\", s, flags=re.I)
    try:
        s = os.path.expandvars(s)
    except Exception:
        pass
    # 相对路径（如 system32\drivers\xxx.sys）补上系统根目录
    if s and not re.match(r"^[a-zA-Z]:[\\/]", s) and not s.startswith("\\\\"):
        s = SYS_ROOT + "\\" + s.lstrip("\\/")
    return s


def extract_image(binpath: str | None) -> str:
    """从服务 ImagePath 中提取可执行/DLL 路径（兼容带引号、不带引号、正斜杠等写法）。"""
    s = expand_path(binpath).strip()
    if not s:
        return ""
    if s.startswith('"'):
        m = re.match(r'^"([^"]+)"', s)
        if m:
            return m.group(1)
    s = s.strip('"')
    # 优先：截取到第一个可执行文件扩展名
    m = re.match(r'^(.*?\.(?:exe|dll|sys|ocx|drv))(?=\s|"|$)', s, re.I)
    if m and os.path.isfile(m.group(1).strip('"')):
        return m.group(1).strip('"')
    # 其次：截取到第一个命令行参数（ -x 或 /x）
    m = re.match(r'^(.*?)(?=\s+[-/][a-zA-Z]|$)', s)
    if m:
        return m.group(1).strip('"').strip()
    return s.strip('"').strip()


def classify_path(path: str | None) -> tuple[str, str]:
    """返回 (来源分级, 说明)。分级: system / program / medium / high / unknown"""
    p = norm(expand_path(path))
    if not p:
        return "unknown", "路径未知（权限不足或已退出）"
    p = p.replace("/", "\\")
    # 1) 可信区域优先
    for pre in TRUSTED_PREFIXES:
        if p.startswith(pre.rstrip("\\") + "\\") or p == pre.rstrip("\\"):
            if pre.startswith((r"c:\windows", SYS_ROOT)):
                return "system", "位于 Windows 系统目录"
            if "programdata" in pre:
                return "program", "位于 Microsoft / 系统托管目录"
            return "program", "位于 Program Files（标准安装目录）"
    # 2) 按目录分段判定高风险
    segs = [s for s in os.path.dirname(p).split("\\") if s]
    for s in segs:
        if s in ("temp", "tmp") or s == "downloads" or s == "public" \
                or s.startswith("$recycle") or s == "perflogs" or s == "desktop":
            return "high", f"位于高风险目录 (…\\{s}\\…)"
    # 3) 用户可写但常见的软件目录
    for s in segs:
        if s == "appdata":
            return "medium", "位于用户 AppData 目录"
        if s == "programdata":
            return "medium", "位于 ProgramData 目录"
    if re.match(r"^[a-z]:\\?$", p):
        return "high", "位于磁盘根目录"
    return "medium", "位于非标准安装目录"


def is_known_app(name: str | None, path: str | None) -> bool:
    s = f"{norm(name)} {norm(path)}"
    return any(tok in s for tok in KNOWN_APP_TOKENS)


# ----------------------------------------------------------------------------
# 本程序自身的进程
# ----------------------------------------------------------------------------
# 单文件（PyInstaller onefile）版本运行时，进程表里会同时出现两个同名进程：
#   · 引导器：先把自身解包到 %TEMP%\_MEIxxxxxx，再以自己为父进程启动真正的应用，
#     然后一直守着不退出，为的是应用结束后清理解包目录；
#   · 应用本体：真正的 Python/Qt 进程。
# 两者**命令行完全相同**（同一个 --elevated-token），很容易被误认为"旧实例没退出"。
#
# 更要紧的是：这类绿色版 exe 通常位于非标准目录且未签名，本工具的规则会把
# "未签名 + 非标准目录"判成中危 —— 于是它扫自己就会刷出两条指向自己的告警，
# 纯属噪音。所以把自身进程组识别出来单独标注，并跳过那几条规则。

def self_exe_path() -> str:
    """本程序自身的可执行文件路径（非冻结环境返回空串）。

    源码运行时 sys.executable 是 python.exe，若按它匹配，会把机器上**所有**
    Python 进程都当成"自身"——那是错的。所以非冻结环境只靠 pid 匹配本进程。
    """
    if getattr(sys, "frozen", False):
        try:
            return os.path.abspath(sys.executable)
        except Exception:
            return ""
    return ""


SELF_EXE = self_exe_path()


def mark_self_processes(procs: list[dict]) -> dict[int, str]:
    """识别本程序自身的进程，返回 {pid: 角色说明}。

    纯函数（不查系统），便于单测：入参只需 pid / ppid / exe 三个字段。
    """
    self_pids: set[int] = set()
    me = os.getpid()
    for p in procs:
        pid = p.get("pid")
        if not pid:
            continue
        if pid == me:
            self_pids.add(pid)          # 本进程永远算自身（源码运行也成立）
        elif SELF_EXE and norm(p.get("exe")) == norm(SELF_EXE):
            self_pids.add(pid)          # 同一个 exe 文件：引导器 / 另一个实例
    by_pid = {p.get("pid"): p for p in procs}
    notes: dict[int, str] = {}
    for pid in self_pids:
        me_row = by_pid.get(pid) or {}
        parent = by_pid.get(me_row.get("ppid"))
        child_is_self = any(c.get("ppid") == pid and c.get("pid") in self_pids
                            for c in procs)
        parent_is_self = bool(parent) and parent.get("pid") in self_pids
        if child_is_self:
            notes[pid] = "本程序自身进程 · 单文件引导器（解包并守护应用进程）"
        elif parent_is_self:
            notes[pid] = "本程序自身进程 · 应用本体"
        else:
            notes[pid] = "本程序自身进程"
    return notes


def collect_self_group() -> list[dict]:
    """当前与本程序相关的进程清单（供界面展示"为什么有两个进程"）。"""
    me = os.getpid()
    rows: list[dict] = []
    try:
        for p in psutil.process_iter(["pid", "ppid", "name", "exe", "memory_info"]):
            try:
                info = p.info
                if not (info.get("pid") == me
                        or (SELF_EXE and norm(info.get("exe")) == norm(SELF_EXE))):
                    continue
                mem = info.get("memory_info")
                rows.append({"pid": info.get("pid"),
                             "ppid": info.get("ppid") or 0,
                             "name": info.get("name") or "",
                             "exe": info.get("exe") or "",
                             "rss_mb": round((mem.rss if mem else 0) / 1048576, 1)})
            except Exception:
                continue
    except Exception:
        return []
    notes = mark_self_processes(rows)
    for r in rows:
        r["role"] = notes.get(r["pid"], "本程序自身进程")
        r["is_me"] = r["pid"] == me
    return sorted(rows, key=lambda r: r["pid"])


def ip_is_public(ip: str) -> bool:
    try:
        import ipaddress
        a = ipaddress.ip_address(ip)
    except Exception:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_multicast
                or a.is_reserved or a.is_unspecified)


def resolve_hostname(ip: str) -> str:
    try:
        return socket.gethostbyaddr(ip)[0]
    except Exception:
        return ""


def read_reg_str(key, sub: str, name: str) -> str | None:
    try:
        with winreg.OpenKey(key, sub) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return str(v)
    except Exception:
        return None


def read_reg_int(key, sub: str, name: str) -> int | None:
    try:
        with winreg.OpenKey(key, sub) as k:
            v, _ = winreg.QueryValueEx(k, name)
            return int(v)
    except Exception:
        return None


# ----------------------------------------------------------------------------
# 数字签名批量校验（PowerShell 降级：失败则标记 unknown）
# ----------------------------------------------------------------------------

def _run_sig_batch(paths: list[str]) -> dict[str, dict]:
    """对一批文件调用 Authenticode 校验（UTF-8 输出，避免 GBK 解码失败）。"""
    out: dict[str, dict] = {}
    ps_lines = [
        "$ErrorActionPreference='SilentlyContinue'",
        "[Console]::OutputEncoding=[System.Text.Encoding]::UTF8",
        "$paths = @(",
    ]
    ps_lines.append(",".join("'" + p.replace("'", "''") + "'" for p in paths))
    ps_lines += [
        ")",
        "foreach($p in $paths){",
        "  $s = Get-AuthenticodeSignature -FilePath $p",
        "  $subj = ''",
        "  if($s.SignerCertificate){ $subj = $s.SignerCertificate.Subject }",
        "  Write-Output ($p + \"`t\" + $s.Status + \"`t\" + $subj)",
        "}",
    ]
    script = "\n".join(ps_lines)
    try:
        encoded = __import__("base64").b64encode(script.encode("utf-16-le")).decode()
        proc = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy",
             "Bypass", "-EncodedCommand", encoded],
            capture_output=True, timeout=180,
            creationflags=CREATE_NO_WINDOW,
        )
        raw = proc.stdout.decode("utf-8", errors="replace") if proc.stdout else ""
        for line in raw.splitlines():
            parts = line.split("\t")
            if len(parts) >= 2 and parts[1].strip():
                out[parts[0].strip().lower()] = {
                    "status": parts[1].strip(),
                    "signer": parts[2].strip() if len(parts) > 2 else "",
                }
    except Exception:
        pass
    return out


def batch_signature(paths: list[str]) -> dict[str, dict]:
    """批量校验 Authenticode 签名，自动分批以规避命令行长度限制。"""
    result: dict[str, dict] = {}
    paths = [p for p in paths if p and os.path.isfile(p)]
    if not paths:
        return result
    batch: list[str] = []
    size = 0
    for p in paths:
        if size + len(p) > 12000 or len(batch) >= 120:
            result.update(_run_sig_batch(batch))
            batch, size = [], 0
        batch.append(p)
        size += len(p) + 4
    if batch:
        result.update(_run_sig_batch(batch))
    return result


# ----------------------------------------------------------------------------
# 采集：顶层可见窗口（"任务/应用程序"）
# ----------------------------------------------------------------------------

def collect_windows() -> dict[int, list[str]]:
    out: dict[int, list[str]] = {}
    try:
        user32 = ctypes.windll.user32
        WNDENUMPROC = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_void_p, ctypes.c_void_p)

        def cb(hwnd, _):
            if user32.IsWindowVisible(hwnd):
                length = user32.GetWindowTextLengthW(hwnd)
                if 0 < length < 260:
                    buf = ctypes.create_unicode_buffer(length + 1)
                    user32.GetWindowTextW(hwnd, buf, length + 1)
                    title = buf.value.strip()
                    if title and title not in ("Program Manager", "设置", "Settings"):
                        pid = ctypes.c_ulong()
                        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
                        out.setdefault(pid.value, []).append(title)
            return True

        user32.EnumWindows(WNDENUMPROC(cb), 0)
    except Exception:
        pass
    return out


# ----------------------------------------------------------------------------
# 采集：进程
# ----------------------------------------------------------------------------

def collect_processes() -> tuple[list[dict], dict[int, float], dict[int, float]]:
    procs = []
    for pid in psutil.pids():
        try:
            procs.append(psutil.Process(pid))
        except Exception:
            continue
    for p in procs:
        try:
            p.cpu_percent(None)
        except Exception:
            pass
    time.sleep(0.7)

    windows = collect_windows()
    total_mem = psutil.virtual_memory().total
    cpu_count = psutil.cpu_count(logical=True) or 1
    items: list[dict] = []
    cpu_map: dict[int, float] = {}
    mem_map: dict[int, float] = {}

    for p in procs:
        row: dict = {"pid": p.pid, "ppid": None, "name": "", "exe": "", "cmdline": "",
                     "user": "", "started": "", "threads": None, "handles": None,
                     "status": "", "cpu": 0.0, "mem_mb": 0.0, "mem_pct": 0.0,
                     "parent_name": "", "windows": []}
        try:
            row["name"] = p.name()
        except Exception:
            pass
        try:
            row["exe"] = p.exe() or ""
        except Exception:
            row["exe"] = ""
        try:
            row["cmdline"] = " ".join(p.cmdline())
        except Exception:
            row["cmdline"] = ""
        try:
            row["ppid"] = p.ppid()
        except Exception:
            pass
        try:
            row["user"] = p.username() or ""
        except Exception:
            row["user"] = ""
        try:
            row["started"] = datetime.fromtimestamp(p.create_time()).strftime("%Y-%m-%d %H:%M:%S")
        except Exception:
            pass
        try:
            row["threads"] = p.num_threads()
        except Exception:
            pass
        try:
            row["handles"] = p.num_handles()
        except Exception:
            pass
        try:
            row["status"] = p.status()
        except Exception:
            pass
        try:
            cpu = p.cpu_percent(None) or 0.0
            row["cpu"] = round(cpu / cpu_count, 2)
        except Exception:
            pass
        try:
            rss = p.memory_info().rss
            row["mem_mb"] = round(rss / 1024 / 1024, 1)
            row["mem_pct"] = round(rss / total_mem * 100, 2)
        except Exception:
            pass
        try:
            if p.ppid():
                row["parent_name"] = psutil.Process(p.ppid()).name()
        except Exception:
            pass
        row["windows"] = windows.get(p.pid, [])
        cpu_map[p.pid] = row["cpu"]
        mem_map[p.pid] = row["mem_mb"]
        items.append(row)
    return items, cpu_map, mem_map


# ----------------------------------------------------------------------------
# 采集：服务
# ----------------------------------------------------------------------------

def collect_services() -> list[dict]:
    items: list[dict] = []
    start_map = {0: "Boot", 1: "System", 2: "Automatic", 3: "Manual", 4: "Disabled"}
    seen = set()
    try:
        for s in psutil.win_service_iter():
            try:
                info = s.as_dict()
            except Exception:
                continue
            name = info.get("name") or ""
            seen.add(name.lower())
            binpath = (info.get("binpath") or "")
            sub = rf"SYSTEM\CurrentControlSet\Services\{name}"
            start_val = read_reg_int(winreg.HKEY_LOCAL_MACHINE, sub, "Start")
            svc_dll = read_reg_str(winreg.HKEY_LOCAL_MACHINE, sub + r"\Parameters", "ServiceDll")
            delayed = read_reg_int(winreg.HKEY_LOCAL_MACHINE, sub, "DelayedAutostart") == 1
            obj = info.get("username") or read_reg_str(winreg.HKEY_LOCAL_MACHINE, sub, "ObjectName") or ""
            raw_imagepath = read_reg_str(winreg.HKEY_LOCAL_MACHINE, sub, "ImagePath") or ""
            binpath = expand_path(binpath)
            exe_path = extract_image(binpath)
            svc_dll = expand_path(svc_dll) if svc_dll else ""
            items.append({
                "name": name,
                "display": info.get("display_name") or "",
                "status": info.get("status") or "",
                "start_type": info.get("start_type") or "",
                "start_value": start_map.get(start_val, str(start_val) if start_val is not None else ""),
                "delayed": delayed,
                "pid": info.get("pid"),
                "user": obj,
                "binpath": binpath,
                "raw_imagepath": raw_imagepath,
                "exe": exe_path,
                "service_dll": svc_dll or "",
                "desc": (info.get("description") or "").strip(),
            })
    except Exception:
        pass

    # 注册表补充（psutil 未列出的驱动服务等）
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"SYSTEM\CurrentControlSet\Services") as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                if sub.lower() in seen:
                    continue
                full = rf"SYSTEM\CurrentControlSet\Services\{sub}"
                start_val = read_reg_int(winreg.HKEY_LOCAL_MACHINE, full, "Start")
                if start_val is None:
                    continue
                binpath = expand_path(read_reg_str(winreg.HKEY_LOCAL_MACHINE, full, "ImagePath") or "")
                typ = read_reg_int(winreg.HKEY_LOCAL_MACHINE, full, "Type") or 0
                exe_path = extract_image(binpath) if binpath else ""
                svc_dll = expand_path(read_reg_str(winreg.HKEY_LOCAL_MACHINE,
                                                    full + r"\Parameters", "ServiceDll") or "")
                items.append({
                    "name": sub,
                    "display": read_reg_str(winreg.HKEY_LOCAL_MACHINE, full, "DisplayName") or sub,
                    "status": "未运行",
                    "start_type": "",
                    "start_value": start_map.get(start_val, str(start_val)),
                    "delayed": read_reg_int(winreg.HKEY_LOCAL_MACHINE, full, "DelayedAutostart") == 1,
                    "pid": None,
                    "user": read_reg_str(winreg.HKEY_LOCAL_MACHINE, full, "ObjectName") or "",
                    "binpath": binpath,
                    "exe": exe_path,
                    "service_dll": svc_dll,
                    "desc": read_reg_str(winreg.HKEY_LOCAL_MACHINE, full, "Description") or "",
                    "is_driver": bool(typ & 0x00000001),
                })
    except Exception:
        pass
    return items


# ----------------------------------------------------------------------------
# 采集：网络连接
# ----------------------------------------------------------------------------

def collect_connections(proc_names: dict[int, str]) -> list[dict]:
    items: list[dict] = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return items
    for c in conns:
        laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
        raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
        rip = c.raddr.ip if c.raddr else ""
        items.append({
            "proto": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
            "laddr": laddr,
            "lport": c.laddr.port if c.laddr else None,
            "raddr": raddr,
            "rport": c.raddr.port if c.raddr else None,
            "rip": rip,
            "status": c.status,
            "pid": c.pid,
            "proc": proc_names.get(c.pid, "") if c.pid else "",
            "public": ip_is_public(rip) if rip else False,
        })
    return items


# ----------------------------------------------------------------------------
# 采集：持久化（计划任务 + 启动项）
# ----------------------------------------------------------------------------

def collect_tasks() -> list[dict]:
    items: list[dict] = []
    root = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32", "Tasks")
    for dirpath, _dirs, files in os.walk(root):
        for f in files:
            fp = os.path.join(dirpath, f)
            try:
                tree = ET.parse(fp)
                r = tree.getroot()
            except Exception:
                continue
            ns = {"t": "http://schemas.microsoft.com/windows/2004/02/mit/task"}

            def txt(path: str) -> str:
                el = r.find(path, ns)
                return (el.text or "").strip() if el is not None else ""

            rel = os.path.relpath(fp, root)
            enabled = (r.find(".//t:Settings/t:Enabled", ns) is None
                       or (r.find(".//t:Settings/t:Enabled", ns).text or "true").lower() == "true")
            triggers = []
            for tr in r.findall(".//t:Triggers/*", ns):
                triggers.append(tr.tag.split("}")[-1])
            principal = txt(".//t:Principals/t:Principal/t:UserId")
            items.append({
                "type": "计划任务",
                "name": rel,
                "command": txt(".//t:Actions/t:Exec/t:Command"),
                "args": txt(".//t:Actions/t:Exec/t:Arguments"),
                "author": txt(".//t:RegistrationInfo/t:Author"),
                "user": principal,
                "enabled": enabled,
                "triggers": triggers,
                "source": fp,
            })
    return items


RUN_KEYS = [
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKLM\\RunOnce"),
    (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run", "HKLM\\Run(x86)"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", "HKCU\\Run"),
    (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\RunOnce", "HKCU\\RunOnce"),
]


def collect_run_keys() -> list[dict]:
    items: list[dict] = []
    for hive, sub, label in RUN_KEYS:
        try:
            with winreg.OpenKey(hive, sub) as k:
                i = 0
                while True:
                    try:
                        name, val, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    i += 1
                    items.append({
                        "type": "启动项",
                        "name": f"{label} :: {name}",
                        "command": str(val),
                        "args": "",
                        "author": "",
                        "user": "HKCU" if hive == winreg.HKEY_CURRENT_USER else "HKLM",
                        "enabled": True,
                        "triggers": ["开机登录"],
                        "source": f"{label}\\{name}",
                    })
        except Exception:
            continue

    startups = [
        os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\Start Menu\Programs\Startup"),
        os.path.join(os.environ.get("ProgramData", r"C:\ProgramData"),
                     r"Microsoft\Windows\Start Menu\Programs\Startup"),
    ]
    for d in startups:
        if not os.path.isdir(d):
            continue
        for f in os.listdir(d):
            items.append({
                "type": "启动项",
                "name": f"启动文件夹 :: {f}",
                "command": os.path.join(d, f),
                "args": "",
                "author": "",
                "user": os.environ.get("USERNAME", ""),
                "enabled": True,
                "triggers": ["开机登录"],
                "source": os.path.join(d, f),
            })
    return items


# ----------------------------------------------------------------------------
# 规则引擎
# ----------------------------------------------------------------------------

class Findings:
    def __init__(self):
        self.items: list[dict] = []

    def add(self, category: str, severity: str, target_type: str, target: str,
            title: str, detail: str, advice: str, extra: dict | None = None):
        self.items.append({
            "category": category,
            "severity": SEV_KEY.get(severity, severity),
            "target_type": target_type,
            "target": target,
            "title": title,
            "detail": detail,
            "advice": advice,
            "extra": extra or {},
        })

    def max_sev(self, key: str) -> str:
        rel = [f for f in self.items if f["target"] == key]
        if not rel:
            return ""
        return sorted(rel, key=lambda f: SEV_ORDER[f["severity"]])[0]["severity"]


def sev_rank(a: str, b: str) -> str:
    if a not in SEV_ORDER:
        return b
    if b not in SEV_ORDER:
        return a
    return a if SEV_ORDER[a] <= SEV_ORDER[b] else b


def analyze_processes(procs: list[dict], sig: dict[str, dict], F: Findings) -> None:
    pids = {p["pid"] for p in procs}
    # 本程序自身的进程（单文件版=引导器+应用本体）：只标注，不参与风险判定
    self_notes = mark_self_processes(procs)
    for p in procs:
        key = f"process:{p['pid']}"
        name_l = p["name"].lower()
        exe_l = norm(p["exe"])
        src, src_desc = classify_path(p["exe"])
        p["path_source"] = src
        p["path_note"] = src_desc

        siginfo = sig.get(exe_l)
        if siginfo:
            p["sig_status"] = siginfo["status"]
            p["sig_signer"] = siginfo["signer"]
        elif src == "system":
            p["sig_status"] = "系统目录(默认可信)"
            p["sig_signer"] = ""
        else:
            p["sig_status"] = "未验证"
            p["sig_signer"] = ""

        reasons: list[dict] = []

        # 0. 本程序自身的进程：标注为正常并跳过下面的规则。
        #    单文件版运行时必然存在两个同名进程（引导器 + 应用本体），且绿色版
        #    通常位于非标准目录又未签名 —— 不跳过就会刷出两条指向自己的中危告警。
        #    说明：这里连资源占用规则一起跳过；本工具的职责是排查**别的**程序，
        #    对自己的内存占用报警没有意义（要调性能有专门的观测手段）。
        if p["pid"] in self_notes:
            p["self_process"] = True
            p["self_note"] = self_notes[p["pid"]]
            p["path_note"] = f"{src_desc}（{self_notes[p['pid']]}）"
            p["reasons"] = []
            p["risk"] = "正常"
            continue

        # 1. 高风险目录
        if src == "high":
            F.add("进程", "high", "进程", key,
                  f"进程运行于高风险目录：{p['name']} (PID {p['pid']})",
                  f"路径：{p['exe'] or '未知'}；{src_desc}。合法软件通常安装于 Program Files。",
                  "核对文件来源与哈希；若为未知程序建议终止进程、删除文件并用杀毒软件全盘扫描。")
            reasons.append({"sev": "高危", "text": f"高风险目录运行（{src_desc}）"})

        # 2. 系统进程名伪装（Windows 目录 / Defender 平台 / 有效微软签名 均视为可信）
        signed_ms = ("microsoft" in (p.get("sig_signer") or "").lower()
                     and (p.get("sig_status") or "").lower() == "valid")
        sys_ok = (src == "system") or ("windows defender" in exe_l and "platform" in exe_l) or signed_ms
        if name_l in SYSTEM_PROC_NAMES and exe_l and not sys_ok:
            F.add("进程", "critical", "进程", key,
                  f"疑似系统进程伪装：{p['name']} (PID {p['pid']})",
                  f"该进程名属于 Windows 系统进程，但实际路径为 {p['exe']}，不在 System32/SysWOW64。",
                  "极可能是恶意伪装进程。立即隔离该文件、终止进程并进行恶意样本分析。")
            reasons.append({"sev": "严重", "text": "系统进程名伪装（路径不在系统目录）"})

        # 3. 签名
        st = (p.get("sig_status") or "").lower()
        if st in ("notsigned",):
            if src == "high":
                F.add("进程", "high", "进程", key,
                      f"未签名程序运行于高风险目录：{p['name']} (PID {p['pid']})",
                      f"文件无有效数字签名，路径 {p['exe']}。",
                      "高风险目录 + 无签名是典型恶意载荷特征，建议核查哈希并查杀。")
                reasons.append({"sev": "高危", "text": "无数字签名且位于高风险目录"})
            elif src == "medium" and not is_known_app(p["name"], p["exe"]):
                F.add("进程", "medium", "进程", key,
                      f"未签名程序运行于非标准目录：{p['name']} (PID {p['pid']})",
                      f"文件无有效数字签名，路径 {p['exe']}。",
                      "确认该程序是否为你主动安装的绿色软件；否则建议核查哈希并查杀。")
                reasons.append({"sev": "中危", "text": "无数字签名且位于非标准目录"})
            elif src == "medium":
                reasons.append({"sev": "低危", "text": "无数字签名（已知开发工具/受管目录）"})
        elif st in ("hashmismatch", "notsigned" , "nottrusted", "unknownerror"):
            if st in ("hashmismatch", "nottrusted"):
                F.add("进程", "high", "进程", key,
                      f"数字签名校验失败：{p['name']} (PID {p['pid']})",
                      f"签名状态：{p.get('sig_status')}，路径 {p['exe']}。",
                      "签名无效意味着文件可能被篡改或伪造，建议重新获取官方版本。")
                reasons.append({"sev": "高危", "text": f"签名校验失败（{p.get('sig_status')}）"})

        # 4. 命令行特征
        cmd = p["cmdline"] or ""
        if cmd:
            for pat, sev, desc in CMD_PATTERNS:
                if re.search(pat, cmd):
                    F.add("进程", sev, "进程", key,
                          f"可疑命令行：{p['name']} (PID {p['pid']})",
                          f"{desc}。命令行：{cmd[:300]}",
                          "确认该操作是否由你或可信运维脚本发起；否则按安全事件处理并留存进程 dump 与日志。")
                    reasons.append({"sev": SEV_KEY.get(sev, sev), "text": desc})
                    break

        # 5. 资源占用（排除系统空闲/内核占位进程）
        idle_like = name_l in ("system idle process", "system", "memory compression",
                               "registry", "idle") or p["pid"] in (0, 4)
        if p["cpu"] >= CPU_HIGH_THRESHOLD and not idle_like:
            F.add("资源", "medium", "进程", key,
                  f"CPU 占用异常偏高：{p['name']} (PID {p['pid']})",
                  f"整机 CPU 占用约 {p['cpu']}%（单核折算前更高），线程数 {p['threads']}。",
                  "观察是否为持续性占用；若与业务无关，检查是否为挖矿/死循环程序。")
            reasons.append({"sev": "中危", "text": f"CPU 占用 {p['cpu']}%"})
        if (p["mem_mb"] >= MEM_HIGH_THRESHOLD or p["mem_pct"] >= MEM_RATIO_THRESHOLD) \
                and not idle_like:
            F.add("资源", "medium", "进程", key,
                  f"内存占用异常偏高：{p['name']} (PID {p['pid']})",
                  f"常驻内存 {p['mem_mb']} MB，占物理内存 {p['mem_pct']}%。",
                  "排查内存泄漏或异常常驻；结合启动时间与签名综合判断。")
            reasons.append({"sev": "中危", "text": f"内存占用 {p['mem_mb']} MB"})

        # 6. 孤儿 / 异常父进程（系统进程已是正常 Windows 行为，不纳入）
        if p["ppid"] and p["ppid"] not in pids and p["ppid"] != 0 \
                and src != "system" and name_l not in SYSTEM_PROC_NAMES:
            F.add("进程", "low", "进程", key,
                  f"父进程已退出（孤儿进程）：{p['name']} (PID {p['pid']})",
                  f"记录的父进程 PID {p['ppid']} 不在当前进程表中。",
                  "多数情况正常（守护/解耦进程）；若伴随可疑路径则需重点核查。")
            reasons.append({"sev": "低危", "text": "父进程不存在（孤儿进程）"})

        # 7. SYSTEM 身份 + 非系统目录
        if "system" in (p["user"] or "").lower() and src in ("high", "medium"):
            F.add("进程", "high", "进程", key,
                  f"以 SYSTEM 权限运行非系统目录程序：{p['name']} (PID {p['pid']})",
                  f"运行身份 {p['user']}，路径 {p['exe']}。",
                  "高权限 + 非可信路径 = 高危组合，建议立即核查该程序来源。")
            reasons.append({"sev": "高危", "text": "SYSTEM 权限运行非系统目录程序"})

        p["reasons"] = reasons
        p["risk"] = ""
        for r in reasons:
            p["risk"] = sev_rank(p["risk"], r["sev"])
        p["risk"] = p["risk"] or ("正常" if not reasons else "提示")


def analyze_services(services: list[dict], sig: dict[str, dict], procs: list[dict], F: Findings) -> None:
    running = {s["name"] for s in services if s["status"] == "running"}
    for s in services:
        key = f"service:{s['name']}"
        binpath = s["binpath"]
        exe = s["exe"]
        target_file = s["service_dll"] or exe
        src, src_desc = classify_path(target_file)
        s["path_source"] = src
        s["path_note"] = src_desc
        s["real_file"] = target_file

        sig_info = sig.get(norm(target_file))
        if sig_info:
            s["sig_status"] = sig_info["status"]
            s["sig_signer"] = sig_info["signer"]
        elif src == "system":
            s["sig_status"] = "系统目录(默认可信)"
            s["sig_signer"] = ""
        else:
            s["sig_status"] = "未验证"
            s["sig_signer"] = ""

        reasons: list[dict] = []

        # 文件存在性
        if target_file:
            s["file_exists"] = os.path.isfile(target_file)
        else:
            s["file_exists"] = None

        if s["status"] == "running" and target_file and not s["file_exists"]:
            F.add("服务", "high", "服务", key,
                  f"服务二进制文件缺失：{s['name']}",
                  f"服务正在运行，但映像文件 {target_file} 不存在（可能被删除或隐藏）。",
                  "典型的恶意/损坏服务特征。导出服务配置、比对原始文件并查杀。")
            reasons.append({"sev": "高危", "text": "运行中但映像文件不存在"})

        # 路径引号劫持（以注册表原始 ImagePath 判定；内核驱动路径 \??\ 不适用）
        raw_image = s.get("raw_imagepath") or binpath
        is_kernel_drv = raw_image.lstrip().startswith(("\\??\\", "\\\\?\\")) or \
            (exe or "").lower().endswith(".sys")
        if exe and " " in exe and not raw_image.strip().startswith('"') and not is_kernel_drv:
            has_args = bool(re.search(r"\s+[-/]", raw_image))
            sev = "high" if has_args else "medium"
            F.add("服务", sev, "服务", key,
                  f"服务路径未加引号（可能被劫持）：{s['name']}",
                  f"ImagePath = {raw_image}，路径含空格但未用引号包裹，"
                  f"Windows 会先尝试执行 C:\\Program.exe 等前缀路径"
                  f"{'，且带命令行参数，劫持风险更高' if has_args else ''}。",
                  "为 ImagePath 补加英文双引号，或修正为不含空格的路径。")
            reasons.append({"sev": SEV_KEY.get(sev, sev), "text": "服务路径未加引号（路径劫持风险）"})

        # 用户可写目录
        if src == "high" or (src == "medium" and "programdata" not in norm(target_file)):
            if s["status"] == "running":
                F.add("服务", "high", "服务", key,
                      f"服务映像位于用户可写目录：{s['name']}",
                      f"映像路径 {target_file}；{src_desc}。任何用户/程序都可替换该文件实现提权。",
                      "确认该服务来源；将可执行文件迁移至 Program Files 并修复 ACL。")
                reasons.append({"sev": "高危", "text": f"映像位于用户可写目录（{src_desc}）"})

        # 解释器承载服务
        bare = os.path.basename(norm(exe))
        if bare in ("cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe",
                    "wscript.exe", "cscript.exe", "mshta.exe"):
            F.add("服务", "medium", "服务", key,
                  f"服务由脚本解释器承载：{s['name']}",
                  f"ImagePath = {binpath}，由 {bare} 承载运行，常见于持久化或变相执行。",
                  "核查被承载脚本内容与作者；不确定来源建议禁用该服务。")
            reasons.append({"sev": "中危", "text": f"由 {bare} 承载（脚本型服务）"})

        # 未签名 + SYSTEM
        st = (s.get("sig_status") or "").lower()
        if st == "notsigned" and "system" in (s["user"] or "").lower():
            F.add("服务", "medium", "服务", key,
                  f"未签名服务以 SYSTEM 运行：{s['name']}",
                  f"映像 {target_file} 无有效签名，运行身份 {s['user']}。",
                  "核查发行者；无法确认时改为手动启动或禁用。")
            reasons.append({"sev": "中危", "text": "未签名且以 SYSTEM 权限运行"})
        elif st in ("hashmismatch", "nottrusted"):
            F.add("服务", "high", "服务", key,
                  f"服务映像签名无效：{s['name']}",
                  f"签名状态 {s.get('sig_status')}，映像 {target_file}。",
                  "文件可能被篡改，建议从官方渠道重新安装。")
            reasons.append({"sev": "高危", "text": "服务映像签名无效"})

        # 未知后台服务（自动启动 + 非白名单 + 非系统目录 + 无有效签名）
        if (s["start_value"] == "Automatic" and src in ("medium", "high")
                and (s.get("sig_status") or "").lower() != "valid"
                and not any(tok in f"{norm(s['name'])} {norm(target_file)}".lower()
                            for tok in KNOWN_SERVICE_TOKENS)):
            F.add("服务", "medium", "服务", key,
                  f"未知来源的自启动服务：{s['name']}",
                  f"开机自动启动，映像 {target_file}，发行者 {s.get('sig_signer') or '未知'}。",
                  "逐一确认是否为必要软件组件；不需要的服务请设为手动或禁用。")
            reasons.append({"sev": "中危", "text": "未知来源且开机自启动"})

        s["reasons"] = reasons
        s["risk"] = ""
        for r in reasons:
            s["risk"] = sev_rank(s["risk"], r["sev"])
        s["risk"] = s["risk"] or "正常"


def analyze_connections(conns: list[dict], procs: list[dict], F: Findings) -> None:
    pmap = {p["pid"]: p for p in procs}
    pub_groups: dict[int, list[dict]] = {}

    for c in conns:
        key = f"conn:{c['proto']}:{c['laddr']}->{c['raddr'] or '-'}"
        p = pmap.get(c["pid"])
        pname = (p["name"] if p else "") or ""
        pexe = (p["exe"] if p else "") or ""
        reasons: list[dict] = []

        # 监听 0.0.0.0
        if c["status"] == psutil.CONN_LISTEN and (c["laddr"] or "").startswith("0.0.0.0"):
            port = c["lport"] or 0
            note = RISKY_PORTS.get(port, "")
            # Windows 默认共享/RPC 端口由系统进程监听时仅作暴露面提示
            sys_listener = (pname or "").lower() in ("system", "svchost.exe", "lsass.exe")
            if note and port in (135, 139, 445) and sys_listener:
                F.add("网络", "low", "连接", key,
                      f"系统共享端口暴露：{port}",
                      f"{note}。由系统进程 {pname} (PID {c['pid']}) 在 0.0.0.0:{port} 监听，"
                      f"对全部网卡开放。",
                      "若不需要文件共享/RPC 远程管理，建议关闭对应服务或在防火墙阻断公网入站。")
                reasons.append({"sev": "低危", "text": f"系统端口 {port} 全网监听（暴露面）"})
            elif note:
                F.add("网络", "high", "连接", key,
                      f"高危端口对外监听：{port}",
                      f"{note}。进程 {pname or '未知'} (PID {c['pid']}) 在 0.0.0.0:{port} 监听，"
                      f"对所有网卡开放。",
                      "若非业务需要，关闭该端口或绑定回环地址；检查是否为远控/后门。")
                reasons.append({"sev": "高危", "text": f"高危端口 {port} 全网监听（{note}）"})
            elif port not in BENIGN_LISTEN_PORTS:
                F.add("网络", "low", "连接", key,
                      f"非常见端口监听：{port}",
                      f"进程 {pname or '未知'} (PID {c['pid']}) 监听 0.0.0.0:{port}。",
                      "确认该监听的用途；不需要则关闭对应程序或端口。")
                reasons.append({"sev": "低危", "text": f"非常见端口 {port} 全网监听"})

        # 公网外连（先归组，稍后按进程聚合输出，避免同一进程刷屏）
        if c["public"] and c["status"] in (psutil.CONN_ESTABLISHED, psutil.CONN_SYN_SENT):
            pub_groups.setdefault(c["pid"], []).append(c)
            if c["rport"] in RISKY_PORTS and c["rport"] not in (443, 80):
                F.add("网络", "high", "连接", key,
                      f"连接高危端口：{c['rport']}",
                      f"{pname or '未知'} (PID {c['pid']}) → {c['raddr']}，"
                      f"{RISKY_PORTS[c['rport']]}。",
                      "核实是否为企业内部服务；否则按失陷指标处理并阻断。")
                reasons.append({"sev": "高危", "text": f"连接高危端口 {c['rport']}"})

        # 无主连接
        if c["pid"] and not p:
            F.add("网络", "low", "连接", key,
                  f"连接无法关联到存活进程：{c['laddr']} → {c['raddr'] or '-'}",
                  f"PID {c['pid']} 已不在进程表中，可能是受保护进程或已退出。",
                  "以管理员权限复核；长期存在需关注。")
            reasons.append({"sev": "低危", "text": "连接无法关联存活进程"})

        c["reasons"] = reasons
        c["risk"] = ""
        for r in reasons:
            c["risk"] = sev_rank(c["risk"], r["sev"])
        c["risk"] = c["risk"] or "正常"
        c["proc_path"] = pexe

    # 按进程聚合公网外连告警
    for pid, clist in pub_groups.items():
        p = pmap.get(pid)
        pname = (p["name"] if p else "") or "未知"
        pexe = (p["exe"] if p else "") or ""
        addrs = sorted({c["raddr"] for c in clist if c["raddr"]})
        shown = "、".join(addrs[:8]) + (f" 等 {len(addrs)} 个地址" if len(addrs) > 8 else "")
        if is_known_app(pname, pexe):
            continue
        sys_proc = p is not None and p.get("path_source") == "system"
        sev = "low" if sys_proc else "medium"
        for c in clist:
            c["reasons"].append({"sev": SEV_KEY.get(sev, sev),
                                 "text": f"外连公网 {c['raddr']}"})
            c["risk"] = sev_rank(c["risk"], SEV_KEY.get(sev, sev))
        F.add("网络", sev, "连接", f"conn:public:{pid}",
              f"{'系统进程' if sys_proc else '非常见程序'}外连公网：{pname} (PID {pid})",
              f"共 {len(addrs)} 个公网远端地址：{shown}；路径 {pexe or '未知'}。",
              "核查该程序通信目的；系统进程外连多为更新/遥测，"
              "第三方程序若无法解释外连目的建议抓包或隔离分析。")


def analyze_persistence(items: list[dict], sig: dict[str, dict], F: Findings) -> None:
    for it in items:
        key = f"persist:{it['type']}:{it['name']}"
        cmd = it["command"]
        exe = extract_image(cmd)
        # 跳过非可执行文件（desktop.ini、.url 等）
        if exe and not norm(exe).endswith((".exe", ".dll", ".bat", ".cmd", ".ps1",
                                           ".vbs", ".js", ".lnk", ".url", ".sys")):
            it["risk"] = "正常"
            it["reasons"] = []
            it["file_exists"] = None
            it["path_source"] = "unknown"
            it["path_note"] = "非可执行文件（已忽略）"
            it["sig_status"] = "未验证"
            it["sig_signer"] = ""
            continue
        src, src_desc = classify_path(exe)
        it["path_source"] = src
        it["path_note"] = src_desc
        sig_info = sig.get(norm(exe))
        it["sig_status"] = sig_info["status"] if sig_info else "未验证"
        it["sig_signer"] = sig_info["signer"] if sig_info else ""
        it["file_exists"] = os.path.isfile(exe) if exe else None
        reasons: list[dict] = []

        if it["file_exists"] is False:
            F.add("持久化", "medium", "持久化", key,
                  f"{it['type']}指向不存在的文件：{it['name']}",
                  f"命令：{cmd}。残留的无效启动项。",
                  "清理注册表/任务中的无效条目。")
            reasons.append({"sev": "中危", "text": "启动项指向不存在的文件"})

        if src == "high":
            F.add("持久化", "high", "持久化", key,
                  f"{it['type']}位于高风险目录：{it['name']}",
                  f"命令：{cmd}；{src_desc}。开机即自动运行。",
                  "持久化 + 高风险目录是典型恶意驻留特征，建议禁用并核查文件。")
            reasons.append({"sev": "高危", "text": f"持久化项位于高风险目录（{src_desc}）"})
        elif src == "medium" and it["sig_status"] == "NotSigned":
            F.add("持久化", "medium", "持久化", key,
                  f"{it['type']}为未签名程序：{it['name']}",
                  f"命令：{cmd}；路径 {exe}。",
                  "确认软件来源，不需要则禁用。")
            reasons.append({"sev": "中危", "text": "持久化项为未签名程序"})

        if it["type"] == "计划任务":
            joined = f"{cmd} {it['args']}"
            for pat, sev, desc in CMD_PATTERNS:
                if re.search(pat, joined):
                    F.add("持久化", sev, "持久化", key,
                          f"计划任务含可疑命令：{it['name']}",
                          f"{desc}。命令：{joined[:300]}",
                          "立即核查任务创建者与执行内容，必要时禁用任务。")
                    reasons.append({"sev": SEV_KEY.get(sev, sev), "text": desc})
                    break

        it["reasons"] = reasons
        it["risk"] = ""
        for r in reasons:
            it["risk"] = sev_rank(it["risk"], r["sev"])
        it["risk"] = it["risk"] or "正常"


# ----------------------------------------------------------------------------
# 主流程
# ----------------------------------------------------------------------------

def run_scan(progress_cb=None, do_signature: bool = True, do_tasks: bool = True) -> dict:
    """执行完整扫描并返回结构化数据。

    progress_cb: 可选回调 progress_cb(step:int, total:int, message:str)，供 GUI 显示进度。
    """
    def tick(step: int, msg: str):
        if progress_cb:
            try:
                progress_cb(step, 6, msg)
            except Exception:
                pass

    t0 = time.time()
    tick(1, "采集进程与资源占用 ...")
    procs, _cpu, _mem = collect_processes()
    proc_names = {p["pid"]: p["name"] for p in procs}

    tick(2, "采集服务 ...")
    services = collect_services()

    tick(3, "采集网络连接 ...")
    conns = collect_connections(proc_names)

    if do_tasks:
        tick(4, "采集计划任务与启动项 ...")
        persist = collect_tasks() + collect_run_keys()
    else:
        persist: list[dict] = []
        tick(4, "跳过持久化采集")

    # 待验签文件：非 Windows 系统目录的可执行文件
    tick(5, "校验数字签名 ...")
    sig: dict[str, dict] = {}
    if do_signature:
        targets = set()
        for p in procs:
            if p["exe"] and norm(p["exe"]).startswith(SYS_ROOT):
                continue
            targets.add(p["exe"])
        for s in services:
            t = s["service_dll"] or s["exe"]
            if t and not norm(t).startswith(SYS_ROOT):
                targets.add(t)
        for it in persist:
            m = re.match(r'^"([^"]+)"', (it["command"] or "").strip()) or \
                re.match(r"^(\S+)", (it["command"] or "").strip())
            if m and not norm(m.group(1)).startswith(SYS_ROOT):
                targets.add(m.group(1))
        targets = {t for t in targets if t.lower().endswith((".exe", ".dll", ".sys", ".ocx"))}
        sig = batch_signature(sorted(targets))

    tick(6, "应用风险规则 ...")
    F = Findings()
    analyze_processes(procs, sig, F)
    analyze_services(services, sig, procs, F)
    analyze_connections(conns, procs, F)
    analyze_persistence(persist, sig, F)

    # 汇总
    risk_count = {k: 0 for k in SEV_ORDER}
    for f in F.items:
        risk_count[f["severity"]] += 1

    vm = psutil.virtual_memory()
    meta = {
        "host": platform.node(),
        "os": f"{platform.system()} {platform.release()} ({platform.version()})",
        "user": os.environ.get("USERNAME", ""),
        "admin": bool(ctypes.windll.shell32.IsUserAnAdmin()) if hasattr(ctypes.windll, "shell32") else None,
        "scan_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "duration": round(time.time() - t0, 1),
        "cpu_logical": psutil.cpu_count(logical=True),
        "cpu_percent": psutil.cpu_percent(interval=0.3),
        "mem_total_gb": round(vm.total / 1024 ** 3, 1),
        "mem_used_pct": vm.percent,
        "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
        "signature_checked": do_signature,
    }

    summary = {
        "process_count": len(procs),
        "app_count": sum(1 for p in procs if p["windows"]),
        "service_count": len(services),
        "service_running": sum(1 for s in services if s["status"] == "running"),
        "conn_count": len(conns),
        "conn_established": sum(1 for c in conns if c["status"] == psutil.CONN_ESTABLISHED),
        "conn_listen": sum(1 for c in conns if c["status"] == psutil.CONN_LISTEN),
        "persist_count": len(persist),
        "risk": risk_count,
        "risk_total": len(F.items),
    }

    data = {
        "meta": meta,
        "summary": summary,
        "processes": procs,
        "services": services,
        "connections": conns,
        "persistence": persist,
        "findings": sorted(F.items, key=lambda f: SEV_ORDER[f["severity"]]),
    }
    return data


def save_json(data: dict, path: str) -> None:
    with open(path, "w", encoding="utf-8") as fp:
        json.dump(data, fp, ensure_ascii=False, indent=2)


def print_summary(data: dict) -> None:
    meta, summary = data["meta"], data["summary"]
    risk_count = summary["risk"]
    print("\n" + "=" * 72)
    print(f"扫描完成 | 主机 {meta['host']} | {meta['scan_time']} | 耗时 {meta['duration']}s")
    print("-" * 72)
    print(f"进程 {summary['process_count']} (含窗口应用 {summary['app_count']}) | "
          f"服务 {summary['service_count']} (运行中 {summary['service_running']}) | "
          f"连接 {summary['conn_count']} (已建立 {summary['conn_established']}, "
          f"监听 {summary['conn_listen']}) | 持久化项 {summary['persist_count']}")
    print(f"风险项 {summary['risk_total']}："
          f"严重 {risk_count['严重']} / 高危 {risk_count['高危']} / "
          f"中危 {risk_count['中危']} / 低危 {risk_count['低危']} / 提示 {risk_count['提示']}")
    print("=" * 72)
    for f in data["findings"][:20]:
        print(f"[{f['severity']}] {f['target_type']} | {f['title']}")
        print(f"        {f['detail'][:150]}")
    if len(data["findings"]) > 20:
        print(f"... 其余 {len(data['findings']) - 20} 条见 JSON / HTML 报告")


def main():
    ap = argparse.ArgumentParser(description="系统进程与服务安全扫描器")
    ap.add_argument("--json", default="", help="JSON 结果输出路径")
    ap.add_argument("--no-signature", action="store_true", help="跳过数字签名校验（更快）")
    ap.add_argument("--no-tasks", action="store_true", help="跳过计划任务与启动项采集")
    args = ap.parse_args()

    data = run_scan(do_signature=not args.no_signature, do_tasks=not args.no_tasks)

    out = args.json or os.path.join(os.path.dirname(os.path.abspath(__file__)), "scan_result.json")
    save_json(data, out)
    print(f"\nJSON 结果：{out}")
    print_summary(data)


if __name__ == "__main__":
    main()
