# -*- coding: utf-8 -*-
"""实时硬件指标采样：CPU / 内存 / GPU 使用率 / 显存占用 / CPU 温度 / GPU 温度。

────────────────────────────────────────────────────────────────────────
为什么不用现成的库、不 spawn 子进程
────────────────────────────────────────────────────────────────────────
- psutil 在 Windows 上既没有 sensors_temperatures()，也读不到 GPU；
- pynvml / py3nvml 只覆盖 NVIDIA，且要给打包体积再加依赖；
- 常见做法是每几秒调一次 nvidia-smi / PowerShell Get-Counter —— 本工具刻意避免：
  一个安全监控程序自己每 3 秒拉起一个解释器或子进程，既浪费 CPU，
  又恰好落在杀毒软件「高频创建子进程 + 查询性能计数器」的启发式规则里。
  安全工具不该长成它自己要抓的样子。

────────────────────────────────────────────────────────────────────────
实际使用的数据源（全部是 Windows 原生能力，零子进程）
────────────────────────────────────────────────────────────────────────
1. GPU 使用率 / 显存：Windows 性能计数器(PDH) —— \\GPU Engine、\\GPU Adapter Memory，
   用 ctypes 直连 pdh.dll，单次采样 5~10ms。任何厂商(Intel/AMD/NVIDIA)都适用。
2. CPU 温度：
   a. 首选 LibreHardwareMonitor / OpenHardwareMonitor 的 WMI 命名空间（若该程序在运行）
      —— 这是 Windows 上唯一可靠的 CPU 封装/核心温度来源；
   b. 退化为 ACPI 热区(PDH \\Thermal Zone Information)。注意：ACPI 热区常常是
      主板/机身温度而非 CPU 核心温度，本模块会如实标注来源，不冒充 CPU 核心温度。
3. GPU 温度：PDH 拿不到（驱动不导出）。有 nvidia-smi 时取其读数；LHM 在运行也能取；
   否则如实返回 None，界面显示 “—”。绝不猜一个数字。

PDH 查询句柄不是线程安全的，本模块只允许从同一个线程（界面线程）调用 sample()；
nvidia-smi / LHM 这两条会产生子进程的路径在后台线程按低频率刷新并缓存。
"""

from __future__ import annotations

import ctypes
import os
import re
import shutil
import subprocess
import threading
import time
from ctypes import wintypes

import psutil

CREATE_NO_WINDOW = 0x08000000

# ---------------- PDH 计数器路径 ----------------
# 用 PdhAddEnglishCounterW 添加，英文计数器名在中文系统上同样有效
GPU_ENGINE_PATH = r"\GPU Engine(*)\Utilization Percentage"
GPU_MEM_DEDICATED_PATH = r"\GPU Adapter Memory(*)\Dedicated Usage"
GPU_MEM_SHARED_PATH = r"\GPU Adapter Memory(*)\Shared Usage"
GPU_MEM_COMMITTED_PATH = r"\GPU Adapter Memory(*)\Total Committed"
THERMAL_ZONE_PATH = r"\Thermal Zone Information(*)\Temperature"

PDH_FMT_DOUBLE = 0x00000200
PDH_MORE_DATA = 0x800007D2

# nvidia-smi / LHM 走的低频刷新间隔（默认每 3 个采样周期才真的去查一次）
NVSMI_INTERVAL_S = 9.0
LHM_INTERVAL_S = 15.0
# 速率型计数器（GPU 利用率）两次采集至少要隔这么久，否则短间隔会算出无意义的抖动值
MIN_RATE_INTERVAL_S = 1.0

_PID_PREFIX = re.compile(r"^pid_\d+_")
_ADAPTER_KEY = re.compile(r"(luid_0x[0-9a-fA-F]+_0x[0-9a-fA-F]+_phys_\d+)")
GPU_CLASS_KEY = r"SYSTEM\CurrentControlSet\Control\Class\{4d36e968-e325-11ce-bfc1-08002be10318}"


# ======================================================================
# Windows 性能计数器（PDH）最小封装
# ======================================================================

class _PDH_FMT_COUNTERVALUE(ctypes.Structure):
    _fields_ = [("CStatus", wintypes.DWORD), ("doubleValue", ctypes.c_double)]


class _PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [("szName", wintypes.LPWSTR), ("FmtValue", _PDH_FMT_COUNTERVALUE)]


class PdhQuery:
    """一个 PDH 查询：开一次、长期复用，每次采样只 PdhCollectQueryData + 读数。

    这是本模块性能的关键——PDH 首次打开查询略贵，缓存后单次采样不到 10ms。
    """

    def __init__(self):
        self._pdh = ctypes.WinDLL("pdh", use_last_error=True)
        self._bind()
        self.h = ctypes.c_void_p()
        st = self._pdh.PdhOpenQueryW(None, None, ctypes.byref(self.h))
        if st:
            raise OSError(f"PdhOpenQueryW 失败 0x{st:08X}")
        self._counters: dict[str, ctypes.c_void_p] = {}
        self._failed: dict[str, int] = {}

    def _bind(self):
        p = self._pdh
        p.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p,
                                    ctypes.POINTER(ctypes.c_void_p)]
        p.PdhOpenQueryW.restype = wintypes.DWORD
        p.PdhAddEnglishCounterW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR,
                                            ctypes.c_void_p,
                                            ctypes.POINTER(ctypes.c_void_p)]
        p.PdhAddEnglishCounterW.restype = wintypes.DWORD
        p.PdhCollectQueryData.argtypes = [ctypes.c_void_p]
        p.PdhCollectQueryData.restype = wintypes.DWORD
        p.PdhGetFormattedCounterArrayW.argtypes = [ctypes.c_void_p, wintypes.DWORD,
                                                   ctypes.POINTER(wintypes.DWORD),
                                                   ctypes.POINTER(wintypes.DWORD),
                                                   ctypes.c_void_p]
        p.PdhGetFormattedCounterArrayW.restype = wintypes.DWORD
        p.PdhCloseQuery.argtypes = [ctypes.c_void_p]
        p.PdhCloseQuery.restype = wintypes.DWORD

    def add(self, path: str) -> bool:
        """添加计数器；同一路径只加一次。返回是否可用（不可用会被记住，不再重试）。"""
        if path in self._failed:
            return False
        if path in self._counters:
            return True
        hc = ctypes.c_void_p()
        st = self._pdh.PdhAddEnglishCounterW(self.h, path, None, ctypes.byref(hc))
        if st:
            self._failed[path] = st
            return False
        self._counters[path] = hc
        return True

    def why_failed(self, path: str) -> str:
        return f"0x{self._failed[path]:08X}" if path in self._failed else ""

    def collect(self) -> bool:
        st = self._pdh.PdhCollectQueryData(self.h)
        return st == 0

    def read(self, path: str) -> list[tuple[str, float, int]]:
        """读取通配符计数器展开后的全部实例 → [(实例名, 值, 状态码)]。

        必须严格两段式：先问需要多大缓冲，再按报告尺寸取数；
        若取数期间实例数增长了（GPU 引擎实例随进程数变化，这很常见），
        会返回 PDH_MORE_DATA，此时重试而不是硬读——硬读会越界访问直接崩溃。
        """
        hc = self._counters.get(path)
        if hc is None:
            return []
        for _ in range(4):
            size, count = wintypes.DWORD(0), wintypes.DWORD(0)
            st = self._pdh.PdhGetFormattedCounterArrayW(
                hc, PDH_FMT_DOUBLE, ctypes.byref(size), ctypes.byref(count), None)
            if st == 0 and count.value == 0:
                return []
            if st not in (0, PDH_MORE_DATA):
                return []
            need = max(size.value, 1) + 65536      # 留余量，抵消实例数抖动
            buf = ctypes.create_string_buffer(need)
            size2 = wintypes.DWORD(need)
            count2 = wintypes.DWORD()
            st = self._pdh.PdhGetFormattedCounterArrayW(
                hc, PDH_FMT_DOUBLE, ctypes.byref(size2), ctypes.byref(count2), buf)
            if st == 0:
                cap = need // ctypes.sizeof(_PDH_FMT_COUNTERVALUE_ITEM_W)
                arr = ctypes.cast(buf, ctypes.POINTER(_PDH_FMT_COUNTERVALUE_ITEM_W))
                out = []
                for i in range(min(count2.value, cap)):
                    nm = arr[i].szName
                    out.append((nm or "", arr[i].FmtValue.doubleValue,
                                arr[i].FmtValue.CStatus))
                return out
            if st != PDH_MORE_DATA:
                return []
        return []

    def close(self):
        try:
            self._pdh.PdhCloseQuery(self.h)
        except Exception:
            pass


# ======================================================================
# 数据解析（纯函数，便于单测）
# ======================================================================

def aggregate_gpu_utilization(items) -> tuple[dict, float | None]:
    """把 PDH 的 (进程 × 引擎) 实例聚合为「各引擎类型合计」，返回 (分组, 峰值%)。

    口径对齐任务管理器：同一 (适配器, 引擎类型) 下所有进程求和，
    再取最忙的引擎类型作为整体 GPU 使用率。
    实例名形如 pid_15912_luid_0x00000000_0x0001045C_phys_0_eng_0_engtype_3D
    """
    per_engine: dict[tuple[str, str], float] = {}
    for name, val in items:
        m = _ADAPTER_KEY.search(name)
        if not m or "_engtype" not in name:
            continue
        # 实例名以 "_engtype" 结尾接引擎类型，前缀自带一个下划线；空类型的实例直接丢弃
        engtype = name.rsplit("_engtype", 1)[-1].lstrip("_").strip()
        if not engtype:
            continue
        key = (m.group(1).lower(), engtype)
        per_engine[key] = per_engine.get(key, 0.0) + val
    if not per_engine:
        return {}, None
    peak = max(per_engine.values())
    return per_engine, min(peak, 100.0)      # 多进程叠加可能超过 100，钳到 100


def adapter_of(instance_name: str) -> str | None:
    m = _ADAPTER_KEY.search(instance_name or "")
    return m.group(1).lower() if m else None


def thermal_zones_to_celsius(items) -> tuple[float | None, str]:
    """ACPI 热区读数（开尔文）→ 摄氏度。返回 (最高温度, 热区名)。"""
    best, best_name = None, ""
    for name, val, st in items:
        if st != 0 or not (200.0 <= val <= 400.0):   # 排除无效/未初始化的 0 K
            continue
        if best is None or val > best:
            best, best_name = val, name.strip("\\")
    if best is None:
        return None, ""
    return best - 273.15, best_name


def parse_nvidia_smi(text: str) -> dict:
    """解析 nvidia-smi CSV 输出（取第一个 GPU）。

    行格式: name, utilization.gpu, memory.used, memory.total, temperature.gpu
    """
    out: dict = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or "," not in line:
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 5:
            continue
        try:
            out = {
                "name": parts[0],
                "util": float(parts[1]),
                "mem_used_mb": float(parts[2]),
                "mem_total_mb": float(parts[3]),
                "temp": float(parts[4]),
            }
        except ValueError:
            continue
        break
    return out


def pick_cpu_temp_from_lhm(rows) -> float | None:
    """从 LHM/OHM 的 Sensor 行里挑 CPU 封装温度。

    rows: [{"Name": "CPU Package", "SensorType": "Temperature", "Value": 45.0}, ...]
    优先级：CPU Package > CPU (Tctl/Tdie) > Core Max > Core Average > 任一含 CPU 的温度
    """
    temps = [r for r in (rows or [])
             if str(r.get("SensorType", "")).lower() == "temperature"
             and isinstance(r.get("Value"), (int, float))]
    if not temps:
        return None
    for pat in ("cpu package", "cpu (tctl/tdie)", "cpu tctl", "core max",
                "core average", "cpu"):
        for r in temps:
            nm = str(r.get("Name", "")).lower()
            if pat in nm:
                return float(r["Value"])
    return None


def pick_gpu_temp_from_lhm(rows) -> float | None:
    temps = [r for r in (rows or [])
             if str(r.get("SensorType", "")).lower() == "temperature"
             and isinstance(r.get("Value"), (int, float))]
    for pat in ("gpu core", "gpu hot spot", "gpu"):
        for r in temps:
            if pat in str(r.get("Name", "")).lower():
                return float(r["Value"])
    return None


# ======================================================================
# 注册表读显卡信息（比 WMI 快，且避开 AdapterRAM 的 4GB 截断）
# ======================================================================

def read_gpu_adapters() -> list[dict]:
    """读显卡名称与显存容量。

    Win32_VideoController.AdapterRAM 是 UINT32，超过 4GB 会截断（8GB 显卡报成 0），
    所以改用注册表 HardwareInformation.qwMemorySize（64 位）。
    顺带滤掉「Microsoft 基本显示/远程显示」这类虚拟适配器，否则显卡名会显示成
    「Microsoft Remote Display Adapter / Intel(R) UHD Graphics 630」。
    """
    out: list[dict] = []
    seen: set[str] = set()
    try:
        import winreg
    except ImportError:
        return out
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, GPU_CLASS_KEY) as k:
            i = 0
            while True:
                try:
                    sub = winreg.EnumKey(k, i)
                except OSError:
                    break
                i += 1
                if not sub.isdigit():
                    continue
                try:
                    with winreg.OpenKey(k, sub) as sk:
                        try:
                            name = str(winreg.QueryValueEx(sk, "DriverDesc")[0]).strip()
                        except OSError:
                            continue
                        if not name or _is_virtual_adapter(name) or name.lower() in seen:
                            continue
                        seen.add(name.lower())
                        vram = 0
                        try:
                            raw = winreg.QueryValueEx(
                                sk, "HardwareInformation.qwMemorySize")[0]
                            vram = (int.from_bytes(raw, "little")
                                    if isinstance(raw, bytes) else int(raw))
                        except OSError:
                            pass
                        out.append({"name": name, "vram": vram})
                except OSError:
                    continue
    except OSError:
        pass
    return out


_VIRTUAL_ADAPTER_HINTS = ("microsoft remote display", "microsoft basic display",
                          "microsoft basic render", "microsoft hyper-v",
                          "remote display adapter", "idd device")


def _is_virtual_adapter(name: str) -> bool:
    low = name.lower()
    return any(h in low for h in _VIRTUAL_ADAPTER_HINTS)


def find_nvidia_smi() -> str:
    p = shutil.which("nvidia-smi")
    if p:
        return p
    for c in (os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                           "System32", "nvidia-smi.exe"),
              os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files"),
                           "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe"),
              os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"),
                           "NVIDIA Corporation", "NVSMI", "nvidia-smi.exe")):
        if os.path.isfile(c):
            return c
    return ""


def _run_hidden(argv, timeout=6.0) -> str:
    """静默执行外部命令并返回 stdout（不弹控制台窗口）。"""
    try:
        p = subprocess.run(argv, capture_output=True, timeout=timeout,
                           creationflags=CREATE_NO_WINDOW)
        return p.stdout.decode("utf-8", "replace")
    except Exception:
        return ""


def _run_ps(script: str, timeout=8.0) -> str:
    """静默执行 PowerShell（UTF-16LE base64，规避引号与编码问题）。"""
    import base64
    enc = base64.b64encode(script.encode("utf-16-le")).decode()
    return _run_hidden(["powershell.exe", "-NoProfile", "-NonInteractive",
                        "-ExecutionPolicy", "Bypass", "-EncodedCommand", enc], timeout)


# ======================================================================
# 采样器
# ======================================================================

class MetricsSampler:
    """实时指标采样器。界面线程按固定间隔调用 sample() 即可。"""

    def __init__(self):
        self.adapters = read_gpu_adapters()
        self.nvidia_smi = find_nvidia_smi()
        self._lhm_ns = ""                  # ""=未探测, "-"=确认不存在
        self._nvsmi: dict = {}
        self._nvsmi_at = 0.0
        self._nvsmi_busy = False
        self._lhm_rows: list = []
        self._lhm_at = 0.0
        self._lhm_busy = False
        self._last: dict = {}
        self._last_collect = 0.0
        self.warnings: list[str] = []
        self._warmup()                     # 预建 PDH 查询 + 一次性基线采集

    def _warmup(self):
        """把用得到的计数器一次性加进查询，并先采集一次建立速率基线。

        速率型计数器需要两次采集之间的时间差才有值，所以这里先垫一次；
        真正的第一次读数会在界面首次刷新时产生（间隔通常已 >1 秒）。
        """
        q = self._pdh
        if q is None:
            self.warnings.append("无法打开 Windows 性能计数器(PDH)，GPU 指标将不可用。")
            return
        for path in (GPU_ENGINE_PATH, GPU_MEM_DEDICATED_PATH, GPU_MEM_SHARED_PATH,
                     GPU_MEM_COMMITTED_PATH, THERMAL_ZONE_PATH):
            q.add(path)
        q.collect()
        self._last_collect = time.monotonic()

    # ---------- 能力描述（供“指标来源说明”用） ----------

    @property
    def lhm_active(self) -> bool:
        """LibreHardwareMonitor/OpenHardwareMonitor 是否真的在用。

        self._lhm_ns 有三态："" 未探测、"-" 已确认没有、其余为真实命名空间名。
        "-" 是 truthy 的，直接拿它做判断会让界面在没有 LHM 的机器上
        谎称「CPU 温度来源：LibreHardwareMonitor（准确）」——必须走这个属性。
        """
        return self._lhm_ns not in ("", "-")

    def info(self) -> dict:
        return {
            "gpu_engine": self._ok(GPU_ENGINE_PATH),
            "gpu_mem": self._ok(GPU_MEM_DEDICATED_PATH) or self._ok(GPU_MEM_COMMITTED_PATH),
            "thermal_zone": self._ok(THERMAL_ZONE_PATH),
            "nvidia_smi": self.nvidia_smi or "",
            "adapters": self.adapters,
            "lhm_ns": self._lhm_ns if self.lhm_active else "",
        }

    def _ok(self, path: str) -> bool:
        try:
            return bool(self._pdh.add(path))
        except Exception:
            return False

    @property
    def _pdh(self) -> PdhQuery | None:
        try:
            if getattr(self, "_pq", None) is None:
                self._pq = PdhQuery()
            return self._pq
        except Exception:
            self._pq = None
            return None

    def source_summary(self) -> list[str]:
        """人类可读的来源说明，用于界面展示（避免用户误读成 CPU 核心温度）。"""
        info = self.info()
        lhm = self.lhm_active
        lines = []
        if info["gpu_engine"]:
            lines.append("GPU 使用率：Windows 性能计数器 \\GPU Engine（任何厂商适用）")
        elif info["nvidia_smi"]:
            lines.append("GPU 使用率：nvidia-smi")
        else:
            lines.append("GPU 使用率：本机不可用（无 GPU 性能计数器，也未安装 nvidia-smi）")

        if info["gpu_mem"]:
            lines.append("显存占用：Windows 性能计数器 \\GPU Adapter Memory")
        else:
            lines.append("显存占用：本机不可用")
        if info["nvidia_smi"]:
            lines.append(f"GPU 温度 / 显存总量：nvidia-smi（{info['nvidia_smi']}）")
        elif lhm:
            lines.append(f"GPU 温度：{self._lhm_ns} WMI（GPU Core）")
        else:
            lines.append("GPU 温度：本机不可用（PDH 不导出 GPU 温度；需 nvidia-smi "
                         "或运行 LibreHardwareMonitor）")

        if lhm:
            lines.append(f"CPU 温度：{self._lhm_ns} WMI（CPU 封装温度，准确）")
        elif info["thermal_zone"]:
            lines.append("CPU 温度：ACPI 热区（Windows 性能计数器）—— 注意这不是 CPU "
                         "核心温度，通常是主板/机身的某个热区；要拿真实封装温度需运行 "
                         "LibreHardwareMonitor 或 HWiNFO")
        else:
            lines.append("CPU 温度：本机不可用（主板未导出 ACPI 热区，也未运行 "
                         "LibreHardwareMonitor）")
        return lines

    # ---------- 采样 ----------

    def sample(self, allow_subprocess: bool = True) -> dict:
        m: dict = {
            "cpu_pct": None, "mem_pct": None, "mem_used_gb": None, "mem_total_gb": None,
            "gpu_util": None, "gpu_engines": {}, "gpu_adapter": None,
            "gpu_mem_used_gb": None, "gpu_mem_total_gb": None,
            "gpu_mem_dedicated_gb": None, "gpu_mem_shared_gb": None,
            "gpu_mem_pct": None,
            "cpu_temp_c": None, "cpu_temp_src": "",
            "gpu_temp_c": None, "gpu_temp_src": "",
            "gpu_name": (self.adapters[0]["name"] if len(self.adapters) == 1 else
                         " / ".join(a["name"] for a in self.adapters[:2])),
            "ts": time.time(),
        }
        try:
            m["cpu_pct"] = psutil.cpu_percent(interval=None)
            vm = psutil.virtual_memory()
            m["mem_pct"] = float(vm.percent)
            m["mem_used_gb"] = (vm.total - vm.available) / 1024 ** 3
            m["mem_total_gb"] = vm.total / 1024 ** 3
        except Exception:
            pass

        self._sample_pdh(m)
        if allow_subprocess:
            self._sample_nvidia(m)
            self._sample_lhm(m)
        self._last = m
        return m

    def _sample_pdh(self, m: dict):
        q = self._pdh
        if q is None:
            return
        now = time.monotonic()
        dt = now - self._last_collect
        if not q.collect():
            return
        self._last_collect = now

        # --- GPU 使用率（速率型：两次采集间隔太短时不出数，避免报出假抖动）---
        usable = dt >= MIN_RATE_INTERVAL_S
        if usable and q.add(GPU_ENGINE_PATH):
            raw = [(n, v) for n, v, st in q.read(GPU_ENGINE_PATH) if st == 0]
            per_engine, peak = aggregate_gpu_utilization(raw)
            m["gpu_engines"] = per_engine
            m["gpu_util"] = peak
            if per_engine:
                m["gpu_adapter"] = max(per_engine.items(), key=lambda kv: kv[1])[0][0]

        # --- 显存：按适配器取合计已提交，主适配器取当前最忙的那个 ---
        # 注意：三个字典必须各自新建 —— 写成 ded = sha = com = {} 会让三个名字
        # 绑定到同一个 dict，后读的计数器会把先读的覆盖掉（这个坑踩过一次）。
        ded, sha, com = {}, {}, {}
        for path, bucket in ((GPU_MEM_DEDICATED_PATH, ded),
                             (GPU_MEM_SHARED_PATH, sha),
                             (GPU_MEM_COMMITTED_PATH, com)):
            if not q.add(path):
                continue
            for name, val, st in q.read(path):
                if st != 0:
                    continue
                key = adapter_of(name)
                if key:
                    bucket[key] = val
        if com or ded or sha:
            pick = None
            util_engines = m.get("gpu_engines") or {}
            if m.get("gpu_adapter") and m["gpu_adapter"] in com:
                pick = m["gpu_adapter"]
            if pick is None:
                pool = com or ded
                pick = max(pool.items(), key=lambda kv: kv[1])[0] if pool else None
            if pick:
                m["gpu_mem_used_gb"] = com.get(pick, (ded.get(pick, 0) + sha.get(pick, 0))) / 1024 ** 3
                m["gpu_mem_dedicated_gb"] = ded.get(pick, 0.0) / 1024 ** 3
                m["gpu_mem_shared_gb"] = sha.get(pick, 0.0) / 1024 ** 3
                m["gpu_adapter"] = m.get("gpu_adapter") or pick

        # --- CPU 温度（先看 LHM，没有才用 ACPI 热区）---
        if self._lhm_rows:
            t = pick_cpu_temp_from_lhm(self._lhm_rows)
            if t is not None:
                m["cpu_temp_c"], m["cpu_temp_src"] = t, "LHM"
        if m["cpu_temp_c"] is None and q.add(THERMAL_ZONE_PATH):
            t, zone = thermal_zones_to_celsius(q.read(THERMAL_ZONE_PATH))
            if t is not None:
                m["cpu_temp_c"], m["cpu_temp_src"] = t, f"ACPI:{zone}"

        # --- GPU 温度（同样先看 LHM；nvidia-smi 在另一路填充）---
        if self._lhm_rows:
            t = pick_gpu_temp_from_lhm(self._lhm_rows)
            if t is not None:
                m["gpu_temp_c"], m["gpu_temp_src"] = t, "LHM"
        if self._nvsmi.get("temp") is not None and m["gpu_temp_c"] is None:
            m["gpu_temp_c"], m["gpu_temp_src"] = self._nvsmi["temp"], "nvidia-smi"

    def _sample_nvidia(self, m: dict):
        if not self.nvidia_smi:
            return
        now = time.time()
        if (not self._nvsmi_busy) and now - self._nvsmi_at >= NVSMI_INTERVAL_S:
            self._nvsmi_busy = True
            self._nvsmi_at = now

            def worker():
                try:
                    out = _run_hidden([self.nvidia_smi, "--query-gpu=name,"
                                       "utilization.gpu,memory.used,memory.total,"
                                       "temperature.gpu", "--format=csv,noheader,nounits"])
                    parsed = parse_nvidia_smi(out)
                    if parsed:
                        self._nvsmi = parsed
                finally:
                    self._nvsmi_busy = False

            threading.Thread(target=worker, daemon=True).start()
        d = self._nvsmi
        if not d:
            return
        m["gpu_name"] = d.get("name") or m["gpu_name"]
        if d.get("util") is not None:
            m["gpu_util"] = d["util"]                       # nvidia-smi 比 PDH 更准
        if d.get("mem_used_mb"):
            m["gpu_mem_used_gb"] = d["mem_used_mb"] / 1024
        if d.get("mem_total_mb"):
            m["gpu_mem_total_gb"] = d["mem_total_mb"] / 1024
            if m["gpu_mem_used_gb"] is not None and m["gpu_mem_total_gb"]:
                m["gpu_mem_pct"] = min(m["gpu_mem_used_gb"] / m["gpu_mem_total_gb"] * 100, 100)
        if d.get("temp") is not None:
            m["gpu_temp_c"], m["gpu_temp_src"] = d["temp"], "nvidia-smi"

    def _sample_lhm(self, m: dict):
        """LHM/OHM 在运行才走这条；否则最多一次探测后彻底放弃。"""
        now = time.time()
        if (not self._lhm_busy) and now - self._lhm_at >= LHM_INTERVAL_S:
            self._lhm_at = now
            self._lhm_busy = True

            def worker():
                try:
                    if not self._lhm_ns:
                        # 一次 PowerShell 调用同时判定两个命名空间，避免每次多 spawn 一次
                        out = _run_ps(
                            "$n = Get-CimInstance -Namespace root -ClassName __NAMESPACE "
                            "-ErrorAction SilentlyContinue | "
                            "Select-Object -ExpandProperty Name; "
                            "if ($n -contains 'LibreHardwareMonitor') "
                            "{ 'LibreHardwareMonitor' } "
                            "elseif ($n -contains 'OpenHardwareMonitor') "
                            "{ 'OpenHardwareMonitor' } else { 'NO' }", timeout=8)
                        got = out.strip().splitlines()[-1].strip() if out.strip() else "NO"
                        self._lhm_ns = got if got in ("LibreHardwareMonitor",
                                                      "OpenHardwareMonitor") else "-"
                    if self.lhm_active:
                        import json as _json
                        out = _run_ps(
                            f"Get-CimInstance -Namespace root/{self._lhm_ns} "
                            "-ClassName Sensor | Where-Object {$_.SensorType -eq "
                            "'Temperature'} | Select-Object Name,SensorType,Value | "
                            "ConvertTo-Json -Compress", timeout=8)
                        data = _json.loads(out) if out.strip().startswith(("[", "{")) else []
                        self._lhm_rows = data if isinstance(data, list) else [data]
                except Exception:
                    pass
                finally:
                    self._lhm_busy = False

            threading.Thread(target=worker, daemon=True).start()

    def close(self):
        try:
            if getattr(self, "_pq", None):
                self._pq.close()
        except Exception:
            pass


# ======================================================================
# 自检：python metrics.py --probe
# ======================================================================

def _probe():
    print("=" * 72, flush=True)
    print("硬件指标采样自检", flush=True)
    print("=" * 72, flush=True)
    s = MetricsSampler()
    print("\n[1] 能力探测", flush=True)
    for k, v in s.info().items():
        print(f"    {k}: {v}", flush=True)
    print("\n[2] 数据源说明", flush=True)
    for line in s.source_summary():
        print(f"    - {line}", flush=True)
    print("\n[3] 连续 4 次采样（间隔 1.2s）", flush=True)
    for i in range(4):
        t0 = time.perf_counter()
        m = s.sample()
        dt = (time.perf_counter() - t0) * 1000
        print(f"\n    第 {i + 1} 次（采样耗时 {dt:.1f} ms）", flush=True)
        print(f"      CPU {m['cpu_pct']}%   内存 {m['mem_pct']}% "
              f"({m['mem_used_gb']:.1f}/{m['mem_total_gb']:.1f} GB)", flush=True)
        print(f"      GPU {m['gpu_util']}%   适配器 {m['gpu_adapter']}   "
              f"名称 {m['gpu_name']}", flush=True)
        print(f"      显存 已用 {m['gpu_mem_used_gb']} GB "
              f"(独立 {m['gpu_mem_dedicated_gb']} / 共享 {m['gpu_mem_shared_gb']}) "
              f"总量 {m['gpu_mem_total_gb']}", flush=True)
        print(f"      CPU 温度 {m['cpu_temp_c']} [{m['cpu_temp_src']}]   "
              f"GPU 温度 {m['gpu_temp_c']} [{m['gpu_temp_src']}]", flush=True)
        top = sorted((m["gpu_engines"] or {}).items(), key=lambda kv: -kv[1])[:4]
        for (ad, eng), val in top:
            print(f"        引擎 {eng:<16} {val:6.2f}%   {ad}", flush=True)
        time.sleep(1.2)
    print("\n[4] 关闭查询", flush=True)
    s.close()
    print("DONE", flush=True)


if __name__ == "__main__":
    import sys
    if "--probe" in sys.argv:
        _probe()
    else:
        print(__doc__)
