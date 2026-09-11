# -*- coding: utf-8 -*-
"""单实例运行守卫：同一时间只允许一个程序实例在运行。

================================================================================
一、为什么用两套机制（这是本模块的核心设计）
================================================================================

机制 A：内核锁 —— 权威判据
    Windows：命名互斥体 `Local\\<key>.single.v1`（CreateMutexW）
    POSIX  ：`fcntl.flock(LOCK_EX|LOCK_NB)` 锁住锁文件

    为什么它是权威的：**所有权由操作系统内核维护**。进程无论正常退出、抛异常
    崩溃、还是被任务管理器强杀，内核都会立刻回收这个锁对象。
    所以"进程已经死了但锁还留着"这种情况在机制 A 下**不可能发生** —— 这正是
    "异常退出后锁的释放"这个问题的正解：不靠清理代码，靠内核兜底。

    命名规则用 `Local\\` 前缀（会话内命名空间）而不是 `Global\\`：
      · Local\ 是按登录会话隔离的，符合桌面程序语义（不同用户/不同会话各允许一个）
      · Global\ 需要 SeCreateGlobalPrivilege，普通权限进程创建会失败

机制 B：锁文件 instance.lock —— 只负责"说清是谁在占用"
    内容是一段 JSON 元数据：进程号 / 启动时间 / 可执行文件 / 用户 / 主机 /
    是否管理员 / 版本。用途：
      1. 提示语里告诉用户是谁占着（进程号、启动时间、以什么权限运行）
      2. 让用户能判断该关哪个窗口
    它**从不单独作为判据**：这个文件确实可能因异常退出而残留（进程被强杀时
    来不及删），所以任何"文件存在"的结论都必须再用 PID 存活性交叉验证。

================================================================================
二、判定逻辑
================================================================================

    内核锁已被占用                        → 判定"已有实例"（拿不到锁是最硬的证据）
    内核锁空闲 + 锁文件残留                → 核实文件里的 PID：
        进程已不存在 / PID 已被复用 /
        现在跑的是别的程序                 → 陈旧残留 → 清理后接管
        进程活着且确是本程序               → 判定"已有实例"
                                              （如旧版本实例、或用 --allow-multi
                                                启动的实例，它们不持内核锁）
    内核锁空闲 + 无锁文件                  → 正常启动

    PID 复用防护：只比 PID 会误判（PID 会被系统回收再分配）。所以锁文件同时记录
    进程创建时间，核验时要求"创建时间吻合（±2 秒）且可执行文件一致"，两条都满足
    才认定为同一个进程。

    跨权限核验：普通权限实例去查询管理员实例的创建时间会拿到 AccessDenied。
    此时**保守地判定为存活**（宁可误报"已在运行"也不误判成陈旧而多开一个实例）。

================================================================================
三、与"以管理员身份运行"的交接（这个功能与单实例天然冲突）
================================================================================

提权重启必须再起一个进程，因此与单实例检测天然冲突。约定：

    · 普通启动             → 抢不到锁就提示 + 退出（exit code 3）
    · `--elevated-token`   → 这是**用户主动发起的交接**，不拒绝。
      顺序必须是：先让窗口显示并写出交接标记 → 前任看到标记后退出并释放锁
      → 新实例再接管锁。
      顺序不能颠倒：前任唯一的退出触发条件就是那个交接标记，如果新实例先卡在
      等锁上，两边会互相等到超时（提权功能整体失效）。
      等待有上限（ELEVATE_HANDOFF_WAIT_MS），超时则**降级继续运行**并在状态栏
      说明 —— 用户主动要求的提权不该被一个卡死的前任进程挡死。

================================================================================
四、跨平台兼容性
================================================================================

    · 内核锁与锁文件都放在"每用户每会话"的位置，路径来自 %LOCALAPPDATA%，
      POSIX 上退化为 ~/.cache 或 $TMPDIR。
    · POSIX 分支用 `import fcntl`（惰性导入，Windows 上无此模块）实现 flock，
      同样具备"进程死亡即自动释放"的性质。
    · 兜底：若内核锁机制不可用（极少数情况下 CreateMutex 返回意外错误），
      自动降级为 `O_CREAT|O_EXCL` 原子创建锁文件 + PID 存活性检查。
      这条路径不依赖任何平台专有 API，任何平台都能跑。
    · 说明：本程序其余部分（psutil 服务查询、PDH 计数器、winreg、ShellExecuteExW）
      本身是 Windows 专用的；本模块是唯一做跨平台处理的层，独立可用。

================================================================================
五、用法
================================================================================

    guard = InstanceGuard("SysScanGUI")
    ok, owner = guard.acquire()              # 普通启动
    if not ok:
        report_conflict(owner, "系统进程与服务安全扫描器")
        sys.exit(EXIT_ALREADY_RUNNING)
    ...
    guard.release()                          # 退出时（异常退出由内核兜底）

命令行自检/诊断（测试与运维用）：

    python single_instance.py --status       # 是否有实例在运行，占用则退出码 3
    python single_instance.py --hold 10      # 持锁 10 秒（模拟一个运行中的实例）
"""
from __future__ import annotations

import json
import os
import socket
import sys
import tempfile
import time
from dataclasses import dataclass, field

APP_ID_DEFAULT = "SysScanGUI"
EXIT_ALREADY_RUNNING = 3

# 提权交接时等待前任释放锁的上限；超时则降级继续运行
ELEVATE_HANDOFF_WAIT_MS = 15000
# 接管轮的轮询间隔
HANDOFF_POLL_MS = 200

# 锁文件里的进程创建时间与该进程真实创建时间的允许偏差（秒）
CREATE_TIME_TOLERANCE = 2.0

# Windows 错误码
ERROR_ALREADY_EXISTS = 183
ERROR_ACCESS_DENIED = 5

# 锁文件残留多久之后即使无法核验也算陈旧（秒）；防止"锁文件写的 PID 恰好
# 与某个无关进程撞上且 psutil 又读不到信息"时把程序永久挡在门外
STALE_FILE_MAX_AGE = 7 * 86400

_IS_WIN = os.name == "nt"


# ============================================================================
# 占用者信息
# ============================================================================

@dataclass
class InstanceInfo:
    """占用者的可读信息（来自锁文件；核验后可判断是否已是陈旧残留）。"""

    pid: int = 0
    started: float = 0.0
    exe: str = ""
    user: str = ""
    host: str = ""
    elevated: bool = False
    version: str = ""
    session_id: int = 0
    wrote_at: float = 0.0
    stale: bool = False          # 经核验判定为陈旧残留（占用者其实已不存在）
    reason: str = ""             # 判定依据（用于日志与提示语）

    # ---------- 展示 ----------

    def started_text(self) -> str:
        if not self.started:
            return "未知"
        try:
            return time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(self.started))
        except (OSError, ValueError):
            return "未知"

    def describe(self, indent: str = "\u3000\u3000") -> str:
        """多行描述，用于提示语正文。

        缩进默认用全角空格：原生 MessageBox 会把每行开头的半角空格吃掉，
        用全角空格才能真的显示出缩进层级。
        """
        if not self.pid:
            return indent + (self.reason or "无法获取占用者信息")
        lines = [
            f"进程号：{self.pid}"
            + ("（以管理员身份运行）" if self.elevated else "（普通权限）"),
            f"启动时间：{self.started_text()}",
        ]
        if self.exe:
            lines.append(f"程序：{self.exe}")
        if self.user or self.host:
            lines.append(f"用户 / 主机：{self.user or '?'} / {self.host or '?'}")
        if self.reason:
            lines.append(f"判定依据：{self.reason}")
        return "\n".join(indent + x for x in lines)

    def as_dict(self) -> dict:
        return {"pid": self.pid, "started": self.started, "exe": self.exe,
                "user": self.user, "host": self.host, "elevated": self.elevated,
                "version": self.version, "session_id": self.session_id,
                "wrote_at": self.wrote_at}


# ============================================================================
# 路径与进程核验
# ============================================================================

def default_lock_dir() -> str:
    """锁文件目录：每用户（可用环境变量覆盖，测试用它做隔离）。"""
    env = os.environ.get("SYSSCAN_LOCK_DIR")
    if env:
        return env
    if _IS_WIN:
        base = os.environ.get("LOCALAPPDATA") or os.environ.get("TEMP")
    else:
        base = (os.environ.get("XDG_CACHE_HOME")
                or os.path.join(os.path.expanduser("~"), ".cache"))
    base = base or tempfile.gettempdir()
    return os.path.join(base, APP_ID_DEFAULT)


def current_key() -> str:
    return os.environ.get("SYSSCAN_INSTANCE_KEY") or APP_ID_DEFAULT


def _norm(path: str) -> str:
    try:
        return os.path.normcase(os.path.abspath(path))
    except Exception:
        return (path or "").lower()


def _file_age(path: str) -> float | None:
    """锁文件的存在时长（秒）；读不到返回 None。"""
    try:
        return max(0.0, time.time() - os.path.getmtime(path))
    except OSError:
        return None


def pid_is_our_instance(pid: int, started: float = 0.0, exe: str = "") -> tuple[bool, str]:
    """核验某个 PID 是否仍是"本程序的那个实例"。

    返回 (是否仍存活, 说明)。注意：拿不到信息时一律偏保守（判为存活），
    因为"误判成活"只会多拦一次启动，"误判成死"会真的多开一个实例。
    """
    if not pid or pid <= 0:
        return False, "锁文件未记录有效进程号"
    try:
        import psutil
    except ImportError:
        return True, "本机缺少 psutil，无法核验进程，保守判定为仍在运行"
    try:
        proc = psutil.Process(pid)
    except psutil.NoSuchProcess:
        return False, f"进程 {pid} 已不存在"
    except psutil.AccessDenied:
        return True, f"进程 {pid} 存在但无权查看（通常是管理员权限实例）"
    except Exception as exc:
        return True, f"核验进程 {pid} 时出错（{exc}），保守判定为仍在运行"

    try:
        created = proc.create_time()
    except psutil.NoSuchProcess:
        return False, f"进程 {pid} 已不存在"
    except psutil.AccessDenied:
        return True, f"进程 {pid} 存在但无权读取创建时间（通常是管理员权限实例）"
    except Exception:
        return True, f"进程 {pid} 的创建时间读取失败，保守判定为仍在运行"

    if started and abs(created - started) > CREATE_TIME_TOLERANCE:
        return False, (f"进程号 {pid} 已被系统复用"
                       f"（当前进程创建于 {time.strftime('%H:%M:%S', time.localtime(created))}，"
                       f"与记录的 {time.strftime('%H:%M:%S', time.localtime(started))} 不符）")

    if exe:
        try:
            live = proc.exe() or ""
        except (psutil.AccessDenied, psutil.NoSuchProcess):
            live = ""
        except Exception:
            live = ""
        if live and _norm(live) != _norm(exe):
            return False, f"进程号 {pid} 现在运行的是别的程序（{live}）"

    return True, ""


def current_process_meta(elevated: bool = False) -> dict:
    """当前进程的可读元数据，写进锁文件供占用者展示。"""
    exe = ""
    if getattr(sys, "frozen", False):
        exe = os.path.abspath(sys.executable)
    else:
        try:
            import psutil
            exe = psutil.Process().exe()
        except Exception:
            exe = os.path.abspath(sys.executable)
    try:
        started = (import_psutil().Process().create_time()
                   if import_psutil() else time.time())
    except Exception:
        started = time.time()
    return {
        "pid": os.getpid(),
        "started": started,
        "exe": exe,
        "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        "host": socket.gethostname(),
        "elevated": bool(elevated),
        "version": getattr(sys, "sysscan_version", ""),
        "session_id": _session_id(),
        "wrote_at": time.time(),
    }


def import_psutil():
    try:
        import psutil
        return psutil
    except ImportError:
        return None


def _session_id() -> int:
    if not _IS_WIN:
        return 0
    try:
        import ctypes
        pid = ctypes.c_ulong(0)
        ctypes.windll.kernel32.ProcessIdToSessionId(os.getpid(), ctypes.byref(pid))
        return int(pid.value)
    except Exception:
        return 0


# ============================================================================
# 机制 A：内核锁的三种实现
# ============================================================================

class _WindowsMutex:
    """命名互斥体。所有权归内核，进程消失即自动释放。"""

    def __init__(self, name: str):
        self.name = name
        self.handle = None
        self._k32 = None

    def try_acquire(self) -> tuple[bool, str]:
        import ctypes
        from ctypes import wintypes
        k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        k32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
        k32.CreateMutexW.restype = wintypes.HANDLE
        k32.CloseHandle.argtypes = [wintypes.HANDLE]
        k32.CloseHandle.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        handle = k32.CreateMutexW(None, False, self.name)
        err = ctypes.get_last_error()
        if not handle:
            if err == ERROR_ACCESS_DENIED:
                # 已有实例且权限比我们高（例如它以管理员身份运行）。
                # 这本身就是"实例已存在"的可靠证据。
                return False, "denied"
            return False, f"error:{err}"
        if err == ERROR_ALREADY_EXISTS:
            # 重要：必须立刻关掉这个句柄。
            # 非所有者句柄同样会让内核对象继续存在；如果留在手里不放，
            # 真正的实例退出后这个名字仍被占用，之后所有启动都会被永久误判
            # 成"已有实例"。
            try:
                k32.CloseHandle(handle)
            except Exception:
                pass
            return False, "exists"
        self._k32 = k32
        self.handle = handle
        return True, ""

    def release(self):
        if self.handle and self._k32:
            try:
                self._k32.CloseHandle(self.handle)
            except Exception:
                pass
        self.handle = None


class _PosixFlock:
    """POSIX 文件锁。进程退出（含被强杀）时内核自动释放。"""

    def __init__(self, path: str):
        self.path = path
        self.fd = None

    def try_acquire(self) -> tuple[bool, str]:
        try:
            import fcntl
        except ImportError:
            return False, "error:no-fcntl"
        try:
            fd = os.open(self.path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError as exc:
            return False, f"error:{exc.errno}"
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            os.close(fd)
            return False, "exists"
        except Exception:
            os.close(fd)
            return False, "error"
        self.fd = fd
        return True, ""

    def release(self):
        if self.fd is None:
            return
        try:
            import fcntl
            fcntl.flock(self.fd, fcntl.LOCK_UN)
        except Exception:
            pass
        try:
            os.close(self.fd)
        except OSError:
            pass
        self.fd = None


class _FileClaim:
    """兜底：原子创建锁文件（O_CREAT|O_EXCL）+ PID 存活性检查。

    不依赖任何平台专有 API；不会自动释放，靠陈旧检测兜底。
    """

    def __init__(self, path: str):
        self.path = path

    def try_acquire(self) -> tuple[bool, str]:
        try:
            fd = os.open(self.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            return False, "exists"
        except OSError as exc:
            return False, f"error:{exc.errno}"
        os.close(fd)
        return True, ""

    def release(self):
        try:
            os.remove(self.path)
        except OSError:
            pass


# ============================================================================
# 守卫
# ============================================================================

class InstanceGuard:
    """单实例守卫。"""

    def __init__(self, key: str = "", lock_dir: str = "", mechanism: str = "auto",
                 elevated: bool = False):
        self.key = key or current_key()
        self.lock_dir = lock_dir or default_lock_dir()
        self.lock_path = os.path.join(self.lock_dir, "instance.lock")
        self.mechanism = mechanism           # auto | mutex | file
        self.elevated = elevated
        self.held = False                    # 是否真正持有内核锁
        self.degraded = False                # 接管超时后的降级运行（未持锁）
        self.last_error = ""
        self._impl = None

    # ---------------- 机制选择 ----------------

    def _make_impl(self):
        mode = self.mechanism
        if mode == "auto":
            mode = "mutex" if _IS_WIN else "flock"
        if mode == "mutex" and not _IS_WIN:
            mode = "flock"
        if mode == "mutex":
            return _WindowsMutex(f"Local\\{self.key}.single.v1"), mode
        if mode == "flock":
            return _PosixFlock(self.lock_path), mode
        return _FileClaim(self.lock_path), "file"

    # ---------------- 锁文件读写 ----------------

    def _ensure_dir(self):
        try:
            os.makedirs(self.lock_dir, exist_ok=True)
        except OSError:
            pass

    def _read_lock_file(self) -> InstanceInfo | None:
        try:
            with open(self.lock_path, encoding="utf-8") as fp:
                raw = json.load(fp)
            if not isinstance(raw, dict):
                return None
        except (OSError, ValueError):
            # 文件不存在 → 无占用者信息；存在但坏掉 → 交由调用方按"无法核验"处理
            if os.path.exists(self.lock_path):
                return InstanceInfo(reason="锁文件内容无法解析")
            return None
        info = InstanceInfo()
        for k in ("pid", "started", "exe", "user", "host", "elevated",
                  "version", "session_id", "wrote_at"):
            if k in raw:
                setattr(info, k, raw[k])
        info.pid = int(info.pid or 0)
        return info

    def _write_lock_file(self):
        """写入占用者元数据。锁文件只是"说明牌"，写失败不影响持锁。"""
        self._ensure_dir()
        data = current_process_meta(self.elevated)
        try:
            with open(self.lock_path, "w", encoding="utf-8") as fp:
                json.dump(data, fp, ensure_ascii=False, indent=2)
        except OSError:
            pass

    def _remove_lock_file(self):
        """只删自己写的锁文件（进程号比对方已死更可靠）。"""
        try:
            info = self._read_lock_file()
            if info and info.pid and info.pid != os.getpid():
                return False
            os.remove(self.lock_path)
            return True
        except OSError:
            return False
        except Exception:
            return False

    def _drop_stale_file(self, info: InstanceInfo) -> bool:
        """清理**经核验确认**陈旧的锁文件。

        核验是前提：只有在调用方已经判定占用者不存在（PID 已死 / 被复用 /
        换了程序）时才允许走到这里。删除前再读一次，防止删掉别人刚写的文件。
        """
        cur = self._read_lock_file()
        if cur is not None and cur.pid and cur.pid != info.pid:
            return False                      # 已被别的进程重新写入，不能删
        try:
            os.remove(self.lock_path)
            return True
        except OSError:
            return False

    # ---------------- 占用者查询 ----------------

    def owner(self) -> InstanceInfo | None:
        """当前锁文件记录的占用者；若核验判定为陈旧残留，则 stale=True。"""
        info = self._read_lock_file()
        if info is None:
            return None
        alive, why = pid_is_our_instance(info.pid, info.started, info.exe)
        if alive:
            info.stale = False
            info.reason = ""
            return info
        info.stale = True
        info.reason = why
        # 再叠加一条"文件确实很老"的佐证。用文件 mtime 而不是 wrote_at 字段：
        # 锁文件损坏时根本读不到 wrote_at，拿它当依据会写出"已存在超过 7 天"
        # 这种与事实不符的提示。
        age = _file_age(self.lock_path)
        if age is not None and age > STALE_FILE_MAX_AGE:
            info.reason = (why + "；且锁文件已存在超过 "
                           f"{STALE_FILE_MAX_AGE // 86400} 天").lstrip("；")
        return info

    def _describe_holder(self, kernel_reason: str) -> InstanceInfo:
        """给提示语准备占用者信息：优先用锁文件，拿不到就说明原因。"""
        info = self.owner()
        if info is not None and not info.stale:
            return info
        if info is not None and info.stale:
            # 内核说被占、文件说人已死：以内核为准，但如实说明矛盾
            info.stale = False
            info.reason = (f"内核锁被占用（{_reason_text(kernel_reason)}），"
                           f"但锁文件里的进程已不在（{info.reason}），"
                           "可能是旧版本实例或锁文件损坏")
            return info
        return InstanceInfo(reason=f"内核锁被占用（{_reason_text(kernel_reason)}），"
                                   "但读不到占用者信息（锁文件缺失或不可读）")

    # ---------------- 获取 / 释放 ----------------

    def acquire(self, wait_ms: int = 0, takeover: bool = False
                ) -> tuple[bool, InstanceInfo | None]:
        """尝试成为唯一实例。

        返回 (是否可以继续运行, 占用者信息)：
            (True,  None)  → 成功持有内核锁
            (False, info)  → 已有实例，调用方应提示并退出
            (True,  info)  → takeover=True 且等待超时，**降级继续运行**
                             （此时 self.held 为 False，self.degraded 为 True）
        """
        self._ensure_dir()
        self._impl, mode = self._make_impl()
        self._file_is_lock = (mode == "file")   # 兜底模式：锁文件本身就是锁
        deadline = time.monotonic() + max(0, wait_ms) / 1000.0
        stale_drops = 0

        while True:
            ok, why = self._impl.try_acquire()
            if ok:
                self.held = True
                self.degraded = False
                self._write_lock_file()
                return True, None

            if why.startswith("error"):
                # 内核机制不可用 → 降级到文件声明式（跨平台兜底），而不是放行多开
                self.last_error = why
                if mode != "file":
                    self._impl = _FileClaim(self.lock_path)
                    ok2, why2 = self._impl.try_acquire()
                    if ok2:
                        self.held = False
                        self._write_lock_file()
                        return True, None
                    why = why2

            if why == "denied":
                # 权限不足=对方权限更高，不会因为"等一会儿"就变好
                return False, self._describe_holder(why)

            if why == "exists" and self._file_is_lock and stale_drops < 3:
                # 兜底文件模式不会自动释放，必须主动识别"进程已死但文件还在"的残留，
                # 否则一次崩溃就会把程序永久挡在门外。核验后清掉再抢。
                old = self.owner()
                if old is not None and old.stale and self._drop_stale_file(old):
                    stale_drops += 1
                    continue

            if takeover and time.monotonic() < deadline:
                time.sleep(HANDOFF_POLL_MS / 1000.0)
                continue

            holder = self._describe_holder(why)
            if takeover:
                # 用户主动发起的提权交接：前任卡住不该把用户挡死
                self.held = False
                self.degraded = True
                holder.reason = (holder.reason + "；已按提权交接降级继续运行").strip("；")
                return True, holder
            return False, holder

    def release(self):
        """释放锁。正常退出靠这里，异常退出靠内核自动回收。"""
        try:
            if self._impl is not None and self.held:
                self._impl.release()
        except Exception:
            pass
        self.held = False
        if not self.degraded:
            self._remove_lock_file()

    # ---------------- 诊断 ----------------

    def status(self) -> dict:
        info = self.owner()
        return {"key": self.key, "lock_path": self.lock_path, "held": self.held,
                "degraded": self.degraded, "holder": info.as_dict() if info else None,
                "holder_stale": bool(info and info.stale),
                "holder_reason": (info.reason if info else "")}


def _reason_text(reason: str) -> str:
    return {"exists": "已被占用", "denied": "被更高权限的实例占用"}.get(reason, reason)


# ============================================================================
# 提示与"切到已有窗口"
# ============================================================================

def conflict_text(owner: InstanceInfo | None, app_title: str = APP_ID_DEFAULT,
                  raised: bool = False) -> str:
    """生成给用户看的提示文案。"""
    lines = [f"「{app_title}」已经在运行中。",
             "",
             "本程序同一时间只允许一个实例运行：多个实例会同时读写同一份扫描结果、",
             "同时执行停止服务/结束进程等处置动作，容易互相干扰。",
             "",
             "占用者信息："]
    lines.append(owner.describe() if owner else "    无法获取占用者信息")
    lines.append("")
    if raised:
        lines.append("已尝试把它的窗口切到前台。若没有看到，请用任务栏切换过去。")
    else:
        lines.append("请切换到那个已打开的窗口继续使用。")
    lines.append("如果确认它已经没用了，请先关闭它（或在任务管理器里结束该进程），"
                 "然后重新启动本程序。")
    return "\n".join(lines)


class _FLASHWINFO(object):
    pass


def find_app_windows(title_hint: str = "", pid: int = 0
                     ) -> list[tuple[int, int, str, bool]]:
    """枚举可能是本程序主窗口的顶层窗口，返回 (hwnd, pid, 标题, 是否可见)。

    按 PID 匹配最可靠（标题会带"（管理员）"后缀）；无 PID 时退回标题包含匹配。
    """
    if not _IS_WIN:
        return []
    import ctypes
    from ctypes import wintypes
    user32 = ctypes.WinDLL("user32", use_last_error=True)
    user32.EnumWindows.argtypes = [ctypes.c_void_p, wintypes.LPARAM]
    user32.EnumWindows.restype = wintypes.BOOL
    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.c_void_p]

    found: list[tuple[int, int, str, bool]] = []
    CB = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _cb(hwnd, _lp):
        try:
            wpid = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(wpid))
            n = user32.GetWindowTextLengthW(hwnd)
            if n <= 0:
                return True
            buf = ctypes.create_unicode_buffer(n + 2)
            user32.GetWindowTextW(hwnd, buf, n + 2)
            title = buf.value
            if pid:
                if wpid.value != pid:
                    return True
            elif title_hint and title_hint not in title:
                return True
            found.append((int(hwnd), int(wpid.value), title,
                          bool(user32.IsWindowVisible(hwnd))))
        except Exception:
            pass
        return True

    try:
        user32.EnumWindows(CB(_cb), 0)
    except Exception:
        return []
    return found


def raise_existing_window(pid: int = 0, title_hint: str = "") -> bool:
    """把已有实例的主窗口切到前台。尽力而为，失败不影响后续提示。"""
    if not _IS_WIN:
        return False
    wins = find_app_windows(title_hint, pid)
    if not wins:
        wins = find_app_windows(title_hint, 0)     # 退化成按标题匹配
    if not wins:
        return False
    # 优先可见窗口
    wins.sort(key=lambda w: (not w[3],))
    hwnd = wins[0][0]
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.WinDLL("user32", use_last_error=True)
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]

        class FLASHWINFO(ctypes.Structure):
            _fields_ = [("cbSize", wintypes.UINT), ("hwnd", wintypes.HWND),
                        ("dwFlags", wintypes.DWORD), ("uCount", wintypes.UINT),
                        ("dwTimeout", wintypes.DWORD)]

        SW_RESTORE = 9
        user32.ShowWindow(hwnd, SW_RESTORE)
        user32.SetForegroundWindow(hwnd)
        # 前台锁定策略可能让 SetForegroundWindow 无效，任务栏闪烁一定可见
        fi = FLASHWINFO(ctypes.sizeof(FLASHWINFO), hwnd, 3 | 12, 3, 0)
        user32.FlashWindowEx(ctypes.byref(fi))
        return True
    except Exception:
        return False


def message_box(title: str, text: str, icon_info: bool = True) -> bool:
    """原生消息框（不依赖 Qt）。返回是否真的弹出了。"""
    if not _IS_WIN:
        return False
    try:
        import ctypes
        MB_OK = 0x0
        MB_ICONINFORMATION = 0x40
        MB_ICONWARNING = 0x30
        MB_SETFOREGROUND = 0x10000
        flags = MB_OK | MB_SETFOREGROUND | (MB_ICONINFORMATION if icon_info else MB_ICONWARNING)
        ctypes.windll.user32.MessageBoxW(None, text, title, flags)
        return True
    except Exception:
        return False


def report_conflict(owner: InstanceInfo | None, app_title: str = APP_ID_DEFAULT,
                    interactive: bool = True, quiet: bool = False) -> str:
    """已经有一个实例在运行时：把已有窗口切到前台 + 提示用户。

    返回提示文案（便于测试与日志核对）。调用方随后应以
    EXIT_ALREADY_RUNNING 退出（此时尚未创建窗口、尚未写任何文件）。
    """
    pid = owner.pid if owner else 0
    raised = raise_existing_window(pid, app_title)
    text = conflict_text(owner, app_title, raised=raised)
    if not quiet:
        try:
            out = sys.stderr if sys.stderr is not None else None
            if out is not None:
                out.write(text + "\n")
                out.flush()
        except Exception:
            pass
    if interactive:
        message_box(f"{app_title} · 已在运行", text)
    return text


# ============================================================================
# 命令行自检 / 诊断
# ============================================================================

def _main(argv: list[str]) -> int:
    if "--status" in argv or "--check" in argv:
        guard = InstanceGuard()
        info = guard.owner()
        held = False
        ok, _other = guard.acquire()
        if ok:
            guard.release()
        else:
            held = True
        print(json.dumps({"running": held, "lock_path": guard.lock_path,
                          "holder": info.as_dict() if info else None,
                          "stale": bool(info and info.stale)},
                         ensure_ascii=False, indent=2))
        return EXIT_ALREADY_RUNNING if held else 0
    if "--hold" in argv:
        secs = 10.0
        i = argv.index("--hold")
        if i + 1 < len(argv):
            try:
                secs = float(argv[i + 1])
            except ValueError:
                pass
        guard = InstanceGuard()
        ok, other = guard.acquire()
        print(f"HOLD pid={os.getpid()} acquired={ok} lock={guard.lock_path} "
              f"holder={(other.pid if other else 0)}", flush=True)
        if not ok:
            return EXIT_ALREADY_RUNNING
        try:
            time.sleep(secs)
        finally:
            guard.release()
        print("HOLD released", flush=True)
        return 0
    print(__doc__)
    return 0


if __name__ == "__main__":
    sys.exit(_main(sys.argv[1:]))
