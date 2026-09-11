# -*- coding: utf-8 -*-
"""提权重启链路自测。

不触发 UAC：把提权动词临时替换为 open，其余走完全相同的代码路径。
验证点：
  1. nShow 为 SW_SHOWNORMAL（传 0 会导致新实例窗口不可见 —— 本次故障根因）
  2. shell_execute_ex 失败路径能返回错误码而非抛异常，且不弹系统框卡死
  3. 端到端握手：子实例写确认文件 → 原实例确认后关闭自身 → 清理确认文件
  4. 超时分支（独立进程验证）：确认文件始终不出现时，原实例不关闭并给出友好提示
"""
import os
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, HERE)

import gui                                                   # noqa: E402
import psutil                                                # noqa: E402
from PySide6.QtCore import QTimer                             # noqa: E402
from PySide6.QtWidgets import QApplication                    # noqa: E402

FAILED = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


def children_with_token():
    """正在运行的提权子实例（含 --elevated-token 参数）。"""
    out = []
    for p in psutil.process_iter(["pid", "cmdline"]):
        cl = p.info["cmdline"] or []
        j = " ".join(str(x) for x in cl)
        if "--elevated-token" in j and "process_iter" not in j:
            out.append((p.info["pid"], j))
    return out


def kill_token_children():
    for p in psutil.process_iter(["pid", "cmdline"]):
        cl = p.info["cmdline"] or []
        if "--elevated-token" in " ".join(str(x) for x in cl):
            try:
                p.kill()
            except Exception:
                pass


def is_admin_ref() -> bool:
    """独立实现的令牌提权判定，用作 gui.is_admin() 的对照基准。"""
    from ctypes import wintypes
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
    handle = wintypes.HANDLE()
    if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(), 0x0008,
                                     ctypes.byref(handle)):
        return False
    try:
        need = wintypes.DWORD(0)
        advapi32.GetTokenInformation(handle, 20, None, 0, ctypes.byref(need))
        value = wintypes.DWORD(0)
        advapi32.GetTokenInformation(handle, 20, ctypes.byref(value),
                                     ctypes.sizeof(value), ctypes.byref(need))
        return bool(value.value)
    finally:
        kernel32.CloseHandle(handle)


# ---------- 1. 静态检查 ----------
import ctypes                                                        # noqa: E402
import inspect                                                       # noqa: E402

check("SW_SHOWNORMAL 常量 == 1", gui.SW_SHOWNORMAL == 1)
check("shell_execute_ex 默认 nShow=SW_SHOWNORMAL",
      "show: int = SW_SHOWNORMAL" in inspect.getsource(gui.shell_execute_ex))
check("SHELLEXECUTEINFOW 结构体有效", ctypes.sizeof(gui.SHELLEXECUTEINFOW) > 0)
check("已启用 SEE_MASK_NOASYNC（可立即拿到错误码）",
      "SEE_MASK_NOASYNC" in inspect.getsource(gui.shell_execute_ex))
check("已启用 SEE_MASK_FLAG_NO_UI（不弹系统框、不卡死）",
      "SEE_MASK_FLAG_NO_UI" in inspect.getsource(gui.shell_execute_ex))
check("提权确认文件使用系统临时目录", os.path.isabs(gui.ELEVATE_DIR))
# 权限判定必须用令牌 Elevation，而不是 shell32.IsUserAnAdmin（后者在 UAC 下会误判）
check("is_admin 采用令牌 Elevation 判定（未调用 IsUserAnAdmin）",
      "TOKEN_ELEVATION" in inspect.getsource(gui.is_admin)
      and "ctypes.windll.shell32.IsUserAnAdmin" not in inspect.getsource(gui.is_admin))
try:
    shell_says = bool(ctypes.windll.shell32.IsUserAnAdmin())
except Exception:
    shell_says = False
token_truth = is_admin_ref()
check(f"is_admin 结论与令牌一致（IsUserAnAdmin={shell_says} 令牌={token_truth}）",
      gui.is_admin() == token_truth, f"gui.is_admin()={gui.is_admin()}")

# ---------- 2. 失败路径（本地不存在的文件，必须快速失败） ----------
missing = os.path.join(HERE, "__no_such_app__.exe")
t0 = time.time()
ok, err = gui.shell_execute_ex(missing, "", "", verb="open")
cost = time.time() - t0
check("不存在的目标快速返回失败（未卡死）", (not ok) and err != 0 and cost < 5,
      f"ok={ok} err={err} {cost:.2f}s")

# ---------- 3. 握手成功分支 ----------
gui.ELEVATE_VERB = "open"                    # 跳过 UAC，路径其余部分完全一致
gui.is_admin = lambda: False                 # 强制走提权分支

dialogs = []
gui._info = lambda *a, **k: dialogs.append(("info", a[1] if len(a) > 1 else ""))
gui._error = lambda *a, **k: dialogs.append(("error", a[1] if len(a) > 1 else ""))
gui._ask = lambda *a, **k: True

kill_token_children()


class ProbeApp(gui.ScanApp):
    """记录自身是否被关闭（closeEvent 是 Qt 虚函数，只能用子类拦截）。"""

    def __init__(self):
        self.closed_flag = False
        super().__init__()

    def closeEvent(self, event):
        self.closed_flag = True
        super().closeEvent(event)


app = QApplication.instance() or QApplication(sys.argv)
win = ProbeApp()
win.show()
win.run_as_admin()
marker = win._elev_marker
observed = []


def probe():
    for pid, cmd in children_with_token():
        if pid not in [p for p, _ in observed]:
            observed.append((pid, cmd))


t_probe = QTimer()
t_probe.timeout.connect(probe)
t_probe.start(60)
QTimer.singleShot(25000, app.quit)
app.exec()
t_probe.stop()

check("提权子实例确实启动（检测到 --elevated-token 进程）", bool(observed),
      str(observed[:2]))
check("原实例握手成功后自行关闭（把界面交给提权实例）", win.closed_flag)
check("确认文件已被清理", not os.path.exists(marker))
check("全过程未弹出错误提示", not dialogs, str(dialogs))

kill_token_children()

# ---------- 4. 超时分支：独立进程验证（Qt 状态干净） ----------
phase4 = r'''
import os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.getcwd())
import gui
from PySide6.QtWidgets import QApplication
from PySide6.QtCore import QTimer

shown = []
gui._info = lambda *a, **k: shown.append(a[1] if len(a) > 1 else "")
gui._error = lambda *a, **k: shown.append("ERR")
gui._ask = lambda *a, **k: True

class ProbeApp(gui.ScanApp):
    def __init__(self):
        self.closed_flag = False
        super().__init__()
    def closeEvent(self, e):
        self.closed_flag = True
        super().closeEvent(e)

app = QApplication(sys.argv)
win = ProbeApp()
win.show()
win._watch_elevated(os.path.join(gui.ELEVATE_DIR, "never_appears.ok"), timeout_ms=800)
state = {}
def stop():
    state["closed"] = win.closed_flag
    state["visible"] = win.isVisible()
    app.quit()
QTimer.singleShot(2500, stop)
app.exec()
print("RESULT", state.get("closed"), state.get("visible"), len(shown) > 0, flush=True)
os._exit(0)
'''
env = dict(os.environ)
env["PYTHONPATH"] = "C:/temp/noop"
env["QT_QPA_PLATFORM"] = "offscreen"
# 必须写成文件执行：venv 的启动器会重写命令行，用 python -c 传多行脚本会静默失效
p4file = os.path.join(HERE, "_p4_timeout_check.py")
with open(p4file, "w", encoding="utf-8") as f:
    f.write(phase4)
try:
    r = subprocess.run([sys.executable, "-u", p4file], capture_output=True, cwd=HERE,
                       env=env, timeout=120)
    out = (r.stdout or b"").decode("utf-8", "replace")
finally:
    try:
        os.remove(p4file)
    except OSError:
        pass
line = [ln for ln in out.splitlines() if ln.startswith("RESULT")]
parts = line[0].split()[1:] if line else []
check("Phase4 子进程正常产出结果", bool(line), f"rc={r.returncode} out={out[-200:]!r}")
closed = parts[0] == "True" if len(parts) > 0 else True
visible = parts[1] == "True" if len(parts) > 1 else False
prompted = parts[2] == "True" if len(parts) > 2 else False

check("超时后原实例保持运行（不再凭空消失）", not closed, f"closed={closed}")
check("超时后窗口仍可见", visible, f"visible={visible}")
check("超时给出友好提示", prompted, f"prompted={prompted}")

print()
print("ALL_CHECKS_PASSED" if not FAILED else f"FAILED: {FAILED}")
sys.exit(1 if FAILED else 0)
