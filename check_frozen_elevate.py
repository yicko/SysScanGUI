# -*- coding: utf-8 -*-
"""对打包后的 exe 做提权链路验证（不触发 UAC）。

做两件事：
  1. 以 --elevated-token 启动 exe（与提权实例启动方式一致），确认
     a) 主窗口真的可见（这正是本次故障点：nShow=0 时窗口不可见）
     b) 启动确认文件被写出（原实例靠它判断"提权实例已就绪"）
  2. 收尾：关闭进程、清理确认文件
"""
import ctypes
import os
import subprocess
import sys
import time
import uuid
from ctypes import wintypes

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
EXE = os.path.join(HERE, "dist", "SysScanGUI.exe")
ELEV_DIR = os.path.join(os.environ.get("TEMP", ""), "sysscan_elev")

FAILED = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


user32 = ctypes.windll.user32


def windows_of(pids):
    found = []
    CB = ctypes.WINFUNCTYPE(ctypes.c_bool, wintypes.HWND, wintypes.LPARAM)

    def cb(hwnd, _lp):
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        if pid.value in pids:
            n = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(n + 2)
            user32.GetWindowTextW(hwnd, buf, n + 2)
            found.append((buf.value, bool(user32.IsWindowVisible(hwnd))))
        return True

    user32.EnumWindows(CB(cb), 0)
    return found


def pids_of():
    return [p.info["pid"] for p in psutil.process_iter(["pid", "name"])
            if "sysscangui" in (p.info["name"] or "").lower()]


def kill_all():
    for p in psutil.process_iter(["pid", "name"]):
        if "sysscangui" in (p.info["name"] or "").lower():
            try:
                p.kill()
            except Exception:
                pass
    time.sleep(1.0)


check("exe 存在", os.path.isfile(EXE))
kill_all()
os.makedirs(ELEV_DIR, exist_ok=True)
marker = os.path.join(ELEV_DIR, uuid.uuid4().hex + ".ok")

proc = subprocess.Popen([EXE, "--elevated-token", marker])
time.sleep(6.0)

wins = windows_of(set(pids_of()))
main = [w for w in wins if "扫描器" in w[0]]
check("exe 以 --elevated-token 启动后主窗口可见", bool(main) and main[0][1], str(wins[:4]))
check("启动确认文件已写出（原实例据此交接）", os.path.isfile(marker))
if os.path.isfile(marker):
    with open(marker, encoding="utf-8") as f:
        pid = f.read().strip()
    check("确认文件内容为有效 PID", pid.isdigit(), pid)
check("进程仍在运行（未闪退）", bool(pids_of()))

kill_all()
try:
    os.remove(marker)
except OSError:
    pass
check("确认文件已清理", not os.path.exists(marker))

print()
print("FROZEN_ALL_PASSED" if not FAILED else f"FAILED: {FAILED}")
sys.exit(1 if FAILED else 0)
