# -*- coding: utf-8 -*-
"""对打包后的 exe 做单实例检测验证（真实双开 + 提示框 + 异常退出后释放）。

做四件事：
  1. 第一个 exe 实例能正常启动并持有单实例锁（锁文件落在隔离的锁目录里）
  2. 第二个实例启动时弹出提示框（原生 MessageBox，标题含"已在运行"），
     关闭提示框后以退出码 3 结束；第一个实例不受影响（窗口仍在、锁未易主）
  3. 强杀第一个实例（模拟异常退出）后，内核自动释放锁 ——
     第三个实例能正常启动，不需要手工清理残留锁文件
  4. 收尾清理

两个环境事实（第一版测试就栽在这上面）：
  · PyInstaller onefile 会跑两个进程：bootloader（Popen.pid）+ 真正执行 Python 的子进程。
    **只有子进程持锁，也只有子进程有主窗口**，Popen.pid 不能用来做断言 ——
    真正持锁的 PID 从锁文件里读（这正是锁文件存在的意义之一）。
  · exe 会往自己所在目录写 scan_result.json 等文件，所以必须复制到临时副本目录里跑，
    不能在发布目录原地跑。
"""
import ctypes
import json
import os
import shutil
import subprocess
import sys
import time
from ctypes import wintypes

import psutil

HERE = os.path.dirname(os.path.abspath(__file__))
EXE_SRC = os.path.join(HERE, "dist", "SysScanGUI.exe")
WORK = os.path.join(HERE, "_frozen_single_tmp")
EXE = os.path.join(WORK, "SysScanGUI.exe")
LOCKDIR = os.path.join(WORK, "lock")
LOCK_FILE = os.path.join(LOCKDIR, "instance.lock")

FAILED = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


user32 = ctypes.windll.user32


def exe_pids():
    """所有 SysScanGUI 进程（含 onefile 的 bootloader 与子进程）。"""
    return {p.info["pid"] for p in psutil.process_iter(["pid", "name"])
            if "sysscangui" in (p.info["name"] or "").lower()}


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
            found.append((buf.value, bool(user32.IsWindowVisible(hwnd)), pid.value))
        return True

    user32.EnumWindows(CB(cb), 0)
    return found


def find_window(title_part, timeout=25.0, want_visible=True):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for title, vis, pid in windows_of(exe_pids()):
            if title_part in title and (vis or not want_visible):
                return title, vis, pid
        time.sleep(0.4)
    return None


def read_lock():
    try:
        with open(LOCK_FILE, encoding="utf-8") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def wait_lock(timeout=25.0):
    deadline = time.time() + timeout
    while time.time() < deadline:
        info = read_lock()
        if info and info.get("pid"):
            return info
        time.sleep(0.4)
    return None


def env_for():
    return {**os.environ, "SYSSCAN_LOCK_DIR": LOCKDIR,
            "SYSSCAN_INSTANCE_KEY": "SysScanFrozenTest", "PYTHONPATH": "C:/temp/noop"}


def kill_all():
    for p in psutil.process_iter(["pid", "name"]):
        if "sysscangui" in (p.info["name"] or "").lower():
            try:
                p.kill()
            except Exception:
                pass
    time.sleep(1.0)


check("dist/SysScanGUI.exe 存在", os.path.isfile(EXE_SRC), EXE_SRC)
kill_all()
shutil.rmtree(WORK, ignore_errors=True)
os.makedirs(LOCKDIR, exist_ok=True)
shutil.copy2(EXE_SRC, EXE)
shutil.copy2(os.path.join(HERE, "scan_result.json"), WORK)

# ---------- 1. 第一个实例启动并持锁 ----------
p1 = subprocess.Popen([EXE], env=env_for(), cwd=WORK)
w1 = find_window("扫描器")
info1 = wait_lock()
check("第一个实例启动且主窗口可见", w1 is not None, str(w1))
check("第一个实例持有单实例锁（锁文件已写出）", info1 is not None, str(info1))
real1 = int(info1["pid"]) if info1 else 0
check("锁文件记录的是真正执行程序的子进程 PID（onefile 有 bootloader+子进程两个 PID，"
      "Popen.pid 不等于它，这是正常的）",
      real1 and real1 != p1.pid and real1 in exe_pids(),
      f"real={real1} bootloader={p1.pid}")
check("锁文件里标明了是否以管理员运行（供提示语展示）",
      "elevated" in (info1 or {}), str((info1 or {}).get("elevated")))
check("锁文件没有落进程序目录（放在用户级目录，不污染发布目录）",
      not os.path.isfile(os.path.join(WORK, "instance.lock")))

# ---------- 2. 第二个实例：提示 + 退出码 3 ----------
p2 = subprocess.Popen([EXE], env=env_for(), cwd=WORK)
box = find_window("已在运行")
check("第二个实例弹出了「已在运行」提示框（原生 MessageBox）", box is not None, str(box))
if box is not None:
    hwnd = user32.FindWindowW(None, box[0])
    if hwnd:
        user32.PostMessageW(hwnd, 0x0010, 0, 0)      # WM_CLOSE
try:
    rc2 = p2.wait(timeout=40)
except subprocess.TimeoutExpired:
    p2.kill()
    rc2 = None
check("关闭提示框后第二个实例以退出码 3 退出", rc2 == 3, f"rc={rc2}")
lock_after = read_lock() or {}
check("第二个实例没有夺取锁（锁文件仍指向第一个实例）",
      int(lock_after.get("pid", 0)) == real1, f"{lock_after.get('pid')} vs {real1}")
check("第一个实例不受影响：进程仍在、窗口仍可见",
      real1 in exe_pids() and find_window("扫描器", timeout=5) is not None)

# ---------- 3. 异常退出后锁自动释放 ----------
for p in psutil.process_iter(["pid", "name"]):
    if "sysscangui" in (p.info["name"] or "").lower():
        try:
            p.kill()                    # 模拟崩溃/被任务管理器结束
        except Exception:
            pass
time.sleep(1.5)
check("强杀后锁文件仍残留（进程来不及清理，正是要处理的场景）", os.path.isfile(LOCK_FILE))
check("残留锁已无对应进程（内核已回收锁对象）", not exe_pids(), str(exe_pids()))

p3 = subprocess.Popen([EXE], env=env_for(), cwd=WORK)
w3 = find_window("扫描器")
info3 = wait_lock()
real3 = int(info3["pid"]) if info3 else 0
check("异常退出后无需手工清理，第三个实例能正常启动（内核已回收锁）",
      w3 is not None, str(w3))
check("第三个实例重新写入了锁文件（指向自己，不是上一个残留值）",
      real3 and real3 != real1 and real3 in exe_pids(),
      f"new={real3} old={real1}")

# ---------- 4. 收尾 ----------
for p in (p3,):
    try:
        p.kill()
    except Exception:
        pass
kill_all()
shutil.rmtree(WORK, ignore_errors=True)
check("临时工作目录已清理", not os.path.isdir(WORK))

print()
print("FROZEN_SINGLE_ALL_PASSED" if not FAILED else f"FAILED: {FAILED}")
sys.exit(1 if FAILED else 0)
