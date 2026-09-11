# -*- coding: utf-8 -*-
"""单实例运行守卫回归测试。

覆盖：
  [1] 基础：获取 / 释放 / 锁文件内容 / 同进程重入拒绝 / **非所有者句柄不复用** 回归
  [2] 跨进程冲突 + 异常退出（强杀）后的锁释放 + 残留锁文件陈旧判定
  [3] 陈旧判定四分支：PID 已死 / PID 被复用 / 换了程序 / 锁文件损坏
  [4] 兜底文件模式（O_EXCL）与跨平台分支（fcntl 惰性导入、机制选择）
  [5] 提示文案与"切到已有窗口"（不弹窗、找不到窗口不崩）
  [6] 与界面 / 提权链路的集成：豁免标志、端到端拒绝退出码 3、
      单实例判定必须在建窗口之前、提权实例延后接管的顺序、接管成功与降级两条路径

测试隔离：全部使用独立锁目录 + 独立实例键，绝不干扰你正在使用的实例。

已知坑（写在这里免得下次再踩）：
  · venv 的 python.exe 是重定向启动器，会再拉起基础解释器子进程 ——
    Popen.pid 不是真正持锁的那个 PID，必须以子进程自己打印的 pid 为准，
    强杀时两个都要杀。
  · 不能用 `python -c "<多行>"` 传多行脚本（会被启动器改写后静默失效），
    必须写成文件再执行。
"""
import json
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, HERE)

# 测试隔离：独立锁目录 + 独立键
LOCKDIR = os.path.join(HERE, "_single_test_lock")
KEY = "SysScanSingleTest"
os.environ["SYSSCAN_LOCK_DIR"] = LOCKDIR
os.environ["SYSSCAN_INSTANCE_KEY"] = KEY
os.environ.pop("SYSSCAN_ALLOW_MULTI", None)

import psutil                      # noqa: E402
import single_instance as si       # noqa: E402

LOCK_FILE = os.path.join(LOCKDIR, "instance.lock")
FAILED = []


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


def reset_lockdir():
    shutil.rmtree(LOCKDIR, ignore_errors=True)
    os.makedirs(LOCKDIR, exist_ok=True)


def child_env(**extra):
    env = dict(os.environ)
    env["SYSSCAN_LOCK_DIR"] = LOCKDIR
    env["SYSSCAN_INSTANCE_KEY"] = KEY
    env["PYTHONPATH"] = "C:/temp/noop"
    env.update(extra)
    return env


def dec(b) -> str:
    return (b or b"").decode("utf-8", "replace")


def spawn_holder(secs: int = 30):
    """起一个持锁子进程，返回 (Popen, 真正持锁的 PID)。"""
    p = subprocess.Popen([sys.executable, "-u", os.path.join(HERE, "single_instance.py"),
                          "--hold", str(secs)],
                         stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                         env=child_env(), cwd=HERE)
    pid = 0
    if p.stdout is not None:
        line = dec(p.stdout.readline())
        for tok in line.split():
            if tok.startswith("pid="):
                try:
                    pid = int(tok[4:])
                except ValueError:
                    pid = 0
    return p, pid


def kill_holder(p, pid):
    """强杀持锁进程（模拟崩溃/被任务管理器结束）。"""
    for target in {getattr(p, "pid", 0), pid}:
        if not target:
            continue
        try:
            psutil.Process(target).kill()
        except Exception:
            pass
    try:
        p.wait(timeout=5)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def kill_leftover_holders():
    for proc in psutil.process_iter(["pid", "cmdline"]):
        try:
            j = " ".join(str(x) for x in (proc.info["cmdline"] or []))
        except Exception:
            continue
        if "single_instance.py" in j and "--hold" in j:
            try:
                proc.kill()
            except Exception:
                pass


def dead_pid() -> int:
    """拿一个确定已经退出、且不会被立刻复用的 PID。"""
    p = subprocess.Popen([sys.executable, "-c", "pass"])
    p.wait()
    time.sleep(0.3)
    return p.pid


def forge_lock_file(**kw):
    """伪造锁文件（用于构造陈旧锁场景）。"""
    me = psutil.Process()
    base = {"pid": os.getpid(), "started": me.create_time(), "exe": me.exe(),
            "user": "tester", "host": "testhost", "elevated": False,
            "version": "", "session_id": 0, "wrote_at": time.time()}
    base.update(kw)
    os.makedirs(LOCKDIR, exist_ok=True)
    with open(LOCK_FILE, "w", encoding="utf-8") as f:
        json.dump(base, f, ensure_ascii=False)
    return base


kill_leftover_holders()

# ============================================================================
print("\n[1] 基础：获取 / 释放 / 锁文件内容 / 重入拒绝")
reset_lockdir()
g1 = si.InstanceGuard(KEY, LOCKDIR)
ok, holder = g1.acquire()
check("空闲时可获取单实例锁", ok and holder is None and g1.held,
      f"ok={ok} held={g1.held} holder={holder}")
check("锁文件已写出", os.path.isfile(g1.lock_path), g1.lock_path)
raw = json.load(open(LOCK_FILE, encoding="utf-8")) if os.path.isfile(LOCK_FILE) else {}
check("锁文件记录了进程号 / 创建时间 / 程序路径 / 用户 / 主机",
      raw.get("pid") == os.getpid() and raw.get("started") and raw.get("exe")
      and raw.get("user") and raw.get("host"),
      json.dumps(raw, ensure_ascii=False)[:150])
check("记录的是当前进程真实创建时间（PID 复用防护的依据）",
      raw.get("started") and abs(raw["started"] - psutil.Process().create_time()) < 3,
      str(raw.get("started")))

g2 = si.InstanceGuard(KEY, LOCKDIR)
ok2, h2 = g2.acquire()
check("同一进程内重复获取被拒（命名互斥体已被自己持有）", not ok2 and h2 is not None, f"ok={ok2}")
check("拒绝时能报出占用者进程号", bool(h2) and h2.pid == os.getpid(),
      str(h2.pid if h2 else None))

g1.release()
check("释放后锁文件被删除", not os.path.exists(LOCK_FILE))
g3 = si.InstanceGuard(KEY, LOCKDIR)
ok3, h3 = g3.acquire()
check("释放后立即可重新获取（防「非所有者句柄留住导致永远占用」回归）",
      ok3 and h3 is None and g3.held, f"ok={ok3} held={g3.held}")
g3.release()
check("空闲时 owner() 不误报", si.InstanceGuard(KEY, LOCKDIR).owner() is None)

# ============================================================================
print("\n[2] 跨进程冲突 / 异常退出后的锁释放")
reset_lockdir()
child, cpid = spawn_holder(40)
check("持锁子进程已启动并自报 PID", cpid > 0, f"pid={cpid}")
g = si.InstanceGuard(KEY, LOCKDIR)
ok, holder = g.acquire()
check("另一进程持锁时获取被拒", (not ok) and holder is not None, f"ok={ok}")
check("报出的占用者进程号就是持锁子进程", bool(holder) and holder.pid == cpid,
      f"{holder.pid if holder else None} vs {cpid}")
check("活着的占用者不被误判为陈旧", bool(holder) and not holder.stale,
      holder.reason if holder else "")
check("占用者信息含启动时间与程序路径",
      bool(holder) and bool(holder.started) and bool(holder.exe),
      holder.describe("").replace("\n", " | ")[:140] if holder else "")
check("占用者描述文案含进程号与启动时间",
      bool(holder) and str(cpid) in holder.describe() and holder.started_text() in holder.describe(),
      holder.describe("").replace("\n", " | ")[:160] if holder else "")

kill_holder(child, cpid)
time.sleep(0.8)                                  # 等内核回收锁对象、进程从表里消失
orphan = si.InstanceGuard(KEY, LOCKDIR).owner()
check("崩溃残留的锁文件被识别为陈旧", orphan is not None and orphan.stale,
      f"stale={getattr(orphan, 'stale', None)}")
check("陈旧判定给出原因（进程已不存在）", bool(orphan) and "已不存在" in orphan.reason,
      orphan.reason if orphan else "")

t0 = time.time()
g2b = si.InstanceGuard(KEY, LOCKDIR)
ok2b, h2b = g2b.acquire()
cost = time.time() - t0
check("强杀持锁进程后锁被内核立即回收（无需等超时）", ok2b and cost < 2,
      f"ok={ok2b} {cost:.2f}s holder={h2b}")
check("接管后锁文件重新指向本进程",
      json.load(open(LOCK_FILE, encoding="utf-8"))["pid"] == os.getpid())
g2b.release()

# ============================================================================
print("\n[3] 陈旧锁四分支：PID 已死 / 被复用 / 换了程序 / 文件损坏")
reset_lockdir()
dead = dead_pid()
forge_lock_file(pid=dead)
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("PID 已不存在 → 判为陈旧", bool(info) and info.stale, info.reason if info else "")
check("原因里写明该进程已不存在", bool(info) and "已不存在" in info.reason,
      info.reason if info else "")

me = psutil.Process()
forge_lock_file(pid=os.getpid(), started=me.create_time() - 5000)
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("PID 被系统复用（创建时间不符）→ 判为陈旧", bool(info) and info.stale,
      info.reason if info else "")
check("原因里写明 PID 被复用", bool(info) and "复用" in info.reason, info.reason if info else "")

forge_lock_file(pid=os.getpid(), started=me.create_time(),
                exe=os.path.join(os.environ.get("SystemRoot", r"C:\Windows"),
                                 "System32", "notepad.exe"))
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("PID 对但跑的是别的程序 → 判为陈旧", bool(info) and info.stale,
      info.reason if info else "")

forge_lock_file(pid=os.getpid(), started=me.create_time(), exe=me.exe())
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("身份完全吻合的活进程 → 不误判为陈旧", bool(info) and not info.stale,
      info.reason if info else "")

with open(LOCK_FILE, "w", encoding="utf-8") as f:
    f.write("{ 这不是合法 JSON")
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("锁文件损坏 → 判为陈旧（不会把程序永久挡在门外）",
      bool(info) and info.stale, info.reason if info else "")
check("损坏锁文件不会谎称「已存在超过 7 天」（用文件真实 mtime 判定，不看读不到的字段）",
      bool(info) and "天" not in info.reason, info.reason if info else "")

old = time.time() - 8 * 86400                   # 真·老文件才该给出这条佐证
os.utime(LOCK_FILE, (old, old))
info = si.InstanceGuard(KEY, LOCKDIR).owner()
check("确实很老的锁文件会给出「已存在超过 7 天」佐证",
      bool(info) and "已存在超过 7 天" in info.reason, info.reason if info else "")
reset_lockdir()
check("无锁文件时 owner() 返回 None", si.InstanceGuard(KEY, LOCKDIR).owner() is None)

# ============================================================================
print("\n[4] 兜底文件模式与跨平台分支")
reset_lockdir()
f1 = si.InstanceGuard(KEY, LOCKDIR, mechanism="file")
ok, _ = f1.acquire()
check("兜底模式可获取（O_CREAT|O_EXCL 原子创建）", ok and f1.held, f"ok={ok} held={f1.held}")
f2 = si.InstanceGuard(KEY, LOCKDIR, mechanism="file")
ok2, h2 = f2.acquire()
check("兜底模式下第二个实例被拒", not ok2 and h2 is not None, f"ok={ok2}")

dead2 = dead_pid()
with open(LOCK_FILE, "w", encoding="utf-8") as f:      # 模拟崩溃残留
    json.dump({"pid": dead2, "started": time.time() - 60, "exe": "x"}, f)
f3 = si.InstanceGuard(KEY, LOCKDIR, mechanism="file")
ok3, h3 = f3.acquire()
check("兜底模式下崩溃残留（PID 已死）能被核验并接管、不会永久占用",
      ok3 and h3 is None, f"ok={ok3} reason={getattr(h3, 'reason', '')}")
check("接管后锁文件为本进程",
      json.load(open(LOCK_FILE, encoding="utf-8"))["pid"] == os.getpid())
f3.release()
check("兜底模式释放后锁文件被删除", not os.path.exists(LOCK_FILE))

reset_lockdir()
p1 = si.InstanceGuard(KEY, LOCKDIR, mechanism="flock")   # Windows 上没有 fcntl
ok, _ = p1.acquire()
check("指定 flock 但平台无 fcntl 时降级到文件声明式（而非放行多开）",
      ok and p1.last_error.startswith("error"), f"ok={ok} err={p1.last_error}")
p2 = si.InstanceGuard(KEY, LOCKDIR, mechanism="flock")
ok2, h2 = p2.acquire()
check("降级后仍能拦住第二个实例", not ok2 and h2 is not None, f"ok={ok2}")
p1.release()
check("自动模式在 Windows 上选命名互斥体（其他平台选 flock）",
      si.InstanceGuard(KEY, LOCKDIR)._make_impl()[1]
      == ("mutex" if os.name == "nt" else "flock"))

src = open(os.path.join(HERE, "single_instance.py"), encoding="utf-8").read()
fcntl_lines = [ln for ln in src.splitlines() if ln.strip().startswith("import fcntl")]
check("fcntl 只在函数内惰性导入（模块级导入会让 Windows 直接 ImportError）",
      bool(fcntl_lines) and all(ln.startswith((" ", "\t")) for ln in fcntl_lines),
      str(fcntl_lines))
check("POSIX 与兜底路径均存在（flock / O_EXCL 两条）",
      "class _PosixFlock" in src and "class _FileClaim" in src
      and "O_CREAT | os.O_EXCL" in src)

# ============================================================================
print("\n[5] 提示文案与「切到已有窗口」")
owner = si.InstanceInfo(pid=4321, started=time.time() - 120,
                        exe=r"C:\somewhere\SysScanGUI.exe", user="demo",
                        host="DEMO-PC", elevated=True)
txt = si.conflict_text(owner, "系统进程与服务安全扫描器", raised=True)
for token in ("已经在运行", "同一时间只允许一个实例", "4321", "管理员",
              r"C:\somewhere\SysScanGUI.exe", "启动时间", "任务管理器"):
    check(f"提示文案包含「{token}」", token in txt)
check("拿不到占用者信息时也能给出提示（不崩）",
      "无法获取占用者信息" in si.conflict_text(None, "X"))
check("找不到窗口时返回 False 且不抛异常",
      si.raise_existing_window(999999, "绝对不存在的窗口标题-xyz") is False)
check("标题不匹配时枚举结果为空", si.find_app_windows("绝对不存在的窗口标题-xyz") == [])

t0 = time.time()
out = si.report_conflict(owner, "系统进程与服务安全扫描器",
                         interactive=False, quiet=True)
cost = time.time() - t0
check("interactive=False 时不弹模态框（调用瞬时返回，自动化前提）", cost < 2,
      f"{cost:.2f}s")
check("report_conflict 返回同一份可读提示", "已经在运行" in out and "4321" in out,
      out.splitlines()[0] if out else "")

# ============================================================================
print("\n[6] 与界面 / 提权链路的集成")
import gui                                                       # noqa: E402

saved_argv = sys.argv[:]
sys.argv = ["gui.py", "--smoke"]
check("--smoke（自检）跳过单实例检测", gui.single_instance_disabled())
sys.argv = ["gui.py", "--allow-multi"]
check("--allow-multi（诊断）跳过单实例检测", gui.single_instance_disabled())
sys.argv = ["gui.py"]
check("普通启动不跳过检测", not gui.single_instance_disabled())
os.environ["SYSSCAN_ALLOW_MULTI"] = "1"
check("环境变量 SYSSCAN_ALLOW_MULTI=1 可跳过（自动化测试并行用）",
      gui.single_instance_disabled())
os.environ.pop("SYSSCAN_ALLOW_MULTI", None)
sys.argv = saved_argv[:]

check("退出码常量与模块一致", gui.EXIT_ALREADY_RUNNING == si.EXIT_ALREADY_RUNNING == 3,
      str(gui.EXIT_ALREADY_RUNNING))

src_gui = open(os.path.join(HERE, "gui.py"), encoding="utf-8").read()
body = src_gui[src_gui.index("def main():"):src_gui.index('if __name__ ==')]
i_guard = body.index("InstanceGuard(")
i_qapp = body.index("QApplication(sys.argv)")
i_exit = body.index("sys.exit(EXIT_ALREADY_RUNNING)")
i_show = body.index("win.show()")
i_handoff = body.index("start_handoff_takeover")
check("单实例判定在创建 QApplication / 窗口之前", i_guard < i_qapp,
      f"guard@{i_guard} qapp@{i_qapp}")
check("拒绝路径在创建窗口之前退出（干净退出）", i_exit < i_qapp, f"exit@{i_exit}")
check("提权实例被豁免（token 非空时不抢锁）",
      "if not token:" in body and body.index("if not token:") < body.index("guard.acquire()"))
check("提权实例先起窗口写标记、再接管锁（顺序不可颠倒，否则双方互等到超时）",
      i_show < i_handoff, f"show@{i_show} handoff@{i_handoff}")
check("closeEvent 里释放单实例锁（交棒给提权实例的前提）",
      "release_instance_lock()" in src_gui[src_gui.index("def closeEvent"):
                                           src_gui.index("def _arg_value")])

# ---- 端到端：已有实例时第二个实例提示 + 退出码 3 ----
reset_lockdir()
child, cpid = spawn_holder(60)
json_before = os.path.getmtime(os.path.join(HERE, "scan_result.json")) \
    if os.path.isfile(os.path.join(HERE, "scan_result.json")) else 0
r = subprocess.run([sys.executable, "-u", os.path.join(HERE, "gui.py")],
                   capture_output=True, env=child_env(SYSSCAN_NO_UI="1"),
                   cwd=HERE, timeout=240)
out = dec(r.stdout) + dec(r.stderr)
check("已有实例运行时，第二个实例以退出码 3 安全退出",
      r.returncode == si.EXIT_ALREADY_RUNNING, f"rc={r.returncode}")
check("退出前打印了占用者提示", "已经在运行" in out and str(cpid) in out,
      out.strip().splitlines()[0] if out.strip() else "(无输出)")
check("未夺取运行锁（锁文件仍指向原实例）",
      json.load(open(LOCK_FILE, encoding="utf-8"))["pid"] == cpid,
      str(json.load(open(LOCK_FILE, encoding="utf-8"))["pid"]))
json_after = os.path.getmtime(os.path.join(HERE, "scan_result.json")) \
    if os.path.isfile(os.path.join(HERE, "scan_result.json")) else 0
check("干净退出：没有改动任何数据文件", json_before == json_after,
      f"{json_before} -> {json_after}")
kill_holder(child, cpid)

# ---- 提权接管：降级路径（前任一直不退出） ----
print("\n[6b] 提权实例的单实例锁接管（子进程 + 离屏 Qt）")
probe = os.path.join(HERE, "_p_single_takeover.py")
with open(probe, "w", encoding="utf-8") as f:
    f.write('''
import json, os, sys
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, os.getcwd())
import gui, single_instance as si
from PySide6.QtCore import QTimer
from PySide6.QtWidgets import QApplication

timeout_ms = int(sys.argv[1]) if len(sys.argv) > 1 else 600
app = QApplication(sys.argv)
win = gui.ScanApp()
win.show()
guard = si.InstanceGuard(si.current_key())
state = {}

def start():
    win.start_handoff_takeover(guard, timeout_ms=timeout_ms)
    QTimer.singleShot(timeout_ms + 1200, done)

def done():
    state.update({"pid": os.getpid(), "held": bool(guard.held),
                  "degraded": bool(guard.degraded), "status": win.status.text(),
                  "lock_pid": (json.load(open(guard.lock_path, encoding="utf-8")).get("pid")
                               if os.path.isfile(guard.lock_path) else 0)})
    print("TAKEOVER " + json.dumps(state, ensure_ascii=False), flush=True)
    app.quit()

QTimer.singleShot(300, start)
app.exec()
os._exit(0)
''')
try:
    # 场景 A：前任（本进程）一直持锁 → 接管超时 → 降级继续运行，不阻塞
    reset_lockdir()
    gA = si.InstanceGuard(KEY, LOCKDIR)
    gA.acquire()
    pA = subprocess.Popen([sys.executable, "-u", probe, "600"], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=child_env(), cwd=HERE)
    outA = dec(pA.communicate(timeout=180)[0])
    lineA = [ln for ln in outA.splitlines() if ln.startswith("TAKEOVER")]
    stateA = json.loads(lineA[0][9:]) if lineA else {}
    check("前任不退出时提权实例不卡死（超时后降级继续运行）",
          stateA.get("degraded") is True and stateA.get("held") is False,
          json.dumps(stateA, ensure_ascii=False)[:160])
    check("降级时状态栏如实说明（可能出现两个实例）",
          "降级" in (stateA.get("status") or ""), stateA.get("status", ""))
    check("降级实例不去抢/删前任的锁文件",
          stateA.get("lock_pid") == os.getpid() and os.path.isfile(LOCK_FILE),
          f"lock_pid={stateA.get('lock_pid')} expect={os.getpid()}")
    gA.release()

    # 场景 B：前任在接管窗口内退出 → 提权实例成功接管
    reset_lockdir()
    gB = si.InstanceGuard(KEY, LOCKDIR)
    gB.acquire()
    pB = subprocess.Popen([sys.executable, "-u", probe, "6000"], stdout=subprocess.PIPE,
                          stderr=subprocess.STDOUT, env=child_env(), cwd=HERE)
    time.sleep(1.4)
    gB.release()                                  # 交棒
    outB = dec(pB.communicate(timeout=180)[0])
    lineB = [ln for ln in outB.splitlines() if ln.startswith("TAKEOVER")]
    stateB = json.loads(lineB[0][9:]) if lineB else {}
    check("前任退出后提权实例接管到单实例锁",
          stateB.get("held") is True and stateB.get("degraded") is False,
          json.dumps(stateB, ensure_ascii=False)[:160])
    check("接管后锁文件指向提权实例自身",
          stateB.get("lock_pid") == stateB.get("pid"),
          f"lock_pid={stateB.get('lock_pid')} self={stateB.get('pid')}")
    gB.release()
    if os.path.isfile(LOCK_FILE):
        os.remove(LOCK_FILE)
finally:
    try:
        os.remove(probe)
    except OSError:
        pass

kill_leftover_holders()
shutil.rmtree(LOCKDIR, ignore_errors=True)
shutil.rmtree(os.path.join(os.path.dirname(LOCKDIR), "SysScanSingleTest"),
              ignore_errors=True)

print()
print("ALL_CHECKS_PASSED" if not FAILED else f"FAILED: {FAILED}")
sys.exit(1 if FAILED else 0)
