# -*- coding: utf-8 -*-
"""本程序自身进程标注的回归测试。

背景（这是用户实际报上来的现象）：
    从普通模式切到管理员模式后，进程里会出现两个"本程序进程"。
    实测这不是提权交接的 bug，而是 PyInstaller onefile 的固定结构 ——
    引导器（解包 + 守护）与应用本体命令行**完全相同**。更要紧的是：绿色版 exe
    位于非标准目录且未签名，本工具的规则会把"未签名 + 非标准目录"判成中危，
    于是它扫自己会刷出两条指向自己的中危告警，很容易被误会成"旧实例没退出"。

本测试覆盖：
  [1] mark_self_processes 角色判定：引导器 / 应用本体 / 单个进程 / 同名不同路径不误判
  [2] 源码运行（SELF_EXE 为空）只认 pid，不把全机 python.exe 当自身
  [3] analyze_processes 端到端：自身进程标为正常且不产生 findings；
      **同目录下别的未签名程序仍然要判中危**（防止白名单过宽 —— 这条最重要）
  [4] 真实进程表：本进程被标注为自身，且不产生指向自己的风险项
  [5] 文案与界面：self_process_hint / DetailDialog 的说明行
  [6] collect_self_group 至少包含本进程，且字段齐全
"""
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
sys.path.insert(0, HERE)

import gui                                                      # noqa: E402
import scan                                                     # noqa: E402
from PySide6.QtWidgets import QApplication                      # noqa: E402

FAILED = []
FAKE_EXE = r"D:\PortableApps\SysScanGUI.exe"           # 模拟"绿色版位于非标准目录"
OTHER_EXE = r"D:\PortableApps\OtherGreenApp.exe"       # 同目录下的**别的**程序


def check(name, cond, detail=""):
    print(("PASS  " if cond else "FAIL  ") + name + (f"   [{detail}]" if detail else ""))
    if not cond:
        FAILED.append(name)


def mkproc(pid, name, exe, ppid=0, cmdline="", cpu=1.0, mem_mb=30.0, mem_pct=1.0,
           threads=8, user="PC\\user"):
    """构造 analyze_processes 需要的完整记录（字段缺失会让规则抛 KeyError）。"""
    return {"pid": pid, "ppid": ppid, "name": name, "exe": exe, "cmdline": cmdline,
            "user": user, "started": "", "threads": threads, "handles": None,
            "status": "running", "cpu": cpu, "mem_mb": mem_mb, "mem_pct": mem_pct,
            "parent_name": "", "windows": []}


def unsigned_sig(*exes):
    """未签名的签名表（key 用小写路径，与 scan.norm 一致）。"""
    return {scan.norm(e): {"status": "NotSigned", "signer": ""} for e in exes}


def findings_for(F, pid):
    return [f for f in F.items if f.get("target") == f"process:{pid}"]


# ============================================================================
# [1] 角色判定
# ============================================================================
print("--- [1] mark_self_processes 角色判定 ---")
_orig_self_exe = scan.SELF_EXE
try:
    scan.SELF_EXE = FAKE_EXE
    procs = [
        mkproc(900000, "SysScanGUI.exe", FAKE_EXE, ppid=1234),          # 引导器
        mkproc(900001, "SysScanGUI.exe", FAKE_EXE, ppid=900000),        # 应用本体
        mkproc(900002, "OtherGreenApp.exe", OTHER_EXE, ppid=1234),      # 同目录别的程序
        mkproc(900003, "SysScanGUI.exe", r"D:\Downloads\SysScanGUI.exe"),  # 同名不同路径
    ]
    notes = scan.mark_self_processes(procs)
    check("引导器被识别为「单文件引导器」", "引导器" in notes.get(900000, ""),
          notes.get(900000, ""))
    check("应用本体被识别为「应用本体」", notes.get(900001, "") == "本程序自身进程 · 应用本体",
          notes.get(900001, ""))
    check("同目录下的别的程序**不**算自身", 900002 not in notes)
    check("同名但路径不同的进程**不**算自身", 900003 not in notes)
    check("自身进程数为 2", len(notes) == 2, str(sorted(notes)))

    order = [
        mkproc(910000, "SysScanGUI.exe", FAKE_EXE, ppid=1234),
    ]
    notes1 = scan.mark_self_processes(order)
    check("只有单个自身进程时给通用说明",
          notes1.get(910000) == "本程序自身进程", notes1.get(910000, ""))

    # 大小写 / 引号差异不应影响匹配
    procs_c = [mkproc(920000, "SysScanGUI.exe", FAKE_EXE.upper(), ppid=1)]
    check("路径大小写不同仍能识别", 920000 in scan.mark_self_processes(procs_c))

    # ========================================================================
    # [2] 源码运行：只认 pid
    # ========================================================================
    print("\n--- [2] 源码运行（非冻结）只认 pid ---")
    scan.SELF_EXE = ""
    others = [mkproc(930000, "python.exe", sys.executable, ppid=1),
              mkproc(930001, "python.exe", r"C:\Python311\python.exe", ppid=1)]
    notes2 = scan.mark_self_processes(others)
    check("非冻结时不按 sys.executable 匹配（不会把全机 python.exe 当自身）",
          not notes2, str(notes2))
    notes2b = scan.mark_self_processes(others + [mkproc(os.getpid(), "python.exe",
                                                        os.path.abspath(sys.executable))])
    check("非冻结时本进程 pid 仍被标注", os.getpid() in notes2b, str(notes2b))

    # ========================================================================
    # [3] analyze_processes 端到端
    # ========================================================================
    print("\n--- [3] analyze_processes 端到端 ---")
    scan.SELF_EXE = FAKE_EXE
    F = scan.Findings()
    recs = [
        mkproc(940000, "SysScanGUI.exe", FAKE_EXE, ppid=1234),      # 引导器
        mkproc(940001, "SysScanGUI.exe", FAKE_EXE, ppid=940000),    # 应用本体
        mkproc(940002, "OtherGreenApp.exe", OTHER_EXE, ppid=1234),  # 别的未签名程序
    ]
    scan.analyze_processes(recs, unsigned_sig(FAKE_EXE, OTHER_EXE), F)
    by_pid = {p["pid"]: p for p in recs}

    check("自身·引导器 risk=正常", by_pid[940000]["risk"] == "正常",
          by_pid[940000]["risk"])
    check("自身·应用本体 risk=正常", by_pid[940001]["risk"] == "正常",
          by_pid[940001]["risk"])
    check("自身记录带 self_process 标记",
          by_pid[940000].get("self_process") and by_pid[940001].get("self_process"))
    check("自身记录的 self_note 能区分角色",
          "引导器" in by_pid[940000].get("self_note", "")
          and "应用本体" in by_pid[940001].get("self_note", ""),
          f"{by_pid[940000].get('self_note')} / {by_pid[940001].get('self_note')}")
    check("自身记录无 reasons", by_pid[940000]["reasons"] == []
          and by_pid[940001]["reasons"] == [])
    check("自身记录不产生 findings",
          not findings_for(F, 940000) and not findings_for(F, 940001),
          str([f["title"] for f in F.items]))
    check("path_note 里说明了身份",
          "自身进程" in by_pid[940001].get("path_note", ""),
          by_pid[940001].get("path_note", ""))

    # 最关键的反向断言：白名单不能放得过宽
    check("★ 同目录下别的未签名程序仍判中危", by_pid[940002]["risk"] == "中危",
          by_pid[940002]["risk"])
    other_f = findings_for(F, 940002)
    check("★ 且确实产生了对应的中危风险项",
          any(f["severity"] == "中危" and "未签名" in f["title"] for f in other_f),
          str([(f["severity"], f["title"]) for f in other_f]))

    # 无签名信息（sig={}）时也不能凭空报警
    F2 = scan.Findings()
    recs2 = [mkproc(950000, "SysScanGUI.exe", FAKE_EXE, ppid=1234)]
    scan.analyze_processes(recs2, {}, F2)
    check("自身进程在无签名信息时也不报警", recs2[0]["risk"] == "正常"
          and not findings_for(F2, 950000))

    # 自身进程即使落在会被判中危的路径上，也整体跳过规则 —— 保持行为可预期
    F3 = scan.Findings()
    recs3 = [mkproc(960000, "SysScanGUI.exe", FAKE_EXE, ppid=1234)]
    scan.SELF_EXE = r"Z:\SysScanGUI.exe"
    recs3[0]["exe"] = r"Z:\SysScanGUI.exe"
    scan.analyze_processes(recs3, {}, F3)
    check("自身进程位于磁盘根目录也不报警（规则整体跳过）",
          recs3[0]["risk"] == "正常", recs3[0]["risk"])

    # ========================================================================
    # [4] 真实进程表集成
    # ========================================================================
    print("\n--- [4] 真实进程表集成 ---")
    scan.SELF_EXE = ""
    import psutil
    me = psutil.Process(os.getpid())
    real = [mkproc(os.getpid(), me.name(), me.exe() or "", ppid=os.getppid())]
    F4 = scan.Findings()
    scan.analyze_processes(real, {}, F4)
    check("真实进程表里本进程被标注为自身", real[0].get("self_process") is True,
          str(real[0].get("self_note")))
    check("真实进程表里本进程 risk=正常", real[0]["risk"] == "正常", real[0]["risk"])
    check("真实进程表里本进程不产生风险项", not findings_for(F4, os.getpid()),
          str([f["title"] for f in F4.items]))
finally:
    scan.SELF_EXE = _orig_self_exe

# ============================================================================
# [5] 文案与界面
# ============================================================================
print("\n--- [5] 文案与界面 ---")
check("非自身记录没有说明文案", gui.self_process_hint({"pid": 1}) == "")
hint = gui.self_process_hint({"self_process": True, "self_note": "本程序自身进程 · 应用本体"})
check("自身记录说明文案包含角色", "应用本体" in hint, hint[:60])
check("说明文案解释了「不是旧实例没退出」", "不是旧实例没退出" in hint)
check("说明文案提到 onefile", "onefile" in hint)

app = QApplication.instance() or QApplication(sys.argv)
dlg = gui.DetailDialog(None, "processes",
                       {"pid": os.getpid(), "name": "SysScanGUI.exe",
                        "exe": FAKE_EXE, "risk": "正常", "reasons": [],
                        "self_process": True,
                        "self_note": "本程序自身进程 · 单文件引导器（解包并守护应用进程）"},
                       [])
from PySide6.QtWidgets import QLabel                               # noqa: E402
texts = [w.text() for w in dlg.findChildren(QLabel)]
check("详情窗显示了自身进程说明行",
      any("引导器" in t and "onefile" in t for t in texts),
      str([t for t in texts if "自身" in t or "引导器" in t])[:200])
dlg2 = gui.DetailDialog(None, "processes",
                        {"pid": 1234, "name": "explorer.exe", "exe": r"C:\Windows\explorer.exe",
                         "risk": "正常", "reasons": []}, [])
texts2 = [w.text() for w in dlg2.findChildren(QLabel)]
check("普通记录的详情窗不出现该说明行",
      not any("onefile" in t for t in texts2))

# ============================================================================
# [6] collect_self_group
# ============================================================================
print("\n--- [6] collect_self_group ---")
group = scan.collect_self_group()
check("至少包含本进程", any(r["pid"] == os.getpid() for r in group),
      str([(r["pid"], r["role"]) for r in group]))
check("字段齐全",
      all({"pid", "ppid", "name", "exe", "rss_mb", "role", "is_me"} <= set(r)
          for r in group),
      str(group[:2]))
check("本进程 is_me=True", any(r["is_me"] for r in group))
check("rss_mb 是数字", all(isinstance(r["rss_mb"], (int, float)) for r in group))

print()
print("ALL_CHECKS_PASSED" if not FAILED else f"FAILED: {FAILED}")
sys.exit(1 if FAILED else 0)
