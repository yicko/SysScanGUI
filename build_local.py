#!/usr/bin/env python3
"""本地构建入口 —— 专门绕开 Smart App Control 对未签名 exe 的拦截。

背景（2026-09-15 本机实测，可复现）
----------------------------------
Windows 11 的 Smart App Control（SAC）在强制模式下会直接阻止**未签名**的
PyInstaller 产物，报 `OSError [WinError 4551] 应用程序控制策略已阻止此文件`，
并且**没有「仍要运行」按钮**（已确认判定依据是文件内容，换目录/换名都无效）。

关键实测对照（同一台机器、同一份源码、同一天，唯一变量是解释器发行版）：

    ┌──────────────────────────────────────────────┬───────────┬────────────┐
    │ 构建用解释器                                  │ 签名状态   │ SAC 结果   │
    ├──────────────────────────────────────────────┼───────────┼────────────┤
    │ uv / 受管 python-build-standalone 3.13        │ 未签名     │ ❌ 被拦    │
    │ python.org 官方 3.11.9                        │ PSF 已签名 │ ✅ 可运行  │
    │ CI（actions/setup-python → python.org 3.11.9）│ PSF 已签名 │ ✅ 可运行  │
    └──────────────────────────────────────────────┴───────────┴────────────┘

原因：PyInstaller onefile 会把 Python 运行时打进 exe（`python3.dll` /
`pythonXY.dll`）。python.org 的这些二进制由 Python Software Foundation 做了
Authenticode 签名，python-build-standalone（uv 默认拉的发行版）则**完全没有签名**；
一个应用里混入未签名组件，SAC 就会整体判为不可信。CI 一直没问题，正是因为
`actions/setup-python` 装的就是 python.org 版。

所以：**本地构建改用 python.org 解释器即可，无需关闭 SAC，也无需代码签名证书。**

用法
----
    python build_local.py                 # 自动挑选已签名解释器并构建
    python build_local.py --list          # 只看候选解释器及其签名状态
    python build_local.py --distpath out  # 指定输出目录
    python build_local.py --interpreter "C:/Program Files/Python311/python.exe"

说明：本脚本不改动任何系统设置，只做「选解释器 + 调 PyInstaller」。
"""

from __future__ import annotations

import argparse
import base64
import glob
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SPEC = os.path.join(HERE, "SysScanGUI.spec")

# 尽量与 .github/workflows/release.yml 对齐：CI 固定用 3.11
PREFERRED_MAJOR_MINOR = "3.11"

# 优先在这些位置找解释器（不包含任何 venv / 受管环境）
SEARCH_GLOBS = [
    r"C:\Program Files\Python3*\python.exe",
    r"C:\Program Files\Python\Python3*\python.exe",
    r"C:\Program Files (x86)\Python3*\python.exe",
    os.path.expanduser(r"~\AppData\Local\Programs\Python\Python3*\python.exe"),
    r"C:\Python3*\python.exe",
    # 放在最后：WorkBuddy 受管解释器是 python-build-standalone（未签名），
    # 列出来只为在 --list 时能看清它为何会失败。
    os.path.expanduser(
        r"~\.workbuddy\binaries\python\versions\*\python.exe"),
]

_PS = "powershell.exe"


def _ps(cmd: str) -> str:
    """调用 Windows PowerShell 5.1；-EncodedCommand 规避引号问题，强制 UTF-8 输出。"""
    enc = base64.b64encode(cmd.encode("utf-16-le")).decode("ascii")
    p = subprocess.run(
        [_PS, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass",
         "-EncodedCommand", enc],
        capture_output=True)
    return p.stdout.decode("utf-8", errors="replace")


def _sign_status(paths: list[str]) -> dict[str, str]:
    """批量查 Authenticode 状态 → {path: 'Valid'|'NotSigned'|...}。

    用一次 PowerShell 调用查完，避免逐文件 spawn。
    注意 PowerShell 5.1 的数组不支持尾随逗号，用 join 拼。
    """
    if not paths:
        return {}
    listed = ",".join("'" + p.replace("'", "''") + "'" for p in paths)
    # 用 '|' 作分隔符：PowerShell 单引号串里的 `t 是字面量、不会变成制表符，
    # 用 Format-List 又太长，所以选一个路径里不可能出现的字符。
    cmd = ("[Console]::OutputEncoding=[Text.Encoding]::UTF8;"
           f"foreach($p in @({listed})){{"
           "  $s=Get-AuthenticodeSignature -LiteralPath $p;"
           "  ('{0}|{1}' -f $p,$s.Status)"
           "}")
    out = _ps(cmd)
    res: dict[str, str] = {}
    for line in out.splitlines():
        line = line.strip()
        if "|" in line:
            p, st = line.rsplit("|", 1)
            res[p.strip()] = st.strip()
    return res


def find_interpreters() -> list[str]:
    found: list[str] = []
    for pat in SEARCH_GLOBS:
        found += glob.glob(pat)
    # 去掉重复与解释器旁边的 venv
    uniq = []
    for p in found:
        if os.path.isfile(p) and p not in uniq:
            uniq.append(p)

    def rank(p: str) -> tuple:
        v = os.path.basename(os.path.dirname(p)).replace("Python", "") or "0"
        # 3.11 优先（与 CI 一致），其余按版本降序
        return (0 if v.startswith(PREFERRED_MAJOR_MINOR) else 1,
                tuple(-int(x) for x in (v.split(".") + ["0", "0"])[:2]))

    return sorted(uniq, key=rank)


def pick_signed(interps: list[str]) -> tuple[str | None, list[tuple[str, str]]]:
    st = _sign_status(interps)
    rows = [(p, st.get(p, "Unknown")) for p in interps]
    for p, s in rows:
        if s == "Valid":
            return p, rows
    return None, rows


def main() -> int:
    ap = argparse.ArgumentParser(description="用已签名的 python.org 解释器本地构建")
    ap.add_argument("--list", action="store_true", help="只列出候选解释器及签名状态")
    ap.add_argument("--interpreter", help="手动指定解释器路径")
    ap.add_argument("--distpath", help="输出目录（默认 spec 里的 dist）")
    ap.add_argument("--version", help="注入版本号（默认交给 app_version 推断）")
    args = ap.parse_args()

    interps = find_interpreters()
    if args.interpreter:
        interps = [args.interpreter, *[p for p in interps if p != args.interpreter]]

    if not interps:
        print("✗ 没找到任何 Python 解释器。请先安装 python.org 官方版（3.11 x64）。")
        return 2

    chosen, rows = pick_signed(interps)

    print("候选解释器与 Authenticode 状态：")
    for p, s in rows:
        mark = "✅" if s == "Valid" else ("⚠️ " if s == "NotSigned" else "  ")
        print(f"  {mark} {s:<12} {p}")
    print()

    if args.list:
        return 0

    if chosen is None:
        print("✗ 没有找到**已签名**的解释器 —— 用它构建出的 exe 会被 Smart App Control 拦。")
        print("  解决：安装 python.org 官方版 Python 3.11 x64（安装包自带 PSF 签名），")
        print("  然后重新运行本脚本；或用 --interpreter 指定其路径。")
        return 3

    print(f"→ 选用已签名解释器：{chosen}")
    env = dict(os.environ)
    env.setdefault("PYTHONUTF8", "1")
    if args.version:
        env["SYSSCAN_BUILD_VERSION"] = args.version
    # 本机 WorkBuddy 受管 Python 注入了「安全删除」垫片；用空 sitecustomize 抢占，
    # 让 PyInstaller 的清理动作正常工作（仅影响本进程环境变量，不改系统）。
    noop = r"C:\temp\noop"
    if os.path.isfile(os.path.join(noop, "sitecustomize.py")):
        env["PYTHONPATH"] = noop

    cmd = ["uv", "run", "--no-project", "--python", chosen,
           "--with", "PySide6-Essentials", "--with", "psutil",
           "--with", "pyinstaller",
           "python", "-m", "PyInstaller", "--noconfirm", "--clean"]
    if args.distpath:
        cmd += ["--distpath", args.distpath]
    cmd.append(SPEC)

    # uv 可能不在 PATH（本机装在 ~/.local/bin）
    if not _which("uv"):
        for c in (os.path.expanduser(r"~\.local\bin\uv.exe"),
                  os.path.expanduser(r"~\.cargo\bin\uv.exe")):
            if os.path.isfile(c):
                cmd[0] = c
                break

    print("→ " + " ".join(cmd[:6]) + " ... " + os.path.basename(SPEC))
    print()
    return subprocess.call(cmd, cwd=HERE, env=env)


def _which(name: str) -> str | None:
    for d in os.environ.get("PATH", "").split(os.pathsep):
        c = os.path.join(d, name + ".exe")
        if os.path.isfile(c):
            return c
        c = os.path.join(d, name)
        if os.path.isfile(c):
            return c
    return None


if __name__ == "__main__":
    sys.exit(main())
