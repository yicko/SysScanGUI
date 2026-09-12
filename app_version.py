# -*- coding: utf-8 -*-
"""构建版本号 —— 源码、打包、CI 与用户界面共用的唯一来源。

版本号**不硬编码在源码里**，而是由打包时所在的 git 状态决定。这样
「关于」弹窗显示的版本号、exe 右键属性里的版本号、以及 Release 页上的
tag，三者永远指同一件事 —— 用户报 bug 时能立刻对上是哪个构建。

取号顺序（`resolve_build_version`）：

  1. 环境变量 `SYSSCAN_BUILD_VERSION` —— CI 用它把 tag 显式注入（最可靠）
  2. `git describe --tags --exact-match --dirty` —— 本地正好在某个 tag 上
  3. `git describe --tags --dirty` —— 本地在 tag 之后
     （形如 `1.0.2-3-g1efab92-dirty`，顺带说明"
      这是 tag 之后 3 个提交、且工作区有未提交改动"）
  4. `DEV_VERSION` —— 源码直接运行 / 没有 git / 没有 tag

源码直接运行（`python gui.py`）时拿到的是 `DEV_VERSION`，而不是某个真版本号：
**宁可显示 0.0.0-dev 也不冒充正式构建** —— 一眼就能区分"用户跑的是官方包"
还是"跑的是改过的源码"。

注入方式见 `SysScanGUI.spec`：打包时把解析出的版本号写成 `_build_version.txt`
一并打进包（onefile 会解包到 `sys._MEIPASS`），运行期由 `current()` 读回。
"""
from __future__ import annotations

import os
import re
import subprocess
import sys

DEV_VERSION = "0.0.0-dev"
ENV_VAR = "SYSSCAN_BUILD_VERSION"
INJECT_NAME = "_build_version.txt"


def build_root() -> str:
    """注入文件的所在目录。

    冻结后（onefile）是解包目录 `sys._MEIPASS`；源码运行是本文件所在目录。
    """
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return meipass
    return os.path.dirname(os.path.abspath(__file__))


def read_injected(root: str | None = None) -> str:
    """读打包时注入的版本号；没有该文件（源码运行）返回空串。"""
    path = os.path.join(root or build_root(), INJECT_NAME)
    try:
        with open(path, encoding="utf-8") as f:
            return f.read().strip()
    except OSError:
        return ""


def current() -> str:
    """本进程正在运行的版本号。"""
    return read_injected() or DEV_VERSION


def is_official() -> bool:
    """是否为正式构建（有注入版本号），而非源码直接运行。"""
    return current() != DEV_VERSION


def _clean(v) -> str:
    """去掉 tag 的前导 v：`v1.0.2` → `1.0.2`（版本号不带 v，tag 才带）。

    只在「v 后面紧跟数字」时才剥，避免把 `version1` 这类串剥成 `ersion1`。
    非字符串输入一律按文本处理，不抛异常（这是打包路径上的代码）。
    """
    s = ("" if v is None else str(v)).strip()
    if s[:1] in ("v", "V") and s[1:2].isdigit():
        s = s[1:]
    return s


def _run_git(args: list[str], cwd: str) -> str:
    """跑一条 git 命令，成功返回 stdout（已 strip），失败一律返回空串。"""
    try:
        r = subprocess.run(["git", *args], cwd=cwd, capture_output=True, timeout=15,
                           creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    except Exception:
        return ""
    if r.returncode != 0:
        return ""
    return (r.stdout or b"").decode("utf-8", "replace").strip()


def resolve_build_version(env: dict | None = None, root: str | None = None) -> str:
    """解析出「这个包应该带的版本号」（打包时由 spec 调用）。

    env 与 root 可注入，便于测试；默认取真实环境变量与本文件所在目录。
    """
    env = os.environ if env is None else env
    v = _clean(env.get(ENV_VAR, ""))
    if v:
        return v
    root = root or os.path.dirname(os.path.abspath(__file__))
    # 先试"正好打在 tag 上"，再退到"tag 之后"（带上距离与提交号，并有 dirty 标记）
    # 调用点也做异常防护：本函数在 SysScanGUI.spec 里执行，任何异常都会让打包直接失败，
    # 而"取不到版本号"远没有"打不出包"严重。
    for extra in (["--exact-match"], []):
        try:
            out = _run_git(["describe", "--tags", "--dirty", *extra], root)
        except Exception:
            continue
        if out:
            return _clean(out)
    return DEV_VERSION


def version_tuple(v: str | None = None) -> tuple[int, int, int, int]:
    """转成 Windows 版本资源要的 4 段数字。

    `1.0.2` → `(1, 0, 2, 0)`；`1.0.2-3-g1efab92-dirty` → `(1, 0, 2, 0)`；
    `0.0.0-dev` → `(0, 0, 0, 0)`（非数字后缀只影响文本版本，不影响数字段）。
    """
    head = re.match(r"\s*[vV]?(\d+(?:\.\d+)*)", v if v is not None else current())
    parts = [int(x) for x in head.group(1).split(".")] if head else []
    return tuple((parts + [0, 0, 0, 0])[:4])  # type: ignore[return-value]


__version__ = current()
