# -*- coding: utf-8 -*-
"""版本号回归测试：python check_version.py

版本号是"用户报 bug 时唯一的定位线索"，一旦它悄悄失真（永远是 dev、
或与 Release tag 对不上），排障成本会成倍上升。本测试钉住三件事：

  1. 取号规则：环境变量 → git describe → DEV_VERSION 的优先级与清洗
  2. 注入链路：注入文件 → current() → 「关于」弹窗显示的版本
     —— 并用**反向验证**证明弹窗里的版本真的来自注入，不是源码里写死的
  3. 不冒充：源码直接运行时必须是 DEV_VERSION，绝不能显示某个真版本号

运行：
    python check_version.py
    python check_version.py --verbose
"""
from __future__ import annotations

import os
import sys
import tempfile
import traceback

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

import app_version as ver_mod                  # noqa: E402
import gui                                     # noqa: E402

VERBOSE = "--verbose" in sys.argv
FAILS: list[str] = []


def check(cond: bool, msg: str, detail: str = ""):
    if cond:
        if VERBOSE:
            print(f"    ok  {msg}")
    else:
        FAILS.append(msg)
        print(f"    FAIL  {msg}" + (f"   ← {detail}" if detail else ""))


def main() -> int:
    print("[1] _clean：剥掉 tag 的前导 v")
    check(ver_mod._clean("v1.0.2") == "1.0.2", "v1.0.2 → 1.0.2")
    check(ver_mod._clean("V1.0.2") == "1.0.2", "V1.0.2 → 1.0.2")
    check(ver_mod._clean("1.0.2") == "1.0.2", "无前缀的版本号不被改动")
    check(ver_mod._clean("  v1.0.2  ") == "1.0.2", "首尾空白被去掉")
    check(ver_mod._clean("v1.0.2-3-gabc-dirty") == "1.0.2-3-gabc-dirty",
          "tag 之后的描述串只剥前导 v")
    check(ver_mod._clean("") == "", "空串 → 空串")
    check(ver_mod._clean("version1") == "version1", "不以数字开头的串不被误剥")

    print("[2] version_tuple：转 Windows 版本资源的 4 段数字")
    cases = [("1.0.2", (1, 0, 2, 0)),
             ("v1.0.2", (1, 0, 2, 0)),
             ("1.0.2-3-g1efab92-dirty", (1, 0, 2, 0)),
             ("0.0.0-dev", (0, 0, 0, 0)),
             ("2", (2, 0, 0, 0)),
             ("3.1", (3, 1, 0, 0)),
             ("1.2.3.4.5", (1, 2, 3, 4)),
             ("dev", (0, 0, 0, 0)),
             ("", (0, 0, 0, 0))]
    for src, want in cases:
        got = ver_mod.version_tuple(src)
        check(got == want, f"version_tuple({src!r}) == {want}", f"实际 {got}")

    print("[3] resolve_build_version：取号优先级")
    env_win = {ver_mod.ENV_VAR: "9.9.9-ci"}
    check(ver_mod.resolve_build_version(env=env_win, root=HERE) == "9.9.9-ci",
          "环境变量优先于 git")
    check(ver_mod.resolve_build_version(env={ver_mod.ENV_VAR: "v9.9.9"},
                                        root=HERE) == "9.9.9",
          "环境变量里的前导 v 被剥掉")
    check(ver_mod.resolve_build_version(env={ver_mod.ENV_VAR: "   "}, root=HERE)
          != "   ", "空白环境变量被忽略（不当作版本号）")

    # git 分支：用假的 git 运行器精确控制返回值，不依赖本机 git 状态
    orig_run_git = ver_mod._run_git
    try:
        calls: list[list[str]] = []

        def fake_git(args, cwd):
            calls.append(list(args))
            # 第一次调用（--exact-match）空，第二次（无 flag）给出 tag 之后的描述串
            return "" if "--exact-match" in args else "v1.0.2-3-g1efab92-dirty"

        ver_mod._run_git = fake_git
        got = ver_mod.resolve_build_version(env={}, root=HERE)
        check(got == "1.0.2-3-g1efab92-dirty",
              "无环境变量时回退 git describe（已剥 v）", f"实际 {got!r}")
        check(len(calls) == 2 and "--exact-match" in calls[0],
              "先试 --exact-match，再退到普通 describe", f"实际 {calls}")
        check(any("--dirty" in c for c in calls),
              "带上 --dirty，本地有未提交改动时能看出来")

        ver_mod._run_git = lambda args, cwd: "v2.0.0"
        got = ver_mod.resolve_build_version(env={}, root=HERE)
        check(got == "2.0.0", "正好在 tag 上时直接取该 tag", f"实际 {got!r}")

        ver_mod._run_git = lambda args, cwd: ""
        check(ver_mod.resolve_build_version(env={}, root=HERE) == ver_mod.DEV_VERSION,
              "git 取不到（无仓库/无 tag）→ DEV_VERSION")

        def boom(args, cwd):
            raise FileNotFoundError("git 不存在")

        ver_mod._run_git = boom
        check(ver_mod.resolve_build_version(env={}, root=HERE) == ver_mod.DEV_VERSION,
              "git 不可用时不抛异常，安全落到 DEV_VERSION")
    finally:
        ver_mod._run_git = orig_run_git

    print("[4] 真实仓库：本地 git 确实能取到东西")
    real = ver_mod._run_git(["describe", "--tags", "--dirty"], HERE)
    live = ver_mod.resolve_build_version(env={}, root=HERE)
    if VERBOSE:
        print(f"    git describe → {real!r}")
        print(f"    resolve_build_version → {live!r}")
    check(live == ver_mod.DEV_VERSION or live[0].isdigit(),
          "解析结果要么是 DEV_VERSION，要么以数字开头（是版本号而非报错文本）",
          f"实际 {live!r}")
    if real:
        check(live == ver_mod._clean(real), "与 git describe 的输出一致", f"实际 {live!r}")
    else:
        check(live == ver_mod.DEV_VERSION, "git 无输出时落到 DEV_VERSION")

    print("[5] 注入文件：读回与容错")
    with tempfile.TemporaryDirectory() as tmp:
        check(ver_mod.read_injected(tmp) == "", "目录里没有注入文件 → 空串")
        p = os.path.join(tmp, ver_mod.INJECT_NAME)
        with open(p, "w", encoding="utf-8") as f:
            f.write("1.0.3\n")
        check(ver_mod.read_injected(tmp) == "1.0.3", "读到注入的版本号并 strip 换行")

        # 反向验证：current() / about_text() 必须跟着注入文件走
        orig_root = ver_mod.build_root
        try:
            ver_mod.build_root = lambda: tmp
            check(ver_mod.current() == "1.0.3", "current() 取自注入文件", ver_mod.current())
            check(ver_mod.is_official() is True, "有注入 → 判定为正式构建")
            check("版本 1.0.3" in gui.about_text(),
                  "「关于」显示注入的版本号", gui.about_text().splitlines()[1])

            with open(p, "w", encoding="utf-8") as f:
                f.write("7.7.7-rebuild")
            check(ver_mod.current() == "7.7.7-rebuild",
                  "换掉注入内容，current() 跟着变")
            check("版本 7.7.7-rebuild" in gui.about_text(),
                  "换掉注入内容，「关于」跟着变（证明版本号不是源码里写死的）")

            os.remove(p)
            check(ver_mod.current() == ver_mod.DEV_VERSION,
                  "移除注入文件 → 回落到 DEV_VERSION")
            check(ver_mod.is_official() is False, "无注入 → 判定为源码运行")
            check("版本 " + ver_mod.DEV_VERSION in gui.about_text(),
                  "「关于」如实显示 DEV_VERSION（不冒充正式版本）")
        finally:
            ver_mod.build_root = orig_root

    print("[6] 源码运行：必须如实显示 dev")
    check(ver_mod.build_root() == HERE, "源码运行时的根目录是本文件所在目录")
    check(ver_mod.current() == ver_mod.DEV_VERSION, "源码运行 → DEV_VERSION",
          ver_mod.current())
    check(ver_mod.__version__ == ver_mod.current(), "__version__ 与 current() 一致")
    text = gui.about_text()
    check(f"版本 {ver_mod.DEV_VERSION}" in text, "「关于」含 DEV_VERSION")
    check(text.splitlines()[1].startswith("版本 "), "版本号位于「关于」第二行",
          repr(text.splitlines()[:2]))

    print("[7] 「关于」其余内容未被破坏")
    for w in ("互斥体", "锁文件", "PyInstaller", "onefile"):
        check(w not in text, f"仍不含实现细节「{w}」")
    for w in ("不联网", "管理员权限", "运行实例信息", "MIT"):
        check(w in text, f"仍含用户关心的「{w}」")

    print()
    if FAILS:
        print(f"CHECKS_FAILED: {len(FAILS)} 项未通过")
        for f in FAILS:
            print("  -", f)
        return 1
    print("ALL_CHECKS_PASSED")
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception:
        traceback.print_exc()
        sys.exit(1)
