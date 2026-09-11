# -*- coding: utf-8 -*-
"""冻结环境下的扫描链路回归测试入口（不随产品发布，但请保留：每次改 spec 后跑一遍）。

构建命令（每次修改 SysScanGUI.spec 的剔除规则后执行）：
    python -m PyInstaller --noconfirm --onefile --console --name _scanchk \
        --distpath _chk_dist --workpath _chk_build --specpath _chk_build \
        --exclude-module ssl --exclude-module _ssl --exclude-module _hashlib \
        --exclude-module sitecustomize --exclude-module pyinstaller \
        --exclude-module PyInstaller --exclude-module tkinter check_frozen_scan.py
    ./_chk_dist/_scanchk.exe      # 期望输出 ALL_CHECKS_PASSED

验证点：
  1. 剔除 ssl / _ssl / _hashlib（连带 OpenSSL DLL）后，扫描功能不受影响
  2. PowerShell 签名校验子进程通道在冻结环境可用
  3. 计划任务 XML 解析（pyexpat）与注册表读取（winreg）可用
  4. report.build_html 渲染可用
"""
import json
import os
import sys
import traceback

HERE = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
if not getattr(sys, "frozen", False):
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import report
import scan


def main() -> int:
    try:
        print("[1] run_scan ...")
        steps = []
        data = scan.run_scan(progress_cb=lambda s, t, m: steps.append(s),
                             do_signature=True, do_tasks=True)
        print(f"    progress steps = {sorted(set(steps))}")
        sm = data["summary"]
        print(f"    processes={sm['process_count']} services={sm['service_count']} "
              f"conns={sm['conn_count']} persist={sm['persist_count']} risks={sm['risk_total']}")
        print(f"    signature_checked={data['meta'].get('signature_checked')}")
        if sm["process_count"] < 50:
            print("FAIL: 进程数异常偏少")
            return 1

        print("[2] 签名校验结果抽样 ...")
        from collections import Counter
        signed = [p for p in data["processes"] if p.get("sig_signer")]
        stat = Counter((p.get("sig_status") or "?") for p in data["processes"])
        print(f"    含签名者信息的进程 {len(signed)} 个；状态分布 {dict(stat)}")
        if data["meta"].get("signature_checked") and stat.get("未验证", 0) > len(data["processes"]) * 0.9:
            print("FAIL: 签名校验通道失效（绝大多数进程未验证，PowerShell 调用可能未生效）")
            return 1

        print("[3] 计划任务 XML 解析结果 ...")
        tasks = [it for it in data["persistence"] if it.get("type") == "计划任务"]
        print(f"    计划任务 {len(tasks)} 项")
        if not tasks:
            print("FAIL: 未采集到计划任务（pyexpat / schtasks 可能缺失）")
            return 1

        print("[4] report.build_html ...")
        html = report.build_html(data)
        if len(html) < 20000:
            print(f"FAIL: HTML 过短 ({len(html)})")
            return 1
        out = os.path.join(HERE, "_scanchk_report.html")
        with open(out, "w", encoding="utf-8") as f:
            f.write(html)
        print(f"    HTML {len(html) / 1024:.0f} KB -> {out}")

        print("[5] ssl / hashlib 确认未被打包 ...")
        for mod in ("ssl", "_ssl", "_hashlib"):
            try:
                __import__(mod)
                print(f"    WARN: {mod} 仍可导入（预期不应存在）")
            except ImportError:
                print(f"    OK: {mod} 不存在，且前述功能全部正常")

        print("ALL_CHECKS_PASSED")
        return 0
    except Exception:
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
