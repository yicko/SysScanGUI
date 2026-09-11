# -*- coding: utf-8 -*-
"""实时硬件指标界面回归测试：python check_metrics_ui.py

验证概览页 6 张指标卡片、状态栏实时读数、来源说明对话框、开关与退出清理，
并覆盖几个具体回归点：
  · 概览页从 QTextEdit 改成「面板 + HTML」容器后，_render_overview 不能再往旧控件写
  · 任何一项拿不到数据时必须显示 “—” 且不画进度条，不能填 0 假装正常
  · 关闭窗口要停掉定时器并释放 PDH 查询句柄
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from PySide6.QtWidgets import QApplication          # noqa: E402
from PySide6.QtTest import QTest                    # noqa: E402

import gui                                          # noqa: E402
import metrics as metrics_mod                       # noqa: E402

PASS = FAIL = 0
FAILED: list[str] = []


def check(cond, label, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print(f"  [OK] {label}")
    else:
        FAIL += 1
        FAILED.append(label)
        print(f"  [FAIL] {label}" + (f"   ← {detail}" if detail else ""))


def show(label, value):
    print(f"      · {label}: {value}")


app = QApplication.instance() or QApplication([])

print("[1] 启动主窗口")
win = gui.ScanApp()
win.resize(1280, 800)
win.show()
QTest.qWait(300)
check(hasattr(win, "metrics_panel"), "概览页挂上了指标面板")
check(hasattr(win, "sampler") and isinstance(win.sampler, metrics_mod.MetricsSampler),
      "主窗口持有指标采样器")
check(hasattr(win, "overview_html"), "概览摘要改为独立 HTML 视图（旧 self.overview 已让位给容器）")
tiles = win.metrics_panel.tiles
show("指标卡片", list(tiles.keys()))
check(list(tiles.keys()) == ["cpu", "mem", "gpu", "vram", "ctemp", "gtemp"],
      "六张卡片齐全：CPU / 内存 / GPU / 显存 / CPU 温度 / GPU 温度")

print("\n[2] 定时器与开关")
check(win._metric_timer.isActive(), "指标定时器默认运行")
check(win._metric_timer.interval() == gui.METRIC_INTERVAL_MS, "刷新间隔为 3 秒")
win.act_live_metrics.setChecked(False)
check(not win._metric_timer.isActive(), "关闭开关后定时器停止")
check(win.live_lbl.text() == "", "关闭开关后清空状态栏读数")
win.act_live_metrics.setChecked(True)
check(win._metric_timer.isActive(), "重新打开开关后定时器恢复")

print("\n[3] 真实读数（等一次有效采样）")
deadline = time.time() + 8
while time.time() < deadline and (win._last_metrics.get("gpu_util") is None
                                  or win._last_metrics.get("cpu_pct") is None):
    QTest.qWait(400)
m = win._last_metrics
show("采样结果", {k: m.get(k) for k in ("cpu_pct", "mem_pct", "gpu_util",
                                        "gpu_mem_used_gb", "cpu_temp_c", "gpu_temp_c")})
show("状态栏", win.live_lbl.text())
check(m.get("cpu_pct") is not None, "拿到 CPU 使用率")
check(m.get("mem_pct") is not None, "拿到内存占用率")
check(m.get("gpu_util") is not None, "拿到 GPU 使用率（本机 PDH 可用）")
check(tiles["cpu"].value_lbl.text().endswith("%"), "CPU 卡片显示了百分比")
check(tiles["mem"].value_lbl.text().endswith("%"), "内存卡片显示了百分比")
check(tiles["gpu"].value_lbl.text().endswith("%"), "GPU 卡片显示了百分比")
check("GB" in tiles["vram"].value_lbl.text(), "显存卡片显示了容量")
check("CPU" in win.live_lbl.text(), "状态栏包含 CPU 读数")
check("GPU" in win.live_lbl.text(), "状态栏包含 GPU 读数")
check("·" in win.live_lbl.text(), "状态栏多个指标用分隔符连接")

print("\n[4] 温度卡片与来源标注")
show("CPU 温度卡片", (tiles["ctemp"].value_lbl.text(), tiles["ctemp"].sub_lbl.text()))
show("GPU 温度卡片", (tiles["gtemp"].value_lbl.text(), tiles["gtemp"].sub_lbl.text()))
if m.get("cpu_temp_c") is not None:
    check(tiles["ctemp"].value_lbl.text().endswith("°C"), "CPU 温度带 °C 单位")
    check(tiles["ctemp"].bar.isVisible(), "有温度读数时显示进度条")
    check("ACPI" in tiles["ctemp"].sub_lbl.text()
          or "LHM" in tiles["ctemp"].sub_lbl.text(), "CPU 温度卡片标注了来源")
    check("核心" not in tiles["ctemp"].sub_lbl.text().replace("不等于", ""),
          "不把 ACPI 热区谎称为 CPU 核心温度")
else:
    check(tiles["ctemp"].value_lbl.text() == "—", "拿不到 CPU 温度时显示 —")
    check(not tiles["ctemp"].bar.isVisible(), "拿不到数据时不画进度条")
if m.get("gpu_temp_c") is None:
    check(tiles["gtemp"].value_lbl.text() == "—", "拿不到 GPU 温度时显示 —")
    check("nvidia-smi" in tiles["gtemp"].sub_lbl.text()
          or "LibreHardwareMonitor" in tiles["gtemp"].sub_lbl.text(),
          "GPU 温度不可用时说明了获取途径")
    check(not tiles["gtemp"].bar.isVisible(), "GPU 温度不可用时不画进度条")

print("\n[5] 全部指标缺失时不得伪造数值")
win.metrics_panel.update_from({})
allna = all(t.value_lbl.text() == "—" for t in tiles.values())
show("六张卡片", [t.value_lbl.text() for t in tiles.values()])
check(allna, "数据全空时六张卡片都显示 —，不填 0")
check(all(not t.bar.isVisible() for t in tiles.values()),
      "数据全空时不显示任何进度条（避免读成 0%）")
check(all(t.sub_lbl.text() for t in tiles.values()),
      "每张卡片都给出不可用原因，而不是留空")

print("\n[5b] 百分比格式化（小数不被抹成 0，倍数不印长尾）")
show("_fmt_pct", [gui._fmt_pct(x) for x in (0.204, 0.0, 3.7, 37.0, 100.0, None)])
check(gui._fmt_pct(0.204) == "0.2%", "0.2% 的真实活动不会显示成 0%")
check(gui._fmt_pct(0.0) == "0.0%", "真正为 0 时显示 0.0%")
check(gui._fmt_pct(37.0) == "37%", "两位以上百分比不保留多余小数")
check(gui._fmt_pct(None) == "—", "缺失值显示 —")
fake = {"cpu_pct": 6.3, "gpu_util": 0.204, "mem_pct": 43.7}
win.metrics_panel.update_from(fake)
check(tiles["gpu"].value_lbl.text() == "0.2%", "GPU 卡片按 1 位小数显示低占用")
# 状态栏也要确定性验证：注入采样器结果后走真实的 _refresh_metrics 路径。
# （原来这里直接断言实时读数，只有真实 GPU 恰好也读到 0.2% 才会通过 —— 碰运气的断言）
orig_sample = win.sampler.sample
win.sampler.sample = lambda: dict(fake)
try:
    win._refresh_metrics()
    status_txt = win.live_lbl.text()
finally:
    win.sampler.sample = orig_sample
check("0.20401" not in status_txt, "状态栏不出现 float 长尾")
check("GPU 0.2%" in status_txt, "状态栏低占用保留一位小数")
check("CPU 6.3%" in status_txt and "内存 44%" in status_txt,
      f"状态栏各指标格式正确   [{status_txt}]")

print("\n[6] 部分缺失的混合场景")
win.metrics_panel.update_from({
    "cpu_pct": 12.0, "mem_pct": 43.0, "mem_used_gb": 13.6, "mem_total_gb": 31.9,
    "gpu_util": 37.0, "gpu_name": "Intel(R) UHD Graphics 630",
    "gpu_mem_used_gb": 1.17, "gpu_mem_dedicated_gb": 0.0, "gpu_mem_shared_gb": 0.8,
    "cpu_temp_c": 47.5, "cpu_temp_src": "LHM",
    "gpu_temp_c": 52.0, "gpu_temp_src": "nvidia-smi",
})
show("CPU", (tiles["cpu"].value_lbl.text(), tiles["cpu"].bar.value()))
show("GPU", (tiles["gpu"].value_lbl.text(), tiles["gpu"].bar.value()))
show("显存", (tiles["vram"].value_lbl.text(), tiles["vram"].sub_lbl.text()))
show("GPU 温度", tiles["gtemp"].value_lbl.text())
check(tiles["cpu"].value_lbl.text() == "12%", "CPU 数值格式正确")
check(tiles["mem"].value_lbl.text() == "43%", "内存数值格式正确")
check(tiles["gpu"].value_lbl.text() == "37%", "GPU 数值格式正确")
check(tiles["gpu"].bar.value() == 37, "GPU 进度条跟随数值")
check(tiles["mem"].sub_lbl.text() == "13.6 / 31.9 GB", "内存卡片给出已用/总量")
check("1.17 GB" in tiles["vram"].value_lbl.text(), "显存显示绝对占用")
check(not tiles["vram"].bar.isVisible(), "显存总量未知时不画百分比条（避免假分母）")
check("总量未知" in tiles["vram"].sub_lbl.text(), "显存总量未知时明确说明")
check(tiles["ctemp"].value_lbl.text() == "47.5°C", "CPU 温度保留一位小数")
check("LHM" in tiles["ctemp"].sub_lbl.text(), "LHM 来源标注正确")
check(tiles["gtemp"].value_lbl.text() == "52.0°C", "GPU 温度显示正确")
check(tiles["gtemp"].bar.isVisible(), "有 GPU 温度时显示进度条")

print("\n[7] 高负载配色（红/琥珀）")
win.metrics_panel.update_from({"cpu_pct": 95.0, "mem_pct": 80.0, "gpu_util": 90.0,
                               "cpu_temp_c": 92.0, "gpu_temp_c": 90.0})
show("CPU 颜色", tiles["cpu"].value_lbl.styleSheet())
check(gui.METRIC_HIGH in tiles["cpu"].value_lbl.styleSheet(), "CPU 95% 用危险色")
check(gui.METRIC_HIGH in tiles["gpu"].value_lbl.styleSheet(), "GPU 90% 用危险色")
check(gui.METRIC_MID in tiles["mem"].value_lbl.styleSheet(), "内存 80% 用偏高色")
check(gui.METRIC_HIGH in tiles["ctemp"].value_lbl.styleSheet(), "CPU 92°C 用危险色")
win.metrics_panel.update_from({"cpu_pct": 5.0, "mem_pct": 10.0, "gpu_util": 2.0})
check(gui.METRIC_OK in tiles["cpu"].value_lbl.styleSheet(), "低负载回到正常色")

print("\n[8] 来源说明对话框（拦截弹窗，检查文案）")
captured = {}
orig_info = gui._info
gui._info = lambda parent, title, text: captured.update({"title": title, "text": text})
try:
    win.show_metric_sources()
finally:
    gui._info = orig_info
txt = captured.get("text", "")
show("对话框标题", captured.get("title"))
for line in txt.splitlines()[:12]:
    print(f"      | {line}")
check(captured.get("title") == "指标数据来源", "对话框标题正确")
check("GPU 使用率" in txt and "显存" in txt and "CPU 温度" in txt,
      "四个指标都有来源说明")
check("不可用" in txt or win.sampler.lhm_active, "取不到的数据源如实说明不可用")
check("ACPI" in txt, "解释了 ACPI 热区不等于 CPU 核心温度")
check("PDH" in txt or "性能计数器" in txt, "说明了取数机制（PDH 直连）")
check("Intel" in txt or "未识别" in txt, "列出了识别到的显卡")
check("nvidia-smi" in txt and "PowerShell" in txt, "说明了刻意不调外部命令的原因")

print("\n[9] 概览 HTML 摘要未受重构影响")
html = win.overview_html.toPlainText()
show("摘要素略", html[:60].replace("\n", " "))
check("扫描概览" in html, "概览摘要仍然正常渲染（旧 self.overview.setHtml 已改到 overview_html）")
check("实时指标" in html, "摘要提示里说明了实时指标")
check(win.overview.__class__.__name__ != "QTextEdit", "概览页已是容器控件而非纯 QTextEdit")

print("\n[10] 退出清理")
closed = {"v": 0}
orig_close = win.sampler.close


def spy_close():
    closed["v"] += 1
    orig_close()


win.sampler.close = spy_close
win.close()
QTest.qWait(200)
check(closed["v"] >= 1, "关闭窗口时释放了 PDH 查询句柄")
check(not win._metric_timer.isActive(), "关闭后指标定时器已停止")
check(not win._conn_timer.isActive(), "关闭后连接刷新定时器已停止")

print("\n" + "=" * 64)
print(f"通过 {PASS} 项，失败 {FAIL} 项")
if FAILED:
    for x in FAILED:
        print(f"  FAILED: {x}")
print("ALL_CHECKS_PASSED" if FAIL == 0 else "CHECKS_FAILED")
sys.exit(0 if FAIL == 0 else 1)
