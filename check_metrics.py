# -*- coding: utf-8 -*-
"""hardware metrics 回归测试：python check_metrics.py

覆盖三层：
  A. 纯函数（聚合口径 / 温度换算 / 各来源解析）—— 不依赖真实硬件，可离线验证
  B. 真实采样（读本机 PDH）—— 验证确实拿到数、成本可接受、反复采样不崩
  C. 防回归（源码级守卫 + 采样间隔语义）—— 针对已经踩过的具体坑
"""

import os
import statistics
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import metrics as M     # noqa: E402

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


# ======================================================================
print("[1] GPU 利用率聚合口径（对齐任务管理器：同引擎跨进程求和，取最忙引擎）")
AD = "luid_0x00000000_0x0001045C_phys_0"
AD2 = "luid_0x00000000_0x00010A6D_phys_0"


def inst(pid, engtype, adapter=AD):
    return f"pid_{pid}_{adapter}_eng_0_engtype_{engtype}"


items = [
    (inst(100, "3D"), 4.0),
    (inst(200, "3D"), 6.0),          # 同一引擎两个进程 → 应相加为 10
    (inst(300, "VideoDecode"), 3.0),
    (inst(400, "Copy"), 1.0),
    (inst(500, ""), 99.0),           # 空引擎类型 → 必须丢弃，不能污染结果
]
per, peak = M.aggregate_gpu_utilization(items)
show("分组", {f"{k[1]}@{k[0][-6:]}": round(v, 2) for k, v in per.items()})
show("峰值", peak)
check(peak is not None and abs(peak - 10.0) < 1e-9,
      "同引擎跨进程求和后取峰值 = 10.0", f"得到 {peak}")
check(per.get((AD.lower(), "3D")) == 10.0, "3D 引擎合计为 4+6=10")
check(all(k[1] != "" for k in per), "空引擎类型的实例被丢弃")

per2, peak2 = M.aggregate_gpu_utilization(
    [(inst(1, "3D"), 80.0), (inst(2, "3D"), 70.0)])
check(peak2 == 100.0, "多进程叠加超过 100 时被钳到 100", f"得到 {peak2}")

check(M.aggregate_gpu_utilization([]) == ({}, None), "空输入返回 ({}, None)")
per3, peak3 = M.aggregate_gpu_utilization([("garbage", 5.0)])
check(peak3 is None, "无法解析的实例名不产生读数")

per4, _p = M.aggregate_gpu_utilization(
    [(inst(1, "3D"), 2.0), (inst(2, "3D", AD2), 7.0)])
check(len(per4) == 2, "不同适配器分开统计（避免把虚拟显示适配器混进来）")

check(M.adapter_of(inst(9, "3D")) == AD.lower(), "adapter_of 归一化大小写")
check(M.adapter_of("bad") is None, "adapter_of 对非法名返回 None")

# ======================================================================
print("\n[2] ACPI 热区温度换算")
zones = [
    (r"\_TZ.TZ00", 301.0, 0),
    (r"\_TZ.TZ01", 318.4, 0),        # 最高 → 选中，318.4K = 45.25°C
    (r"\_TZ.TZ02", 0.0, 0),          # 未初始化 → 必须丢弃
    (r"\_TZ.TZ03", 350.0, 0xC0000BC6),   # 状态非 0 → 必须丢弃
]
t, zone = M.thermal_zones_to_celsius(zones)
show("选中热区", zone)
show("温度", round(t, 3) if t is not None else None)
check(t is not None and abs(t - 45.25) < 1e-6, "取最高有效热区并换算为摄氏度", f"得到 {t}")
check(zone == "_TZ.TZ01", "返回的热区名去掉了反斜杠前缀")
check(M.thermal_zones_to_celsius([]) == (None, ""), "无热区时返回 (None, '')")
check(M.thermal_zones_to_celsius([(r"\_TZ.TZ00", 0.0, 0)])[0] is None,
      "全部无效时不返回 0K 这种假数据")

# ======================================================================
print("\n[3] nvidia-smi 输出解析")
line = "NVIDIA GeForce RTX 3060, 12, 2048, 12288, 45"
d = M.parse_nvidia_smi(line)
show("解析结果", d)
check(d.get("util") == 12.0 and d.get("mem_used_mb") == 2048.0
      and d.get("mem_total_mb") == 12288.0 and d.get("temp") == 45.0,
      "标准 CSV 行全部字段解析正确")
check(d.get("name") == "NVIDIA GeForce RTX 3060", "显卡名解析正确")
check(M.parse_nvidia_smi("") == {}, "空输出返回空 dict")
check(M.parse_nvidia_smi("nvidia-smi has failed\nbecause it couldn't communicate")
      == {}, "错误文本不产生假读数")
check(M.parse_nvidia_smi("RTX 4090, [N/A], 100, 24564, 30").get("util") is None,
      "非数值字段（[N/A]）不让整行解析崩溃")

# ======================================================================
print("\n[4] LibreHardwareMonitor 传感器挑选")
lhm = [
    {"Name": "GPU Core", "SensorType": "Temperature", "Value": 52.0},
    {"Name": "CPU Package", "SensorType": "Temperature", "Value": 47.5},
    {"Name": "Core #1", "SensorType": "Temperature", "Value": 44.0},
    {"Name": "Core Average", "SensorType": "Temperature", "Value": 43.0},
    {"Name": "GPU Fan", "SensorType": "Fan", "Value": 1200.0},
    {"Name": "CPU Total", "SensorType": "Load", "Value": 12.0},
]
check(M.pick_cpu_temp_from_lhm(lhm) == 47.5, "CPU 温度优先取 CPU Package")
check(M.pick_gpu_temp_from_lhm(lhm) == 52.0, "GPU 温度取 GPU Core")
check(M.pick_cpu_temp_from_lhm([{"Name": "Core Max", "SensorType": "Temperature",
                                 "Value": 60.0}]) == 60.0, "没有 Package 时退化到 Core Max")
check(M.pick_cpu_temp_from_lhm([{"Name": "Fan", "SensorType": "Fan", "Value": 9.0}])
      is None, "非温度类型不会被误当温度")
check(M.pick_cpu_temp_from_lhm([]) is None, "空列表返回 None")

# ======================================================================
print("\n[5] 显卡信息：注册表读取 + 虚拟适配器过滤")
s = M.MetricsSampler()
ad = s.adapters
show("识别到的物理显卡", [a["name"] for a in ad])
check(isinstance(ad, list), "返回列表")
check(all(a["name"] for a in ad), "显卡名非空")
check(not any("microsoft remote display" in a["name"].lower() for a in ad),
      "「Microsoft Remote Display Adapter」等虚拟适配器已被过滤")
check(len({a["name"].lower() for a in ad}) == len(ad), "同型号不会重复列出")
show("能力探测", s.info())

# ======================================================================
print("\n[6] 真实采样（本机 PDH）")
raw = s.sample()                       # 第 1 次：与预热间隔 <1s，利用率应为 None
show("第 1 次 gpu_util（间隔过短）", raw["gpu_util"])
check(raw["gpu_util"] is None,
      "两次采集间隔 <1 秒时不报利用率（避免报出无意义的抖动值）")
check(raw["cpu_pct"] is not None, "CPU 使用率有读数")
check(raw["mem_pct"] is not None and 0 <= raw["mem_pct"] <= 100, "内存占用率在 0~100")
check(raw["mem_total_gb"] and raw["mem_total_gb"] > 1, "内存总量合理")

time.sleep(1.3)
t0 = time.perf_counter()
m = s.sample()
cost = (time.perf_counter() - t0) * 1000
show("第 2 次 gpu_util", m["gpu_util"])
show("采样耗时(ms)", round(cost, 1))
show("显存 已用/独立/共享 (GB)",
     (None if m["gpu_mem_used_gb"] is None else round(m["gpu_mem_used_gb"], 3),
      None if m["gpu_mem_dedicated_gb"] is None else round(m["gpu_mem_dedicated_gb"], 3),
      None if m["gpu_mem_shared_gb"] is None else round(m["gpu_mem_shared_gb"], 3)))
show("GPU 名", m["gpu_name"])
show("CPU 温度", (None if m["cpu_temp_c"] is None else round(m["cpu_temp_c"], 1),
                  m["cpu_temp_src"]))
show("GPU 温度", (m["gpu_temp_c"], m["gpu_temp_src"]))
check(m["gpu_util"] is not None, "间隔足够时 GPU 利用率有读数")
check(m["gpu_util"] is None or 0 <= m["gpu_util"] <= 100, "GPU 利用率在 0~100")
check(cost < 150, "单次采样耗时 <150ms（PDH 直连，不起子进程）", f"{cost:.1f}ms")
check(m["gpu_engines"] and all(k[1] for k in m["gpu_engines"]),
      "引擎分组键都带非空引擎类型")
check(m["gpu_mem_used_gb"] is None or m["gpu_mem_used_gb"] > 0, "显存占用有读数")
if m["gpu_mem_dedicated_gb"] is not None and m["gpu_mem_shared_gb"] is not None:
    check(m["gpu_mem_used_gb"] >= max(m["gpu_mem_dedicated_gb"], m["gpu_mem_shared_gb"]) - 1e-6,
          "已用显存 ≥ 单项（独立/共享）")
check(m["cpu_temp_c"] is None or 0 < m["cpu_temp_c"] < 120, "CPU 温度在合理区间")
if m["cpu_temp_c"] is not None:
    check(bool(m["cpu_temp_src"]), "温度始终带来源标注（不冒充 CPU 核心温度）")
check(m["gpu_temp_c"] is None or 0 < m["gpu_temp_c"] < 120, "GPU 温度要么合理要么缺失")

# ======================================================================
print("\n[7] 防回归：显存三桶必须互相独立")
src_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "metrics.py")
src = open(src_path, encoding="utf-8").read()
# 曾经写成 ded = sha = com = {}，三个名字绑定同一个 dict，
# 导致「独立显存 / 共享显存 / 合计」三项永远显示同一个数。
# 只扫代码行、跳过注释行，否则解释这个坑的注释本身会被断言命中。
code_lines = [ln.split("#", 1)[0] for ln in src.splitlines()]
code_only = "\n".join(code_lines)
check("ded = sha = com = {}" not in code_only,
      "不存在 ded = sha = com = {} 这种字典别名写法（曾导致三项数值恒等）")
check("ded, sha, com = {}, {}, {}" in code_only, "三个显存字典各自独立创建")

ded_only = round(m["gpu_mem_dedicated_gb"] or 0.0, 6)
sha_only = round(m["gpu_mem_shared_gb"] or 0.0, 6)
com_only = round(m["gpu_mem_used_gb"] or 0.0, 6)
if (ded_only, sha_only, com_only) != (0.0, 0.0, 0.0):
    check(len({ded_only, sha_only, com_only}) > 1,
          "本机三项显存读数不全相等（说明三桶确实分别取值）",
          f"{ded_only}/{sha_only}/{com_only}")
else:
    print("      · 本机显存读数全为 0，跳过三桶差异断言")

# ======================================================================
print("\n[8] 反复采样稳定性（20 次，模拟状态栏长期刷新）")
costs = []
bad = 0
for _ in range(20):
    t0 = time.perf_counter()
    mm = s.sample(allow_subprocess=False)
    costs.append((time.perf_counter() - t0) * 1000)
    if mm["cpu_pct"] is None or mm["mem_pct"] is None:
        bad += 1
    time.sleep(0.05)
show("采样耗时 min/中位/max (ms)",
     (round(min(costs), 2), round(statistics.median(costs), 2), round(max(costs), 2)))
check(bad == 0, "20 次采样全部拿到 CPU/内存读数")
check(statistics.median(costs) < 60, "稳态采样中位耗时 <60ms")
check(max(costs) < 400, "无单次异常尖峰（<400ms）", f"max={max(costs):.1f}ms")

# ======================================================================
print("\n[9] 数据源说明文案")
deadline = time.time() + 20                 # 等后台的 LHM 探测线程给出确定结论
while s._lhm_ns == "" and time.time() < deadline:
    time.sleep(0.25)
show("LHM 命名空间探测结果", repr(s._lhm_ns))
lines = s.source_summary()
for x in lines:
    print(f"      - {x}")
check(len(lines) >= 4, "四个指标都有来源说明")
check(any("ACPI" in x or "LibreHardwareMonitor" in x for x in lines)
      or s.info()["thermal_zone"] is False, "CPU 温度说明了实际来源")
check(any("不可用" in x for x in lines) or s.lhm_active,
      "拿不到的数据源如实说明不可用，而非编造数值")
# 回归：_lhm_ns 的 「"-" = 已确认没有」是 truthy 的，曾被直接当判断条件，
# 导致没有 LHM 的机器上界面谎称「CPU 温度来源：LibreHardwareMonitor（准确）」。
if s._lhm_ns == "-":
    check(not s.lhm_active, "确认无 LHM 时 lhm_active 为 False")
    check(not any("LibreHardwareMonitor WMI" in x for x in lines),
          "没有 LibreHardwareMonitor 时不谎称温度来源是它", str(lines))
    check(s.info()["lhm_ns"] == "", "info() 对外只暴露真实存在的 LHM 命名空间")

print("\n[10] 关闭查询")
s.close()
s.close()                                  # 重复关闭不能抛
check(True, "重复 close() 不抛异常")

print("\n" + "=" * 64)
print(f"通过 {PASS} 项，失败 {FAIL} 项")
if FAILED:
    for x in FAILED:
        print(f"  FAILED: {x}")
print("ALL_CHECKS_PASSED" if FAIL == 0 else "CHECKS_FAILED")
sys.exit(0 if FAIL == 0 else 1)
