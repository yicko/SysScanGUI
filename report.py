# -*- coding: utf-8 -*-
"""将 scan.py 产出的 JSON 渲染为结构化 HTML 安全扫描报告。"""

from __future__ import annotations

import argparse
import html
import json
import os
from datetime import datetime

SEV_ORDER = ["严重", "高危", "中危", "低危", "提示", "正常"]

CSS = """
:root{
  --bg:#f6f7fb; --card:#ffffff; --line:#e5e8ef; --text:#1f2430; --muted:#6b7280;
  --brand:#2f6feb; --brand-soft:#eaf1ff;
  --s0:#7f1d1d; --s0b:#fee2e2; --s1:#b42318; --s1b:#ffe4e2;
  --s2:#b54708; --s2b:#fef0c7; --s3:#475467; --s3b:#eef1f5; --ok:#027a48; --okb:#e3f5ec;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
 font-family:"Segoe UI","Microsoft YaHei",system-ui,-apple-system,sans-serif;font-size:14px;line-height:1.6}
.wrap{max-width:1440px;margin:0 auto;padding:28px 24px 64px}
h1{font-size:24px;margin:0 0 4px}
h2{font-size:17px;margin:28px 0 12px}
.sub{color:var(--muted);font-size:13px}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:18px 20px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:18px 0}
.kpi{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:14px 16px}
.kpi .n{font-size:26px;font-weight:650;letter-spacing:-.5px}
.kpi .l{color:var(--muted);font-size:12px;margin-top:2px}
.bars{display:grid;gap:8px;margin-top:6px}
.bar{display:flex;align-items:center;gap:10px;font-size:13px}
.bar .nm{width:52px;color:var(--muted)}
.bar .tr{flex:1;background:#eef1f5;border-radius:6px;height:16px;overflow:hidden}
.bar .fl{height:100%;border-radius:6px}
.bar .ct{width:44px;text-align:right;font-variant-numeric:tabular-nums}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{padding:8px 10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}
th{background:#fafbfd;color:var(--muted);font-weight:600;font-size:12px;position:sticky;top:0;z-index:2}
tr:hover td{background:#fbfcfe}
td.mono,td.path{font-family:Consolas,"Cascadia Mono",monospace;font-size:12px;color:#374151;word-break:break-all}
.tag{display:inline-block;padding:1px 8px;border-radius:999px;font-size:12px;font-weight:600;white-space:nowrap}
.t0{color:var(--s0);background:var(--s0b)} .t1{color:var(--s1);background:var(--s1b)}
.t2{color:var(--s2);background:var(--s2b)} .t3{color:var(--s3);background:var(--s3b)}
.tok{color:var(--ok);background:var(--okb)}
.tabs{display:flex;gap:6px;flex-wrap:wrap;margin:22px 0 0;border-bottom:1px solid var(--line)}
.tab{padding:9px 16px;cursor:pointer;border:1px solid transparent;border-bottom:none;
 border-radius:8px 8px 0 0;color:var(--muted);font-size:13px;background:transparent}
.tab.on{background:var(--card);border-color:var(--line);color:var(--brand);font-weight:600}
.pane{display:none;background:var(--card);border:1px solid var(--line);border-top:none;
 border-radius:0 0 12px 12px;padding:0}
.pane.on{display:block}
.tools{display:flex;gap:10px;flex-wrap:wrap;align-items:center;padding:12px 16px;border-bottom:1px solid var(--line)}
input[type=search],select{padding:6px 10px;border:1px solid var(--line);border-radius:8px;
 font-size:13px;background:#fff;color:var(--text);outline:none}
input[type=search]{min-width:260px}
input[type=search]:focus,select:focus{border-color:var(--brand)}
.scroll{max-height:70vh;overflow:auto}
.empty{padding:24px;color:var(--muted);text-align:center}
.finding{border-bottom:1px solid var(--line);padding:14px 18px}
.finding:last-child{border-bottom:none}
.finding .hd{display:flex;gap:10px;align-items:center;flex-wrap:wrap}
.finding .ttl{font-weight:600}
.finding .meta{color:var(--muted);font-size:12px;margin-top:4px}
.finding .dtl{margin-top:6px;color:#374151}
.finding .adv{margin-top:6px;font-size:12.5px;color:var(--brand);background:var(--brand-soft);
 padding:6px 10px;border-radius:8px;display:inline-block}
.mono{font-family:Consolas,monospace;font-size:12px}
.foot{margin-top:26px;color:var(--muted);font-size:12px;text-align:center}
"""


def sev_class(s: str) -> str:
    return {"严重": "t0", "高危": "t1", "中危": "t2", "低危": "t3",
            "提示": "t3", "正常": "tok"}.get(s, "t3")


def e(v) -> str:
    return html.escape("" if v is None else str(v))


def build_html(data: dict) -> str:
    meta, summary = data["meta"], data["summary"]
    risk = summary["risk"]
    maxr = max(list(risk.values()) + [1])
    colors = {"严重": "#7f1d1d", "高危": "#d92d20", "中危": "#f79009", "低危": "#98a2b3", "提示": "#98a2b3"}

    bars = "".join(
        f'<div class="bar"><span class="nm">{k}</span>'
        f'<span class="tr"><span class="fl" style="width:{risk[k]/maxr*100:.1f}%;'
        f'background:{colors[k]}"></span></span>'
        f'<span class="ct">{risk[k]}</span></div>' for k in SEV_ORDER[:5])

    kpis = [("进程总数", summary["process_count"]), ("窗口应用", summary["app_count"]),
            ("服务总数", summary["service_count"]), ("运行中服务", summary["service_running"]),
            ("网络连接", summary["conn_count"]), ("已建立连接", summary["conn_established"]),
            ("监听端口", summary["conn_listen"]), ("持久化项", summary["persist_count"]),
            ("风险项", summary["risk_total"])]

    # ---- findings ----
    f_html = []
    for f in data["findings"]:
        f_html.append(
            f'<div class="finding" data-sev="{e(f["severity"])}" data-cat="{e(f["category"])}">'
            f'<div class="hd"><span class="tag {sev_class(f["severity"])}">{e(f["severity"])}</span>'
            f'<span class="ttl">{e(f["title"])}</span>'
            f'<span class="tag t3">{e(f["category"])} · {e(f["target_type"])}</span></div>'
            f'<div class="meta">{e(f["target"])}</div>'
            f'<div class="dtl">{e(f["detail"])}</div>'
            f'<div class="adv">建议：{e(f["advice"])}</div></div>')
    findings_html = "".join(f_html) or '<div class="empty">未发现风险项</div>'

    # ---- processes ----
    rows = []
    for p in data["processes"]:
        rows.append(
            f'<tr data-sev="{e(p["risk"])}">'
            f'<td class="mono">{p["pid"]}</td>'
            f'<td>{e(p["name"])}</td>'
            f'<td class="path">{e(p["exe"])}</td>'
            f'<td class="path">{e((p["cmdline"] or "")[:220])}</td>'
            f'<td>{e(p["user"])}</td>'
            f'<td class="mono">{e(p["cpu"])}</td>'
            f'<td class="mono">{e(p["mem_mb"])}</td>'
            f'<td>{e(p["started"])}</td>'
            f'<td>{e(p["sig_status"])}</td>'
            f'<td><span class="tag {sev_class(p["risk"])}">{e(p["risk"])}</span>'
            + "".join(f'<div style="font-size:12px;color:#6b7280">{e(r["text"])}</div>'
                      for r in p.get("reasons", []))
            + "</td></tr>")
    proc_html = "".join(rows) or '<div class="empty">无数据</div>'

    # ---- services ----
    rows = []
    for s in data["services"]:
        rows.append(
            f'<tr data-sev="{e(s["risk"])}">'
            f'<td>{e(s["name"])}</td>'
            f'<td>{e(s["display"])}</td>'
            f'<td>{e(s["status"])}</td>'
            f'<td>{e(s["start_value"] or s["start_type"])}</td>'
            f'<td>{e(s["user"])}</td>'
            f'<td class="mono">{e(s["pid"])}</td>'
            f'<td class="path">{e(s["real_file"] or s["binpath"])}</td>'
            f'<td>{e(s["sig_status"])}</td>'
            f'<td><span class="tag {sev_class(s["risk"])}">{e(s["risk"])}</span>'
            + "".join(f'<div style="font-size:12px;color:#6b7280">{e(r["text"])}</div>'
                      for r in s.get("reasons", []))
            + "</td></tr>")
    svc_html = "".join(rows) or '<div class="empty">无数据</div>'

    # ---- connections ----
    rows = []
    for c in data["connections"]:
        flag = "公网" if c.get("public") else ("内网" if c.get("raddr") else "本地")
        rows.append(
            f'<tr data-sev="{e(c["risk"])}">'
            f'<td>{e(c["proto"])}</td>'
            f'<td class="mono">{e(c["laddr"])}</td>'
            f'<td class="mono">{e(c["raddr"])}</td>'
            f'<td>{e(c["status"])}</td>'
            f'<td>{flag}</td>'
            f'<td class="mono">{e(c["pid"])}</td>'
            f'<td>{e(c["proc"])}</td>'
            f'<td class="path">{e(c.get("proc_path"))}</td>'
            f'<td><span class="tag {sev_class(c["risk"])}">{e(c["risk"])}</span>'
            + "".join(f'<div style="font-size:12px;color:#6b7280">{e(r["text"])}</div>'
                      for r in c.get("reasons", []))
            + "</td></tr>")
    conn_html = "".join(rows) or '<div class="empty">无数据</div>'

    # ---- persistence ----
    rows = []
    for it in data["persistence"]:
        trig = "、".join(it.get("triggers") or [])
        rows.append(
            f'<tr data-sev="{e(it["risk"])}">'
            f'<td>{e(it["type"])}</td>'
            f'<td>{e(it["name"])}</td>'
            f'<td class="path">{e(it["command"])} {e(it.get("args"))}</td>'
            f'<td>{e(it.get("author") or it.get("user"))}</td>'
            f'<td>{e(trig)}</td>'
            f'<td>{"是" if it.get("enabled") else "否"}</td>'
            f'<td>{e(it.get("sig_status"))}</td>'
            f'<td><span class="tag {sev_class(it["risk"])}">{e(it["risk"])}</span>'
            + "".join(f'<div style="font-size:12px;color:#6b7280">{e(r["text"])}</div>'
                      for r in it.get("reasons", []))
            + "</td></tr>")
    pers_html = "".join(rows) or '<div class="empty">无数据</div>'

    # ---- apps ----
    rows = []
    for p in data["processes"]:
        if p.get("windows"):
            rows.append(
                f'<tr><td class="mono">{p["pid"]}</td><td>{e(p["name"])}</td>'
                f'<td>{e(" | ".join(p["windows"]))}</td>'
                f'<td class="path">{e(p["exe"])}</td>'
                f'<td class="mono">{e(p["cpu"])}</td><td class="mono">{e(p["mem_mb"])}</td>'
                f'<td><span class="tag {sev_class(p["risk"])}">{e(p["risk"])}</span></td></tr>')
    app_html = "".join(rows) or '<div class="empty">未检测到带窗口的应用程序</div>'

    JS = """
    document.querySelectorAll('.tab').forEach(t=>{
      t.onclick=()=>{
        document.querySelectorAll('.tab').forEach(x=>x.classList.remove('on'));
        document.querySelectorAll('.pane').forEach(x=>x.classList.remove('on'));
        t.classList.add('on');
        document.getElementById(t.dataset.pane).classList.add('on');
      };
    });
    function bindTools(paneId){
      const pane=document.getElementById(paneId);
      const q=pane.querySelector('input[type=search]');
      const sel=pane.querySelector('select');
      const rows=[...pane.querySelectorAll('tbody tr, .finding')];
      function run(){
        const kw=(q?q.value:'').toLowerCase();
        const sev=sel?sel.value:'';
        rows.forEach(r=>{
          const okKw=!kw||r.textContent.toLowerCase().includes(kw);
          const okSev=!sev||r.dataset.sev===sev;
          r.style.display=(okKw&&okSev)?'':'none';
        });
      }
      if(q)q.oninput=run; if(sel)sel.onchange=run;
    }
    ['p-findings','p-proc','p-svc','p-conn','p-pers'].forEach(bindTools);
    const gq=document.getElementById('gsearch');
    if(gq){gq.oninput=()=>{
      const kw=gq.value.toLowerCase();
      document.querySelectorAll('.finding').forEach(r=>{
        r.style.display=(!kw||r.textContent.toLowerCase().includes(kw))?'':'none';});
    };}
    """

    return f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>系统进程与服务安全扫描报告 · {e(meta['host'])}</title>
<style>{CSS}</style></head><body><div class="wrap">
<h1>系统进程与服务安全扫描报告</h1>
<div class="sub">主机 <b>{e(meta['host'])}</b> · {e(meta['os'])} · 账户 {e(meta['user'])}
{'（管理员权限）' if meta.get('admin') else '（非管理员权限，部分信息受限）'}
· 开机时间 {e(meta['boot_time'])} · 扫描于 {e(meta['scan_time'])} · 耗时 {e(meta['duration'])}s</div>

<div class="grid">{''.join(f'<div class="kpi"><div class="n">{v}</div><div class="l">{k}</div></div>' for k, v in kpis)}</div>

<div class="card">
  <b>风险分布</b>
  <div class="bars">{bars}</div>
  <div class="sub" style="margin-top:10px">CPU {e(meta['cpu_percent'])}% ·
  物理内存 {e(meta['mem_total_gb'])} GB（已用 {e(meta['mem_used_pct'])}%） ·
  逻辑核心 {e(meta['cpu_logical'])} · 数字签名校验 {'已启用' if meta.get('signature_checked') else '已跳过'}</div>
</div>

<div class="tabs">
  <div class="tab on" data-pane="p-findings">风险清单 ({summary['risk_total']})</div>
  <div class="tab" data-pane="p-proc">进程 ({summary['process_count']})</div>
  <div class="tab" data-pane="p-svc">服务 ({summary['service_count']})</div>
  <div class="tab" data-pane="p-conn">网络连接 ({summary['conn_count']})</div>
  <div class="tab" data-pane="p-pers">持久化 ({summary['persist_count']})</div>
  <div class="tab" data-pane="p-app">应用程序 ({summary['app_count']})</div>
</div>

<div class="pane on" id="p-findings">
  <div class="tools">
    <input id="gsearch" type="search" placeholder="搜索风险项关键词…">
    <select><option value="">全部等级</option>
    <option value="严重">严重</option><option value="高危">高危</option>
    <option value="中危">中危</option><option value="低危">低危</option></select>
  </div>
  <div class="scroll">{findings_html}</div>
</div>

<div class="pane" id="p-proc">
  <div class="tools">
    <input type="search" placeholder="搜索进程名 / 路径 / 命令行 / 用户…">
    <select><option value="">全部</option><option value="严重">仅严重</option>
    <option value="高危">仅高危</option><option value="中危">仅中危</option>
    <option value="低危">仅低危</option><option value="正常">仅正常</option></select>
  </div>
  <div class="scroll"><table><thead><tr>
    <th>PID</th><th>进程名</th><th>映像路径</th><th>命令行</th><th>运行身份</th>
    <th>CPU%</th><th>内存MB</th><th>启动时间</th><th>签名</th><th>风险</th>
  </tr></thead><tbody>{proc_html}</tbody></table></div>
</div>

<div class="pane" id="p-svc">
  <div class="tools">
    <input type="search" placeholder="搜索服务名 / 路径…">
    <select><option value="">全部</option><option value="严重">仅严重</option>
    <option value="高危">仅高危</option><option value="中危">仅中危</option>
    <option value="低危">仅低危</option><option value="正常">仅正常</option></select>
  </div>
  <div class="scroll"><table><thead><tr>
    <th>服务名</th><th>显示名</th><th>状态</th><th>启动类型</th><th>登录身份</th>
    <th>PID</th><th>映像 / DLL</th><th>签名</th><th>风险</th>
  </tr></thead><tbody>{svc_html}</tbody></table></div>
</div>

<div class="pane" id="p-conn">
  <div class="tools">
    <input type="search" placeholder="搜索 IP / 端口 / 进程…">
    <select><option value="">全部</option><option value="高危">仅高危</option>
    <option value="中危">仅中危</option><option value="低危">仅低危</option>
    <option value="正常">仅正常</option></select>
  </div>
  <div class="scroll"><table><thead><tr>
    <th>协议</th><th>本地地址</th><th>远端地址</th><th>状态</th><th>范围</th>
    <th>PID</th><th>进程</th><th>进程路径</th><th>风险</th>
  </tr></thead><tbody>{conn_html}</tbody></table></div>
</div>

<div class="pane" id="p-pers">
  <div class="tools">
    <input type="search" placeholder="搜索任务名 / 命令…">
    <select><option value="">全部</option><option value="高危">仅高危</option>
    <option value="中危">仅中危</option><option value="低危">仅低危</option>
    <option value="正常">仅正常</option></select>
  </div>
  <div class="scroll"><table><thead><tr>
    <th>类型</th><th>名称</th><th>命令</th><th>作者 / 账户</th><th>触发器</th>
    <th>启用</th><th>签名</th><th>风险</th>
  </tr></thead><tbody>{pers_html}</tbody></table></div>
</div>

<div class="pane" id="p-app">
  <div class="tools"><input type="search" placeholder="搜索应用窗口…"></div>
  <div class="scroll"><table><thead><tr>
    <th>PID</th><th>进程</th><th>窗口标题</th><th>映像路径</th>
    <th>CPU%</th><th>内存MB</th><th>风险</th>
  </tr></thead><tbody>{app_html}</tbody></table></div>
</div>

<div class="foot">报告由本地扫描脚本生成，数据仅在本机处理 · 生成时间 {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</div>
</div><script>{JS}</script></body></html>"""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--json", default="scan_result.json")
    ap.add_argument("--out", default="report.html")
    args = ap.parse_args()
    with open(args.json, "r", encoding="utf-8") as f:
        data = json.load(f)
    html_str = build_html(data)
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_str)
    print(f"HTML 报告：{os.path.abspath(args.out)}")


if __name__ == "__main__":
    main()
