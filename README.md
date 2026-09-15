# SysScanGUI · Windows 系统进程与服务安全扫描器

![Platform](https://img.shields.io/badge/platform-Windows%2010%20%2F%2011-0078D6)
![Python](https://img.shields.io/badge/python-3.9%2B-3776AB)
![UI](https://img.shields.io/badge/UI-PySide6%20(Qt%206)-41CD52)
![License](https://img.shields.io/badge/license-MIT-green)
[![Release](https://img.shields.io/github/v/release/yicko/SysScanGUI?display_name=tag&sort=semver)](https://github.com/yicko/SysScanGUI/releases/latest)
[![Release Build](https://github.com/yicko/SysScanGUI/actions/workflows/release.yml/badge.svg)](https://github.com/yicko/SysScanGUI/actions/workflows/release.yml)

一个面向 Windows 的**本机安全自检工具**：完整枚举进程、服务、网络连接与持久化项，用一套可解释的规则给出风险等级，并允许你在同一个界面里直接完成处置（结束进程、停用服务、删除启动项……）以及事后恢复。

扫描结果既可以导出为结构化 JSON，也可以渲染成一份自带搜索与筛选的单文件 HTML 报告。**所有数据都只在本机内存与本地磁盘中流转，程序不联网、不上传任何内容。**

---

## 目录

- [项目简介](#项目简介)
- [功能特性](#功能特性)
- [工作原理](#工作原理)
- [风险等级](#风险等级)
- [下载](#下载)
  - [代码签名与来源验证](#代码签名与来源验证)
- [环境要求](#环境要求)
- [安装](#安装)
- [使用方法](#使用方法)
  - [图形界面](#1-图形界面推荐)
  - [命令行扫描](#2-命令行扫描)
  - [打包为单文件可执行程序](#3-打包为单文件可执行程序可选)
  - [运行回归测试](#4-运行回归测试)
- [发布新版本](#发布新版本维护者)
  - [启用代码签名](#启用代码签名维护者)
- [目录结构](#目录结构)
- [设计取舍](#设计取舍)
- [已知局限](#已知局限)
- [安全与隐私](#安全与隐私)
- [免责声明](#免责声明)
- [贡献](#贡献)
- [许可证](#许可证)

---

## 项目简介

Windows 自带的任务管理器只告诉你"有什么在跑"，却很少回答"这些东西是不是该在这儿跑"。SysScanGUI 想补上这一环：

它把散落在任务管理器、服务管理器、`netstat`、计划任务程序、注册表里的信息汇总到一张表里，然后回答三个问题——

1. **这是什么？** 路径、数字签名与签发者、运行身份、父进程、命令行、启动时间。
2. **它正常吗？** 是否跑在用户可写目录、是否伪装成系统进程、是否由脚本解释器承载、是否监听高危端口、是否指向一个已经不存在的文件……
3. **我能做什么？** 直接终止 / 停用 / 删除，并留下操作历史以便恢复。

规则命中时，程序会同时给出**判定依据**和**建议动作**，而不是只丢一个红点。设计上刻意避免"吓人的空警报"——拿不到的数据就显示 `—`，不会用绿色或数字假装一切正常。

## 功能特性

### 采集

- **进程**：完整命令行、映像路径、运行身份、父进程、启动时间、线程/句柄数、CPU 与内存占用、所属可见窗口标题。
- **服务**：除 `psutil` 之外还回读注册表，覆盖驱动服务等 `psutil` 不列出的项；采集 `ImagePath`、`ServiceDll`、启动类型、延迟启动标志、登录身份。
- **网络连接**：TCP/UDP、监听与已建立、本地与远端地址、按 RFC 判定公网/内网。
- **持久化**：计划任务（直接解析 `System32\Tasks` 下的任务 XML）、注册表 `Run` / `RunOnce` 共 5 个位置、用户与全局启动文件夹。

### 风险分析

- **路径可信度分级**：系统目录 / Program Files / 用户 AppData / 临时下载等高危目录，按路径分段精确匹配（避免 `DesktopExtension.exe` 这类子串误判）。
- **数字签名校验**：批量调用 Authenticode，记录签名状态与签发者；自动分批以规避命令行长度限制。签名有效且签发者为 Microsoft 的进程会被正确放行。
- **系统进程名伪装检测**：`svchost.exe`、`lsass.exe` 之类的名字出现在非系统目录 → 判定为严重。
- **命令行特征库**：20 余条模式覆盖 `-EncodedCommand`、`certutil -decode`、`bitsadmin /transfer`、`regsvr32` 远程脚本对象、卷影副本删除等 LOLBAS 滥用与凭据窃取工具特征。
- **服务专项检查**：映像文件缺失、`ImagePath` 未加引号（路径劫持）、映像位于用户可写目录、由 `cmd`/`powershell`/`mshta` 等解释器承载、未签名却以 SYSTEM 运行、未知来源的开机自启动服务。
- **网络专项检查**：高危端口（反弹 Shell / 远控 / VNC / Tor 等）全网监听、系统共享端口暴露面、非常见端口监听、按进程聚合的公网外连、无法关联到存活进程的连接。
- **资源与权限异常**：CPU/内存占用畸高、孤儿进程、以 SYSTEM 权限运行非系统目录程序。

### 图形界面

- **六个视图**：概览 / 进程 / 服务 / 网络连接 / 持久化 / 风险清单，均有独立的关键字搜索与风险等级过滤。
- **实时硬件指标面板**：CPU 使用率、内存占用、GPU 使用率、显存占用、CPU 温度、GPU 温度，6 张卡片每 3 秒刷新。
- **点击列标题排序**：数值列按数值比大小（不是按文本），支持中文自然序；再点一次切换升降序，箭头指示当前方向。
- **分层自动刷新**：概览指标常开；连接列表默认关闭、可选 8 秒后台轻刷；处置动作完成后自动核实结果，**不做全量定时重扫**。
- **处置与恢复**：右键即可结束进程、停止/禁用服务、禁用/删除计划任务、删除启动项；每一步都先备份原始值并写入操作历史，可一键恢复。
- **导出**：JSON / HTML / CSV。
- **提权运行**：一键以管理员身份重启（服务管理与部分进程信息受限时才需要）。
- **单实例保护**：同一时间只允许一个实例，避免多个实例互相覆盖扫描结果或重复执行处置动作。
- **自身进程识别**：单文件版运行时会出现「引导器 + 应用本体」两个同名进程，程序会把它们标注为
  「本程序自身进程」并跳过风险判定，不会把自己的进程报成「未签名程序运行于非标准目录」。
- **系统事件日志查看与分析**：独立「系统日志」标签页，覆盖 Application / System / Security 等常用通道；
  支持按时间范围、级别（信息/警告/错误/严重）、事件 ID、来源与关键字筛选并分页浏览，可展开查看单条
  详情；统计各级别数量与占比、按事件 ID / 来源 / 时间段聚合，识别高频错误与异常趋势并以柱状图呈现；
  读取在后台线程进行，界面不阻塞。

### 报告输出

- **JSON**：完整结构化数据，便于二次加工。
- **HTML**：单文件、零外部依赖，内嵌标签页、搜索框与等级过滤，可直接发给别人或归档。

### 系统事件日志

新增的「系统日志」模块采用与扫描器一致的分层结构，且完全独立——不读写 `scan_result.json`、不参与既有五个数据页的新增/编辑/导出，因此不会影响现有模块：

- **数据读取层（`eventlog_reader.py`）**：用 `ctypes` 直接调用 `wevtapi.dll`（`EvtQuery` / `EvtNext` / `EvtRender`），零额外依赖、零子进程（与 `metrics.py` 走 PDH 的思路一致）。级别 / 时间 / 事件 ID / 来源 通过 XPath 在服务端筛选（快、省内存），关键字等自由文本在已取回数据上做客户端即时筛选。读取在后台线程分批进行（增量加载），不会卡住界面；另设整体超时上限与取消开关。
- **分析统计层（`eventlog_stats.py`）**：纯函数，对取回的记录做级别数量与占比、按事件 ID / 来源 / 时间段的聚合，识别高频错误与异常趋势。
- **界面展示层（`eventlog_widget.py`）**：筛选控件、分页表格、详情对话框、QPainter 柱状图（不引入 QtCharts，保持打包精简）、刷新与导出（CSV / JSON）。

异常场景都有明确提示：读取 Security 通道需要「管理审核与安全日志」特权（提示以管理员重新运行）、日志服务不可用、日志为空、读取超时（整体超时后停止并提示缩小范围）。

## 工作原理

```
        采集层 (scan.py)                    规则层 (scan.py)              输出层
 ┌───────────────────────────┐    ┌──────────────────────────┐   ┌──────────────────┐
 │ 进程  · 服务 · 网络连接    │ →  │ 路径可信度 / 数字签名     │ → │ JSON  结构化数据  │
 │ 计划任务 · 注册表启动项    │    │ 命令行特征 / 资源占用     │   │ HTML  可视化报告  │
 │ 可见窗口（应用程序）       │    │ 权限与父子关系 / 暴露面   │   │ GUI   交互式界面  │
 └───────────────────────────┘    └──────────────────────────┘   └──────────────────┘
                                              ↓
                                      每条风险都附带
                                      「判定依据 + 建议动作」
```

`gui.py` 与 `scan.py`、`report.py` 共用同一份 `scan_result.json`，结构完全一致——命令行生成的报告可以直接拖进界面继续分析，界面里的处置结果也能导出成同样的 JSON。

## 风险等级

| 等级 | 含义 | 典型场景 |
|:---:|---|---|
| **严重** | 高度确信的恶意特征，应立即处置 | 系统进程名伪装（`svchost.exe` 跑在 `Downloads` 里） |
| **高危** | 明显偏离正常基线，需人工确认 | 无签名程序运行于临时目录、服务映像缺失、高危端口全网监听 |
| **中危** | 可疑但存在合理解释，建议核查 | 未签名程序位于非标准目录、未知来源的开机自启动服务 |
| **低危** | 暴露面或异常现象，通常是配置问题 | 系统共享端口对外开放、非常见端口监听、孤儿进程 |
| **提示** | 仅作记录 | — |
| **正常** | 未命中任何规则 | — |

## 环境要求

- **操作系统**：Windows 10 / 11（核心功能依赖 `winreg`、`pdh.dll`、`ShellExecuteExW` 等 Windows 原生能力）
- **Python**：3.9 及以上
- **依赖**：见 [`requirements.txt`](requirements.txt) —— `psutil` 与 `PySide6-Essentials`
- **权限**：普通权限即可运行；以管理员身份运行可获得更完整的服务管理与进程信息

> 单实例守卫（`single_instance.py`）是本项目唯一做了跨平台处理的模块；程序其余部分为 Windows 专用。

## 下载

不想装 Python 的话，直接取预编译版本：

| 文件 | 说明 |
|---|---|
| [`SysScanGUI.exe`](https://github.com/yicko/SysScanGUI/releases/latest) | 单文件绿色版，约 21.6 MiB，**无需安装 Python**，双击即用 |
| `SHA256SUMS.txt` | 同页提供的校验和 |

核对下载完整性：

```powershell
Get-FileHash .\SysScanGUI.exe -Algorithm SHA256
# 或
certutil -hashfile SysScanGUI.exe SHA256
```

### 代码签名与来源验证

**当前发布的 exe 仍是未签名状态**——签名流程已就绪，待证书申请通过后启用（详见[启用代码签名](#启用代码签名维护者)）。在那之前首次运行可能触发 SmartScreen 提示，点「更多信息 → 仍要运行」即可。

无论是否已签名，**每次发布都值得核对产物来源**。发布流程会为 exe 生成 GitHub 构建溯源证明（build provenance attestation），可用 GitHub CLI 验证这个 exe 确实由本仓库的 CI 在 `windows-latest` 上编译、中途未被替换：

```bash
gh attestation verify SysScanGUI.exe --repo yicko/SysScanGUI
```

签名启用后，还可用以下命令查看签署者与时间戳（签署者将显示为 `SignPath Foundation`——开源计划的证书以其名义签发，私钥保存在其 HSM 内）：

```powershell
Get-AuthenticodeSignature .\SysScanGUI.exe | Format-List Status, SignerCertificate, TimeStamperCertificate
```

有一点需要说清楚：**签名不等于首次下载零提示**。SmartScreen 的信誉来自「文件哈希 + 发布者证书」的下载历史累积，新证书与每个新版本都要重新积累，通常需要数周与数百次干净下载才会消退。签名真正解决的是「未知发布者」标签，以及让信誉能够跨版本累积。

## 安装

从源码运行需要自行准备 Python 环境：

```bash
git clone https://github.com/yicko/SysScanGUI.git
cd SysScanGUI

python -m venv .venv
.venv\Scripts\activate

pip install -r requirements.txt
```

## 使用方法

### 1. 图形界面（推荐）

```bash
python gui.py
```

或直接双击 `run_gui.bat`。脚本会自动探测可用的 Python 解释器，找不到带 `PySide6` 与 `psutil` 的环境时会给出明确提示。

| 操作 | 方式 |
|---|---|
| 开始扫描 | 工具栏 **开始扫描** |
| 查看某条记录详情 | 双击该行 |
| 排序 | 单击列标题（再点一次切换升降序） |
| 处置动作 | 右键该行 → 选择动作 |
| 查看/回滚历史操作 | 菜单 **操作 → 处理历史 / 恢复** |
| 恢复默认排序 | 工具栏 **恢复默认排序** |
| 查看指标数据来源 | 菜单 **视图 → 指标数据来源** |
| 以管理员身份重启 | 菜单 **操作 → 以管理员身份重新运行** |

> 程序内建单实例检测。若已有实例在运行，新实例会把已有窗口切到前台并提示占用者信息，然后以退出码 `3` 安全退出。

### 2. 命令行扫描

```bash
# 采集 + 应用规则，输出 JSON 与控制台摘要
python scan.py --json scan_result.json

# 由 JSON 渲染 HTML 报告
python report.py --json scan_result.json --out report.html
```

或直接双击 `run_scan.bat`（自动安装缺失依赖 → 扫描 → 生成报告 → 打开报告）。

`scan.py` 可用参数：

| 参数 | 说明 |
|---|---|
| `--json PATH` | 指定 JSON 输出路径，默认 `scan_result.json` |
| `--no-signature` | 跳过数字签名校验，扫描更快 |
| `--no-tasks` | 跳过计划任务与启动项采集 |

### 3. 打包为单文件可执行程序（可选）

```bash
pip install pyinstaller
python -m PyInstaller --noconfirm --clean SysScanGUI.spec
```

产物为 `dist/SysScanGUI.exe`。`SysScanGUI.spec` 内含一套**瘦身规则**：剔除运行期不会被加载的 Qt 模块（QtNetwork / QtSvg / QtSql …）、软件 OpenGL 回退实现（`opengl32sw.dll`，约 19.7 MB）、第三方 OpenSSL、96 个未使用的 Qt 翻译包，以及误从 `PATH` 抓进来的系统 API Set DLL。所有剔除项都经过冒烟测试与完整扫描验证。

打包同时会写入**版本号**，来源只有一个：环境变量 `SYSSCAN_BUILD_VERSION`（CI 用它注入 tag），未设置时回退 `git describe` 取最近的 tag。版本号写进两处 —— 包内供「关于」弹窗显示，以及 exe 的版本资源（右键 → 属性 → 详细信息）。源码直接运行时显示 `0.0.0-dev`，**如实区分「官方构建」与「改过的源码」**，不冒充正式版本。

> 打包后的 exe 未做代码签名，首次运行可能触发 SmartScreen 提示。

### 4. 运行回归测试

各测试脚本相互独立，按改动范围挑一个跑即可：

```bash
python check_metrics.py        # 硬件指标采样与解析（PDH、温度换算、显存分桶）
python check_metrics_ui.py     # 指标面板卡片渲染，空数据必须显示 — 而不是伪造
python check_sort.py           # 表格点击排序（数值语义、筛选后保持、箭头可见）
python check_refresh.py        # 分层自动刷新、操作后核实、单飞守卫
python check_elevate.py        # 提权链路（ShellExecuteExW + 启动握手）
python check_single.py         # 单实例守卫（互斥体、陈旧锁、PID 复用、提示文案）
python check_selfproc.py       # 自身进程标注（引导器/应用本体识别、不误报、不越权放行）
python check_ui_text.py        # 文案一致性（「关于」不写实现细节 + README 的菜单指引真实存在）
python check_version.py        # 版本号（取号优先级、注入链路、「关于」显示、不冒充正式版本）
python check_eventlog.py        # 系统日志模块（XPath 构造、XML 解析、统计聚合、面板分页/筛选/导出、标签页索引隔离）
python check_frozen_scan.py    # 打包后 exe 的扫描能力
python check_frozen_elevate.py # 打包后 exe 的提权窗口可见性
python check_frozen_single.py  # 打包后 exe 的单实例行为
```

脚本会打印逐条断言结果与通过计数。部分涉及提权或冻结 exe 的测试需要管理员权限。

## 发布新版本（维护者）

Release 由 GitHub Actions 在云端编译，**不需要在本地打包再上传**：

```bash
git tag v1.0.1
git push origin v1.0.1
```

推送 `v*` 形式的 tag 即触发 [`.github/workflows/release.yml`](.github/workflows/release.yml)，在 `windows-latest` 上依次执行：

1. 按**锁定版本**安装依赖（PySide6-Essentials / PyInstaller，与本地验证过的版本一致，避免剔除规则因版本漂移失效）；
2. 用 `SysScanGUI.spec` 打包，并把**触发本次构建的 tag 作为版本号**注入（CI 经 `SYSSCAN_BUILD_VERSION` 传入，spec 写进包内与 exe 版本资源）；
3. **版本号自检**——断言 exe 版本资源里的版本等于该 tag，冒烟步骤再断言 exe 启动后从包内读回的版本同样等于该 tag。两条通道互相独立，任何一条断掉都会让流水线失败，而不是发出一个「有版本号但永远是 dev」的包；
4. **体积护栏**——产物若超过 30 MiB 直接失败，防止在剔除规则失效时把膨胀包发出去；
5. **代码签名**（未配置时整组步骤自动跳过，见下）；
6. **冒烟测试**——真的启动一次 exe 并等一次硬件采样落地，失败则不发布。它排在签名之后，因此同时验证了签名没有破坏 exe 本身；
7. **构建溯源证明**——为产物生成 attestation，供用户核对来源；
8. 生成 `SHA256SUMS.txt`，用 `gh` CLI 创建 Release 并上传资产（幂等：同一 tag 重跑会更新说明并覆盖资产）。

也可以在 Actions 页面手动触发并填一个已存在的 tag，用于重新构建同一版本。工作流除代码签名用的 `signpath/*` 外，只用 GitHub 官方的 `actions/*` 与预装的 `gh` CLI。

### 启用代码签名（维护者）

签名默认不启用。在仓库 Settings → Secrets and variables → Actions 配好以下四项后，下一次推送 `v*` tag 产出的即为已签名 exe：

| 类型 | 名称 | 说明 |
|---|---|---|
| Secret | `SIGNPATH_API_TOKEN` | SignPath REST API 令牌（Submitter 权限） |
| Secret | `SIGNPATH_ORGANIZATION_ID` | SignPath 组织 ID |
| Variable | `SIGNPATH_PROJECT_SLUG` | 项目标识；**它是否非空即代码签名的总开关** |
| Variable | `SIGNPATH_SIGNING_POLICY_SLUG` | 签名策略标识，通常为 `release-signing` |

只配了一部分时，工作流会在「核对签名配置完整性」一步直接失败，而不是静默产出未签名包——避免误以为已经签上。

签名流程为：上传待签名产物 → 提交签名请求并取回已签名产物 → 替换 `dist` 下的编译产物 → 用 `Get-AuthenticodeSignature` 断言签名有效且带 RFC 3161 时间戳。

> **顺序约束**：签名会改变文件字节，因此「提交签名并替换产物」必须排在生成 `SHA256SUMS.txt` 之前，否则发布的校验和会与线上产物对不上。签名完成后也不得再对 exe 做任何改动。

## 目录结构

```
sysscan/
├── scan.py                 # 采集层 + 规则引擎（核心，可独立命令行运行）
├── report.py               # JSON → 单文件 HTML 报告渲染
├── gui.py                  # PySide6 图形界面主程序（入口）
├── metrics.py              # 实时硬件指标采样（ctypes 直连 PDH，零子进程）
├── single_instance.py      # 单实例守卫（命名互斥体 + 锁文件双保险）
├── app_version.py          # 构建版本号（环境变量 → git tag → dev，可单测）
├── eventlog_reader.py      # 系统日志·数据读取层（ctypes 调 wevtapi，XPath 服务端筛选）
├── eventlog_stats.py       # 系统日志·分析统计层（级别/事件ID/来源/时间聚合，纯函数）
├── eventlog_widget.py      # 系统日志·界面展示层（筛选/分页/详情/图表/导出/后台线程）
├── SysScanGUI.spec         # PyInstaller 打包配置（含体积瘦身规则）
├── requirements.txt        # 运行期依赖
├── run_gui.bat             # 启动图形界面
├── run_scan.bat            # 命令行扫描 + 生成 HTML 报告
├── check_metrics.py        # ┐
├── check_metrics_ui.py     # │
├── check_sort.py           # │
├── check_refresh.py        # │ 回归测试
├── check_elevate.py        # │ （各脚本相互独立，按需运行）
├── check_single.py         # │
├── check_selfproc.py       # │
├── check_ui_text.py        # │
├── check_version.py        # │
├── check_eventlog.py       # │
├── check_frozen_scan.py    # │
├── check_frozen_elevate.py # │
├── check_frozen_single.py  # ┘
├── .github/
│   └── workflows/
│       └── release.yml     # GitHub Actions：推送 v* tag 即自动编译并发布 Release
├── README.md
├── LICENSE
└── .gitignore
```

## 设计取舍

这些决定不是随手做的，它们解释了代码里一些看起来"绕"的地方：

- **宁可如实说"不知道"，也不猜一个数字。** 拿不到 GPU 温度就显示 `—`；CPU 温度取自 ACPI 热区时会明确标注"这不是 CPU 核心温度"。安全工具最不该做的事，就是用假数据让人放松警惕。
- **不 spawn 子进程查指标。** 常见做法是每几秒调一次 `nvidia-smi` 或 `powershell Get-Counter`。但一个安全监控程序自己高频创建子进程、查询性能计数器，恰好落在杀毒软件的启发式规则里——它不该长成它自己要抓的样子。因此硬件指标走 `ctypes` 直连 `pdh.dll`，单次采样仅数毫秒。
- **判定必须可解释。** 每条风险都带"判定依据"与"建议动作"，而不是只给一个等级。用户需要能自己判断这个警报是真是假。
- **处置前先备份。** 终止进程前用 `(pid, name, exe, create_time)` 四元组核验身份（PID 会被系统复用，只信 PID 会杀错进程）；停用服务、删除启动项前先记录原始值，随时可回滚。
- **数据诚实优先于界面的"清爽"。** 指标面板在数据缺失时显示占位符而非隐藏卡片——隐藏会让人误以为该项正常。
- **不做全量定时重扫。** 全量扫描开销大且会打断用户当前操作；改为"概览指标轻量常刷 + 处置后单点核实"。
- **刷新是合并而非替换。** 后台重采后按身份键保留用户填写的备注与手动风险标记，并恢复选中行与滚动位置。

## 已知局限

- **GPU 温度**在多数集成显卡机器上不可用：Windows 性能计数器不导出该数据，需依赖 `nvidia-smi`（仅 NVIDIA）或运行 LibreHardwareMonitor（可自动识别并改用其读数）。
- **CPU 温度**在未运行 LibreHardwareMonitor 时来自 ACPI 热区，读数是主板/机身热区温度（通常长期稳定不动），界面会如实标注来源。
- **集显显存总量**无法获得（动态共享系统内存），只报告占用绝对值。
- 部分受保护进程的信息（路径、命令行）在非管理员权限下会缺失，属系统限制。
- **单文件版运行时，进程表里会出现两个同名进程**（`SysScanGUI.exe`）：一个是 PyInstaller
  的**引导器**（先把自身解包到临时目录、再启动真正的应用，并守着以便退出时清理），另一个是
  **应用本体**，两者命令行完全相同。这是单文件打包的固定结构，**不是「旧实例没退出」**。
  程序在扫描时会把自己的进程标注为「本程序自身进程」并跳过风险判定（否则绿色版位于非标准
  目录又未签名，会刷出两条指向自己的中危告警）；菜单 **帮助 → 运行实例信息** 里可以看到
  当前这两个进程的 pid 与角色。不想要这个结构的话，只能改用目录式（onedir）打包。
- 打包后的 exe **当前未签名**（签名流程已就绪，待证书申请通过后启用），首次运行可能触发 SmartScreen 提示。
- 签名只解决「未知发布者」与信誉累积问题，**不会让首次下载立即零提示**——SmartScreen 信誉需要靠下载历史逐步建立。
- 扫描结果为启发式判定，**存在误报与漏报**，仅供排查参考，不能替代专业安全软件的实时防护。

## 安全与隐私

- **程序不联网。** 网络采集通过本地 API 读取连接表，不发起任何外部请求，不上传任何数据。
- **扫描结果只落本地磁盘。** JSON 与 HTML 报告默认生成在程序目录下。
- 本仓库**不包含任何扫描结果**：`scan_result.json` 与 `report.html` 已被 `.gitignore` 排除。这类文件会记录主机名、账户名、完整进程命令行与远端 IP 地址，属于个人隐私数据。
- 提交问题（Issue）时请勿直接粘贴完整扫描结果，建议先脱敏主机名、账户名与 IP。
- **产物来源可验证。** 每次发布都附 `SHA256SUMS.txt` 与 GitHub 构建溯源证明，可核对产物是否确实由本仓库的 CI 编译、中途未被替换（见[代码签名与来源验证](#代码签名与来源验证)）。

## 免责声明

本工具会执行**终止进程、停止/禁用服务、删除计划任务与启动项**等具有破坏性的系统操作。**请务必在操作前确认目标对象确实可以安全处置**——停用关键服务或结束系统进程可能导致系统不稳定、功能异常甚至无法正常启动。

作者不对因使用本工具而造成的任何数据丢失、系统损坏或其他损害承担责任。使用前请自行评估风险，建议在关键环境中先做好系统还原点或备份。

## 贡献

欢迎提交 Issue 与 Pull Request。

- 报告 Bug 时请说明 Windows 版本、Python 版本、复现步骤与期望行为；**请先对扫描结果中的主机名、账户名与 IP 做脱敏处理**。
- 新增风险规则时，建议同时在对应的 `check_*.py` 中补充断言，保持测试与规则同步。
- 修改 `SysScanGUI.spec` 中的剔除规则后，请重新执行冒烟测试与完整扫描，确认没有删掉运行期真正需要的组件。

## 许可证

本项目基于 [MIT License](LICENSE) 发布，可自由用于商业与非商业用途，只需保留原始版权声明。

```
Copyright (c) 2026 yicko
```
