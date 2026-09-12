# -*- mode: python ; coding: utf-8 -*-
"""SysScanGUI 瘦身打包配置（PyInstaller 6.x）

思路：不改动 gui.py 一行代码，只在打包阶段把「被 hook 顺手收进来、但本程序
运行期根本不会加载」的资源剔掉。所有剔除项都经 --smoke 冒烟 + 完整扫描验证。

构建命令：
    python -m PyInstaller --noconfirm --clean SysScanGUI.spec
"""
import os
import sys
import tempfile

# --------------------------------------------------------------------------
# 1. 剔除的 Qt / 第三方二进制（按文件名匹配，统一小写）
# --------------------------------------------------------------------------
DROP_BIN_NAMES = {
    # 19.7 MB 软件 OpenGL 回退实现（Mesa llvmpipe）。
    # 本程序只用 QWidget 的 raster 光栅绘制，不创建 OpenGL 上下文，用不到。
    "opengl32sw.dll",
    # 6.5 MB：来自 PATH 中 PortableGit 自带 OpenSSL，由 _ssl/_hashlib 顺带拖进来。
    # 本程序不做任何 TLS 通信（网络采集靠 psutil，不联网）。
    "libcrypto-3-x64.dll",
    "libssl-3-x64.dll",
    # 1.1 MB：来自 Windows Performance Toolkit 目录，属系统自带 DLL，
    # 打包进来既占体积又有跨机器兼容隐患（应使用目标机 System32 的版本）。
    "ucrtbase.dll",
    # Qt 模块：源码未 import（gui.py 只用 QtCore / QtGui / QtWidgets）
    "qt6network.dll", "qtnetwork.pyd",
    "qt6svg.dll",
    "qt6opengl.dll", "qtopengl.pyd",
    "qt6sql.dll", "qtsql.pyd",
    "qt6xml.dll", "qtxml.pyd",
    "qt6test.dll", "qttest.pyd",
    "qt6dbus.dll", "qtdbus.pyd",
    "qt6printsupport.dll", "qtprintsupport.pyd",
    # 平台插件：默认 qwindows 即可，direct2d / minimal 用不到
    "qdirect2d.dll", "qminimal.dll",
}

# UCRT API Set 前向 DLL（api-ms-win-* / ext-ms-win-*），系统自带，不应打包
DROP_BIN_PREFIXES = ("api-ms-win-", "ext-ms-win-")

# 与 QtNetwork / QtSvg 配套的插件目录，模块都删了，插件留着也用不了
DROP_PLUGIN_DIRS = (
    "/plugins/tls/",
    "/plugins/generic/",
    "/plugins/networkinformation/",
    "/plugins/iconengines/",
    "/plugins/qmltooling/",
    "/plugins/sqldrivers/",
)

# 图片格式插件：只保留 ico/gif/jpeg 作保险，其余（webp/tiff/icns/tga/wbmp/pdf/svg）删掉
DROP_IMAGEFORMATS = {
    "qwebp.dll", "qtiff.dll", "qicns.dll", "qpdf.dll", "qsvg.dll", "qtga.dll", "qwbmp.dll",
}

# --------------------------------------------------------------------------
# 2. 翻译包：Qt 的 .qm 只有显式 QTranslator 加载才生效，本程序未加载，
#    96 个语言包里只留中文界面兜底，其余全删
# --------------------------------------------------------------------------
KEEP_TRANSLATIONS = {"qt_zh_cn.qm", "qtbase_zh_cn.qm"}


def _name_of(entry):
    return str(entry[0]).replace("\\", "/").lower()


def keep_binary(entry):
    name = _name_of(entry)
    base = name.rsplit("/", 1)[-1]
    if base in DROP_BIN_NAMES:
        return False
    if base.startswith(DROP_BIN_PREFIXES):
        return False
    if any(d in name for d in DROP_PLUGIN_DIRS):
        return False
    if "/plugins/imageformats/" in name and base in DROP_IMAGEFORMATS:
        return False
    return True


def keep_data(entry):
    name = _name_of(entry)
    if "/translations/" in name:
        return name.rsplit("/", 1)[-1] in KEEP_TRANSLATIONS
    return True


def _filter(entries, predicate):
    kept, dropped_bytes, dropped_cnt = [], 0, 0
    for e in entries:
        if predicate(e):
            kept.append(e)
        else:
            dropped_cnt += 1
            try:
                dropped_bytes += os.path.getsize(e[1])
            except Exception:
                pass
    return kept, dropped_cnt, dropped_bytes


# --------------------------------------------------------------------------
# 3. 模块级排除：从依赖分析源头切断，比事后删文件更干净
# --------------------------------------------------------------------------
EXCLUDES = [
    # 环境相关
    "sitecustomize", "pyinstaller", "PyInstaller",
    # 不做 TLS/HASH → 连带剔除 OpenSSL（约 6.5 MB）
    "ssl", "_ssl", "_hashlib",
    # 未使用的 Qt 绑定
    "PySide6.QtNetwork", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtSvg",
    "PySide6.QtSql", "PySide6.QtTest", "PySide6.QtXml", "PySide6.QtDBus",
    "PySide6.QtPrintSupport", "PySide6.QtOpenGL", "PySide6.QtPdf",
    "PySide6.QtDesigner", "PySide6.QtUiTools", "PySide6.QtHelp",
    "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets",
    "PySide6.QtMultimedia", "PySide6.QtBluetooth", "PySide6.QtPositioning",
    "PySide6.QtSensors", "PySide6.QtSerialPort", "PySide6.QtStateMachine",
    "PySide6.QtConcurrent", "PySide6.QtScxml", "PySide6.QtRemoteObjects",
    # 其他 GUI 框架（曾用于 tkinter 版，现已移除）
    "tkinter", "PyQt5", "PyQt6", "matplotlib", "numpy", "PIL",
]

# --------------------------------------------------------------------------
# 4. 版本号注入：让「关于」弹窗、exe 右键属性、Release tag 指向同一个版本
#    取号逻辑在 app_version.py（可单测）：环境变量 → git describe → DEV_VERSION
#    CI 通过 SYSSCAN_BUILD_VERSION 显式传入 tag；本地打包则自动读 git。
#    注入件放在临时目录，不污染源码树。
# --------------------------------------------------------------------------
sys.path.insert(0, SPECPATH)
import app_version as _ver_mod           # noqa: E402

BUILD_VERSION = _ver_mod.resolve_build_version()
print("[VER] build version = %s" % BUILD_VERSION)
if BUILD_VERSION == _ver_mod.DEV_VERSION:
    print("[VER] WARN: no version could be determined (no %s, not a git repo, or "
          "no tag); the build will report %s"
          % (_ver_mod.ENV_VAR, _ver_mod.DEV_VERSION))

_ver_dir = tempfile.mkdtemp(prefix="sysscan_ver_")

# 通道 1：随包注入，运行期由 app_version.current() 从 sys._MEIPASS 读回
_ver_txt = os.path.join(_ver_dir, _ver_mod.INJECT_NAME)
with open(_ver_txt, "w", encoding="utf-8") as _f:
    _f.write(BUILD_VERSION)

# 通道 2：Windows 版本资源 —— 右键 exe → 属性 → 详细信息里直接看到版本号。
# 直接构造 VSVersionInfo 对象传给 EXE（PyInstaller 同时支持传文件路径），
# 省掉落盘与 eval 往返；中文字符串经 toRaw() 以 UTF-16 写入 PE，无编码风险。
_verinfo = None
try:
    from PyInstaller.utils.win32.versioninfo import (FixedFileInfo, StringFileInfo,
                                                     StringStruct, StringTable,
                                                     VarFileInfo, VarStruct,
                                                     VSVersionInfo)
    _nums = _ver_mod.version_tuple(BUILD_VERSION)
    _verinfo = VSVersionInfo(
        ffi=FixedFileInfo(filevers=_nums, prodvers=_nums, mask=0x3F, flags=0x0,
                          OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
        kids=[StringFileInfo([StringTable("080404B0", [
            StringStruct("CompanyName", "SysScanGUI"),
            StringStruct("FileDescription", "系统进程与服务安全扫描器"),
            StringStruct("FileVersion", BUILD_VERSION),
            StringStruct("InternalName", "SysScanGUI"),
            StringStruct("LegalCopyright", "MIT License"),
            StringStruct("OriginalFilename", "SysScanGUI.exe"),
            StringStruct("ProductName", "SysScanGUI"),
            StringStruct("ProductVersion", BUILD_VERSION),
        ])]),
            VarFileInfo([VarStruct("Translation", [0x0804, 1200])])],
    )
    print("[VER] version resource ready (ProductVersion = %s, numeric %s)"
          % (BUILD_VERSION, _nums))
except Exception as _e:                    # 版本资源只是加分项，失败不该阻断打包
    print("[VER] WARN: version resource skipped (%s); exe is still usable" % _e)
    _verinfo = None

a = Analysis(
    ["gui.py"],
    pathex=[],
    binaries=[],
    # 通道 1：把注入的版本号放进包里。dest 用 "." = 包根目录 —— 这与
    # a.datas 里 (dest, src, typecode) 三元组的语义不同，别混用。
    datas=[(_ver_txt, ".")],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=2,          # 字节码优化级别 2：剥离 docstring / assert
)

a.binaries, _b_cnt, _b_bytes = _filter(a.binaries, keep_binary)
a.datas, _d_cnt, _d_bytes = _filter(a.datas, keep_data)
# 自检：注入件必须活过剔除规则并留在最终 datas 里（列表为空 = 注入没生效）
_inj = [e for e in a.datas if _ver_mod.INJECT_NAME in str(e[0])]
print("[VER] datas entries = %d, injected = %r" % (len(a.datas), _inj))
print("[SLIM] dropped binaries %d / %.2f MB, datas %d / %.2f MB, total %.2f MB"
      % (_b_cnt, _b_bytes / 1048576, _d_cnt, _d_bytes / 1048576,
         (_b_bytes + _d_bytes) / 1048576))

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="SysScanGUI",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,             # 归档已做 zlib 压缩，UPX 收益有限且易触发杀软误报
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=_verinfo,       # Windows 版本资源（None = 不写入）
)
