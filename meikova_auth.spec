# -*- mode: python ; coding: utf-8 -*-
from pathlib import Path
import sys

block_cipher = None
ROOT = Path(__file__).resolve().parent

datas = [
    (str(ROOT / "static"), "static"),
    (str(ROOT / "keys"), "keys"),
]

if (ROOT / "icon.ico").exists():
    datas.append((str(ROOT / "icon.ico"), "."))

if (ROOT / "icon-32.png").exists():
    datas.append((str(ROOT / "icon-32.png"), "."))

hiddenimports = [
    "uvicorn",
    "uvicorn.logging",
    "uvicorn.loops",
    "uvicorn.loops.auto",
    "uvicorn.protocols",
    "uvicorn.protocols.http",
    "uvicorn.protocols.http.auto",
    "uvicorn.lifespan",
    "uvicorn.lifespan.on",
    "fastapi",
    "starlette",
    "pydantic",
    "cryptography",
    "cryptography.hazmat.primitives.asymmetric.ed25519",
    "sqlite3",
    "libsql_client",
]

a = Analysis(
    ["meikova_auth_desktop.py"],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "scipy"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="MeikovaAuth",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=str(ROOT / "icon.ico") if (ROOT / "icon.ico").exists() else None,
)
