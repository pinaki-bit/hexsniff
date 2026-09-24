# -*- mode: python ; coding: utf-8 -*-


import os

spec_dir = os.path.dirname(os.path.abspath(SPEC))
frontend_dist = os.path.join(os.path.dirname(spec_dir), 'frontend', 'dist')
rules_dir = os.path.join(spec_dir, 'app', 'rules')

a = Analysis(
    ['desktop_app.py'],
    pathex=[],
    binaries=[],
    datas=[(frontend_dist, 'frontend/dist'), (rules_dir, 'app/rules')],
    hiddenimports=['scapy.layers.all', 'scapy.layers.inet', 'uvicorn.logging', 'uvicorn.loops', 'uvicorn.loops.auto', 'uvicorn.protocols', 'uvicorn.protocols.http', 'uvicorn.protocols.http.auto', 'uvicorn.protocols.websockets', 'uvicorn.protocols.websockets.auto', 'uvicorn.lifespan', 'uvicorn.lifespan.on', 'webview'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='HexSniff',
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
)
