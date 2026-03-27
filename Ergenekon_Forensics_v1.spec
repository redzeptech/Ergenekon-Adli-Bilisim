# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['C:\\Users\\Recep\\Desktop\\Ergenekon-Adli-Bilisim\\amcache_evilhunter.py'],
    pathex=['C:\\Users\\Recep\\Desktop\\Ergenekon-Adli-Bilisim'],
    binaries=[],
    datas=[('C:\\Users\\Recep\\Desktop\\Ergenekon-Adli-Bilisim\\ergenekon', 'ergenekon'), ('C:\\Users\\Recep\\Desktop\\Ergenekon-Adli-Bilisim\\binaries', 'binaries')],
    hiddenimports=[],
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
    name='Ergenekon_Forensics_v1',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='C:\\Users\\Recep\\AppData\\Local\\Temp\\pyi_version_o168r7mv.txt',
)
