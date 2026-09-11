# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec file for Project Revelare

import os
from pathlib import Path

block_cipher = None

# Get the project root directory
project_root = Path(SPECPATH)

# Data files to include
datas = [
    # Flask templates
    (str(project_root / 'revelare' / 'web' / 'templates'), 'revelare/web/templates'),
    # Flask static files
    (str(project_root / 'revelare' / 'web' / 'static'), 'revelare/web/static'),
    # GeoIP databases (root level)
    (str(project_root / 'GeoLite2-City.mmdb'), '.'),
    (str(project_root / 'GeoLite2-ASN.mmdb'), '.'),
    # GeoIP databases (in revelare directory)
    (str(project_root / 'revelare' / 'GeoLite2-City.mmdb'), 'revelare'),
    (str(project_root / 'revelare' / 'GeoLite2-ASN.mmdb'), 'revelare'),
]

# Only include GeoIP files if they exist
datas = [d for d in datas if os.path.exists(d[0])]

# Hidden imports (modules PyInstaller might miss)
hiddenimports = [
    'flask',
    'werkzeug',
    'jinja2',
    'markupsafe',
    'itsdangerous',
    'click',
    'blinker',
    'maxminddb',
    'pypdf',
    'docx',
    'PIL',
    'numpy',
    'pandas',
    'requests',
    'py7zr',
    'exifread',
    'sqlite3',
    'tkinter',
    'webbrowser',
    'revelare',
    'revelare.cli',
    'revelare.cli.suite',
    'revelare.config',
    'revelare.config.config',
    'revelare.core',
    'revelare.core.case_manager',
    'revelare.core.extractor',
    'revelare.core.file_processors',
    'revelare.utils',
    'revelare.utils.logger',
    'revelare.utils.reporter',
    'revelare.utils.file_extractor',
    'revelare.web',
]

a = Analysis(
    ['revelare_launcher.py'],
    pathex=[],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
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
    name='ProjectRevelare',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,  # Set to False for windowed mode (no console)
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,  # Add path to .ico file if you have an icon
)
