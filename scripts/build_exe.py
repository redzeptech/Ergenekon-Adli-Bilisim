"""Build Ergenekon-Adli-Bilisim as onefile Windows executable."""

from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def run_command(command: list[str], cwd: Path) -> None:
    """Run shell command and stop on error."""
    print(f"[build] {' '.join(command)}")
    subprocess.run(command, cwd=str(cwd), check=True)


def make_version_file() -> Path:
    """Create a temporary PyInstaller version file with EXE metadata."""
    version_text = """# UTF-8
VSVersionInfo(
  ffi=FixedFileInfo(
    filevers=(1, 0, 0, 0),
    prodvers=(1, 0, 0, 0),
    mask=0x3F,
    flags=0x0,
    OS=0x40004,
    fileType=0x1,
    subtype=0x0,
    date=(0, 0)
    ),
  kids=[
    StringFileInfo(
      [
      StringTable(
        u'040904B0',
        [StringStruct(u'CompanyName', u'Ergenekon Adli Bilisim'),
        StringStruct(u'FileDescription', u'Forensic Analysis Tool'),
        StringStruct(u'FileVersion', u'1.0.0'),
        StringStruct(u'InternalName', u'Ergenekon_Forensics_v1'),
        StringStruct(u'LegalCopyright', u'Copyright (c) Ergenekon Adli Bilisim'),
        StringStruct(u'OriginalFilename', u'Ergenekon_Forensics_v1.exe'),
        StringStruct(u'ProductName', u'Ergenekon Adli Bilisim'),
        StringStruct(u'ProductVersion', u'1.0.0')])
      ]),
    VarFileInfo([VarStruct(u'Translation', [1033, 1200])])
  ]
)
"""
    tmp = tempfile.NamedTemporaryFile(
        mode="w", encoding="utf-8", suffix=".txt", prefix="pyi_version_", delete=False
    )
    with tmp:
        tmp.write(version_text)
    version_path = Path(tmp.name)
    print(f"[build] Version metadata file: {version_path}")
    return version_path


def ensure_pyinstaller(project_root: Path) -> None:
    """Install PyInstaller when missing from environment."""
    if shutil.which("pyinstaller"):
        return
    run_command([sys.executable, "-m", "pip", "install", "pyinstaller"], cwd=project_root)


def install_requirements(project_root: Path, requirements_path: Path) -> None:
    """Install dependencies declared by requirements file."""
    if not requirements_path.exists():
        raise FileNotFoundError(f"requirements.txt bulunamadi: {requirements_path}")
    run_command(
        [sys.executable, "-m", "pip", "install", "-r", str(requirements_path)],
        cwd=project_root,
    )


def build_onefile(
    project_root: Path,
    entry_script: Path,
    *,
    icon_path: Path | None = None,
    version_file: Path,
    noconsole: bool = False,
) -> None:
    """Build onefile EXE with required data folders."""
    if not entry_script.exists():
        raise FileNotFoundError(f"Giris scripti bulunamadi: {entry_script}")

    binaries_dir = project_root / "binaries"
    ergenekon_dir = project_root / "ergenekon"
    if not binaries_dir.exists():
        raise FileNotFoundError(f"binaries klasoru bulunamadi: {binaries_dir}")
    if not ergenekon_dir.exists():
        raise FileNotFoundError(f"ergenekon paketi bulunamadi: {ergenekon_dir}")

    pyinstaller_cmd = [
        "pyinstaller",
        "--noconfirm",
        "--clean",
        "--onefile",
        "--name",
        "Ergenekon_Forensics_v1",
        "--paths",
        str(project_root),
        "--add-data",
        f"{ergenekon_dir};ergenekon",
        "--add-data",
        f"{binaries_dir};binaries",
        "--version-file",
        str(version_file),
    ]
    if icon_path:
        resolved_icon = project_root / icon_path
        if not resolved_icon.exists():
            raise FileNotFoundError(f"Icon dosyasi bulunamadi: {resolved_icon}")
        pyinstaller_cmd.extend(["--icon", str(resolved_icon)])
    if noconsole:
        pyinstaller_cmd.append("--noconsole")

    pyinstaller_cmd.append(str(entry_script))
    run_command(pyinstaller_cmd, cwd=project_root)
    print("[build] Tamamlandi: dist/Ergenekon_Forensics_v1.exe")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Ergenekon-Adli-Bilisim icin PyInstaller onefile EXE olusturur."
    )
    parser.add_argument(
        "--entry",
        type=Path,
        default=Path("amcache_evilhunter.py"),
        help="PyInstaller icin giris scripti (varsayilan: amcache_evilhunter.py)",
    )
    parser.add_argument(
        "--icon",
        type=Path,
        default=None,
        help="Opsiyonel .ico dosya yolu (repo kokune goreli)",
    )
    parser.add_argument(
        "--noconsole",
        action="store_true",
        help="Konsol penceresi olmadan GUI-style executable uretir",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    project_root = Path(__file__).resolve().parents[1]
    requirements_path = project_root / "requirements.txt"
    entry_script = project_root / args.entry

    version_file = make_version_file()
    try:
        install_requirements(project_root, requirements_path)
        ensure_pyinstaller(project_root)
        build_onefile(
            project_root,
            entry_script,
            icon_path=args.icon,
            version_file=version_file,
            noconsole=args.noconsole,
        )
    finally:
        if version_file.exists():
            version_file.unlink()


if __name__ == "__main__":
    main()
