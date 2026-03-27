from __future__ import annotations

import argparse
import os
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

try:
    import winreg  # type: ignore
except ImportError as exc:  # pragma: no cover
    raise SystemExit("This script must be run on Windows (winreg is required).") from exc


@dataclass(frozen=True)
class DemoRecord:
    key_name: str
    lower_case_long_path: str
    publisher: str
    version: str
    original_file_name: str
    file_id_sha1: str
    size: int


def _filetime_qword(dt: datetime) -> int:
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    dt_utc = dt.astimezone(timezone.utc)
    epoch_1601 = datetime(1601, 1, 1, tzinfo=timezone.utc)
    return int((dt_utc - epoch_1601).total_seconds() * 10_000_000)


def _set_sz(key: int, name: str, value: str) -> None:
    winreg.SetValueEx(key, name, 0, winreg.REG_SZ, value)


def _set_qword(key: int, name: str, value: int) -> None:
    winreg.SetValueEx(key, name, 0, winreg.REG_QWORD, int(value))


def _delete_tree(root: int, subkey: str) -> None:
    try:
        with winreg.OpenKey(root, subkey, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
            while True:
                try:
                    child = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(root, f"{subkey}\\{child}")
    except FileNotFoundError:
        return
    winreg.DeleteKey(root, subkey)


def _write_demo_structure(base_key_path: str, records: Iterable[DemoRecord]) -> None:
    base = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, base_key_path, 0, winreg.KEY_WRITE)
    winreg.CloseKey(base)

    inv_path = f"{base_key_path}\\Root\\InventoryApplicationFile"
    inv = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, inv_path, 0, winreg.KEY_WRITE)
    winreg.CloseKey(inv)

    now = datetime.now(timezone.utc)
    ft_now = _filetime_qword(now)

    for rec in records:
        rec_path = f"{inv_path}\\{rec.key_name}"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, rec_path, 0, winreg.KEY_WRITE) as k:
            _set_sz(k, "LowerCaseLongPath", rec.lower_case_long_path)
            _set_sz(k, "Name", os.path.basename(rec.lower_case_long_path))
            _set_sz(k, "Publisher", rec.publisher)
            _set_sz(k, "Version", rec.version)
            _set_sz(k, "OriginalFileName", rec.original_file_name)
            _set_sz(k, "FileId", rec.file_id_sha1)  # parser maps FileId -> SHA-1
            _set_qword(k, "Size", rec.size)
            _set_qword(k, "LastModifiedTime", ft_now)


def _reg_save(hkcu_subkey: str, out_path: Path) -> None:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    cmd = ["reg", "save", f"HKCU\\{hkcu_subkey}", str(out_path), "/y"]
    # `reg.exe` output encoding varies by system locale; avoid UnicodeDecodeError.
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")
    if proc.returncode != 0:
        msg = (proc.stdout or "") + ("\n" if proc.stdout and proc.stderr else "") + (proc.stderr or "")
        raise RuntimeError(
            "Failed to export demo hive via `reg save`.\n"
            "Try running PowerShell / CMD as Administrator and re-run this script.\n"
            f"Command: {' '.join(cmd)}\n"
            f"Exit code: {proc.returncode}\n"
            f"Output:\n{msg}".rstrip()
        )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate a small demo Amcache.hve-like hive for testing Ergenekon-Adli."
    )
    parser.add_argument(
        "--out",
        type=Path,
        default=Path(__file__).resolve().parent / "demo_Amcache.hve",
        help="Output hive path (default: ergenekon/utils/demo_Amcache.hve).",
    )
    parser.add_argument(
        "--keep-registry-key",
        action="store_true",
        help="Do not delete the temporary HKCU registry key after export.",
    )
    args = parser.parse_args()

    base_key_path = r"Software\ErgenekonAdliBilisimDemo"

    records = [
        DemoRecord(
            key_name="0001",
            lower_case_long_path=r"c:\users\demo\appdata\roaming\svch0st.exe",
            publisher="",
            version="1.0.0",
            original_file_name="svchost.exe",
            file_id_sha1="0000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
            size=1337,
        ),
        DemoRecord(
            key_name="0002",
            lower_case_long_path=r"c:\program files\google\chrome\application\chrome.exe",
            publisher="Google LLC",
            version="123.0.0.0",
            original_file_name="chrome.exe",
            file_id_sha1="00001234567890abcdef1234567890abcdef1234",
            size=42_000_000,
        ),
    ]

    try:
        _write_demo_structure(base_key_path, records)
        _reg_save(base_key_path, args.out)
        print(f"[OK] Demo hive written: {args.out}")
        print(
            "\nTry running:\n"
            f'  python amcache_evilhunter.py -i "{args.out}" --sigma --mask --output-dir "case_demo"\n'
        )
        return 0
    finally:
        if not args.keep_registry_key:
            _delete_tree(winreg.HKEY_CURRENT_USER, base_key_path)


if __name__ == "__main__":
    raise SystemExit(main())

