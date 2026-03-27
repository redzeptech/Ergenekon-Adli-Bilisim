"""
UserAssist (NTUSER.DAT) komut satırı aracı — uareport hattının modüler karşılığı.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from tabulate import tabulate

from ergenekon.core.userassist_engine import UserAssistEngine
from ergenekon.exporters.userassist_export import (
    userassist_rows_to_records,
    write_userassist_csv,
    write_userassist_json,
)
from ergenekon.utils.masker import mask_kvkk_identifiers


def _cli_version() -> str:
    try:
        from importlib.metadata import version

        return version("ergenekon-adli")
    except Exception:
        from ergenekon import __version__

        return __version__


def main() -> None:
    ver = _cli_version()
    parser = argparse.ArgumentParser(
        description="UserAssist kayıtlarını NTUSER.DAT dosyalarından çıkarır (ergenekon).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"uareport / ergenekon-adli {ver}",
    )
    parser.add_argument(
        "-d",
        "--directory",
        type=Path,
        required=True,
        help="NTUSER.DAT dosyalarının aranacağı kök dizin",
    )
    parser.add_argument(
        "--user",
        type=str,
        default=None,
        help="Yalnızca bu Windows kullanıcı klasör adı (büyük/küçük harf duyarsız)",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "both"),
        default="table",
        help="Çıktı: tablo (tabulate), JSON (stdout) veya ikisi",
    )
    parser.add_argument(
        "--mask",
        action="store_true",
        help="KVKK paylaşımı için User / Artifact alanlarında sözdeanonimleştirme",
    )
    parser.add_argument(
        "--json-out",
        type=Path,
        default=None,
        help="JSON çıktıyı dosyaya yaz (tüm kayıtlar)",
    )
    parser.add_argument(
        "--csv",
        type=Path,
        default=None,
        help="CSV çıktı dosyası",
    )
    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"uareport (ergenekon-adli {ver})",
    )
    args = parser.parse_args()

    engine = UserAssistEngine(args.directory, user_filter=args.user)
    rows = engine.run()
    records = userassist_rows_to_records(rows)

    if args.mask:
        records = [mask_kvkk_identifiers(r) for r in records]

    if not records:
        msg = "UserAssist kaydı bulunamadı"
        if args.user:
            msg += f" (kullanıcı filtresi: {args.user})"
        print(msg + ".", file=sys.stderr)
        return

    headers = ["User", "Artifact", "RunCount", "LastRun", "FocusCount", "FocusTimeMs"]
    table_rows = [[r[h] for h in headers] for r in records]

    if args.format in ("table", "both"):
        print("\n" + tabulate(table_rows, headers=headers, tablefmt="grid") + "\n")

    if args.format in ("json", "both"):
        print(json.dumps(records, ensure_ascii=False, indent=2, default=str))

    if args.json_out:
        write_userassist_json(args.json_out, records)
        print(f"JSON yazıldı: {args.json_out}", file=sys.stderr)

    if args.csv:
        write_userassist_csv(args.csv, records)
        print(f"CSV yazıldı: {args.csv}", file=sys.stderr)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nİptal edildi.", file=sys.stderr)
        sys.exit(130)
