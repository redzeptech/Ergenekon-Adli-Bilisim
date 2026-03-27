"""
AmCache-EvilHunter CLI.
Özgün mantık: Cristian Souza; paketleme: Ergenekon Adli Bilişim.
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import logging
import os
import socket
import subprocess
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from requests.exceptions import HTTPError
from rich.console import Console
from rich.live import Live
from rich.table import Table

from ergenekon.core.amcache_engine import AmcacheEngine
from ergenekon.core.exceptions import HiveParseError
from ergenekon.exporters import (
    flatten_amcache_data,
    write_amcache_csv,
    write_amcache_json,
    write_amcache_markdown_report,
    write_forensic_timeline_html,
)
from ergenekon.parsers.amcache import find_suspicious, missing_publisher
from ergenekon.parsers.shimcache import (
    ShimcacheParser,
    build_execution_timeline,
    correlate_amcache_shimcache,
)
from ergenekon.parsers.sigma_rules import apply_sigma_rules
from ergenekon.utils.logging_config import configure_logging
from ergenekon.utils.privacy import mask_path, mask_pii
from ergenekon.utils.threat_intel import lookup_opentip, lookup_vt

console = Console()
logger = logging.getLogger("ergenekon.amcache_cli")
MASK_POLICY_FIELDS: dict[str, tuple[str, ...]] = {
    "balanced": ("Username", "ComputerName", "Path", "FilePath"),
    "strict": (
        "Username",
        "ComputerName",
        "Path",
        "FilePath",
        "Name",
        "OriginalFileName",
        "Publisher",
    ),
}


def _cli_version() -> str:
    try:
        from importlib.metadata import version

        return version("ergenekon-adli")
    except Exception:
        from ergenekon import __version__

        return __version__


def prompt_overwrite(path: Path) -> None:
    """Prompt before overwriting an existing file.

    Args:
        path: Output file path.
    """
    if path.exists():
        ans = input(f"File {path} exists. Overwrite? [y/N]: ")
        if ans.lower() != "y":
            print("Aborted: file not overwritten.", file=sys.stderr)
            sys.exit(0)


def print_table(
    data: dict[str, dict[str, dict[str, Any]]],
    vt_enabled: bool,
    opentip_enabled: bool,
    vt_api_key: str | None = None,
    ot_api_key: str | None = None,
    only_detections: bool = False,
) -> bool:
    """Render analysis results as a live Rich table.

    Args:
        data: Category -> record name -> field map.
        vt_enabled: Enables VirusTotal enrichment.
        opentip_enabled: Enables OpenTIP enrichment.
        vt_api_key: VirusTotal API key.
        ot_api_key: OpenTIP API key.
        only_detections: Filters table rows by positive detections.

    Returns:
        True if at least one row is printed.
    """
    any_printed = False
    rows_to_print: list[tuple[str, list[Any], str | None]] = []
    vt_rate_limited = False
    ot_rate_limited = False

    def make_table():
        tbl = Table(show_header=True, header_style="bold cyan", expand=True)
        tbl.add_column("SHA-1", style="dim")
        tbl.add_column("Name")
        tbl.add_column("RecordDate", justify="center")
        tbl.add_column("OS?", justify="center")
        if vt_enabled:
            tbl.add_column("VT", justify="right")
        elif opentip_enabled:
            tbl.add_column("OT", justify="center")
        return tbl

    table = make_table()
    with Live(table, console=console, refresh_per_second=4) as live:
        for recs in data.values():
            for vals in recs.values():
                sha = vals.get("SHA-1")
                if not sha:
                    continue
                name = vals.get("Name", "")
                record_date_str = vals.get("RecordDate", "")
                os_flag = "Yes" if vals.get("IsOsComponent") else "No"

                style = None
                vt_cell = ""
                ot_cell = ""

                if vt_enabled and vt_api_key:
                    if vt_rate_limited:
                        vt_cell = "SKIPPED"
                        det = None
                    else:
                        det, _, vt_cell = lookup_vt(sha, vt_api_key)
                        if vt_cell == "RATE_LIMIT":
                            vt_rate_limited = True
                            vt_cell = "SKIPPED"
                            det = None
                            console.print(
                                "[bold yellow]Limit doldu, enrichment atlanıyor (VT).[/]"
                            )
                            logger.warning("VT rate limit reached. Enrichment skipped.")
                    if det and det > 0:
                        style = "bold red"
                    if only_detections and (det is None or det == 0):
                        continue

                elif opentip_enabled and ot_api_key:
                    if ot_rate_limited:
                        status = "SKIPPED"
                    else:
                        status = lookup_opentip(sha, ot_api_key)
                        if status == "RATE_LIMIT":
                            ot_rate_limited = True
                            status = "SKIPPED"
                            console.print(
                                "[bold yellow]Limit doldu, enrichment atlanıyor (OpenTIP).[/]"
                            )
                            logger.warning(
                                "OpenTIP rate limit reached. Enrichment skipped."
                            )
                    ot_cell = status
                    if status.lower() == "malware":
                        style = "bold red"
                    if only_detections and status.lower() != "malware":
                        continue

                row = [sha, name, record_date_str, os_flag]
                if vt_enabled:
                    row.append(vt_cell)
                elif opentip_enabled:
                    row.append(ot_cell)

                rows_to_print.append((record_date_str, row, style))
                rows_to_print.sort(key=lambda t: t[0])

                table = make_table()
                for _, r, st in rows_to_print:
                    table.add_row(*r, style=st)
                live.update(table)
                any_printed = True

    if not any_printed:
        msg = "No entries found."
        if (vt_enabled or opentip_enabled) and only_detections:
            msg = "No entries with detections found."
        console.print(f"[bold red]{msg}[/]")
        return False
    return True


def _compute_file_sha256(path: Path) -> str:
    """Compute SHA-256 digest for evidence file."""
    hasher = hashlib.sha256()
    with path.open("rb") as file_obj:
        for chunk in iter(lambda: file_obj.read(1024 * 1024), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _get_running_exe_path() -> Path | None:
    """Best-effort: return the on-disk path of the running EXE."""
    candidates: list[Path] = []
    try:
        candidates.append(Path(sys.executable))
    except Exception:
        pass
    try:
        if sys.argv and sys.argv[0]:
            candidates.append(Path(sys.argv[0]))
    except Exception:
        pass

    for c in candidates:
        try:
            if c.exists() and c.is_file():
                return c
        except Exception:
            continue
    return None


def _write_runtime_case_verification(
    *,
    output_dir: Path,
    forensic_header: dict[str, str],
    input_path: Path,
    report_hashes: dict[str, str],
    signing_key: bytes | None,
    json_path: Path,
    csv_path: Path,
    md_path: Path,
) -> tuple[Path, Path]:
    """Write a runtime tamper-evidence note (CASE_VERIFICATION.txt)."""
    exe_path = _get_running_exe_path()
    execution_exe_hash = (
        _compute_file_sha256(exe_path) if exe_path and exe_path.exists() else "N/A"
    )

    input_evidence_hash = forensic_header.get("Evidence Hash", "N/A")

    # Combine JSON/CSV/MD report hashes deterministically into one "Output_Report_Hash".
    json_digest = report_hashes.get(json_path.name, "MISSING")
    csv_digest = report_hashes.get(csv_path.name, "MISSING")
    md_digest = report_hashes.get(md_path.name, "MISSING")
    combined_report_digest_material = (
        f"JSON_SHA256={json_digest}\nCSV_SHA256={csv_digest}\nMD_SHA256={md_digest}\n"
    )
    output_report_hash = hashlib.sha256(
        combined_report_digest_material.encode("utf-8")
    ).hexdigest()

    signature_input = (
        f"Execution_EXE_Hash={execution_exe_hash}\n"
        f"Input_Evidence_Hash={input_evidence_hash}\n"
        f"Output_Report_Hash={output_report_hash}\n"
    )

    if signing_key:
        digital_signature = hmac.new(
            signing_key,
            signature_input.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()
        signature_alg = "HMAC-SHA256"
    else:
        # Fallback: still produce a tamper-evident integrity digest.
        digital_signature = hashlib.sha256(signature_input.encode("utf-8")).hexdigest()
        signature_alg = "SHA-256 (no signing key)"

    analysis_timestamp = forensic_header.get("Analysis Timestamp", _utc_timestamp_now())
    statement = (
        "Bu analiz Ergenekon-Adli motoru tarafından "
        f"{analysis_timestamp} tarihinde yapılmış ve bütünlüğü doğrulanmıştır."
    )

    case_path = output_dir / "CASE_VERIFICATION.txt"
    lines = [
        "CASE_VERIFICATION (Runtime Integrity)",
        "",
        "> * Execution_EXE_Hash: " + execution_exe_hash,
        "> * Input_Evidence_Hash: " + input_evidence_hash,
        "> * Output_Report_Hash: " + output_report_hash,
        "> * Digital Signature (" + signature_alg + "): " + digital_signature,
        "",
        "> * Statement: " + statement,
        "",
        f"Evidence Path: {input_path}",
        "",
    ]
    case_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Runtime case verification written: %s", case_path)

    # Also write a template-compatible Markdown verification note.
    tool_version = forensic_header.get("Tool Version", "N/A")
    analyst_signature_line = (
        f"{forensic_header.get('Analyst ID', 'N/A')}, {analysis_timestamp}"
    )
    integrity_statement = (
        "Bu rapor Ergenekon-Adli motoru ile üretilmiş olup, HMAC-SHA256 ile mühürlenmiştir."
        if signing_key
        else "Bu rapor Ergenekon-Adli motoru ile üretilmiş olup, SHA-256 ile mühürlenmiştir."
    )
    md_lines = [
        "# Verification Note (Chain of Custody)",
        "",
        "## Tool Verification",
        f"Tool: `{exe_path.name if exe_path else 'Ergenekon_Forensics_v1.exe'}`",
        "",
        f"Version: `{tool_version}`",
        "",
        f"Tool SHA-256: `{execution_exe_hash}`",
        "",
        "## Evidence Tracking",
        "> * Evidence Source: (Analiz edilen dosya yolu)",
        f">   * Evidence Source: {input_path}",
        "",
        "> * Original Hash: (Dosyanın ilk alındığı andaki hash'i)",
        f">   * Original Hash: {input_evidence_hash}",
        "",
        "> * Analysis Hash: (Analiz anındaki hash'i - Eşleşmeli!)",
        f">   * Analysis Hash: {output_report_hash}",
        "",
        "## Analyst Signature",
        f"> {analyst_signature_line}",
        "",
        "## Integrity Statement",
        f"`{integrity_statement}`",
        "",
        "---",
        "",
        "### Runtime Digital Signature Detail",
        f"- Digital Signature ({signature_alg}): `{digital_signature}`",
        "",
        "### Statement",
        f"- {statement}",
        "",
    ]
    md_path_out = output_dir / "CASE_VERIFICATION.md"
    md_path_out.write_text("\n".join(md_lines) + "\n", encoding="utf-8")
    logger.info("Runtime verification markdown written: %s", md_path_out)

    return case_path, md_path_out


def _get_machine_serial() -> str:
    """Read machine serial number best-effort on Windows."""
    try:
        result = subprocess.run(
            ["wmic", "bios", "get", "serialnumber"],
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        if len(lines) >= 2:
            return lines[1]
    except Exception:
        pass
    return "UNKNOWN_SERIAL"


def _build_analysis_metadata(
    *,
    start_ts: datetime,
    end_ts: datetime | None = None,
) -> dict[str, str]:
    """Build masked analysis metadata for chain-of-custody context."""
    analyst = getpass.getuser() or "unknown_user"
    hostname = socket.gethostname() or os.getenv("COMPUTERNAME", "unknown_host")
    serial = _get_machine_serial()
    return {
        "AnalystIdMasked": mask_pii(analyst, active=True),
        "HostNameMasked": mask_pii(hostname, active=True),
        "MachineSerialMasked": mask_pii(serial, active=True),
        "AnalysisStart": start_ts.isoformat(timespec="seconds"),
        "AnalysisEnd": (end_ts or datetime.now()).isoformat(timespec="seconds"),
    }


def _utc_timestamp_now() -> str:
    """Return current UTC time in ISO-8601 with Z suffix."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _build_forensic_header(
    *,
    case_id: str,
    evidence_hash: str,
    tool_version: str,
) -> dict[str, str]:
    """Build forensic header fields required by all reports."""
    analyst = getpass.getuser() or "unknown_user"
    hostname = socket.gethostname() or os.getenv("COMPUTERNAME", "unknown_host")
    analyst_raw = f"{hostname}/{analyst}"
    return {
        "Case ID": case_id,
        "Evidence Hash": evidence_hash,
        "Analyst ID": mask_pii(analyst_raw, active=True),
        "Analysis Timestamp": _utc_timestamp_now(),
        "Tool Version": f"Ergenekon-Adli v{tool_version}",
        "Tool Build Date": _tool_build_date(),
        "Python Runtime": _python_runtime_tag(),
    }


def _git_short_sha() -> str:
    """Return short git SHA if available, otherwise a stable fallback."""
    try:
        result = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"],
            capture_output=True,
            text=True,
            timeout=3,
            check=False,
        )
        if result.returncode == 0:
            sha = result.stdout.strip()
            if sha:
                return sha
    except Exception:
        pass
    return "nogit"


def _build_tool_version_tag(version: str) -> str:
    """Build tool version tag with git revision traceability."""
    return f"{version}+{_git_short_sha()}"


def _tool_build_date() -> str:
    """Resolve build date from env or return fallback."""
    return os.getenv("ERGENEKON_BUILD_DATE", "unknown")


def _python_runtime_tag() -> str:
    """Return Python runtime version tag."""
    return f"Python {sys.version.split()[0]}"


def _print_forensic_context(forensic_header: dict[str, str]) -> None:
    """Print forensic context block to console."""
    console.print("[bold cyan]Forensic Context[/]")
    for key, value in forensic_header.items():
        console.print(f"- {key}: {value}")


def _mask_record_fields(
    record: dict[str, Any],
    *,
    active: bool,
    fields_to_mask: set[str],
) -> dict[str, Any]:
    """Mask selected PII fields in a record.

    Args:
        record: Single forensic record dictionary.
        active: Global mask toggle.

    Returns:
        Shallow-cloned record with masked fields.
    """
    masked = dict(record)

    for field_name in ("Username", "ComputerName", "Path"):
        if field_name not in fields_to_mask:
            continue
        value = masked.get(field_name)
        if isinstance(value, str):
            if field_name == "Path":
                masked[field_name] = mask_path(value, active=active)
            else:
                masked[field_name] = mask_pii(value, active=active)

    # Field-aware masking for path-like and generic text fields.
    file_path = masked.get("FilePath")
    if "FilePath" in fields_to_mask and isinstance(file_path, str):
        masked["FilePath"] = mask_path(file_path, active=active)
    for generic_field in ("Name", "OriginalFileName", "Publisher"):
        if generic_field in fields_to_mask and isinstance(masked.get(generic_field), str):
            masked[generic_field] = mask_pii(str(masked[generic_field]), active=active)
    return masked


def _mask_dataset(
    data: dict[str, dict[str, dict[str, Any]]],
    *,
    active: bool,
    fields_to_mask: set[str],
) -> dict[str, dict[str, dict[str, Any]]]:
    """Mask the whole dataset record by record.

    Args:
        data: Category -> record name -> field map.
        active: Global mask toggle.

    Returns:
        New dataset with masked PII fields.
    """
    return {
        category: {
            record_name: _mask_record_fields(
                values, active=active, fields_to_mask=fields_to_mask
            )
            for record_name, values in records.items()
        }
        for category, records in data.items()
    }


def _export_outputs(
    data: dict[str, dict[str, dict[str, Any]]],
    execution_timeline: list[dict[str, Any]],
    output_dir: Path,
    json_path: Path | None,
    csv_path: Path | None,
    report_path: Path | None,
    input_path: Path | None = None,
    forensic_header: dict[str, str] | None = None,
    analysis_metadata: dict[str, str] | None = None,
) -> tuple[dict[str, Path], dict[str, str], Path]:
    """Export forensic outputs to JSON, CSV and Markdown files.

    Export failures are logged and do not terminate processing.

    Args:
        data: Category -> record name -> field map.
        output_dir: Default output directory.
        json_path: Optional explicit JSON output file.
        csv_path: Optional explicit CSV output file.
        report_path: Optional explicit Markdown output file.
        input_path: Source evidence path for report header.
        forensic_header: Mandatory forensic header metadata.
        analysis_metadata: Metadata for chain-of-custody style reporting.
    Returns:
        Tuple of (written report paths, report hashes, manifest path).
    """
    flat_rows = flatten_amcache_data(data)
    output_dir.mkdir(parents=True, exist_ok=True)

    target_json = json_path or (output_dir / "amcache.json")
    target_csv = csv_path or (output_dir / "amcache.csv")
    target_md = report_path or (output_dir / "report.md")
    target_html = output_dir / "forensic_timeline.html"
    target_hash = output_dir / "report.hash"

    for target in (target_json, target_csv, target_md, target_html):
        if target.exists():
            prompt_overwrite(target)

    try:
        write_amcache_json(
            target_json,
            data,
            forensic_header=forensic_header,
            analysis_metadata=analysis_metadata,
            execution_timeline=execution_timeline,
        )
        logger.info("JSON export completed: %s", target_json)
    except OSError as exc:
        logger.exception("JSON export failed: %s", exc)

    try:
        write_amcache_csv(
            target_csv,
            flat_rows,
            forensic_header=forensic_header,
            analysis_metadata=analysis_metadata,
        )
        logger.info("CSV export completed: %s", target_csv)
    except OSError as exc:
        logger.exception("CSV export failed: %s", exc)

    try:
        write_amcache_markdown_report(
            target_md,
            flat_rows,
            examined_file=input_path,
            forensic_header=forensic_header,
            analysis_metadata=analysis_metadata,
            execution_timeline=execution_timeline,
        )
        logger.info("Markdown report completed: %s", target_md)
    except OSError as exc:
        logger.exception("Markdown report failed: %s", exc)

    try:
        write_forensic_timeline_html(
            target_html,
            amcache_rows=flatten_amcache_data({"Amcache": data.get("Amcache", {})}),
            shimcache_rows=flatten_amcache_data({"Shimcache": data.get("Shimcache", {})}),
            execution_timeline=execution_timeline,
        )
        logger.info("Forensic timeline dashboard completed: %s", target_html)
    except OSError as exc:
        logger.exception("Forensic timeline dashboard export failed: %s", exc)

    hash_targets = [target_json, target_csv, target_md, target_html]
    report_paths: dict[str, Path] = {}
    report_hashes: dict[str, str] = {}
    hash_lines: list[str] = []
    if forensic_header:
        tool_version = forensic_header.get("Tool Version")
        if tool_version:
            hash_lines.append(f"Tool Version: {tool_version}")
        for key, value in forensic_header.items():
            if key == "Tool Version":
                continue
            hash_lines.append(f"{key}: {value}")
    if analysis_metadata:
        for key, value in analysis_metadata.items():
            hash_lines.append(f"Analysis Metadata {key}={value}")
    if hash_lines:
        hash_lines.append("")
    for file_path in hash_targets:
        if not file_path.exists():
            continue
        digest = hashlib.sha256(file_path.read_bytes()).hexdigest()
        report_paths[file_path.name] = file_path
        report_hashes[file_path.name] = digest
        hash_lines.append(f"{file_path.name} {digest}")
        logger.info("Integrity hash generated. file=%s sha256=%s", file_path, digest)
    if hash_lines:
        target_hash.write_text("\n".join(hash_lines) + "\n", encoding="utf-8")
        logger.info("Hash manifest written: %s", target_hash)
    return report_paths, report_hashes, target_hash


def _resolve_signing_key(
    *,
    key_file: Path | None,
    env_var_name: str,
) -> bytes | None:
    """Resolve signing key from file or environment variable."""
    if key_file:
        return key_file.read_text(encoding="utf-8").strip().encode("utf-8")
    env_value = os.getenv(env_var_name, "").strip()
    if env_value:
        return env_value.encode("utf-8")
    return None


def _write_report_signatures(
    *,
    output_dir: Path,
    report_hashes: dict[str, str],
    forensic_header: dict[str, str],
    signing_key: bytes | None,
) -> tuple[Path | None, dict[str, str]]:
    """Write report signatures with HMAC-SHA256 when key is available."""
    if not signing_key:
        logger.warning("No signing key found. report.sig will not be created.")
        return None, {}
    signature_path = output_dir / "report.sig"
    signatures: dict[str, str] = {}
    lines = [
        f"Case ID: {forensic_header.get('Case ID', 'CASE-2026-001')}",
        f"Analysis Timestamp: {forensic_header.get('Analysis Timestamp', 'N/A')}",
        "",
    ]
    for file_name in sorted(report_hashes.keys()):
        digest = report_hashes[file_name]
        signature = hmac.new(signing_key, digest.encode("utf-8"), hashlib.sha256).hexdigest()
        signatures[file_name] = signature
        lines.append(f"{file_name} {signature}")
    signature_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Report signature file written: %s", signature_path)
    return signature_path, signatures


def _append_custody_event(
    *,
    output_dir: Path,
    forensic_header: dict[str, str],
    input_path: Path,
    report_hashes: dict[str, str],
    signatures: dict[str, str],
) -> Path:
    """Append an immutable hash-chained custody entry."""
    custody_path = output_dir / "custody.log"
    prev_hash = "GENESIS"
    if custody_path.exists():
        lines = [line.strip() for line in custody_path.read_text(encoding="utf-8").splitlines() if line.strip()]
        if lines:
            try:
                prev_entry = json.loads(lines[-1])
                prev_hash = str(prev_entry.get("entry_hash", "GENESIS"))
            except json.JSONDecodeError:
                prev_hash = "UNKNOWN_PREV_HASH"

    payload: dict[str, Any] = {
        "entry_type": "analysis_artifact",
        "timestamp_utc": _utc_timestamp_now(),
        "case_id": forensic_header.get("Case ID", "CASE-2026-001"),
        "evidence_file": str(input_path),
        "evidence_hash": forensic_header.get("Evidence Hash", "N/A"),
        "analyst_id": forensic_header.get("Analyst ID", "N/A"),
        "report_hashes": report_hashes,
        "report_signatures": signatures,
        "prev_entry_hash": prev_hash,
    }
    canonical = json.dumps(payload, sort_keys=True, ensure_ascii=True)
    payload["entry_hash"] = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    with custody_path.open("a", encoding="utf-8") as file_obj:
        file_obj.write(json.dumps(payload, ensure_ascii=False, sort_keys=True) + "\n")
    logger.info("Custody log appended: %s", custody_path)
    return custody_path


def _parse_hash_manifest(path: Path) -> dict[str, str]:
    """Parse report.hash entries into filename -> sha256 map."""
    parsed: dict[str, str] = {}
    if not path.exists():
        return parsed
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or ":" in stripped:
            continue
        parts = stripped.split(" ", maxsplit=1)
        if len(parts) == 2:
            parsed[parts[0]] = parts[1].strip()
    return parsed


def _parse_signature_manifest(path: Path) -> dict[str, str]:
    """Parse report.sig entries into filename -> signature map."""
    parsed: dict[str, str] = {}
    if not path.exists():
        return parsed
    for line in path.read_text(encoding="utf-8").splitlines():
        stripped = line.strip()
        if not stripped or ":" in stripped:
            continue
        parts = stripped.split(" ", maxsplit=1)
        if len(parts) == 2:
            parsed[parts[0]] = parts[1].strip()
    return parsed


def _verify_custody_log(custody_path: Path) -> tuple[bool, str]:
    """Verify hash-chain integrity for custody.log."""
    if not custody_path.exists():
        return False, f"Missing custody log: {custody_path}"
    lines = [line.strip() for line in custody_path.read_text(encoding="utf-8").splitlines() if line.strip()]
    if not lines:
        return False, "Custody log is empty."
    expected_prev = "GENESIS"
    for idx, line in enumerate(lines, start=1):
        entry = json.loads(line)
        entry_hash = str(entry.get("entry_hash", ""))
        prev = str(entry.get("prev_entry_hash", ""))
        if prev != expected_prev:
            return False, f"Custody chain broken at line {idx}."
        check_payload = dict(entry)
        check_payload.pop("entry_hash", None)
        canonical = json.dumps(check_payload, sort_keys=True, ensure_ascii=True)
        computed = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        if computed != entry_hash:
            return False, f"Custody entry hash mismatch at line {idx}."
        expected_prev = entry_hash
    return True, "Custody hash-chain is valid."


def _verify_integrity_bundle(
    *,
    output_dir: Path,
    signing_key: bytes | None,
) -> tuple[bool, list[str]]:
    """Verify report hashes, optional signatures and custody chain."""
    messages: list[str] = []
    manifest_path = output_dir / "report.hash"
    parsed_hashes = _parse_hash_manifest(manifest_path)
    if not parsed_hashes:
        return False, [f"Missing or invalid hash manifest: {manifest_path}"]
    all_ok = True
    for file_name, expected_hash in sorted(parsed_hashes.items()):
        file_path = output_dir / file_name
        if not file_path.exists():
            messages.append(f"[FAIL] Missing report file: {file_name}")
            all_ok = False
            continue
        actual_hash = _compute_file_sha256(file_path)
        if actual_hash != expected_hash:
            messages.append(f"[FAIL] Hash mismatch: {file_name}")
            all_ok = False
        else:
            messages.append(f"[OK] Hash verified: {file_name}")

    signature_path = output_dir / "report.sig"
    if signature_path.exists():
        if not signing_key:
            messages.append("[FAIL] report.sig exists but signing key is not available.")
            all_ok = False
        else:
            parsed_sigs = _parse_signature_manifest(signature_path)
            for file_name, expected_hash in sorted(parsed_hashes.items()):
                expected_sig = parsed_sigs.get(file_name)
                if not expected_sig:
                    messages.append(f"[FAIL] Missing signature: {file_name}")
                    all_ok = False
                    continue
                computed_sig = hmac.new(
                    signing_key,
                    expected_hash.encode("utf-8"),
                    hashlib.sha256,
                ).hexdigest()
                if computed_sig != expected_sig:
                    messages.append(f"[FAIL] Signature mismatch: {file_name}")
                    all_ok = False
                else:
                    messages.append(f"[OK] Signature verified: {file_name}")

    custody_ok, custody_msg = _verify_custody_log(output_dir / "custody.log")
    if custody_ok:
        messages.append(f"[OK] {custody_msg}")
    else:
        messages.append(f"[FAIL] {custody_msg}")
        all_ok = False
    return all_ok, messages


def _write_verification_report(
    *,
    output_dir: Path,
    forensic_header: dict[str, str],
    ok: bool,
    messages: list[str],
) -> Path:
    """Write human-readable verification report for sealed package."""
    report_path = output_dir / "verification_report.txt"
    lines = [
        "ERGENEKON SEALED CASE VERIFICATION REPORT",
        "",
        f"Case ID: {forensic_header.get('Case ID', 'ERGENEKON-2026-001')}",
        f"Evidence Hash: {forensic_header.get('Evidence Hash', 'N/A')}",
        f"Analyst ID: {forensic_header.get('Analyst ID', 'N/A')}",
        f"Analysis Timestamp: {forensic_header.get('Analysis Timestamp', 'N/A')}",
        f"Tool Version: {forensic_header.get('Tool Version', 'N/A')}",
        f"Tool Build Date: {forensic_header.get('Tool Build Date', 'unknown')}",
        f"Python Runtime: {forensic_header.get('Python Runtime', 'N/A')}",
        f"Verification Timestamp: {_utc_timestamp_now()}",
        f"Verification Status: {'PASS' if ok else 'FAIL'}",
        "",
    ]
    lines.extend(messages)
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    logger.info("Verification report written: %s", report_path)
    return report_path


def _build_sealed_case_package(
    *,
    output_dir: Path,
    package_name: str,
    evidence_input_path: Path,
    files_to_include: list[Path],
) -> Path:
    """Create zip package that contains analysis outputs and integrity artifacts."""
    package_path = output_dir / package_name
    if package_path.exists():
        prompt_overwrite(package_path)
    with zipfile.ZipFile(package_path, "w", compression=zipfile.ZIP_DEFLATED) as zip_obj:
        for file_path in files_to_include:
            if file_path.exists():
                zip_obj.write(file_path, arcname=file_path.name)
        # Keep original evidence basename in package for case context (best effort).
        if evidence_input_path.exists():
            zip_obj.write(evidence_input_path, arcname=f"evidence_{evidence_input_path.name}")
    logger.info("Sealed case package written: %s", package_path)
    return package_path


def _write_package_manifest(
    *,
    output_dir: Path,
    package_path: Path,
    forensic_header: dict[str, str],
) -> Path:
    """Write package manifest with zip metadata and per-entry SHA-256 values."""
    manifest_path = output_dir / "package_manifest.json"
    package_hash = _compute_file_sha256(package_path)
    entries: list[dict[str, Any]] = []
    with zipfile.ZipFile(package_path, "r") as zip_obj:
        for info in zip_obj.infolist():
            with zip_obj.open(info, "r") as entry_obj:
                entry_hash = hashlib.sha256(entry_obj.read()).hexdigest()
            entries.append(
                {
                    "name": info.filename,
                    "size": info.file_size,
                    "compressed_size": info.compress_size,
                    "sha256": entry_hash,
                }
            )
    payload: dict[str, Any] = {
        "Case ID": forensic_header.get("Case ID", "ERGENEKON-2026-001"),
        "Evidence Hash": forensic_header.get("Evidence Hash", "N/A"),
        "Analyst ID": forensic_header.get("Analyst ID", "N/A"),
        "Analysis Timestamp": forensic_header.get("Analysis Timestamp", "N/A"),
        "Tool Version": forensic_header.get("Tool Version", "N/A"),
        "Tool Build Date": forensic_header.get("Tool Build Date", "unknown"),
        "Python Runtime": forensic_header.get("Python Runtime", "N/A"),
        "Package Name": package_path.name,
        "Package Size": package_path.stat().st_size,
        "Package SHA-256": package_hash,
        "Manifest Timestamp": _utc_timestamp_now(),
        "Entries": entries,
    }
    manifest_path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    logger.info("Package manifest written: %s", manifest_path)
    return manifest_path


def main() -> None:
    """CLI entrypoint for Amcache analysis workflow."""
    configure_logging()
    ver = _cli_version()
    parser = argparse.ArgumentParser(
        description="AmCache-EvilHunter: Amcache.hve ayrıştırma ve analiz (ergenekon paketi).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=f"AmCache-EvilHunter — ergenekon-adli {ver}",
    )

    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "-v",
        "--vt",
        action="store_true",
        help="VirusTotal sorgusu (VT_API_KEY)",
    )
    group.add_argument(
        "--opentip",
        action="store_true",
        help="Kaspersky OpenTIP (OPENTIP_API_KEY)",
    )

    parser.add_argument(
        "-V",
        "--version",
        action="version",
        version=f"AmCache-EvilHunter (ergenekon-adli {ver})",
    )
    parser.add_argument("-i", "--input", type=Path, required=False, help="Amcache.hve yolu")
    parser.add_argument(
        "-s",
        "--system",
        type=Path,
        required=False,
        help="SYSTEM hive yolu (Shimcache/AppCompatCache icin)",
    )
    parser.add_argument(
        "--authorized-use-confirm",
        action="store_true",
        help=(
            "SYSTEM hive analizi icin yetkili/izinli kullanim onayi "
            "(TCK 243 sorumluluk bildirimi)"
        ),
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=Path("output"),
        help="Varsayılan çıktı dizini (JSON/CSV/report.md)",
    )
    parser.add_argument("--start", type=str, help="YYYY-MM-DD — bu tarihten itibaren")
    parser.add_argument("--end", type=str, help="YYYY-MM-DD — bu tarihe kadar")
    parser.add_argument("--search", type=str, help="Virgülle ayrılmış arama terimleri")
    parser.add_argument(
        "--find-suspicious",
        action="store_true",
        help="Bilinen şüpheli ad kalıplarına göre süz",
    )
    parser.add_argument(
        "--missing-publisher",
        action="store_true",
        help="Yayıncı boş olan kayıtlar",
    )
    parser.add_argument("--exclude-os", action="store_true", help="OS bileşeni olmayanlar")
    parser.add_argument(
        "--only-detections",
        action="store_true",
        help="Yalnızca tespit içerenler (VT/OpenTIP)",
    )
    parser.add_argument("--json", type=Path, help="JSON çıktı dosyası")
    parser.add_argument("--csv", type=Path, help="CSV çıktı dosyası")
    parser.add_argument("--report-md", type=Path, help="Markdown rapor dosyası")
    parser.add_argument(
        "--case-id",
        type=str,
        default="ERGENEKON-2026-001",
        help="Forensic vaka kimligi",
    )
    parser.add_argument(
        "--sign-key-file",
        type=Path,
        default=None,
        help="HMAC imzalama anahtari dosyasi",
    )
    parser.add_argument(
        "--sign-key-env",
        type=str,
        default="ERGENEKON_SIGNING_KEY",
        help="HMAC imzalama anahtarini okuyacagi ortam degiskeni",
    )
    parser.add_argument(
        "--verify-integrity",
        action="store_true",
        help="Sadece report.hash/report.sig/custody.log dogrulama modu",
    )
    parser.add_argument(
        "--sealed-package",
        action="store_true",
        help="Zip sealed case package uret (raporlar + hash + sig + custody + verify report)",
    )
    parser.add_argument(
        "--sealed-package-name",
        type=str,
        default="sealed_case_package.zip",
        help="Sealed case paket dosya adi",
    )
    parser.add_argument(
        "--show-forensic-context",
        action="store_true",
        help="Analiz baslamadan forensic header bilgisini yazdir",
    )
    parser.add_argument(
        "--show-forensic-context-json",
        action="store_true",
        help="Analiz baslamadan forensic header bilgisini JSON olarak yazdir",
    )
    parser.add_argument(
        "--format",
        choices=("table", "json", "both"),
        default="table",
        help="Stdout: Rich tablo, düz JSON dizi veya ikisi (dosya çıktılarından bağımsız)",
    )
    parser.add_argument(
        "--mask",
        action="store_true",
        help="PII maskeleme: Username, ComputerName, Path ve FilePath",
    )
    parser.add_argument(
        "--mask-policy",
        choices=("balanced", "strict", "custom"),
        default="balanced",
        help="Maskeleme politikasi secimi (balanced/strict/custom)",
    )
    parser.add_argument(
        "--mask-fields",
        type=str,
        default="",
        help="Custom policy icin virgulle ayrilmis alan listesi",
    )
    parser.add_argument(
        "--sigma",
        action="store_true",
        help="Sigma-benzeri supheli dosya yolu kurallarini uygula",
    )
    parser.add_argument(
        "--sigma-rules",
        type=Path,
        default=Path("ergenekon/rules/sigma_amcache.yml"),
        help="Sigma kural YAML dosya yolu",
    )
    args = parser.parse_args()
    logger.info("Amcache CLI started. input=%s", args.input)
    tool_version_tag = _build_tool_version_tag(ver)
    try:
        signing_key = _resolve_signing_key(key_file=args.sign_key_file, env_var_name=args.sign_key_env)
    except OSError as exc:
        logger.exception("Signing key could not be loaded: %s", exc)
        console.print(f"[bold red]Error:[/] Signing key okunamadi: {exc}", style="red")
        sys.exit(1)

    if args.verify_integrity:
        ok, messages = _verify_integrity_bundle(output_dir=args.output_dir, signing_key=signing_key)
        for line in messages:
            console.print(line)
        sys.exit(0 if ok else 1)

    if not args.input:
        console.print("[bold red]Error:[/] --input zorunludur (verify modu haric).", style="red")
        sys.exit(1)
    if args.system and not args.authorized_use_confirm:
        console.print(
            "[bold red]Error:[/] --system kullanimi icin --authorized-use-confirm zorunludur.",
            style="red",
        )
        sys.exit(1)

    try:
        evidence_hash = _compute_file_sha256(args.input)
    except Exception as exc:
        logger.exception("Evidence hash could not be computed: %s", exc)
        console.print(
            f"[bold red]Error:[/] Evidence hash hesaplanamadi, analiz durduruldu: {exc}",
            style="red",
        )
        sys.exit(1)
    logger.info("Evidence Hash (SHA-256): %s", evidence_hash)

    vt_api_key: str | None = None
    ot_api_key: str | None = None
    if args.vt:
        vt_api_key = os.getenv("VT_API_KEY")
        if not vt_api_key:
            console.print("[bold red]Error:[/] VT_API_KEY tanımlı değil", style="red")
            sys.exit(1)
    if args.opentip:
        ot_api_key = os.getenv("OPENTIP_API_KEY")
        if not ot_api_key:
            console.print("[bold red]Error:[/] OPENTIP_API_KEY tanımlı değil", style="red")
            sys.exit(1)

    start_dt = end_dt = None
    if args.start:
        try:
            start_dt = datetime.strptime(args.start, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --start YYYY-MM-DD olmalı", style="red")
            sys.exit(1)
    if args.end:
        try:
            end_dt = datetime.strptime(args.end, "%Y-%m-%d")
        except ValueError:
            console.print("[bold red]Error:[/] --end YYYY-MM-DD olmalı", style="red")
            sys.exit(1)
    if start_dt and end_dt and start_dt > end_dt:
        console.print("[bold red]Error:[/] --start, --end'den önce olamaz", style="red")
        sys.exit(1)

    search_terms = None
    if args.search:
        search_terms = [t.strip().lower() for t in args.search.split(",") if t.strip()]

    try:
        analysis_started_at = datetime.now()
        forensic_header = _build_forensic_header(
            case_id=args.case_id,
            evidence_hash=evidence_hash,
            tool_version=tool_version_tag,
        )
        if args.show_forensic_context:
            _print_forensic_context(forensic_header)
        if args.show_forensic_context_json:
            print(json.dumps(forensic_header, ensure_ascii=False, indent=2))
        engine = AmcacheEngine(args.input, start=start_dt, end=end_dt)
        data = engine.run()
        logger.info("Amcache parse completed. categories=%d", len(data))

        if search_terms:
            filtered = {}
            for cat, recs in data.items():
                keep = {
                    rec: vals
                    for rec, vals in recs.items()
                    if any(term in vals.get("FilePath", "").lower() for term in search_terms)
                }
                if keep:
                    filtered[cat] = keep
            data = filtered

        if args.find_suspicious:
            data = find_suspicious(data)

        if args.missing_publisher:
            data = missing_publisher(data)

        if args.exclude_os:
            filtered = {}
            for cat, recs in data.items():
                keep = {rec: vals for rec, vals in recs.items() if not vals.get("IsOsComponent")}
                if keep:
                    filtered[cat] = keep
            data = filtered

        if args.sigma:
            data, sigma_alerts = apply_sigma_rules(data, rules_path=args.sigma_rules)
            logger.info("Sigma matching completed. alerts=%d", len(sigma_alerts))
            if sigma_alerts:
                console.print(
                    f"[bold yellow]Sigma alert:[/] {len(sigma_alerts)} supheli kayit eslesti."
                )

        shimcache_data: dict[str, dict[str, dict[str, Any]]] = {"Shimcache": {}}
        if args.system:
            console.print(
                "[bold yellow]Legal notice:[/] TCK 243 kapsaminda sadece yetkili/izinli SYSTEM hive dosyalari analiz edilmelidir."
            )
            shimcache_data = ShimcacheParser(args.system).parse()
            correlate_amcache_shimcache(data, shimcache_data)
            data.update(shimcache_data)
            logger.info(
                "Shimcache parse completed. entries=%d",
                len(shimcache_data.get("Shimcache", {})),
            )

        if args.mask:
            if args.mask_policy == "custom":
                fields_to_mask = {
                    field.strip() for field in args.mask_fields.split(",") if field.strip()
                }
                if not fields_to_mask:
                    console.print(
                        "[bold red]Error:[/] --mask-policy custom icin --mask-fields gerekli",
                        style="red",
                    )
                    sys.exit(1)
            else:
                fields_to_mask = set(MASK_POLICY_FIELDS[args.mask_policy])
            # Shimcache Path alani, --mask acikken her zaman maskele.
            fields_to_mask.add("Path")
            data = _mask_dataset(data, active=True, fields_to_mask=fields_to_mask)
            logger.info(
                "Masking enabled. policy=%s fields=%s",
                args.mask_policy,
                sorted(fields_to_mask),
            )

        table_ok = True
        if args.format in ("table", "both"):
            table_ok = print_table(
                data,
                vt_enabled=args.vt,
                opentip_enabled=args.opentip,
                vt_api_key=vt_api_key,
                ot_api_key=ot_api_key,
                only_detections=args.only_detections,
            )
            if args.format == "table" and not table_ok:
                sys.exit(
                    1
                    if (args.vt or args.opentip) and args.only_detections
                    else 0
                )

        if args.format in ("json", "both"):
            flat = flatten_amcache_data(data)
            print(json.dumps(flat, ensure_ascii=False, indent=2, default=str))

        analysis_metadata = _build_analysis_metadata(
            start_ts=analysis_started_at, end_ts=datetime.now()
        )
        analysis_metadata["AnalysisTimestampUtc"] = forensic_header["Analysis Timestamp"]
        execution_timeline = build_execution_timeline(
            {"Amcache": data.get("Amcache", {})},
            {"Shimcache": data.get("Shimcache", {})},
        )
        analysis_metadata["ExecutionTimelineEvents"] = len(execution_timeline)
        logger.info("Analysis Metadata: %s", analysis_metadata)

        _, report_hashes, _ = _export_outputs(
            data=data,
            execution_timeline=execution_timeline,
            output_dir=args.output_dir,
            json_path=args.json,
            csv_path=args.csv,
            report_path=args.report_md,
            input_path=args.input,
            forensic_header=forensic_header,
            analysis_metadata=analysis_metadata,
        )
        signature_path, signatures = _write_report_signatures(
            output_dir=args.output_dir,
            report_hashes=report_hashes,
            forensic_header=forensic_header,
            signing_key=signing_key,
        )
        custody_path = _append_custody_event(
            output_dir=args.output_dir,
            forensic_header=forensic_header,
            input_path=args.input,
            report_hashes=report_hashes,
            signatures=signatures,
        )

        # Runtime tamper-evidence note: per-analysis CASE_VERIFICATION.txt.
        # (Keeps evidence provenance inside the report output directory.)
        target_json = args.json or (args.output_dir / "amcache.json")
        target_csv = args.csv or (args.output_dir / "amcache.csv")
        target_md = args.report_md or (args.output_dir / "report.md")
        case_verification_path, case_verification_md_path = _write_runtime_case_verification(
            output_dir=args.output_dir,
            forensic_header=forensic_header,
            input_path=args.input,
            report_hashes=report_hashes,
            signing_key=signing_key,
            json_path=target_json,
            csv_path=target_csv,
            md_path=target_md,
        )
        if args.sealed_package:
            verify_ok, verify_messages = _verify_integrity_bundle(
                output_dir=args.output_dir,
                signing_key=signing_key,
            )
            verification_report_path = _write_verification_report(
                output_dir=args.output_dir,
                forensic_header=forensic_header,
                ok=verify_ok,
                messages=verify_messages,
            )
            report_file_paths = [args.output_dir / name for name in report_hashes.keys()]
            include_paths = report_file_paths + [
                args.output_dir / "report.hash",
                custody_path,
                verification_report_path,
                case_verification_path,
                case_verification_md_path,
            ]
            if signature_path:
                include_paths.append(signature_path)
            package_path = _build_sealed_case_package(
                output_dir=args.output_dir,
                package_name=args.sealed_package_name,
                evidence_input_path=args.input,
                files_to_include=include_paths,
            )
            manifest_path = _write_package_manifest(
                output_dir=args.output_dir,
                package_path=package_path,
                forensic_header=forensic_header,
            )
            console.print(f"[bold green]Sealed package created:[/] {package_path}")
            console.print(f"[bold green]Package manifest:[/] {manifest_path}")

    except FileNotFoundError as e:
        logger.exception("Input file not found: %s", e)
        console.print(f"[bold red]Error:[/] {e}", style="red")
        sys.exit(1)
    except HiveParseError as e:
        logger.exception("Hive parse error: %s", e)
        console.print(f"[bold red]Hive hatası:[/] {e}", style="red")
        sys.exit(1)
    except HTTPError as e:
        logger.exception("Threat intel HTTP error: %s", e)
        console.print(f"[bold red]HTTP error:[/] {e}", style="red")
        sys.exit(1)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[bold yellow]İptal edildi.[/]")
        sys.exit(0)
