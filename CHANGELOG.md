# Değişiklik günlüğü

## [1.3.1-tr] - 2026-03-26

### Ergenekon yerelleştirmesi
- Kurulum: Türkçe dil dosyası (`Turkish.isl`), uygulama adı **Ergenekon Adli Bilişim**, bileşen ve görev açıklamaları Türkçe.
- Kaynak dizini: `..\ftools` (depo köküne göreli); sabit `c:\ftools` kaldırıldı.
- TestDisk ve PhotoRec tek bileşende birleştirildi (`diskforensics\testdisk`).
- Sağ tık menü anahtarı `ergenekon_adli_bilisim` olarak güncellendi; dosya türü kayıtları `ErgenekonAdliBilisim.*` progID ile.
- Kök README ve `requirements.txt` depo içeriğiyle uyumlu hale getirildi.

### Python modüler paket (2026-03-26)
- `ergenekon/` paketi: `core/`, `parsers/`, `export/`, `utils/` (Amcache ayrıştırma, dışa aktarma, VT/OpenTIP, anonimleştirme, log).
- `pyproject.toml` (`ergenekon-adli`); kök `requirements.txt` → `pip install -e .`.
- `tools/amcache-evilhunter/amcache-evilhunter.py` CLI ince sarmalayıcıya indirildi.

### 0.2.0 — Kurumsal modülerleştirme
- **UserAssist:** `parsers/userassist.py`, `UserAssistEngine`, `uareport` / `python -m ergenekon.cli.userassist_cli`; tablo + JSON (`--format`), `--mask`, `--json-out` / `--csv`.
- **Amcache CLI:** `--format table|json|both`, `--mask`; `flatten_amcache_data` dışa aktarım.
- **KVKK:** `mask_kvkk_identifiers()` (User, Path, SID anahtarları); kök `amcache_evilhunter.py` / `uareport.py` → ince sarmalayıcı.
- **Bağımlılık:** `tabulate`. README’de TCK / KVKK referans tablosu.

### Maskeleme (KVKK / test)
- `ergenekon/utils/masker.py`: `mask_sensitive_data` (SHA-256 hex[:10]), `mask_ip`, `mask_sid`, yol ve serbest metin için IP/SID maskeleme, `mask_structure` ile dict/list alan maskeleme.

### 0.1.1 — AmcacheEngine ve konsol komutu
- `AmcacheEngine` (`ergenekon.core`): `AnalysisEngine` alt sınıfı, `run()` ayrıştırılmış + normalize veri döner.
- `[project.scripts]` → `amcache-evilhunter`; CLI `ergenekon/cli/amcache_cli.py` içinde; `-V` sürümü `importlib.metadata` ile paket sürümünden okunur.

### Yapı düzenlemesi (2026-03-26)
- `docs/help/help.html`: yardım dosyası `src/help` yerine `docs/help` altında (tek doğruluk kaynağı).
- `tools/amcache-evilhunter/`: Python aracı kökten `tools` altına taşındı.
- `scripts/prepare-ftools.ps1`: `docs` → `ftools\help` kopyası.
- `output/`: Inno `OutputDir`; `.gitignore` ile yoksayıldı.
- `SetupIconFile` ve PATH kaldırma hatası (`utilities\testdisk`) giderildi; TestDisk sabit exe kısayolları kaldırıldı.

## [1.3] - 2026-01-12

### Added
- API Monitor.
- ILSpy.
- mal_unpack.
- Foremost-NG.
- ImHex.
- CobaltStrikeScan.
- 7-Zip.
- Notepad++.
- SQLite command line.
- AmCache-EvilHunter.
- LogFileParser.
- SRUM-DUMP.

### Updates
- Major updates for various tools.
- x64dbg was moved to the Binary Analysis section.
- Hayabusa now includes rules from https://github.com/cristianzsh/k-evtrace/tree/main/rules.

## [1.2] - 2025-05-01

### Added
- Netcat (nc.exe).
- PPEE (puppy).
- radare2.
- scdbg.
- DB Browser for SQLite.
- TestDisk.
- WinPython.
  - bmc-tools.
  - pyinstxtractor.
  - pefile.
  - oletools.
- TrID.
- SrumECmd.
- SumECmd.
- WxTCmd.
- APT-Hunter.
- NetworkMiner.
- Bulk Extractor.
- OSFMount.
- CyberChef.

### Updates

- Major updates for various tools.

## [1.1] - 2024-01-24

### Added
- Hayabusa.
- Get-Hashes script.
- MemProcFS.
- Online search tools (Kaspersky, VirusTotal, MalwareBazaar, Hybrid Analysis).
- UPX.
- XVolkolak.
- The Sleuth Kit.
- BusyBox.
- dd.
- Timeline Explorer.
- $I Parse.

## [1.0] - 2023-12-23

- Initial version.
