# Project Revelare

Digital forensics and intelligence extraction: pull indicators of compromise from files and data sources, keep cases as metadata and findings, and leave the original documents where they are.

## Ingest and audit paths

New ingest does **not** keep a forensic copy under `cases/<case>/evidence/` or `extracted_files/`.

Each processed document is copied to a temp directory, hashed, parsed, then the temp copy is deleted (`try`/`finally`). Audit data is stored on the findings and in `cases/<case>/ingest_manifest.json`:

- `SourcePath` - original filesystem path (CLI/sync) or `upload://original-filename` (web upload)
- `SourceHash` - SHA-256 of the source file
- `SourceMtime` / timestamps - source file times and ingest time

CSV exports include `SourcePath` and `SourceHash` columns. The SQLite master DB stores the same fields on each indicator.

**Existing cases:** copies already sitting in `evidence/` or `extracted_files/` are left in place. Revelare does not mass-delete prior vault copies. Purge those directories yourself if you want them gone.

**Re-analysis:** for new ingest, re-analysis re-reads the original source path if it still exists. Web-only uploads have no original path, so re-upload to process again.

## How to run

Python 3.8+. Install dependencies with `pip install -r requirements.txt`. GeoLite2-City.mmdb and GeoLite2-ASN.mmdb in the project root are optional (IP enrichment).

### Web

```bash
python start.py
```

Choose option 1 (Web Interface). Open http://localhost:5000

You can also launch the CLI or onboarding wizard from the same menu.

### CLI

```bash
# Create a new case
python -m revelare.cli.revelare_cli --onboard

# Process files
python -m revelare.cli.revelare_cli -p "case_001" -f evidence.zip

# Sync cases from an external directory
python -m revelare.cli.revelare_cli --sync "C:\path\to\cases"

# Discover only (do not process files)
python -m revelare.cli.revelare_cli --sync "C:\path\to\cases" --sync-no-process

# Export / import a case
python -m revelare.cli.revelare_cli --export-case "case_name"
python -m revelare.cli.revelare_cli --export-case "case_name" --export-indicators-only
python -m revelare.cli.revelare_cli --import-case "path\to\export.zip"
```

Sync tracks processed files in `cases/.case_sync_cache.json` (delete it to force a full resync). Optional env: `REVELARE_EXTERNAL_CASES_DIR`, `REVELARE_SYNC_PROCESS_FILES`.

Web UI also has case import/export (dashboard Import Case; case management Export Case). Full export can include leftover `evidence/` / `extracted_files/` from older cases; indicators-only export is metadata and findings only.

### Docker

```bash
docker-compose up -d
# http://localhost:5000

docker-compose logs -f
docker-compose down

docker-compose exec revelare python -m revelare.cli.revelare_cli --onboard
```

Volumes: `./cases`, `./logs`, `./temp`. Copy `env.template` to `.env` for port/API keys. If port 5000 is taken, change the mapping in `docker-compose.yml`.

### Windows .exe

```batch
utilities\build_exe.bat
```

Output is `dist/ProjectRevelare.exe` (gitignored). Double-click to run; no Python needed on the target machine. Manual: `pyinstaller --clean revelare.spec`.

## What it does

- Stages a temp copy, extracts IOCs, records source path/hash, deletes the temp file
- Text, documents, email, archives, images, audio, video, and more
- IPs, domains, emails, cards, crypto addresses, and related indicators
- Optional GeoIP/ASN enrichment
- Case lifecycle, hash duplicate detection, external-directory sync
- HTML reports; JSON/CSV/warrant/portable export; optional Truleo conversion

## Identifier notes

- **Ingest:** temp-copy only. Findings keep `SourcePath` and `SourceHash`; the temp file is deleted.
- **Crypto:** checksummed BTC/ETH/XMR stay without nearby keywords. Matches inside URLs, emails, or path tokens are dropped. Encoded MIME image/binary bodies are skipped so photo payloads are not sliced into wallet-shaped tokens.
- **Names:** isolated title-case First Last (Jane Doe, Martin Brown) is kept with no legal-keyword gate. Email headers, salutations, investigator/role prefixes, hyphenated title slices, and spreadsheet/legal/marketing labels (Case No, Start Date, Coordinated Universal Time, Emergency Response, Coming Soon, and similar) are dropped. A synthetic 8-name warrant/email/CDR fixture in `tests/fixtures` is the precision/recall check.
- **Money pathways:** bank, fintech-app, and gambling brand names are per-case only and stay out of cross-case Link Analysis. Nearby `Payment_Tokens` (cashtag, handle, account/routing/last-4) are linkable.

## Project structure

```
project_revelare/
  revelare/         core, CLI, web, config
  utilities/        optional helpers (exe build, batch clean)
  requirements.txt
```

Case data, logs, temp files, GeoIP DBs, and build output stay out of git (see `.gitignore`).

## Support

Open an issue on GitHub: https://github.com/GeminoLibi/Project_Revelare
