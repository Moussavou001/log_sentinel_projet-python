# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

All commands must be run from `log_sentinel/` with the virtual environment activated (`env\Scripts\activate`).

```bash
# Interface web (recommandée)
streamlit run app.py

# Interface CLI
python main.py -f samples/sample_access.log
python main.py -f samples/sample_access.log --check-ip --bf-threshold 3 --scan-threshold 5
python main.py -f samples/sample_access.log --no-report --output-dir ./output

# Tests
python -m unittest discover -s tests -v

# Test d'un seul fichier
python -m unittest tests.test_detector -v
python -m unittest tests.test_statistics -v
```

## Architecture

The pipeline has two entry points that share the same `src/` modules:

- **`main.py`** — CLI (argparse + Rich). Calls `detect_signature()`, `detect_brute_force()`, `detect_scan()` individually to drive a progress bar.
- **`app.py`** — Streamlit web UI. Calls `detector.analyze()` which wraps all three detection steps. Uses `st.session_state` to cache results across rerenders.

### Pipeline flow (both entry points)

```
LogLoader.load()          → raw lines[]
LogLoader.detect_format() → "apache" | "nginx" | "syslog" | "unknown"
LogParser.parse_all()     → LogEntry[] (dataclass)
  ↓ converted to dict[]
AttackDetector            → Alert[] (dataclass)
LogStatistics.compute()   → stats dict
OSINTChecker.check_ips()  → osint_data dict  (optional, hits ip-api.com)
HTMLReporter.generate()   → reports/report.html
```

### Key module responsibilities

- **`src/loader.py`** — reads file with encoding fallback, detects format by sampling lines against regex heuristics.
- **`src/parser.py`** — Apache and Nginx share the same Combined Log regex; Syslog maps `host` → `ip` and `message` → `uri`. Unknown format tries all parsers in order.
- **`src/detector.py`** — `ATTACK_PATTERNS` dict of pre-compiled regexes applied to `uri` (all types) and `user_agent` (`malicious_ua`). Brute-force counts 401/403 per IP above threshold. Scan requires both `> SCAN_THRESHOLD` distinct URIs **and** `> 50%` 404 rate.
- **`src/statistics.py`** — uses `collections.Counter` and `defaultdict`; returns a plain dict with keys `total_requests`, `unique_ips`, `error_rate`, `top_ips`, `top_uris`, `status_codes`, `methods`.
- **`src/reporter.py`** — generates a self-contained HTML file (inline CSS, no external deps).
- **`src/osint.py`** — calls `http://ip-api.com/batch` (free, no API key). Limited to 5 IPs.

### Data model

`LogEntry` and `Alert` are both `@dataclass`. The pipeline converts `LogEntry` objects to plain `dict` before passing them to `AttackDetector` and `LogStatistics`. The `Alert` dataclass is used everywhere downstream.

### Risk score formula

Used identically in `main.py` and `app.py` (duplicated logic in `_calculer_score_risque`):
```
score = min(50, alert_count × 2) + min(30, error_rate × 0.6) + (20 if heavy attack types present else 0)
```
Heavy types: `brute_force`, `scan`, `sql_injection`, `command_injection`.

## Tests

25 tests total across two files:
- `tests/test_detector.py` — 13 tests covering `AttackDetector` and `LogParser`
- `tests/test_statistics.py` — 12 tests covering `LogStatistics` and `LogLoader`
