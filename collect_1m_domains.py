#!/usr/bin/env python3
"""
collect_1m_domains.py
═══════════════════════════════════════════════════════════════════════════
Production-grade domain dataset collector for ML model training.

Collects 1,000,000 unique domains with time synchronization:
  • 500,000 Malware domains  (URLhaus, ThreatFox, PhishTank, OpenPhish)
  • 500,000 Benign domains   (Tranco Archive — time-synchronized)

Architecture:
  - SQLite staging database for deduplication & atomic resume
  - Stream processing (iter_lines / iter_content) for RAM efficiency
  - Batch inserts (50,000 rows) to avoid OOM
  - Exponential backoff retries for network resilience
  - Monthly Tranco snapshots matched to malware date distribution

Prerequisites:
  pip install requests tranco

Auth Keys (FREE — register once at https://auth.abuse.ch/):
  Set the environment variables below before running:
    ABUSE_CH_AUTH_KEY   — required for URLhaus + ThreatFox downloads

  If no auth key is set, the script will attempt legacy unauthenticated
  endpoints as fallback and use PhishTank + OpenPhish + Phishing.Database
  (GitHub) as supplementary no-auth sources.

Usage:
  python collect_1m_domains.py
  python collect_1m_domains.py --auth-key YOUR_KEY_HERE
═══════════════════════════════════════════════════════════════════════════
"""

from __future__ import annotations

import argparse
import csv
import io
import logging
import os
import re
import sqlite3
import sys
import tempfile
import time
import zipfile
from datetime import datetime, timedelta
from io import BytesIO
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

# ═══════════════════════════════════════════════════════════════════════════
#  CONFIGURATION
# ═══════════════════════════════════════════════════════════════════════════

MALWARE_TARGET = 500_000
BENIGN_TARGET  = 500_000
BATCH_SIZE     = 50_000
DB_PATH        = "dataset_staging.db"

# ── Malware Source URLs ──────────────────────────────────────────────────
# abuse.ch API v2 (requires Auth-Key)
URLHAUS_CSV_FULL_V2   = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/full.csv.zip"
URLHAUS_CSV_RECENT_V2 = "https://urlhaus-api.abuse.ch/v2/files/exports/{auth_key}/recent.csv"

# Legacy (may still work without auth for public feeds)
URLHAUS_CSV_LEGACY   = "https://urlhaus.abuse.ch/downloads/csv/"
URLHAUS_CSV_RECENT   = "https://urlhaus.abuse.ch/downloads/csv_recent/"

# ThreatFox (abuse.ch, requires Auth-Key for full export)
THREATFOX_CSV_V2     = "https://threatfox-api.abuse.ch/v2/files/exports/{auth_key}/full.csv.zip"

# No-auth supplementary sources
PHISHTANK_CSV        = "http://data.phishtank.com/data/online-valid.csv"
OPENPHISH_FEED       = "https://openphish.com/feed.txt"
PHISHING_DB_ACTIVE   = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
PHISHING_DB_NEW      = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-NEW-today.txt"
KADHOSTS_TXT         = "https://raw.githubusercontent.com/PolishFiltersTeam/KADhosts/master/KADhosts.txt"
BLACKBOOK_TXT        = "https://raw.githubusercontent.com/stamparm/blackbook/master/blackbook.txt"

# ── Network settings ────────────────────────────────────────────────────
MAX_RETRIES         = 5
INITIAL_BACKOFF_SEC = 2
REQUEST_TIMEOUT     = 180
CHUNK_SIZE          = 65_536   # 64 KB for streaming

# ── Domain validation ───────────────────────────────────────────────────
DOMAIN_RE = re.compile(
    r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
)

# ═══════════════════════════════════════════════════════════════════════════
#  LOGGING
# ═══════════════════════════════════════════════════════════════════════════

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(levelname)-7s │ %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler("collect_domains.log", encoding="utf-8"),
    ],
)
log = logging.getLogger("collector")


# ═══════════════════════════════════════════════════════════════════════════
#  DOMAIN CLEANING
# ═══════════════════════════════════════════════════════════════════════════

def clean_domain(raw: str) -> Optional[str]:
    """
    Extract and validate a domain from a raw URL or domain string.

    Steps:
      1. Strip whitespace, lowercase
      2. Parse URL if scheme present → extract hostname
      3. Otherwise split on ':' and '/' to isolate host
      4. Remove 'www.' prefix and trailing dots
      5. Validate against DOMAIN_RE
      6. Reject pure-numeric (IP) strings
    """
    if not raw or not isinstance(raw, str):
        return None

    raw = raw.strip().lower()
    if not raw:
        return None

    # Parse URL with scheme
    if "://" in raw:
        try:
            parsed = urlparse(raw)
            host = parsed.hostname or ""
        except Exception:
            return None
    else:
        # domain:port/path or bare domain
        host = raw.split(":")[0].split("/")[0].split("?")[0].split("#")[0]

    # Strip www. and trailing dot
    if host.startswith("www."):
        host = host[4:]
    host = host.rstrip(".")

    if not host:
        return None

    # Regex validation
    if not DOMAIN_RE.match(host):
        return None

    # Reject IP-address-like strings (e.g. 192.168.1.1)
    parts = host.split(".")
    if all(p.isdigit() for p in parts):
        return None

    return host


# ═══════════════════════════════════════════════════════════════════════════
#  HTTP UTILITY
# ═══════════════════════════════════════════════════════════════════════════

def http_get(
    url: str,
    stream: bool = False,
    timeout: int = REQUEST_TIMEOUT,
    max_retries: int = MAX_RETRIES,
    **kwargs,
) -> requests.Response:
    """HTTP GET with exponential-backoff retries."""
    delay = INITIAL_BACKOFF_SEC
    last_exc: Optional[Exception] = None
    headers = kwargs.pop("headers", {})
    headers.setdefault(
        "User-Agent",
        "DomainCollector/1.0 (Research; +https://github.com)",
    )

    for attempt in range(1, max_retries + 1):
        try:
            resp = requests.get(
                url, stream=stream, timeout=timeout, headers=headers, **kwargs
            )
            resp.raise_for_status()
            return resp
        except requests.RequestException as exc:
            last_exc = exc
            if attempt < max_retries:
                log.warning(
                    "  Attempt %d/%d failed (%s). Retry in %ds…",
                    attempt, max_retries, exc, delay,
                )
                time.sleep(delay)
                delay = min(delay * 2, 120)
            else:
                log.error(
                    "  All %d attempts failed for %s: %s",
                    max_retries, url, exc,
                )
    raise last_exc  # type: ignore[misc]


# ═══════════════════════════════════════════════════════════════════════════
#  DATABASE LAYER
# ═══════════════════════════════════════════════════════════════════════════

def init_database(db_path: str) -> sqlite3.Connection:
    """
    STEP 1: Initialize SQLite staging database.

    Creates the `domains` table with a composite primary key
    (domain, label) for automatic deduplication and indexes on
    label, timestamp, and (label, timestamp) for fast queries.
    """
    conn = sqlite3.connect(db_path)
    # Performance tuning
    conn.execute("PRAGMA journal_mode = WAL")
    conn.execute("PRAGMA synchronous = NORMAL")
    conn.execute("PRAGMA cache_size = -65536")   # 64 MB
    conn.execute("PRAGMA temp_store = MEMORY")
    conn.execute("PRAGMA mmap_size = 268435456") # 256 MB mmap

    conn.execute("""
        CREATE TABLE IF NOT EXISTS domains (
            domain    TEXT    NOT NULL,
            label     TEXT    NOT NULL CHECK(label IN ('malware', 'benign')),
            timestamp TEXT,
            source    TEXT,
            PRIMARY KEY (domain, label)
        ) WITHOUT ROWID
    """)
    conn.execute("CREATE INDEX IF NOT EXISTS idx_label        ON domains(label)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_timestamp    ON domains(timestamp)")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_label_ts     ON domains(label, timestamp)")
    conn.commit()
    return conn


def count_label(conn: sqlite3.Connection, label: str) -> int:
    """Return number of unique domains for a given label."""
    row = conn.execute(
        "SELECT COUNT(*) FROM domains WHERE label = ?", (label,)
    ).fetchone()
    return row[0] if row else 0


def batch_insert(conn: sqlite3.Connection, rows: List[Tuple[str, str, str, str]]) -> None:
    """Insert batch of (domain, label, timestamp, source), ignoring duplicates."""
    if not rows:
        return
    conn.executemany(
        "INSERT OR IGNORE INTO domains(domain, label, timestamp, source) "
        "VALUES (?, ?, ?, ?)",
        rows,
    )
    conn.commit()


def get_malware_month_distribution(conn: sqlite3.Connection) -> Dict[str, int]:
    """Return {YYYY-MM: count} for malware domains with timestamps."""
    cur = conn.execute("""
        SELECT substr(timestamp, 1, 7) AS ym, COUNT(*)
        FROM domains
        WHERE label = 'malware' AND timestamp IS NOT NULL AND length(timestamp) >= 7
        GROUP BY ym
        ORDER BY ym
    """)
    return dict(cur.fetchall())


# ═══════════════════════════════════════════════════════════════════════════
#  MALWARE COLLECTORS
# ═══════════════════════════════════════════════════════════════════════════

def _stream_csv_zip(
    conn: sqlite3.Connection,
    url: str,
    source_name: str,
    target: int,
    date_col: int,
    value_col: int,
    value_type_col: Optional[int] = None,
    allowed_types: Optional[set] = None,
    skip_prefix: str = "#",
    header_startswith: Optional[str] = None,
) -> int:
    """
    Generic: download a ZIP containing a CSV, stream-parse it,
    clean domains and batch-insert into SQLite.

    Returns the current malware count after processing.
    """
    n = count_label(conn, "malware")
    if n >= target:
        return n

    tmp_path: Optional[str] = None
    try:
        log.info("  Downloading %s …", url.split("?")[0][:80])
        resp = http_get(url, stream=True, timeout=300)

        # Stream to temp file (RAM-safe)
        with tempfile.NamedTemporaryFile(suffix=".zip", delete=False) as tmp:
            for chunk in resp.iter_content(chunk_size=CHUNK_SIZE):
                tmp.write(chunk)
            tmp_path = tmp.name
        resp.close()

        zf = zipfile.ZipFile(tmp_path)
        csv_names = [f for f in zf.namelist() if f.endswith(".csv") or f.endswith(".txt")]
        if not csv_names:
            log.warning("  No CSV found inside ZIP from %s", source_name)
            return count_label(conn, "malware")

        with zf.open(csv_names[0]) as fh:
            batch: List[Tuple[str, str, str, str]] = []
            processed = 0

            for raw_line in io.TextIOWrapper(fh, encoding="utf-8", errors="replace"):
                raw_line = raw_line.strip()
                if not raw_line or raw_line.startswith(skip_prefix):
                    continue
                if header_startswith and raw_line.startswith(header_startswith):
                    continue

                try:
                    row = next(csv.reader(io.StringIO(raw_line)))
                except (csv.Error, StopIteration):
                    continue

                if len(row) <= max(date_col, value_col):
                    continue

                # Type filter (e.g. ThreatFox ioc_type)
                if value_type_col is not None and allowed_types:
                    ioc_type = row[value_type_col].strip('" ').lower()
                    if ioc_type not in allowed_types:
                        continue

                date_val = row[date_col].strip('" ')
                value = row[value_col].strip('" ')

                dom = clean_domain(value)
                if not dom:
                    continue

                ts = date_val[:10] if len(date_val) >= 10 else None
                batch.append((dom, "malware", ts, source_name))
                processed += 1

                if len(batch) >= BATCH_SIZE:
                    batch_insert(conn, batch)
                    batch.clear()
                    n = count_label(conn, "malware")
                    log.info(
                        "  %s: %s / %s unique  (%s records parsed)",
                        source_name, f"{n:,}", f"{target:,}", f"{processed:,}",
                    )
                    if n >= target:
                        break

            if batch:
                batch_insert(conn, batch)

        zf.close()

    except zipfile.BadZipFile:
        log.warning("  %s response is not a valid ZIP. Trying as plain CSV…", source_name)
        return _stream_csv_plain(conn, url, source_name, target, date_col, value_col, skip_prefix, header_startswith)
    except Exception as e:
        log.error("  %s error: %s", source_name, e)
    finally:
        if tmp_path and os.path.exists(tmp_path):
            try:
                os.unlink(tmp_path)
            except OSError:
                pass

    n = count_label(conn, "malware")
    log.info("  %s done → %s unique malware domains", source_name, f"{n:,}")
    return n


def _stream_csv_plain(
    conn: sqlite3.Connection,
    url: str,
    source_name: str,
    target: int,
    date_col: int,
    value_col: int,
    skip_prefix: str = "#",
    header_startswith: Optional[str] = None,
) -> int:
    """Stream a plain (non-zipped) CSV via iter_lines."""
    n = count_label(conn, "malware")
    if n >= target:
        return n

    try:
        resp = http_get(url, stream=True)
    except Exception as e:
        log.error("  %s download failed: %s", source_name, e)
        return count_label(conn, "malware")

    batch: List[Tuple[str, str, str, str]] = []
    processed = 0

    for raw_line in resp.iter_lines(decode_unicode=True):
        if isinstance(raw_line, bytes):
            raw_line = raw_line.decode("utf-8", errors="replace")
        if not raw_line or raw_line.startswith(skip_prefix):
            continue
        if header_startswith and raw_line.startswith(header_startswith):
            continue

        try:
            row = next(csv.reader(io.StringIO(raw_line)))
        except (csv.Error, StopIteration):
            continue

        if len(row) <= max(date_col, value_col):
            continue

        date_val = row[date_col].strip('" ')
        value = row[value_col].strip('" ')

        dom = clean_domain(value)
        if not dom:
            continue

        ts = date_val[:10] if len(date_val) >= 10 else None
        batch.append((dom, "malware", ts, source_name))
        processed += 1

        if len(batch) >= BATCH_SIZE:
            batch_insert(conn, batch)
            batch.clear()
            n = count_label(conn, "malware")
            log.info(
                "  %s: %s / %s unique  (%s URLs parsed)",
                source_name, f"{n:,}", f"{target:,}", f"{processed:,}",
            )
            if n >= target:
                break

    if batch:
        batch_insert(conn, batch)
    resp.close()

    n = count_label(conn, "malware")
    log.info("  %s done → %s unique malware domains", source_name, f"{n:,}")
    return n


# ── Individual Source Functions ──────────────────────────────────────────

def collect_urlhaus(conn: sqlite3.Connection, target: int, auth_key: Optional[str]) -> int:
    """
    STEP 2a: Collect malware domains from URLhaus full CSV dump.

    URLhaus CSV columns:
      id, dateadded, url, url_status, last_online, threat, tags, urlhaus_link, reporter
    """
    log.info("─── [Source 1] URLhaus Full CSV Dump ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s malware domains — skip.", f"{n:,}")
        return n

    # Try API v2 with auth key (preferred)
    if auth_key:
        url = URLHAUS_CSV_FULL_V2.format(auth_key=auth_key)
        log.info("  Using URLhaus API v2 (authenticated)…")
        n = _stream_csv_zip(
            conn, url, "urlhaus",
            target=target,
            date_col=1,    # dateadded
            value_col=2,   # url
            header_startswith='"id"',
        )
        if n >= target:
            return n

    # Fallback: legacy unauthenticated CSV
    log.info("  Trying URLhaus legacy endpoint (unauthenticated)…")
    return _stream_csv_plain(
        conn, URLHAUS_CSV_LEGACY, "urlhaus",
        target=target,
        date_col=1,   # dateadded
        value_col=2,  # url
        header_startswith='"id"',
    )


def collect_threatfox(conn: sqlite3.Connection, target: int, auth_key: Optional[str]) -> int:
    """
    STEP 2b: Collect malware domains from ThreatFox full CSV export.

    ThreatFox CSV columns:
      first_seen_utc, ioc_id, ioc_value, ioc_type, threat_type, ...
    We filter for ioc_type ∈ {domain, url}.
    """
    log.info("─── [Source 2] ThreatFox Full CSV Export ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s — skip.", f"{n:,}")
        return n

    if not auth_key:
        log.warning("  ThreatFox requires Auth-Key. Skipping.")
        log.warning("  Get a free key at: https://auth.abuse.ch/")
        return n

    url = THREATFOX_CSV_V2.format(auth_key=auth_key)
    return _stream_csv_zip(
        conn, url, "threatfox",
        target=target,
        date_col=0,            # first_seen_utc
        value_col=2,           # ioc_value
        value_type_col=3,      # ioc_type
        allowed_types={"domain", "url"},
        header_startswith='"first_seen',
    )


def collect_phishtank(conn: sqlite3.Connection, target: int) -> int:
    """
    STEP 2c: Collect malware domains from PhishTank online-valid.csv.

    PhishTank CSV columns:
      phish_id, url, phish_detail_url, submission_time, verified, ...
    """
    log.info("─── [Source 3] PhishTank (no auth) ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s — skip.", f"{n:,}")
        return n

    log.info("  Source: %s", PHISHTANK_CSV)

    try:
        resp = http_get(PHISHTANK_CSV, stream=True, timeout=300)
    except Exception as e:
        log.error("  PhishTank download failed: %s", e)
        return count_label(conn, "malware")

    batch: List[Tuple[str, str, str, str]] = []
    processed = 0
    header_skipped = False

    for raw_line in resp.iter_lines(decode_unicode=True):
        if isinstance(raw_line, bytes):
            raw_line = raw_line.decode("utf-8", errors="replace")
        if not raw_line:
            continue
        if not header_skipped:
            header_skipped = True
            if "phish_id" in raw_line.lower():
                continue

        try:
            row = next(csv.reader(io.StringIO(raw_line)))
        except (csv.Error, StopIteration):
            continue

        if len(row) < 4:
            continue

        url_val = row[1].strip('" ')
        submit_time = row[3].strip('" ')

        dom = clean_domain(url_val)
        if not dom:
            continue

        ts = submit_time[:10] if len(submit_time) >= 10 else None
        batch.append((dom, "malware", ts, "phishtank"))
        processed += 1

        if len(batch) >= BATCH_SIZE:
            batch_insert(conn, batch)
            batch.clear()
            n = count_label(conn, "malware")
            log.info(
                "  PhishTank: %s / %s unique  (%s URLs parsed)",
                f"{n:,}", f"{target:,}", f"{processed:,}",
            )
            if n >= target:
                break

    if batch:
        batch_insert(conn, batch)
    resp.close()

    n = count_label(conn, "malware")
    log.info("  PhishTank done → %s unique malware domains", f"{n:,}")
    return n


def collect_openphish(conn: sqlite3.Connection, target: int) -> int:
    """
    STEP 2d: Collect malware domains from OpenPhish community feed.
    No timestamps available — uses today's date.
    """
    log.info("─── [Source 4] OpenPhish Community Feed ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s — skip.", f"{n:,}")
        return n

    try:
        resp = http_get(OPENPHISH_FEED, timeout=60)
    except Exception as e:
        log.error("  OpenPhish download failed: %s", e)
        return count_label(conn, "malware")

    today = datetime.utcnow().strftime("%Y-%m-%d")
    batch: List[Tuple[str, str, str, str]] = []
    for line in resp.text.splitlines():
        dom = clean_domain(line.strip())
        if dom:
            batch.append((dom, "malware", today, "openphish"))
        if len(batch) >= BATCH_SIZE:
            batch_insert(conn, batch)
            batch.clear()
            if count_label(conn, "malware") >= target:
                break
    if batch:
        batch_insert(conn, batch)

    n = count_label(conn, "malware")
    log.info("  OpenPhish done → %s unique malware domains", f"{n:,}")
    return n


def collect_phishing_database_github(conn: sqlite3.Connection, target: int) -> int:
    """
    STEP 2e: Collect phishing domains from Phishing.Database (GitHub).
    Large, community-curated list. No timestamps — uses today's date.
    """
    log.info("─── [Source 5] Phishing.Database (GitHub) ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s — skip.", f"{n:,}")
        return n

    today = datetime.utcnow().strftime("%Y-%m-%d")

    for url_label, url in [
        ("ACTIVE domains", PHISHING_DB_ACTIVE),
        ("NEW-today domains", PHISHING_DB_NEW),
    ]:
        if count_label(conn, "malware") >= target:
            break

        log.info("  Fetching %s …", url_label)
        try:
            resp = http_get(url, stream=True, timeout=120)
        except Exception as e:
            log.warning("  %s failed: %s", url_label, e)
            continue

        batch: List[Tuple[str, str, str, str]] = []
        processed = 0
        for raw_line in resp.iter_lines(decode_unicode=True):
            if isinstance(raw_line, bytes):
                raw_line = raw_line.decode("utf-8", errors="replace")
            if not raw_line:
                continue
            dom = clean_domain(raw_line.strip())
            if dom:
                batch.append((dom, "malware", today, "phishing_db"))
                processed += 1
            if len(batch) >= BATCH_SIZE:
                batch_insert(conn, batch)
                batch.clear()
                n = count_label(conn, "malware")
                log.info(
                    "  PhishingDB %s: %s / %s unique (%s parsed)",
                    url_label, f"{n:,}", f"{target:,}", f"{processed:,}",
                )
                if n >= target:
                    break
        if batch:
            batch_insert(conn, batch)
        resp.close()

    n = count_label(conn, "malware")
    log.info("  Phishing.Database done → %s unique malware domains", f"{n:,}")
    return n


def collect_kadhosts_and_blackbook(conn: sqlite3.Connection, target: int) -> int:
    """
    STEP 2f: Collect additional malware & phishing domains from KADhosts and Blackbook.
    """
    log.info("─── [Source 6] KADhosts & Blackbook ───")
    n = count_label(conn, "malware")
    if n >= target:
        log.info("  Already at %s — skip.", f"{n:,}")
        return n

    today = datetime.utcnow().strftime("%Y-%m-%d")
    sources = [
        ("KADhosts", KADHOSTS_TXT),
        ("Blackbook", BLACKBOOK_TXT),
    ]

    for name, url in sources:
        if count_label(conn, "malware") >= target:
            break
        log.info("  Fetching %s …", name)
        try:
            resp = http_get(url, stream=True, timeout=120)
        except Exception as e:
            log.warning("  %s failed: %s", name, e)
            continue

        batch: List[Tuple[str, str, str, str]] = []
        processed = 0
        for raw_line in resp.iter_lines(decode_unicode=True):
            if isinstance(raw_line, bytes):
                raw_line = raw_line.decode("utf-8", errors="replace")
            if not raw_line or raw_line.startswith("#"):
                continue
            parts = raw_line.strip().split()
            value = parts[-1] if parts else ""
            dom = clean_domain(value)
            if dom:
                batch.append((dom, "malware", today, name.lower()))
                processed += 1
            if len(batch) >= BATCH_SIZE:
                batch_insert(conn, batch)
                batch.clear()
                n = count_label(conn, "malware")
                log.info(
                    "  %s: %s / %s unique (%s parsed)",
                    name, f"{n:,}", f"{target:,}", f"{processed:,}",
                )
                if n >= target:
                    break
        if batch:
            batch_insert(conn, batch)
        resp.close()

    n = count_label(conn, "malware")
    log.info("  KADhosts & Blackbook done → %s unique malware domains", f"{n:,}")
    return n


# ═══════════════════════════════════════════════════════════════════════════
#  BENIGN COLLECTOR  — Tranco List Archive (time-synchronized)
# ═══════════════════════════════════════════════════════════════════════════

def _init_tranco():
    """Initialize the Tranco Python client with caching if available."""
    try:
        from tranco import Tranco
        t = Tranco(cache=True, cache_dir=".tranco_cache")
        return t
    except ImportError:
        log.info("  'tranco' Python package not found. Using direct HTTP API fallback.")
        return None


def _get_tranco_domains_for_date(
    tranco_client,
    date_str: str,
    max_domains: int = 1_000_000,
) -> Tuple[List[str], Optional[str]]:
    """
    Download a Tranco list for a specific date.
    Tries Python package first, falls back to direct HTTP API if unavailable.
    Returns (list_of_domains, list_id) or ([], None) on failure.
    """
    # 1. Try Python package if client initialized
    if tranco_client is not None:
        try:
            tlist = tranco_client.list(date=date_str)
            list_id = getattr(tlist, "list_id", None) or getattr(tlist, "list_page", date_str)
            domains = tlist.top(min(max_domains, 1_000_000))
            return domains, str(list_id)
        except Exception as e:
            log.debug("  Tranco Python package fetch for %s failed: %s. Trying direct HTTP…", date_str, e)

    # 2. Fallback: Direct HTTP query to tranco-list.eu API
    try:
        # Step A: Get daily list_id
        url_id = f"https://tranco-list.eu/daily_list_id?date={date_str}&subdomains=false"
        resp_id = http_get(url_id, timeout=30, max_retries=2)
        if resp_id.status_code != 200 or not resp_id.text.strip():
            return [], None
        list_id = resp_id.text.strip()

        # Step B: Download list content
        url_list = f"https://tranco-list.eu/download/{list_id}/1000000"
        resp_list = http_get(url_list, timeout=120, max_retries=2)
        lines = resp_list.text.splitlines()

        domains: List[str] = []
        for line in lines:
            line = line.strip()
            if not line:
                continue
            parts = line.split(",")
            d = parts[1].strip() if len(parts) >= 2 else parts[0].strip()
            cleaned = clean_domain(d)
            if cleaned:
                domains.append(cleaned)

        return domains, list_id
    except Exception as e:
        log.debug("  Direct HTTP Tranco fetch for %s failed: %s", date_str, e)
        return [], None


def _get_tranco_latest_fallback() -> List[str]:
    """Download the latest Tranco top-1M via direct URL (fallback)."""
    log.info("  Downloading latest Tranco top-1M (direct ZIP fallback)…")
    url = "https://tranco-list.eu/top-1m.csv.zip"
    try:
        resp = http_get(url, timeout=180)
    except Exception as e:
        log.error("  Tranco latest download failed: %s", e)
        return []

    raw = resp.content
    if raw[:4] == b"PK\x03\x04":
        try:
            zf = zipfile.ZipFile(BytesIO(raw))
            text = zf.read(zf.namelist()[0]).decode("utf-8", errors="replace")
        except Exception:
            text = resp.text
    else:
        text = resp.text

    domains: List[str] = []
    for line in text.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(",")
        d = parts[1].strip() if len(parts) >= 2 else parts[0].strip()
        cleaned = clean_domain(d)
        if cleaned:
            domains.append(cleaned)

    log.info("  Tranco latest → %s domains loaded", f"{len(domains):,}")
    return domains


def collect_benign_time_synced(conn: sqlite3.Connection, target: int) -> None:
    """
    STEP 3: Collect benign domains time-synchronized to malware timestamps.

    Strategy:
      1. Get monthly distribution of malware domains.
      2. For each month, fetch the Tranco list for the 15th.
      3. Insert benign domains proportionally to malware distribution.
      4. If a specific month's list is unavailable, try adjacent dates.
      5. Fallback to latest Tranco top-1M if still short.
    """
    log.info("═" * 65)
    log.info("STEP 3: Benign Domain Collection (Time-Synchronized)")
    log.info("═" * 65)

    n = count_label(conn, "benign")
    if n >= target:
        log.info("  Already at %s benign domains — done.", f"{n:,}")
        return

    month_dist = get_malware_month_distribution(conn)

    if not month_dist:
        log.warning("  No malware timestamps found! Using latest Tranco as fallback.")
        domains = _get_tranco_latest_fallback()
        today = datetime.utcnow().strftime("%Y-%m-%d")
        batch = [(d, "benign", today, "tranco") for d in domains]
        for i in range(0, len(batch), BATCH_SIZE):
            batch_insert(conn, batch[i : i + BATCH_SIZE])
            if count_label(conn, "benign") >= target:
                break
        return

    total_mal = sum(month_dist.values())
    months = sorted(month_dist.keys())
    log.info("  Malware spans %d months: %s → %s", len(months), months[0], months[-1])
    log.info("  Total malware domains with timestamps: %s", f"{total_mal:,}")

    # Initialize Tranco client (if available)
    tranco_client = _init_tranco()

    # Cache: list_id → domain list (avoid re-downloading same list)
    list_cache: Dict[str, List[str]] = {}
    # Track which list_id each month used
    month_list_ids: Dict[str, Optional[str]] = {}

    for idx, ym in enumerate(months, 1):
        n = count_label(conn, "benign")
        if n >= target:
            break

        mal_count = month_dist[ym]
        proportion = mal_count / total_mal
        # Overshoot by 20% to account for dedup across months
        month_quota = max(int(proportion * target * 1.2), 500)

        log.info(
            "  [%d/%d] %s  │  malware=%s  │  benign_quota≈%s",
            idx, len(months), ym, f"{mal_count:,}", f"{month_quota:,}",
        )

        # Representative date: 15th of the month
        rep_date = f"{ym}-15"
        domains: List[str] = []
        list_id: Optional[str] = None

        # Try 15th, then 1st, then 28th
        for day in ["15", "01", "28"]:
            try_date = f"{ym}-{day}"
            domains, list_id = _get_tranco_domains_for_date(tranco_client, try_date)
            if domains:
                break

        if list_id and list_id in list_cache:
            domains = list_cache[list_id]
            log.info("    Reusing cached list %s (%s domains)", list_id, f"{len(domains):,}")
        elif domains and list_id:
            # Clean domains
            cleaned = []
            for d in domains:
                c = clean_domain(d)
                if c:
                    cleaned.append(c)
            domains = cleaned
            list_cache[list_id] = domains
            log.info("    Downloaded Tranco list %s → %s domains", list_id, f"{len(domains):,}")
        else:
            log.warning("    No Tranco list found for %s", ym)
            month_list_ids[ym] = None
            continue

        month_list_ids[ym] = list_id

        # Insert domains with this month's representative date
        batch: List[Tuple[str, str, str, str]] = []
        taken = 0
        for d in domains:
            batch.append((d, "benign", rep_date, "tranco"))
            taken += 1
            if taken >= month_quota:
                break
            if len(batch) >= BATCH_SIZE:
                batch_insert(conn, batch)
                batch.clear()
                if count_label(conn, "benign") >= target:
                    break
        if batch:
            batch_insert(conn, batch)

        n = count_label(conn, "benign")
        log.info("    Benign total: %s / %s", f"{n:,}", f"{target:,}")

        # Rate-limit Tranco API (be respectful)
        time.sleep(1.5)

    # ── Fallback: fill remaining with latest Tranco list ────────────
    n = count_label(conn, "benign")
    if n < target:
        shortfall = target - n
        log.warning(
            "  Still need %s more benign domains. Supplementing with latest Tranco…",
            f"{shortfall:,}",
        )
        domains = _get_tranco_latest_fallback()
        if domains:
            # Assign median malware month as timestamp
            median_month = months[len(months) // 2]
            fallback_ts = f"{median_month}-15"
            batch = []
            for d in domains:
                batch.append((d, "benign", fallback_ts, "tranco"))
                if len(batch) >= BATCH_SIZE:
                    batch_insert(conn, batch)
                    batch.clear()
                    if count_label(conn, "benign") >= target:
                        break
            if batch:
                batch_insert(conn, batch)

    n = count_label(conn, "benign")
    log.info("  ★ Benign collection complete: %s / %s", f"{n:,}", f"{target:,}")


# ═══════════════════════════════════════════════════════════════════════════
#  EXPORT TO CSV
# ═══════════════════════════════════════════════════════════════════════════

def export_csv(
    conn: sqlite3.Connection,
    label: str,
    filepath: str,
    limit: int,
) -> int:
    """
    STEP 4: Export domains to CSV with header (domain, label).
    Reads from SQLite in batches to keep memory usage low.
    """
    log.info("  Exporting '%s' → %s …", label, filepath)

    cursor = conn.execute(
        "SELECT domain, label FROM domains WHERE label = ? LIMIT ?",
        (label, limit),
    )

    written = 0
    with open(filepath, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["domain", "label"])

        while True:
            rows = cursor.fetchmany(BATCH_SIZE)
            if not rows:
                break
            writer.writerows(rows)
            written += len(rows)

    log.info("  → %s rows written to %s", f"{written:,}", filepath)
    return written


# ═══════════════════════════════════════════════════════════════════════════
#  STATISTICS SUMMARY
# ═══════════════════════════════════════════════════════════════════════════

def print_statistics(conn: sqlite3.Connection) -> None:
    """Print dataset statistics for verification."""
    log.info("─── Dataset Statistics ───")

    for label in ("malware", "benign"):
        row = conn.execute("""
            SELECT
                COUNT(*),
                MIN(timestamp),
                MAX(timestamp),
                COUNT(DISTINCT substr(timestamp, 1, 7)),
                COUNT(DISTINCT source)
            FROM domains WHERE label = ? AND timestamp IS NOT NULL
        """, (label,)).fetchone()

        if row and row[0]:
            log.info(
                "  %s: %s domains │ %s → %s │ %d months │ %d sources",
                label.upper(), f"{row[0]:,}", row[1], row[2], row[3], row[4],
            )

    # Source breakdown
    cur = conn.execute("""
        SELECT source, label, COUNT(*)
        FROM domains
        GROUP BY source, label
        ORDER BY label, COUNT(*) DESC
    """)
    log.info("  ── Source Breakdown ──")
    for source, label, cnt in cur:
        log.info("    %s │ %s │ %s", label, source or "unknown", f"{cnt:,}")


# ═══════════════════════════════════════════════════════════════════════════
#  MAIN ORCHESTRATION
# ═══════════════════════════════════════════════════════════════════════════

def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Collect 1M domains (500K malware + 500K benign) for ML training."
    )
    parser.add_argument(
        "--auth-key",
        default=os.environ.get("ABUSE_CH_AUTH_KEY", ""),
        help="abuse.ch Auth-Key (or set ABUSE_CH_AUTH_KEY env var). "
             "Free registration at https://auth.abuse.ch/",
    )
    parser.add_argument(
        "--db", default=DB_PATH,
        help=f"SQLite database path (default: {DB_PATH})",
    )
    parser.add_argument(
        "--malware-target", type=int, default=MALWARE_TARGET,
        help=f"Target number of malware domains (default: {MALWARE_TARGET:,})",
    )
    parser.add_argument(
        "--benign-target", type=int, default=BENIGN_TARGET,
        help=f"Target number of benign domains (default: {BENIGN_TARGET:,})",
    )
    return parser.parse_args()


def main() -> None:
    if sys.platform == "win32":
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
            sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        except AttributeError:
            pass

    args = parse_args()
    db_path = args.db
    auth_key = args.auth_key or None
    malware_target = args.malware_target
    benign_target = args.benign_target

    banner = r"""
╔═══════════════════════════════════════════════════════════════╗
║          Domain Dataset Collector v1.0                       ║
║          Target: {:>10s} domains                             ║
║          ({:>7s} malware + {:>7s} benign)                    ║
╚═══════════════════════════════════════════════════════════════╝
""".format(
        f"{malware_target + benign_target:,}",
        f"{malware_target:,}",
        f"{benign_target:,}",
    )
    print(banner)

    if auth_key:
        log.info("Auth-Key: %s…%s (set)", auth_key[:4], auth_key[-4:])
    else:
        log.info("Auth-Key: NOT SET — URLhaus/ThreatFox authenticated endpoints unavailable.")
        log.info("  → Will use legacy/unauthenticated endpoints + supplementary sources.")
        log.info("  → For best results, get a FREE key at https://auth.abuse.ch/")

    t0 = time.time()

    # ══════════════════════════════════════════════════════════════════════
    # STEP 1: Initialize SQLite Database
    # ══════════════════════════════════════════════════════════════════════
    log.info("═" * 65)
    log.info("STEP 1: Database Initialization")
    log.info("═" * 65)

    resuming = os.path.exists(db_path)
    conn = init_database(db_path)

    if resuming:
        mal_existing = count_label(conn, "malware")
        ben_existing = count_label(conn, "benign")
        log.info(
            "  Resuming from existing database: %s",
            db_path,
        )
        log.info(
            "  Existing data: malware=%s  benign=%s",
            f"{mal_existing:,}", f"{ben_existing:,}",
        )
    else:
        log.info("  Created fresh database: %s", db_path)

    # ══════════════════════════════════════════════════════════════════════
    # STEP 2: Collect Malware Domains
    # ══════════════════════════════════════════════════════════════════════
    log.info("═" * 65)
    log.info("STEP 2: Malware Domain Collection")
    log.info("═" * 65)

    # Source 1: URLhaus (largest, has timestamps)
    n = collect_urlhaus(conn, malware_target, auth_key)

    # Source 2: ThreatFox (requires auth key)
    if n < malware_target:
        n = collect_threatfox(conn, malware_target, auth_key)

    # Source 3: PhishTank (no auth, has timestamps)
    if n < malware_target:
        n = collect_phishtank(conn, malware_target)

    # Source 4: OpenPhish (no auth, no timestamps)
    if n < malware_target:
        n = collect_openphish(conn, malware_target)

    # Source 5: Phishing.Database on GitHub (large, no auth)
    if n < malware_target:
        n = collect_phishing_database_github(conn, malware_target)

    # Source 6: KADhosts & Blackbook (supplementary malware lists)
    if n < malware_target:
        n = collect_kadhosts_and_blackbook(conn, malware_target)

    mal_final = count_label(conn, "malware")
    log.info("═" * 40)
    log.info("  ★ Total malware domains: %s / %s", f"{mal_final:,}", f"{malware_target:,}")
    if mal_final < malware_target:
        log.warning(
            "  ⚠ Could not reach target (%s collected). "
            "Consider adding an abuse.ch Auth-Key for URLhaus + ThreatFox.",
            f"{mal_final:,}",
        )

    # ══════════════════════════════════════════════════════════════════════
    # STEP 3: Collect Benign Domains (Time-Synchronized)
    # ══════════════════════════════════════════════════════════════════════
    collect_benign_time_synced(conn, benign_target)

    # ══════════════════════════════════════════════════════════════════════
    # STEP 4: Export to CSV
    # ══════════════════════════════════════════════════════════════════════
    log.info("═" * 65)
    log.info("STEP 4: Export to CSV")
    log.info("═" * 65)

    mal_exported = export_csv(conn, "malware", "malware_domains.csv", malware_target)
    ben_exported = export_csv(conn, "benign", "benign_domains.csv", benign_target)

    # Statistics
    print_statistics(conn)

    conn.close()

    # ══════════════════════════════════════════════════════════════════════
    # DONE
    # ══════════════════════════════════════════════════════════════════════
    elapsed = time.time() - t0
    h, rem = divmod(int(elapsed), 3600)
    m, s = divmod(rem, 60)

    log.info("═" * 65)
    log.info("  ✅ COLLECTION COMPLETE")
    log.info("  ── Results ──")
    log.info("    Malware domains exported:  %s", f"{mal_exported:,}")
    log.info("    Benign domains exported:   %s", f"{ben_exported:,}")
    log.info("    Total domains:             %s", f"{mal_exported + ben_exported:,}")
    log.info("  ── Time ──")
    log.info("    Elapsed: %dh %dm %ds", h, m, s)
    log.info("  ── Output Files ──")
    log.info("    • malware_domains.csv  (header: domain,label)")
    log.info("    • benign_domains.csv   (header: domain,label)")
    log.info("    • %s  (staging database — safe to delete)", db_path)
    log.info("    • collect_domains.log  (execution log)")
    log.info("═" * 65)


if __name__ == "__main__":
    main()
