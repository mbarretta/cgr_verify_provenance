"""
CISA Known Exploited Vulnerabilities (KEV) catalog cross-check.

The CISA KEV catalog lists CVEs with confirmed active exploitation in the
wild. BOD 22-01 requires federal agencies to remediate by a per-CVE
deadline, and CISOs/ISSOs commonly gate production deploys on
"zero-KEV-actionable" at minimum.

Scope of this module:
- Fetch + parse the canonical catalog JSON published by CISA.
- Cache locally for 24h to avoid per-image network round-trips and to
  tolerate short CISA outages.
- Look up a list of CVE IDs against the catalog; return full entries
  (with due_date, ransomware-use flag, remediation requirement) so the
  caller can surface the information to auditors.

Non-goals here:
- Deciding WHAT to do with a hit. That's policy — the caller demotes
  the overall verdict. This module is pure data.
- Cross-referencing with VEX. By the time a CVE reaches this lookup, it
  has already survived the VEX filter upstream in scan.py — so any hit
  here is unadjudicated. That's the "hard-fail" case per the plan.
"""

from __future__ import annotations

import contextlib
import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from verify_provenance import run_cmd

KEV_CATALOG_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
)
DEFAULT_CACHE_DIR = Path.home() / ".cache" / "verify-provenance"
DEFAULT_CACHE_FILE = DEFAULT_CACHE_DIR / "cisa_kev.json"
DEFAULT_MAX_AGE_HOURS = 24


@dataclass
class KevEntry:
    """One row from the CISA KEV catalog."""

    cve_id: str
    vendor_project: str = ""
    product: str = ""
    vulnerability_name: str = ""
    date_added: str = ""  # YYYY-MM-DD
    short_description: str = ""
    required_action: str = ""
    due_date: str = ""  # YYYY-MM-DD — BOD 22-01 deadline
    known_ransomware_use: str = ""  # "Known" | "Unknown"


@dataclass
class KevCatalog:
    """Parsed catalog. Keyed by uppercase CVE ID."""

    entries: dict[str, KevEntry] = field(default_factory=dict)
    date_released: str = ""
    catalog_version: str = ""
    total_count: int = 0
    source_note: str = ""  # how this catalog was loaded (for display)

    def lookup(self, cve_id: str) -> KevEntry | None:
        return self.entries.get(cve_id.upper())

    def is_empty(self) -> bool:
        return not self.entries


def load_kev_catalog(
    cache_file: Path | str = DEFAULT_CACHE_FILE,
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS,
    allow_network: bool = True,
) -> KevCatalog:
    """Load KEV catalog; refresh from CISA if stale or missing.

    Falls back to a stale cache if the fresh fetch fails — stale data is
    more useful than no data for spot-checks, and the caller can read
    `source_note` to surface the freshness warning to auditors.
    """
    path = Path(cache_file)
    stale = _is_stale(path, max_age_hours)

    if (not path.exists() or stale) and allow_network:
        fetch_error = _fetch_kev(path)
        if fetch_error:
            if path.exists():
                catalog = _parse_kev_file(path)
                catalog.source_note = f"stale cache (fetch failed: {fetch_error})"
                return catalog
            return KevCatalog(source_note=f"fetch failed: {fetch_error}")
        catalog = _parse_kev_file(path)
        catalog.source_note = "fresh fetch from CISA"
        return catalog

    if not path.exists():
        return KevCatalog(source_note="no cache and network disabled")

    catalog = _parse_kev_file(path)
    age_note = "fresh cache" if not stale else f"stale cache (> {max_age_hours}h old)"
    catalog.source_note = age_note
    return catalog


def _is_stale(path: Path, max_age_hours: int) -> bool:
    if not path.exists():
        return True
    mtime = path.stat().st_mtime
    age_seconds = time.time() - mtime
    return age_seconds > max_age_hours * 3600


def _fetch_kev(path: Path) -> str:
    """Download the catalog. Returns empty string on success, error message on failure.

    Writes to a .tmp sibling and atomically renames so an interrupted
    download can't leave a truncated cache.
    """
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        return f"cannot create cache dir: {e}"
    tmp = path.with_suffix(path.suffix + ".tmp")
    success, _, stderr = run_cmd(
        ["curl", "-sfL", "-o", str(tmp), KEV_CATALOG_URL],
        timeout=60,
    )
    if not success:
        if tmp.exists():
            with contextlib.suppress(OSError):
                tmp.unlink()
        err_lines = (stderr or "").strip().splitlines()
        return err_lines[-1] if err_lines else "curl failed"
    try:
        tmp.replace(path)
    except OSError as e:
        return f"cache write failed: {e}"
    return ""


def _parse_kev_file(path: Path) -> KevCatalog:
    """Parse the CISA catalog JSON. Tolerates schema drift — unknown fields
    are ignored, missing fields default to empty strings."""
    try:
        raw = path.read_text(encoding="utf-8")
        doc = json.loads(raw)
    except (OSError, json.JSONDecodeError):
        return KevCatalog()
    if not isinstance(doc, dict):
        return KevCatalog()

    catalog = KevCatalog()
    if isinstance(doc.get("dateReleased"), str):
        catalog.date_released = doc["dateReleased"]
    if isinstance(doc.get("catalogVersion"), str):
        catalog.catalog_version = doc["catalogVersion"]
    count = doc.get("count")
    if isinstance(count, int):
        catalog.total_count = count

    vulns = doc.get("vulnerabilities", [])
    if not isinstance(vulns, list):
        return catalog

    for v in vulns:
        if not isinstance(v, dict):
            continue
        cve_id = v.get("cveID")
        if not isinstance(cve_id, str) or not cve_id:
            continue
        entry = KevEntry(
            cve_id=cve_id.upper(),
            vendor_project=_str_field(v.get("vendorProject")),
            product=_str_field(v.get("product")),
            vulnerability_name=_str_field(v.get("vulnerabilityName")),
            date_added=_str_field(v.get("dateAdded")),
            short_description=_str_field(v.get("shortDescription")),
            required_action=_str_field(v.get("requiredAction")),
            due_date=_str_field(v.get("dueDate")),
            known_ransomware_use=_str_field(v.get("knownRansomwareCampaignUse")),
        )
        catalog.entries[entry.cve_id] = entry
    return catalog


def _str_field(v: object) -> str:
    return v if isinstance(v, str) else ""


def check_cves_against_kev(cve_ids: list[str], catalog: KevCatalog) -> list[KevEntry]:
    """Return KevEntry for each CVE in the catalog. Preserves input order,
    de-duplicates on CVE ID so repeated findings don't inflate the hit count."""
    seen: set[str] = set()
    hits: list[KevEntry] = []
    for cve in cve_ids:
        if not isinstance(cve, str):
            continue
        norm = cve.upper()
        if norm in seen:
            continue
        seen.add(norm)
        entry = catalog.lookup(norm)
        if entry is not None:
            hits.append(entry)
    return hits
