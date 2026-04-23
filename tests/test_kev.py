"""Tests for the kev module — catalog parsing, staleness, cross-check."""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any
from unittest.mock import patch

sys.path.insert(0, "..")

from kev import (  # noqa: E402
    KevCatalog,
    KevEntry,
    _fetch_kev,
    _is_stale,
    _parse_kev_file,
    check_cves_against_kev,
    load_kev_catalog,
)


def _make_kev_doc(vulns: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "title": "CISA Known Exploited Vulnerabilities Catalog",
        "catalogVersion": "2026.04.23",
        "dateReleased": "2026-04-23T12:00:00.000Z",
        "count": len(vulns),
        "vulnerabilities": vulns,
    }


def _kev_vuln(cve: str, due_date: str = "2026-05-14",
              ransomware: str = "Unknown") -> dict[str, Any]:
    return {
        "cveID": cve,
        "vendorProject": "TestVendor",
        "product": "TestProduct",
        "vulnerabilityName": f"{cve} Remote Code Execution",
        "dateAdded": "2026-04-23",
        "shortDescription": "A test KEV entry.",
        "requiredAction": "Apply updates.",
        "dueDate": due_date,
        "knownRansomwareCampaignUse": ransomware,
    }


class TestKevEntryDefaults:
    def test_defaults(self) -> None:
        e = KevEntry(cve_id="CVE-1")
        assert e.vendor_project == ""
        assert e.due_date == ""


class TestKevCatalogLookup:
    def test_lookup_case_insensitive(self) -> None:
        cat = KevCatalog(entries={"CVE-2024-0001": KevEntry(cve_id="CVE-2024-0001")})
        assert cat.lookup("cve-2024-0001") is not None
        assert cat.lookup("CVE-2024-0001") is not None

    def test_lookup_miss_returns_none(self) -> None:
        cat = KevCatalog()
        assert cat.lookup("CVE-X") is None

    def test_is_empty(self) -> None:
        assert KevCatalog().is_empty() is True
        cat = KevCatalog(entries={"X": KevEntry(cve_id="X")})
        assert cat.is_empty() is False


class TestParseKevFile:
    def test_full_parse(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text(json.dumps(_make_kev_doc([
            _kev_vuln("CVE-2024-0001"),
            _kev_vuln("CVE-2024-0002", ransomware="Known"),
        ])))
        cat = _parse_kev_file(p)
        assert cat.total_count == 2
        assert cat.catalog_version == "2026.04.23"
        assert "CVE-2024-0001" in cat.entries
        e = cat.entries["CVE-2024-0002"]
        assert e.known_ransomware_use == "Known"
        assert e.due_date == "2026-05-14"

    def test_missing_file_returns_empty(self, tmp_path: Path) -> None:
        cat = _parse_kev_file(tmp_path / "missing.json")
        assert cat.is_empty()

    def test_malformed_json(self, tmp_path: Path) -> None:
        p = tmp_path / "bad.json"
        p.write_text("{ this is not json")
        assert _parse_kev_file(p).is_empty()

    def test_tolerates_missing_fields(self, tmp_path: Path) -> None:
        p = tmp_path / "minimal.json"
        p.write_text(json.dumps({
            "vulnerabilities": [{"cveID": "CVE-2024-0001"}]
        }))
        cat = _parse_kev_file(p)
        assert "CVE-2024-0001" in cat.entries
        # Missing fields are empty strings, not None
        assert cat.entries["CVE-2024-0001"].due_date == ""

    def test_uppercases_cve_id(self, tmp_path: Path) -> None:
        p = tmp_path / "lower.json"
        p.write_text(json.dumps({
            "vulnerabilities": [{"cveID": "cve-2024-0001"}]
        }))
        cat = _parse_kev_file(p)
        assert "CVE-2024-0001" in cat.entries

    def test_non_dict_vuln_entry_skipped(self, tmp_path: Path) -> None:
        p = tmp_path / "mixed.json"
        p.write_text(json.dumps({
            "vulnerabilities": [
                "not-a-dict",
                {"cveID": "CVE-2024-0001"},
                {},  # no cveID
            ]
        }))
        cat = _parse_kev_file(p)
        assert len(cat.entries) == 1


class TestStaleness:
    def test_missing_file_is_stale(self, tmp_path: Path) -> None:
        assert _is_stale(tmp_path / "does-not-exist.json", 24) is True

    def test_fresh_file_not_stale(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text("{}")
        assert _is_stale(p, 24) is False

    def test_old_file_is_stale(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text("{}")
        old_time = time.time() - (25 * 3600)  # 25h old
        os.utime(p, (old_time, old_time))
        assert _is_stale(p, 24) is True


class TestLoadKevCatalog:
    def test_fresh_cache_is_reused(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text(json.dumps(_make_kev_doc([_kev_vuln("CVE-2024-0001")])))
        # Fresh file + allow_network=True should use cache without calling _fetch_kev
        with patch("kev._fetch_kev") as mock_fetch:
            cat = load_kev_catalog(cache_file=p, max_age_hours=24)
            mock_fetch.assert_not_called()
        assert "CVE-2024-0001" in cat.entries
        assert "fresh cache" in cat.source_note

    def test_stale_cache_triggers_fetch(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text(json.dumps(_make_kev_doc([])))
        old_time = time.time() - (25 * 3600)
        os.utime(p, (old_time, old_time))

        # Fetch will overwrite with new content
        def fake_fetch(path: Path) -> str:
            path.write_text(json.dumps(_make_kev_doc([_kev_vuln("CVE-2024-9999")])))
            return ""

        with patch("kev._fetch_kev", side_effect=fake_fetch):
            cat = load_kev_catalog(cache_file=p, max_age_hours=24)
        assert "CVE-2024-9999" in cat.entries
        assert "fresh fetch" in cat.source_note

    def test_fetch_failure_falls_back_to_stale_cache(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        p.write_text(json.dumps(_make_kev_doc([_kev_vuln("CVE-2024-0001")])))
        old_time = time.time() - (25 * 3600)
        os.utime(p, (old_time, old_time))

        with patch("kev._fetch_kev", return_value="network unreachable"):
            cat = load_kev_catalog(cache_file=p, max_age_hours=24)
        # Used the stale cache rather than failing outright
        assert "CVE-2024-0001" in cat.entries
        assert "stale cache" in cat.source_note
        assert "network unreachable" in cat.source_note

    def test_no_cache_no_network(self, tmp_path: Path) -> None:
        cat = load_kev_catalog(
            cache_file=tmp_path / "missing.json",
            allow_network=False,
        )
        assert cat.is_empty()
        assert "no cache" in cat.source_note

    def test_first_load_no_cache_fetches(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"

        def fake_fetch(path: Path) -> str:
            path.write_text(json.dumps(_make_kev_doc([_kev_vuln("CVE-2024-0001")])))
            return ""

        with patch("kev._fetch_kev", side_effect=fake_fetch):
            cat = load_kev_catalog(cache_file=p)
        assert "CVE-2024-0001" in cat.entries


class TestFetchKev:
    def test_success_writes_file(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"

        def fake_run_cmd(cmd: list[str], timeout: int = 60) -> tuple[bool, str, str]:
            # Simulate curl writing the target file
            out_idx = cmd.index("-o") + 1
            Path(cmd[out_idx]).write_text(json.dumps(_make_kev_doc([])))
            return True, "", ""

        with patch("kev.run_cmd", side_effect=fake_run_cmd):
            err = _fetch_kev(p)
        assert err == ""
        assert p.exists()

    def test_failure_reports_error(self, tmp_path: Path) -> None:
        p = tmp_path / "kev.json"
        with patch("kev.run_cmd", return_value=(False, "", "curl: host unreachable")):
            err = _fetch_kev(p)
        assert "unreachable" in err
        assert not p.exists()


class TestCrossCheck:
    def test_hit_and_miss(self) -> None:
        cat = KevCatalog(entries={
            "CVE-2024-0001": KevEntry(cve_id="CVE-2024-0001", due_date="2026-05-14"),
            "CVE-2024-0002": KevEntry(cve_id="CVE-2024-0002"),
        })
        hits = check_cves_against_kev(
            ["CVE-2024-0001", "CVE-2024-9999", "CVE-2024-0002"], cat
        )
        assert [h.cve_id for h in hits] == ["CVE-2024-0001", "CVE-2024-0002"]

    def test_dedupe(self) -> None:
        cat = KevCatalog(entries={"CVE-X": KevEntry(cve_id="CVE-X")})
        hits = check_cves_against_kev(["cve-x", "CVE-X", "CVE-x"], cat)
        assert len(hits) == 1

    def test_case_insensitive_input(self) -> None:
        cat = KevCatalog(entries={"CVE-2024-0001": KevEntry(cve_id="CVE-2024-0001")})
        hits = check_cves_against_kev(["cve-2024-0001"], cat)
        assert len(hits) == 1

    def test_empty_catalog(self) -> None:
        assert check_cves_against_kev(["CVE-X"], KevCatalog()) == []

    def test_empty_input(self) -> None:
        cat = KevCatalog(entries={"CVE-X": KevEntry(cve_id="CVE-X")})
        assert check_cves_against_kev([], cat) == []

    def test_non_string_items_ignored(self) -> None:
        cat = KevCatalog(entries={"CVE-X": KevEntry(cve_id="CVE-X")})
        hits = check_cves_against_kev(["CVE-X", 42, None, "CVE-X"], cat)  # type: ignore[list-item]
        assert len(hits) == 1
