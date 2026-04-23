"""Tests for the scan module — grype JSON parsing + run_scan orchestration."""

from __future__ import annotations

import json
import sys
from typing import Any
from unittest.mock import patch

sys.path.insert(0, "..")

from scan import (  # noqa: E402
    SEVERITY_ORDER,
    ScanResult,
    VulnCounts,
    _extract_grype_version,
    extract_cve_list,
    parse_grype_json,
    run_scan,
)


def _grype_output(matches: list[dict[str, Any]], version: str = "0.79.0") -> str:
    """Minimal grype -o json shape: `matches` array + `descriptor.version`."""
    return json.dumps({
        "matches": matches,
        "descriptor": {"name": "grype", "version": version},
        "source": {"type": "image", "target": {"userInput": "cgr.dev/x/y"}},
    })


def _match(cve: str, severity: str) -> dict[str, Any]:
    return {
        "vulnerability": {
            "id": cve,
            "severity": severity,
            "fix": {"state": "fixed", "versions": ["1.2.3"]},
        },
        "artifact": {"name": "pkg", "version": "1.2.0", "purl": "pkg:apk/wolfi/pkg@1.2.0"},
    }


class TestVulnCounts:
    def test_total_sums_all_severities(self) -> None:
        v = VulnCounts(critical=1, high=2, medium=3, low=4, negligible=5, unknown=6)
        assert v.total() == 21

    def test_empty_total_zero(self) -> None:
        assert VulnCounts().total() == 0

    def test_as_dict_stable_ordering(self) -> None:
        v = VulnCounts(critical=1, high=2)
        d = v.as_dict()
        assert list(d.keys()) == list(SEVERITY_ORDER)
        assert d["critical"] == 1


class TestParseGrypeJson:
    def test_empty_matches(self) -> None:
        counts = parse_grype_json(_grype_output([]))
        assert counts.total() == 0

    def test_severities_counted(self) -> None:
        counts = parse_grype_json(_grype_output([
            _match("CVE-2024-0001", "Critical"),
            _match("CVE-2024-0002", "High"),
            _match("CVE-2024-0003", "High"),
            _match("CVE-2024-0004", "Medium"),
            _match("CVE-2024-0005", "Low"),
            _match("CVE-2024-0006", "Negligible"),
        ]))
        assert counts.critical == 1
        assert counts.high == 2
        assert counts.medium == 1
        assert counts.low == 1
        assert counts.negligible == 1
        assert counts.total() == 6

    def test_unknown_severity_bucketed(self) -> None:
        counts = parse_grype_json(_grype_output([
            _match("CVE-2024-0007", "WeirdSeverity"),
        ]))
        assert counts.unknown == 1
        assert counts.critical == 0

    def test_malformed_json_returns_zero(self) -> None:
        counts = parse_grype_json("{not json")
        assert counts.total() == 0

    def test_empty_string_returns_zero(self) -> None:
        assert parse_grype_json("").total() == 0

    def test_missing_matches_array(self) -> None:
        counts = parse_grype_json(json.dumps({"descriptor": {"version": "0.79"}}))
        assert counts.total() == 0


class TestExtractCveList:
    def test_default_limit(self) -> None:
        text = _grype_output([_match(f"CVE-2024-{i:04d}", "High") for i in range(15)])
        cves = extract_cve_list(text)
        assert len(cves) == 10
        assert cves[0] == "CVE-2024-0000"

    def test_custom_limit(self) -> None:
        text = _grype_output([_match(f"CVE-2024-{i:04d}", "High") for i in range(5)])
        cves = extract_cve_list(text, limit=3)
        assert cves == ["CVE-2024-0000", "CVE-2024-0001", "CVE-2024-0002"]

    def test_malformed_returns_empty(self) -> None:
        assert extract_cve_list("@@@") == []


class TestGrypeVersion:
    def test_version_extracted(self) -> None:
        assert _extract_grype_version(_grype_output([], version="0.80.1")) == "0.80.1"

    def test_missing_descriptor(self) -> None:
        assert _extract_grype_version(json.dumps({"matches": []})) == ""


class TestRunScan:
    """Exercise run_scan with mocked grype + shutil.which."""

    def test_grype_not_installed_returns_error(self) -> None:
        with patch("scan.grype_installed", return_value=False):
            result = run_scan("cgr.dev/x/y@sha256:abc")
        assert result.success is False
        assert "grype binary not found" in result.error

    def test_grype_success_no_vex(self) -> None:
        out = _grype_output([_match("CVE-1", "High"), _match("CVE-2", "Medium")])
        with patch("scan.grype_installed", return_value=True), \
             patch("scan.run_cmd", return_value=(True, out, "")):
            result = run_scan("cgr.dev/x/y@sha256:abc")
        assert result.success is True
        assert result.raw_counts.total() == 2
        assert result.raw_counts.high == 1
        assert result.raw_counts.medium == 1
        # No VEX passed → actionable == raw
        assert result.actionable_counts.total() == 2
        assert result.vex_applied is False
        assert "CVE-1" in result.top_cves

    def test_grype_failure_returns_error(self) -> None:
        with patch("scan.grype_installed", return_value=True), \
             patch("scan.run_cmd", return_value=(False, "", "grype: db unavailable")):
            result = run_scan("cgr.dev/x/y@sha256:abc")
        assert result.success is False
        assert "db unavailable" in result.error

    def test_grype_with_vex_applied(self) -> None:
        raw_out = _grype_output([
            _match("CVE-1", "High"),
            _match("CVE-2", "Medium"),
            _match("CVE-3", "Medium"),
        ])
        # With VEX, CVE-2 and CVE-3 suppressed
        vex_out = _grype_output([_match("CVE-1", "High")])

        calls = []

        def fake_run_cmd(cmd: list[str], timeout: int = 30) -> tuple[bool, str, str]:
            calls.append(cmd)
            # Distinguish by presence of --vex
            if "--vex" in cmd:
                return True, vex_out, ""
            return True, raw_out, ""

        vex_pred = {
            "@context": "https://openvex.dev/ns/v0.2.0",
            "statements": [
                {"vulnerability": {"@id": "CVE-2"}, "status": "not_affected"},
                {"vulnerability": {"@id": "CVE-3"}, "status": "fixed"},
            ],
        }
        with patch("scan.grype_installed", return_value=True), \
             patch("scan.run_cmd", side_effect=fake_run_cmd):
            result = run_scan("cgr.dev/x/y@sha256:abc", vex_predicate=vex_pred)
        assert result.success is True
        assert result.raw_counts.total() == 3
        assert result.actionable_counts.total() == 1
        assert result.vex_applied is True
        # Both invocations observed
        assert len(calls) == 2
        assert any("--vex" in c for c in calls)

    def test_vex_run_failure_falls_back_to_raw(self) -> None:
        raw_out = _grype_output([_match("CVE-1", "High")])

        def fake_run_cmd(cmd: list[str], timeout: int = 30) -> tuple[bool, str, str]:
            if "--vex" in cmd:
                return False, "", "grype: vex parse error"
            return True, raw_out, ""

        vex_pred = {"@context": "https://openvex.dev/ns/v0.2.0"}
        with patch("scan.grype_installed", return_value=True), \
             patch("scan.run_cmd", side_effect=fake_run_cmd):
            result = run_scan("cgr.dev/x/y@sha256:abc", vex_predicate=vex_pred)
        assert result.success is True  # raw scan did succeed
        assert result.vex_applied is False  # VEX run failed
        assert result.actionable_counts.total() == 1  # fell back to raw
        assert "VEX-adjusted scan failed" in result.error


class TestScanResultDefaults:
    def test_defaults(self) -> None:
        r = ScanResult()
        assert r.success is False
        assert r.error == ""
        assert r.raw_counts.total() == 0
        assert r.actionable_counts.total() == 0
        assert r.vex_applied is False
        assert r.top_cves == []
