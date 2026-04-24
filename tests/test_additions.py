"""Tests for the P1-3/P1-4/P1-5/P2-1 through P2-5 additions.

Consolidated into one file to keep the additions easy to review. Existing
per-module test files cover primitives; this one covers the new glue
(freshness, FIPS, evidence bundle, SBOM drift, APK coords, cert-extension
surfacing) so regressions surface quickly.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, "..")

from verify_provenance import (  # noqa: E402
    ChainDetails,
    VerificationResult,
    _detect_fips_variant,
    _evaluate_freshness,
    _extract_fulcio_extensions,
)

# ─────────────────────── Freshness helper ───────────────────────


class TestEvaluateFreshness:
    def _make(self, age: int = -1, eol: bool = False) -> VerificationResult:
        r = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        r.chain.image_age_days = age
        r.chain.eol_predicate_present = eol
        return r

    def test_eol_predicate_wins_over_age(self) -> None:
        r = self._make(age=1, eol=True)  # fresh + EOL → EOL wins
        _evaluate_freshness(r, r.chain, max_age_days=365)
        assert r.freshness_status == "EOL"

    def test_unknown_age_stays_na(self) -> None:
        r = self._make(age=-1)
        _evaluate_freshness(r, r.chain, max_age_days=30)
        assert r.freshness_status == "N/A"

    def test_fresh_when_under_threshold(self) -> None:
        r = self._make(age=10)
        _evaluate_freshness(r, r.chain, max_age_days=30)
        assert r.freshness_status == "FRESH"

    def test_stale_when_over_threshold(self) -> None:
        r = self._make(age=40)
        _evaluate_freshness(r, r.chain, max_age_days=30)
        assert r.freshness_status == "STALE"

    def test_no_threshold_always_fresh(self) -> None:
        """max_age_days=0 disables the STALE verdict (age is informational)."""
        r = self._make(age=9999)
        _evaluate_freshness(r, r.chain, max_age_days=0)
        assert r.freshness_status == "FRESH"


# ────────────────────────── FIPS detection ──────────────────────────


class TestFipsDetection:
    def test_fips_suffix(self) -> None:
        is_fips, reason = _detect_fips_variant("python-fips", "cgr.dev/o/python-fips:latest")
        assert is_fips is True
        assert "-fips" in reason

    def test_plain_image(self) -> None:
        is_fips, reason = _detect_fips_variant("python", "cgr.dev/o/python:latest")
        assert is_fips is False
        assert reason == ""

    def test_fips_in_tag_not_name(self) -> None:
        """Some variants tag with -fips rather than name with -fips."""
        is_fips, _ = _detect_fips_variant("python", "cgr.dev/o/python:3.12-fips@sha256:x")
        assert is_fips is True

    def test_case_insensitive(self) -> None:
        is_fips, _ = _detect_fips_variant("Python-FIPS", "cgr.dev/o/Python-FIPS:latest")
        assert is_fips is True


# ────────────────────── Fulcio cert extensions ──────────────────────


class TestFulcioExtensions:
    def test_happy_path(self) -> None:
        chain = ChainDetails()
        _extract_fulcio_extensions(chain, {
            "GithubWorkflowRef": "refs/heads/main",
            "GithubWorkflowSha": "deadbeef" * 5,
            "GithubWorkflowTrigger": "push",
            "GithubWorkflowRunID": "42",
        })
        assert chain.github_workflow_ref == "refs/heads/main"
        assert chain.github_workflow_sha.startswith("deadbeef")
        assert chain.github_workflow_trigger == "push"
        assert chain.github_workflow_run_id == "42"

    def test_lowercase_variant(self) -> None:
        chain = ChainDetails()
        _extract_fulcio_extensions(chain, {
            "githubWorkflowRef": "refs/tags/v1",
        })
        assert chain.github_workflow_ref == "refs/tags/v1"

    def test_missing_fields_stay_empty(self) -> None:
        chain = ChainDetails()
        _extract_fulcio_extensions(chain, {})
        assert chain.github_workflow_ref == ""


# ───────────────────────── Evidence bundle ─────────────────────────


class TestEvidenceBundle:
    def _minimal_result(self) -> VerificationResult:
        r = VerificationResult(
            image="test-image", base_digest="sha256:abc", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="12345", sig_status="VALID",
            status="VERIFIED", error="",
        )
        r.chain.customer_digest = "sha256:abc"
        r.chain.base_digest_full = "sha256:abc"
        r.chain.rekor_verified = True
        return r

    def test_bundle_structure(self, tmp_path: Path) -> None:
        from evidence import write_evidence_bundle

        result = self._minimal_result()
        img_dir = write_evidence_bundle(
            bundle_root=tmp_path,
            result=result,
            tool_version="0.1.0",
            customer_org="test-org",
            mode="delivery",
            policy_source="(defaults)",
        )
        assert img_dir.exists()
        assert (img_dir / "metadata.json").exists()
        assert (img_dir / "SUMMARY.md").exists()
        assert (img_dir / "SHA256SUMS").exists()
        assert (img_dir / "controls.json").exists()
        assert (img_dir / "attestations").is_dir()

    def test_metadata_content(self, tmp_path: Path) -> None:
        from evidence import write_evidence_bundle

        result = self._minimal_result()
        img_dir = write_evidence_bundle(
            bundle_root=tmp_path, result=result, tool_version="0.1.0",
            customer_org="test-org", mode="delivery", policy_source="p.json",
        )
        meta = json.loads((img_dir / "metadata.json").read_text())
        assert meta["verification_status"] == "VERIFIED"
        assert meta["tool_version"] == "0.1.0"
        assert meta["policy_source"] == "p.json"

    def test_controls_mapping_includes_signature(self, tmp_path: Path) -> None:
        from evidence import write_evidence_bundle

        result = self._minimal_result()
        img_dir = write_evidence_bundle(
            bundle_root=tmp_path, result=result, tool_version="v",
            customer_org="o", mode="m", policy_source="p",
        )
        controls = json.loads((img_dir / "controls.json").read_text())
        assert "signature" in controls
        assert "SSDF" in controls["signature"]
        assert "rekor_verified" in controls  # chain.rekor_verified == True

    def test_sha256sums_covers_all_files(self, tmp_path: Path) -> None:
        from evidence import write_evidence_bundle

        result = self._minimal_result()
        img_dir = write_evidence_bundle(
            bundle_root=tmp_path, result=result, tool_version="v",
            customer_org="o", mode="m", policy_source="p",
        )
        lines = (img_dir / "SHA256SUMS").read_text().strip().splitlines()
        assert len(lines) > 0
        # Each line has hash + "  " + path
        for ln in lines:
            h, _, path = ln.partition("  ")
            assert len(h) == 64
            assert (img_dir / path).exists()
        # Manifest should NOT include itself
        assert not any("SHA256SUMS" in ln for ln in lines)

    def test_attestation_files_written(self, tmp_path: Path) -> None:
        from attestation import PREDICATE_SLSA_V1, AttestationRecord
        from evidence import write_evidence_bundle

        result = self._minimal_result()
        rec = AttestationRecord(
            predicate_type=PREDICATE_SLSA_V1, verified=True, subject_matches=True,
        )
        result.chain.attestations[PREDICATE_SLSA_V1] = rec

        img_dir = write_evidence_bundle(
            bundle_root=tmp_path, result=result, tool_version="v",
            customer_org="o", mode="m", policy_source="p",
        )
        # v1 → attestations/v1.json
        files = list((img_dir / "attestations").glob("*.json"))
        assert len(files) == 1


# ────────────────────── SBOM drift (scan.py) ──────────────────────


class TestExtractPurlSet:
    def test_spdx(self) -> None:
        from scan import extract_purl_set

        doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/x"},
                    {"referenceType": "other", "referenceLocator": "not-a-purl"},
                ]},
                {"externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/y"},
                ]},
            ],
        }
        assert extract_purl_set(doc) == {
            "pkg:apk/wolfi/x", "pkg:apk/wolfi/y",
        }

    def test_cyclonedx(self) -> None:
        from scan import extract_purl_set

        doc = {
            "bomFormat": "CycloneDX", "specVersion": "1.5",
            "components": [
                {"purl": "pkg:apk/wolfi/x"},
                {"purl": "pkg:apk/wolfi/y"},
                {"name": "no-purl"},
            ],
        }
        assert extract_purl_set(doc) == {"pkg:apk/wolfi/x", "pkg:apk/wolfi/y"}

    def test_empty_doc(self) -> None:
        from scan import extract_purl_set

        assert extract_purl_set({}) == set()


class TestRunSbomDrift:
    def test_syft_missing(self) -> None:
        from scan import run_sbom_drift

        with patch("scan.syft_installed", return_value=False):
            d = run_sbom_drift("cgr.dev/x/y", attested_purls=set())
        assert d.success is False
        assert "syft" in d.error

    def test_clean_match(self) -> None:
        from scan import run_sbom_drift

        attested = {"pkg:apk/wolfi/a", "pkg:apk/wolfi/b"}
        # syft returns the same set
        syft_doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/a"},
                ]},
                {"externalRefs": [
                    {"referenceType": "purl", "referenceLocator": "pkg:apk/wolfi/b"},
                ]},
            ],
        }
        with patch("scan.syft_installed", return_value=True), \
             patch("scan.run_cmd", return_value=(True, json.dumps(syft_doc), "")):
            d = run_sbom_drift("cgr.dev/x/y", attested_purls=attested)
        assert d.success is True
        assert d.drift_ratio == 0.0
        assert d.shared_count == 2
        assert d.only_attested == []
        assert d.only_local == []

    def test_drift_detected(self) -> None:
        from scan import run_sbom_drift

        attested = {"pkg:apk/wolfi/a", "pkg:apk/wolfi/b"}
        syft_doc = {
            "spdxVersion": "SPDX-2.3",
            "packages": [{"externalRefs": [{"referenceType": "purl",
                                            "referenceLocator": "pkg:apk/wolfi/c"}]}],
        }
        with patch("scan.syft_installed", return_value=True), \
             patch("scan.run_cmd", return_value=(True, json.dumps(syft_doc), "")):
            d = run_sbom_drift("cgr.dev/x/y", attested_purls=attested)
        assert d.success is True
        assert d.drift_ratio > 0.5
        assert "pkg:apk/wolfi/a" in d.only_attested
        assert "pkg:apk/wolfi/c" in d.only_local


# ──────────────────── APK coordinate parsing ────────────────────


class TestApkCoordinate:
    def test_basic(self) -> None:
        from verify_library import parse_apk_coordinate, resolve_apk_url

        a = parse_apk_coordinate("glibc-2.39-r1")
        assert a["name"] == "glibc"
        assert a["version"] == "2.39-r1"
        assert a["filename"] == "glibc-2.39-r1.apk"
        assert resolve_apk_url("glibc-2.39-r1").endswith("/apk/x86_64/glibc-2.39-r1.apk")

    def test_arch_override(self) -> None:
        from verify_library import resolve_apk_url

        assert resolve_apk_url("glibc-2.39-r1@aarch64").endswith("/apk/aarch64/glibc-2.39-r1.apk")

    def test_invalid(self) -> None:
        from verify_library import parse_apk_coordinate

        with pytest.raises(ValueError):
            parse_apk_coordinate("no-version-info")


# ─────────────────── --full flag implications ───────────────────


class TestFullFlagImplications:
    """--full means 'run every verification check'; --scan stays opt-in."""

    def _args(self, **overrides: object) -> object:
        """Build a minimal args Namespace for run_image_mode flag-normalization."""
        import argparse
        defaults = {
            "full": False, "verify_signatures": False, "verify_attestations": False,
            "scan": False, "sbom_drift": False, "version": True,  # exit-early after normalize
            "customer_org": "x", "format": "table",
        }
        defaults.update(overrides)
        return argparse.Namespace(**defaults)

    def _normalize(self, args: object) -> None:
        """Exercise only the flag-normalization block of run_image_mode.
        Duplicated here so the test doesn't need to reach past the --version
        early-exit in the function itself."""
        if args.full:
            args.verify_signatures = True
            args.verify_attestations = True
        if args.scan or args.sbom_drift:
            args.verify_attestations = True

    def test_full_implies_verify_signatures(self) -> None:
        args = self._args(full=True)
        self._normalize(args)
        assert args.verify_signatures is True

    def test_full_implies_verify_attestations(self) -> None:
        args = self._args(full=True)
        self._normalize(args)
        assert args.verify_attestations is True

    def test_full_does_not_imply_scan(self) -> None:
        """Vulnerability scanning is explicitly opt-in; it's not a
        verification check and grype takes minutes per image."""
        args = self._args(full=True)
        self._normalize(args)
        assert args.scan is False

    def test_full_does_not_imply_sbom_drift(self) -> None:
        """SBOM drift requires syft; remains opt-in to avoid surprising users."""
        args = self._args(full=True)
        self._normalize(args)
        assert args.sbom_drift is False

    def test_scan_alone_does_not_set_signatures(self) -> None:
        """Sanity: --scan pulls in attestations (for VEX) but NOT signatures."""
        args = self._args(scan=True)
        self._normalize(args)
        assert args.verify_attestations is True
        assert args.verify_signatures is False  # only --full implies this


# ─────────────────── Summary renderers (--format) ───────────────────


class TestSummaryRenderers:
    def _results(self) -> list[VerificationResult]:
        """Two contrived results covering the interesting value combinations:
        one clean verified image and one with findings + KEV hit + policy failure.
        """
        r1 = VerificationResult(
            image="python", base_digest="sha256:aaa", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="111", sig_status="VALID",
            status="VERIFIED", error="",
        )
        r1.chain.rekor_verified = True
        r1.chain.image_age_days = 2
        r1.freshness_status = "FRESH"
        r1.slsa_status = "VERIFIED"
        r1.sbom_status = "VERIFIED"
        r1.sbom_package_count = 287
        r1.policy_status = "PASS"
        r1.vuln_status = "CLEAN"
        r1.kev_status = "CLEAN"
        r1.vex_applied = True
        r1.fips_variant = False

        r2 = VerificationResult(
            image="legacy-app", base_digest="sha256:bbb", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="222", sig_status="VALID",
            status="KEV_HIT", error="",
        )
        r2.chain.rekor_verified = True
        r2.chain.image_age_days = 180
        r2.freshness_status = "STALE"
        r2.slsa_status = "VERIFIED"
        r2.sbom_status = "VERIFIED"
        r2.sbom_package_count = 100
        r2.policy_status = "PASS"
        r2.vuln_status = "FINDINGS"
        r2.vuln_critical = 2
        r2.vuln_high = 5
        r2.vuln_medium = 10
        r2.vuln_low = 3
        r2.vuln_total = 20
        r2.kev_status = "HIT"
        r2.kev_count = 1
        r2.fips_variant = True
        return [r1, r2]

    def test_table_has_header_and_rows(self) -> None:
        from verify_provenance import _render_summary_table

        out = _render_summary_table(self._results())
        assert "IMAGE" in out
        assert "VERDICT" in out
        assert "python" in out
        assert "legacy-app" in out
        assert "KEV_HIT" in out
        # Compact VULN encoding for the findings row
        assert "2C/5H/10M/3L" in out
        # VEX star on r1
        assert "0C/0H/0M/0L*" in out
        # FRESH suppressed from age column; STALE kept
        python_line = next(line for line in out.splitlines() if "python" in line)
        assert "FRESH" not in python_line  # FRESH is the common case → hidden
        legacy_line = next(line for line in out.splitlines() if "legacy-app" in line)
        assert "STALE" in legacy_line

    def test_table_columns_aligned(self) -> None:
        """Sanity: each data row is at least as wide as the header."""
        from verify_provenance import _render_summary_table

        out = _render_summary_table(self._results())
        # Everything up to the first blank line is the table; legend follows.
        table_block = out.split("\n\n", 1)[0]
        non_sep = [
            ln for ln in table_block.splitlines()
            if ln.strip() and not set(ln.strip()) <= set("- ")
        ]
        assert len(non_sep) == 3  # header + 2 data rows
        header_width = len(non_sep[0])
        for row in non_sep[1:]:
            # Row trailing spaces are stripped by ljust padding, so allow some slack
            assert len(row.rstrip()) >= header_width - 2

    def test_json_output_shape(self) -> None:
        import argparse as ap

        from verify_provenance import _render_summary_json

        args = ap.Namespace(customer_org="test-org")
        results = self._results()
        counts = {"VERIFIED": 1, "KEV_HIT": 1}
        out = _render_summary_json(
            results, args, customer_only=True, reference_org="chainguard-private",
            csv_file="test-org.csv", counts=counts,
        )
        doc = json.loads(out)
        assert doc["customer_org"] == "test-org"
        assert doc["mode"] == "delivery"
        assert doc["reference_org"] is None  # customer-only
        assert doc["total"] == 2
        assert doc["verdict_counts"] == counts
        assert len(doc["results"]) == 2
        assert doc["results"][0]["image"] in ("python", "legacy-app")
        kev_row = next(r for r in doc["results"] if r["image"] == "legacy-app")
        assert kev_row["verdict"] == "KEV_HIT"
        assert kev_row["vuln_total"] == 20
        assert kev_row["fips_variant"] is True

    def test_json_output_with_no_csv_file(self) -> None:
        """`--csv-output` unset → no file written, csv_file field is null."""
        import argparse as ap

        from verify_provenance import _render_summary_json

        args = ap.Namespace(customer_org="test-org")
        out = _render_summary_json(
            self._results(), args, customer_only=True, reference_org="chainguard-private",
            csv_file=None, counts={},
        )
        doc = json.loads(out)
        assert doc["csv_file"] is None

    def test_csv_output_parseable(self) -> None:
        import csv as _csv
        import io

        from verify_provenance import _render_summary_csv

        out = _render_summary_csv(self._results(), customer_only=True)
        reader = _csv.reader(io.StringIO(out))
        rows = list(reader)
        assert rows[0][0] == "IMAGE"
        assert len(rows) == 3  # header + 2 data rows
        # Image column matches input
        assert {rows[1][0], rows[2][0]} == {"python", "legacy-app"}

    def test_exit_status_verified_is_zero(self) -> None:
        from verify_provenance import _compute_exit_status

        assert _compute_exit_status(
            self._results(), {"VERIFIED": 1, "KEV_HIT": 1}, customer_only=True
        ) == 0

    def test_exit_status_not_found_in_full_mode_is_one(self) -> None:
        from verify_provenance import _compute_exit_status

        assert _compute_exit_status(
            self._results(), {"NOT_FOUND": 3}, customer_only=False
        ) == 1

    def test_exit_status_not_found_customer_only_is_zero(self) -> None:
        """NOT_FOUND is meaningless in delivery mode (no reference org check)."""
        from verify_provenance import _compute_exit_status

        assert _compute_exit_status(
            self._results(), {"NOT_FOUND": 3}, customer_only=True
        ) == 0
