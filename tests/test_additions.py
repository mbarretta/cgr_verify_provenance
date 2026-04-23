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
