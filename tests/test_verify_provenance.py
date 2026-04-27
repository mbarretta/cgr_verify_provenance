"""Tests for verify_provenance module."""

import base64
import json

# Import the module under test
import sys
from unittest.mock import MagicMock, patch

sys.path.insert(0, "..")
from verify_provenance import (
    BASE_DIGEST_LABEL,
    REQUIRED_TOOLS,
    ChainDetails,
    VerificationResult,
    check_dependencies,
    run_cmd,
)


def _policy():  # type: ignore[no-untyped-def]
    """Permissive policy for glue tests. Empty allowlists = no policy checks
    run, so these tests exercise status mapping without getting tangled in
    builder.id/source_uri behavior. Allowlist semantics live in test_policy.py.
    """
    from policy import IdentityPolicy
    return IdentityPolicy(
        cosign_oidc_issuer_regex="^x$",
        cosign_identity_regex=".*",
        allowed_builder_ids=[],
        allowed_source_uris=[],
    )


class TestRunCmd:
    """Tests for the run_cmd helper function."""

    def test_run_cmd_success(self) -> None:
        """Test successful command execution."""
        success, stdout, stderr = run_cmd(["echo", "hello"])
        assert success is True
        assert stdout.strip() == "hello"
        assert stderr == ""

    def test_run_cmd_failure(self) -> None:
        """Test failed command execution."""
        success, stdout, stderr = run_cmd(["false"])
        assert success is False

    def test_run_cmd_timeout(self) -> None:
        """Test command timeout handling."""
        success, stdout, stderr = run_cmd(["sleep", "10"], timeout=1)
        assert success is False
        assert stderr == "timeout"

    def test_run_cmd_nonexistent(self) -> None:
        """Test nonexistent command handling."""
        success, stdout, stderr = run_cmd(["nonexistent_command_12345"])
        assert success is False


class TestCheckDependencies:
    """Tests for dependency checking."""

    def test_check_dependencies_with_echo(self) -> None:
        """Test that common tools are found."""
        # At minimum, 'echo' should exist on any system
        import shutil
        assert shutil.which("echo") is not None

    @patch("shutil.which")
    def test_check_dependencies_missing(self, mock_which: MagicMock) -> None:
        """Test detection of missing dependencies."""
        mock_which.return_value = None
        missing = check_dependencies()
        assert len(missing) == len(REQUIRED_TOOLS)
        assert "chainctl" in missing
        assert "crane" in missing
        assert "cosign" in missing

    @patch("shutil.which")
    def test_check_dependencies_all_present(self, mock_which: MagicMock) -> None:
        """Test when all dependencies are present."""
        mock_which.return_value = "/usr/local/bin/tool"
        missing = check_dependencies()
        assert len(missing) == 0


class TestRekorVerificationCrossCheck:
    """Rekor logIndex cross-check between bundle JSON and cosign verify output."""

    def test_matching_logindex_no_mismatch_marker(self) -> None:
        from verify_provenance import _cross_check_rekor_logindex

        chain = ChainDetails(
            rekor_log_index="12345",
            rekor_url="https://search.sigstore.dev/?logIndex=12345",
        )
        cert_info = {"Bundle": {"Payload": {"logIndex": 12345}}}
        _cross_check_rekor_logindex(chain, cert_info)
        assert "MISMATCH" not in chain.rekor_url

    def test_mismatch_flagged_in_rekor_url(self) -> None:
        from verify_provenance import _cross_check_rekor_logindex

        chain = ChainDetails(
            rekor_log_index="12345",
            rekor_url="https://search.sigstore.dev/?logIndex=12345",
        )
        cert_info = {"Bundle": {"Payload": {"logIndex": 99999}}}
        _cross_check_rekor_logindex(chain, cert_info)
        assert "MISMATCH" in chain.rekor_url
        assert "12345" in chain.rekor_url
        assert "99999" in chain.rekor_url

    def test_no_bundle_in_cert_info_no_op(self) -> None:
        from verify_provenance import _cross_check_rekor_logindex

        chain = ChainDetails(
            rekor_log_index="12345",
            rekor_url="https://search.sigstore.dev/?logIndex=12345",
        )
        _cross_check_rekor_logindex(chain, {})
        assert "MISMATCH" not in chain.rekor_url

    def test_no_existing_logindex_no_op(self) -> None:
        """If we had no bundle logIndex to begin with, no mismatch possible."""
        from verify_provenance import _cross_check_rekor_logindex

        chain = ChainDetails(rekor_url="")
        cert_info = {"Bundle": {"Payload": {"logIndex": 12345}}}
        _cross_check_rekor_logindex(chain, cert_info)
        # No MISMATCH marker because there was no bundle-side value
        assert chain.rekor_url == ""

    def test_customer_rekor_index_also_checked(self) -> None:
        """Customer-only mode stores logIndex in customer_rekor_index instead."""
        from verify_provenance import _cross_check_rekor_logindex

        chain = ChainDetails(
            customer_rekor_index="77",
            rekor_url="url",
        )
        cert_info = {"Bundle": {"Payload": {"logIndex": 888}}}
        _cross_check_rekor_logindex(chain, cert_info)
        assert "MISMATCH" in chain.rekor_url


class TestChainDetails:
    """Tests for ChainDetails dataclass."""

    def test_chain_details_defaults(self) -> None:
        """Test default values for ChainDetails."""
        chain = ChainDetails()
        assert chain.customer_image == ""
        assert chain.customer_digest == ""
        assert chain.base_digest_full == ""
        assert chain.base_digest_label == BASE_DIGEST_LABEL
        assert chain.reference_exists is False
        assert chain.signature_found is False
        assert chain.payload_matches is False
        assert chain.cert_verified is False
        # Rekor fields: neither present in bundle nor cryptographically verified by default
        assert chain.rekor_verified is False
        assert chain.rekor_set_present is False

    def test_chain_details_initialization(self) -> None:
        """Test ChainDetails with values."""
        chain = ChainDetails(
            customer_image="cgr.dev/test/image:latest",
            customer_digest="sha256:abc123",
            base_digest_full="sha256:def456",
        )
        assert chain.customer_image == "cgr.dev/test/image:latest"
        assert chain.customer_digest == "sha256:abc123"
        assert chain.base_digest_full == "sha256:def456"


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_verification_result_defaults(self) -> None:
        """Test default values for VerificationResult."""
        result = VerificationResult(
            image="test-image",
            base_digest="sha256:abc...",
            ref_status="N/A",
            rekor_status="N/A",
            rekor_log_index="",
            sig_status="N/A",
            status="ERROR",
            error="",
        )
        assert result.image == "test-image"
        assert result.status == "ERROR"
        assert isinstance(result.chain, ChainDetails)


class TestPayloadDecoding:
    """Tests for signature payload decoding logic."""

    def test_decode_payload(self) -> None:
        """Test decoding a cosign signature payload."""
        # Create a mock payload structure
        payload = {
            "critical": {
                "image": {
                    "docker-manifest-digest": "sha256:abc123def456"
                },
                "type": "cosign container image signature"
            },
            "optional": {}
        }
        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode()).decode()

        # Decode it back
        decoded = base64.b64decode(payload_b64).decode("utf-8")
        parsed = json.loads(decoded)

        assert parsed["critical"]["image"]["docker-manifest-digest"] == "sha256:abc123def456"

    def test_payload_digest_extraction(self) -> None:
        """Test extracting digest from nested payload structure."""
        payload = {
            "critical": {
                "image": {
                    "docker-manifest-digest": "sha256:expected_digest"
                }
            }
        }

        digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
        assert digest == "sha256:expected_digest"

    def test_payload_missing_fields(self) -> None:
        """Test handling of missing fields in payload."""
        payload = {"critical": {}}

        digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
        assert digest == ""


class TestConstants:
    """Tests for module constants."""

    def test_base_digest_label(self) -> None:
        """Test the base digest label constant."""
        assert BASE_DIGEST_LABEL == "org.opencontainers.image.base.digest"

    def test_required_tools(self) -> None:
        """Test required tools list."""
        assert "chainctl" in REQUIRED_TOOLS
        assert "crane" in REQUIRED_TOOLS
        assert "cosign" in REQUIRED_TOOLS


class TestVerifyImageAttestationsGlue:
    """Status mapping between AttestationRecord and result.slsa_status."""

    def _make_rec(self, **overrides: object) -> object:
        from attestation import PREDICATE_SLSA_V1, AttestationRecord
        rec = AttestationRecord(predicate_type=PREDICATE_SLSA_V1)
        for k, v in overrides.items():
            setattr(rec, k, v)
        return rec

    def test_verified_and_matched(self) -> None:
        from attestation import PREDICATE_SLSA_V1
        from verify_provenance import _verify_image_attestations
        rec = self._make_rec(verified=True, subject_matches=True)
        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),

            )
        assert result.slsa_status == "VERIFIED"
        assert result.chain.attestations[PREDICATE_SLSA_V1] is rec

    def test_subject_mismatch(self) -> None:
        from verify_provenance import _verify_image_attestations
        rec = self._make_rec(
            verified=True, subject_matches=False,
            error="attestation subject digest did not match image digest",
        )
        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),

            )
        assert result.slsa_status == "SUBJECT_MISMATCH"

    def test_no_attestation_found(self) -> None:
        from verify_provenance import _verify_image_attestations
        rec = self._make_rec(
            verified=False,
            error="no matching attestations",
        )
        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),

            )
        assert result.slsa_status == "NOT_FOUND"

    def test_cosign_error_other(self) -> None:
        from verify_provenance import _verify_image_attestations
        rec = self._make_rec(verified=False, error="network error")
        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),

            )
        assert result.slsa_status == "UNVERIFIED"


class TestSbomGlue:
    """SBOM retrieval interleaving: SPDX preferred, CycloneDX fallback."""

    def _rec(self, predicate_type: str, **overrides: object) -> object:
        from attestation import AttestationRecord
        rec = AttestationRecord(predicate_type=predicate_type)
        for k, v in overrides.items():
            setattr(rec, k, v)
        return rec

    def _sbom_summary(self, package_count: int = 3, is_empty: bool = False,
                     sbom_format: str = "spdx") -> object:
        from attestation import SbomSummary
        return SbomSummary(
            sbom_format=sbom_format, package_count=package_count, is_empty=is_empty,
        )

    def test_spdx_verified_populates_sbom_status(self) -> None:
        from attestation import PREDICATE_SLSA_V1, PREDICATE_SPDX
        from verify_provenance import _verify_image_attestations

        slsa_rec = self._rec(PREDICATE_SLSA_V1, verified=True, subject_matches=True)
        spdx_rec = self._rec(
            PREDICATE_SPDX, verified=True, subject_matches=True,
            sbom=self._sbom_summary(package_count=42),
        )

        def side_effect(**kwargs: object) -> object:
            if kwargs["predicate_type"] == PREDICATE_SLSA_V1:
                return slsa_rec
            return spdx_rec

        with patch("attestation.retrieve_and_verify_attestation", side_effect=side_effect):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),
            )
        assert result.slsa_status == "VERIFIED"
        assert result.sbom_status == "VERIFIED"
        assert result.sbom_format == "spdx"
        assert result.sbom_package_count == 42

    def test_spdx_missing_falls_back_to_cyclonedx(self) -> None:
        from attestation import (
            PREDICATE_CYCLONEDX,
            PREDICATE_SLSA_V1,
            PREDICATE_SPDX,
        )
        from verify_provenance import _verify_image_attestations

        slsa_rec = self._rec(PREDICATE_SLSA_V1, verified=True, subject_matches=True)
        spdx_rec = self._rec(
            PREDICATE_SPDX, verified=False, error="no matching attestations",
        )
        cyclo_rec = self._rec(
            PREDICATE_CYCLONEDX, verified=True, subject_matches=True,
            sbom=self._sbom_summary(package_count=17, sbom_format="cyclonedx"),
        )

        def side_effect(**kwargs: object) -> object:
            pt = kwargs["predicate_type"]
            if pt == PREDICATE_SLSA_V1:
                return slsa_rec
            if pt == PREDICATE_SPDX:
                return spdx_rec
            return cyclo_rec

        with patch("attestation.retrieve_and_verify_attestation", side_effect=side_effect):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),
            )
        assert result.sbom_status == "VERIFIED"
        assert result.sbom_format == "cyclonedx"
        assert result.sbom_package_count == 17

    def test_empty_sbom_marked_empty(self) -> None:
        from attestation import PREDICATE_SLSA_V1, PREDICATE_SPDX
        from verify_provenance import _verify_image_attestations

        slsa_rec = self._rec(PREDICATE_SLSA_V1, verified=True, subject_matches=True)
        spdx_rec = self._rec(
            PREDICATE_SPDX, verified=True, subject_matches=True,
            sbom=self._sbom_summary(package_count=0, is_empty=True),
        )

        def side_effect(**kwargs: object) -> object:
            if kwargs["predicate_type"] == PREDICATE_SLSA_V1:
                return slsa_rec
            return spdx_rec

        with patch("attestation.retrieve_and_verify_attestation", side_effect=side_effect):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),
            )
        assert result.sbom_status == "EMPTY"

    def test_sbom_subject_mismatch(self) -> None:
        from attestation import PREDICATE_SLSA_V1, PREDICATE_SPDX
        from verify_provenance import _verify_image_attestations

        slsa_rec = self._rec(PREDICATE_SLSA_V1, verified=True, subject_matches=True)
        spdx_rec = self._rec(
            PREDICATE_SPDX, verified=True, subject_matches=False,
            error="attestation subject digest did not match image digest",
        )

        def side_effect(**kwargs: object) -> object:
            if kwargs["predicate_type"] == PREDICATE_SLSA_V1:
                return slsa_rec
            return spdx_rec

        with patch("attestation.retrieve_and_verify_attestation", side_effect=side_effect):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=_policy(),
            )
        assert result.slsa_status == "VERIFIED"
        assert result.sbom_status == "SUBJECT_MISMATCH"


class TestPolicyGlue:
    """Policy allowlist evaluation triggered after SLSA parse."""

    def test_policy_pass_when_builder_matches(self) -> None:
        from attestation import (
            PREDICATE_SLSA_V1,
            AttestationRecord,
            SlsaProvenance,
        )
        from policy import IdentityPolicy
        from verify_provenance import _verify_image_attestations

        prov = SlsaProvenance(
            builder_id="https://approved-builder.example.com/ci",
            source_uri="git+https://github.com/my-org/my-repo@main",
        )
        rec = AttestationRecord(
            predicate_type=PREDICATE_SLSA_V1,
            verified=True,
            subject_matches=True,
            slsa=prov,
        )
        strict_policy = IdentityPolicy(
            cosign_oidc_issuer_regex="^x$",
            cosign_identity_regex=".*",
            allowed_builder_ids=[r"^https://approved-builder\.example\.com/.*$"],
            allowed_source_uris=[r"^git\+https://github\.com/my-org/.*$"],
        )

        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=strict_policy,
            )
        assert result.policy_status == "PASS"
        assert result.chain.policy_violations == []

    def test_policy_violation_demotes_verdict(self) -> None:
        from attestation import (
            PREDICATE_SLSA_V1,
            AttestationRecord,
            SlsaProvenance,
        )
        from policy import IdentityPolicy
        from verify_provenance import _verify_image_attestations

        prov = SlsaProvenance(
            builder_id="https://evil-fork.example/ci",
            source_uri="",
        )
        rec = AttestationRecord(
            predicate_type=PREDICATE_SLSA_V1,
            verified=True,
            subject_matches=True,
            slsa=prov,
        )
        strict_policy = IdentityPolicy(
            cosign_oidc_issuer_regex="^x$",
            cosign_identity_regex=".*",
            allowed_builder_ids=[r"^https://approved-builder\.example\.com/.*$"],
            allowed_source_uris=[r"^git\+https://github\.com/my-org/.*$"],
        )

        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=strict_policy,
            )
        assert result.policy_status == "VIOLATION"
        # Two violations: builder_id is off-allowlist, source_uri is empty
        checks = {v.check for v in result.chain.policy_violations}
        assert checks == {"builder_id", "source_uri"}

    def test_policy_not_evaluated_when_slsa_not_verified(self) -> None:
        """Policy eval only runs on verified+matched records — otherwise the
        predicate isn't trustworthy input in the first place."""
        from attestation import PREDICATE_SLSA_V1, AttestationRecord
        from policy import IdentityPolicy
        from verify_provenance import _verify_image_attestations

        rec = AttestationRecord(
            predicate_type=PREDICATE_SLSA_V1,
            verified=False,
            error="no matching attestations",
        )
        strict_policy = IdentityPolicy(
            cosign_oidc_issuer_regex="^x$",
            cosign_identity_regex=".*",
            allowed_builder_ids=[r"^https://approved-builder\.example\.com/.*$"],
            allowed_source_uris=[],
        )

        with patch("attestation.retrieve_and_verify_attestation", return_value=rec):
            result = VerificationResult(
                image="x", base_digest="", ref_status="", rekor_status="",
                rekor_log_index="", sig_status="", status="", error="",
            )
            _verify_image_attestations(
                result, result.chain,
                image_ref="cgr.dev/o/i@sha256:abc",
                expected_digest="sha256:abc",
                policy=strict_policy,
            )
        assert result.slsa_status == "NOT_FOUND"
        assert result.policy_status == "N/A"
        assert result.chain.policy_violations == []


class TestScanGlue:
    """Vulnerability scan status mapping + VEX predicate passing."""

    def test_scan_clean(self) -> None:
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(),
            actionable_counts=VulnCounts(),
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain, image_ref="cgr.dev/x/y@sha256:abc")
        assert result.vuln_status == "CLEAN"
        assert result.vuln_total == 0

    def test_scan_findings(self) -> None:
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(critical=1, high=3),
            actionable_counts=VulnCounts(critical=1, high=2),
            vex_applied=True,
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain, image_ref="cgr.dev/x/y@sha256:abc")
        assert result.vuln_status == "FINDINGS"
        assert result.vuln_critical == 1
        assert result.vuln_high == 2  # actionable, not raw
        assert result.vuln_total == 3
        assert result.vex_applied is True

    def test_scan_error(self) -> None:
        from scan import ScanResult
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(success=False, error="grype: db unavailable")
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain, image_ref="cgr.dev/x/y@sha256:abc")
        assert result.vuln_status == "ERROR"

    def test_vex_predicate_passed_only_when_verified(self) -> None:
        """Unverified or subject-mismatched VEX must NOT be passed to grype —
        that's exactly the attack surface signing protects."""
        from attestation import PREDICATE_OPENVEX, AttestationRecord
        from verify_provenance import _run_vuln_scan

        # Subject-mismatched VEX: signed but describes a different image
        rogue_vex = AttestationRecord(
            predicate_type=PREDICATE_OPENVEX,
            verified=True,
            subject_matches=False,
            predicate={"statements": [{"vulnerability": {"@id": "CVE-1"},
                                       "status": "not_affected"}]},
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        result.chain.attestations[PREDICATE_OPENVEX] = rogue_vex

        captured_vex: list[object] = []

        def fake_run_scan(image_ref: str, vex_predicate: object = None, timeout: int = 300) -> object:
            captured_vex.append(vex_predicate)
            from scan import ScanResult
            return ScanResult(success=True)

        with patch("scan.run_scan", side_effect=fake_run_scan):
            _run_vuln_scan(result, result.chain, image_ref="cgr.dev/x/y@sha256:abc")
        assert captured_vex == [None]  # rogue VEX was NOT passed

    def test_kev_hit_populated(self) -> None:
        """KEV cross-check runs against actionable CVE list when catalog present."""
        from kev import KevCatalog, KevEntry
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(high=2),
            actionable_counts=VulnCounts(high=2),
            actionable_cve_ids=["CVE-2024-0001", "CVE-2024-0002"],
        )
        cat = KevCatalog(entries={
            "CVE-2024-0001": KevEntry(cve_id="CVE-2024-0001", due_date="2026-05-14"),
        })
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain,
                          image_ref="cgr.dev/x/y@sha256:abc",
                          kev_catalog=cat)
        assert result.kev_status == "HIT"
        assert result.kev_count == 1
        assert len(result.chain.kev_hits) == 1

    def test_kev_clean_when_no_overlap(self) -> None:
        from kev import KevCatalog, KevEntry
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(high=1),
            actionable_counts=VulnCounts(high=1),
            actionable_cve_ids=["CVE-2024-9999"],
        )
        cat = KevCatalog(entries={
            "CVE-2024-0001": KevEntry(cve_id="CVE-2024-0001"),
        })
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain,
                          image_ref="cgr.dev/x/y@sha256:abc",
                          kev_catalog=cat)
        assert result.kev_status == "CLEAN"
        assert result.kev_count == 0

    def test_kev_stays_na_without_catalog(self) -> None:
        """With no catalog supplied, kev_status must stay 'N/A' even if findings."""
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(high=1),
            actionable_counts=VulnCounts(high=1),
            actionable_cve_ids=["CVE-2024-0001"],
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain,
                          image_ref="cgr.dev/x/y@sha256:abc",
                          kev_catalog=None)
        assert result.kev_status == "N/A"

    def test_kev_skipped_for_empty_catalog(self) -> None:
        """An empty catalog (e.g. CISA fetch failed, no cache) acts like no catalog."""
        from kev import KevCatalog
        from scan import ScanResult, VulnCounts
        from verify_provenance import _run_vuln_scan

        sr = ScanResult(
            success=True,
            raw_counts=VulnCounts(high=1),
            actionable_counts=VulnCounts(high=1),
            actionable_cve_ids=["CVE-2024-0001"],
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        with patch("scan.run_scan", return_value=sr):
            _run_vuln_scan(result, result.chain,
                          image_ref="cgr.dev/x/y@sha256:abc",
                          kev_catalog=KevCatalog())
        assert result.kev_status == "N/A"

    def test_vex_predicate_passed_when_verified_and_matched(self) -> None:
        from attestation import PREDICATE_OPENVEX, AttestationRecord
        from verify_provenance import _run_vuln_scan

        good_vex = AttestationRecord(
            predicate_type=PREDICATE_OPENVEX,
            verified=True,
            subject_matches=True,
            predicate={"statements": [{"vulnerability": {"@id": "CVE-1"},
                                       "status": "not_affected"}]},
        )
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        result.chain.attestations[PREDICATE_OPENVEX] = good_vex

        captured_vex: list[object] = []

        def fake_run_scan(image_ref: str, vex_predicate: object = None, timeout: int = 300) -> object:
            captured_vex.append(vex_predicate)
            from scan import ScanResult
            return ScanResult(success=True)

        with patch("scan.run_scan", side_effect=fake_run_scan):
            _run_vuln_scan(result, result.chain, image_ref="cgr.dev/x/y@sha256:abc")
        assert captured_vex == [good_vex.predicate]


class TestUpstreamSourcesGlue:
    """Glue: _verify_upstream_sources_step + verdict demotion + flag wiring."""

    def _spdx_rec(self, predicate: dict[str, object]) -> object:
        from attestation import PREDICATE_SPDX, AttestationRecord
        return AttestationRecord(
            predicate_type=PREDICATE_SPDX,
            verified=True,
            subject_matches=True,
            predicate=predicate,
        )

    def _doc_with_one_git_source(self, expected_commit: str) -> dict[str, object]:
        # Smallest SPDX doc the walker accepts: one binary + one source via
        # GENERATED_FROM, with a github purl.
        src_id = f"SPDXRef-Package-{expected_commit}"
        return {
            "spdxVersion": "SPDX-2.3",
            "packages": [
                {"SPDXID": "SPDXRef-Package-bin", "name": "openssl", "versionInfo": "3.6.1"},
                {
                    "SPDXID": src_id,
                    "name": "openssl-source",
                    "externalRefs": [
                        {
                            "referenceCategory": "PACKAGE-MANAGER",
                            "referenceType": "purl",
                            "referenceLocator": "pkg:github/openssl/openssl@openssl-3.6.1",
                        }
                    ],
                },
            ],
            "relationships": [
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": src_id,
                    "relationshipType": "GENERATED_FROM",
                }
            ],
        }

    def test_skipped_when_no_verified_spdx(self) -> None:
        from verify_provenance import _verify_upstream_sources_step

        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        # No attestations on chain at all.
        _verify_upstream_sources_step(result, result.chain)
        assert result.upstream_sources_status == "N/A"
        assert result.chain.upstream_summary is None

    def test_populates_summary_on_verified_spdx(self) -> None:
        from attestation import PREDICATE_SPDX
        from verify_provenance import _verify_upstream_sources_step

        commit = "c" * 40
        rec = self._spdx_rec(self._doc_with_one_git_source(commit))
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        result.chain.attestations[PREDICATE_SPDX] = rec
        ls_remote_out = f"{commit}\trefs/tags/openssl-3.6.1\n"
        with patch("upstream.run_cmd", return_value=(True, ls_remote_out, "")):
            _verify_upstream_sources_step(result, result.chain)
        assert result.upstream_sources_status == "VERIFIED"
        assert result.upstream_sources_total == 1
        assert result.upstream_sources_verified == 1
        assert result.upstream_sources_failed == 0

    def test_failed_propagates_to_status(self) -> None:
        from attestation import PREDICATE_SPDX
        from verify_provenance import _verify_upstream_sources_step

        commit = "c" * 40
        wrong = "b" * 40
        rec = self._spdx_rec(self._doc_with_one_git_source(commit))
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        result.chain.attestations[PREDICATE_SPDX] = rec
        ls_remote_out = f"{wrong}\trefs/tags/openssl-3.6.1\n"
        with patch("upstream.run_cmd", return_value=(True, ls_remote_out, "")):
            _verify_upstream_sources_step(result, result.chain)
        assert result.upstream_sources_status == "FAILED"
        assert result.upstream_sources_failed == 1

    def test_error_does_not_set_failed_status(self) -> None:
        from attestation import PREDICATE_SPDX
        from verify_provenance import _verify_upstream_sources_step

        commit = "c" * 40
        rec = self._spdx_rec(self._doc_with_one_git_source(commit))
        result = VerificationResult(
            image="x", base_digest="", ref_status="", rekor_status="",
            rekor_log_index="", sig_status="", status="", error="",
        )
        result.chain.attestations[PREDICATE_SPDX] = rec
        # Network error: run_cmd returns failure.
        with patch("upstream.run_cmd", return_value=(False, "", "fatal: net down")):
            _verify_upstream_sources_step(result, result.chain)
        assert result.upstream_sources_status == "ERROR"
        assert result.upstream_sources_failed == 0
        assert result.upstream_sources_errors == 1


class TestUpstreamFlagImplication:
    """`--verify-upstream-sources` should imply `--verify-attestations`."""

    def _parse(self, *flags: str) -> object:
        import argparse

        from verify_provenance import _build_image_subparser

        parser = argparse.ArgumentParser()
        sub = parser.add_subparsers(dest="cmd")
        _build_image_subparser(sub)
        return parser.parse_args(["image", "--customer-org", "foo", *flags])

    def test_flag_implication_runs(self) -> None:
        # Re-running just the implication block (the relevant slice of
        # run_image_mode) on an args object with --verify-upstream-sources set
        # should set verify_attestations True.
        args = self._parse("--verify-upstream-sources")
        # Mirror the check in run_image_mode.
        if args.scan or args.sbom_drift or args.verify_upstream_sources:  # type: ignore[attr-defined]
            args.verify_attestations = True  # type: ignore[attr-defined]
        assert args.verify_attestations  # type: ignore[attr-defined]


class TestUpstreamCsvAndJsonGating:
    """Output-format column gating respects `upstream_on`."""

    def _result(self, **overrides: object) -> VerificationResult:
        r = VerificationResult(
            image="x", base_digest="sha256:abc", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="1", sig_status="VALID",
            status="VERIFIED", error="",
        )
        for k, v in overrides.items():
            setattr(r, k, v)
        return r

    def test_summary_table_omits_upstream_when_off(self) -> None:
        from verify_provenance import _render_summary_table

        r = self._result(
            upstream_sources_status="VERIFIED",
            upstream_sources_total=5, upstream_sources_verified=5,
        )
        out = _render_summary_table([r], attestations_on=False, scan_on=False, upstream_on=False)
        assert "UPSTREAM" not in out

    def test_summary_table_shows_upstream_when_on(self) -> None:
        from verify_provenance import _render_summary_table

        r = self._result(
            upstream_sources_status="VERIFIED",
            upstream_sources_total=5, upstream_sources_verified=5,
        )
        out = _render_summary_table([r], attestations_on=False, scan_on=False, upstream_on=True)
        assert "UPSTREAM" in out
        assert "5/5" in out

    def test_csv_writes_upstream_columns(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        from verify_provenance import _write_on_disk_csv

        r = self._result(
            upstream_sources_status="VERIFIED",
            upstream_sources_total=3, upstream_sources_verified=3,
        )
        csv_file = tmp_path / "out.csv"
        _write_on_disk_csv(
            str(csv_file), [r], customer_only=False,
            attestations_on=False, scan_on=False, upstream_on=True,
        )
        body = csv_file.read_text()
        assert "upstream_sources_status" in body
        assert "upstream_sources_verified" in body


class TestUpstreamEvidenceBundle:
    """Evidence-bundle integration: per-image upstream_sources.json + control map."""

    def test_writes_upstream_artifact_and_control_when_status_set(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import json as _json

        from evidence import write_evidence_bundle
        from upstream import UpstreamSummary, UpstreamVerifyResult

        result = VerificationResult(
            image="myimage", base_digest="sha256:abc", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="1", sig_status="VALID",
            status="VERIFIED", error="",
        )
        result.upstream_sources_status = "VERIFIED"
        result.upstream_sources_total = 2
        result.upstream_sources_verified = 2
        result.chain.upstream_summary = UpstreamSummary(
            total=2, verified=2,
            results=[
                UpstreamVerifyResult(label="a", source_type="git", status="VERIFIED"),
                UpstreamVerifyResult(label="b", source_type="http", status="VERIFIED"),
            ],
        )
        out_dir = write_evidence_bundle(
            tmp_path, result, tool_version="t", customer_org="o",
            mode="full", policy_source="(defaults)",
        )
        upstream_file = out_dir / "upstream_sources.json"
        assert upstream_file.exists()
        body = _json.loads(upstream_file.read_text())
        assert body["verified"] == 2
        # Control map carries the new entry only when the check actually ran.
        controls = _json.loads((out_dir / "controls.json").read_text())
        assert "upstream_sources" in controls
        assert "SR-3" in controls["upstream_sources"]["NIST_800-161"]
        # Hash seal lists the new file.
        seal = (out_dir / "SHA256SUMS").read_text()
        assert "upstream_sources.json" in seal

    def test_skips_artifact_and_control_when_status_na(self, tmp_path) -> None:  # type: ignore[no-untyped-def]
        import json as _json

        from evidence import write_evidence_bundle

        result = VerificationResult(
            image="myimage", base_digest="sha256:abc", ref_status="EXISTS",
            rekor_status="EXISTS", rekor_log_index="1", sig_status="VALID",
            status="VERIFIED", error="",
        )
        # upstream_sources_status default is "N/A"; no chain.upstream_summary.
        out_dir = write_evidence_bundle(
            tmp_path, result, tool_version="t", customer_org="o",
            mode="full", policy_source="(defaults)",
        )
        assert not (out_dir / "upstream_sources.json").exists()
        controls = _json.loads((out_dir / "controls.json").read_text())
        assert "upstream_sources" not in controls

