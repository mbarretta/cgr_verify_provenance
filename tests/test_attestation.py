"""Tests for the attestation module — DSSE decode, subject-digest checks,
SLSA predicate parsing, and the cosign-verify wrapper."""

from __future__ import annotations

import base64
import json
import sys
from typing import Any
from unittest.mock import patch

sys.path.insert(0, "..")

from attestation import (  # noqa: E402
    COSIGN_TYPE_SHORTNAMES,
    PREDICATE_CYCLONEDX,
    PREDICATE_SLSA_V1,
    PREDICATE_SPDX,
    _build_verify_attestation_cmd,
    _extract_sha256,
    decode_statement,
    parse_cyclonedx_sbom,
    parse_slsa_provenance,
    parse_spdx_sbom,
    retrieve_and_verify_attestation,
    subject_digest_matches,
)

IMAGE_DIGEST = "sha256:" + "a" * 64
OTHER_DIGEST = "sha256:" + "b" * 64


def _envelope(statement: dict[str, Any]) -> dict[str, Any]:
    """Wrap a statement as a DSSE envelope the way cosign emits them."""
    payload_b64 = base64.b64encode(json.dumps(statement).encode("utf-8")).decode("ascii")
    return {
        "payloadType": "application/vnd.in-toto+json",
        "payload": payload_b64,
        "signatures": [{"keyid": "", "sig": "xxx"}],
    }


def _statement(
    subject_sha256: str, predicate_type: str, predicate: dict[str, Any]
) -> dict[str, Any]:
    return {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [{"name": "ignored-for-verification", "digest": {"sha256": subject_sha256}}],
        "predicateType": predicate_type,
        "predicate": predicate,
    }


SLSA_PREDICATE_FIXTURE: dict[str, Any] = {
    "buildDefinition": {
        "buildType": "https://chainguard.dev/builder/apko@v1",
        "externalParameters": {
            "source": {
                "uri": "git+https://github.com/chainguard-images/images@refs/heads/main",
                "digest": {"gitCommit": "deadbeef" * 5},
            }
        },
        "resolvedDependencies": [
            {"uri": "pkg:apk/wolfi/glibc"},
            {"uri": "pkg:apk/wolfi/ca-certificates"},
        ],
    },
    "runDetails": {
        "builder": {
            "id": "https://token.actions.githubusercontent.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
            "version": {"cosign": "v2.4.0"},
        },
        "metadata": {
            "invocationId": "https://github.com/chainguard-images/images/actions/runs/999",
            "startedOn": "2026-04-23T00:00:00Z",
            "finishedOn": "2026-04-23T00:05:00Z",
        },
    },
}


class TestExtractSha256:
    def test_normalizes_prefix(self) -> None:
        assert _extract_sha256("sha256:ABCDEF") == "abcdef"

    def test_bare_hex(self) -> None:
        assert _extract_sha256("ABCDEF") == "abcdef"

    def test_empty(self) -> None:
        assert _extract_sha256("") == ""

    def test_other_algo_rejected(self) -> None:
        # Non-sha256 returns empty so it can never match
        assert _extract_sha256("sha512:abcdef") == ""


class TestDecodeStatement:
    def test_dsse_envelope(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_SLSA_V1, SLSA_PREDICATE_FIXTURE)
        env = _envelope(stmt)
        assert decode_statement(env) == stmt

    def test_bare_statement(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_SLSA_V1, {})
        assert decode_statement(stmt) == stmt

    def test_malformed_returns_empty(self) -> None:
        assert decode_statement({"payload": "@@@not-base64@@@"}) == {}

    def test_no_payload_no_subject(self) -> None:
        assert decode_statement({"unrelated": "data"}) == {}


class TestSubjectDigestMatch:
    def test_match(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_SLSA_V1, {})
        matched, observed = subject_digest_matches(stmt, IMAGE_DIGEST)
        assert matched is True
        assert observed == ["a" * 64]

    def test_mismatch(self) -> None:
        stmt = _statement("b" * 64, PREDICATE_SLSA_V1, {})
        matched, observed = subject_digest_matches(stmt, IMAGE_DIGEST)
        assert matched is False
        assert observed == ["b" * 64]

    def test_case_insensitive(self) -> None:
        stmt = _statement("A" * 64, PREDICATE_SLSA_V1, {})
        matched, _ = subject_digest_matches(stmt, IMAGE_DIGEST)
        assert matched is True

    def test_multi_subject_one_matches(self) -> None:
        stmt = {
            "subject": [
                {"name": "x", "digest": {"sha256": "b" * 64}},
                {"name": "y", "digest": {"sha256": "a" * 64}},
            ]
        }
        matched, observed = subject_digest_matches(stmt, IMAGE_DIGEST)
        assert matched is True
        assert set(observed) == {"a" * 64, "b" * 64}

    def test_no_subjects(self) -> None:
        matched, observed = subject_digest_matches({"subject": []}, IMAGE_DIGEST)
        assert matched is False
        assert observed == []

    def test_malformed_subject(self) -> None:
        matched, _ = subject_digest_matches(
            {"subject": ["not-a-dict", {"digest": "not-a-dict"}]},
            IMAGE_DIGEST,
        )
        assert matched is False


class TestSlsaProvenanceParser:
    def test_full_parse(self) -> None:
        prov = parse_slsa_provenance(SLSA_PREDICATE_FIXTURE)
        assert prov.build_type == "https://chainguard.dev/builder/apko@v1"
        assert "chainguard-images/images" in prov.builder_id
        assert prov.builder_version == {"cosign": "v2.4.0"}
        assert prov.source_uri.startswith("git+https://github.com/chainguard-images")
        assert prov.source_digest.get("gitCommit", "").startswith("deadbeef")
        assert prov.invocation_id.endswith("/999")
        assert prov.started_on == "2026-04-23T00:00:00Z"
        assert prov.finished_on == "2026-04-23T00:05:00Z"
        assert prov.resolved_dependency_count == 2

    def test_partial_predicate_no_error(self) -> None:
        prov = parse_slsa_provenance({"buildDefinition": {"buildType": "x"}})
        assert prov.build_type == "x"
        assert prov.builder_id == ""
        assert prov.resolved_dependency_count == 0

    def test_empty_predicate(self) -> None:
        prov = parse_slsa_provenance({})
        assert prov.build_type == ""
        assert prov.builder_id == ""


class TestBuildVerifyAttestationCmd:
    def test_slsa_uses_shortname(self) -> None:
        cmd = _build_verify_attestation_cmd(
            "cgr.dev/x/y@sha256:abc",
            PREDICATE_SLSA_V1,
            "^https://issuer\\.enforce\\.dev/.*$",
            ".*",
        )
        assert "slsaprovenance1" in cmd
        assert cmd[-1] == "cgr.dev/x/y@sha256:abc"
        assert "--certificate-oidc-issuer-regexp" in cmd
        assert "--certificate-identity-regexp" in cmd
        assert "--trusted-root" not in cmd

    def test_unknown_type_uses_full_uri(self) -> None:
        cmd = _build_verify_attestation_cmd(
            "cgr.dev/x/y", "https://example.com/custom", "regex", ".*"
        )
        assert "https://example.com/custom" in cmd

    def test_trusted_root_forwarded(self) -> None:
        cmd = _build_verify_attestation_cmd(
            "cgr.dev/x/y", PREDICATE_SPDX, "regex", ".*", trusted_root="/tmp/tr.json"
        )
        assert "--trusted-root" in cmd
        assert "/tmp/tr.json" in cmd


class TestRetrieveAttestation:
    """Mock run_cmd and exercise the retrieve_and_verify_attestation flow."""

    def _mock_cosign_stdout(self, statements: list[dict[str, Any]]) -> str:
        return json.dumps([_envelope(s) for s in statements])

    def test_success_subject_matches(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_SLSA_V1, SLSA_PREDICATE_FIXTURE)
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, self._mock_cosign_stdout([stmt]), "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/org/image@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        assert rec.verified is True
        assert rec.subject_matches is True
        assert rec.slsa is not None
        assert rec.slsa.build_type == "https://chainguard.dev/builder/apko@v1"
        assert rec.error == ""

    def test_cosign_failure(self) -> None:
        with patch("attestation.run_cmd") as m:
            m.return_value = (False, "", "error: no matching attestations")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/x/y@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        assert rec.verified is False
        assert rec.subject_matches is False
        assert "no matching attestations" in rec.error

    def test_subject_mismatch_does_not_trust(self) -> None:
        # Cosign verified signature but subject is for a different image.
        stmt = _statement("b" * 64, PREDICATE_SLSA_V1, SLSA_PREDICATE_FIXTURE)
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, self._mock_cosign_stdout([stmt]), "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/x/y@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        # Verified by cosign, but rejected by our subject-digest assertion.
        assert rec.verified is True
        assert rec.subject_matches is False
        assert "subject digest did not match" in rec.error

    def test_multiple_envelopes_picks_matching_subject(self) -> None:
        non_match = _statement(
            "b" * 64, PREDICATE_SLSA_V1, {"buildDefinition": {"buildType": "other"}}
        )
        match = _statement("a" * 64, PREDICATE_SLSA_V1, SLSA_PREDICATE_FIXTURE)
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, self._mock_cosign_stdout([non_match, match]), "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/x/y@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        assert rec.subject_matches is True
        assert rec.slsa is not None
        assert rec.slsa.build_type == "https://chainguard.dev/builder/apko@v1"

    def test_ndjson_fallback(self) -> None:
        """Some cosign versions emit newline-delimited JSON rather than an array."""
        stmt = _statement("a" * 64, PREDICATE_SLSA_V1, SLSA_PREDICATE_FIXTURE)
        env_line = json.dumps(_envelope(stmt))
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, env_line + "\n", "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/x/y@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        assert rec.subject_matches is True

    def test_empty_output_is_error(self) -> None:
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, "", "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/x/y@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SLSA_V1,
                "^https://.*$",
                ".*",
            )
        assert rec.verified is False
        assert "empty output" in rec.error


class TestShortnames:
    def test_slsa_v1(self) -> None:
        assert COSIGN_TYPE_SHORTNAMES[PREDICATE_SLSA_V1] == "slsaprovenance1"

    def test_spdx(self) -> None:
        assert COSIGN_TYPE_SHORTNAMES[PREDICATE_SPDX] == "spdxjson"


# ───────────────────────────── SBOM fixtures ─────────────────────────────

SPDX_FIXTURE: dict[str, Any] = {
    "SPDXID": "SPDXRef-DOCUMENT",
    "spdxVersion": "SPDX-2.3",
    "name": "cgr.dev/chainguard/python",
    "creationInfo": {"created": "2026-04-23T00:00:00Z"},
    "packages": [
        {
            "SPDXID": "SPDXRef-Package-glibc",
            "name": "glibc",
            "versionInfo": "2.39-r1",
            "licenseConcluded": "LGPL-2.1-or-later AND GPL-2.0-or-later",
            "licenseDeclared": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceType": "purl",
                    "referenceLocator": "pkg:apk/wolfi/glibc@2.39-r1",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-ca-certs",
            "name": "ca-certificates",
            "versionInfo": "20241121-r0",
            "licenseConcluded": "MPL-2.0",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:apk/wolfi/ca-certificates@20241121-r0",
                }
            ],
        },
        {
            "SPDXID": "SPDXRef-Package-python",
            "name": "python-3.12",
            "versionInfo": "3.12.5-r0",
            "licenseDeclared": "Python-2.0",
            "externalRefs": [
                {
                    "referenceType": "purl",
                    "referenceLocator": "pkg:apk/wolfi/python-3.12@3.12.5-r0",
                }
            ],
        },
    ],
}

CYCLONEDX_FIXTURE: dict[str, Any] = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "metadata": {
        "component": {
            "type": "container",
            "name": "cgr.dev/chainguard/python",
        }
    },
    "components": [
        {
            "type": "library",
            "name": "glibc",
            "version": "2.39-r1",
            "purl": "pkg:apk/wolfi/glibc@2.39-r1",
            "licenses": [
                {"license": {"id": "LGPL-2.1-or-later"}},
                {"license": {"name": "GPL-2.0-or-later"}},
            ],
        },
        {
            "type": "library",
            "name": "openssl",
            "version": "3.3.2-r0",
            "purl": "pkg:apk/wolfi/openssl@3.3.2-r0",
            "licenses": [{"expression": "Apache-2.0"}],
        },
    ],
}


class TestSpdxParser:
    def test_full_parse(self) -> None:
        s = parse_spdx_sbom(SPDX_FIXTURE)
        assert s.sbom_format == "spdx"
        assert s.spec_version == "SPDX-2.3"
        assert s.document_name == "cgr.dev/chainguard/python"
        assert s.package_count == 3
        assert s.is_empty is False
        # LGPL-2.1-or-later + GPL-2.0-or-later (from concluded expression)
        # + MPL-2.0 + Python-2.0 (declared, since concluded was absent)
        assert set(s.unique_licenses) == {
            "LGPL-2.1-or-later",
            "GPL-2.0-or-later",
            "MPL-2.0",
            "Python-2.0",
        }
        assert len(s.purl_sample) == 3
        assert "pkg:apk/wolfi/glibc@2.39-r1" in s.purl_sample

    def test_empty_packages_flagged(self) -> None:
        s = parse_spdx_sbom({"spdxVersion": "SPDX-2.3", "packages": []})
        assert s.package_count == 0
        assert s.is_empty is True

    def test_missing_packages_flagged(self) -> None:
        s = parse_spdx_sbom({"spdxVersion": "SPDX-2.3"})
        assert s.is_empty is True

    def test_noassertion_license_skipped(self) -> None:
        s = parse_spdx_sbom(
            {
                "spdxVersion": "SPDX-2.3",
                "packages": [
                    {"name": "x", "licenseConcluded": "NOASSERTION", "licenseDeclared": "MIT"},
                ],
            }
        )
        # NOASSERTION on concluded means we fall back to declared
        assert s.unique_licenses == ["MIT"]

    def test_purl_sample_is_capped(self) -> None:
        pkgs = [
            {
                "name": f"p{i}",
                "externalRefs": [{"referenceType": "purl", "referenceLocator": f"pkg:apk/x/p{i}"}],
            }
            for i in range(25)
        ]
        s = parse_spdx_sbom({"spdxVersion": "SPDX-2.3", "packages": pkgs})
        assert s.package_count == 25
        assert len(s.purl_sample) == 10


class TestCyclonedxParser:
    def test_full_parse(self) -> None:
        s = parse_cyclonedx_sbom(CYCLONEDX_FIXTURE)
        assert s.sbom_format == "cyclonedx"
        assert s.spec_version == "1.5"
        assert s.document_name == "cgr.dev/chainguard/python"
        assert s.package_count == 2
        assert s.is_empty is False
        assert set(s.unique_licenses) >= {
            "LGPL-2.1-or-later",
            "GPL-2.0-or-later",
            "Apache-2.0",
        }
        assert "pkg:apk/wolfi/glibc@2.39-r1" in s.purl_sample

    def test_empty_components(self) -> None:
        s = parse_cyclonedx_sbom({"bomFormat": "CycloneDX", "specVersion": "1.5", "components": []})
        assert s.is_empty is True
        assert s.package_count == 0

    def test_missing_components(self) -> None:
        s = parse_cyclonedx_sbom({"bomFormat": "CycloneDX", "specVersion": "1.5"})
        assert s.is_empty is True


class TestRetrieveSbomAttestation:
    """SBOM attestations flow through the same retrieve path as SLSA."""

    def test_spdx_retrieval_populates_sbom(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_SPDX, SPDX_FIXTURE)
        env_text = json.dumps([_envelope(stmt)])
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, env_text, "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/o/i@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_SPDX,
                "^https://.*$",
                ".*",
            )
        assert rec.subject_matches is True
        assert rec.sbom is not None
        assert rec.sbom.sbom_format == "spdx"
        assert rec.sbom.package_count == 3
        assert rec.slsa is None  # type-correct typed parse

    def test_cyclonedx_retrieval_populates_sbom(self) -> None:
        stmt = _statement("a" * 64, PREDICATE_CYCLONEDX, CYCLONEDX_FIXTURE)
        env_text = json.dumps([_envelope(stmt)])
        with patch("attestation.run_cmd") as m:
            m.return_value = (True, env_text, "")
            rec = retrieve_and_verify_attestation(
                "cgr.dev/o/i@" + IMAGE_DIGEST,
                IMAGE_DIGEST,
                PREDICATE_CYCLONEDX,
                "^https://.*$",
                ".*",
            )
        assert rec.subject_matches is True
        assert rec.sbom is not None
        assert rec.sbom.sbom_format == "cyclonedx"
        assert rec.sbom.package_count == 2
