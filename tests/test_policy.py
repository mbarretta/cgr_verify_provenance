"""Tests for the policy module — defaults, file loader, SLSA evaluation."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, "..")

from policy import (  # noqa: E402
    DEFAULT_BUILD_BUILDER_IDS,
    DEFAULT_BUILD_IDENTITY_REGEX,
    DEFAULT_BUILD_ISSUER_REGEX,
    DEFAULT_CUSTOMER_IDENTITY_REGEX,
    DEFAULT_CUSTOMER_ISSUER_REGEX,
    IdentityPolicy,
    PolicyError,
    _any_match,
    default_build_policy,
    default_customer_policy,
    evaluate_slsa_policy,
    load_policy_file,
)


class _FakeSlsa:
    """Stand-in for attestation.SlsaProvenance — evaluate_slsa_policy reads
    by attribute so a tiny duck-typed fake keeps this test file free of
    cross-module imports."""

    def __init__(self, builder_id: str = "", source_uri: str = "") -> None:
        self.builder_id = builder_id
        self.source_uri = source_uri


class TestDefaults:
    def test_customer_defaults_preserve_hardcoded_values(self) -> None:
        """Running without --policy-file must behave exactly as before."""
        p = default_customer_policy()
        assert p.cosign_oidc_issuer_regex == DEFAULT_CUSTOMER_ISSUER_REGEX
        assert p.cosign_identity_regex == DEFAULT_CUSTOMER_IDENTITY_REGEX
        # Defaults include some allowlist entries so policy eval has teeth
        assert p.allowed_builder_ids
        assert p.allowed_source_uris

    def test_build_defaults_preserve_hardcoded_values(self) -> None:
        p = default_build_policy()
        assert p.cosign_oidc_issuer_regex == DEFAULT_BUILD_ISSUER_REGEX
        assert p.cosign_identity_regex == DEFAULT_BUILD_IDENTITY_REGEX
        # chainguard-images workflow appears in the default build allowlist
        assert any(
            "chainguard-images" in pat for pat in p.allowed_builder_ids
        ) or p.allowed_builder_ids == list(DEFAULT_BUILD_BUILDER_IDS)


class TestLoadPolicyFile:
    def test_empty_file_inherits_defaults(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text("{}")
        customer, build = load_policy_file(p)
        assert customer == default_customer_policy()
        assert build == default_build_policy()

    def test_override_single_field(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "customer": {
                        "cosign_identity_regex": "^my-custom-identity$",
                    }
                }
            )
        )
        customer, build = load_policy_file(p)
        assert customer.cosign_identity_regex == "^my-custom-identity$"
        # Other customer fields unchanged
        assert customer.cosign_oidc_issuer_regex == DEFAULT_CUSTOMER_ISSUER_REGEX
        # Build policy completely untouched
        assert build == default_build_policy()

    def test_override_list_field(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "build": {
                        "allowed_builder_ids": [r"^https://my-hardened-builder/.*$"],
                        "allowed_source_uris": [r"^git\+ssh://internal-git/.*$"],
                    }
                }
            )
        )
        _, build = load_policy_file(p)
        assert build.allowed_builder_ids == ["^https://my-hardened-builder/.*$"]
        assert build.allowed_source_uris == [r"^git\+ssh://internal-git/.*$"]

    def test_unknown_field_fails_closed(self, tmp_path: Path) -> None:
        """Typo protection: misspelled fields must raise, not silently ignore."""
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "customer": {"cozign_identity_regex": "whatever"},  # typo
                }
            )
        )
        with pytest.raises(PolicyError, match="unknown field"):
            load_policy_file(p)

    def test_unknown_stanza_fails_closed(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text(json.dumps({"custoomer": {}}))  # typo
        with pytest.raises(PolicyError, match="unknown stanza"):
            load_policy_file(p)

    def test_underscore_prefixed_top_keys_allowed(self, tmp_path: Path) -> None:
        """Escape hatch for comments in JSON policies."""
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "_comment": "this is ignored",
                    "_author": "ops team",
                    "customer": {"cosign_identity_regex": "^ok$"},
                }
            )
        )
        customer, _ = load_policy_file(p)
        assert customer.cosign_identity_regex == "^ok$"

    def test_bad_regex_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "customer": {"cosign_identity_regex": "[unterminated"},
                }
            )
        )
        with pytest.raises(PolicyError, match="not a valid regex"):
            load_policy_file(p)

    def test_wrong_type_rejected(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text(
            json.dumps(
                {
                    "customer": {"allowed_builder_ids": "single-string-not-list"},
                }
            )
        )
        with pytest.raises(PolicyError, match="list of regex"):
            load_policy_file(p)

    def test_malformed_json(self, tmp_path: Path) -> None:
        p = tmp_path / "policy.json"
        p.write_text("{ this is not json")
        with pytest.raises(PolicyError, match="invalid JSON"):
            load_policy_file(p)

    def test_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(PolicyError, match="unable to read"):
            load_policy_file(tmp_path / "does-not-exist.json")


class TestEvaluateSlsaPolicy:
    def test_pass_on_allowlisted_builder_and_source(self) -> None:
        prov = _FakeSlsa(
            builder_id="https://token.actions.githubusercontent.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
            source_uri="git+https://github.com/chainguard-images/images@refs/heads/main",
        )
        violations = evaluate_slsa_policy(prov, default_build_policy())
        assert violations == []

    def test_violation_on_unknown_builder(self) -> None:
        prov = _FakeSlsa(
            builder_id="https://evil-builder.example.com/malicious",
            source_uri="git+https://github.com/chainguard-images/images@refs/heads/main",
        )
        violations = evaluate_slsa_policy(prov, default_build_policy())
        assert len(violations) == 1
        assert violations[0].check == "builder_id"
        assert violations[0].observed == "https://evil-builder.example.com/malicious"

    def test_violation_on_unknown_source(self) -> None:
        prov = _FakeSlsa(
            builder_id="https://token.actions.githubusercontent.com/chainguard-images/images/.github/workflows/release.yaml@refs/heads/main",
            source_uri="git+https://github.com/attacker/fork@main",
        )
        violations = evaluate_slsa_policy(prov, default_build_policy())
        assert len(violations) == 1
        assert violations[0].check == "source_uri"

    def test_missing_builder_id_flagged_when_allowlist_is_nonempty(self) -> None:
        prov = _FakeSlsa(builder_id="", source_uri="")
        violations = evaluate_slsa_policy(prov, default_build_policy())
        # Empty builder_id is flagged. Empty source_uri is NOT flagged under
        # defaults — the apko build type legitimately omits it, so `^$` is
        # in the default allowed_source_uris list.
        assert {v.check for v in violations} == {"builder_id"}

    def test_apko_builder_with_empty_source_passes_under_defaults(self) -> None:
        """Customer-private & public apko-built images emit empty externalParameters
        and name the apko Terraform provider as builder.id. Defaults must pass these."""
        prov = _FakeSlsa(
            builder_id="https://github.com/chainguard-dev/terraform-provider-apko",
            source_uri="",
        )
        assert evaluate_slsa_policy(prov, default_build_policy()) == []
        assert evaluate_slsa_policy(prov, default_customer_policy()) == []

    def test_apko_regex_rejects_sibling_repos(self) -> None:
        """The apko builder regex must not match `terraform-provider-apko-*`
        sibling repos — a valid boundary char (`/` or `@`) must follow."""
        for bogus in (
            "https://github.com/chainguard-dev/terraform-provider-apko-malicious",
            "https://github.com/chainguard-dev/terraform-provider-apkollama/evil",
            "https://github.com/chainguard-dev/terraform-provider-apko.attacker.com/x",
        ):
            prov = _FakeSlsa(builder_id=bogus, source_uri="")
            checks = {v.check for v in evaluate_slsa_policy(prov, default_build_policy())}
            assert "builder_id" in checks, f"regex over-matched {bogus!r}"

    def test_empty_allowlist_is_permissive(self) -> None:
        """Empty allowlist means 'no policy' — caller opted out of that check."""
        prov = _FakeSlsa(builder_id="anything", source_uri="anything")
        policy = IdentityPolicy(
            cosign_oidc_issuer_regex="^x$",
            cosign_identity_regex=".*",
            allowed_builder_ids=[],
            allowed_source_uris=[],
        )
        assert evaluate_slsa_policy(prov, policy) == []

    def test_multiple_allowlist_patterns_or_semantics(self) -> None:
        """Any one regex match passes; the list is OR-joined."""
        prov = _FakeSlsa(builder_id="https://second-allowed.example/abc")
        policy = IdentityPolicy(
            cosign_oidc_issuer_regex="^x$",
            cosign_identity_regex=".*",
            allowed_builder_ids=[
                r"^https://first-allowed\.example/.*$",
                r"^https://second-allowed\.example/.*$",
            ],
            allowed_source_uris=[],
        )
        assert evaluate_slsa_policy(prov, policy) == []


class TestAnyMatch:
    def test_no_patterns_false(self) -> None:
        assert _any_match("anything", []) is False

    def test_search_not_fullmatch(self) -> None:
        # Pattern without ^$ anchors uses re.search semantics
        assert _any_match("prefix-evil-suffix", ["evil"]) is True

    def test_anchored_pattern(self) -> None:
        assert _any_match("prefix-evil-suffix", [r"^evil$"]) is False
        assert _any_match("evil", [r"^evil$"]) is True
