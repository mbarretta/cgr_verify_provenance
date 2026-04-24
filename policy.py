"""
Policy / allowlist configuration for signer identity + provenance.

Today's tool hardcodes two sets of OIDC + identity regex pairs: one for
Chainguard-Enforce-delivered customer images, one for GitHub-Actions-built
base images. This module makes those values the *defaults* of a policy
object that callers can override via a JSON file passed with
`--policy-file`.

The module answers two questions:

1. **What regex should I hand cosign?** — `cosign_oidc_issuer_regex` and
   `cosign_identity_regex`, which flow directly into
   `cosign verify --certificate-oidc-issuer-regexp` /
   `--certificate-identity-regexp`.

2. **Does this SLSA provenance come from an approved builder + source?** —
   `allowed_builder_ids` and `allowed_source_uris` are lists of regexes
   evaluated against the parsed `SlsaProvenance` after cosign has
   cryptographically verified the signature. A provenance that verifies
   but names an unapproved builder or source repo gets flagged as a
   policy violation, not a successful verification.

Design notes:
- Pure stdlib (json). No PyYAML; keep runtime deps zero.
- Two parallel policy stanzas: "customer" (Enforce-delivered images) and
  "build" (GitHub Actions builds of base images). Each mode uses one.
- Lists for builder/source allowlists support multiple trust anchors
  (e.g. both the public `chainguard-images` workflow and a private
  Enforce builder).
- Defaults encode today's hardcoded values verbatim so passing no
  `--policy-file` is behavior-preserving.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# ─────────────────── Default regex strings (hardcoded today) ───────────────────

# Customer-org delivery: Chainguard Enforce OIDC
DEFAULT_CUSTOMER_ISSUER_REGEX = r"^https://issuer\.enforce\.dev.*$"
DEFAULT_CUSTOMER_IDENTITY_REGEX = r".*"

# Reference-org base images: GitHub Actions workflow identity
DEFAULT_BUILD_ISSUER_REGEX = r"^https://token\.actions\.githubusercontent\.com.*$"
DEFAULT_BUILD_IDENTITY_REGEX = r".*chainguard.*"

# SLSA `builder.id` regex allowlists. Any one match passes.
DEFAULT_BUILD_BUILDER_IDS = [
    # Public-registry images: chainguard-images/images release workflow
    r"^https://token\.actions\.githubusercontent\.com/chainguard-images/images/\.github/workflows/.*$",
    # Any github.com/chainguard-images/* workflow run URL (builder.id varies by image)
    r"^https?://github\.com/chainguard-images/.*$",
    # Customer-private & public apko-built images name the apko Terraform provider
    # as builder.id (buildType=https://apko.dev/slsa-build-type@v1).
    r"^https://github\.com/chainguard-dev/terraform-provider-apko.*$",
]
DEFAULT_CUSTOMER_BUILDER_IDS = [
    # Enforce-built customer images (catalog syncer / apko builder)
    r"^https?://issuer\.enforce\.dev/.*$",
    # Some Chainguard customer-org attestations still name the GHA builder
    r"^https://token\.actions\.githubusercontent\.com/chainguard-images/.*$",
    # apko Terraform provider (same builder used for customer-private images)
    r"^https://github\.com/chainguard-dev/terraform-provider-apko.*$",
]

# SLSA `externalParameters.source.uri` regex allowlists. Includes `^$` because
# the apko build type (https://apko.dev/slsa-build-type@v1) builds from a
# declarative config, not a git tree, and legitimately emits an empty
# externalParameters (source URI absent). builder_id still constrains who is
# allowed to produce such an attestation.
DEFAULT_SOURCE_URIS = [
    r"^$",
    r"^git\+?https://github\.com/chainguard-images/.*$",
    r"^https://github\.com/chainguard-images/.*$",
]


@dataclass
class IdentityPolicy:
    """Policy for one verification mode (customer-only OR full build)."""

    cosign_oidc_issuer_regex: str
    cosign_identity_regex: str
    allowed_builder_ids: list[str] = field(default_factory=list)
    allowed_source_uris: list[str] = field(default_factory=list)


@dataclass
class PolicyViolation:
    """One failed policy check against a verified SLSA predicate."""

    check: str  # "builder_id" | "source_uri"
    observed: str
    expected_patterns: list[str]

    def summary(self) -> str:
        return (
            f"{self.check} {self.observed!r} does not match any of "
            f"{len(self.expected_patterns)} allowed patterns"
        )


# ─────────────────────────── Default constructors ───────────────────────────


def default_customer_policy() -> IdentityPolicy:
    return IdentityPolicy(
        cosign_oidc_issuer_regex=DEFAULT_CUSTOMER_ISSUER_REGEX,
        cosign_identity_regex=DEFAULT_CUSTOMER_IDENTITY_REGEX,
        allowed_builder_ids=list(DEFAULT_CUSTOMER_BUILDER_IDS),
        allowed_source_uris=list(DEFAULT_SOURCE_URIS),
    )


def default_build_policy() -> IdentityPolicy:
    return IdentityPolicy(
        cosign_oidc_issuer_regex=DEFAULT_BUILD_ISSUER_REGEX,
        cosign_identity_regex=DEFAULT_BUILD_IDENTITY_REGEX,
        allowed_builder_ids=list(DEFAULT_BUILD_BUILDER_IDS),
        allowed_source_uris=list(DEFAULT_SOURCE_URIS),
    )


# ─────────────────────────────── File loader ────────────────────────────────

_KNOWN_STANZAS = {"customer", "build"}
_STANZA_FIELDS = {
    "cosign_oidc_issuer_regex",
    "cosign_identity_regex",
    "allowed_builder_ids",
    "allowed_source_uris",
}


class PolicyError(ValueError):
    """Raised for malformed policy files — unknown fields, wrong types, etc."""


def _overlay_stanza(base: IdentityPolicy, stanza: dict[str, Any], path: str) -> IdentityPolicy:
    """Overlay a partial stanza onto a base policy, rejecting unknown fields.

    We fail closed on unknown fields: a typo in a policy file shouldn't silently
    fall back to default behavior. If a user misspells `allowed_builder_ids`
    we want them to know, not to quietly deploy a wide-open policy.
    """
    unknown = set(stanza.keys()) - _STANZA_FIELDS
    if unknown:
        raise PolicyError(
            f"{path}: unknown field(s) {sorted(unknown)} — allowed fields: {sorted(_STANZA_FIELDS)}"
        )

    out = IdentityPolicy(
        cosign_oidc_issuer_regex=base.cosign_oidc_issuer_regex,
        cosign_identity_regex=base.cosign_identity_regex,
        allowed_builder_ids=list(base.allowed_builder_ids),
        allowed_source_uris=list(base.allowed_source_uris),
    )
    for key in _STANZA_FIELDS:
        if key not in stanza:
            continue
        val = stanza[key]
        if key.endswith("_regex"):
            if not isinstance(val, str):
                raise PolicyError(f"{path}: '{key}' must be a string regex")
            # Fail closed on bad regex
            try:
                re.compile(val)
            except re.error as e:
                raise PolicyError(f"{path}: '{key}' is not a valid regex: {e}") from e
            setattr(out, key, val)
        else:
            if not isinstance(val, list) or not all(isinstance(x, str) for x in val):
                raise PolicyError(f"{path}: '{key}' must be a list of regex strings")
            for pat in val:
                try:
                    re.compile(pat)
                except re.error as e:
                    raise PolicyError(f"{path}: '{key}' pattern {pat!r} is invalid: {e}") from e
            setattr(out, key, list(val))
    return out


def load_policy_file(path: str | Path) -> tuple[IdentityPolicy, IdentityPolicy]:
    """Load a policy JSON file; return (customer_policy, build_policy).

    File shape:
        {
          "customer": { ... optional field overrides ... },
          "build":    { ... optional field overrides ... }
        }

    Missing stanzas inherit the baked-in defaults. Missing fields within a
    stanza inherit the default for that field. Unknown fields raise
    PolicyError (fail closed).
    """
    p = Path(path)
    try:
        raw = p.read_text(encoding="utf-8")
    except OSError as e:
        raise PolicyError(f"{p}: unable to read policy file: {e}") from e
    try:
        doc = json.loads(raw)
    except json.JSONDecodeError as e:
        raise PolicyError(f"{p}: invalid JSON: {e}") from e
    if not isinstance(doc, dict):
        raise PolicyError(f"{p}: top-level policy must be a JSON object")

    # Ignore underscore-prefixed top-level keys as a comment convention
    # (JSON has no real comments). Stanza-level fields are still strict.
    top_keys = {k for k in doc if not k.startswith("_")}
    unknown_stanzas = top_keys - _KNOWN_STANZAS
    if unknown_stanzas:
        raise PolicyError(
            f"{p}: unknown stanza(s) {sorted(unknown_stanzas)} — allowed: {sorted(_KNOWN_STANZAS)}"
        )

    customer = default_customer_policy()
    build = default_build_policy()
    if "customer" in doc:
        if not isinstance(doc["customer"], dict):
            raise PolicyError(f"{p}: 'customer' stanza must be an object")
        customer = _overlay_stanza(customer, doc["customer"], str(p))
    if "build" in doc:
        if not isinstance(doc["build"], dict):
            raise PolicyError(f"{p}: 'build' stanza must be an object")
        build = _overlay_stanza(build, doc["build"], str(p))
    return customer, build


# ──────────────────────────── SLSA policy evaluation ────────────────────────────


def evaluate_slsa_policy(
    prov: Any,  # attestation.SlsaProvenance — kept untyped to avoid circular import
    policy: IdentityPolicy,
) -> list[PolicyViolation]:
    """Return violations for an already-parsed SLSA provenance.

    Empty list = pass. A missing field (e.g. builder.id empty) is NOT a
    violation if the policy accepts `.*` — it's just a non-assertion. But
    if the policy has *any* non-`.*` allowlist, a missing field can't
    match, so it's reported. This surfaces the common bad case: a SLSA
    predicate with no builder.id that would otherwise slip through.
    """
    violations: list[PolicyViolation] = []

    if policy.allowed_builder_ids:
        builder_id = getattr(prov, "builder_id", "") or ""
        if not _any_match(builder_id, policy.allowed_builder_ids):
            violations.append(
                PolicyViolation(
                    check="builder_id",
                    observed=builder_id,
                    expected_patterns=list(policy.allowed_builder_ids),
                )
            )

    if policy.allowed_source_uris:
        source_uri = getattr(prov, "source_uri", "") or ""
        if not _any_match(source_uri, policy.allowed_source_uris):
            violations.append(
                PolicyViolation(
                    check="source_uri",
                    observed=source_uri,
                    expected_patterns=list(policy.allowed_source_uris),
                )
            )

    return violations


def _any_match(s: str, patterns: list[str]) -> bool:
    """True iff s matches at least one regex in patterns. Uses re.search so
    anchors in the pattern are authoritative; patterns may use ^…$ to
    require a full match."""
    return any(re.search(pat, s) for pat in patterns)
