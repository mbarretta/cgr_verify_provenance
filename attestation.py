"""
Attestation retrieval + verification primitives.

Shared by image mode (and, over time, library mode) for pulling Chainguard's
published attestations (SLSA provenance, SPDX/CycloneDX SBOMs, OpenVEX, apko
config, EOL) off a signed image, cryptographically verifying the signature
via cosign, and then parsing the in-toto Statement underneath.

Two ideas live here that the rest of the tool leans on:

1. The in-toto `subject[].digest` check — the single most important step in
   attestation verification. An attestation is only meaningful if its
   embedded subject digest matches the artifact you're verifying; otherwise
   an attacker could re-attach a valid attestation that describes a
   different artifact.

2. A thin wrapper around `cosign verify-attestation` that returns the
   decoded in-toto Statement(s). cosign does the crypto (Fulcio cert +
   Rekor SET + inclusion proof under the hood); we parse what comes back.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field

from verify_provenance import run_cmd

# Canonical predicate type URIs
PREDICATE_SLSA_V1 = "https://slsa.dev/provenance/v1"
PREDICATE_SLSA_V02 = "https://slsa.dev/provenance/v0.2"
PREDICATE_SPDX = "https://spdx.dev/Document"
PREDICATE_CYCLONEDX = "https://cyclonedx.org/bom"
PREDICATE_OPENVEX = "https://openvex.dev/ns/v0.2.0"
PREDICATE_APKO = "https://apko.dev/image-configuration"
PREDICATE_EOL = "https://chainguard.dev/end-of-life"

# cosign --type shorthand (cosign accepts both the URI and a shortname)
COSIGN_TYPE_SHORTNAMES = {
    PREDICATE_SLSA_V1: "slsaprovenance1",
    PREDICATE_SLSA_V02: "slsaprovenance",
    PREDICATE_SPDX: "spdxjson",
    PREDICATE_CYCLONEDX: "cyclonedx",
    PREDICATE_OPENVEX: "openvex",
}


@dataclass
class SlsaProvenance:
    """Parsed fields out of a SLSA v1.0 `predicate`."""

    build_type: str = ""
    builder_id: str = ""
    builder_version: dict[str, str] = field(default_factory=dict)
    source_uri: str = ""
    source_digest: dict[str, str] = field(default_factory=dict)
    invocation_id: str = ""
    started_on: str = ""
    finished_on: str = ""
    external_parameters: dict[str, object] = field(default_factory=dict)
    resolved_dependency_count: int = 0


@dataclass
class SbomSummary:
    """Audit-grade summary of an SBOM predicate (SPDX or CycloneDX).

    This is not a full parse — it deliberately surfaces only what a CISO /
    accreditor asks for at a glance: package count, license set, and a
    PURL sample. Deeper analysis (license policy eval, component graph,
    vuln scan) belongs in a separate stage.
    """

    sbom_format: str = ""  # "spdx" | "cyclonedx"
    spec_version: str = ""  # e.g. "SPDX-2.3", "1.5"
    document_name: str = ""
    package_count: int = 0
    unique_licenses: list[str] = field(default_factory=list)
    purl_sample: list[str] = field(default_factory=list)
    is_empty: bool = False  # true if package_count == 0 (flagged to caller)


@dataclass
class AttestationRecord:
    """One attestation for one predicate type on one image.

    `verified` means cosign's signature/Rekor check passed.
    `subject_matches` means the in-toto subject digest matches the image digest.
    Both must be True before a caller should trust the parsed `predicate`.
    """

    predicate_type: str
    verified: bool = False
    subject_matches: bool = False
    subject_digests: list[str] = field(default_factory=list)
    statement_type: str = ""
    predicate: dict[str, object] = field(default_factory=dict)
    slsa: SlsaProvenance | None = None
    sbom: SbomSummary | None = None
    error: str = ""
    cosign_command: str = ""


def _extract_sha256(digest_ref: str) -> str:
    """Normalize a docker-style digest `sha256:<hex>` to its hex part."""
    if not digest_ref:
        return ""
    if ":" in digest_ref:
        algo, _, hex_part = digest_ref.partition(":")
        if algo.lower() == "sha256":
            return hex_part.lower()
        return ""
    return digest_ref.lower()


def decode_statement(dsse_or_statement: dict[str, object]) -> dict[str, object]:
    """Return the in-toto Statement from either a DSSE envelope or a bare Statement.

    `cosign verify-attestation --output json` emits a DSSE envelope whose
    `payload` field is a base64-encoded in-toto Statement. Some cosign
    versions / flags emit the decoded Statement directly. Handle both.
    """
    payload = dsse_or_statement.get("payload")
    if isinstance(payload, str):
        # DSSE envelope path
        try:
            decoded = base64.b64decode(payload).decode("utf-8")
            parsed = json.loads(decoded)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, json.JSONDecodeError):
            return {}
        return {}
    # Already a decoded statement
    if isinstance(dsse_or_statement.get("subject"), list):
        return dsse_or_statement
    return {}


def subject_digest_matches(
    statement: dict[str, object], expected_digest: str
) -> tuple[bool, list[str]]:
    """P0-1: assert at least one subject digest matches the expected image digest.

    Returns (matched, observed_digests_as_sha256_hex). Absence of any sha256
    digest counts as a non-match; this is intentional — we don't consult
    alternative algorithms since Chainguard + OCI both use sha256 exclusively.
    """
    expected_hex = _extract_sha256(expected_digest)
    subjects = statement.get("subject", [])
    observed: list[str] = []
    if not isinstance(subjects, list):
        return False, observed

    matched = False
    for subj in subjects:
        if not isinstance(subj, dict):
            continue
        digest = subj.get("digest")
        if not isinstance(digest, dict):
            continue
        sha = digest.get("sha256")
        if isinstance(sha, str):
            sha_lower = sha.lower()
            observed.append(sha_lower)
            if expected_hex and sha_lower == expected_hex:
                matched = True
    return matched, observed


def parse_slsa_provenance(predicate: dict[str, object]) -> SlsaProvenance:
    """Extract the fields an auditor will ask for. Tolerates missing fields."""
    prov = SlsaProvenance()

    build_def = predicate.get("buildDefinition")
    if isinstance(build_def, dict):
        bt = build_def.get("buildType")
        if isinstance(bt, str):
            prov.build_type = bt
        ext = build_def.get("externalParameters")
        if isinstance(ext, dict):
            prov.external_parameters = ext
            # Common shape: externalParameters.source{ uri, digest }
            src = ext.get("source")
            if isinstance(src, dict):
                uri = src.get("uri")
                if isinstance(uri, str):
                    prov.source_uri = uri
                src_digest = src.get("digest")
                if isinstance(src_digest, dict):
                    prov.source_digest = {k: v for k, v in src_digest.items() if isinstance(v, str)}
        deps = build_def.get("resolvedDependencies")
        if isinstance(deps, list):
            prov.resolved_dependency_count = len(deps)

    run = predicate.get("runDetails")
    if isinstance(run, dict):
        builder = run.get("builder")
        if isinstance(builder, dict):
            bid = builder.get("id")
            if isinstance(bid, str):
                prov.builder_id = bid
            bv = builder.get("version")
            if isinstance(bv, dict):
                prov.builder_version = {k: v for k, v in bv.items() if isinstance(v, str)}
        meta = run.get("metadata")
        if isinstance(meta, dict):
            inv = meta.get("invocationId")
            if isinstance(inv, str):
                prov.invocation_id = inv
            started = meta.get("startedOn")
            if isinstance(started, str):
                prov.started_on = started
            finished = meta.get("finishedOn")
            if isinstance(finished, str):
                prov.finished_on = finished
    return prov


# ───────────────────────────── SBOM parsers ─────────────────────────────

# How many PURLs to keep in the summary. Full list would bloat the audit
# record for large images (Chainguard's python image has ~200 packages); a
# sample is enough for a human-readable summary and the full list lives in
# the raw predicate we retain on the AttestationRecord.
_PURL_SAMPLE_LIMIT = 10


def _collect_spdx_licenses(pkg: dict[str, object]) -> list[str]:
    """Extract license identifiers from one SPDX package, preferring concluded."""
    out: list[str] = []
    for key in ("licenseConcluded", "licenseDeclared"):
        val = pkg.get(key)
        if isinstance(val, str) and val and val != "NOASSERTION":
            # SPDX allows expressions like "MIT AND Apache-2.0 OR BSD-3-Clause";
            # split on boolean operators so we populate a de-duped identifier set.
            for tok in val.replace("(", " ").replace(")", " ").split():
                if tok.upper() in ("AND", "OR", "WITH"):
                    continue
                out.append(tok)
            break  # concluded is authoritative; don't double-count declared
    return out


def parse_spdx_sbom(predicate: dict[str, object]) -> SbomSummary:
    """Parse an SPDX 2.x JSON document into an audit summary.

    Returns a non-empty summary for any parseable SPDX document, even one
    with zero packages — `is_empty=True` signals the caller to flag the
    attestation as untrustworthy evidence.
    """
    summary = SbomSummary(sbom_format="spdx")

    spec = predicate.get("spdxVersion")
    if isinstance(spec, str):
        summary.spec_version = spec

    name = predicate.get("name")
    if isinstance(name, str):
        summary.document_name = name

    packages = predicate.get("packages")
    if not isinstance(packages, list):
        summary.is_empty = True
        return summary

    summary.package_count = len(packages)
    if summary.package_count == 0:
        summary.is_empty = True

    license_set: set[str] = set()
    purls: list[str] = []
    for pkg in packages:
        if not isinstance(pkg, dict):
            continue
        for lic in _collect_spdx_licenses(pkg):
            license_set.add(lic)
        ext_refs = pkg.get("externalRefs")
        if isinstance(ext_refs, list):
            for ref in ext_refs:
                if not isinstance(ref, dict):
                    continue
                rt = ref.get("referenceType")
                loc = ref.get("referenceLocator")
                if rt == "purl" and isinstance(loc, str) and len(purls) < _PURL_SAMPLE_LIMIT:
                    purls.append(loc)

    summary.unique_licenses = sorted(license_set)
    summary.purl_sample = purls
    return summary


def parse_cyclonedx_sbom(predicate: dict[str, object]) -> SbomSummary:
    """Parse a CycloneDX 1.x JSON document into an audit summary."""
    summary = SbomSummary(sbom_format="cyclonedx")

    spec = predicate.get("specVersion")
    if isinstance(spec, str):
        summary.spec_version = spec

    meta = predicate.get("metadata")
    if isinstance(meta, dict):
        comp = meta.get("component")
        if isinstance(comp, dict):
            nm = comp.get("name")
            if isinstance(nm, str):
                summary.document_name = nm

    components = predicate.get("components")
    if not isinstance(components, list):
        summary.is_empty = True
        return summary

    summary.package_count = len(components)
    if summary.package_count == 0:
        summary.is_empty = True

    license_set: set[str] = set()
    purls: list[str] = []
    for comp in components:
        if not isinstance(comp, dict):
            continue
        purl = comp.get("purl")
        if isinstance(purl, str) and len(purls) < _PURL_SAMPLE_LIMIT:
            purls.append(purl)
        # CycloneDX licenses: list of {license: {id: ..., name: ...}} entries,
        # or {expression: "MIT AND Apache-2.0"}.
        licenses = comp.get("licenses")
        if isinstance(licenses, list):
            for entry in licenses:
                if not isinstance(entry, dict):
                    continue
                lic = entry.get("license")
                if isinstance(lic, dict):
                    lid = lic.get("id") or lic.get("name")
                    if isinstance(lid, str) and lid:
                        license_set.add(lid)
                expr = entry.get("expression")
                if isinstance(expr, str):
                    for tok in expr.replace("(", " ").replace(")", " ").split():
                        if tok.upper() in ("AND", "OR", "WITH"):
                            continue
                        license_set.add(tok)

    summary.unique_licenses = sorted(license_set)
    summary.purl_sample = purls
    return summary


def _build_verify_attestation_cmd(
    image_ref: str,
    predicate_type: str,
    oidc_issuer_regex: str,
    identity_regex: str,
    trusted_root: str | None = None,
) -> list[str]:
    cmd = [
        "cosign",
        "verify-attestation",
        "--type",
        COSIGN_TYPE_SHORTNAMES.get(predicate_type, predicate_type),
        "--certificate-oidc-issuer-regexp",
        oidc_issuer_regex,
        "--certificate-identity-regexp",
        identity_regex,
    ]
    if trusted_root:
        cmd += ["--trusted-root", trusted_root]
    cmd.append(image_ref)
    return cmd


def _pretty_cmd(cmd: list[str]) -> str:
    def q(s: str) -> str:
        return f"'{s}'" if any(c in s for c in " \t\"'\\$*?") else s

    return " ".join(q(c) for c in cmd)


def retrieve_and_verify_attestation(
    image_ref: str,
    image_digest: str,
    predicate_type: str,
    oidc_issuer_regex: str,
    identity_regex: str,
    trusted_root: str | None = None,
    timeout: int = 60,
) -> AttestationRecord:
    """Run `cosign verify-attestation` for one predicate type, decode, and check subject.

    Chainguard attaches multiple attestations per image; cosign emits one
    DSSE envelope per attestation (newline-delimited JSON) when multiple
    are present. We parse each, looking for the first with a matching
    subject digest. A record with verified=True+subject_matches=True is
    safe to consume; either being False means the caller must not trust
    the parsed predicate.
    """
    rec = AttestationRecord(predicate_type=predicate_type)
    cmd = _build_verify_attestation_cmd(
        image_ref, predicate_type, oidc_issuer_regex, identity_regex, trusted_root
    )
    rec.cosign_command = _pretty_cmd(cmd)

    success, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if not success:
        # Distinguish "no attestation of that type" from real verify failure.
        # cosign's wording varies across versions; keep the raw stderr trimmed.
        err = (stderr or "").strip().splitlines()
        rec.error = err[-1] if err else "cosign verify-attestation failed"
        return rec
    rec.verified = True

    # cosign emits one DSSE envelope per attestation as a JSON array or NDJSON.
    # Handle both; ignore blank lines.
    envelopes: list[dict[str, object]] = []
    text = stdout.strip()
    if not text:
        rec.error = "cosign returned empty output"
        rec.verified = False
        return rec

    try:
        parsed = json.loads(text)
        if isinstance(parsed, list):
            envelopes = [e for e in parsed if isinstance(e, dict)]
        elif isinstance(parsed, dict):
            envelopes = [parsed]
    except json.JSONDecodeError:
        # NDJSON fallback
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    envelopes.append(obj)
            except json.JSONDecodeError:
                continue

    if not envelopes:
        rec.error = "no attestation envelopes parsed from cosign output"
        rec.verified = False
        return rec

    # Walk envelopes; first one with a subject-digest match wins. If none
    # match, keep the last parsed predicate for reporting but leave
    # subject_matches=False so the caller doesn't trust it.
    last_statement: dict[str, object] = {}
    last_predicate: dict[str, object] = {}
    for env in envelopes:
        stmt = decode_statement(env)
        if not stmt:
            continue
        last_statement = stmt
        pred = stmt.get("predicate")
        if isinstance(pred, dict):
            last_predicate = pred
        matched, observed = subject_digest_matches(stmt, image_digest)
        if matched:
            rec.subject_matches = True
            rec.subject_digests = observed
            rec.statement_type = str(stmt.get("_type", ""))
            rec.predicate = last_predicate
            _attach_typed_parse(rec, predicate_type, last_predicate)
            return rec

    # No envelope matched on subject digest.
    rec.subject_matches = False
    if last_statement:
        _, observed = subject_digest_matches(last_statement, image_digest)
        rec.subject_digests = observed
        rec.statement_type = str(last_statement.get("_type", ""))
        rec.predicate = last_predicate
        _attach_typed_parse(rec, predicate_type, last_predicate)
    if not rec.error:
        rec.error = "attestation subject digest did not match image digest"
    return rec


def _attach_typed_parse(
    rec: AttestationRecord, predicate_type: str, predicate: dict[str, object]
) -> None:
    """Populate `rec.slsa` or `rec.sbom` based on predicate type. No-op for others."""
    if predicate_type in (PREDICATE_SLSA_V1, PREDICATE_SLSA_V02):
        rec.slsa = parse_slsa_provenance(predicate)
    elif predicate_type == PREDICATE_SPDX:
        rec.sbom = parse_spdx_sbom(predicate)
    elif predicate_type == PREDICATE_CYCLONEDX:
        rec.sbom = parse_cyclonedx_sbom(predicate)
