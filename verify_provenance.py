#!/usr/bin/env python3
"""
Chainguard Image Delivery Verification

Verifies that customer org images were authentically delivered by Chainguard.

DEFAULT MODE (--customer-only, no chainguard-private access needed):
  Verifies each image:
  1. Has a valid signature from Chainguard Enforce (issuer.enforce.dev)
  2. The signature is recorded in the public Rekor transparency log
  3. Extracts the base_digest label (claimed provenance)

  This proves:
  - Chainguard's Enforce system signed and delivered this exact image
  - The delivery timestamp is publicly recorded and auditable
  - The image claims a specific source (base_digest)

  To verify images match across customers, compare base_digest values.
  Same base_digest = same claimed source image.

FULL MODE (requires access to reference org like chainguard-private):
  Additionally verifies:
  4. The base_digest exists in the reference org
  5. The base image has a valid build signature from Chainguard's GitHub workflow
  6. The build signature is recorded in Rekor

Use --verify-signatures to enable full cryptographic signature verification.
"""

import argparse
import base64
import csv
import json
import shutil
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from collections.abc import Callable

    from attestation import AttestationRecord
    from policy import IdentityPolicy, PolicyViolation
    from upstream import UpstreamVerifyResult

__version__ = "0.1.0"

# Required external tools
REQUIRED_TOOLS = ["chainctl", "crane", "cosign", "curl"]

# OIDC issuers for signature verification
CHAINGUARD_ENFORCE_ISSUER = "https://issuer.enforce.dev"
GITHUB_ACTIONS_ISSUER = "https://token.actions.githubusercontent.com"

# OCI label for base image digest
BASE_DIGEST_LABEL = "org.opencontainers.image.base.digest"


def check_dependencies() -> list[str]:
    """Check that required CLI tools are installed. Returns list of missing tools."""
    missing = []
    for tool in REQUIRED_TOOLS:
        if shutil.which(tool) is None:
            missing.append(tool)
    return missing


def print_version() -> None:
    """Print version and dependency information."""
    print(f"verify-provenance {__version__}")
    print()
    print("Dependencies:")
    for tool in REQUIRED_TOOLS:
        path = shutil.which(tool)
        if path:
            print(f"  {tool}: {path}")
        else:
            print(f"  {tool}: NOT FOUND")


@dataclass
class ChainDetails:
    """Detailed verification chain data for an image."""
    # Step 1: Customer image config
    customer_image: str = ""
    customer_digest: str = ""  # The customer image's own digest
    base_digest_full: str = ""
    base_digest_label: str = BASE_DIGEST_LABEL

    # Step 2: Reference org verification (full mode only)
    reference_image: str = ""
    reference_exists: bool = False

    # Step 3: Signature data
    signature_found: bool = False
    payload_digest: str = ""  # docker-manifest-digest from payload
    payload_matches: bool = False

    # Step 4: Rekor transparency
    rekor_log_index: str = ""
    rekor_url: str = ""
    rekor_integrated_time: str = ""
    # True iff cosign verify / verify-attestation succeeded, which by default
    # requires the Rekor entry's SignedEntryTimestamp (SET) to validate against
    # Rekor's public key. A bare rekor_log_index extracted from the bundle JSON
    # is NOT enough — an attacker controlling the registry could forge a
    # logIndex value. This field is the authoritative "we cryptographically
    # confirmed Rekor signed this" signal.
    rekor_verified: bool = False
    rekor_set_present: bool = False  # True if bundle embeds a SignedEntryTimestamp

    # Step 5: Certificate identity + Fulcio OID extensions
    # Cosign's `optional` block surfaces the GitHub OIDC claims it extracted
    # from the Fulcio cert (OIDs 1.3.6.1.4.1.57264.1.*): workflow ref, SHA,
    # trigger, runID. Auditors love seeing the exact workflow file + commit.
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_verified: bool = False
    github_workflow_ref: str = ""
    github_workflow_sha: str = ""
    github_workflow_trigger: str = ""
    github_workflow_run_id: str = ""

    # Customer-only mode fields
    customer_sig_found: bool = False
    customer_sig_issuer: str = ""
    customer_rekor_index: str = ""
    customer_rekor_url: str = ""

    # Step 6: Attestations (--verify-attestations)
    # Populated only when --verify-attestations is passed. Keyed by predicate
    # URI. The string-quoted type dodges a circular import at runtime
    # (attestation imports run_cmd from this module).
    attestations: dict[str, "AttestationRecord"] = field(default_factory=dict)

    # Step 6b: Policy evaluation (--policy-file, or with defaults)
    # Violations against the SLSA provenance allowlists (builder.id, source_uri).
    # Empty list = policy satisfied (or policy check not run).
    policy_violations: list["PolicyViolation"] = field(default_factory=list)

    # Step 8: Vulnerability scan (--scan)
    # Populated only when --scan. `scan_result` typed loosely to avoid
    # importing scan.py at dataclass-declaration time (runtime-optional dep).
    scan_result: "object | None" = None
    # Step 9: CISA KEV hits among actionable CVEs (list of KevEntry).
    kev_hits: list[object] = field(default_factory=list)

    # Step 10: Image freshness + Chainguard end-of-life attestation
    image_created: str = ""  # raw ISO-8601 timestamp from config.created
    image_age_days: int = -1  # -1 = unknown; computed from image_created
    eol_predicate_present: bool = False  # True if EOL attestation verified
    eol_details: dict[str, object] = field(default_factory=dict)

    # Step 11: SBOM drift (--sbom-drift). SbomDrift | None; loose-typed here
    # for the same reason as scan_result.
    sbom_drift: "object | None" = None

    # Step 12: Upstream-source verification (--verify-upstream-sources).
    # Walks the SPDX SBOM's relationships + purls and verifies every
    # upstream source (git ls-remote tag→commit; tarball checksum). Loose
    # typing for the same scan_result reason — upstream.py is only imported
    # when the flag is set.
    upstream_summary: "object | None" = None


@dataclass
class VerificationResult:
    image: str
    base_digest: str
    ref_status: str
    rekor_status: str
    rekor_log_index: str
    sig_status: str
    status: str
    error: str
    chain: ChainDetails = field(default_factory=ChainDetails)
    # Attestation status summary — one of "", "N/A", "VERIFIED",
    # "SUBJECT_MISMATCH", "UNVERIFIED", "NOT_FOUND". Kept at top-level
    # (not just on `chain`) so it appears in summary counts + CSV.
    slsa_status: str = "N/A"
    # SBOM verification result: "N/A" | "VERIFIED" | "SUBJECT_MISMATCH" |
    # "EMPTY" (signed + subject matches but contains zero packages) |
    # "NOT_FOUND" | "UNVERIFIED". `sbom_format` distinguishes SPDX vs
    # CycloneDX when an SBOM was found.
    sbom_status: str = "N/A"
    sbom_format: str = ""
    sbom_package_count: int = 0
    # Policy status: "N/A" (no attestation ever reached policy eval),
    # "PASS" (all allowlists matched), "VIOLATION" (one or more checks failed).
    policy_status: str = "N/A"
    # Vulnerability scan: "N/A" | "CLEAN" | "FINDINGS" | "ERROR". Counts
    # are VEX-adjusted (actionable) — raw counts live on chain.scan_result.
    vuln_status: str = "N/A"
    vuln_critical: int = 0
    vuln_high: int = 0
    vuln_medium: int = 0
    vuln_low: int = 0
    vuln_total: int = 0
    vex_applied: bool = False
    # CISA KEV cross-check: "N/A" | "CLEAN" | "HIT"; count of actionable
    # CVEs matching the KEV catalog.
    kev_status: str = "N/A"
    kev_count: int = 0
    # Freshness: "N/A" | "FRESH" | "STALE" (above --max-age-days) | "EOL"
    # (Chainguard EOL attestation present — in grace period).
    freshness_status: str = "N/A"
    # FIPS variant detection ("true" if image is a Chainguard FIPS variant).
    fips_variant: bool = False
    fips_reason: str = ""
    # SBOM drift: "N/A" | "CLEAN" | "DRIFT" | "ERROR"
    sbom_drift_status: str = "N/A"
    sbom_drift_ratio: float = 0.0
    # Upstream-source verification: "N/A" | "VERIFIED" | "FAILED" | "ERROR".
    # FAILED demotes the overall verdict to UPSTREAM_FAILED; ERROR (transient
    # network/auth) does not, matching the KEV-fetch posture.
    upstream_sources_status: str = "N/A"
    upstream_sources_total: int = 0
    upstream_sources_verified: int = 0
    upstream_sources_failed: int = 0
    upstream_sources_errors: int = 0
    upstream_sources_skipped: int = 0


def run_cmd(args: list[str], timeout: int = 30) -> tuple[bool, str, str]:
    """Run a command and return (success, stdout, stderr)."""
    try:
        result = subprocess.run(
            args, capture_output=True, text=True, timeout=timeout
        )
        return result.returncode == 0, result.stdout, result.stderr
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


def get_image_list(customer_org: str) -> list[str]:
    """Get list of entitled images for the customer organization."""
    success, output, _ = run_cmd(
        ["chainctl", "images", "repos", "list", "--parent", customer_org, "-o", "json"],
        timeout=60,
    )
    if not success or not output:
        return []

    # Parse JSON - handle malformed JSON by extracting names with string ops
    images = set()
    for line in output.split('"name":"'):
        if line and not line.startswith("{"):
            name = line.split('"')[0]
            if name and "/" not in name:  # Filter out paths, keep just names
                images.add(name)

    return sorted(images)


def verify_image(
    image: str,
    registry: str,
    customer_org: str,
    reference_org: str,
    verify_signatures: bool,
    capture_details: bool,
    customer_only: bool = False,
    verify_attestations: bool = False,
    customer_policy: "IdentityPolicy | None" = None,
    build_policy: "IdentityPolicy | None" = None,
    scan: bool = False,
    kev_catalog: "object | None" = None,
    max_age_days: int = 0,
    trusted_root: str | None = None,
    sbom_drift_enabled: bool = False,
    verify_upstream_sources: bool = False,
    upstream_cache: "dict[tuple[str, str], UpstreamVerifyResult] | None" = None,
    upstream_github_token: str = "",
) -> VerificationResult:
    """Verify a single image with optional detailed chain capture."""
    customer_image = f"{registry}/{customer_org}/{image}:latest"
    reference_image = f"{registry}/{reference_org}/{image}"

    chain = ChainDetails(
        customer_image=customer_image,
        reference_image=reference_image,
    )

    result = VerificationResult(
        image=image,
        base_digest="N/A",
        ref_status="N/A",
        rekor_status="N/A",
        rekor_log_index="",
        sig_status="N/A",
        status="ERROR",
        error="",
        chain=chain,
    )

    # Step 1: Get customer image digest
    success, digest_output, _ = run_cmd(["crane", "digest", customer_image])
    if success:
        chain.customer_digest = digest_output.strip()

    # Step 2: Get image config and extract base digest
    success, config_output, err = run_cmd(["crane", "config", customer_image])
    if not success:
        result.error = f"Failed to get config: {err}"
        return result

    try:
        config = json.loads(config_output)
        labels = config.get("config", {}).get("Labels", {})
        base_digest = labels.get("org.opencontainers.image.base.digest", "")
        # Extract build timestamp for freshness check. Image configs use ISO
        # 8601 with 'Z' suffix. Python 3.11+ parses this natively; we strip
        # the Z for 3.10 compatibility.
        created_raw = config.get("created", "")
        if isinstance(created_raw, str) and created_raw:
            chain.image_created = created_raw
            try:
                dt = datetime.fromisoformat(created_raw.replace("Z", "+00:00"))
                age_delta = datetime.now(tz=timezone.utc) - dt
                chain.image_age_days = max(0, age_delta.days)
            except ValueError:
                pass
    except json.JSONDecodeError:
        result.error = "Failed to parse config JSON"
        return result

    if not base_digest:
        result.status = "NO_BASE"
        result.error = "No base digest label"
        return result

    chain.base_digest_full = base_digest
    result.base_digest = base_digest[:19] + "..."  # Truncate for display

    # Pre-attestation: FIPS variant detection (name/tag based, cheap).
    result.fips_variant, result.fips_reason = _detect_fips_variant(image, customer_image)

    # Customer-only mode: verify via customer image signature
    if customer_only:
        return verify_customer_only(
            result, chain, customer_image, capture_details,
            verify_attestations=verify_attestations,
            policy=customer_policy,
            scan=scan,
            kev_catalog=kev_catalog,
            max_age_days=max_age_days,
            trusted_root=trusted_root,
            sbom_drift_enabled=sbom_drift_enabled,
            verify_upstream_sources=verify_upstream_sources,
            upstream_cache=upstream_cache,
            upstream_github_token=upstream_github_token,
        )

    # Full mode: verify via reference org

    # Step 3: Check reference org
    success, _, _ = run_cmd(
        ["crane", "digest", f"{reference_image}@{base_digest}"], timeout=15
    )
    result.ref_status = "EXISTS" if success else "NOT_FOUND"
    chain.reference_exists = success

    # Step 4: Download and parse signature from reference
    success, sig_output, _ = run_cmd(
        ["cosign", "download", "signature", f"{reference_image}@{base_digest}"],
        timeout=30,
    )

    if success and sig_output:
        chain.signature_found = True
        try:
            sig_data = json.loads(sig_output)

            # Extract payload to verify digest matches
            payload_b64 = sig_data.get("Payload", "")
            if payload_b64:
                try:
                    payload_json = base64.b64decode(payload_b64).decode("utf-8")
                    payload = json.loads(payload_json)
                    # The digest is in critical.image.docker-manifest-digest
                    payload_digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
                    chain.payload_digest = payload_digest
                    chain.payload_matches = (payload_digest == base_digest)
                except Exception:
                    pass

            # Extract Rekor bundle (unverified: these values come from
            # reading the signature JSON, not from Rekor itself).
            bundle = sig_data.get("Bundle", {})
            payload_data = bundle.get("Payload", {})
            log_index = payload_data.get("logIndex")
            integrated_time = payload_data.get("integratedTime")
            # SignedEntryTimestamp presence: ties this entry to Rekor's
            # private key (verified cryptographically by cosign verify below).
            chain.rekor_set_present = bool(bundle.get("SignedEntryTimestamp"))

            if log_index:
                result.rekor_status = "EXISTS"
                result.rekor_log_index = str(log_index)
                chain.rekor_log_index = str(log_index)
                chain.rekor_url = f"https://search.sigstore.dev/?logIndex={log_index}"
                if integrated_time:
                    chain.rekor_integrated_time = datetime.fromtimestamp(integrated_time, tz=timezone.utc).isoformat()
            else:
                result.rekor_status = "NOT_FOUND"

        except json.JSONDecodeError:
            result.rekor_status = "ERROR"
    else:
        result.rekor_status = "NOT_FOUND"

    # Resolve build policy (defaults if none supplied)
    if build_policy is None:
        from policy import default_build_policy as _dbp
        effective_build_policy = _dbp()
    else:
        effective_build_policy = build_policy

    # Step 5: Signature verification (extracts certificate details). cosign
    # verify's default behavior includes fetching the Rekor entry and
    # validating its SignedEntryTimestamp against Rekor's public key — so
    # success here means the Rekor inclusion is cryptographically confirmed,
    # not just claimed by the bundle JSON.
    if verify_signatures or capture_details:
        verify_cmd = [
            "cosign", "verify",
            "--certificate-oidc-issuer-regexp", effective_build_policy.cosign_oidc_issuer_regex,
            "--certificate-identity-regexp", effective_build_policy.cosign_identity_regex,
            "--output", "json",
        ]
        if trusted_root:
            verify_cmd += ["--trusted-root", trusted_root]
        verify_cmd.append(f"{reference_image}@{base_digest}")
        success, verify_output, verify_err = run_cmd(verify_cmd, timeout=30)

        if success:
            result.sig_status = "VALID"
            chain.cert_verified = True
            chain.rekor_verified = True

            # Parse verification output for certificate details + Rekor fields
            try:
                verify_data = json.loads(verify_output)
                if isinstance(verify_data, list) and len(verify_data) > 0:
                    cert_info = verify_data[0].get("optional", {})
                    chain.cert_issuer = cert_info.get("Issuer", "")
                    chain.cert_subject = cert_info.get("Subject", "")
                    _extract_fulcio_extensions(chain, cert_info)
                    # Belt-and-suspenders: cosign's own output records the
                    # Rekor logIndex it verified. If it disagrees with what
                    # we parsed from `cosign download signature`, that's a
                    # signal the bundle was tampered with in-registry.
                    _cross_check_rekor_logindex(chain, cert_info)
            except json.JSONDecodeError:
                pass
        else:
            result.sig_status = "INVALID"

    # Step 6: Attestation verification (SLSA provenance + SBOM + optional VEX/EOL/apko)
    if verify_attestations and chain.base_digest_full:
        _verify_image_attestations(
            result, chain,
            image_ref=f"{reference_image}@{base_digest}",
            expected_digest=base_digest,
            policy=effective_build_policy,
            include_openvex=scan,
            include_eol=(max_age_days > 0 or verify_attestations),
            include_apko=verify_attestations,
            trusted_root=trusted_root,
        )

    # Step 8: Vulnerability scan + Step 9 KEV check
    if scan:
        _run_vuln_scan(
            result, chain,
            image_ref=f"{reference_image}@{base_digest}",
            kev_catalog=kev_catalog,
        )

    # Step 10: Freshness + EOL evaluation
    _evaluate_freshness(result, chain, max_age_days)

    # Step 11: SBOM drift (syft vs attested)
    if sbom_drift_enabled:
        _run_sbom_drift(
            result, chain, image_ref=f"{reference_image}@{base_digest}"
        )

    # Step 12: Upstream-source verification (--verify-upstream-sources)
    if verify_upstream_sources:
        _verify_upstream_sources_step(
            result, chain,
            cache=upstream_cache,
            github_token_value=upstream_github_token,
        )

    # Determine final status
    if result.ref_status == "EXISTS" and result.rekor_status == "EXISTS":
        result.status = "VERIFIED"
    elif result.ref_status == "EXISTS":
        result.status = "PARTIAL"
    else:
        result.status = "NOT_FOUND"

    # A confirmed subject-mismatch on any attestation is worse than "no
    # attestation" and should demote the overall verdict — even valid
    # sig+Rekor can't rescue a signed attestation that describes a
    # different image. Policy violations (wrong builder/source) demote too.
    # A KEV hit among actionable CVEs demotes VERIFIED → KEV_HIT so
    # pipelines can gate on the single verification_status column. Upstream
    # FAILED (SBOM claims an upstream tag/checksum that doesn't match
    # reality) is the same flavour of integrity failure as KEV — demote
    # VERIFIED to UPSTREAM_FAILED.
    if "SUBJECT_MISMATCH" in (result.slsa_status, result.sbom_status):
        result.status = "ATTESTATION_FAILED"
    elif result.policy_status == "VIOLATION":
        result.status = "POLICY_VIOLATION"
    elif result.kev_status == "HIT" and result.status == "VERIFIED":
        result.status = "KEV_HIT"
    elif result.upstream_sources_status == "FAILED" and result.status == "VERIFIED":
        result.status = "UPSTREAM_FAILED"

    return result


def verify_customer_only(
    result: VerificationResult,
    chain: ChainDetails,
    customer_image: str,
    capture_details: bool,
    verify_attestations: bool = False,
    policy: "IdentityPolicy | None" = None,
    scan: bool = False,
    kev_catalog: "object | None" = None,
    max_age_days: int = 0,
    trusted_root: str | None = None,
    sbom_drift_enabled: bool = False,
    verify_upstream_sources: bool = False,
    upstream_cache: "dict[tuple[str, str], UpstreamVerifyResult] | None" = None,
    upstream_github_token: str = "",
) -> VerificationResult:
    """Verify using only customer org access (no reference org needed)."""
    # Download signature from customer image
    success, sig_output, _ = run_cmd(
        ["cosign", "download", "signature", customer_image],
        timeout=30,
    )

    if not success or not sig_output:
        result.error = "No signature found on customer image"
        result.status = "NO_SIG"
        return result

    chain.customer_sig_found = True

    try:
        sig_data = json.loads(sig_output)

        # Extract payload to see what's signed
        payload_b64 = sig_data.get("Payload", "")
        if payload_b64:
            try:
                payload_json = base64.b64decode(payload_b64).decode("utf-8")
                payload = json.loads(payload_json)
                chain.payload_digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
                # In customer-only mode, payload should match customer digest
                chain.payload_matches = (chain.payload_digest == chain.customer_digest)
            except Exception:
                pass

        # Get certificate info
        cert_data = sig_data.get("Cert", {})
        if cert_data:
            # Extract issuer from certificate URIs
            uris = cert_data.get("URIs", [])
            if uris and len(uris) > 0:
                chain.customer_sig_issuer = uris[0].get("Host", "") + uris[0].get("Path", "")

        # Extract Rekor bundle (unverified: these values come from reading
        # the signature JSON, not from Rekor itself).
        bundle = sig_data.get("Bundle", {})
        payload_data = bundle.get("Payload", {})
        log_index = payload_data.get("logIndex")
        integrated_time = payload_data.get("integratedTime")
        chain.rekor_set_present = bool(bundle.get("SignedEntryTimestamp"))

        if log_index:
            result.rekor_status = "EXISTS"
            result.rekor_log_index = str(log_index)
            chain.customer_rekor_index = str(log_index)
            chain.customer_rekor_url = f"https://search.sigstore.dev/?logIndex={log_index}"
            if integrated_time:
                chain.rekor_integrated_time = datetime.fromtimestamp(integrated_time, tz=timezone.utc).isoformat()
        else:
            result.rekor_status = "NOT_FOUND"

    except json.JSONDecodeError:
        result.error = "Failed to parse signature"
        return result

    # Resolve customer policy (defaults if none supplied)
    if policy is None:
        from policy import default_customer_policy as _dcp
        effective_policy = _dcp()
    else:
        effective_policy = policy

    # Verify signature cryptographically. cosign verify's default behavior
    # includes Rekor SET verification against Rekor's public key, so success
    # here is the authoritative "Rekor inclusion is real" signal — not the
    # bare logIndex we pulled from the bundle.
    if capture_details:
        verify_cmd = [
            "cosign", "verify",
            "--certificate-oidc-issuer-regexp", effective_policy.cosign_oidc_issuer_regex,
            "--certificate-identity-regexp", effective_policy.cosign_identity_regex,
            "--output", "json",
        ]
        if trusted_root:
            verify_cmd += ["--trusted-root", trusted_root]
        verify_cmd.append(customer_image)
        success, verify_output, _ = run_cmd(verify_cmd, timeout=30)

        if success:
            result.sig_status = "VALID"
            chain.cert_verified = True
            chain.rekor_verified = True
            try:
                verify_data = json.loads(verify_output)
                if isinstance(verify_data, list) and len(verify_data) > 0:
                    cert_info = verify_data[0].get("optional", {})
                    _cross_check_rekor_logindex(chain, cert_info)
                    _extract_fulcio_extensions(chain, cert_info)
            except json.JSONDecodeError:
                pass
        else:
            result.sig_status = "INVALID"

    # Step 5: Attestation verification (SLSA provenance + SBOM + optional VEX/EOL/apko)
    if verify_attestations and chain.customer_digest:
        _verify_image_attestations(
            result, chain,
            image_ref=customer_image,
            expected_digest=chain.customer_digest,
            policy=effective_policy,
            include_openvex=scan,
            include_eol=(max_age_days > 0 or verify_attestations),
            include_apko=verify_attestations,
            trusted_root=trusted_root,
        )

    # Step 8: Vulnerability scan + Step 9 KEV check
    if scan:
        _run_vuln_scan(result, chain, image_ref=customer_image, kev_catalog=kev_catalog)

    # Step 10: Freshness + EOL evaluation
    _evaluate_freshness(result, chain, max_age_days)

    # Step 11: SBOM drift (syft vs attested)
    if sbom_drift_enabled:
        _run_sbom_drift(result, chain, image_ref=customer_image)

    # Step 12: Upstream-source verification (--verify-upstream-sources)
    if verify_upstream_sources:
        _verify_upstream_sources_step(
            result, chain,
            cache=upstream_cache,
            github_token_value=upstream_github_token,
        )

    # In customer-only mode, we mark as VERIFIED if we have signature + Rekor
    # but note that we can't verify the BASE digest, only the customer image delivery
    if chain.customer_sig_found and result.rekor_status == "EXISTS":
        result.status = "DELIVERY_VERIFIED"
        result.ref_status = "SKIPPED"
    else:
        result.status = "PARTIAL"

    # See note in verify_image: subject-mismatch on any attestation demotes
    # the overall verdict regardless of how well the signature + Rekor
    # steps went. Policy violations also demote. KEV hits demote VERIFIED
    # outcomes (DELIVERY_VERIFIED specifically here). Upstream FAILED
    # demotes the same way — a forged-but-cosigned SBOM is no more
    # trustworthy than a substituted attestation.
    if "SUBJECT_MISMATCH" in (result.slsa_status, result.sbom_status):
        result.status = "ATTESTATION_FAILED"
    elif result.policy_status == "VIOLATION":
        result.status = "POLICY_VIOLATION"
    elif result.kev_status == "HIT" and result.status == "DELIVERY_VERIFIED":
        result.status = "KEV_HIT"
    elif (
        result.upstream_sources_status == "FAILED"
        and result.status == "DELIVERY_VERIFIED"
    ):
        result.status = "UPSTREAM_FAILED"

    return result


def _extract_fulcio_extensions(chain: ChainDetails, cert_info: dict[str, object]) -> None:
    """Pull GitHub workflow identity from cosign verify's optional block.

    Cosign surfaces the Fulcio cert's OID extensions (1.3.6.1.4.1.57264.1.*)
    as named fields: `GithubWorkflowRef`, `GithubWorkflowSha`, etc. Some
    versions vary the casing — check both conventions.
    """
    def pick(*keys: str) -> str:
        for k in keys:
            v = cert_info.get(k)
            if isinstance(v, str) and v:
                return v
        return ""

    chain.github_workflow_ref = pick("GithubWorkflowRef", "githubWorkflowRef")
    chain.github_workflow_sha = pick("GithubWorkflowSha", "githubWorkflowSha")
    chain.github_workflow_trigger = pick("GithubWorkflowTrigger", "githubWorkflowTrigger")
    chain.github_workflow_run_id = pick("GithubWorkflowRunID", "githubWorkflowRunId")


def _cross_check_rekor_logindex(chain: ChainDetails, cert_info: dict[str, object]) -> None:
    """After cosign verify succeeds, confirm the logIndex it verified matches
    the one we read from the separately-fetched bundle.

    cosign verify -o json embeds the Rekor bundle it verified under
    optional.Bundle.Payload. A mismatch against what we earlier extracted
    from `cosign download signature` would be noteworthy — the registry
    would have served two different bundles for the same artifact. We
    don't hard-fail on mismatch (this belongs in a stricter mode later)
    but we do blank out the display logIndex so an auditor reading the
    chain output sees the inconsistency.
    """
    try:
        bundle = cert_info.get("Bundle", {})
        if not isinstance(bundle, dict):
            return
        payload = bundle.get("Payload", {})
        if not isinstance(payload, dict):
            return
        verified_idx = payload.get("logIndex")
        if verified_idx is None:
            return
        verified_idx_s = str(verified_idx)
        existing = chain.rekor_log_index or chain.customer_rekor_index
        if existing and existing != verified_idx_s:
            # Flag mismatch: prepend a marker to the display URL so it's
            # visible in output. Real hard-fail behavior is P2 scope.
            chain.rekor_url = (
                f"MISMATCH: bundle logIndex={existing}, verified logIndex={verified_idx_s}"
            )
    except (AttributeError, TypeError):
        return


def _verify_image_attestations(
    result: VerificationResult,
    chain: ChainDetails,
    image_ref: str,
    expected_digest: str,
    policy: "IdentityPolicy",
    include_openvex: bool = False,
    include_eol: bool = False,
    include_apko: bool = False,
    trusted_root: str | None = None,
) -> None:
    """Fetch + verify all Chainguard-signed attestations we care about.

    Today: SLSA v1.0 provenance and SPDX/CycloneDX SBOM. Populates
    `chain.attestations[predicate_type]` per predicate and sets coarse
    `result.*_status` summary fields. After SLSA is parsed, also runs the
    policy allowlist against the provenance and records violations on
    `result.policy_status` + `chain.policy_violations`. Never raises —
    failures are surfaced as data, not exceptions.
    """
    # Import locally to avoid a circular import at module-load time —
    # attestation.py imports run_cmd from this module.
    from attestation import (
        PREDICATE_CYCLONEDX,
        PREDICATE_SLSA_V1,
        PREDICATE_SPDX,
        retrieve_and_verify_attestation,
    )
    from policy import evaluate_slsa_policy

    # --- SLSA v1.0 provenance ---------------------------------------------
    slsa_rec = retrieve_and_verify_attestation(
        image_ref=image_ref,
        image_digest=expected_digest,
        predicate_type=PREDICATE_SLSA_V1,
        oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
        identity_regex=policy.cosign_identity_regex,
        trusted_root=trusted_root,
    )
    chain.attestations[PREDICATE_SLSA_V1] = slsa_rec
    result.slsa_status = _summarize_attestation_status(slsa_rec)

    # Policy evaluation: only meaningful on a successfully-verified,
    # subject-matched SLSA record. Otherwise the predicate isn't trustworthy
    # input for the allowlist check in the first place.
    if slsa_rec.verified and slsa_rec.subject_matches and slsa_rec.slsa is not None:
        violations = evaluate_slsa_policy(slsa_rec.slsa, policy)
        chain.policy_violations = violations
        result.policy_status = "VIOLATION" if violations else "PASS"

    # --- SBOM: prefer SPDX; fall back to CycloneDX ------------------------
    # Chainguard has published SPDX since day one; CycloneDX on customer
    # images only for builds after 2026-01-29. Try SPDX first because it
    # covers more of the fleet. If SPDX isn't present, retry for CycloneDX.
    sbom_rec = retrieve_and_verify_attestation(
        image_ref=image_ref,
        image_digest=expected_digest,
        predicate_type=PREDICATE_SPDX,
        oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
        identity_regex=policy.cosign_identity_regex,
        trusted_root=trusted_root,
    )
    chain.attestations[PREDICATE_SPDX] = sbom_rec
    sbom_found = sbom_rec.verified and sbom_rec.subject_matches

    if not sbom_found:
        # Look for CycloneDX — if present, it becomes the canonical SBOM record
        # for this run. We still keep the SPDX attempt on chain.attestations
        # for the audit trail.
        cyclo_rec = retrieve_and_verify_attestation(
            image_ref=image_ref,
            image_digest=expected_digest,
            predicate_type=PREDICATE_CYCLONEDX,
            oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
            identity_regex=policy.cosign_identity_regex,
            trusted_root=trusted_root,
        )
        chain.attestations[PREDICATE_CYCLONEDX] = cyclo_rec
        if cyclo_rec.verified and cyclo_rec.subject_matches:
            sbom_rec = cyclo_rec

    result.sbom_status = _summarize_sbom_status(sbom_rec)
    if sbom_rec.sbom is not None:
        result.sbom_format = sbom_rec.sbom.sbom_format
        result.sbom_package_count = sbom_rec.sbom.package_count

    # --- OpenVEX (opt-in: only when --scan is requested) ------------------
    # Pulling OpenVEX costs another cosign call per image; the scan flow is
    # the only current consumer, so we keep it gated to avoid unnecessary
    # network/auth overhead when users only want attestation verification.
    if include_openvex:
        from attestation import PREDICATE_OPENVEX

        vex_rec = retrieve_and_verify_attestation(
            image_ref=image_ref,
            image_digest=expected_digest,
            predicate_type=PREDICATE_OPENVEX,
            oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
            identity_regex=policy.cosign_identity_regex,
            trusted_root=trusted_root,
        )
        chain.attestations[PREDICATE_OPENVEX] = vex_rec

    # --- End-of-life (opportunistic when --max-age-days given) ------------
    # Chainguard only publishes this predicate for images in the EOL grace
    # period, so "not found" is the normal case. We still record the attempt
    # on chain.attestations for audit trails.
    if include_eol:
        from attestation import PREDICATE_EOL

        eol_rec = retrieve_and_verify_attestation(
            image_ref=image_ref,
            image_digest=expected_digest,
            predicate_type=PREDICATE_EOL,
            oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
            identity_regex=policy.cosign_identity_regex,
            trusted_root=trusted_root,
        )
        chain.attestations[PREDICATE_EOL] = eol_rec
        if eol_rec.verified and eol_rec.subject_matches:
            chain.eol_predicate_present = True
            chain.eol_details = eol_rec.predicate

    # --- apko image configuration (opt-in) --------------------------------
    # Surfaces entrypoint, user, packages for downstream policy checks.
    if include_apko:
        from attestation import PREDICATE_APKO

        apko_rec = retrieve_and_verify_attestation(
            image_ref=image_ref,
            image_digest=expected_digest,
            predicate_type=PREDICATE_APKO,
            oidc_issuer_regex=policy.cosign_oidc_issuer_regex,
            identity_regex=policy.cosign_identity_regex,
            trusted_root=trusted_root,
        )
        chain.attestations[PREDICATE_APKO] = apko_rec


def _run_vuln_scan(
    result: VerificationResult,
    chain: ChainDetails,
    image_ref: str,
    kev_catalog: "object | None" = None,
) -> None:
    """Run grype against the image; apply OpenVEX predicate if one was verified.

    After scanning, cross-checks actionable (VEX-adjusted) CVEs against the
    CISA KEV catalog. Any hit is unadjudicated by the producer, so it flips
    kev_status to HIT and — in the outer verdict block — demotes the
    overall verification_status to KEV_HIT.

    Populates result.vuln_* + result.kev_* summary fields; stashes the full
    ScanResult on chain.scan_result and KevEntry list on chain.kev_hits.
    """
    from attestation import PREDICATE_OPENVEX
    from scan import run_scan

    # Only pass the VEX predicate if it was both verified AND subject-matched.
    # An unverified or substituted VEX would suppress vulns we shouldn't
    # suppress — the whole point of signed VEX is that we only trust it when
    # crypto says we should.
    vex_rec = chain.attestations.get(PREDICATE_OPENVEX)
    vex_predicate: dict[str, object] | None = None
    if vex_rec is not None and vex_rec.verified and vex_rec.subject_matches:
        vex_predicate = vex_rec.predicate

    scan_result = run_scan(image_ref=image_ref, vex_predicate=vex_predicate)
    chain.scan_result = scan_result

    if not scan_result.success:
        result.vuln_status = "ERROR"
        return

    # Populate the summary fields from the VEX-adjusted ("actionable") counts.
    # Raw counts live in chain.scan_result for the detailed chain output.
    ac = scan_result.actionable_counts
    result.vuln_critical = ac.critical
    result.vuln_high = ac.high
    result.vuln_medium = ac.medium
    result.vuln_low = ac.low
    result.vuln_total = ac.total()
    result.vex_applied = scan_result.vex_applied
    result.vuln_status = "CLEAN" if result.vuln_total == 0 else "FINDINGS"

    # KEV cross-check: only meaningful against actionable CVEs (VEX-adjudicated
    # hits don't count against us; the producer has documented them).
    if kev_catalog is not None:
        from kev import KevCatalog, check_cves_against_kev

        if isinstance(kev_catalog, KevCatalog) and not kev_catalog.is_empty():
            hits = check_cves_against_kev(scan_result.actionable_cve_ids, kev_catalog)
            chain.kev_hits = list(hits)
            result.kev_count = len(hits)
            result.kev_status = "HIT" if hits else "CLEAN"


def _evaluate_freshness(
    result: VerificationResult, chain: ChainDetails, max_age_days: int
) -> None:
    """Classify freshness. EOL attestation takes precedence over age threshold."""
    if chain.eol_predicate_present:
        result.freshness_status = "EOL"
        return
    if chain.image_age_days < 0:
        result.freshness_status = "N/A"
        return
    if max_age_days > 0 and chain.image_age_days > max_age_days:
        result.freshness_status = "STALE"
    else:
        result.freshness_status = "FRESH"


def _detect_fips_variant(image_name: str, image_ref: str) -> tuple[bool, str]:
    """FIPS detection by tag/name substring.

    Returns (is_fips_variant, reason). Predicate-based detection would be
    more authoritative but Chainguard's FIPS attestation schema is evolving;
    tag substring matches the current convention (`cgr.dev/org/X-fips`).
    """
    lower_name = image_name.lower()
    lower_ref = image_ref.lower()
    if lower_name.endswith("-fips") or "-fips:" in lower_ref or "-fips@" in lower_ref:
        return True, "tag/name contains '-fips' suffix"
    return False, ""


def _run_sbom_drift(
    result: VerificationResult, chain: ChainDetails, image_ref: str
) -> None:
    """Run syft against the image and diff against the attested SBOM's PURL set.

    Only meaningful when an SBOM attestation has already been verified; an
    unverified attested SBOM could itself be substituted, so diffing against
    it would be meaningless. Looks up SPDX first, falls back to CycloneDX.
    """
    from attestation import PREDICATE_CYCLONEDX, PREDICATE_SPDX
    from scan import extract_purl_set, run_sbom_drift

    attested_rec = None
    for pt in (PREDICATE_SPDX, PREDICATE_CYCLONEDX):
        rec = chain.attestations.get(pt)
        if rec and rec.verified and rec.subject_matches and rec.predicate:
            attested_rec = rec
            break
    if attested_rec is None:
        result.sbom_drift_status = "ERROR"
        return

    attested_purls = extract_purl_set(attested_rec.predicate)
    drift = run_sbom_drift(image_ref=image_ref, attested_purls=attested_purls)
    chain.sbom_drift = drift
    if not drift.success:
        result.sbom_drift_status = "ERROR"
        return
    result.sbom_drift_ratio = drift.drift_ratio
    # >5% drift is noteworthy. Container build-time SBOMs and runtime
    # scans legitimately differ by a few percent (scanner classifies some
    # layers differently). Tune via policy later.
    result.sbom_drift_status = "DRIFT" if drift.drift_ratio > 0.05 else "CLEAN"


def _verify_upstream_sources_step(
    result: VerificationResult,
    chain: ChainDetails,
    cache: "dict[tuple[str, str], UpstreamVerifyResult] | None" = None,
    github_token_value: str = "",
) -> None:
    """Walk the verified SPDX SBOM and check every upstream source upstream.

    Only meaningful with a cryptographically verified, subject-matched SPDX
    record on `chain.attestations`. CycloneDX is not yet supported (different
    schema; deferred). When neither is available, this step records
    `upstream_sources_status="N/A"` and returns silently.
    """
    from attestation import PREDICATE_CYCLONEDX, PREDICATE_SPDX
    from upstream import UpstreamSummary, verify_sources, walk_spdx_sources

    spdx_rec = chain.attestations.get(PREDICATE_SPDX)
    if spdx_rec is None or not (spdx_rec.verified and spdx_rec.subject_matches):
        # No verified SPDX. CycloneDX walking isn't implemented yet — we
        # explicitly leave status as N/A so reports don't claim a failure.
        cyclo_rec = chain.attestations.get(PREDICATE_CYCLONEDX)
        if cyclo_rec is not None and cyclo_rec.verified and cyclo_rec.subject_matches:
            result.upstream_sources_status = "N/A"
        return

    sources = walk_spdx_sources(spdx_rec.predicate)
    if not sources:
        chain.upstream_summary = UpstreamSummary()
        return

    summary = verify_sources(
        sources,
        github_token_value=github_token_value,
        cache=cache,
    )
    chain.upstream_summary = summary
    result.upstream_sources_total = summary.total
    result.upstream_sources_verified = summary.verified
    result.upstream_sources_failed = summary.failed
    result.upstream_sources_errors = summary.errors
    result.upstream_sources_skipped = summary.skipped
    result.upstream_sources_status = summary.as_status()


def _summarize_attestation_status(rec: "AttestationRecord") -> str:
    """Signature-level summary shared by SLSA and SBOM flows."""
    if rec.verified and rec.subject_matches:
        return "VERIFIED"
    if rec.verified and not rec.subject_matches:
        return "SUBJECT_MISMATCH"
    if rec.error and "no matching attestations" in rec.error.lower():
        return "NOT_FOUND"
    return "UNVERIFIED"


def _summarize_sbom_status(rec: "AttestationRecord") -> str:
    """Same summary as SLSA plus an EMPTY verdict for zero-package SBOMs.

    An empty SBOM is signed metadata that proves nothing about content —
    treat it as a failure mode distinct from missing entirely.
    """
    base = _summarize_attestation_status(rec)
    if base == "VERIFIED" and rec.sbom is not None and rec.sbom.is_empty:
        return "EMPTY"
    return base


def print_chain_details(result: VerificationResult, index: int, customer_only: bool = False):
    """Print detailed verification chain for an image."""
    chain = result.chain

    print(f"\n{'═' * 80}")
    print(f"  IMAGE {index}: {result.image}")
    print(f"{'═' * 80}")

    if customer_only:
        print_chain_details_customer_only(result, chain)
    else:
        print_chain_details_full(result, chain)


def print_chain_details_customer_only(result: VerificationResult, chain: ChainDetails):
    """Print verification chain for customer-only mode."""

    # Step 1: Customer Image Info
    print(f"\n  ┌─ STEP 1: Extract Base Digest from Customer Image")
    print(f"  │")
    print(f"  │  Customer Image:  {chain.customer_image}")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    crane config {chain.customer_image} | \\")
    print(f"  │      jq -r '.config.Labels[\"{chain.base_digest_label}\"]'")
    print(f"  │")
    if chain.base_digest_full:
        print(f"  │  Base Digest: {chain.base_digest_full}")
        print(f"  │")
        print(f"  └─ ✓ Base digest found (references source in chainguard-private)")
    else:
        print(f"  │")
        print(f"  └─ ✗ No base digest label found")
        return

    # Step 2: Customer Image Signature
    print(f"\n  ┌─ STEP 2: Download & Verify Customer Image Signature")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    cosign download signature {chain.customer_image}")
    print(f"  │")
    if chain.customer_sig_found:
        print(f"  │  Signature:      Found in OCI registry")
        print(f"  │  Signed Digest:  {chain.payload_digest}")
        if chain.customer_sig_issuer:
            print(f"  │  Issuer:         {chain.customer_sig_issuer}")
        print(f"  │")
        if chain.payload_matches:
            print(f"  └─ ✓ Signature found and payload verified")
        else:
            print(f"  └─ ⚠ Signature payload doesn't match (may sign different manifest)")
    else:
        print(f"  │")
        print(f"  └─ ✗ No signature found on customer image")
        return

    # Step 3: Rekor Entry
    print(f"\n  ┌─ STEP 3: Verify Rekor Transparency Log Entry")
    print(f"  │")
    if chain.customer_rekor_index:
        print(f"  │  Log Index:      {chain.customer_rekor_index}")
        if chain.rekor_integrated_time:
            print(f"  │  Integrated At:  {chain.rekor_integrated_time}")
        set_badge = "✓ present in bundle" if chain.rekor_set_present else "✗ absent"
        print(f"  │  SET:            {set_badge}")
        verify_badge = (
            "✓ SET signed by Rekor public key (verified by cosign)"
            if chain.rekor_verified
            else "○ not cryptographically verified yet (see Step 4)"
        )
        print(f"  │  Rekor Verified: {verify_badge}")
        print(f"  │")
        print(f"  │  View in browser:")
        print(f"  │    {chain.customer_rekor_url}")
        print(f"  │")
        print(f"  │  Command (fetch entry):")
        print(f"  │    rekor-cli get --log-index {chain.customer_rekor_index}")
        print(f"  │")
        if chain.rekor_verified:
            print(f"  └─ ✓ Delivery signature recorded AND cryptographically verified in Rekor")
        else:
            print(f"  └─ ⚠ Rekor entry claimed by bundle but SET not yet cryptographically verified")
    else:
        print(f"  │")
        print(f"  └─ ✗ No Rekor entry found")

    # Step 4: Certificate Verification
    print(f"\n  ┌─ STEP 4: Cryptographic Signature Verification")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    cosign verify \\")
    print(f"  │      --certificate-oidc-issuer-regexp 'https://issuer.enforce.dev.*' \\")
    print(f"  │      --certificate-identity-regexp '.*' \\")
    print(f"  │      {chain.customer_image}")
    print(f"  │")
    if chain.cert_verified:
        print(f"  │  OIDC Issuer: https://issuer.enforce.dev (Chainguard Enforce)")
        print(f"  │")
        print(f"  └─ ✓ Signature cryptographically verified as Chainguard-delivered")
    else:
        if result.sig_status == "INVALID":
            print(f"  │")
            print(f"  └─ ✗ Signature verification FAILED")
        else:
            print(f"  │")
            print(f"  └─ ○ Verification in progress...")

    # Step 5 (optional): SLSA provenance attestation
    _print_slsa_step(result, chain)

    # Final verdict
    print(f"\n  ┌─ VERIFICATION RESULT")
    print(f"  │")
    if result.status == "DELIVERY_VERIFIED":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✓ Chainguard delivery verified: image was signed by Chainguard")
        print(f"       Enforce and recorded in public transparency log.")
        print(f"       Base digest label shows claimed provenance.")
        print(f"")
        print(f"       NOTE: To verify the base image's original build signature,")
        print(f"       use --reference-org chainguard-private (requires access).")
    elif result.status == "ATTESTATION_FAILED":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ Attestation subject digest does NOT match image digest.")
        print(f"       A signed attestation was found but describes a different artifact.")
    elif result.status == "POLICY_VIOLATION":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ Attestation verified but provenance does not satisfy policy")
        print(f"       allowlist (see Step 6b above for the failing check).")
    elif result.status == "KEV_HIT":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ {result.kev_count} actionable CVE(s) in CISA KEV catalog —")
        print(f"       known exploited, not adjudicated by producer VEX (see Step 9).")
    elif result.status == "UPSTREAM_FAILED":
        print(f"  │  Status: {result.status}")
        print("  │")
        print(f"  └─ ✗ {result.upstream_sources_failed} upstream source(s) "
              "do NOT match the SBOM —")
        print("       SBOM claims a tag/checksum that doesn't exist upstream "
              "(see Step 12).")
    elif result.status == "PARTIAL":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ⚠ Partial: Signature found but no Rekor entry")
    else:
        print(f"  │  Status: {result.status}")
        if result.error:
            print(f"  │  Error:  {result.error}")
        print(f"  │")
        print(f"  └─ ✗ Verification failed")


def print_chain_details_full(result: VerificationResult, chain: ChainDetails):
    """Print verification chain for full mode (with reference org access)."""
    ref_image_with_digest = f"{chain.reference_image}@{chain.base_digest_full}"

    # Step 1: Extract Base Digest
    print(f"\n  ┌─ STEP 1: Extract Base Digest from Customer Image")
    print(f"  │")
    print(f"  │  Customer Image: {chain.customer_image}")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    crane config {chain.customer_image} | \\")
    print(f"  │      jq -r '.config.Labels[\"{chain.base_digest_label}\"]'")
    print(f"  │")
    if chain.base_digest_full:
        print(f"  │  Base Digest: {chain.base_digest_full}")
        print(f"  │")
        print(f"  └─ ✓ Base digest found")
    else:
        print(f"  │")
        print(f"  └─ ✗ No base digest label found")
        return

    # Step 2: Reference Org
    print(f"\n  ┌─ STEP 2: Verify Base Digest Exists in Reference Org")
    print(f"  │")
    print(f"  │  Reference Image: {ref_image_with_digest}")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    crane digest {ref_image_with_digest}")
    print(f"  │")
    if chain.reference_exists:
        print(f"  └─ ✓ Digest exists in reference org")
    else:
        print(f"  └─ ✗ Digest NOT FOUND in reference org")
        return

    # Step 3: Signature Payload
    print(f"\n  ┌─ STEP 3: Download Signature & Verify Payload Integrity")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    cosign download signature {ref_image_with_digest}")
    print(f"  │")
    print(f"  │  Decode payload to see signed digest:")
    print(f"  │    cosign download signature {ref_image_with_digest} | \\")
    print(f"  │      jq -r '.Payload' | base64 -d | jq '.critical.image'")
    print(f"  │")
    if chain.signature_found:
        print(f"  │  Signature:      Found in OCI registry")
        print(f"  │  Payload Digest: {chain.payload_digest}")
        print(f"  │")
        if chain.payload_matches:
            print(f"  └─ ✓ Payload docker-manifest-digest matches base digest")
        else:
            print(f"  └─ ✗ Payload digest does NOT match base digest (tampering?)")
    else:
        print(f"  │")
        print(f"  └─ ✗ No signature found")

    # Step 4: Rekor Entry
    print(f"\n  ┌─ STEP 4: Verify Rekor Transparency Log Entry")
    print(f"  │")
    print(f"  │  Extract logIndex from signature bundle:")
    print(f"  │    cosign download signature {ref_image_with_digest} | \\")
    print(f"  │      jq '.Bundle.Payload.logIndex'")
    print(f"  │")
    if chain.rekor_log_index:
        print(f"  │  Log Index:      {chain.rekor_log_index}")
        if chain.rekor_integrated_time:
            print(f"  │  Integrated At:  {chain.rekor_integrated_time}")
        set_badge = "✓ present in bundle" if chain.rekor_set_present else "✗ absent"
        print(f"  │  SET:            {set_badge}")
        verify_badge = (
            "✓ SET signed by Rekor public key (verified by cosign)"
            if chain.rekor_verified
            else "○ not cryptographically verified yet (see Step 5)"
        )
        print(f"  │  Rekor Verified: {verify_badge}")
        print(f"  │")
        print(f"  │  View in browser:")
        print(f"  │    {chain.rekor_url}")
        print(f"  │")
        print(f"  │  Command (fetch entry):")
        print(f"  │    rekor-cli get --log-index {chain.rekor_log_index}")
        print(f"  │")
        if chain.rekor_verified:
            print(f"  └─ ✓ Signature recorded AND cryptographically verified in Rekor")
        else:
            print(f"  └─ ⚠ Rekor entry claimed by bundle but SET not yet cryptographically verified")
    else:
        print(f"  │")
        print(f"  └─ ✗ No Rekor entry found")

    # Step 5: Certificate Verification
    print(f"\n  ┌─ STEP 5: Cryptographic Signature Verification")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    cosign verify \\")
    print(f"  │      --certificate-oidc-issuer https://token.actions.githubusercontent.com \\")
    print(f"  │      --certificate-identity-regexp '.*chainguard.*' \\")
    print(f"  │      {ref_image_with_digest}")
    print(f"  │")
    if chain.cert_verified:
        print(f"  │  OIDC Issuer: {chain.cert_issuer or 'https://token.actions.githubusercontent.com'}")
        if chain.cert_subject:
            print(f"  │  Subject:     {chain.cert_subject}")
        if chain.github_workflow_ref:
            print(f"  │  Workflow Ref:  {chain.github_workflow_ref}")
        if chain.github_workflow_sha:
            print(f"  │  Commit SHA:    {chain.github_workflow_sha}")
        if chain.github_workflow_trigger:
            print(f"  │  Trigger:       {chain.github_workflow_trigger}")
        if chain.github_workflow_run_id:
            print(f"  │  Run ID:        {chain.github_workflow_run_id}")
        print(f"  │")
        print(f"  └─ ✓ Signature cryptographically verified as Chainguard-signed")
    else:
        if result.sig_status == "INVALID":
            print(f"  │")
            print(f"  └─ ✗ Signature verification FAILED")
        else:
            print(f"  │")
            print(f"  └─ ○ Signature verification skipped (use --verify-signatures)")

    # Step 6 (optional): SLSA provenance attestation
    _print_slsa_step(result, chain)

    # Final verdict
    print(f"\n  ┌─ VERIFICATION RESULT")
    print(f"  │")
    if result.status == "VERIFIED":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✓ Base image verified: exists in reference org, signed by")
        print(f"       Chainguard, and recorded in public transparency log.")
    elif result.status == "ATTESTATION_FAILED":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ Attestation subject digest does NOT match image digest.")
        print(f"       A signed attestation was found but describes a different artifact.")
    elif result.status == "POLICY_VIOLATION":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ Attestation verified but provenance does not satisfy policy")
        print(f"       allowlist (see Step 6b above for the failing check).")
    elif result.status == "KEV_HIT":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✗ {result.kev_count} actionable CVE(s) in CISA KEV catalog —")
        print(f"       known exploited, not adjudicated by producer VEX (see Step 9).")
    elif result.status == "UPSTREAM_FAILED":
        print(f"  │  Status: {result.status}")
        print("  │")
        print(f"  └─ ✗ {result.upstream_sources_failed} upstream source(s) "
              "do NOT match the SBOM —")
        print("       SBOM claims a tag/checksum that doesn't exist upstream "
              "(see Step 12).")
    elif result.status == "PARTIAL":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ⚠ Partial: Image exists in reference but no Rekor entry")
    else:
        print(f"  │  Status: {result.status}")
        if result.error:
            print(f"  │  Error:  {result.error}")
        print(f"  │")
        print(f"  └─ ✗ Verification failed")


def _print_slsa_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print the SLSA provenance attestation step when attestations are enabled.

    Silent (no-op) when attestations weren't requested for this image, so
    existing behaviour and output of `verify_provenance.py image --customer-org X`
    (without the new flag) is byte-for-byte unchanged.
    """
    from attestation import PREDICATE_SLSA_V1

    rec = chain.attestations.get(PREDICATE_SLSA_V1)
    if rec is None:
        return

    print(f"\n  ┌─ STEP 6: Verify SLSA v1.0 Provenance Attestation")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    {rec.cosign_command}")
    print(f"  │")

    if not rec.verified:
        print(f"  │  Result: ATTESTATION NOT FOUND OR NOT VERIFIED")
        if rec.error:
            print(f"  │  Detail: {rec.error}")
        print(f"  │")
        print(f"  └─ ○ No verified SLSA provenance attached (status: {result.slsa_status})")
        return

    if not rec.subject_matches:
        print(f"  │  Signature:       Valid (Chainguard-signed)")
        print(f"  │  Subject Match:   FAILED — attestation describes a different digest")
        if rec.subject_digests:
            print(f"  │  Observed digest: sha256:{rec.subject_digests[0]}")
        print(f"  │")
        print(f"  └─ ✗ Attestation subject digest does NOT match image — NOT TRUSTED")
        return

    prov = rec.slsa
    print(f"  │  Signature:       Valid (Chainguard-signed)")
    print(f"  │  Subject Match:   ✓ in-toto subject digest matches image digest")
    # cosign verify-attestation's default flow validates the Rekor SET
    # against Rekor's public key; a successful `verified` implies that.
    print(f"  │  Rekor SET:       ✓ verified against Rekor public key (by cosign)")
    if prov:
        if prov.builder_id:
            print(f"  │  Builder:         {prov.builder_id}")
        if prov.build_type:
            print(f"  │  Build Type:      {prov.build_type}")
        if prov.source_uri:
            print(f"  │  Source:          {prov.source_uri}")
        if prov.source_digest:
            for algo, val in prov.source_digest.items():
                print(f"  │  Source {algo}:    {val}")
        if prov.started_on:
            print(f"  │  Built At:        {prov.started_on}")
        if prov.invocation_id:
            print(f"  │  Invocation:      {prov.invocation_id}")
        if prov.resolved_dependency_count:
            print(f"  │  Dependencies:    {prov.resolved_dependency_count} resolved")
    print(f"  │")
    print(f"  └─ ✓ SLSA v1.0 provenance verified and bound to this image digest")

    # Step 6b: Policy evaluation (if attestations ran)
    _print_policy_step(result, chain)

    # Step 7: SBOM attestation (if fetched alongside SLSA)
    _print_sbom_step(result, chain)

    # Step 8: Vulnerability scan (if --scan)
    _print_scan_step(result, chain)

    # Step 9: KEV cross-check (piggybacks on --scan)
    _print_kev_step(result, chain)

    # Step 10: Freshness + EOL + FIPS posture
    _print_freshness_step(result, chain)

    # Step 12: Upstream-source verification (if --verify-upstream-sources)
    _print_upstream_step(result, chain)


def _format_kev_hits(hits: list[object]) -> str:
    """Compact CSV-safe summary: `CVE-2023-1234(due=2023-04-01); CVE-...`."""
    from kev import KevEntry

    parts = []
    for h in hits:
        if not isinstance(h, KevEntry):
            continue
        due = f"(due={h.due_date})" if h.due_date else ""
        parts.append(f"{h.cve_id}{due}")
    return "; ".join(parts)


def _format_upstream_failures(summary: "object | None") -> str:
    """Compact CSV-safe summary of FAILED upstream sources.

    Format: `glibc-2.43-r2(commit mismatch); openssl-3.6.1-r2(...); …`.
    Only FAILED entries are listed — VERIFIED is silent, SKIP/ERROR are
    aggregated into the count columns.
    """
    from upstream import UpstreamSummary

    if not isinstance(summary, UpstreamSummary):
        return ""
    parts = [
        f"{r.label}({r.detail})" for r in summary.results if r.status == "FAILED"
    ]
    return "; ".join(parts)


def _format_policy_violations(violations: list["PolicyViolation"]) -> str:
    """Flatten policy violations into a single CSV-safe string.

    Each violation becomes `check=<observed>`; multiple joined by `; `.
    Designed for humans grepping the CSV — not a replacement for structured
    machine-readable output, which P1-5 evidence bundle will provide.
    """
    if not violations:
        return ""
    return "; ".join(
        f"{v.check}={v.observed}" if v.observed else f"{v.check}=(empty)"
        for v in violations
    )


def _print_policy_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Show builder.id / source_uri allowlist results against the SLSA predicate."""
    if result.policy_status == "N/A":
        return
    print(f"\n  ┌─ STEP 6b: Evaluate Policy Allowlists Against SLSA Provenance")
    print(f"  │")
    if result.policy_status == "PASS":
        print(f"  │  Result: ✓ Builder identity and source URI match allowlist")
        print(f"  │")
        print(f"  └─ ✓ Policy satisfied")
        return

    print(f"  │  Result: ✗ POLICY VIOLATION — attestation verified but builder")
    print(f"  │          or source does not match allowlist")
    for v in chain.policy_violations:
        print(f"  │")
        print(f"  │  Check:    {v.check}")
        print(f"  │  Observed: {v.observed or '(empty)'}")
        print(f"  │  Allowed:  {v.expected_patterns[0]}")
        for pat in v.expected_patterns[1:]:
            print(f"  │            {pat}")
    print(f"  │")
    print(f"  └─ ✗ One or more policy checks failed — image NOT trusted under policy")


def _print_sbom_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print the SBOM attestation step. Chooses SPDX or CycloneDX
    depending on which one verified; prints both if neither did, so the
    auditor can see what was attempted.
    """
    from attestation import PREDICATE_CYCLONEDX, PREDICATE_SPDX

    spdx_rec = chain.attestations.get(PREDICATE_SPDX)
    cyclo_rec = chain.attestations.get(PREDICATE_CYCLONEDX)
    if spdx_rec is None and cyclo_rec is None:
        return

    # Pick the successful record if one exists; otherwise show SPDX as the
    # "primary" attempt since that's what Chainguard publishes on every image.
    primary = None
    if spdx_rec and spdx_rec.verified and spdx_rec.subject_matches:
        primary = spdx_rec
    elif cyclo_rec and cyclo_rec.verified and cyclo_rec.subject_matches:
        primary = cyclo_rec
    else:
        primary = spdx_rec or cyclo_rec

    assert primary is not None  # both None handled above
    label = "SPDX" if primary.predicate_type == PREDICATE_SPDX else "CycloneDX"

    print(f"\n  ┌─ STEP 7: Verify {label} SBOM Attestation")
    print(f"  │")
    print(f"  │  Command:")
    print(f"  │    {primary.cosign_command}")
    print(f"  │")

    if not primary.verified:
        print(f"  │  Result: SBOM ATTESTATION NOT FOUND OR NOT VERIFIED")
        if primary.error:
            print(f"  │  Detail: {primary.error}")
        print(f"  │")
        print(f"  └─ ○ No verified SBOM attached (status: {result.sbom_status})")
        return

    if not primary.subject_matches:
        print(f"  │  Signature:       Valid (Chainguard-signed)")
        print(f"  │  Subject Match:   FAILED — SBOM describes a different digest")
        print(f"  │")
        print(f"  └─ ✗ SBOM subject digest does NOT match image — NOT TRUSTED")
        return

    sbom = primary.sbom
    print(f"  │  Signature:       Valid (Chainguard-signed)")
    print(f"  │  Subject Match:   ✓ in-toto subject digest matches image digest")
    print(f"  │  Rekor SET:       ✓ verified against Rekor public key (by cosign)")
    if sbom:
        print(f"  │  Format:          {sbom.sbom_format.upper()} {sbom.spec_version}")
        if sbom.document_name:
            print(f"  │  Document:        {sbom.document_name}")
        print(f"  │  Packages:        {sbom.package_count}")
        if sbom.unique_licenses:
            licenses_display = ", ".join(sbom.unique_licenses[:6])
            if len(sbom.unique_licenses) > 6:
                licenses_display += f", … (+{len(sbom.unique_licenses) - 6} more)"
            print(f"  │  Licenses:        {licenses_display}")
        if sbom.purl_sample:
            print(f"  │  Sample PURLs:    {sbom.purl_sample[0]}")
            for p in sbom.purl_sample[1:3]:
                print(f"  │                   {p}")
            if len(sbom.purl_sample) > 3 or sbom.package_count > 3:
                print(f"  │                   … ({sbom.package_count} total)")
        if sbom.is_empty:
            print(f"  │")
            print(f"  └─ ⚠ SBOM signed and bound to image but contains zero packages — EMPTY")
            return
    print(f"  │")
    print(f"  └─ ✓ SBOM verified and bound to this image digest")


def _print_scan_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print grype scan + VEX adjudication results."""
    if result.vuln_status == "N/A":
        return
    from scan import ScanResult

    scan_result = chain.scan_result if isinstance(chain.scan_result, ScanResult) else None
    print(f"\n  ┌─ STEP 8: Vulnerability Scan (grype) + OpenVEX Adjudication")
    print(f"  │")
    if scan_result is None or not scan_result.success:
        err = scan_result.error if scan_result else "scan did not run"
        print(f"  │  Result: ERROR")
        print(f"  │  Detail: {err}")
        print(f"  │")
        print(f"  └─ ✗ Scan failed — no vulnerability data available")
        return

    print(f"  │  Scanner:  grype {scan_result.scanner_version or '(version unknown)'}")
    print(f"  │  Command:  {scan_result.grype_command}")
    print(f"  │")
    raw = scan_result.raw_counts
    ac = scan_result.actionable_counts
    print(f"  │  RAW findings (pre-VEX, audit record):")
    print(
        f"  │    critical={raw.critical}  high={raw.high}  "
        f"medium={raw.medium}  low={raw.low}  total={raw.total()}"
    )
    print(f"  │")
    if scan_result.vex_applied:
        print(f"  │  ACTIONABLE (after Chainguard OpenVEX adjudication):")
        print(
            f"  │    critical={ac.critical}  high={ac.high}  "
            f"medium={ac.medium}  low={ac.low}  total={ac.total()}"
        )
        suppressed = raw.total() - ac.total()
        print(f"  │  VEX suppressed {suppressed} finding(s)")
    else:
        print(f"  │  VEX: not applied (no signed OpenVEX attestation available)")
        print(f"  │  Actionable counts = raw counts.")
    if scan_result.top_cves:
        print(f"  │")
        print(f"  │  First {len(scan_result.top_cves)} CVE(s): {', '.join(scan_result.top_cves[:5])}")
        if len(scan_result.top_cves) > 5:
            print(f"  │                        {', '.join(scan_result.top_cves[5:])}")
    print(f"  │")
    if result.vuln_status == "CLEAN":
        print(f"  └─ ✓ No actionable vulnerabilities")
    else:
        print(f"  └─ ⚠ {result.vuln_total} actionable vulnerability(ies) — review required")


def _print_freshness_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print image freshness + EOL posture + FIPS variant detection."""
    # Only render when we have something meaningful to say.
    if (
        result.freshness_status == "N/A"
        and not result.fips_variant
        and chain.image_age_days < 0
    ):
        return
    print(f"\n  ┌─ STEP 10: Image Freshness / End-of-Life / FIPS Posture")
    print(f"  │")
    if chain.image_created:
        print(f"  │  Build Timestamp: {chain.image_created}")
    if chain.image_age_days >= 0:
        print(f"  │  Age:             {chain.image_age_days} day(s)")
    badge = {
        "FRESH": "✓ within freshness threshold",
        "STALE": "⚠ older than --max-age-days threshold",
        "EOL": "⚠ Chainguard EOL attestation present (in grace period)",
        "N/A": "○ freshness not evaluated",
    }.get(result.freshness_status, result.freshness_status)
    print(f"  │  Freshness:       {badge}")
    if result.fips_variant:
        print(f"  │  FIPS Variant:    ✓ detected ({result.fips_reason})")
        print(f"  │                    Verify CMVP cert on the NIST Active list manually.")
    print(f"  │")
    if result.freshness_status == "EOL":
        print(f"  └─ ⚠ Image flagged EOL by Chainguard — plan migration before grace period ends")
    elif result.freshness_status == "STALE":
        print(f"  └─ ⚠ Image exceeds configured freshness threshold")
    else:
        print(f"  └─ ✓ Freshness + FIPS posture recorded")


def _print_upstream_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print --verify-upstream-sources results.

    Emits a sourcier-style tree: one line per source with a status badge,
    grouped by source_type. Long fleets won't want all this — use the
    summary table for compact output. Verbose chain mode is opt-in already.
    """
    if result.upstream_sources_status == "N/A":
        return
    from upstream import UpstreamSummary

    summary = (
        chain.upstream_summary
        if isinstance(chain.upstream_summary, UpstreamSummary)
        else None
    )
    print("\n  ┌─ STEP 12: Verify Upstream Sources Against SBOM Claims")
    print("  │")
    if summary is None or summary.total == 0:
        print("  │  Result: no source coordinates found in SBOM")
        print("  │")
        print("  └─ ○ Nothing to verify (SBOM has no relationship/purl edges)")
        return
    countable = summary.total - summary.skipped
    print(f"  │  Sources walked: {summary.total}  "
          f"(verified={summary.verified}, failed={summary.failed}, "
          f"errors={summary.errors}, skipped={summary.skipped})")
    if summary.cache_hits:
        print(f"  │  Cache hits:     {summary.cache_hits} "
              "(reused upstream lookups across images)")
    print("  │")
    badge = {
        "VERIFIED": "✓",
        "FAILED": "✗",
        "ERROR": "?",
        "SKIP": "-",
    }
    shown = 0
    for r in summary.results:
        if r.status == "VERIFIED" and shown >= 5 and summary.failed:
            # When there are failures, prioritise showing them. Cap successful
            # entries at 5 so a 25-source image isn't a wall of green.
            continue
        if shown >= 12:
            break
        shown += 1
        b = badge.get(r.status, "?")
        line = f"  │  {b} {r.label}"
        if r.url:
            line += f" — {r.url}"
        print(line)
        if r.detail:
            print(f"  │      {r.detail}")
    if shown < summary.total:
        print(f"  │  … plus {summary.total - shown} more (see CSV / evidence bundle)")
    print("  │")
    if result.upstream_sources_status == "FAILED":
        print(f"  └─ ✗ {summary.failed} of {countable} upstream source(s) "
              "do NOT match the SBOM claim — image NOT trusted")
    elif result.upstream_sources_status == "ERROR":
        print("  └─ ⚠ Upstream verification could not complete "
              "(transient errors); not demoting verdict")
    else:
        print(f"  └─ ✓ All {summary.verified} verifiable upstream source(s) match")


def _print_kev_step(result: VerificationResult, chain: ChainDetails) -> None:
    """Pretty-print CISA KEV cross-check results."""
    if result.kev_status == "N/A":
        return
    from kev import KevEntry

    print(f"\n  ┌─ STEP 9: Cross-Check Actionable CVEs Against CISA KEV Catalog")
    print(f"  │")
    if result.kev_status == "CLEAN":
        print(f"  │  Result: ✓ No actionable CVE appears in the KEV catalog")
        print(f"  │")
        print(f"  └─ ✓ No known-exploited vulnerabilities unadjudicated")
        return

    print(f"  │  Result: ✗ {result.kev_count} actionable CVE(s) are in the KEV catalog")
    print(f"  │          (known exploited, not suppressed by producer VEX)")
    shown = 0
    for h in chain.kev_hits:
        if not isinstance(h, KevEntry):
            continue
        shown += 1
        if shown > 5:
            break
        print(f"  │")
        print(f"  │  {h.cve_id}  —  {h.vulnerability_name or 'unnamed'}")
        if h.vendor_project or h.product:
            print(f"  │    Vendor/Product: {h.vendor_project} / {h.product}")
        if h.date_added:
            print(f"  │    KEV since:   {h.date_added}")
        if h.due_date:
            print(f"  │    BOD 22-01 due: {h.due_date}")
        if h.known_ransomware_use and h.known_ransomware_use.lower() != "unknown":
            print(f"  │    Ransomware:   {h.known_ransomware_use}")
    if result.kev_count > 5:
        print(f"  │")
        print(f"  │  … plus {result.kev_count - 5} more KEV hit(s); see CSV for full list")
    print(f"  │")
    print(f"  └─ ✗ Hard-fail per BOD 22-01 guidance — remediation required")


def _build_image_subparser(subparsers: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    p = subparsers.add_parser(
        "image",
        help="Verify Chainguard OCI images (customer delivery / full build chain)",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --customer-org my-org
      Verify delivery signatures for all images in my-org

  %(prog)s --customer-org my-org --full
      Full verification including base image in chainguard-private

  %(prog)s --customer-org my-org --limit 5 --verify-signatures
      Check first 5 images with full cryptographic verification
""",
    )
    p.add_argument("--customer-org",
                   help="Customer organization to verify (required unless --version)")
    p.add_argument("--full", action="store_true",
                   help="Run every verification check: base digest exists in "
                        "chainguard-private, base image signed by Chainguard's build "
                        "system, all signed attestations (SLSA, SBOM, apko, EOL) "
                        "retrieved and in-toto-subject-matched, policy allowlists "
                        "evaluated, freshness/FIPS surfaced. Implies both "
                        "--verify-signatures and --verify-attestations. Does NOT "
                        "imply --scan (vulnerability scanning is opt-in).")
    p.add_argument("--verify-signatures", action="store_true",
                   help="Enable full cryptographic signature verification")
    p.add_argument("--verify-attestations", action="store_true",
                   help="Additionally fetch and verify Chainguard-signed "
                        "attestations attached to the image (currently: SLSA v1.0 "
                        "provenance). Asserts the in-toto subject digest matches "
                        "the image being verified.")
    p.add_argument("--policy-file",
                   help="Path to a JSON policy file overriding the default allowed "
                        "OIDC issuer / signer identity / SLSA builder.id / source-repo "
                        "regexes. See README for schema. Defaults preserve current "
                        "hardcoded Chainguard values.")
    p.add_argument("--scan", action="store_true",
                   help="Run grype vulnerability scan against each image and, when "
                        "a Chainguard-published OpenVEX attestation is available, "
                        "apply it to compute an actionable CVE count. Implies "
                        "--verify-attestations (needed to fetch the VEX doc). "
                        "Requires grype in PATH.")
    p.add_argument("--max-age-days", type=int, default=0,
                   help="If > 0, flag images older than this many days as STALE. "
                        "Chainguard's EOL attestation (when present) always produces "
                        "an EOL status regardless of this threshold.")
    p.add_argument("--trusted-root",
                   help="Path to a Sigstore TUF trusted_root.json. Enables offline / "
                        "air-gapped verification: cosign reads Fulcio + Rekor roots "
                        "from this file instead of the network.")
    p.add_argument("--evidence-bundle",
                   help="Write per-image evidence (attestation envelopes, SBOM, "
                        "scan output, KEV hits, policy eval, control mapping, "
                        "Markdown summary, SHA256SUMS seal) to this directory. "
                        "Existing contents are preserved; each image gets its own "
                        "subdirectory.")
    p.add_argument("--sbom-drift", action="store_true",
                   help="Run syft against each image, diff the generated PURL set "
                        "against the attested SBOM. Catches registry-side SBOM-attestation "
                        "swaps. Implies --verify-attestations. Requires syft in PATH.")
    p.add_argument("--verify-upstream-sources", action="store_true",
                   help="Walk the verified SPDX SBOM and confirm every upstream "
                        "source matches: git-tag→commit via `git ls-remote`, "
                        "tarball checksums via streaming hash. Catches forged "
                        "SBOMs whose package coordinates do not exist upstream. "
                        "Implies --verify-attestations. Network-heavy "
                        "(~25-50 RTTs/image); requires `git` in PATH. Cannot "
                        "be used with --trusted-root (the check is "
                        "fundamentally network-dependent).")
    p.add_argument("-v", "--verbose", action="store_true",
                   help="Print the full per-image verification chain "
                        "(Step 1..10) for every image. Default output is just "
                        "a summary table with one row per image.")
    p.add_argument("--csv-output",
                   help="Write the full verification CSV to this path. When "
                        "unset, no file is written (use `--format csv` to pipe "
                        "the summary to stdout instead).")
    p.add_argument("--format", choices=["table", "json", "csv"], default="table",
                   help="End-of-run summary format. `table` is human-readable; "
                        "`json` and `csv` route banner/progress to stderr so "
                        "stdout can be piped to jq / further tooling. The "
                        "per-customer CSV file on disk is always written "
                        "regardless of this choice.")
    p.add_argument("--limit", type=int, default=0,
                   help="Limit number of images to check (0 = all)")
    p.add_argument("--version", action="store_true",
                   help="Show version and dependency information")


def run_image_mode(args: argparse.Namespace) -> None:
    # --full means "run every verification check we have": signature,
    # Rekor SET, SLSA provenance, SBOM, policy allowlists, freshness/EOL,
    # FIPS detection, apko config. It intentionally does NOT imply --scan,
    # because vulnerability scanning is a separate concern (risk posture,
    # not authenticity) and grype takes minutes per image.
    if args.full:
        args.verify_signatures = True
        args.verify_attestations = True
    # --scan implies --verify-attestations (we need to pull OpenVEX).
    # --sbom-drift also needs the attested SBOM to diff against.
    # --verify-upstream-sources walks the SPDX SBOM, so it likewise requires
    # a cryptographically verified SBOM upfront.
    if args.scan or args.sbom_drift or args.verify_upstream_sources:
        args.verify_attestations = True

    # Route banner + progress to stderr when stdout is reserved for
    # machine-readable output. Keeps `verify-provenance image ... --format json
    # | jq .` clean.
    meta_stream = sys.stderr if args.format in ("json", "csv") else sys.stdout

    def _meta(line: str = "") -> None:
        print(line, file=meta_stream)

    # Handle --version flag
    if args.version:
        print_version()
        sys.exit(0)

    # Require --customer-org if not --version
    if not args.customer_org:
        print("Error: --customer-org is required", file=sys.stderr)
        sys.exit(2)

    # Check dependencies
    missing = check_dependencies()
    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("See PREREQUISITES.md for installation instructions.", file=sys.stderr)
        sys.exit(1)

    registry = "cgr.dev"
    reference_org = "chainguard-private"

    # Determine mode
    customer_only = not args.full

    # Check auth
    success, _, _ = run_cmd(["chainctl", "auth", "status"], timeout=10)
    if not success:
        print("Error: Not authenticated. Run 'chainctl auth login'", file=sys.stderr)
        sys.exit(1)

    # Load policy (defaults if no --policy-file). Fail closed on a malformed file.
    from policy import (
        PolicyError,
        default_build_policy,
        default_customer_policy,
        load_policy_file,
    )
    if args.policy_file:
        try:
            customer_policy, build_policy = load_policy_file(args.policy_file)
        except PolicyError as e:
            print(f"Error loading policy file: {e}", file=sys.stderr)
            sys.exit(2)
        policy_source = args.policy_file
    else:
        customer_policy = default_customer_policy()
        build_policy = default_build_policy()
        policy_source = "(defaults)"

    # Header
    mode_desc = "DELIVERY VERIFICATION" if customer_only else "FULL VERIFICATION"
    title = f"Chainguard Image   {mode_desc}"
    _meta("╔══════════════════════════════════════════════════════════════════════════════╗")
    _meta(f"║{title:^78}║")
    _meta("╠══════════════════════════════════════════════════════════════════════════════╣")
    _meta(f"║  Customer Org:     {args.customer_org:<58}║")
    if not customer_only:
        _meta(f"║  Reference Org:    {reference_org:<58}║")
    _meta(f"║  Signature Verify: {str(args.verify_signatures):<58}║")
    _meta(f"║  Attestations:     {str(args.verify_attestations):<58}║")
    _meta(f"║  Policy:           {policy_source:<58}║")
    _meta(f"║  Vuln Scan:        {str(args.scan):<58}║")
    _meta("╚══════════════════════════════════════════════════════════════════════════════╝")
    _meta()

    # If --scan was requested, check grype is on PATH now — fail fast rather
    # than producing partial results for half the fleet.
    if args.scan:
        from scan import grype_installed
        if not grype_installed():
            print("Error: --scan requires grype in PATH. See PREREQUISITES.md",
                  file=sys.stderr)
            sys.exit(1)

    # --verify-upstream-sources needs `git` for `git ls-remote`. It also can't
    # coexist with --trusted-root (the upstream check is network-dependent
    # by design — there's no air-gapped equivalent of "ask github for this
    # tag's commit").
    upstream_cache: "dict[tuple[str, str], UpstreamVerifyResult] | None" = None
    upstream_github_token: str = ""
    if args.verify_upstream_sources:
        from upstream import git_installed, github_token

        if not git_installed():
            print("Error: --verify-upstream-sources requires git in PATH. "
                  "See PREREQUISITES.md", file=sys.stderr)
            sys.exit(1)
        if args.trusted_root:
            print("Error: --verify-upstream-sources is incompatible with "
                  "--trusted-root (the upstream check needs the public "
                  "internet)", file=sys.stderr)
            sys.exit(2)
        # One cache shared across every image in the run; many APK packages
        # are common across the fleet (glibc, openssl, ncurses) so the
        # cache typically saves dozens of round-trips per run.
        upstream_cache = {}
        upstream_github_token = github_token()

    # Load CISA KEV catalog once per run; every per-image scan reuses it.
    # Failing to load isn't fatal — we continue with no KEV data and the
    # kev_status field stays "N/A" per image.
    kev_catalog = None
    if args.scan:
        from kev import load_kev_catalog
        kev_catalog = load_kev_catalog()
        if kev_catalog.is_empty():
            print(f"Warning: KEV catalog unavailable ({kev_catalog.source_note}); "
                  "KEV cross-check will be skipped.", file=sys.stderr)
        else:
            _meta(f"KEV catalog: {kev_catalog.total_count} entries "
                  f"({kev_catalog.source_note})")

    # Get images
    _meta(f"Fetching entitled images for '{args.customer_org}'...")
    images = get_image_list(args.customer_org)

    if not images:
        print("Error: Could not retrieve image list", file=sys.stderr)
        sys.exit(1)

    _meta(f"Found {len(images)} images")

    if args.limit > 0:
        images = images[: args.limit]
        _meta(f"Limited to first {args.limit} images")

    # Verify images sequentially. Verbose mode prints the full per-image chain;
    # default mode prints a terse one-line progress indicator per image and
    # defers the human-readable output to the end-of-run summary table.
    _meta("\nVerifying images...")
    results: list[VerificationResult] = []
    for i, img in enumerate(images, 1):
        result = verify_image(
            img, registry, args.customer_org, reference_org,
            args.verify_signatures, capture_details=True,
            customer_only=customer_only,
            verify_attestations=args.verify_attestations,
            customer_policy=customer_policy,
            build_policy=build_policy,
            scan=args.scan,
            kev_catalog=kev_catalog,
            max_age_days=args.max_age_days,
            trusted_root=args.trusted_root,
            sbom_drift_enabled=args.sbom_drift,
            verify_upstream_sources=args.verify_upstream_sources,
            upstream_cache=upstream_cache,
            upstream_github_token=upstream_github_token,
        )
        results.append(result)
        if args.verbose:
            print_chain_details(result, i, customer_only=customer_only)
        else:
            # Terse one-line progress per image so long runs don't look hung.
            _meta(f"  [{i}/{len(images)}] {result.image:<40} {result.status}")

        if args.evidence_bundle:
            from evidence import write_evidence_bundle
            from pathlib import Path as _Path
            try:
                write_evidence_bundle(
                    bundle_root=_Path(args.evidence_bundle),
                    result=result,
                    tool_version=__version__,
                    customer_org=args.customer_org,
                    mode="full" if not customer_only else "delivery",
                    policy_source=policy_source,
                )
            except OSError as e:
                print(f"Warning: evidence bundle write failed for {result.image}: {e}",
                      file=sys.stderr)

    # Sort by image name
    results.sort(key=lambda r: r.image)

    # Write CSV only when --csv-output is set. Column groups are dropped
    # when the corresponding check didn't run — otherwise a 0 in vuln_total
    # misreads as "clean" when the scan was never done.
    csv_file: str | None = args.csv_output
    if csv_file:
        _write_on_disk_csv(
            csv_file, results, customer_only,
            attestations_on=bool(args.verify_attestations),
            scan_on=bool(args.scan),
            upstream_on=bool(args.verify_upstream_sources),
        )

    # Count results
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    # Which check groups actually ran this invocation — drives dynamic
    # column inclusion in every format so readers never see a 0 that's
    # really "not checked".
    attestations_on = bool(args.verify_attestations)
    scan_on = bool(args.scan)
    upstream_on = bool(args.verify_upstream_sources)

    # Emit the summary in the requested format BEFORE the fleet-wide counts
    # block. JSON/CSV callers typically don't want the decorative counts.
    if args.format == "json":
        print(_render_summary_json(results, args, customer_only, reference_org,
                                   csv_file, counts))
        # Skip the rest of the decorative output.
        sys.exit(_compute_exit_status(results, counts, customer_only))
    elif args.format == "csv":
        print(_render_summary_csv(results, customer_only,
                                  attestations_on=attestations_on,
                                  scan_on=scan_on,
                                  upstream_on=upstream_on))
        sys.exit(_compute_exit_status(results, counts, customer_only))

    # Per-image summary table (always rendered in table mode).
    print()
    print(_render_summary_table(results,
                                attestations_on=attestations_on,
                                scan_on=scan_on,
                                upstream_on=upstream_on))

    # Fleet-wide counts
    print()
    print("═" * 80)
    print("  SUMMARY")
    print("═" * 80)
    print(f"  Customer Org:       {args.customer_org}")
    if not customer_only:
        print(f"  Reference Org:      {reference_org}")
    print(f"  Mode:               {'Delivery Verification' if customer_only else 'Full Verification'}")
    print(f"  Total Checked:      {len(results)}")
    print()

    if customer_only:
        print(f"  Delivery Verified:  {counts.get('DELIVERY_VERIFIED', 0)}  (signed by Chainguard + in Rekor)")
        print(f"  No Signature:       {counts.get('NO_SIG', 0)}")
        print(f"  Partial:            {counts.get('PARTIAL', 0)}")
        print(f"  No Base Digest:     {counts.get('NO_BASE', 0)}")
        print(f"  Errors:             {counts.get('ERROR', 0)}")
    else:
        print(f"  Verified:           {counts.get('VERIFIED', 0)}  (in reference + Rekor)")
        print(f"  Partial:            {counts.get('PARTIAL', 0)}   (in reference only)")
        print(f"  Not Found:          {counts.get('NOT_FOUND', 0)}")
        print(f"  No Base Digest:     {counts.get('NO_BASE', 0)}")
        print(f"  Errors:             {counts.get('ERROR', 0)}")

    if args.verify_attestations:
        slsa_counts: dict[str, int] = {}
        sbom_counts: dict[str, int] = {}
        for r in results:
            slsa_counts[r.slsa_status] = slsa_counts.get(r.slsa_status, 0) + 1
            sbom_counts[r.sbom_status] = sbom_counts.get(r.sbom_status, 0) + 1
        print()
        print(f"  SLSA Verified:      {slsa_counts.get('VERIFIED', 0)}  "
              f"(signed provenance, subject digest matches image)")
        if slsa_counts.get('SUBJECT_MISMATCH', 0):
            print(f"  SLSA Mismatch:      {slsa_counts['SUBJECT_MISMATCH']}  "
                  f"(signed but describes different digest — REJECTED)")
        if slsa_counts.get('NOT_FOUND', 0):
            print(f"  SLSA Not Found:     {slsa_counts['NOT_FOUND']}")
        if slsa_counts.get('UNVERIFIED', 0):
            print(f"  SLSA Unverified:    {slsa_counts['UNVERIFIED']}")

        print(f"  SBOM Verified:      {sbom_counts.get('VERIFIED', 0)}  "
              f"(signed SBOM, subject digest matches image)")
        if sbom_counts.get('SUBJECT_MISMATCH', 0):
            print(f"  SBOM Mismatch:      {sbom_counts['SUBJECT_MISMATCH']}  "
                  f"(signed but describes different digest — REJECTED)")
        if sbom_counts.get('EMPTY', 0):
            print(f"  SBOM Empty:         {sbom_counts['EMPTY']}  "
                  f"(signed but contains zero packages)")
        if sbom_counts.get('NOT_FOUND', 0):
            print(f"  SBOM Not Found:     {sbom_counts['NOT_FOUND']}")
        if sbom_counts.get('UNVERIFIED', 0):
            print(f"  SBOM Unverified:    {sbom_counts['UNVERIFIED']}")

        policy_counts: dict[str, int] = {}
        for r in results:
            policy_counts[r.policy_status] = policy_counts.get(r.policy_status, 0) + 1
        print(f"  Policy Pass:        {policy_counts.get('PASS', 0)}  "
              f"(builder.id + source URI on allowlist)")
        if policy_counts.get('VIOLATION', 0):
            print(f"  Policy Violation:   {policy_counts['VIOLATION']}  "
                  f"(attestation verified but provenance off-allowlist — REJECTED)")

    if args.verify_upstream_sources:
        upstream_total = sum(r.upstream_sources_total for r in results)
        upstream_verified = sum(r.upstream_sources_verified for r in results)
        upstream_failed = sum(r.upstream_sources_failed for r in results)
        upstream_errors = sum(r.upstream_sources_errors for r in results)
        failed_images = sum(
            1 for r in results if r.upstream_sources_status == "FAILED"
        )
        print()
        print(f"  Upstream Verified:  {upstream_verified}/{upstream_total} sources "
              f"({failed_images} image(s) with at least one FAILED upstream)")
        if upstream_errors:
            print(f"  Upstream Errors:    {upstream_errors} sources "
                  "(transient network/auth — verdict not demoted)")
        if upstream_failed:
            print(f"  Upstream Failed:    {upstream_failed}  "
                  "(SBOM upstream claims do NOT match remote — REJECTED)")

    if args.scan:
        # Aggregate VEX-adjusted (actionable) counts across the fleet.
        total_crit = sum(r.vuln_critical for r in results)
        total_high = sum(r.vuln_high for r in results)
        total_med = sum(r.vuln_medium for r in results)
        total_low = sum(r.vuln_low for r in results)
        clean = sum(1 for r in results if r.vuln_status == "CLEAN")
        with_findings = sum(1 for r in results if r.vuln_status == "FINDINGS")
        scan_errors = sum(1 for r in results if r.vuln_status == "ERROR")
        vex_used = sum(1 for r in results if r.vex_applied)
        kev_hit_images = sum(1 for r in results if r.kev_status == "HIT")
        total_kev_hits = sum(r.kev_count for r in results)
        print()
        print(f"  Scan Clean:         {clean}  (no actionable vulnerabilities)")
        print(f"  Scan Findings:      {with_findings}  "
              f"(actionable: C={total_crit} H={total_high} M={total_med} L={total_low})")
        if scan_errors:
            print(f"  Scan Errors:        {scan_errors}")
        print(f"  VEX Applied:        {vex_used}  (images with signed OpenVEX adjudication)")
        if kev_hit_images:
            print(f"  KEV Hit Images:     {kev_hit_images}  "
                  f"({total_kev_hits} unadjudicated KEV-cataloged CVE(s) across fleet — REJECTED)")
        else:
            print(f"  KEV Hit Images:     0  (no unadjudicated KEV-cataloged CVEs)")

    print()
    if csv_file:
        print(f"  CSV Output:         {csv_file}")
    print("═" * 80)

    if customer_only:
        print("\n  NOTE: To compare images across customers, share the base_digest")
        print("        column from the CSV. Matching base_digest = same source image.")

    # Exit status
    if not customer_only and counts.get("NOT_FOUND", 0) > 0:
        print(f"\nWARNING: Some images not found in '{reference_org}'")
        sys.exit(1)

    if counts.get("PARTIAL", 0) > 0:
        print("\nWARNING: Some images have no Rekor entries")

    verified_count = counts.get("DELIVERY_VERIFIED", 0) if customer_only else counts.get("VERIFIED", 0)
    if verified_count == len(results) and len(results) > 0:
        print("\n✓ ALL IMAGES VERIFIED")


def _write_on_disk_csv(
    csv_file: str,
    results: list[VerificationResult],
    customer_only: bool,
    attestations_on: bool,
    scan_on: bool,
    upstream_on: bool = False,
) -> None:
    """Emit the detailed on-disk CSV (wider schema than the summary table).

    Columns are grouped so entire check-groups drop together when not run:
    - Base (always): image, digest, rekor fields, signature, verdict, error
    - Attestations: slsa_*, sbom_*, policy_*
    - Scan: vuln_*, vex_applied, kev_*
    - Upstream: upstream_sources_*, upstream_failures
    - Freshness/FIPS (always): image_age_days, freshness_status, fips_variant
    """
    # Build header + per-row generators in lock-step so columns can't drift.
    def base_cols(r: VerificationResult) -> list[str | int]:
        if customer_only:
            rekor_url = r.chain.customer_rekor_url or ""
            return [
                r.image, r.chain.base_digest_full, r.rekor_status,
                r.chain.customer_rekor_index, rekor_url,
                str(r.chain.rekor_verified).lower(), r.sig_status, r.status,
            ]
        rekor_url = (
            f"https://search.sigstore.dev/?logIndex={r.rekor_log_index}"
            if r.rekor_log_index else ""
        )
        return [
            r.image, r.chain.base_digest_full, r.ref_status, r.rekor_status,
            r.rekor_log_index, rekor_url,
            str(r.chain.rekor_verified).lower(), r.sig_status, r.status,
        ]

    base_headers = (
        ["image", "base_digest", "rekor_status", "rekor_log_index",
         "rekor_url", "rekor_verified", "signature_status", "verification_status"]
        if customer_only else
        ["image", "base_digest", "reference_status", "rekor_status",
         "rekor_log_index", "rekor_url", "rekor_verified",
         "signature_status", "verification_status"]
    )
    attest_headers = [
        "slsa_status", "sbom_status", "sbom_format", "sbom_package_count",
        "policy_status", "policy_violations",
    ]
    scan_headers = [
        "vuln_status", "vuln_critical", "vuln_high", "vuln_medium",
        "vuln_low", "vuln_total", "vex_applied", "kev_status", "kev_count",
        "kev_cves",
    ]
    upstream_headers = [
        "upstream_sources_status", "upstream_sources_total",
        "upstream_sources_verified", "upstream_sources_failed",
        "upstream_sources_errors", "upstream_sources_skipped",
        "upstream_failures",
    ]
    tail_headers = ["image_age_days", "freshness_status", "fips_variant", "error"]

    def attest_cols(r: VerificationResult) -> list[object]:
        return [
            r.slsa_status, r.sbom_status, r.sbom_format, r.sbom_package_count,
            r.policy_status, _format_policy_violations(r.chain.policy_violations),
        ]

    def scan_cols(r: VerificationResult) -> list[object]:
        return [
            r.vuln_status, r.vuln_critical, r.vuln_high, r.vuln_medium,
            r.vuln_low, r.vuln_total, str(r.vex_applied).lower(),
            r.kev_status, r.kev_count, _format_kev_hits(r.chain.kev_hits),
        ]

    def upstream_cols(r: VerificationResult) -> list[object]:
        return [
            r.upstream_sources_status, r.upstream_sources_total,
            r.upstream_sources_verified, r.upstream_sources_failed,
            r.upstream_sources_errors, r.upstream_sources_skipped,
            _format_upstream_failures(r.chain.upstream_summary),
        ]

    def tail_cols(r: VerificationResult) -> list[object]:
        return [
            r.chain.image_age_days, r.freshness_status,
            str(r.fips_variant).lower(), r.error,
        ]

    headers = list(base_headers)
    if attestations_on:
        headers += attest_headers
    if scan_on:
        headers += scan_headers
    if upstream_on:
        headers += upstream_headers
    headers += tail_headers

    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(headers)
        for r in results:
            row: list[object] = list(base_cols(r))
            if attestations_on:
                row += attest_cols(r)
            if scan_on:
                row += scan_cols(r)
            if upstream_on:
                row += upstream_cols(r)
            row += tail_cols(r)
            writer.writerow(row)


# ─────────────────────── Summary renderers (--format) ───────────────────────

# Column groups that only make sense when a particular check actually ran.
# Default-zero numeric fields (CVE counts, KEV count) would misread as
# "clean" in a run that never looked — so when a check is off, its column
# group is dropped from all three output formats entirely.
#
# Always-on columns: IMAGE, VERDICT, SIG, REKOR, AGE, FIPS
# --verify-attestations → SLSA, SBOM, POLICY
# --scan               → VULN, KEV


def _fmt_rekor(r: VerificationResult) -> str:
    """Tri-state: ✓ = SET cryptographically verified, ✗ = bundle claim
    only (not verified), - = no bundle entry."""
    if r.chain.rekor_verified:
        return "✓"
    if r.rekor_status == "EXISTS":
        return "✗"
    return "-"


def _fmt_sbom(r: VerificationResult) -> str:
    if r.sbom_package_count:
        return f"{r.sbom_status}({r.sbom_package_count})"
    return r.sbom_status


def _fmt_vuln(r: VerificationResult) -> str:
    """Compact C/H/M/L; trailing * = VEX-adjudicated."""
    s = f"{r.vuln_critical}C/{r.vuln_high}H/{r.vuln_medium}M/{r.vuln_low}L"
    return s + "*" if r.vex_applied else s


def _fmt_kev(r: VerificationResult) -> str:
    return str(r.kev_count)


def _fmt_age(r: VerificationResult) -> str:
    if r.chain.image_age_days < 0:
        return "?"
    age = f"{r.chain.image_age_days}d"
    if r.freshness_status not in ("FRESH", "N/A"):
        age += f" {r.freshness_status}"
    return age


def _fmt_upstream(r: VerificationResult) -> str:
    """Compact `<verified>/<countable> ✓` or `<verified>/<countable> (N failed)`.

    `countable` excludes SKIP entries (no source info → not actually
    verifiable). When N>0 sources erred (transient network) but none
    failed, append a `?N` suffix so the auditor sees the gap.
    """
    if r.upstream_sources_status == "N/A":
        return "N/A"
    countable = r.upstream_sources_total - r.upstream_sources_skipped
    if countable <= 0:
        return "skip"
    badge = f"{r.upstream_sources_verified}/{countable}"
    if r.upstream_sources_failed:
        return badge + f" ({r.upstream_sources_failed} failed)"
    if r.upstream_sources_errors:
        return badge + f" ?{r.upstream_sources_errors}"
    return badge + " ✓"


def _fmt_fips(r: VerificationResult) -> str:
    return "yes" if r.fips_variant else "no"


def _build_summary_columns(
    attestations_on: bool,
    scan_on: bool,
    upstream_on: bool = False,
) -> list[tuple[str, str, "Callable[[VerificationResult], str]"]]:
    """Return (header, json_key, getter) tuples for the columns that apply
    to this run. Order matches the canonical table layout."""
    cols: list[tuple[str, str, "Callable[[VerificationResult], str]"]] = [
        ("IMAGE", "image", lambda r: r.image),
        ("VERDICT", "verdict", lambda r: r.status),
        ("SIG", "signature", lambda r: r.sig_status),
        ("REKOR", "rekor", _fmt_rekor),
    ]
    if attestations_on:
        cols += [
            ("SLSA", "slsa", lambda r: r.slsa_status),
            ("SBOM", "sbom", _fmt_sbom),
            ("POLICY", "policy", lambda r: r.policy_status),
        ]
    if scan_on:
        cols += [
            ("VULN", "vuln", _fmt_vuln),
            ("KEV", "kev", _fmt_kev),
        ]
    if upstream_on:
        cols.append(("UPSTREAM", "upstream", _fmt_upstream))
    cols += [
        ("AGE", "age", _fmt_age),
        ("FIPS", "fips", _fmt_fips),
    ]
    return cols


def _render_summary_table(
    results: list[VerificationResult],
    attestations_on: bool = True,
    scan_on: bool = True,
    upstream_on: bool = False,
) -> str:
    """Render an ASCII table sized to content. Minimal dependencies — no rich,
    no tabulate. Plain stdlib."""
    columns = _build_summary_columns(attestations_on, scan_on, upstream_on)
    headers = [c[0] for c in columns]
    rows = [[c[2](r) for c in columns] for r in results]

    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(cell))

    def fmt_row(row: list[str]) -> str:
        return "  ".join(cell.ljust(w) for cell, w in zip(row, widths, strict=True))

    lines = [fmt_row(headers), "  ".join("-" * w for w in widths)]
    for row in rows:
        lines.append(fmt_row(row))

    # Legend for the compact encodings. Only print legend lines for columns
    # the caller actually rendered so the output isn't misleading.
    legend: list[str] = [
        "  Legend: REKOR ✓=SET cryptographically verified, ✗=bundle claim only, -=absent"
    ]
    if scan_on:
        legend.append(
            "          VULN  C/H/M/L counts; trailing * = OpenVEX adjudication applied"
        )
    if upstream_on:
        legend.append(
            "          UPSTREAM verified/countable; (N failed) = SBOM "
            "claim ≠ upstream; ?N = N transient errors"
        )
    lines.append("")
    lines.extend(legend)
    return "\n".join(lines)


def _render_summary_json(
    results: list[VerificationResult],
    args: argparse.Namespace,
    customer_only: bool,
    reference_org: str,
    csv_file: str | None,
    counts: dict[str, int],
) -> str:
    """Machine-readable JSON. Each image is a flat object whose keys are
    gated on which checks ran — missing-because-not-checked is
    unambiguous when the keys themselves are absent.

    `image`, `verdict`, `signature`, `rekor_verified`, `rekor_log_index`,
    `image_age_days`, `freshness_status`, `fips_variant`, `error` are
    always present.
    """
    attestations_on = bool(args.verify_attestations)
    scan_on = bool(args.scan)
    # Tolerant of older callers (tests build Namespace by hand without every
    # newer flag). Treat missing attribute as the flag being off.
    upstream_on = bool(getattr(args, "verify_upstream_sources", False))

    per_image = []
    for r in results:
        obj: dict[str, object] = {
            "image": r.image,
            "base_digest": r.chain.base_digest_full,
            "verdict": r.status,
            "signature": r.sig_status,
            "rekor_verified": r.chain.rekor_verified,
            "rekor_log_index": r.chain.rekor_log_index or r.chain.customer_rekor_index,
            "image_age_days": r.chain.image_age_days,
            "freshness_status": r.freshness_status,
            "fips_variant": r.fips_variant,
            "error": r.error,
        }
        if attestations_on:
            obj.update({
                "slsa_status": r.slsa_status,
                "sbom_status": r.sbom_status,
                "sbom_format": r.sbom_format,
                "sbom_package_count": r.sbom_package_count,
                "policy_status": r.policy_status,
            })
        if scan_on:
            obj.update({
                "vuln_status": r.vuln_status,
                "vuln_critical": r.vuln_critical,
                "vuln_high": r.vuln_high,
                "vuln_medium": r.vuln_medium,
                "vuln_low": r.vuln_low,
                "vuln_total": r.vuln_total,
                "vex_applied": r.vex_applied,
                "kev_status": r.kev_status,
                "kev_count": r.kev_count,
            })
        if upstream_on:
            obj.update({
                "upstream_sources_status": r.upstream_sources_status,
                "upstream_sources_total": r.upstream_sources_total,
                "upstream_sources_verified": r.upstream_sources_verified,
                "upstream_sources_failed": r.upstream_sources_failed,
                "upstream_sources_errors": r.upstream_sources_errors,
                "upstream_sources_skipped": r.upstream_sources_skipped,
                "upstream_failures": _format_upstream_failures(
                    r.chain.upstream_summary
                ),
            })
        per_image.append(obj)

    out = {
        "customer_org": args.customer_org,
        "reference_org": reference_org if not customer_only else None,
        "mode": "delivery" if customer_only else "full",
        "tool_version": __version__,
        "csv_file": csv_file,
        "checks_run": {
            "signature": True,  # always attempted
            "rekor": True,
            "attestations": attestations_on,
            "scan": scan_on,
            "sbom_drift": bool(getattr(args, "sbom_drift", False)),
            "upstream_sources": upstream_on,
        },
        "total": len(results),
        "verdict_counts": counts,
        "results": per_image,
    }
    return json.dumps(out, indent=2, sort_keys=True)


def _render_summary_csv(
    results: list[VerificationResult],
    customer_only: bool,
    attestations_on: bool = True,
    scan_on: bool = True,
    upstream_on: bool = False,
) -> str:
    """Same column gating as the summary table — when a check is off,
    its columns are dropped entirely rather than emitted as zeros or N/A."""
    import io
    columns = _build_summary_columns(attestations_on, scan_on, upstream_on)
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow([c[0] for c in columns])
    for r in results:
        w.writerow([c[2](r) for c in columns])
    return buf.getvalue().rstrip("\n")


def _compute_exit_status(
    results: list[VerificationResult],
    counts: dict[str, int],
    customer_only: bool,
) -> int:
    """Centralized exit-status policy used by all three --format paths."""
    if not customer_only and counts.get("NOT_FOUND", 0) > 0:
        return 1
    return 0


def _build_library_subparser(subparsers: "argparse._SubParsersAction[argparse.ArgumentParser]") -> None:
    p = subparsers.add_parser(
        "library",
        help="Verify Chainguard library packages via chainctl + optional Sigstore bundles",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --parent-org my-org --path /path/to/myapp.jar
      Run chainctl libraries verify against a local artifact.

  %(prog)s --parent-org my-org --ecosystem java \\
      --coordinate org.apache.commons:commons-compress:1.28.0 --with-signatures
      Fetch artifact + bundle, verify both via chainctl and cosign verify-blob.
""",
    )
    p.add_argument("--parent-org", required=True,
                   help="Chainguard org that owns the pull-token / libraries entitlement")
    p.add_argument("--path", action="append", default=[],
                   help="Local path, directory, or OCI ref to verify (repeatable). "
                        "Passed straight through to `chainctl libraries verify`.")
    p.add_argument("--coordinate", action="append", default=[],
                   help="Library coordinate (repeatable). Format: "
                        "'groupId:artifactId:version' (java), 'pkg==version' (python), "
                        "'pkg@version' or '@scope/pkg@version' (npm).")
    p.add_argument("--from-file",
                   help="File containing one coordinate per line")
    p.add_argument("--ecosystem", choices=["java", "python", "npm", "apk"],
                   help="Required when --coordinate or --from-file is used")
    p.add_argument("--with-signatures", action="store_true",
                   help="Additionally fetch <file>.bundle.json for coordinate inputs and "
                        "run `cosign verify-blob`")
    p.add_argument("--trusted-root",
                   help="Path to a Sigstore TUF trusted_root.json (forwarded to cosign)")
    p.add_argument("--cache-dir", default="",
                   help="Directory for cached downloads "
                        "(default: ~/.cache/verify-provenance/libraries)")
    p.add_argument("--csv-output",
                   help="Write results to this CSV path")
    p.add_argument("--limit", type=int, default=0,
                   help="Limit number of inputs processed (0 = all)")


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="verify-provenance",
        description="Verify Chainguard provenance for images (cgr.dev) and "
                    "libraries (libraries.cgr.dev).",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="cmd", required=True, metavar="{image,library}")
    _build_image_subparser(subparsers)
    _build_library_subparser(subparsers)

    args = parser.parse_args()

    if args.cmd == "image":
        run_image_mode(args)
    elif args.cmd == "library":
        # Lazy import so image mode doesn't pay for it
        from verify_library import run_library_mode
        sys.exit(run_library_mode(args))


if __name__ == "__main__":
    main()
