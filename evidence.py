"""
Evidence-bundle writer.

When `--evidence-bundle <dir>` is passed, each verified image gets its own
subdirectory under <dir>/ containing the raw artifacts an auditor will
want: the DSSE envelopes for every attestation we pulled, the SBOM
document(s), the OpenVEX document (if any), the grype JSON, a
control-to-check mapping, a human-readable Markdown summary, and a
sha256sum-format manifest for integrity sealing.

Design notes:
- Directory layout, not tarball, so auditors can grep / diff directly.
  Tarball packaging is trivial to add later if needed.
- No cryptographic sealing — just a hash manifest. Real sealing (sign
  with cosign) is a future layer.
- Best-effort: write what's available, skip what isn't. A partial bundle
  is more useful than no bundle.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import asdict, is_dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from verify_provenance import VerificationResult


# Mapping from check (by result field name) to the regulatory controls it
# satisfies. Used to render an auditor-friendly controls.json per bundle.
# Not exhaustive — the intent is "these controls are evidenced by this check"
# rather than "this check fully satisfies the control."
CONTROL_MAP: dict[str, dict[str, list[str]]] = {
    "signature": {
        "SSDF": ["PS.2"],
        "NIST_800-161": ["SR-4", "SR-11"],
        "NIST_800-190": ["§4.3.2"],
        "FedRAMP_SR": ["SR-11(1)"],
    },
    "rekor_verified": {
        "SSDF": ["PS.3"],
        "NIST_800-161": ["SR-4(3)"],
    },
    "slsa": {
        "SSDF": ["PO.3", "PS.1"],
        "NIST_800-161": ["SR-3", "SR-4"],
        "FedRAMP_SR": ["SR-3", "SR-4"],
    },
    "sbom": {
        "SSDF": ["PW.4"],
        "NIST_800-161": ["SR-10"],
        "CISA_NTIA_SBOM": ["minimum-elements"],
    },
    "scan": {
        "SSDF": ["RV.1"],
        "NIST_800-190": ["§4.3.3"],
        "FedRAMP_RA": ["RA-5"],
        "CMMC": ["3.11.2"],
    },
    "kev": {
        "CISA_BOD": ["22-01"],
    },
    "policy": {
        "NIST_800-161": ["SR-11"],
    },
    "freshness": {
        "SSDF": ["RV.1"],
        "CMMC": ["3.12.3"],
    },
    "fips": {
        "FIPS_140-3": ["variant-detected"],
        "FedRAMP_SR": ["SR-11"],
    },
    # `--verify-upstream-sources` evidences supply-chain integrity by
    # reaching upstream and confirming the SBOM's claims (tag→commit,
    # tarball checksum) are real. SR-3 / SR-4 are the canonical mappings
    # for "you actually verified the source you said you used"; SSDF PS.3
    # covers provenance authenticity.
    "upstream_sources": {
        "SSDF": ["PS.3"],
        "NIST_800-161": ["SR-3", "SR-4"],
        "FedRAMP_SR": ["SR-3", "SR-4"],
    },
}


def _safe_name(s: str) -> str:
    """Make an image-ref usable as a directory name."""
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s).strip("_") or "image"


def _write_json(path: Path, obj: Any) -> None:
    """Serialize obj (possibly a dataclass tree) to pretty JSON."""

    def default(o: Any) -> Any:
        if is_dataclass(o) and not isinstance(o, type):
            return asdict(o)
        if isinstance(o, set | frozenset):
            return sorted(o)
        return str(o)

    path.write_text(json.dumps(obj, indent=2, default=default, sort_keys=True))


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def write_evidence_bundle(
    bundle_root: Path,
    result: VerificationResult,
    tool_version: str,
    customer_org: str,
    mode: str,
    policy_source: str,
) -> Path:
    """Write the per-image evidence subdirectory. Returns the subdir path."""
    img_dir = bundle_root / _safe_name(result.image)
    img_dir.mkdir(parents=True, exist_ok=True)
    attest_dir = img_dir / "attestations"
    attest_dir.mkdir(exist_ok=True)

    now = datetime.now(tz=timezone.utc).isoformat(timespec="seconds")

    # 1) Top-level metadata for this image
    meta = {
        "image": result.image,
        "base_digest": result.chain.base_digest_full,
        "customer_digest": result.chain.customer_digest,
        "verification_status": result.status,
        "verified_at": now,
        "tool_version": tool_version,
        "customer_org": customer_org,
        "mode": mode,
        "policy_source": policy_source,
        "slsa_status": result.slsa_status,
        "sbom_status": result.sbom_status,
        "policy_status": result.policy_status,
        "vuln_status": result.vuln_status,
        "kev_status": result.kev_status,
        "freshness_status": result.freshness_status,
        "rekor_verified": result.chain.rekor_verified,
        "fips_variant": result.fips_variant,
        "fips_reason": result.fips_reason,
        "upstream_sources_status": result.upstream_sources_status,
        "upstream_sources_total": result.upstream_sources_total,
        "upstream_sources_verified": result.upstream_sources_verified,
        "upstream_sources_failed": result.upstream_sources_failed,
        "upstream_sources_errors": result.upstream_sources_errors,
        "upstream_sources_skipped": result.upstream_sources_skipped,
    }
    _write_json(img_dir / "metadata.json", meta)

    # 2) Every attestation we retrieved → DSSE envelope / predicate JSON
    for predicate_type, rec in result.chain.attestations.items():
        # Use a short filename from the predicate_type
        fname = _safe_name(predicate_type.rsplit("/", 1)[-1] or "attestation") + ".json"
        _write_json(attest_dir / fname, rec)

    # 3) Scan result (raw + actionable)
    if result.chain.scan_result is not None:
        _write_json(img_dir / "scan.json", result.chain.scan_result)

    # 4) KEV hits
    if result.chain.kev_hits:
        _write_json(img_dir / "kev_hits.json", result.chain.kev_hits)

    # 5) Policy violations
    if result.chain.policy_violations:
        _write_json(img_dir / "policy_violations.json", result.chain.policy_violations)

    # 5b) Upstream source verification record (full per-source list)
    if result.upstream_sources_status != "N/A" and result.chain.upstream_summary is not None:
        _write_json(img_dir / "upstream_sources.json", result.chain.upstream_summary)

    # 6) Controls mapping — which frameworks each recorded check evidences.
    # Only include checks that actually ran (non-"N/A").
    relevant: dict[str, dict[str, list[str]]] = {}
    if result.sig_status in {"VALID", "INVALID"}:
        relevant["signature"] = CONTROL_MAP["signature"]
    if result.chain.rekor_verified:
        relevant["rekor_verified"] = CONTROL_MAP["rekor_verified"]
    if result.slsa_status != "N/A":
        relevant["slsa"] = CONTROL_MAP["slsa"]
    if result.sbom_status != "N/A":
        relevant["sbom"] = CONTROL_MAP["sbom"]
    if result.vuln_status != "N/A":
        relevant["scan"] = CONTROL_MAP["scan"]
    if result.kev_status != "N/A":
        relevant["kev"] = CONTROL_MAP["kev"]
    if result.policy_status != "N/A":
        relevant["policy"] = CONTROL_MAP["policy"]
    if result.freshness_status != "N/A":
        relevant["freshness"] = CONTROL_MAP["freshness"]
    if result.fips_variant:
        relevant["fips"] = CONTROL_MAP["fips"]
    if result.upstream_sources_status != "N/A":
        relevant["upstream_sources"] = CONTROL_MAP["upstream_sources"]
    _write_json(img_dir / "controls.json", relevant)

    # 7) Human-readable summary
    _write_markdown_summary(img_dir / "SUMMARY.md", result, meta)

    # 8) Hash-seal manifest (sha256sum format) — last, after all other files
    _write_hash_seal(img_dir)

    return img_dir


def _write_markdown_summary(path: Path, result: VerificationResult, meta: dict[str, Any]) -> None:
    lines: list[str] = [
        f"# Verification Evidence — `{result.image}`",
        "",
        f"- **Verified at:** {meta['verified_at']}",
        f"- **Tool version:** {meta['tool_version']}",
        f"- **Customer org:** {meta['customer_org']}",
        f"- **Mode:** {meta['mode']}",
        f"- **Policy source:** {meta['policy_source']}",
        f"- **Overall verdict:** `{result.status}`",
        "",
        "## Cryptographic chain",
        f"- Signature: `{result.sig_status}`",
        f"- Rekor SET cryptographically verified: `{result.chain.rekor_verified}`",
        f"- Base digest: `{result.chain.base_digest_full or '(none)'}`",
    ]
    if result.chain.github_workflow_ref:
        lines += [
            f"- Build workflow ref: `{result.chain.github_workflow_ref}`",
            f"- Build commit SHA: `{result.chain.github_workflow_sha}`",
        ]
    lines += [
        "",
        "## Attestations",
        f"- SLSA provenance: `{result.slsa_status}`",
        f"- SBOM ({result.sbom_format or 'n/a'}, {result.sbom_package_count} pkgs): `{result.sbom_status}`",
        f"- Policy allowlist: `{result.policy_status}`",
        "",
        "## Vulnerability posture",
        f"- Scan: `{result.vuln_status}` "
        f"(C={result.vuln_critical} H={result.vuln_high} "
        f"M={result.vuln_medium} L={result.vuln_low})",
        f"- VEX applied: `{result.vex_applied}`",
        f"- CISA KEV: `{result.kev_status}` ({result.kev_count} hit(s))",
        "",
        "## Freshness & compliance",
        f"- Image age: {result.chain.image_age_days if result.chain.image_age_days >= 0 else 'unknown'} days",
        f"- Freshness: `{result.freshness_status}`",
        f"- FIPS variant: `{result.fips_variant}` {result.fips_reason}".rstrip(),
    ]
    if result.upstream_sources_status != "N/A":
        countable = result.upstream_sources_total - result.upstream_sources_skipped
        lines += [
            "",
            "## Upstream source verification",
            f"- Status: `{result.upstream_sources_status}`",
            f"- Verified: {result.upstream_sources_verified} / {countable}",
            f"- Failed: {result.upstream_sources_failed}",
            f"- Transient errors: {result.upstream_sources_errors}",
            f"- Skipped (no source info): {result.upstream_sources_skipped}",
        ]
    lines += [
        "",
        "## Files in this bundle",
        "- `metadata.json` — top-level summary fields",
        "- `attestations/*.json` — one file per verified attestation",
        "- `scan.json` — full grype output (raw + VEX-adjusted)",
        "- `kev_hits.json` — CISA KEV entries matching actionable CVEs",
        "- `policy_violations.json` — allowlist failures (if any)",
        "- `upstream_sources.json` — per-source git/tarball verification (if --verify-upstream-sources)",
        "- `controls.json` — map of checks to regulatory frameworks",
        "- `SHA256SUMS` — integrity-seal manifest for the bundle",
    ]
    path.write_text("\n".join(lines) + "\n")


def _write_hash_seal(img_dir: Path) -> None:
    """Create a SHA256SUMS file for every regular file in img_dir (except itself)."""
    manifest_path = img_dir / "SHA256SUMS"
    with manifest_path.open("w") as f:
        for p in sorted(img_dir.rglob("*")):
            if not p.is_file() or p.name == "SHA256SUMS":
                continue
            rel = p.relative_to(img_dir)
            f.write(f"{_sha256_file(p)}  {rel}\n")
