"""
Vulnerability scanning + OpenVEX adjudication.

Runs `grype` (Wolfi-aware, best fit for Chainguard) against a verified image
and, when a Chainguard-published OpenVEX attestation is available, applies
it to produce an *actionable* CVE count (what's left after the producer's
documented "not_affected" / "fixed" adjudications).

Why grype:
- Natively understands Wolfi/apk package advisories, which minimizes false
  positives on Chainguard images.
- Accepts `--vex <file>` for OpenVEX suppression, matching the
  Chainguard-published predicate format.

Why two grype runs:
- One without --vex gives the "raw" findings an auditor wants on record.
- One with --vex gives the "actionable" findings a CISO uses to gate.
- Running with --vex --show-suppressed in one shot would also work but
  requires post-parsing to split the two views; two runs keeps each
  invocation's output unambiguous and easier to archive separately.
"""

from __future__ import annotations

import contextlib
import json
import shutil
import tempfile
from dataclasses import dataclass, field
from pathlib import Path

from verify_provenance import run_cmd

# Grype severity labels in priority order (highest first).
SEVERITY_ORDER = ("critical", "high", "medium", "low", "negligible", "unknown")


@dataclass
class VulnCounts:
    """Match counts by severity. All attributes default to zero."""

    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    negligible: int = 0
    unknown: int = 0

    def total(self) -> int:
        return self.critical + self.high + self.medium + self.low + self.negligible + self.unknown

    def as_dict(self) -> dict[str, int]:
        return {sev: getattr(self, sev) for sev in SEVERITY_ORDER}


@dataclass
class ScanResult:
    """One scan of one image, with and without VEX adjudication.

    `raw_counts`        — findings before any VEX filter applied. The
                          canonical audit-record number.
    `actionable_counts` — findings after VEX filter applied. Equal to
                          raw_counts when no VEX was available.
    `vex_applied`       — whether a VEX doc was actually passed to grype.
    `top_cves`          — first N CVE IDs from the raw scan, for humans.
    """

    success: bool = False
    error: str = ""
    raw_counts: VulnCounts = field(default_factory=VulnCounts)
    actionable_counts: VulnCounts = field(default_factory=VulnCounts)
    vex_applied: bool = False
    scanner_version: str = ""
    grype_command: str = ""
    top_cves: list[str] = field(default_factory=list)
    # Full actionable CVE list (VEX-adjusted if VEX applied, else == raw).
    # Consumed by the KEV cross-check so it can flag KEV hits among the
    # findings the producer has NOT adjudicated away.
    actionable_cve_ids: list[str] = field(default_factory=list)


def grype_installed() -> bool:
    return shutil.which("grype") is not None


def syft_installed() -> bool:
    return shutil.which("syft") is not None


@dataclass
class SbomDrift:
    """Summary of a diff between a locally-generated SBOM and an attested one.

    `drift_ratio` is a conservative estimate: packages unique to either
    side, divided by the union. A value near 0 means the two SBOMs agree
    on content; non-trivial drift suggests the attached SBOM may describe
    a different image.
    """

    success: bool = False
    error: str = ""
    attested_count: int = 0
    local_count: int = 0
    shared_count: int = 0
    only_attested: list[str] = field(default_factory=list)
    only_local: list[str] = field(default_factory=list)
    drift_ratio: float = 0.0


def _extract_purls_from_spdx(doc: dict[str, object]) -> set[str]:
    out: set[str] = set()
    pkgs = doc.get("packages", [])
    if not isinstance(pkgs, list):
        return out
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        refs = p.get("externalRefs", [])
        if not isinstance(refs, list):
            continue
        for r in refs:
            if isinstance(r, dict) and r.get("referenceType") == "purl":
                loc = r.get("referenceLocator")
                if isinstance(loc, str):
                    out.add(loc)
    return out


def _extract_purls_from_cyclonedx(doc: dict[str, object]) -> set[str]:
    out: set[str] = set()
    comps = doc.get("components", [])
    if not isinstance(comps, list):
        return out
    for c in comps:
        if isinstance(c, dict):
            purl = c.get("purl")
            if isinstance(purl, str):
                out.add(purl)
    return out


def extract_purl_set(predicate: dict[str, object]) -> set[str]:
    """Return the PURL set from an SPDX or CycloneDX predicate, best-effort."""
    if "spdxVersion" in predicate:
        return _extract_purls_from_spdx(predicate)
    if predicate.get("bomFormat") == "CycloneDX" or "specVersion" in predicate:
        return _extract_purls_from_cyclonedx(predicate)
    # Try both; whichever yields results.
    s = _extract_purls_from_spdx(predicate)
    return s or _extract_purls_from_cyclonedx(predicate)


def run_sbom_drift(image_ref: str, attested_purls: set[str], timeout: int = 180) -> SbomDrift:
    """Run `syft -o spdx-json` against image_ref; diff its PURL set against
    the attested set. Intentionally skip drift check if syft unavailable."""
    drift = SbomDrift(attested_count=len(attested_purls))
    if not syft_installed():
        drift.error = "syft binary not found in PATH"
        return drift

    cmd = ["syft", image_ref, "-o", "spdx-json", "--quiet"]
    success, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if not success:
        err_lines = (stderr or "").strip().splitlines()
        drift.error = err_lines[-1] if err_lines else "syft failed"
        return drift

    try:
        local_doc = json.loads(stdout)
    except json.JSONDecodeError as e:
        drift.error = f"syft output parse failed: {e}"
        return drift
    if not isinstance(local_doc, dict):
        drift.error = "syft output not a JSON object"
        return drift

    local_purls = _extract_purls_from_spdx(local_doc)
    drift.local_count = len(local_purls)
    shared = attested_purls & local_purls
    drift.shared_count = len(shared)
    only_attested = sorted(attested_purls - local_purls)
    only_local = sorted(local_purls - attested_purls)
    # Cap the lists so the JSON bundle stays small.
    drift.only_attested = only_attested[:50]
    drift.only_local = only_local[:50]

    union = len(attested_purls | local_purls)
    if union > 0:
        drift.drift_ratio = (len(only_attested) + len(only_local)) / union
    drift.success = True
    return drift


def parse_grype_json(text: str) -> VulnCounts:
    """Count grype matches by severity. Unknown severities roll into 'unknown'.

    Tolerates malformed or empty input — returns a zeroed VulnCounts so
    callers don't have to distinguish "no findings" from "parse error";
    the ScanResult.error field is the parse-error signal.
    """
    counts = VulnCounts()
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return counts
    if not isinstance(doc, dict):
        return counts
    matches = doc.get("matches", [])
    if not isinstance(matches, list):
        return counts
    for m in matches:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability")
        if not isinstance(vuln, dict):
            continue
        sev_raw = vuln.get("severity")
        sev = (sev_raw or "").lower() if isinstance(sev_raw, str) else ""
        if sev in SEVERITY_ORDER:
            setattr(counts, sev, getattr(counts, sev) + 1)
        else:
            counts.unknown += 1
    return counts


def extract_cve_list(text: str, limit: int = 10) -> list[str]:
    """Pull the first N CVE IDs out of grype JSON for display."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return []
    if not isinstance(doc, dict):
        return []
    cves: list[str] = []
    matches = doc.get("matches", [])
    if not isinstance(matches, list):
        return []
    for m in matches:
        if not isinstance(m, dict):
            continue
        vuln = m.get("vulnerability")
        if not isinstance(vuln, dict):
            continue
        vid = vuln.get("id")
        if isinstance(vid, str):
            cves.append(vid)
            if len(cves) >= limit:
                break
    return cves


def _extract_grype_version(text: str) -> str:
    """Grype puts its version under descriptor.name / descriptor.version in -o json."""
    try:
        doc = json.loads(text)
    except json.JSONDecodeError:
        return ""
    if not isinstance(doc, dict):
        return ""
    desc = doc.get("descriptor", {})
    if isinstance(desc, dict):
        v = desc.get("version")
        if isinstance(v, str):
            return v
    return ""


def run_scan(
    image_ref: str,
    vex_predicate: dict[str, object] | None = None,
    timeout: int = 300,
) -> ScanResult:
    """Run grype against an image; optionally re-run with --vex for actionable counts.

    Returns ScanResult with `success=True` once the raw scan succeeds.
    If the VEX-adjusted run fails, actionable_counts fall back to
    raw_counts and vex_applied stays False — raw data is more valuable
    than no data.
    """
    result = ScanResult()
    if not grype_installed():
        result.error = "grype binary not found in PATH"
        return result

    # Raw scan — the audit number.
    cmd = ["grype", image_ref, "-o", "json", "--quiet"]
    result.grype_command = " ".join(cmd)
    success, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if not success:
        err_lines = (stderr or "").strip().splitlines()
        result.error = err_lines[-1] if err_lines else "grype scan failed"
        return result

    result.raw_counts = parse_grype_json(stdout)
    result.actionable_counts = result.raw_counts  # default when no VEX
    result.top_cves = extract_cve_list(stdout)
    result.scanner_version = _extract_grype_version(stdout)
    # Full list for downstream KEV cross-check. When no VEX runs, actionable
    # == raw, so we populate from the raw output here and let the VEX branch
    # overwrite it on success.
    result.actionable_cve_ids = extract_cve_list(stdout, limit=10_000)

    # VEX-adjusted scan — the gating number.
    if vex_predicate is not None:
        try:
            with tempfile.NamedTemporaryFile(mode="w", suffix=".openvex.json", delete=False) as f:
                json.dump(vex_predicate, f)
                vex_path = f.name
        except OSError as e:
            # Couldn't write VEX file — report raw only.
            result.error = f"failed to write VEX predicate: {e}"
            result.success = True
            return result

        try:
            cmd2 = ["grype", image_ref, "-o", "json", "--vex", vex_path, "--quiet"]
            success2, stdout2, stderr2 = run_cmd(cmd2, timeout=timeout)
            if success2:
                result.actionable_counts = parse_grype_json(stdout2)
                result.actionable_cve_ids = extract_cve_list(stdout2, limit=10_000)
                result.vex_applied = True
            else:
                # Raw counts already populated; note the VEX failure but don't
                # fail the whole scan — raw is still useful.
                err2 = (stderr2 or "").strip().splitlines()
                result.error = "VEX-adjusted scan failed: " + (
                    err2[-1] if err2 else "unknown error"
                )
        finally:
            with contextlib.suppress(OSError):
                Path(vex_path).unlink(missing_ok=True)

    result.success = True
    return result
