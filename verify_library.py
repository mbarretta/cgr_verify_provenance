"""
Library provenance verification for Chainguard Libraries.

Wraps `chainctl libraries verify` with batched input handling, per-artifact
chain output, and CSV export — mirroring the pattern used by the image
verification mode in verify_provenance.py.

Optional `--with-signatures` additionally fetches the cosign-style
<file>.bundle.json sidecar that Chainguard publishes alongside Java
artifacts, runs `cosign verify-blob`, and surfaces the signer SAN +
Rekor transparency-log fields.
"""

from __future__ import annotations

import argparse
import base64
import csv
import hashlib
import json
import os
import re
import subprocess
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from verify_provenance import run_cmd

LIBRARIES_BASE = "https://libraries.cgr.dev"
CHAINGUARD_ISSUER_REGEX = r"^https://issuer\.enforce\.dev/.*$"
OIDC_ISSUER_REGEX = r"^https://.*$"


# ───────────────────────────── Data types ─────────────────────────────

@dataclass
class LibraryVerifyResult:
    input_ref: str
    ecosystem: str                              # "java" | "python" | "npm" | "unknown"
    artifact_path: Optional[Path] = None
    artifact_url: Optional[str] = None
    artifact_sha256: Optional[str] = None

    # chainctl libraries verify results
    chainctl_coverage: Optional[float] = None
    chainctl_details: str = ""
    matched_coordinate: Optional[str] = None
    chainctl_command: str = ""

    # --with-signatures results (coordinate mode only)
    bundle_path: Optional[Path] = None
    bundle_url: Optional[str] = None
    bundle_size: Optional[int] = None
    bundle_verified: bool = False
    signer_identity: Optional[str] = None
    rekor_log_index: Optional[int] = None
    rekor_log_id: Optional[str] = None
    integrated_time: Optional[int] = None
    integrated_time_iso: Optional[str] = None

    # Overall status + recorded commands for audit-friendly output
    status: str = "PENDING"                     # VERIFIED | CATALOG_ONLY | NO_MATCH | ERROR | SKIPPED
    fetch_commands: list[str] = field(default_factory=list)
    cosign_command: str = ""
    step_failed: Optional[int] = None           # Step number that failed, if any
    error: Optional[str] = None


# ───────────────────────── Pull-token acquisition ─────────────────────

_PULL_TOKEN_CACHE: dict[str, tuple[str, str]] = {}


def acquire_pull_token(ecosystem: str, parent_org: str) -> tuple[str, str, str]:
    """
    Acquire a short-lived pull token from chainctl. Returns
    (identity_id, token, pretty_command).
    Cached per-ecosystem within a single process invocation.
    """
    key = f"{ecosystem}:{parent_org}"
    cmd = [
        "chainctl", "auth", "pull-token", "create",
        f"--repository={ecosystem}",
        f"--parent={parent_org}",
        "--ttl=1h",
        "--output=json",
    ]
    pretty = (
        "chainctl auth pull-token create \\\n"
        f"      --repository={ecosystem} --parent={parent_org} \\\n"
        "      --ttl=1h --output=json"
    )

    if key in _PULL_TOKEN_CACHE:
        user, password = _PULL_TOKEN_CACHE[key]
        return user, password, pretty

    success, stdout, stderr = run_cmd(cmd, timeout=30)
    if not success:
        raise RuntimeError(f"chainctl auth pull-token create failed: {stderr.strip() or stdout.strip()}")

    # chainctl prints a deprecation/status line to stdout before the JSON;
    # grab the last JSON object in the output.
    m = re.search(r"\{[^{}]*\"token\"[^{}]*\}", stdout, re.DOTALL)
    if not m:
        raise RuntimeError(f"Could not parse pull-token JSON from chainctl output: {stdout[:300]}")
    try:
        payload = json.loads(m.group(0))
    except json.JSONDecodeError as e:
        raise RuntimeError(f"Invalid JSON from chainctl: {e}") from e

    user = payload.get("identity_id", "")
    password = payload.get("token", "")
    if not user or not password:
        raise RuntimeError("chainctl pull-token response missing identity_id or token")

    _PULL_TOKEN_CACHE[key] = (user, password)
    return user, password, pretty


# ───────────────────────── Coordinate parsing ─────────────────────────

def parse_java_coordinate(coord: str) -> dict[str, str]:
    """
    'org.apache.commons:commons-compress:1.28.0' →
    {'group': 'org.apache.commons', 'group_path': 'org/apache/commons',
     'artifact': 'commons-compress', 'version': '1.28.0',
     'filename': 'commons-compress-1.28.0.jar'}
    """
    parts = coord.split(":")
    if len(parts) != 3:
        raise ValueError(f"Java coordinate must be 'groupId:artifactId:version', got: {coord}")
    group, artifact, version = parts
    return {
        "group": group,
        "group_path": group.replace(".", "/"),
        "artifact": artifact,
        "version": version,
        "filename": f"{artifact}-{version}.jar",
    }


def parse_python_coordinate(coord: str) -> dict[str, str]:
    """'requests==2.31.0' → {'pkg': 'requests', 'version': '2.31.0'}"""
    if "==" not in coord:
        raise ValueError(f"Python coordinate must be 'pkg==version', got: {coord}")
    pkg, version = coord.split("==", 1)
    return {"pkg": pkg.strip(), "version": version.strip()}


def parse_npm_coordinate(coord: str) -> dict[str, str]:
    """
    'lodash@4.17.21'        → {'pkg': 'lodash', 'version': '4.17.21', 'basename': 'lodash'}
    '@scope/pkg@1.0.0'      → {'pkg': '@scope/pkg', 'version': '1.0.0', 'basename': 'pkg'}
    """
    if coord.startswith("@"):
        # Scoped: split on the @ that separates pkg from version (not the leading one)
        at = coord.rfind("@")
        if at <= 0:
            raise ValueError(f"npm coordinate must be 'pkg@version', got: {coord}")
        pkg, version = coord[:at], coord[at + 1:]
        basename = pkg.split("/", 1)[1] if "/" in pkg else pkg.lstrip("@")
    else:
        if "@" not in coord:
            raise ValueError(f"npm coordinate must be 'pkg@version', got: {coord}")
        pkg, version = coord.split("@", 1)
        basename = pkg
    return {"pkg": pkg, "version": version, "basename": basename}


# ───────────────────────── URL resolution ─────────────────────────────

def resolve_java_url(coord: str) -> tuple[str, str]:
    """Return (artifact_url, bundle_url) for a Java coordinate. Pure function."""
    gav = parse_java_coordinate(coord)
    dir_url = (
        f"{LIBRARIES_BASE}/java/{gav['group_path']}/{gav['artifact']}/{gav['version']}"
    )
    artifact_url = f"{dir_url}/{gav['filename']}"
    bundle_url = f"{artifact_url}.bundle.json"
    return artifact_url, bundle_url


def resolve_python_artifact_url(coord: str, auth: tuple[str, str]) -> str:
    """
    Fetch the PEP 503 simple index for the package, pick the first file whose
    filename contains '-<version>' (wheel or sdist), and return its absolute URL.
    """
    py = parse_python_coordinate(coord)
    index_url = f"{LIBRARIES_BASE}/python/simple/{py['pkg']}/"
    user, pw = auth
    success, stdout, stderr = run_cmd(
        ["curl", "-sfL", "-u", f"{user}:{pw}", index_url], timeout=60
    )
    if not success:
        raise RuntimeError(f"Could not fetch PEP 503 index {index_url}: {stderr.strip()}")
    # The simple index is an HTML page with <a href="..."> entries.
    needle_wheel = f"-{py['version']}-"
    needle_sdist = f"-{py['version']}."
    candidates: list[str] = []
    for m in re.finditer(r'href="([^"]+)"', stdout):
        href = m.group(1)
        name = os.path.basename(href.split("#", 1)[0])
        if needle_wheel in name or needle_sdist in name:
            candidates.append(href.split("#", 1)[0])
    if not candidates:
        raise RuntimeError(f"No distribution for {py['pkg']}=={py['version']} in {index_url}")
    # Prefer sdist (.tar.gz) when present — more stable URL for mirroring semantics.
    candidates.sort(key=lambda h: (0 if h.endswith((".tar.gz", ".zip")) else 1, h))
    chosen = candidates[0]
    if chosen.startswith("http"):
        return chosen
    # Relative URL — join with index base
    return urllib.parse.urljoin(index_url, chosen)


def resolve_npm_tarball_url(coord: str) -> str:
    """
    Return the npm tarball URL for <pkg>@<version>. Uses the standard
    registry layout; no network needed.
    """
    n = parse_npm_coordinate(coord)
    return f"{LIBRARIES_BASE}/javascript/{n['pkg']}/-/{n['basename']}-{n['version']}.tgz"


def parse_apk_coordinate(coord: str) -> dict[str, str]:
    """
    APK coordinate format: `<name>-<version>-r<rev>` (Wolfi/Alpine convention).
    Example: `python-3.12-3.12.5-r0`.
    """
    # APK names can contain dots / hyphens; version is the last two hyphen-separated
    # pieces starting with the first digit after the name. We split on the
    # rightmost `-rN` suffix first, then peel off the version component.
    m = re.match(r"^(?P<name>.+)-(?P<version>\d[^-]*(?:-r\d+)?)$", coord)
    if not m:
        raise ValueError(
            f"Invalid apk coordinate: {coord!r} "
            "(expected '<name>-<version>-rN', e.g. 'glibc-2.39-r1')"
        )
    name = m.group("name")
    version = m.group("version")
    return {
        "name": name,
        "version": version,
        "filename": f"{name}-{version}.apk",
    }


def resolve_apk_url(coord: str) -> str:
    """
    Return the APK URL for a Wolfi-built package on libraries.cgr.dev.
    Format mirrors the apk repo layout: /apk/<arch>/<name>-<version>.apk.
    Defaults to x86_64; `<coord>@<arch>` override supported for aarch64 etc.
    """
    arch = "x86_64"
    if "@" in coord:
        coord, arch = coord.rsplit("@", 1)
    a = parse_apk_coordinate(coord)
    return f"{LIBRARIES_BASE}/apk/{arch}/{a['filename']}"


# ───────────────────────── Fetching ───────────────────────────────────

def default_cache_dir() -> Path:
    return Path(os.path.expanduser("~/.cache/verify-provenance/libraries"))


def cache_path_for_url(cache_dir: Path, url: str) -> Path:
    """Mirror the URL path layout under the cache dir (stable, debuggable)."""
    parsed = urllib.parse.urlparse(url)
    # Strip leading slash so we nest under cache_dir/<host>/<path>
    rel = parsed.path.lstrip("/")
    return cache_dir / parsed.netloc / rel


def fetch_to_cache(url: str, auth: tuple[str, str], cache_dir: Path) -> tuple[Path, str]:
    """
    Download `url` to the cache dir, skipping if already present. Returns
    (path, pretty_command).
    """
    dest = cache_path_for_url(cache_dir, url)
    user, pw = auth
    pretty = f'curl -sfL -u "$USER:$PASS" -o <cache>/{dest.relative_to(cache_dir)} \\\n      {url}'
    if dest.exists() and dest.stat().st_size > 0:
        return dest, pretty
    dest.parent.mkdir(parents=True, exist_ok=True)
    success, _, stderr = run_cmd(
        ["curl", "-sfL", "-u", f"{user}:{pw}", "-o", str(dest), url], timeout=300
    )
    if not success:
        dest.unlink(missing_ok=True)
        raise RuntimeError(f"Failed to download {url}: {stderr.strip()}")
    return dest, pretty


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ──────────────────── Bundle parsing (Sigstore attached bundle) ────────

def parse_bundle_metadata(bundle_path: Path) -> dict[str, object]:
    """
    Parse a cosign-style bundle.json and extract signer SAN + Rekor fields.
    Returns a dict with any fields successfully extracted.
    """
    out: dict[str, object] = {}
    try:
        data = json.loads(bundle_path.read_text())
    except Exception as e:  # noqa: BLE001
        out["parse_error"] = str(e)
        return out

    cert_b64 = data.get("cert")
    if cert_b64:
        # `cert` is base64-encoded PEM. Decode, feed to `openssl x509` to
        # pull the SAN URI without taking on a cryptography library dep.
        try:
            pem = base64.b64decode(cert_b64)
            proc = subprocess.run(
                ["openssl", "x509", "-noout", "-ext", "subjectAltName"],
                input=pem, capture_output=True, timeout=10, check=False,
            )
            if proc.returncode == 0:
                san_match = re.search(r"URI:(\S+)", proc.stdout.decode())
                if san_match:
                    out["signer_identity"] = san_match.group(1)
        except Exception as e:  # noqa: BLE001
            out["cert_error"] = str(e)

    rekor = data.get("rekorBundle", {})
    payload = rekor.get("Payload", {}) if isinstance(rekor, dict) else {}
    if isinstance(payload, dict):
        log_idx = payload.get("logIndex")
        if isinstance(log_idx, int):
            out["rekor_log_index"] = log_idx
        log_id = payload.get("logID")
        if isinstance(log_id, str):
            out["rekor_log_id"] = log_id
        itime = payload.get("integratedTime")
        if isinstance(itime, int):
            out["integrated_time"] = itime
            # ISO format in UTC
            from datetime import datetime, timezone
            out["integrated_time_iso"] = datetime.fromtimestamp(
                itime, tz=timezone.utc
            ).strftime("%Y-%m-%dT%H:%M:%SZ")
    return out


# ───────────────── chainctl libraries verify wrapper ──────────────────

def run_chainctl_verify(path: Path, parent_org: str) -> tuple[dict, str]:
    """Run `chainctl libraries verify -d -o json <path>` and return (json, pretty_command)."""
    cmd = [
        "chainctl", "libraries", "verify",
        f"--parent={parent_org}",
        "-d", "-o", "json",
        str(path),
    ]
    pretty = (
        f"chainctl libraries verify --parent={parent_org} -d -o json \\\n"
        f"      {path}"
    )
    success, stdout, stderr = run_cmd(cmd, timeout=120)
    if not success:
        raise RuntimeError(f"chainctl libraries verify failed: {stderr.strip() or stdout.strip()}")
    try:
        return json.loads(stdout), pretty
    except json.JSONDecodeError as e:
        raise RuntimeError(f"chainctl did not return JSON: {e}\nOutput: {stdout[:300]}") from e


def extract_matched_coordinate(details: str) -> Optional[str]:
    """
    The `details` field from chainctl looks like:
      'Verified via SHA256 checksum comparison with Chainguard repository
       Maven artifact: org.apache.commons:commons-compress:1.28.0'
    Pull the coordinate out when present.
    """
    for prefix in ("Maven artifact: ", "Python package: ", "npm package: "):
        m = re.search(re.escape(prefix) + r"(\S+)", details)
        if m:
            return m.group(1)
    return None


# ───────────────────── cosign verify-blob wrapper ─────────────────────

def verify_bundle_with_cosign(
    artifact: Path, bundle: Path, trusted_root: Optional[str] = None
) -> tuple[bool, str]:
    """
    Run cosign verify-blob and return (success, pretty_command).
    """
    cmd = [
        "cosign", "verify-blob",
        "--bundle", str(bundle),
        "--certificate-identity-regexp", CHAINGUARD_ISSUER_REGEX,
        "--certificate-oidc-issuer-regexp", OIDC_ISSUER_REGEX,
    ]
    pretty_lines = [
        "cosign verify-blob \\",
        f"      --bundle {bundle} \\",
        f"      --certificate-identity-regexp '{CHAINGUARD_ISSUER_REGEX}' \\",
        f"      --certificate-oidc-issuer-regexp '{OIDC_ISSUER_REGEX}' \\",
    ]
    if trusted_root:
        cmd.extend(["--trusted-root", trusted_root])
        pretty_lines.append(f"      --trusted-root {trusted_root} \\")
    cmd.append(str(artifact))
    pretty_lines.append(f"      {artifact}")
    pretty = "\n".join(pretty_lines)

    success, stdout, stderr = run_cmd(cmd, timeout=60)
    combined = (stdout + "\n" + stderr).strip()
    ok = success and "Verified OK" in combined
    return ok, pretty


# ───────────────────────── Chain printer ──────────────────────────────

def _box_open(title: str) -> None:
    print(f"\n  ┌─ {title}")
    print("  │")


def _box_command(cmd_str: str) -> None:
    print("  │  Command:")
    for line in cmd_str.splitlines():
        print(f"  │    {line}")
    print("  │")


def _box_field(label: str, value: object) -> None:
    print(f"  │  {label:<18}{value}")


def _box_close(mark: str, message: str) -> None:
    print("  │")
    print(f"  └─ {mark} {message}")


def print_library_chain(result: LibraryVerifyResult, idx: int, total: int) -> None:
    """Print the 4-step verification chain in the same visual style as image mode."""
    header = f"[{idx}/{total}] {result.input_ref}"
    print(f"\n{'─' * 80}")
    print(f"  {header}")
    print(f"{'─' * 80}")

    # Step 1: Resolve URL / Acquire token (or just the path)
    coord_mode = result.artifact_url is not None
    _box_open("STEP 1: " + (
        "Acquire Pull Token & Resolve URL" if coord_mode else "Register Input Path"
    ))
    if coord_mode:
        print(f"  │  Coordinate:       {result.input_ref}")
        print(f"  │  Ecosystem:        {result.ecosystem}")
        print("  │")
        # Print the pull-token command (first entry of fetch_commands, if we have one)
        if result.fetch_commands:
            _box_command(result.fetch_commands[0])
        _box_field("Artifact URL:", result.artifact_url)
        if result.bundle_url:
            _box_field("Bundle URL:", result.bundle_url)
        _box_close("✓", "Pull token acquired, URL resolved")
    else:
        _box_field("Input:", result.input_ref)
        _box_field("Ecosystem:", result.ecosystem or "auto-detect")
        _box_close("✓", "Local input registered")

    if result.step_failed == 1:
        _print_skipped(2, "prior step failed")
        _print_skipped(3, "prior step failed")
        _print_skipped(4, "prior step failed")
        _print_verdict(result)
        return

    # Step 2: Fetch artifact (+ bundle if coord mode)
    if coord_mode:
        _box_open("STEP 2: Fetch Artifact" + (" & Bundle" if result.bundle_url else ""))
        # Print any fetch commands after the pull-token command (index 1+)
        for cmd_str in result.fetch_commands[1:]:
            _box_command(cmd_str)
        if result.artifact_sha256:
            _box_field("Artifact SHA-256:", result.artifact_sha256)
        if result.bundle_size is not None:
            _box_field("Bundle size:", f"{result.bundle_size} bytes")
        if result.step_failed == 2:
            _box_close("✗", result.error or "Fetch failed")
            _print_skipped(3, "prior step failed")
            _print_skipped(4, "prior step failed")
            _print_verdict(result)
            return
        _box_close("✓", "Downloaded to cache")

    # Step 3: chainctl libraries verify
    step3_num = "3" if coord_mode else "2"
    _box_open(f"STEP {step3_num}: Chainguard Catalog Verification")
    if result.chainctl_command:
        _box_command(result.chainctl_command)
    if result.chainctl_coverage is not None:
        _box_field("Coverage:", f"{result.chainctl_coverage:.0f}%")
    if result.matched_coordinate:
        _box_field("Matched:", result.matched_coordinate)
    if result.chainctl_details:
        first_line = result.chainctl_details.splitlines()[0] if result.chainctl_details else ""
        if first_line and first_line != result.matched_coordinate:
            _box_field("Details:", first_line)
    if result.step_failed == 3 or (
        result.chainctl_coverage is not None and result.chainctl_coverage == 0
    ):
        _box_close(
            "✗", result.error or f"Coverage {result.chainctl_coverage or 0}% — not in Chainguard catalog"
        )
    else:
        _box_close("✓", "Artifact matched in Chainguard repository")

    # Step 4: Sigstore bundle verification (coordinate mode + --with-signatures only)
    step4_num = "4" if coord_mode else "3"
    if result.bundle_path is not None:
        _box_open(f"STEP {step4_num}: Sigstore Bundle Verification")
        if result.cosign_command:
            _box_command(result.cosign_command)
        if result.signer_identity:
            _box_field("Signer SAN:", result.signer_identity)
        if result.rekor_log_index is not None:
            _box_field("Rekor logIndex:", result.rekor_log_index)
        if result.rekor_log_id:
            _box_field("Rekor logID:", result.rekor_log_id[:16] + "…")
        if result.integrated_time_iso:
            _box_field("Integrated at:", result.integrated_time_iso)
            _box_field(
                "Rekor URL:",
                f"https://search.sigstore.dev/?logIndex={result.rekor_log_index}",
            )
        if result.bundle_verified:
            _box_close("✓", "Signature cryptographically verified")
        else:
            _box_close("✗", result.error or "cosign verify-blob failed")
    elif coord_mode and result.ecosystem in ("python", "npm", "apk") and not result.bundle_url:
        # Bundle wasn't requested (no --with-signatures). Note and continue.
        pass

    _print_verdict(result)


def _print_skipped(step_num: int, reason: str) -> None:
    _box_open(f"STEP {step_num}: (skipped)")
    _box_close("○", f"Skipped — {reason}")


def _print_verdict(result: LibraryVerifyResult) -> None:
    _box_open("VERIFICATION RESULT")
    _box_field("Status:", result.status)
    if result.error:
        _box_field("Error:", result.error)
    if result.status == "VERIFIED":
        _box_close("✓", "Library verified: Chainguard catalog match + Sigstore bundle "
                        "signed by Chainguard Enforce, recorded in public transparency log.")
    elif result.status == "CATALOG_ONLY":
        _box_close("✓", "Library matched in Chainguard catalog (signature chain not requested).")
    elif result.status == "NO_MATCH":
        _box_close("✗", "Artifact not found in Chainguard catalog.")
    elif result.status == "SKIPPED":
        _box_close("○", "Input skipped.")
    else:
        _box_close("✗", "Verification failed.")


# ───────────────────────── CSV writer ─────────────────────────────────

CSV_COLUMNS = [
    "input_ref", "ecosystem", "artifact_path", "artifact_url", "artifact_sha256",
    "chainctl_coverage", "matched_coordinate",
    "bundle_url", "signer_identity", "rekor_log_index", "rekor_url",
    "integrated_time_iso", "status", "error",
]


def write_library_csv(path: str, results: list[LibraryVerifyResult]) -> None:
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(CSV_COLUMNS)
        for r in results:
            rekor_url = ""
            if r.rekor_log_index is not None:
                rekor_url = f"https://search.sigstore.dev/?logIndex={r.rekor_log_index}"
            w.writerow([
                r.input_ref, r.ecosystem,
                str(r.artifact_path) if r.artifact_path else "",
                r.artifact_url or "",
                r.artifact_sha256 or "",
                f"{r.chainctl_coverage:.0f}" if r.chainctl_coverage is not None else "",
                r.matched_coordinate or "",
                r.bundle_url or "",
                r.signer_identity or "",
                r.rekor_log_index if r.rekor_log_index is not None else "",
                rekor_url,
                r.integrated_time_iso or "",
                r.status,
                r.error or "",
            ])


# ────────────────────────── Orchestration ─────────────────────────────

def _verify_path_input(
    path_str: str, parent_org: str, ecosystem_hint: Optional[str] = None,
) -> LibraryVerifyResult:
    """
    Verify a local path (or OCI ref / remote URL supported by chainctl)
    with no coordinate-mode fetching.
    """
    r = LibraryVerifyResult(input_ref=path_str, ecosystem=ecosystem_hint or "unknown")
    try:
        # chainctl libraries verify accepts directories, JARs, archives, OCI refs, remote URLs
        target = Path(path_str) if os.path.exists(path_str) else Path(path_str)
        r.artifact_path = target if os.path.exists(path_str) else None
        data, pretty = run_chainctl_verify(target, parent_org)
        r.chainctl_command = pretty
        cov = data.get("artifactVerificationCoverage")
        if isinstance(cov, (int, float)):
            r.chainctl_coverage = float(cov)
        details = data.get("details", "") or ""
        r.chainctl_details = details
        r.matched_coordinate = extract_matched_coordinate(details)
        if r.chainctl_coverage and r.chainctl_coverage > 0:
            r.status = "CATALOG_ONLY"
            if not r.ecosystem or r.ecosystem == "unknown":
                # Infer ecosystem from the matched coordinate prefix
                if details.startswith("Maven") or "Maven artifact:" in details:
                    r.ecosystem = "java"
                elif "Python" in details:
                    r.ecosystem = "python"
                elif "npm" in details:
                    r.ecosystem = "npm"
        else:
            r.status = "NO_MATCH"
            r.step_failed = 3 if r.artifact_path is not None else 1
    except Exception as e:  # noqa: BLE001
        r.status = "ERROR"
        r.error = str(e)
        r.step_failed = 3
    return r


def _verify_coordinate_input(
    coord: str, ecosystem: str, parent_org: str,
    with_signatures: bool, trusted_root: Optional[str], cache_dir: Path,
) -> LibraryVerifyResult:
    r = LibraryVerifyResult(input_ref=coord, ecosystem=ecosystem)

    # ── Step 1: acquire pull token + resolve URL ──
    try:
        user, pw, token_cmd = acquire_pull_token(ecosystem, parent_org)
        r.fetch_commands.append(token_cmd)
    except Exception as e:  # noqa: BLE001
        r.status = "ERROR"
        r.error = f"pull-token: {e}"
        r.step_failed = 1
        return r

    try:
        if ecosystem == "java":
            artifact_url, bundle_url = resolve_java_url(coord)
            r.artifact_url = artifact_url
            if with_signatures:
                r.bundle_url = bundle_url
        elif ecosystem == "python":
            r.artifact_url = resolve_python_artifact_url(coord, (user, pw))
            # Chainguard publishes .bundle.json sidecars alongside the
            # python dist — same convention as Java. Fetch may 404 for
            # older artifacts; we handle that in the fetch step.
            if with_signatures:
                r.bundle_url = r.artifact_url + ".bundle.json"
        elif ecosystem == "npm":
            r.artifact_url = resolve_npm_tarball_url(coord)
            if with_signatures:
                r.bundle_url = r.artifact_url + ".bundle.json"
        elif ecosystem == "apk":
            r.artifact_url = resolve_apk_url(coord)
            if with_signatures:
                r.bundle_url = r.artifact_url + ".bundle.json"
        else:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")
    except Exception as e:  # noqa: BLE001
        r.status = "ERROR"
        r.error = f"url-resolve: {e}"
        r.step_failed = 1
        return r

    # ── Step 2: fetch artifact (+ bundle) ──
    try:
        assert r.artifact_url is not None
        artifact_path, art_cmd = fetch_to_cache(r.artifact_url, (user, pw), cache_dir)
        r.artifact_path = artifact_path
        r.fetch_commands.append(art_cmd)
        r.artifact_sha256 = sha256_of(artifact_path)

        if r.bundle_url:
            bundle_path, b_cmd = fetch_to_cache(r.bundle_url, (user, pw), cache_dir)
            r.bundle_path = bundle_path
            r.bundle_size = bundle_path.stat().st_size
            r.fetch_commands.append(b_cmd)
    except Exception as e:  # noqa: BLE001
        r.status = "ERROR"
        r.error = f"fetch: {e}"
        r.step_failed = 2
        return r

    # ── Step 3: chainctl libraries verify ──
    try:
        assert r.artifact_path is not None
        data, pretty = run_chainctl_verify(r.artifact_path, parent_org)
        r.chainctl_command = pretty
        cov = data.get("artifactVerificationCoverage")
        if isinstance(cov, (int, float)):
            r.chainctl_coverage = float(cov)
        r.chainctl_details = data.get("details", "") or ""
        r.matched_coordinate = extract_matched_coordinate(r.chainctl_details)
    except Exception as e:  # noqa: BLE001
        r.status = "ERROR"
        r.error = f"chainctl: {e}"
        r.step_failed = 3
        return r

    if not r.chainctl_coverage or r.chainctl_coverage == 0:
        r.status = "NO_MATCH"
        r.step_failed = 3
        return r

    # ── Step 4: cosign verify-blob (Java bundle only for now) ──
    if r.bundle_path:
        md = parse_bundle_metadata(r.bundle_path)
        r.signer_identity = md.get("signer_identity")  # type: ignore[assignment]
        r.rekor_log_index = md.get("rekor_log_index")  # type: ignore[assignment]
        r.rekor_log_id = md.get("rekor_log_id")  # type: ignore[assignment]
        r.integrated_time = md.get("integrated_time")  # type: ignore[assignment]
        r.integrated_time_iso = md.get("integrated_time_iso")  # type: ignore[assignment]

        try:
            ok, cosign_pretty = verify_bundle_with_cosign(
                r.artifact_path, r.bundle_path, trusted_root
            )
            r.cosign_command = cosign_pretty
            r.bundle_verified = ok
            if ok:
                r.status = "VERIFIED"
            else:
                r.status = "CATALOG_ONLY"
                r.error = "cosign verify-blob failed"
                r.step_failed = 4
        except Exception as e:  # noqa: BLE001
            r.status = "CATALOG_ONLY"
            r.error = f"cosign: {e}"
            r.step_failed = 4
    else:
        r.status = "CATALOG_ONLY"

    return r


def run_library_mode(args: argparse.Namespace) -> int:
    # Dependency check
    from verify_provenance import check_dependencies
    missing = check_dependencies()
    if missing:
        print(f"Error: Missing required tools: {', '.join(missing)}", file=sys.stderr)
        print("See PREREQUISITES.md for installation instructions.", file=sys.stderr)
        return 1

    # chainctl auth status (same gate as image mode)
    success, _, _ = run_cmd(["chainctl", "auth", "status"], timeout=10)
    if not success:
        print("Error: Not authenticated. Run 'chainctl auth login'", file=sys.stderr)
        return 1

    # Gather inputs
    coordinates: list[str] = list(args.coordinate or [])
    if args.from_file:
        with open(args.from_file) as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    coordinates.append(line)

    paths: list[str] = list(args.path or [])

    if not coordinates and not paths:
        print("Error: provide at least one --path, --coordinate, or --from-file",
              file=sys.stderr)
        return 2

    if coordinates and not args.ecosystem:
        print("Error: --ecosystem is required when using --coordinate or --from-file",
              file=sys.stderr)
        return 2

    # Apply --limit across the combined input set
    all_inputs: list[tuple[str, str]] = (
        [("path", p) for p in paths]
        + [("coordinate", c) for c in coordinates]
    )
    if args.limit and args.limit > 0:
        all_inputs = all_inputs[: args.limit]

    cache_dir = Path(args.cache_dir) if args.cache_dir else default_cache_dir()
    cache_dir.mkdir(parents=True, exist_ok=True)

    # Header
    title = "Chainguard Library  PROVENANCE VERIFICATION"
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║{title:^78}║")
    print("╠══════════════════════════════════════════════════════════════════════════════╣")
    print(f"║  Parent Org:       {args.parent_org:<58}║")
    if args.ecosystem:
        print(f"║  Ecosystem:        {args.ecosystem:<58}║")
    print(f"║  With Signatures:  {str(args.with_signatures):<58}║")
    print(f"║  Cache Dir:        {str(cache_dir):<58}║")
    print(f"║  Inputs:           {len(all_inputs):<58}║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")

    results: list[LibraryVerifyResult] = []
    total = len(all_inputs)
    for i, (kind, ref) in enumerate(all_inputs, 1):
        if kind == "path":
            r = _verify_path_input(ref, args.parent_org, args.ecosystem)
        else:
            r = _verify_coordinate_input(
                ref, args.ecosystem, args.parent_org,
                args.with_signatures, args.trusted_root, cache_dir,
            )
        results.append(r)
        print_library_chain(r, i, total)

    # CSV
    if args.csv_output:
        write_library_csv(args.csv_output, results)

    # Summary
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    print()
    print("═" * 80)
    print("  SUMMARY")
    print("═" * 80)
    print(f"  Parent Org:         {args.parent_org}")
    print(f"  Total Checked:      {len(results)}")
    print(f"  Verified:           {counts.get('VERIFIED', 0)}  (catalog + signature)")
    print(f"  Catalog Only:       {counts.get('CATALOG_ONLY', 0)}")
    print(f"  Not in Catalog:     {counts.get('NO_MATCH', 0)}")
    print(f"  Errors:             {counts.get('ERROR', 0)}")
    if args.csv_output:
        print(f"  CSV Output:         {args.csv_output}")
    print("═" * 80)

    # Exit status
    if counts.get("ERROR", 0) or counts.get("NO_MATCH", 0):
        return 1
    return 0
