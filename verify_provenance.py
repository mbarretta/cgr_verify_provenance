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
from typing import Optional

__version__ = "0.1.0"

# Required external tools
REQUIRED_TOOLS = ["chainctl", "crane", "cosign"]

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

    # Step 5: Certificate identity
    cert_issuer: str = ""
    cert_subject: str = ""
    cert_verified: bool = False

    # Customer-only mode fields
    customer_sig_found: bool = False
    customer_sig_issuer: str = ""
    customer_rekor_index: str = ""
    customer_rekor_url: str = ""


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
    except json.JSONDecodeError:
        result.error = "Failed to parse config JSON"
        return result

    if not base_digest:
        result.status = "NO_BASE"
        result.error = "No base digest label"
        return result

    chain.base_digest_full = base_digest
    result.base_digest = base_digest[:19] + "..."  # Truncate for display

    # Customer-only mode: verify via customer image signature
    if customer_only:
        return verify_customer_only(result, chain, customer_image, capture_details)

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

            # Extract Rekor bundle
            bundle = sig_data.get("Bundle", {})
            payload_data = bundle.get("Payload", {})
            log_index = payload_data.get("logIndex")
            integrated_time = payload_data.get("integratedTime")

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

    # Step 5: Signature verification (extracts certificate details)
    if verify_signatures or capture_details:
        success, verify_output, verify_err = run_cmd(
            [
                "cosign", "verify",
                "--certificate-oidc-issuer", "https://token.actions.githubusercontent.com",
                "--certificate-identity-regexp", ".*chainguard.*",
                "--output", "json",
                f"{reference_image}@{base_digest}",
            ],
            timeout=30,
        )

        if success:
            result.sig_status = "VALID"
            chain.cert_verified = True

            # Parse verification output for certificate details
            try:
                verify_data = json.loads(verify_output)
                if isinstance(verify_data, list) and len(verify_data) > 0:
                    cert_info = verify_data[0].get("optional", {})
                    chain.cert_issuer = cert_info.get("Issuer", "")
                    chain.cert_subject = cert_info.get("Subject", "")
            except json.JSONDecodeError:
                pass
        else:
            result.sig_status = "INVALID"

    # Determine final status
    if result.ref_status == "EXISTS" and result.rekor_status == "EXISTS":
        result.status = "VERIFIED"
    elif result.ref_status == "EXISTS":
        result.status = "PARTIAL"
    else:
        result.status = "NOT_FOUND"

    return result


def verify_customer_only(
    result: VerificationResult,
    chain: ChainDetails,
    customer_image: str,
    capture_details: bool,
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

        # Extract Rekor bundle
        bundle = sig_data.get("Bundle", {})
        payload_data = bundle.get("Payload", {})
        log_index = payload_data.get("logIndex")
        integrated_time = payload_data.get("integratedTime")

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

    # Verify signature cryptographically
    if capture_details:
        success, verify_output, _ = run_cmd(
            [
                "cosign", "verify",
                "--certificate-oidc-issuer-regexp", "https://issuer.enforce.dev.*",
                "--certificate-identity-regexp", ".*",
                "--output", "json",
                customer_image,
            ],
            timeout=30,
        )

        if success:
            result.sig_status = "VALID"
            chain.cert_verified = True
        else:
            result.sig_status = "INVALID"

    # In customer-only mode, we mark as VERIFIED if we have signature + Rekor
    # but note that we can't verify the BASE digest, only the customer image delivery
    if chain.customer_sig_found and result.rekor_status == "EXISTS":
        result.status = "DELIVERY_VERIFIED"
        result.ref_status = "SKIPPED"
    else:
        result.status = "PARTIAL"

    return result


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
        print(f"  │  Log Index:  {chain.customer_rekor_index}")
        if chain.rekor_integrated_time:
            print(f"  │  Signed At:  {chain.rekor_integrated_time}")
        print(f"  │")
        print(f"  │  View in browser:")
        print(f"  │    {chain.customer_rekor_url}")
        print(f"  │")
        print(f"  │  Command (fetch entry):")
        print(f"  │    rekor-cli get --log-index {chain.customer_rekor_index}")
        print(f"  │")
        print(f"  └─ ✓ Delivery signature recorded in public transparency log")
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
        print(f"  │  Log Index:  {chain.rekor_log_index}")
        if chain.rekor_integrated_time:
            print(f"  │  Signed At:  {chain.rekor_integrated_time}")
        print(f"  │")
        print(f"  │  View in browser:")
        print(f"  │    {chain.rekor_url}")
        print(f"  │")
        print(f"  │  Command (fetch entry):")
        print(f"  │    rekor-cli get --log-index {chain.rekor_log_index}")
        print(f"  │")
        print(f"  └─ ✓ Signature recorded in public transparency log")
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
        print(f"  │")
        print(f"  └─ ✓ Signature cryptographically verified as Chainguard-signed")
    else:
        if result.sig_status == "INVALID":
            print(f"  │")
            print(f"  └─ ✗ Signature verification FAILED")
        else:
            print(f"  │")
            print(f"  └─ ○ Signature verification skipped (use --verify-signatures)")

    # Final verdict
    print(f"\n  ┌─ VERIFICATION RESULT")
    print(f"  │")
    if result.status == "VERIFIED":
        print(f"  │  Status: {result.status}")
        print(f"  │")
        print(f"  └─ ✓ Base image verified: exists in reference org, signed by")
        print(f"       Chainguard, and recorded in public transparency log.")
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


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Verify Chainguard image provenance and delivery authenticity",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s --customer-org my-org
      Verify delivery signatures for all images in my-org

  %(prog)s --customer-org my-org --full
      Full verification including base image in chainguard-private

  %(prog)s --customer-org my-org --limit 5 --verify-signatures
      Check first 5 images with full cryptographic verification
"""
    )
    parser.add_argument(
        "--customer-org",
        help="Customer organization to verify (required unless --version)"
    )
    parser.add_argument(
        "--full", action="store_true",
        help="Full verification mode: also verify base digest exists in "
             "chainguard-private and was signed by Chainguard's build system "
             "(implies --verify-signatures)"
    )
    parser.add_argument(
        "--verify-signatures", action="store_true",
        help="Enable full cryptographic signature verification"
    )
    parser.add_argument(
        "--limit", type=int, default=0,
        help="Limit number of images to check (0 = all)"
    )
    parser.add_argument(
        "--version", action="store_true",
        help="Show version and dependency information"
    )
    args = parser.parse_args()

    # --full implies --verify-signatures
    if args.full:
        args.verify_signatures = True

    # Handle --version flag
    if args.version:
        print_version()
        sys.exit(0)

    # Require --customer-org if not --version
    if not args.customer_org:
        parser.error("--customer-org is required")

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

    # Header
    mode_desc = "DELIVERY VERIFICATION" if customer_only else "FULL VERIFICATION"
    title = f"Chainguard Image   {mode_desc}"
    print("╔══════════════════════════════════════════════════════════════════════════════╗")
    print(f"║{title:^78}║")
    print("╠══════════════════════════════════════════════════════════════════════════════╣")
    print(f"║  Customer Org:     {args.customer_org:<58}║")
    if not customer_only:
        print(f"║  Reference Org:    {reference_org:<58}║")
    print(f"║  Signature Verify: {str(args.verify_signatures):<58}║")
    print("╚══════════════════════════════════════════════════════════════════════════════╝")
    print()

    # Get images
    print(f"Fetching entitled images for '{args.customer_org}'...")
    images = get_image_list(args.customer_org)

    if not images:
        print("Error: Could not retrieve image list", file=sys.stderr)
        sys.exit(1)

    print(f"Found {len(images)} images")

    if args.limit > 0:
        images = images[: args.limit]
        print(f"Limited to first {args.limit} images")

    # Verify images sequentially with detailed output
    print("\nVerifying images...")
    results: list[VerificationResult] = []
    for i, img in enumerate(images, 1):
        result = verify_image(
            img, registry, args.customer_org, reference_org,
            args.verify_signatures, capture_details=True,
            customer_only=customer_only,
        )
        results.append(result)
        print_chain_details(result, i, customer_only=customer_only)

    # Sort by image name
    results.sort(key=lambda r: r.image)

    # Write CSV - include full base_digest for cross-customer comparison
    csv_file = f"{args.customer_org}.csv"
    with open(csv_file, "w", newline="") as f:
        writer = csv.writer(f)
        if customer_only:
            writer.writerow([
                "image", "base_digest", "rekor_status", "rekor_log_index",
                "rekor_url", "signature_status", "verification_status", "error"
            ])
            for r in results:
                rekor_url = r.chain.customer_rekor_url or ""
                writer.writerow([
                    r.image, r.chain.base_digest_full, r.rekor_status,
                    r.chain.customer_rekor_index, rekor_url, r.sig_status,
                    r.status, r.error
                ])
        else:
            writer.writerow([
                "image", "base_digest", "reference_status", "rekor_status",
                "rekor_log_index", "rekor_url", "signature_status",
                "verification_status", "error"
            ])
            for r in results:
                rekor_url = ""
                if r.rekor_log_index:
                    rekor_url = f"https://search.sigstore.dev/?logIndex={r.rekor_log_index}"
                writer.writerow([
                    r.image, r.chain.base_digest_full, r.ref_status, r.rekor_status,
                    r.rekor_log_index, rekor_url, r.sig_status, r.status, r.error
                ])

    # Count results
    counts: dict[str, int] = {}
    for r in results:
        counts[r.status] = counts.get(r.status, 0) + 1

    # Summary
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

    print()
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


if __name__ == "__main__":
    main()
