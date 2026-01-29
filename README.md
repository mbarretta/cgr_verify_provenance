# Chainguard Image Provenance Verification

Verify that container images delivered to your organization were authentically built and signed by Chainguard.

## What This Tool Verifies

| Question | How It's Verified |
|----------|-------------------|
| **Is my image from Chainguard?** | Signature OIDC issuer is `issuer.enforce.dev` (Chainguard) |
| **Is it the same as the base image?** | `base_digest` label matches image in `chainguard-private` reference org |
| **Has it been tampered with?** | Signed digest in payload matches actual image digest |
| **Is the signature forged/backdated?** | Signature recorded in immutable Rekor transparency log with timestamp |

## Prerequisites

Install required CLI tools:
- `chainctl` - Chainguard CLI
- `crane` - Container registry tool
- `cosign` - Sigstore signing/verification

See [PREREQUISITES.md](PREREQUISITES.md) for installation instructions.

## Usage

### Authenticate First

```bash
chainctl auth login
```

### Delivery Verification (Default)

Verifies images were signed and delivered by Chainguard. No access to `chainguard-private` required.

```bash
./verify_provenance.py --customer-org your-org-name
```

This verifies:
1. Image has a valid signature from Chainguard
2. Delivery signature is recorded in Rekor transparency log
3. Extracts the claimed base digest for cross-customer comparison

### Full Verification

Requires access to `chainguard-private` reference organization.

```bash
./verify_provenance.py --customer-org your-org-name --full
```

Additionally verifies:

4. Base digest exists in reference org
5. Base image has valid build signature from Chainguard's GitHub workflow
6. Base image build signature is recorded in Rekor

### Options

```
--customer-org ORG    Customer organization to verify (required)
--full                Enable full verification mode (implies --verify-signatures)
--verify-signatures   Enable cryptographic signature verification
--limit N             Limit number of images to check
```

## Output

### Terminal Output

Detailed verification chain for each image:

```
════════════════════════════════════════════════════════════════════════════════
  IMAGE 1: python
════════════════════════════════════════════════════════════════════════════════

  ┌─ STEP 1: Extract Base Digest from Customer Image
  │
  │  Customer Image:  cgr.dev/your-org/python:latest
  │
  │  Base Digest: sha256:abc123...
  │
  └─ ✓ Base digest found

  ┌─ STEP 2: Download & Verify Customer Image Signature
  │
  │  Signature:      Found in OCI registry
  │  Signed Digest:  sha256:abc123...
  │
  └─ ✓ Signature found and payload verified

  ...
```

### CSV Export

Results are saved to `{customer-org}.csv` with columns:
- `image` - Image name
- `base_digest` - Full base digest for cross-customer comparison
- `rekor_status` - EXISTS or NOT_FOUND
- `rekor_log_index` - Transparency log entry index
- `rekor_url` - Link to view entry in Sigstore search
- `signature_status` - VALID or INVALID
- `verification_status` - DELIVERY_VERIFIED, VERIFIED, PARTIAL, etc.
- `error` - Error message if any

## Verification Statuses

| Status | Meaning |
|--------|---------|
| `DELIVERY_VERIFIED` | Signed by Chainguard + recorded in Rekor |
| `VERIFIED` | Base image exists in reference org + signed + in Rekor (full mode) |
| `PARTIAL` | Signature found but no Rekor entry |
| `NOT_FOUND` | Base digest not in reference org (full mode only) |
| `NO_SIG` | No signature found on image |
| `NO_BASE` | Image missing `org.opencontainers.image.base.digest` label |
| `ERROR` | Verification failed |

## Cross-Customer Comparison

To verify images are identical across customer organizations, compare the `base_digest` column from each org's CSV output:

```bash
# Run for multiple orgs
./verify_provenance.py --customer-org org-a
./verify_provenance.py --customer-org org-b

# Compare base digests
diff <(cut -d, -f2 org-a.csv | sort) <(cut -d, -f2 org-b.csv | sort)
```

Same `base_digest` = same source image from Chainguard.

## Manual Verification Commands

You can manually verify any step:

```bash
# Extract base digest from customer image
crane config cgr.dev/your-org/image:latest | \
  jq -r '.config.Labels["org.opencontainers.image.base.digest"]'

# Download and inspect signature
cosign download signature cgr.dev/your-org/image:latest | jq .

# Decode signature payload to see what was signed
cosign download signature cgr.dev/your-org/image:latest | \
  jq -r '.Payload' | base64 -d | jq '.critical.image'

# Verify signature cryptographically
cosign verify \
  --certificate-oidc-issuer-regexp 'https://issuer.enforce.dev.*' \
  --certificate-identity-regexp '.*' \
  cgr.dev/your-org/image:latest

# View Rekor entry
rekor-cli get --log-index 12345678
```

## How Verification Works

### Sigstore Integration

This tool uses [Sigstore](https://sigstore.dev/) infrastructure:

- **Cosign**: Downloads and verifies signatures attached to OCI images
- **Rekor**: Public transparency log that records all signatures with timestamps
- **Fulcio**: Issues short-lived certificates based on OIDC identity

### Chain of Trust

```
GitHub Actions (Chainguard CI)
         │
         ▼
    Fulcio CA ──► Issues certificate tied to GitHub OIDC token
         │
         ▼
    Cosign ──► Signs image with certificate
         │
         ▼
    Rekor ──► Records signature + timestamp in append-only log
         │
         ▼
    cgr.dev ──► Stores signed image + signature
         │
         ▼
    Chainguard Automation ──► Delivers to customer org with delivery signature
```

### Why Rekor Prevents Backdating

Rekor is an append-only log. Once a signature is recorded:
- The `integratedTime` timestamp is immutable
- Anyone can independently verify the entry exists
- An attacker cannot insert entries with past timestamps
- The log is publicly auditable at https://search.sigstore.dev/

## License

Apache 2.0
