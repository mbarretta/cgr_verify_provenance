# Chainguard Provenance Verification

Verify that **container images** delivered to your organization — and, as of 0.1.0, **library packages** pulled from Chainguard Libraries — were authentically built and signed by Chainguard.

The tool has two subcommands:

| Subcommand | Verifies |
|---|---|
| `image` | OCI container images from `cgr.dev/<org>/…` (delivery or full build chain) |
| `library` | Library packages from `libraries.cgr.dev/{java,python,javascript}/…` via `chainctl libraries verify` + optional Sigstore bundle verification |

## What This Tool Verifies

| Question | How It's Verified |
|----------|-------------------|
| **Is my image from Chainguard?** | Signature OIDC issuer is `issuer.enforce.dev` (Chainguard) |
| **Is it the same as the base image?** | `base_digest` label matches image in `chainguard-private` reference org |
| **Has it been tampered with?** | Signed digest in payload matches actual image digest |
| **Is the signature forged/backdated?** | Rekor entry's SignedEntryTimestamp cryptographically verified against Rekor's public key via `cosign verify` (not just a logIndex read from the bundle JSON — that alone could be forged) |
| **Who built it, from what source?** (`--verify-attestations`) | SLSA v1.0 provenance attestation retrieved, cosign-verified, and its in-toto subject digest is asserted to match the image digest |
| **What's actually inside it?** (`--verify-attestations`) | SPDX (preferred) or CycloneDX SBOM attestation retrieved, cosign-verified, subject-digest-matched, and parsed for package count, license set, and a PURL sample |
| **What vulnerabilities does it have?** (`--scan`) | `grype` scan produces both raw CVE counts (audit record) and actionable counts after applying the Chainguard-signed OpenVEX attestation (`--vex` filter). Unverified/substituted VEX is rejected — only a signed, subject-matched VEX doc can suppress findings |
| **Any actively-exploited vulnerabilities unadjudicated?** (`--scan`) | Actionable (VEX-adjusted) CVEs are cross-checked against the CISA Known Exploited Vulnerabilities (KEV) catalog, cached locally for 24h. Hits include the BOD 22-01 deadline and ransomware-use flag; the image's overall verdict is demoted to `KEV_HIT` |
| **Is this image fresh? Is it EOL?** (`--max-age-days N`) | Parses `config.created` from the image manifest; flags `STALE` when age exceeds the threshold; pulls Chainguard's end-of-life attestation and flags `EOL` when present (overrides age) |
| **Is this a FIPS variant?** | Detected from image name/tag (`-fips` suffix); surfaces "verify CMVP cert manually" reminder for the auditor |
| **Who (in GitHub) built this image?** | Fulcio cert OID extensions surfaced from `cosign verify` output: workflow ref, commit SHA, trigger, run ID — for the public-registry build path |
| **Does the attached SBOM describe the image I'm running?** (`--sbom-drift`) | Runs `syft` locally against the image, diffs the PURL set against the attested SBOM's PURL set. Catches registry-side SBOM-attestation substitution |
| **Can I verify without network?** (`--trusted-root`) | Accepts a Sigstore TUF `trusted_root.json` and passes it to all cosign invocations, enabling air-gapped verification |
| **Give me the evidence, not just a green check** (`--evidence-bundle <dir>`) | Writes per-image subdirectory with every DSSE envelope, SBOM doc, grype output, KEV hits, policy eval, a Markdown summary, a control-mapping JSON (SSDF / NIST 800-161/190 / FedRAMP / CMMC / CISA BOD), and a SHA256SUMS seal |

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

### Image mode — Delivery Verification (default)

Verifies images were signed and delivered by Chainguard. No access to `chainguard-private` required.

```bash
./verify_provenance.py image --customer-org your-org-name
```

This verifies:
1. Image has a valid signature from Chainguard
2. Delivery signature is recorded in Rekor transparency log
3. Extracts the claimed base digest for cross-customer comparison

### Image mode — Full Verification

Requires access to `chainguard-private` reference organization.

```bash
./verify_provenance.py image --customer-org your-org-name --full
```

`--full` means "run every verification check we have." It implies both
`--verify-signatures` and `--verify-attestations`, so a single flag
produces:

4. Base digest exists in reference org
5. Base image has valid build signature from Chainguard's GitHub workflow
6. Base image build signature is recorded in Rekor and SET-verified
7. SLSA v1.0 provenance, SPDX (or CycloneDX) SBOM, apko image config, and
   (when present) end-of-life attestations retrieved, cosign-verified,
   and in-toto subject-digest-matched against the image
8. Policy allowlist evaluated against the SLSA `builder.id` + source URI
9. Freshness + FIPS variant surfaced

**Not** implied by `--full`: `--scan` (vulnerability scanning is a
separate concern, requires `grype`, and takes minutes per image) and
`--sbom-drift` (requires `syft`). Layer either on as needed.

### Image mode — Attestation Verification (optional)

Add `--verify-attestations` in either delivery or full mode to additionally
fetch and verify Chainguard-signed **SLSA v1.0 provenance** and **SBOM**
(SPDX or CycloneDX) attestations:

```bash
./verify_provenance.py image --customer-org your-org --verify-attestations
./verify_provenance.py image --customer-org your-org --full --verify-attestations
```

For each image the tool:

1. Runs `cosign verify-attestation --type slsaprovenance1 …` then the same
   for `--type spdxjson` (falling back to `--type cyclonedx` if SPDX is
   absent). Cosign handles Fulcio certificate validation + Rekor entry
   verification.
2. Decodes the in-toto Statement from each returned DSSE envelope.
3. **Asserts that the Statement's `subject[].digest.sha256` matches the image
   digest being verified** — this is the check that prevents an attacker
   from re-attaching a valid attestation that describes a *different* image.
4. Parses the predicate:
   - **SLSA**: builder identity, build type, source repo + commit digest,
     invocation ID, and timestamps.
   - **SBOM**: package count, unique SPDX license identifier set, and a
     sample of package URLs (PURLs). An SBOM that is signed but contains
     zero packages is flagged as `EMPTY` — signed metadata that proves
     nothing about image content is not trustworthy evidence.

If a signed attestation is found but its subject digest does not match the
image, the overall verification status becomes `ATTESTATION_FAILED` — even if
the image's own signature + Rekor entry are valid.

**Compatibility note**: Chainguard ships SPDX on every image, CycloneDX on
customer-org images built after 2026-01-29. The tool prefers SPDX and
transparently falls back to CycloneDX so both pre- and post-cutover images
populate an SBOM record.

### Image mode — Policy Allowlists

By default, the tool uses hardcoded regexes for the OIDC issuer, signer
identity, SLSA builder ID, and SLSA source repository. Supply
`--policy-file <path>` to override any or all of them with your own JSON:

```bash
./verify_provenance.py image --customer-org your-org --verify-attestations \
    --policy-file my-policy.json
```

The file shape (all fields optional, defaults inherited per-field):

```json
{
  "customer": {
    "cosign_oidc_issuer_regex": "^https://issuer\\.enforce\\.dev.*$",
    "cosign_identity_regex": ".*",
    "allowed_builder_ids": ["^https?://issuer\\.enforce\\.dev/.*$"],
    "allowed_source_uris": ["^git\\+?https://github\\.com/chainguard-images/.*$"]
  },
  "build": {
    "cosign_oidc_issuer_regex": "^https://token\\.actions\\.githubusercontent\\.com.*$",
    "cosign_identity_regex": ".*chainguard.*",
    "allowed_builder_ids": ["^https://token\\.actions\\.githubusercontent\\.com/chainguard-images/images/.*$"],
    "allowed_source_uris": ["^git\\+?https://github\\.com/chainguard-images/.*$"]
  }
}
```

- `customer` applies in delivery mode; `build` applies in `--full` mode.
- The two `cosign_*_regex` fields are passed to `cosign verify` and
  `cosign verify-attestation`. Tightening them restricts who can sign.
- `allowed_builder_ids` + `allowed_source_uris` are regex allowlists
  evaluated against the parsed SLSA provenance after cosign has
  cryptographically verified it. A verified-but-off-allowlist attestation
  produces a `POLICY_VIOLATION` verdict.
- Empty allowlists (e.g. `"allowed_builder_ids": []`) opt out of that
  check entirely.
- The loader fails closed: unknown fields or invalid regexes raise an
  error rather than silently falling back to defaults. Top-level keys
  starting with `_` (e.g. `_comment`) are ignored for documentation.

See [example-policy.json](example-policy.json) for a full commented example.

### Image mode — Vulnerability Scan + VEX (optional)

Add `--scan` in either delivery or full mode to run a grype vulnerability
scan against each image. When a Chainguard-signed OpenVEX attestation is
available (and its in-toto subject matches the image), it is applied as a
`grype --vex <file>` filter to produce an actionable CVE count alongside
the raw count:

```bash
./verify_provenance.py image --customer-org your-org --scan
```

Two grype invocations happen per image when VEX is present:

1. **Raw scan** — no VEX filter, produces the auditor's CVE-count-of-record.
2. **VEX-adjusted scan** — applies the Chainguard OpenVEX doc; produces
   the "actionable findings" count a CISO uses to gate.

Both counts are printed and written to the CSV (`vuln_total` is VEX-adjusted;
raw counts are in the detailed chain output). An unverified or subject-mismatched
OpenVEX document is **rejected** — the tool will not silently suppress findings
based on signed metadata it can't trust.

`--scan` implies `--verify-attestations` (we need the cryptographic VEX pull).
Requires `grype` in `PATH`; see [PREREQUISITES.md](PREREQUISITES.md).

### CISA KEV Cross-Check (automatic with `--scan`)

After the VEX-adjusted scan completes, each image's actionable CVE list is
cross-checked against the **CISA Known Exploited Vulnerabilities (KEV)
catalog**. The catalog is fetched from `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
and cached at `~/.cache/verify-provenance/cisa_kev.json` for 24 hours (one
fetch per tool invocation; reused across all images).

A KEV hit means the CVE is known to be actively exploited in the wild and
the producer has NOT adjudicated it via signed VEX. Any such hit demotes
the overall `verification_status` to `KEV_HIT`, per the plan's "hard-fail"
guidance aligned with BOD 22-01.

If the CISA fetch fails and no cache exists, the KEV step is skipped with
a warning — the tool doesn't block on CISA availability. If a stale cache
is present, it's used with a visible freshness note.

### Image mode options

```
verify-provenance image --customer-org ORG        Customer organization (required)
                        --full                    All verification checks: implies
                                                  --verify-signatures + --verify-attestations
                                                  (NOT --scan, which is opt-in)
                        --verify-signatures       Enable cryptographic signature verification
                        --verify-attestations     Fetch + verify SLSA provenance + SBOM + apko
                                                  (asserts in-toto subject == image digest)
                        --policy-file FILE        Override default signer/builder allowlists (JSON)
                        --scan                    Run grype + apply OpenVEX + KEV cross-check
                        --max-age-days N          Flag images older than N days as STALE
                        --trusted-root FILE       Offline / air-gap mode (Sigstore TUF root)
                        --sbom-drift              Run syft locally, diff against attested SBOM
                        --evidence-bundle DIR     Emit audit-grade per-image evidence directory
                        --csv-output FILE         Write full verification CSV to disk (else no file)
                        -v / --verbose            Print the full per-image verification chain
                                                  (default: one-row-per-image summary table)
                        --format {table,json,csv} End-of-run summary format (default: table).
                                                  json/csv route banner + progress to stderr.
                        --limit N                 Limit number of images to check
```

### Output format

By default the tool prints a single summary table at the end of the run,
one row per image and one column per check. **Columns for checks that
weren't run are omitted entirely**, so a run without `--scan` doesn't
show misleading `0C/0H/0M/0L` vuln rows and a run without
`--verify-attestations` doesn't show empty `SLSA`/`SBOM`/`POLICY`
columns. This applies to the summary table, `--format csv`, `--format
json`, and the on-disk CSV (`--csv-output`).

With `--full` (or `--scan` layered on top):

```
IMAGE         VERDICT             SIG    REKOR  SLSA              SBOM           POLICY  VULN          KEV  AGE         FIPS
------------  ------------------  -----  -----  ----------------  -------------  ------  ------------  ---  ----------  ----
python        VERIFIED            VALID  ✓      VERIFIED          VERIFIED(287)  PASS    0C/0H/0M/0L*  0    2d          no
nginx-legacy  KEV_HIT             VALID  ✓      VERIFIED          VERIFIED(100)  PASS    2C/5H/10M/3L  1    180d STALE  yes
redis-bad     ATTESTATION_FAILED  VALID  ✓      SUBJECT_MISMATCH  VERIFIED       N/A     N/A           N/A  5d          no

  Legend: REKOR ✓=SET cryptographically verified, ✗=bundle claim only, -=absent
          VULN  C/H/M/L counts; trailing * = OpenVEX adjudication applied
```

Use `--verbose` to get the old per-image step-by-step chain output in
addition to the summary. Use `--format json` for machine-readable output
pipeable to `jq`; `--format csv` for the same rows as CSV on stdout:

```bash
./verify_provenance.py image --customer-org my-org --format json \
    | jq '.results[] | select(.verdict == "KEV_HIT")'
```

In `json` and `csv` modes, banner + progress lines are routed to stderr
so stdout contains only the machine-readable data.

### Library-mode ecosystems

```bash
# Java
./verify_provenance.py library --parent-org my-org --ecosystem java \
    --coordinate org.apache.commons:commons-compress:1.28.0 --with-signatures

# Python (Sigstore bundle verification now wired)
./verify_provenance.py library --parent-org my-org --ecosystem python \
    --coordinate requests==2.31.0 --with-signatures

# npm (Sigstore bundle verification now wired)
./verify_provenance.py library --parent-org my-org --ecosystem npm \
    --coordinate lodash@4.17.21 --with-signatures

# APK (Wolfi-built OS packages)
./verify_provenance.py library --parent-org my-org --ecosystem apk \
    --coordinate glibc-2.39-r1 --with-signatures
```

### Library mode

Verifies Chainguard Library packages. Accepts local paths (files, directories,
OCI refs, remote URLs — anything `chainctl libraries verify` accepts) and/or
library coordinates that the tool resolves to `libraries.cgr.dev` URLs,
downloads, and verifies.

```bash
# Verify a local JAR via chainctl's catalog match
./verify_provenance.py library --parent-org my-org --path ./myapp.jar

# Fetch + verify a coordinate, including Sigstore bundle signature
./verify_provenance.py library --parent-org my-org \
  --ecosystem java \
  --coordinate org.apache.commons:commons-compress:1.28.0 \
  --with-signatures \
  --csv-output java-verify.csv

# Batch from a file (one coordinate per line)
./verify_provenance.py library --parent-org my-org \
  --ecosystem java --from-file java-coords.txt --with-signatures
```

When `--with-signatures` is set for a Java coordinate, the tool:

1. Acquires a short-lived pull token (`chainctl auth pull-token create --repository=java --parent=<org> --ttl=1h`).
2. Downloads the artifact and the `<file>.bundle.json` Sigstore bundle from `libraries.cgr.dev`.
3. Runs `chainctl libraries verify` for the catalog coverage verdict.
4. Runs `cosign verify-blob --bundle <b> --certificate-identity-regexp 'https://issuer.enforce.dev/.*'` for the cryptographic chain. Offline-capable when a `--trusted-root` file is provided.

### Library mode options

```
verify-provenance library --parent-org ORG         Parent org (required)
                          --path PATH              Local path or OCI ref (repeatable)
                          --coordinate COORD       Library coordinate (repeatable)
                          --from-file FILE         Read coordinates from file
                          --ecosystem {java|python|npm}
                          --with-signatures        Fetch + verify Sigstore bundles
                          --trusted-root FILE      Sigstore TUF root for offline verify
                          --cache-dir DIR          Download cache (default ~/.cache/verify-provenance/libraries)
                          --csv-output FILE        Write results to CSV
                          --limit N                Limit number of inputs processed
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

Pass `--csv-output <path>` to emit the full verification CSV to disk.
Without the flag, no file is written (use `--format csv` to pipe the
summary to stdout instead). The CSV columns are:
- `image` - Image name
- `base_digest` - Full base digest for cross-customer comparison
- `rekor_status` - EXISTS or NOT_FOUND
- `rekor_log_index` - Transparency log entry index
- `rekor_url` - Link to view entry in Sigstore search. Will contain
  `MISMATCH: bundle logIndex=X, verified logIndex=Y` if the bundle's
  claimed logIndex disagrees with the one cosign verified (signal of
  registry-side bundle tampering).
- `rekor_verified` - `true` if Rekor's SignedEntryTimestamp was
  cryptographically verified by `cosign verify` (authoritative). `false`
  means a logIndex may appear in the bundle JSON but was not verified.
- `signature_status` - VALID or INVALID
- `verification_status` - DELIVERY_VERIFIED, VERIFIED, PARTIAL, etc.
- `slsa_status` - SLSA attestation result: `N/A` (check not run),
  `VERIFIED`, `SUBJECT_MISMATCH`, `NOT_FOUND`, or `UNVERIFIED`
- `sbom_status` - SBOM attestation result: `N/A`, `VERIFIED`,
  `SUBJECT_MISMATCH`, `EMPTY` (signed but zero packages), `NOT_FOUND`,
  or `UNVERIFIED`
- `sbom_format` - `spdx` or `cyclonedx` (empty when no SBOM was verified)
- `sbom_package_count` - Number of packages in the verified SBOM
- `policy_status` - Policy allowlist result: `N/A` (check not run),
  `PASS`, or `VIOLATION`
- `policy_violations` - Semicolon-separated summary of failed checks
  (e.g. `builder_id=https://evil-fork/ci; source_uri=(empty)`)
- `vuln_status` - `N/A` (scan not run), `CLEAN`, `FINDINGS`, or `ERROR`
- `vuln_critical` / `vuln_high` / `vuln_medium` / `vuln_low` / `vuln_total` -
  VEX-adjusted (actionable) counts by severity
- `vex_applied` - `true` if a signed OpenVEX attestation was used to filter
- `kev_status` - `N/A`, `CLEAN`, or `HIT` for CISA KEV cross-check
- `kev_count` - Number of actionable CVEs in the KEV catalog (unadjudicated)
- `kev_cves` - Semicolon-separated list `CVE-ID(due=YYYY-MM-DD); …` per BOD 22-01
- `error` - Error message if any

## Verification Statuses

| Status | Meaning |
|--------|---------|
| `DELIVERY_VERIFIED` | Signed by Chainguard + recorded in Rekor |
| `VERIFIED` | Base image exists in reference org + signed + in Rekor (full mode) |
| `PARTIAL` | Signature found but no Rekor entry |
| `NOT_FOUND` | Base digest not in reference org (full mode only) |
| `ATTESTATION_FAILED` | `--verify-attestations`: found a signed attestation but its in-toto subject digest describes a different image |
| `POLICY_VIOLATION` | `--verify-attestations`: attestation verified but its SLSA builder.id or source URI is not on the configured allowlist |
| `KEV_HIT` | `--scan`: image has one or more actionable (post-VEX) CVEs that appear in the CISA KEV catalog — hard-fail per BOD 22-01 guidance |
| `NO_SIG` | No signature found on image |
| `NO_BASE` | Image missing `org.opencontainers.image.base.digest` label |
| `ERROR` | Verification failed |

## Cross-Customer Comparison

To verify images are identical across customer organizations, compare the `base_digest` column from each org's CSV output:

```bash
# Run for multiple orgs
./verify_provenance.py image --customer-org org-a --csv-output org-a.csv
./verify_provenance.py image --customer-org org-b --csv-output org-b.csv

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
