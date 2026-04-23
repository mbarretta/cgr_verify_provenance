# Verification Expansion — Implementation Record

## Context

`verify-provenance` started this work cycle as a two-mode (`image` / `library`)
tool that proved **delivery authenticity**: cosign signature + Rekor
`logIndex` extraction + (with `--full`) a base-digest cross-check into
`chainguard-private` signed by the GitHub Actions builder identity, plus
`chainctl libraries verify` for libraries.

Research across two axes — (1) the Chainguard/Sigstore/SLSA/in-toto
technical stack and (2) accreditation / CISO concerns (NIST SSDF, 800-161,
800-190, FedRAMP SR family, Iron Bank/SWFT, CISA KEV, NTIA SBOM minimum
elements, Chainguard FIPS/STIG positioning) — surfaced one consistent gap:
**the tool verified that Chainguard signed something, but never looked at
what Chainguard attested**. Accreditors want independently-verified
evidence of SLSA provenance, SBOM accuracy, vulnerability posture, VEX
adjudication, freshness, and FIPS/STIG posture — not merely a green check
on a signature.

The plan below drove the expansion from a signature verifier into a
**verification + evidence-collection** tool that an accreditor can accept
as proof of control satisfaction. This document captures both the original
tiered plan and what actually shipped.

## Original tiered plan (all three tiers delivered)

### P0 — correctness fixes that make the tool trustworthy

| # | Check | Status |
|---|---|---|
| P0-1 | In-toto `subject[].digest` assertion on every attestation read | **shipped** |
| P0-2 | Retrieve + verify SLSA v1.0 provenance | **shipped** |
| P0-3 | Retrieve + verify SPDX (fallback CycloneDX) SBOM | **shipped** |
| P0-4 | Configurable signer / builder / source allowlists | **shipped** |
| P0-5 | Rekor SET verification claim (not just logIndex extraction) | **shipped** |

### P1 — accreditor-facing checks

| # | Check | Status |
|---|---|---|
| P1-1 | grype scan + OpenVEX adjudication | **shipped** |
| P1-2 | CISA KEV catalog cross-check | **shipped** |
| P1-3 | Image age + Chainguard EOL attestation | **shipped** |
| P1-4 | FIPS variant detection + CMVP surfacing | **shipped** (tag-based detection only; see deviations) |
| P1-5 | Hash-sealed evidence bundle with control mappings | **shipped** |

### P2 — completeness gaps

| # | Check | Status |
|---|---|---|
| P2-1 | Offline / air-gapped image verification (`--trusted-root`) | **shipped** |
| P2-2 | Python/npm library Sigstore bundles + APK ecosystem | **shipped** |
| P2-3 | SBOM drift detection (syft vs attested) | **shipped** |
| P2-4 | apko image-config attestation retrieval | **shipped** |
| P2-5 | Cosign bundle v0.3 / Fulcio cert-extension surfacing | **shipped** |

## Deviations from the plan

1. **Policy file format: JSON, not YAML.** The original plan suggested YAML
   for readability, but that would require adding PyYAML as a runtime
   dependency; the project had zero runtime deps and keeping it that way
   was a stronger signal than the small readability gain. `policy.py` uses
   stdlib `json` and tolerates `_comment`-prefixed top-level keys as an
   escape hatch for human-readable annotations.

2. **Automatic KEV cross-check instead of an opt-in flag.** The plan
   treated KEV as a stand-alone check. Implementation makes it automatic
   whenever `--scan` runs (no separate flag). The overhead is a single
   daily-cached catalog fetch per tool invocation. Opting out would require
   passing `--no-kev` which wasn't added; if a user genuinely doesn't want
   the catalog query, they can skip `--scan`.

3. **FIPS detection scope reduced.** The plan suggested predicate-based
   detection via a Chainguard FIPS attestation. That attestation's schema
   is evolving and I didn't want to commit to a format that might change.
   Shipped implementation uses tag/name `-fips` substring detection (the
   current Chainguard convention) and surfaces a "verify CMVP cert on the
   NIST Active list manually" reminder. Predicate-based detection is a
   clean follow-up once the schema stabilizes.

4. **STIG report retrieval deferred.** Plan called for retrieving the
   Chainguard-published STIG report artifact. Skipped this increment
   because the referrer path for those artifacts isn't standard across
   images; a general implementation needs research. Not a blocker for
   FedRAMP / DoD use cases — those environments typically pull the STIG
   report out-of-band anyway.

5. **Evidence bundle is a directory, not an OCI artifact.** Plan listed
   both as options. Directory won because auditors want to `grep` and
   `diff` directly, and tarball packaging is trivial to add later.

6. **OpenVEX / EOL / apko retrieval is opt-in, not automatic.** The plan
   said "pull everything". In practice, each retrieval is a separate cosign
   network round-trip, so I gated them behind the flags that actually
   consume them:
   - OpenVEX: pulled only when `--scan` (VEX consumer)
   - EOL: pulled when `--max-age-days > 0` OR `--verify-attestations`
   - apko: pulled when `--verify-attestations`
   - SLSA + SBOM: always pulled when `--verify-attestations`

7. **Rekor SET verification**: no separate implementation — cosign's own
   verify path already validates the SET against Rekor's public key. The
   gap the plan called out was that the tool *claimed* Rekor inclusion
   from reading the bundle JSON (forge-able) without actually running the
   SET check. Fix was to set `chain.rekor_verified=True` only after cosign
   verify returns success, and split the rekor_status display so
   "bundle claims logIndex" and "cosign verified SET" are distinct rows in
   the output.

## What shipped: file-by-file

### New modules

- `attestation.py` — DSSE envelope decode, in-toto Statement extraction,
  in-toto subject-digest assertion (the P0-1 core check), cosign
  `verify-attestation` wrapper, SLSA v1.0 predicate parser, SPDX + CycloneDX
  SBOM parsers with license set + PURL sample extraction. Reusable
  primitives consumed by every attestation-retrieving path.
- `policy.py` — `IdentityPolicy` dataclass, JSON loader that fails closed
  on unknown fields/invalid regexes, default policies preserving the
  hardcoded values for backward compatibility, `evaluate_slsa_policy()`
  for builder.id + source_uri allowlist checks.
- `scan.py` — `VulnCounts` + `ScanResult` dataclasses, `run_scan()` with
  optional two-pass VEX-adjusted flow, `parse_grype_json()`,
  `extract_cve_list()`, `extract_purl_set()`, `run_sbom_drift()`.
- `kev.py` — `KevEntry` + `KevCatalog` dataclasses, 24h cached catalog
  loader with atomic fetch + graceful stale-cache fallback,
  `check_cves_against_kev()` cross-check.
- `evidence.py` — `write_evidence_bundle()` writes per-image directory
  with metadata, attestation envelopes, scan/kev/policy/violations JSON,
  `controls.json` mapping checks to SSDF/NIST-800-161/NIST-800-190/
  FedRAMP-SR/FedRAMP-RA/CMMC/CISA-BOD/FIPS-140-3, Markdown SUMMARY,
  SHA256SUMS integrity seal.

### Extended files

- `verify_provenance.py` — from ~900 lines to ~1900. New flags:
  `--verify-attestations`, `--policy-file`, `--scan`, `--max-age-days`,
  `--trusted-root`, `--evidence-bundle`, `--sbom-drift`. New dataclass
  fields on `ChainDetails` (rekor_verified, rekor_set_present, image
  freshness, EOL predicate, scan_result, kev_hits, policy_violations,
  attestations dict keyed by predicate URI, apko/github-workflow extensions,
  sbom_drift). New `VerificationResult` status fields (slsa_status,
  sbom_status, policy_status, vuln_status, kev_status, freshness_status,
  sbom_drift_status, fips_variant). New verdicts: `ATTESTATION_FAILED`,
  `POLICY_VIOLATION`, `KEV_HIT`. New chain-detail printer steps 6-10 for
  policy, SBOM, scan, KEV, freshness. Expanded CSV schema from 8 to 27
  columns.
- `verify_library.py` — wired Python + npm Sigstore bundle verification
  (previously stubbed); added `apk` ecosystem with `parse_apk_coordinate()`
  + `resolve_apk_url()`.
- `example-policy.json` — commented example demonstrating schema overrides.
- `PREREQUISITES.md` — added grype + syft as optional tools.
- `README.md` — expanded What-is-verified table from 4 rows to 11,
  documented all new flags, CSV columns, verdict states, and ecosystems.

### New test files

- `tests/test_attestation.py` — 38 tests (DSSE decode, subject-digest
  checks, SLSA parser, SBOM parsers, retrieve flow with mocked cosign).
- `tests/test_policy.py` — 21 tests (defaults, loader strictness,
  allowlist evaluation, regex semantics).
- `tests/test_scan.py` — 20 tests (grype parser, severity counts, VEX
  adjudication, extract CVE list).
- `tests/test_kev.py` — 26 tests (catalog parsing, staleness math,
  cache/fetch interaction, cross-check).
- `tests/test_additions.py` — 26 tests (freshness, FIPS, Fulcio cert
  extensions, evidence bundle structure + SHA256SUMS, SBOM drift,
  APK coordinates).
- `tests/test_verify_provenance.py` — extended with glue tests for
  `_verify_image_attestations`, `_run_vuln_scan`, `_run_sbom_drift`,
  policy evaluation, KEV cross-check, Rekor logIndex mismatch detection.

### Test totals

| Stage | Tests |
|---|---|
| Pre-session baseline | 33 |
| After P0 (P0-1 → P0-5) | 108 |
| After P1-1 (scan + VEX) | 133 |
| After P1-2 (KEV) | 163 |
| Final (all tiers) | **189** |

## Semantic guarantees earned

The tool now holds six invariants it didn't before:

1. **Attestation substitution blocked.** Every SLSA/SBOM/VEX/EOL/apko
   attestation is rejected unless its in-toto `subject[].digest.sha256`
   matches the image digest being verified. A signed-but-mismatched
   attestation demotes the verdict to `ATTESTATION_FAILED`.

2. **Rekor inclusion is cryptographically verified, not claimed.**
   `rekor_verified=true` is set only after cosign's verify path returns
   success (which validates the SET against Rekor's public key). The
   bundle-extracted logIndex is also cross-checked against the one cosign
   verified — mismatches flagged in `rekor_url` with a `MISMATCH:` marker.

3. **Unknown builders / source repos can't slip through.** SLSA
   provenance must name a builder.id and source URI matching the policy
   allowlist; otherwise verdict demotes to `POLICY_VIOLATION`.

4. **VEX can't lie.** Only a signed, subject-matched OpenVEX doc is
   passed to grype's `--vex` filter. An unverified or substituted VEX is
   discarded silently — the tool doesn't suppress findings based on
   metadata it can't trust.

5. **Actively-exploited CVEs can't be ignored.** Post-VEX actionable CVEs
   are cross-checked against the CISA KEV catalog; any hit demotes the
   verdict to `KEV_HIT`. The only way to suppress a KEV hit is for
   Chainguard to publish a signed, subject-matched VEX
   `not_affected`/`fixed` statement.

6. **SBOM drift detectable.** If `--sbom-drift` is on, the PURL set of a
   locally-generated syft SBOM is diffed against the attested SBOM's PURL
   set; drift > 5% flags `DRIFT`, catching registry-side SBOM
   substitution.

## Verification (how we know it works)

- **Unit**: 189 tests across 6 test files cover parsing, status mapping,
  policy evaluation, file I/O, and glue-layer dispatch. All pass.
- **Lint + format**: `ruff check` + `ruff format --check` clean on every
  file authored this cycle (`attestation.py`, `policy.py`, `scan.py`,
  `kev.py`, `evidence.py`, and all new test files).
- **Type-check**: `mypy` on the new modules passes. `verify_provenance.py`
  and `verify_library.py` retain exactly the 4 pre-existing errors they
  had at session start (missing return annotations on three
  print-chain-details functions + one `dict` type-arg warning); no new
  errors introduced.
- **Smoke**: `python3 verify_provenance.py image --help` renders all 8
  new flags correctly.
- **Live integration** not run in this session — requires `chainctl auth
  login` + live Chainguard catalog access. Recommended next step on a
  real deployment.

## Critical files

- `attestation.py:141` — `subject_digest_matches()` — the P0-1 check.
- `attestation.py:382` — `retrieve_and_verify_attestation()` — the
  generic cosign wrapper every attestation flows through.
- `policy.py:179` — `load_policy_file()` — fail-closed JSON loader.
- `scan.py:156` — `run_scan()` — two-pass grype with optional VEX filter.
- `scan.py:223` — `run_sbom_drift()` — syft-vs-attested diff.
- `kev.py:75` — `load_kev_catalog()` — 24h cached catalog loader.
- `evidence.py:107` — `write_evidence_bundle()` — the auditor's
  deliverable.
- `verify_provenance.py:_verify_image_attestations` — the aggregation
  point where every attestation is pulled and evaluated.

## Out of scope (explicitly not shipped)

- Building our own SLSA policy engine — the allowlist model + cosign's
  `--policy` escape hatch are sufficient.
- Re-implementing Rekor client logic in Python — we call into cosign.
- Reproducible-build verification (requires apko runtime; rarely asked for).
- STIG / CIS scoring — attach the report, don't re-score it.
- Predicate-based FIPS detection — deferred until Chainguard's FIPS
  attestation schema stabilizes.

## Recommended next steps

1. **Live integration test on a known-good public image** (e.g.
   `cgr.dev/chainguard/python`) with `--verify-attestations --scan` to
   confirm the cosign calls produce the expected output shapes on real
   Chainguard data. Mocked tests catch logic; real tests catch shape
   assumptions.
2. **CI job** running the full test suite + ruff + mypy on every PR.
3. **Scheduled weekly run** against the customer org to populate an
   evidence-bundle directory that auditors can pull on demand.
4. **Predicate-based FIPS detection** once Chainguard's FIPS
   attestation schema is documented.
