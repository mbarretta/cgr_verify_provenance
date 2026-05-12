# Prerequisites

This tool requires the following external CLI tools to be installed and available in your PATH.

## Required Tools

### 1. chainctl (Chainguard CLI)

Used for authentication and listing entitled images.

**Installation:**
```bash
# macOS/Linux
brew install chainguard-dev/tap/chainctl

# Or download directly
curl -o chainctl "https://dl.enforce.dev/chainctl/latest/chainctl_$(uname -s)_$(uname -m)"
chmod +x chainctl
sudo mv chainctl /usr/local/bin/
```

**Documentation:** https://edu.chainguard.dev/chainguard/chainctl/

### 2. crane

Used for inspecting image manifests and configurations.

**Installation:**
```bash
# macOS/Linux
brew install crane

# Or via Go
go install github.com/google/go-containerregistry/cmd/crane@latest
```

**Documentation:** https://github.com/google/go-containerregistry/tree/main/cmd/crane

### 3. cosign

Used for downloading and verifying cryptographic signatures.

**Installation:**
```bash
# macOS/Linux
brew install cosign

# Or download from releases
# https://github.com/sigstore/cosign/releases
```

**Documentation:** https://docs.sigstore.dev/cosign/overview/

### 4. curl

Used by the `library` subcommand to fetch artifacts and Sigstore bundles from `libraries.cgr.dev`.

**Installation:**
```bash
# Almost always pre-installed on Linux/macOS. If missing:
# macOS: brew install curl
# Debian/Ubuntu: apt-get install curl
# RHEL/Fedora: yum install curl
```

### 5. openssl (Optional, for library mode)

Used by the `library` subcommand to extract the signer identity (SAN URI) from Sigstore bundle certificates. If `openssl` is missing, the chain output will omit the `Signer SAN` field but verification still succeeds — `cosign verify-blob` does not depend on this.

### 6. grype (Optional, for `--scan`)

Used by `--scan` in image mode to run a vulnerability scan against each
verified image. Chainguard-published OpenVEX attestations, when present,
are passed to grype as `--vex` to produce an actionable (VEX-adjusted)
CVE count alongside the raw count.

**Installation:**
```bash
# macOS
brew install grype

# Linux (script install)
curl -sSfL https://raw.githubusercontent.com/anchore/grype/main/install.sh | sudo sh -s -- -b /usr/local/bin

# Or via Go
go install github.com/anchore/grype/cmd/grype@latest
```

**First run:** grype downloads its vulnerability database on first use
(~30s, ~200MB). Subsequent runs are fast.

**Documentation:** https://github.com/anchore/grype

### 7. syft (Optional, for `--sbom-drift`)

Used by `--sbom-drift` in image mode to generate a local SBOM and diff
its PURL set against the attested SBOM. Flags registry-side SBOM
substitution where a signed SBOM describes a different image's packages.

**Installation:**
```bash
# macOS
brew install syft

# Linux (script install)
curl -sSfL https://raw.githubusercontent.com/anchore/syft/main/install.sh | sudo sh -s -- -b /usr/local/bin
```

**Documentation:** https://github.com/anchore/syft

### 8. git (Optional, for `--verify-upstream-sources`)

Used by `--verify-upstream-sources` in image mode to confirm SBOM-asserted
upstream coordinates by running `git ls-remote <repo> refs/tags/<tag>` and
comparing the resolved commit hash to the SBOM. Almost always already
installed on developer workstations.

**Installation:**
```bash
# macOS
brew install git

# Debian/Ubuntu
apt-get install git

# RHEL/Fedora
dnf install git
```

If your images include packages built from private `chainguard-dev/*`
repositories, set one of `GITHUB_TOKEN` / `GH_TOKEN`, or run `gh auth
login` first; the tool reads the token in that order and injects it into
the `git ls-remote` URL so private tag lookups succeed.

### 9. docker (Optional, for `build-deps`)

Used to run `apk add --simulate` inside `cgr.dev/chainguard/wolfi-base` when
enumerating an image's build-environment closure.

**Installation:** Docker Desktop (macOS/Windows) or Docker Engine (Linux).
On macOS the script bind-mounts files under `$TMPDIR`/`/tmp`; Docker Desktop
typically allows this but may require `/private/tmp` in its file-sharing
list. The script auto-resolves symlinks before mounting.

### 10. yq (Optional, for `build-deps`)

Used to extract `environment.contents.packages`, `pipeline.uses`, and `vars`
blocks from melange recipe YAML.

**Installation:**
```bash
# macOS/Linux (mikefarah/yq, the Go binary — not the Python yq)
brew install yq
```

`build-deps` also requires a GitHub token authorized to read
`chainguard-dev/stereo` — same env vars as `--verify-upstream-sources`.

For `build-deps` against images whose recipes pull from private apk repos
(e.g. FIPS images such as `cgr.dev/chainguard-private/mongodb-fips`),
`chainctl auth login` must be active so the tool can mint a short-lived
apk pull token via `chainctl auth token --audience apk.cgr.dev`. Without
it, `build-deps` falls back to public-only resolution and reports the
unresolvable packages in `errored_recipes`. Use `--no-private-apk` to
opt out, or `--apk-org <name>` to point at a different tenant.

### 11. rekor-cli (Optional)

Used for direct transparency log queries. The tool extracts Rekor data from signatures, but you can use rekor-cli for manual verification.

**Installation:**
```bash
# macOS/Linux
brew install rekor-cli

# Or via Go
go install github.com/sigstore/rekor/cmd/rekor-cli@latest
```

**Documentation:** https://docs.sigstore.dev/rekor/overview/

## Verification

Verify all tools are installed:

```bash
chainctl version
crane version
cosign version
rekor-cli version  # optional
```

## Authentication

Before running the verification tool, authenticate with Chainguard:

```bash
chainctl auth login
```

For full `image` verification mode (verifying against `chainguard-private`), you need access to the reference organization. Contact Chainguard support if you need this access.

For `library` mode, the tool acquires short-lived pull tokens at runtime via
`chainctl auth pull-token create --repository={java|python|javascript} --parent=<org> --ttl=1h --output=json`
so the authenticated user must have the libraries entitlement for the given parent org. No additional setup is required beyond `chainctl auth login`.
