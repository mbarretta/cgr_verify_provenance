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

### 4. rekor-cli (Optional)

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

For full verification mode (verifying against `chainguard-private`), you need access to the reference organization. Contact Chainguard support if you need this access.
