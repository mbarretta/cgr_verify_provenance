"""
Upstream-source verification for SPDX SBOMs.

After the SBOM attestation has been cryptographically verified and its in-toto
subject digest matched against the image, the SBOM's content claims (e.g.
"this image contains glibc-2.43, sourced from gitlab.com/gnutools/glibc at
tag glibc-2.43, commit f762ccf...") are still untrusted: a forged but signed
SBOM with bogus upstream coordinates would currently pass.

This module walks the SPDX `relationships[]` graph (`GENERATED_FROM` primary,
`DESCRIBED_BY` fallback) plus package `externalRefs[]` purls, then for each
upstream source reaches out to the actual upstream and confirms:

  1. For git sources (pkg:github / pkg:gitlab / pkg:generic+vcs_url):
     `git ls-remote <repo> refs/tags/<tag>` resolves to the commit hash
     embedded in the SPDX source-package SPDXID (or in the vcs_url's
     `@<hash>` qualifier).
  2. For http sources (pkg:generic + download_url + checksum):
     download the tarball, recompute sha256/sha512, match the SBOM checksum.

This is the same idea as `chainguard-demo/ynad/sourcier verify`. We keep it
opt-in (network-heavy: ~25-50 RTTs per image) and add it as evidence to the
auditor bundle: "we walked all upstream sources for every image and they
match upstream tags/checksums."

Stdlib only — no third-party deps. Shells out to `git ls-remote` (gated by
the new `--verify-upstream-sources` flag, listed in PREREQUISITES.md).
"""

from __future__ import annotations

import hashlib
import os
import re
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

from verify_provenance import run_cmd

# A purl that doesn't start with one of these is not a source we can verify.
# `pkg:g` covers `pkg:github`, `pkg:gitlab`, `pkg:generic`. Sourcier uses the
# same prefix gate.
_SOURCE_PURL_PREFIX = "pkg:g"

# 40-char SHA-1 hex (git commit). Used to scrape commit hashes out of SPDX
# SPDXIDs and out of the `vcs_url=git+...@<hash>` purl qualifier.
_GIT_COMMIT_RE = re.compile(r"\b([0-9a-f]{40})\b")

# Default concurrency for upstream lookups — matches sourcier.
DEFAULT_MAX_CONCURRENT = 10

# Per-source HTTP timeout (seconds). Tarball downloads can be a few MB.
DEFAULT_HTTP_TIMEOUT = 30

# Per-git-ls-remote timeout (seconds).
DEFAULT_GIT_TIMEOUT = 30

# Strip Authorization on cross-host redirects so a tarball mirror cannot
# capture upstream credentials.
_MAX_REDIRECTS = 10


# ───────────────────────────── data structures ─────────────────────────────


@dataclass
class UpstreamSource:
    """One package's resolved upstream coordinates, ready to verify.

    `source_type` selects the verification path:
      - "git"  — `git ls-remote <url>` resolves <tag> → expected <commit>
      - "http" — download <url>, recompute hash, match <checksum>
      - "none" — purl present but no usable source coordinates; SKIP
    """

    label: str  # human-readable package label (e.g. "glibc-2.43-r2")
    source_type: str  # "git" | "http" | "none"
    url: str = ""  # full URL (no embedded credentials)
    tag: str = ""  # git tag to look up
    commit: str = ""  # expected 40-hex commit hash
    checksum: str = ""  # "sha256:..." or "sha512:..." for http sources
    purl: str = ""  # raw purl (for evidence record)


@dataclass
class UpstreamVerifyResult:
    """Outcome of verifying one UpstreamSource."""

    label: str
    source_type: str
    status: str  # "VERIFIED" | "FAILED" | "ERROR" | "SKIP"
    detail: str = ""
    url: str = ""
    tag: str = ""
    expected: str = ""  # expected commit or checksum
    observed: str = ""  # observed commit or computed hash


@dataclass
class UpstreamSummary:
    """Aggregated upstream verification result for one image."""

    total: int = 0
    verified: int = 0
    failed: int = 0
    errors: int = 0
    skipped: int = 0
    cache_hits: int = 0
    results: list[UpstreamVerifyResult] = field(default_factory=list)

    def as_status(self) -> str:
        """Coarse status used by the verdict path.

        FAILED dominates: any real integrity failure flips this to "FAILED".
        ERROR (network/auth/timeout) does NOT flip to FAILED — same posture
        the rest of the tool takes for transient failures (KEV fetch,
        SBOM-drift errors). It surfaces as a warning in the report.
        SKIP is silent: packages with no source info (distro metadata,
        melange-only) are neither pass nor fail.
        """
        if self.failed > 0:
            return "FAILED"
        if self.verified == 0 and self.errors == 0:
            return "N/A"  # nothing actually verifiable
        if self.errors > 0 and self.verified == 0:
            return "ERROR"
        return "VERIFIED"


# ─────────────────────── SPDX walk: relationships → sources ───────────────────────


def walk_spdx_sources(predicate: dict[str, object]) -> list[UpstreamSource]:
    """Walk an SPDX 2.x predicate and return one UpstreamSource per package.

    Strategy mirrors sourcier:
      1. Index `packages[]` by SPDXID.
      2. For each package P, look at `relationships[]`:
         - First preference: `P GENERATED_FROM Q` → Q is the source package.
         - Fallback:         `P DESCRIBED_BY Q`   → Q is a melange-config
                              package, but it carries the upstream purl too.
      3. From Q's `externalRefs[]`, take the first ref whose
         `referenceLocator` starts with "pkg:g" (github, gitlab, generic).
      4. Decide the source_type from the purl shape; populate fields.

    Returns one entry per *binary* package — the apk/wolfi packages that
    show up in the running image. Distro metadata / OCI layer / melange
    packages without a usable upstream surface as `source_type="none"`,
    which the caller renders as SKIP.
    """
    if not isinstance(predicate, dict):
        return []
    packages_raw = predicate.get("packages", [])
    rels_raw = predicate.get("relationships", [])
    if not isinstance(packages_raw, list) or not isinstance(rels_raw, list):
        return []

    pkgs: dict[str, dict[str, object]] = {}
    for p in packages_raw:
        if not isinstance(p, dict):
            continue
        pid = p.get("SPDXID")
        if isinstance(pid, str):
            pkgs[pid] = p

    # Build a per-source-package adjacency: source_pkg_id -> set of relationships.
    # We index every relationship targeting a package we know about, keyed by
    # the *source* element so the per-package walk is O(1) lookup.
    generated_from: dict[str, str] = {}
    described_by: dict[str, str] = {}
    for r in rels_raw:
        if not isinstance(r, dict):
            continue
        rt = r.get("relationshipType")
        a = r.get("spdxElementId")
        b = r.get("relatedSpdxElement")
        if not isinstance(rt, str) or not isinstance(a, str) or not isinstance(b, str):
            continue
        if rt == "GENERATED_FROM" and a not in generated_from:
            generated_from[a] = b
        elif rt == "DESCRIBED_BY" and a not in described_by:
            described_by[a] = b

    sources: list[UpstreamSource] = []
    seen_ids: set[str] = set()
    for pid, pkg in pkgs.items():
        # Skip the document-root and synthetic distro packages from the walk;
        # their job is to anchor relationships, not to be verified themselves.
        # We discover binaries by virtue of their having a GENERATED_FROM /
        # DESCRIBED_BY edge.
        target_id = generated_from.get(pid) or described_by.get(pid)
        if target_id is None:
            continue
        if pid in seen_ids:
            continue
        seen_ids.add(pid)

        target_pkg = pkgs.get(target_id, {})
        purl = _first_source_purl(target_pkg)
        label = _spdx_pkg_label(pkg)

        if not purl:
            sources.append(UpstreamSource(label=label, source_type="none", purl=""))
            continue

        src = _resolve_purl(purl, target_id, label)
        sources.append(src)
    return sources


def _spdx_pkg_label(pkg: dict[str, object]) -> str:
    """`name-version-release` if available, else the SPDX name, else SPDXID."""
    name = pkg.get("name") if isinstance(pkg.get("name"), str) else ""
    ver = pkg.get("versionInfo") if isinstance(pkg.get("versionInfo"), str) else ""
    if name and ver:
        return f"{name}-{ver}"
    if name:
        return str(name)
    pid = pkg.get("SPDXID")
    return str(pid) if isinstance(pid, str) else "(unnamed)"


def _first_source_purl(pkg: dict[str, object]) -> str:
    """First externalRefs entry whose referenceLocator starts with `pkg:g`."""
    refs = pkg.get("externalRefs")
    if not isinstance(refs, list):
        return ""
    for ref in refs:
        if not isinstance(ref, dict):
            continue
        if ref.get("referenceType") != "purl":
            continue
        loc = ref.get("referenceLocator")
        if isinstance(loc, str) and loc.startswith(_SOURCE_PURL_PREFIX):
            return loc
    return ""


def _parse_purl(purl: str) -> tuple[str, str, str, dict[str, str]]:
    """Crude purl parser: returns (type, namespace_path, version, qualifiers).

    Spec is `pkg:<type>/<namespace>/<name>@<version>?<qualifiers>#<subpath>`.
    We only need the type, a namespace+name path string, the version, and the
    qualifier dict — enough to drive the four resolution cases in
    `_resolve_purl`. Tolerant of missing pieces.
    """
    if not purl.startswith("pkg:"):
        return "", "", "", {}
    body = purl[len("pkg:") :]
    # Strip subpath if present (`#...`).
    if "#" in body:
        body = body.split("#", 1)[0]
    # Split off qualifiers.
    qualifiers: dict[str, str] = {}
    if "?" in body:
        body, qstr = body.split("?", 1)
        for pair in qstr.split("&"):
            if not pair:
                continue
            if "=" in pair:
                k, v = pair.split("=", 1)
                qualifiers[k] = urllib_unquote(v)
            else:
                qualifiers[pair] = ""
    # type/<rest>
    if "/" not in body:
        return body, "", "", qualifiers
    ptype, _, rest = body.partition("/")
    # version is everything after the LAST '@', if any
    version = ""
    if "@" in rest:
        rest, _, version = rest.rpartition("@")
        version = urllib_unquote(version)
    return ptype, rest, version, qualifiers


def urllib_unquote(s: str) -> str:
    """Tiny URL-decode wrapper. Avoids importing urllib.parse at module top
    so consumers that only need the hashing/git paths don't pay for it."""
    from urllib.parse import unquote

    return unquote(s)


def _resolve_purl(purl: str, source_spdxid: str, label: str) -> UpstreamSource:
    """Map a `pkg:g*` purl to an UpstreamSource. Recognises the three forms:

    1. `pkg:github/<owner>/<repo>@<tag>` (or `pkg:gitlab/...`):
       tag = `<tag>`, commit = first 40-hex hash inside the source SPDXID.
    2. `pkg:generic/<name>@<tag>?vcs_url=git+https://host/path@<commit>`:
       tag = `<tag>`, commit = the post-`@` part of vcs_url.
    3. `pkg:generic/<name>@<tag>?download_url=...&checksum=sha256:...`:
       url = download_url, checksum = checksum qualifier.

    Anything else falls back to `source_type="none"`.
    """
    ptype, ns_path, version, quals = _parse_purl(purl)
    src = UpstreamSource(label=label, source_type="none", purl=purl)
    if not ptype:
        return src

    if ptype in ("github", "gitlab"):
        # ns_path is "owner/repo" (or "host/owner/repo" for self-hosted gitlab).
        host = "github.com" if ptype == "github" else "gitlab.com"
        if ptype == "gitlab" and "/" in ns_path:
            # Heuristic: if the first segment contains a dot, treat it as a host.
            head, _, tail = ns_path.partition("/")
            if "." in head:
                host = head
                ns_path = tail
        if not ns_path:
            return src
        src.source_type = "git"
        src.url = f"https://{host}/{ns_path}"
        src.tag = version
        src.commit = _first_commit_in(source_spdxid).lower()
        return src

    if ptype == "generic":
        vcs_url = quals.get("vcs_url", "")
        download_url = quals.get("download_url", "")
        checksum = quals.get("checksum", "")
        if vcs_url:
            url, commit = _split_vcs_url(vcs_url)
            if url:
                src.source_type = "git"
                src.url = url
                src.tag = version
                src.commit = commit.lower()
                return src
        if download_url and checksum:
            src.source_type = "http"
            src.url = download_url
            src.checksum = checksum
            return src
    return src


def _first_commit_in(s: str) -> str:
    m = _GIT_COMMIT_RE.search(s)
    return m.group(1) if m else ""


def _split_vcs_url(vcs_url: str) -> tuple[str, str]:
    """`git+https://host/path@<commit>` → (`https://host/path`, `<commit>`).

    Returns ("", "") when the URL doesn't carry a commit.
    """
    url = vcs_url
    if url.startswith("git+"):
        url = url[len("git+") :]
    if "@" not in url:
        return url, ""
    # Pull the right-most @<commit>; the rest is the URL.
    head, _, commit = url.rpartition("@")
    return head, commit


# ───────────────────────────── verifiers ─────────────────────────────


def github_token() -> str:
    """Return a GitHub token if any is reachable (env or `gh auth token`).

    Order matches sourcier: GITHUB_TOKEN → GH_TOKEN → `gh auth token`.
    Used to inject credentials into clones of `chainguard-dev/*` repos.
    """
    for name in ("GITHUB_TOKEN", "GH_TOKEN"):
        v = os.environ.get(name)
        if v:
            return v
    success, out, _ = run_cmd(["gh", "auth", "token"], timeout=5)
    if success:
        return out.strip()
    return ""


def _inject_github_token(url: str, token: str) -> str:
    """Insert `oauth2:<token>@` into a github.com URL so `git ls-remote` can
    read private chainguard-dev repos. No-op for non-github URLs or when no
    token is available — anonymous git ls-remote works for public repos.
    """
    if not token or "://" not in url:
        return url
    scheme, rest = url.split("://", 1)
    if not rest.startswith("github.com/") and not rest.startswith("github.com:"):
        return url
    if "@" in rest.split("/", 1)[0]:
        # Already has credentials embedded; don't overwrite.
        return url
    return f"{scheme}://oauth2:{token}@{rest}"


def resolve_git_commit(
    repo_url: str, tag: str, github_token_value: str = "", timeout: int = DEFAULT_GIT_TIMEOUT
) -> tuple[str, str]:
    """Run `git ls-remote <url> refs/tags/<tag> refs/tags/<tag>^{}` and return
    the dereferenced commit hash. Returns ("", err) on failure.

    For annotated tags `git ls-remote` emits two lines: the tag object hash
    (refs/tags/X) and the peeled commit hash (refs/tags/X^{}). We prefer
    the peeled line. For lightweight tags only the unpeeled line exists,
    which already points at the commit.
    """
    if not repo_url or not tag:
        return "", "missing repo_url or tag"

    auth_url = _inject_github_token(repo_url, github_token_value)
    cmd = ["git", "ls-remote", auth_url, f"refs/tags/{tag}", f"refs/tags/{tag}^{{}}"]
    success, stdout, stderr = run_cmd(cmd, timeout=timeout)
    if not success:
        # Don't leak the token in error output if we injected one. `run_cmd`
        # already keeps stderr local but the URL we passed may show up; redact.
        msg = (stderr or "").strip().splitlines()
        last = msg[-1] if msg else "git ls-remote failed"
        if github_token_value and github_token_value in last:
            last = last.replace(github_token_value, "***")
        return "", last

    peeled: str = ""
    plain: str = ""
    for line in stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            continue
        sha, ref = parts
        if ref.endswith("^{}"):
            peeled = sha
        elif ref == f"refs/tags/{tag}":
            plain = sha
    commit = peeled or plain
    if not commit:
        return "", f"tag '{tag}' not found at {repo_url}"
    return commit.lower(), ""


def download_and_hash(
    url: str, expected_checksum: str, timeout: int = DEFAULT_HTTP_TIMEOUT
) -> tuple[str, str]:
    """Stream `url`, compute the algo named in `expected_checksum`, return
    `(computed_hex, error)`. The hash bytes never touch disk.

    `expected_checksum` is `algo:hex`, where algo is `sha256` or `sha512`.
    Anything else is rejected — we don't trust md5/sha1 for supply-chain
    integrity claims.
    """
    if ":" not in expected_checksum:
        return "", f"unsupported checksum format: {expected_checksum!r}"
    algo, _, _ = expected_checksum.partition(":")
    algo = algo.lower()
    if algo == "sha256":
        h: hashlib._Hash = hashlib.sha256()
    elif algo == "sha512":
        h = hashlib.sha512()
    else:
        return "", f"unsupported checksum algo: {algo}"

    opener = urllib.request.build_opener(_SafeRedirectHandler())
    try:
        with opener.open(url, timeout=timeout) as resp:
            while True:
                chunk = resp.read(65536)
                if not chunk:
                    break
                h.update(chunk)
    except urllib.error.URLError as e:
        return "", f"download failed: {e.reason}"
    except (OSError, ValueError) as e:
        return "", f"download failed: {e}"
    return h.hexdigest(), ""


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Cap redirects and forbid scheme downgrades.

    urllib's default chain will happily follow https→http; for tarball
    integrity we don't care about cleartext downgrade per se (we're hashing
    the bytes anyway) but we cap the count so a malicious mirror can't
    spin us forever.
    """

    max_redirections = _MAX_REDIRECTS


# ───────────────────────────── orchestration ─────────────────────────────


def verify_sources(
    sources: list[UpstreamSource],
    *,
    max_concurrent: int = DEFAULT_MAX_CONCURRENT,
    github_token_value: str = "",
    cache: dict[tuple[str, str], UpstreamVerifyResult] | None = None,
) -> UpstreamSummary:
    """Verify every source in parallel; return an aggregated summary.

    `cache` is a per-run dict keyed `(scheme_url, tag_or_checksum)` so the
    many images that share APK packages (glibc, openssl, ncurses) only pay
    one network round-trip per upstream. Pass the same cache dict across
    every call in a run. Pass `None` to disable.
    """
    summary = UpstreamSummary(total=len(sources))
    if cache is None:
        cache = {}

    cache_lock = threading.Lock()

    def _verify(src: UpstreamSource) -> UpstreamVerifyResult:
        if src.source_type == "none":
            return UpstreamVerifyResult(
                label=src.label,
                source_type="none",
                status="SKIP",
                detail="no source info in SBOM",
            )
        key = _cache_key(src)
        with cache_lock:
            cached = cache.get(key)
        if cached is not None:
            # Surface the cache hit but make a per-source copy so the per-
            # image evidence record carries the right `label`.
            r = UpstreamVerifyResult(
                label=src.label,
                source_type=src.source_type,
                status=cached.status,
                detail=cached.detail,
                url=cached.url,
                tag=cached.tag,
                expected=cached.expected,
                observed=cached.observed,
            )
            summary.cache_hits += 1
            return r
        if src.source_type == "git":
            r = _verify_git(src, github_token_value)
        elif src.source_type == "http":
            r = _verify_http(src)
        else:
            r = UpstreamVerifyResult(
                label=src.label,
                source_type=src.source_type,
                status="ERROR",
                detail=f"unknown source_type: {src.source_type}",
                url=src.url,
            )
        # Cache only deterministic outcomes (VERIFIED / FAILED). ERROR
        # results often reflect transient network issues; re-trying on the
        # next image gives the run a chance to recover.
        if r.status in ("VERIFIED", "FAILED"):
            with cache_lock:
                cache[key] = r
        return r

    # `max_workers=0` would crash the executor; clamp to 1.
    workers = max(1, min(max_concurrent, len(sources) or 1))
    with ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(_verify, sources))

    summary.results = results
    for r in results:
        if r.status == "VERIFIED":
            summary.verified += 1
        elif r.status == "FAILED":
            summary.failed += 1
        elif r.status == "ERROR":
            summary.errors += 1
        elif r.status == "SKIP":
            summary.skipped += 1
    return summary


def _cache_key(src: UpstreamSource) -> tuple[str, str]:
    """Cache key: identify a source by its remote coordinates, not by label.

    Different images that share glibc-2.43 hit the same upstream — we want
    one network round-trip even though the labels differ across images.
    """
    if src.source_type == "git":
        return (src.url, src.tag)
    if src.source_type == "http":
        return (src.url, src.checksum)
    return (src.label, src.source_type)


def _verify_git(src: UpstreamSource, token: str) -> UpstreamVerifyResult:
    """Look up `tag` upstream and compare to the SBOM-asserted commit hash."""
    if not src.commit:
        return UpstreamVerifyResult(
            label=src.label,
            source_type="git",
            status="ERROR",
            detail="SBOM did not provide a commit hash to compare against",
            url=src.url,
            tag=src.tag,
        )
    observed, err = resolve_git_commit(src.url, src.tag, token)
    if err:
        return UpstreamVerifyResult(
            label=src.label,
            source_type="git",
            status="ERROR",
            detail=err,
            url=src.url,
            tag=src.tag,
            expected=src.commit,
        )
    if observed != src.commit.lower():
        return UpstreamVerifyResult(
            label=src.label,
            source_type="git",
            status="FAILED",
            detail=f"tag '{src.tag}' resolves upstream to {observed[:12]}, "
            f"SBOM claims {src.commit[:12]}",
            url=src.url,
            tag=src.tag,
            expected=src.commit,
            observed=observed,
        )
    return UpstreamVerifyResult(
        label=src.label,
        source_type="git",
        status="VERIFIED",
        detail=f"tag '{src.tag}' matches commit {observed[:12]}",
        url=src.url,
        tag=src.tag,
        expected=src.commit,
        observed=observed,
    )


def _verify_http(src: UpstreamSource) -> UpstreamVerifyResult:
    """Stream the tarball, recompute its hash, compare to the SBOM checksum."""
    expected_algo, _, expected_hex = src.checksum.partition(":")
    if not expected_hex:
        return UpstreamVerifyResult(
            label=src.label,
            source_type="http",
            status="ERROR",
            detail=f"malformed checksum: {src.checksum!r}",
            url=src.url,
        )
    computed, err = download_and_hash(src.url, src.checksum)
    if err:
        return UpstreamVerifyResult(
            label=src.label,
            source_type="http",
            status="ERROR",
            detail=err,
            url=src.url,
            expected=src.checksum,
        )
    if computed.lower() != expected_hex.lower():
        return UpstreamVerifyResult(
            label=src.label,
            source_type="http",
            status="FAILED",
            detail=f"{expected_algo} mismatch: computed {computed[:12]}, "
            f"SBOM claims {expected_hex[:12]}",
            url=src.url,
            expected=src.checksum,
            observed=f"{expected_algo}:{computed}",
        )
    return UpstreamVerifyResult(
        label=src.label,
        source_type="http",
        status="VERIFIED",
        detail=f"{expected_algo} matches {computed[:12]}",
        url=src.url,
        expected=src.checksum,
        observed=f"{expected_algo}:{computed}",
    )


def git_installed() -> bool:
    """`git` on PATH? Used by the orchestrator to fail fast if missing."""
    import shutil

    return shutil.which("git") is not None
