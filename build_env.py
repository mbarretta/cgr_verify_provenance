"""
Transitive build-environment enumeration for apko-built Chainguard images.

Given a verified SPDX SBOM, this module reconstructs the set of packages that
melange installed into the build sandbox of every apk that composes the image
— the build-time complement to the runtime SBOM that ships with the image.

Three-stage pipeline:

  1. Walk the SBOM's `packages[]` for every entry whose name ends in `.yaml`
     and whose `versionInfo` is a 40-char git commit hash. That set is
     exactly the melange recipes pinned at the commits that produced this
     image's apks.

  2. Fetch each recipe yaml from `chainguard-dev/stereo` at its pinned SHA.
     Use the git-tree API to resolve filenames to repo paths in bulk (one
     call per unique SHA, not per recipe). Walk `pipeline.uses:` references
     and pull `pipelines/<name>.yaml` modules whose `needs.packages` add
     build-time deps the recipe doesn't declare directly.

  3. Per recipe, run `apk add --simulate` inside `cgr.dev/chainguard/wolfi-base`
     to compute the transitive apk closure that melange would install. Union
     per-recipe closures into the image-wide build environment.

Stereo is private. Callers must have a GitHub token (env or `gh auth token`
cache) authorized to read `chainguard-dev/stereo`. Recipes whose yaml is not
findable at the pinned SHA are reported as `missing_recipes` and the result
status is `MISSING_RECIPES` — fail loudly is the v1 contract.

Reproducibility caveat: the closure is resolved against `apk.cgr.dev/chainguard`'s
*current* state, not the apk repo as of the build timestamp. Package names are
stable; transitive version pins drift. See README for what a byte-identical
replay would require.

Stdlib only. Shells out to `yq` (recipe parsing) and `docker` (apk simulate).
"""

from __future__ import annotations

import base64
import json
import os
import re
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field

GITHUB_API = "https://api.github.com"
DEFAULT_STEREO_REPO = "chainguard-dev/stereo"
DEFAULT_BASE_IMAGE = "cgr.dev/chainguard/wolfi-base"
DEFAULT_MAX_WORKERS = 8
DEFAULT_DOCKER_TIMEOUT = 600
HTTP_TIMEOUT = 30
YQ_TIMEOUT = 30

# Default Chainguard org for private apk repo lookups. The enterprise/FIPS
# apks (openssl-config-fipshardened, FIPS NIST cert apks, chainguard-baselayout,
# wolfi-baselayout, etc.) live here. Overridable via the CLI --apk-org flag.
DEFAULT_PRIVATE_APK_ORG = "chainguard-private"

# 40-char SHA-1 hex — distinguishes a real pinned commit from non-commit
# versionInfo values (e.g. apk versions like "5.4.2-r0").
_GIT_SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# When the same recipe basename appears at multiple tree paths (e.g.
# version_data/foo.yaml vs enterprise-packages/foo.yaml), prefer the
# non-deprioritized one. `version_data/` holds historical pins, not build
# recipes.
_DEPRIORITIZED_PREFIXES = ("version_data/",)

# Capture lines from `apk add --simulate`:
#   (1/150) Installing bash (5.3-r12)
_APK_INSTALL_RE = re.compile(r"^\(\d+/\d+\) Installing (\S+) \(([^)]+)\)")

# Capture unresolvable package names from apk's failure output:
#   ERROR: unable to select packages:
#     openssl-config-fipshardened (no such package):
#       required by: world[openssl-config-fipshardened]
_APK_UNRESOLVABLE_RE = re.compile(r"^\s{2}([A-Za-z0-9._+-]+)\s+\(no such package\):")


# ─────────────────────── data structures ───────────────────────


class BuildEnvError(Exception):
    """Raised for infrastructure failures (auth, network, docker, yq).

    Recipe-not-found is *not* an error — it lands in `BuildEnvResult.missing_recipes`
    and yields status="MISSING_RECIPES". This exception is reserved for failures
    that prevent the run from producing any meaningful result.
    """


@dataclass
class RecipeRef:
    """One melange recipe pinned in the SBOM."""

    name: str  # e.g. "mongod-8.2.yaml"
    commit_sha: str  # full 40-char sha
    repo: str = DEFAULT_STEREO_REPO
    repo_path: str = ""  # populated after tree lookup
    declared_packages: list[str] = field(default_factory=list)  # de-duped, vars substituted
    pipeline_modules: list[str] = field(default_factory=list)  # raw `uses:` refs
    closure: list[str] = field(default_factory=list)  # "name=version" entries
    error: str = ""  # non-empty if this recipe could not be resolved
    # `error` covers resolution failures (yaml not findable at SHA). `closure_error`
    # is the orthogonal failure mode: yaml resolved fine, but apk couldn't satisfy
    # the declared deps inside the simulate container.
    closure_error: str = ""
    unresolvable_packages: list[str] = field(default_factory=list)


@dataclass
class BuildEnvResult:
    """Aggregated build environment for one image."""

    image: str
    image_digest: str = ""
    recipes: list[RecipeRef] = field(default_factory=list)
    declared_union: list[str] = field(default_factory=list)
    closure_union: list[str] = field(default_factory=list)  # "name=version"
    closure_names: list[str] = field(default_factory=list)  # names only
    missing_recipes: list[str] = field(default_factory=list)  # "name@shortsha"
    pipeline_module_count: int = 0
    status: str = "OK"  # OK | MISSING_RECIPES | DOCKER_FAILED | SBOM_EMPTY | CLOSURE_INCOMPLETE
    error: str = ""
    # v2 additions: per-recipe apk closure errors and the private apk org used.
    errored_recipes: list[str] = field(default_factory=list)  # "name (pkg1, pkg2)"
    private_apk_org: str = ""


@dataclass
class _RecipeClosureOutcome:
    """Per-recipe result from `apk add --simulate`.

    `packages` is the install-line list (success path). `exit_code` is non-zero
    iff apk failed for that recipe; `error_summary` is a short tail of apk's
    error output and `unresolvable_packages` is the parsed list of names apk
    couldn't find in any configured repo.
    """

    packages: list[str]
    exit_code: int = 0
    error_summary: str = ""
    unresolvable_packages: list[str] = field(default_factory=list)


# ─────────────────────── SBOM walk ───────────────────────


def extract_recipe_refs(sbom_predicate: dict[str, object]) -> list[RecipeRef]:
    """Walk SBOM `packages[]` for melange recipe references.

    Match shape: name ends in `.yaml` AND versionInfo is a 40-char hex SHA.
    De-dups on (name, sha). Returns sorted for stable output.
    """
    if not isinstance(sbom_predicate, dict):
        return []
    pkgs = sbom_predicate.get("packages")
    if not isinstance(pkgs, list):
        return []

    seen: set[tuple[str, str]] = set()
    refs: list[RecipeRef] = []
    for p in pkgs:
        if not isinstance(p, dict):
            continue
        name = p.get("name")
        sha = p.get("versionInfo")
        if not (isinstance(name, str) and name.endswith(".yaml")):
            continue
        if not (isinstance(sha, str) and _GIT_SHA_RE.fullmatch(sha)):
            continue
        key = (name, sha)
        if key in seen:
            continue
        seen.add(key)
        refs.append(RecipeRef(name=name, commit_sha=sha))
    refs.sort(key=lambda r: (r.name, r.commit_sha))
    return refs


# ─────────────────────── GitHub API ───────────────────────


def _gh_request(url: str, token: str, timeout: int = HTTP_TIMEOUT) -> dict[str, object]:
    """Authenticated GET to api.github.com; return parsed JSON.

    Raises BuildEnvError on HTTP failure or non-JSON response. Bearer token is
    optional (public endpoints work without one) but required for stereo.
    """
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "verify-provenance",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read()
    except urllib.error.HTTPError as e:
        raise BuildEnvError(f"GET {url} -> HTTP {e.code}: {e.reason}") from None
    except urllib.error.URLError as e:
        raise BuildEnvError(f"GET {url} failed: {e.reason}") from None
    try:
        parsed = json.loads(body)
    except json.JSONDecodeError as e:
        raise BuildEnvError(f"GET {url} returned non-JSON: {e}") from None
    if not isinstance(parsed, dict):
        raise BuildEnvError(f"GET {url} returned non-object JSON: {type(parsed).__name__}")
    return parsed


def fetch_tree(repo: str, sha: str, token: str) -> dict[str, str]:
    """Return {basename: path} for every .yaml blob in the repo at `sha`.

    When the same basename appears at multiple tree paths, prefer paths
    outside `_DEPRIORITIZED_PREFIXES`. The git-tree endpoint returns the
    full recursive tree in one call; that's the prototype's key perf win
    versus probing each candidate prefix per recipe.
    """
    url = f"{GITHUB_API}/repos/{repo}/git/trees/{sha}?recursive=1"
    data = _gh_request(url, token)
    tree = data.get("tree")
    if not isinstance(tree, list):
        return {}

    by_name: dict[str, str] = {}
    for entry in tree:
        if not isinstance(entry, dict):
            continue
        if entry.get("type") != "blob":
            continue
        path = entry.get("path")
        if not (isinstance(path, str) and path.endswith(".yaml")):
            continue
        basename = path.rsplit("/", 1)[-1]
        existing = by_name.get(basename)
        if existing is None:
            by_name[basename] = path
            continue
        # Replace existing only when existing is deprioritized and new isn't.
        existing_dp = existing.startswith(_DEPRIORITIZED_PREFIXES)
        new_dp = path.startswith(_DEPRIORITIZED_PREFIXES)
        if existing_dp and not new_dp:
            by_name[basename] = path
    return by_name


def fetch_blob(repo: str, sha: str, path: str, token: str) -> str:
    """GET /repos/{repo}/contents/{path}?ref={sha}; base64-decode 'content'."""
    url = f"{GITHUB_API}/repos/{repo}/contents/{path}?ref={sha}"
    data = _gh_request(url, token)
    encoded = data.get("content")
    if not isinstance(encoded, str):
        raise BuildEnvError(f"GET {url}: no 'content' field in response")
    try:
        return base64.b64decode(encoded).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as e:
        raise BuildEnvError(f"GET {url}: failed to decode base64 content: {e}") from None


# ─────────────────────── Recipe parsing ───────────────────────


def _yq_to_json(yaml_text: str, expression: str) -> object:
    """Shell out to `yq -o=json <expr> -` to evaluate one expression on a
    yaml document. Returns the parsed JSON object (or None for null).
    """
    cmd = ["yq", "-o=json", expression, "-"]
    try:
        proc = subprocess.run(
            cmd, input=yaml_text, capture_output=True, text=True, timeout=YQ_TIMEOUT
        )
    except subprocess.TimeoutExpired:
        raise BuildEnvError("yq timed out parsing yaml") from None
    except FileNotFoundError:
        raise BuildEnvError("yq not found in PATH") from None
    if proc.returncode != 0:
        raise BuildEnvError(f"yq failed: {(proc.stderr or '').strip()[:200]}")
    text = (proc.stdout or "").strip()
    if not text or text == "null":
        return None
    try:
        return json.loads(text)
    except json.JSONDecodeError as e:
        raise BuildEnvError(f"yq output was not valid JSON: {e}") from None


def parse_recipe(yaml_text: str) -> tuple[list[str], list[str], dict[str, str]]:
    """Extract (declared_packages, pipeline_uses, vars_map) from a melange recipe.

    declared_packages: .environment.contents.packages[] (raw, pre-substitution)
    pipeline_uses:     every .pipeline[].uses, including inside subpackages
                       and test pipelines, flattened + deduplicated
    vars_map:          .vars (key→str(value)) for ${{vars.X}} substitution
    """
    pkgs = _yq_to_json(yaml_text, ".environment.contents.packages // []")
    uses = _yq_to_json(
        yaml_text,
        "[.pipeline[]?.uses, "
        ".subpackages[]?.pipeline[]?.uses, "
        ".test.pipeline[]?.uses, "
        ".subpackages[]?.test.pipeline[]?.uses] "
        "| flatten | unique | map(select(. != null))",
    )
    vars_raw = _yq_to_json(yaml_text, ".vars // {}")

    declared_packages = [str(x) for x in pkgs] if isinstance(pkgs, list) else []
    pipeline_uses = [str(x) for x in uses] if isinstance(uses, list) else []
    vars_map: dict[str, str] = {}
    if isinstance(vars_raw, dict):
        for k, v in vars_raw.items():
            if isinstance(k, str):
                vars_map[k] = str(v) if v is not None else ""
    return declared_packages, pipeline_uses, vars_map


def parse_pipeline_module(yaml_text: str) -> list[str]:
    """Return the .needs.packages list of a pipelines/<name>.yaml module."""
    pkgs = _yq_to_json(yaml_text, ".needs.packages // []")
    return [str(x) for x in pkgs] if isinstance(pkgs, list) else []


# ─────────────────────── Template substitution ───────────────────────


def substitute_vars(pkg: str, vars_map: dict[str, str]) -> str:
    """Replace ${{vars.X}} tokens in `pkg`, then strip any '=version' suffix.

    The output is the bare package name that apk can install. Vars values are
    treated as literal strings (no recursive substitution) — matching melange.
    """
    out = pkg
    for k, v in vars_map.items():
        out = out.replace("${{vars." + k + "}}", v)
    return out.split("=", 1)[0].strip()


# ─────────────────────── Recipe + pipeline-module fetching ───────────────────────


def _fetch_pipeline_module_packages(repo: str, sha: str, mod: str, token: str) -> list[str]:
    """Fetch pipelines/<mod>.yaml and return its needs.packages.

    Many `pipeline.uses` refs (`fetch`, `git-checkout`, `strip`, `patch`) are
    built-in melange pipelines without a corresponding yaml file or without a
    needs.packages block. We silently skip those — empty list means no
    contribution to the build env.
    """
    path = f"pipelines/{mod}.yaml"
    try:
        text = fetch_blob(repo, sha, path, token)
    except BuildEnvError:
        return []
    try:
        return parse_pipeline_module(text)
    except BuildEnvError:
        return []


def _process_recipe(
    ref: RecipeRef,
    token: str,
    tree_cache: dict[str, dict[str, str]],
    tree_lock: threading.Lock,
) -> RecipeRef:
    """Fetch one recipe + its pipeline modules; populate `ref` in place."""
    # 1. Resolve repo path via the per-SHA tree cache.
    with tree_lock:
        tree = tree_cache.get(ref.commit_sha)
    if tree is None:
        try:
            tree = fetch_tree(ref.repo, ref.commit_sha, token)
        except BuildEnvError as e:
            ref.error = str(e)
            return ref
        with tree_lock:
            tree_cache[ref.commit_sha] = tree

    path = tree.get(ref.name, "")
    if not path:
        ref.error = f"recipe {ref.name} not found in {ref.repo}@{ref.commit_sha[:8]}"
        return ref
    ref.repo_path = path

    # 2. Fetch the recipe yaml.
    try:
        recipe_text = fetch_blob(ref.repo, ref.commit_sha, path, token)
    except BuildEnvError as e:
        ref.error = str(e)
        return ref

    # 3. Parse + substitute.
    try:
        declared, uses, vars_map = parse_recipe(recipe_text)
    except BuildEnvError as e:
        ref.error = f"parse {ref.name}: {e}"
        return ref

    pkg_set: set[str] = set()
    for p in declared:
        name = substitute_vars(p, vars_map)
        if name:
            pkg_set.add(name)

    ref.pipeline_modules = list(uses)

    # 4. Walk pipeline.uses → pipelines/<mod>.yaml → needs.packages.
    for mod in uses:
        for p in _fetch_pipeline_module_packages(ref.repo, ref.commit_sha, mod, token):
            name = substitute_vars(p, vars_map)
            if name:
                pkg_set.add(name)

    ref.declared_packages = sorted(pkg_set)
    return ref


# ─────────────────────── apk simulate ───────────────────────


def _docker_script() -> str:
    """Shell snippet that runs inside wolfi-base: one `apk add --simulate`
    per recipe, writing install lines to /out/<recipe>.txt.

    When `PRIVATE_APK_ORG` is set (passed via --env-file), append the private
    apk repo URL so apk resolves from both public and private repos. `HTTP_AUTH`
    (also from the env file) carries the basic-auth credentials apk's HTTP
    client needs to fetch the private APKINDEX.

    Per-recipe `apk add --simulate` failures are no longer silently swallowed:
    rc != 0 writes `/out/<recipe>.rc` + `/out/<recipe>.raw` so the host can
    populate closure_error on the corresponding RecipeRef. Success path is
    unchanged (no .rc/.raw written).
    """
    return (
        "set -eu; "
        'if [ -n "${PRIVATE_APK_ORG:-}" ]; then '
        '  echo "https://apk.cgr.dev/$PRIVATE_APK_ORG" >> /etc/apk/repositories; '
        "fi; "
        "apk update --quiet; "
        "apk add --no-cache --quiet jq >/dev/null 2>&1; "
        "for r in $(jq -r 'keys[]' /in.json); do "
        "  pkgs=$(jq -r --arg r \"$r\" '.[$r][]' /in.json | tr '\\n' ' '); "
        "  rc=0; "
        '  apk add --simulate --no-cache $pkgs > /out/"$r".raw 2>&1 || rc=$?; '
        '  grep -oE \'^\\([0-9]+/[0-9]+\\) Installing [^ ]+ \\([^)]+\\)\' /out/"$r".raw > /out/"$r".txt || true; '
        '  if [ "$rc" -ne 0 ]; then '
        '    echo "$rc" > /out/"$r".rc; '
        "  else "
        '    rm -f /out/"$r".raw; '
        "  fi; "
        "done"
    )


def _parse_apk_error(raw: str) -> tuple[str, list[str]]:
    """Parse apk's failure output into a short summary + unresolvable names.

    apk's failure output looks like:
        ERROR: unable to select packages:
          openssl-config-fipshardened (no such package):
            required by: world[openssl-config-fipshardened]

    Returns (short_summary <= 200 chars, [unresolvable_pkg_names]).
    """
    if not raw:
        return "", []
    unresolvable: list[str] = []
    seen: set[str] = set()
    for line in raw.splitlines():
        m = _APK_UNRESOLVABLE_RE.match(line)
        if m:
            name = m.group(1)
            if name not in seen:
                seen.add(name)
                unresolvable.append(name)
    # Summary: last few non-empty lines, capped at 200 chars.
    tail = [ln for ln in raw.splitlines() if ln.strip()][-5:]
    summary = " | ".join(tail).strip()
    if len(summary) > 200:
        summary = summary[:197] + "..."
    return summary, unresolvable


def simulate_apk_closure(
    by_recipe: dict[str, list[str]],
    base_image: str = DEFAULT_BASE_IMAGE,
    timeout: int = DEFAULT_DOCKER_TIMEOUT,
    tmp_root: str | None = None,
    apk_token: str = "",
    private_apk_org: str = "",
) -> dict[str, _RecipeClosureOutcome]:
    """Compute the transitive apk closure per recipe via `apk add --simulate`.

    Spins up one wolfi-base container, loops through every recipe inside it,
    writes per-recipe install lines to a bind-mounted output dir. Returns
    {recipe_key: _RecipeClosureOutcome} where the outcome captures the
    install lines, exit code, and any apk-error details.

    Per-recipe rather than one big union, because recipes can declare
    conflicting package families (python-3.11 vs python-3.13) that would
    poison a unified resolution.

    When `apk_token` and `private_apk_org` are both set, the function writes
    an env file (chmod 0o600) inside the bind-mount tempdir holding HTTP_AUTH
    + PRIVATE_APK_ORG and passes it to docker via --env-file. Keeping the
    token off the command line keeps it out of `ps` output.

    `tmp_root` controls where the bind-mount temp dir is created. On macOS,
    Docker Desktop only shares a handful of host paths by default — `/tmp`
    and `/var/folders/...` typically aren't on the list, so a tempdir under
    Python's default `$TMPDIR` mounts as an empty directory inside the
    container. Defaults to `~/.cache/verify-provenance/build-deps`, which
    is reliably reachable.
    """
    if not by_recipe:
        return {}

    if tmp_root is None:
        tmp_root = os.path.expanduser("~/.cache/verify-provenance/build-deps")
    os.makedirs(tmp_root, exist_ok=True)

    with tempfile.TemporaryDirectory(prefix="vp-build-env-", dir=tmp_root) as tmp:
        # Resolve symlinks (macOS /tmp → /private/tmp) so docker bind mounts work.
        tmp = os.path.realpath(tmp)
        in_path = os.path.join(tmp, "in.json")
        out_dir = os.path.join(tmp, "out")
        os.makedirs(out_dir, exist_ok=True)
        with open(in_path, "w", encoding="utf-8") as f:
            json.dump(by_recipe, f)

        env_file_path = ""
        if apk_token and private_apk_org:
            env_file_path = os.path.join(tmp, "apk.env")
            # Write with restrictive perms before content so the token never
            # touches a world-readable file descriptor.
            fd = os.open(env_file_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(f"HTTP_AUTH=basic:apk.cgr.dev:user:{apk_token}\n")
                f.write(f"PRIVATE_APK_ORG={private_apk_org}\n")

        cmd = [
            "docker",
            "run",
            "--rm",
            "--platform",
            "linux/amd64",
            "-v",
            f"{in_path}:/in.json:ro",
            "-v",
            f"{out_dir}:/out",
        ]
        if env_file_path:
            cmd.extend(["--env-file", env_file_path])
        cmd.extend([base_image, "sh", "-c", _docker_script()])

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise BuildEnvError(f"docker simulate timed out after {timeout}s") from None
        except FileNotFoundError:
            raise BuildEnvError("docker not found in PATH") from None
        if proc.returncode != 0:
            tail = ((proc.stderr or proc.stdout) or "").strip().splitlines()
            detail = "\n".join(tail[-5:])
            raise BuildEnvError(f"docker simulate failed (exit {proc.returncode}): {detail}")

        closures: dict[str, _RecipeClosureOutcome] = {}
        for recipe in by_recipe:
            out_path = os.path.join(out_dir, f"{recipe}.txt")
            rc_path = os.path.join(out_dir, f"{recipe}.rc")
            raw_path = os.path.join(out_dir, f"{recipe}.raw")
            pkgs: set[str] = set()
            if os.path.exists(out_path):
                with open(out_path, encoding="utf-8") as f:
                    for line in f:
                        m = _APK_INSTALL_RE.match(line.strip())
                        if m:
                            pkgs.add(f"{m.group(1)}={m.group(2)}")
            outcome = _RecipeClosureOutcome(packages=sorted(pkgs))
            if os.path.exists(rc_path):
                try:
                    with open(rc_path, encoding="utf-8") as f:
                        outcome.exit_code = int(f.read().strip() or "1")
                except (OSError, ValueError):
                    outcome.exit_code = 1
                raw = ""
                if os.path.exists(raw_path):
                    try:
                        with open(raw_path, encoding="utf-8", errors="replace") as f:
                            raw = f.read()
                    except OSError:
                        raw = ""
                outcome.error_summary, outcome.unresolvable_packages = _parse_apk_error(raw)
            closures[recipe] = outcome
        return closures


# ─────────────────────── Orchestration ───────────────────────


def _recipe_key(name: str) -> str:
    """Strip the .yaml suffix to produce a recipe key safe to use as a filename."""
    return name[:-5] if name.endswith(".yaml") else name


def enumerate_build_env(
    image_ref: str,
    image_digest: str,
    sbom_predicate: dict[str, object],
    github_token: str,
    *,
    repo: str = DEFAULT_STEREO_REPO,
    base_image: str = DEFAULT_BASE_IMAGE,
    max_workers: int = DEFAULT_MAX_WORKERS,
    docker_timeout: int = DEFAULT_DOCKER_TIMEOUT,
    tmp_root: str | None = None,
    apk_token: str = "",
    private_apk_org: str = "",
) -> BuildEnvResult:
    """Top-level orchestrator.

    1. Walk SBOM for melange recipe refs.
    2. Parallel-fetch recipes + their pipeline modules; collect declared deps.
    3. If any recipe is unresolvable, return with status=MISSING_RECIPES (fail loudly).
    4. Per-recipe apk add --simulate to get transitive closures.
    5. Union closures into the image-wide build env.

    Raises BuildEnvError for hard infrastructure failures (docker unavailable,
    GitHub auth invalid, yq missing). Recipe-not-found is *not* an exception.
    """
    result = BuildEnvResult(image=image_ref, image_digest=image_digest)
    result.private_apk_org = private_apk_org

    refs = extract_recipe_refs(sbom_predicate)
    if not refs:
        result.status = "SBOM_EMPTY"
        result.error = "no .yaml recipe refs found in SBOM packages[]"
        return result
    result.recipes = refs

    tree_cache: dict[str, dict[str, str]] = {}
    tree_lock = threading.Lock()
    workers = max(1, max_workers)

    def _worker(r: RecipeRef) -> RecipeRef:
        # Each ref ships with repo=DEFAULT_STEREO_REPO; override if caller asked.
        r.repo = repo
        return _process_recipe(r, github_token, tree_cache, tree_lock)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        processed = list(pool.map(_worker, refs))
    result.recipes = processed

    missing = [r for r in processed if r.error]
    if missing:
        result.missing_recipes = sorted({f"{r.name}@{r.commit_sha[:8]}" for r in missing})
        result.status = "MISSING_RECIPES"
        head = ", ".join(result.missing_recipes[:5])
        suffix = "..." if len(result.missing_recipes) > 5 else ""
        result.error = f"{len(missing)} recipe(s) could not be resolved from {repo}: {head}{suffix}"
        return result

    # Aggregate declared union + collect per-recipe lists for docker.
    declared_union: set[str] = set()
    pipeline_modules: set[str] = set()
    by_recipe: dict[str, list[str]] = {}
    for r in processed:
        declared_union.update(r.declared_packages)
        pipeline_modules.update(r.pipeline_modules)
        by_recipe[_recipe_key(r.name)] = list(r.declared_packages)
    result.declared_union = sorted(declared_union)
    result.pipeline_module_count = len(pipeline_modules)

    # Per-recipe apk simulate; failure of the docker invocation itself is fatal.
    # Per-recipe apk failures are NOT fatal — they surface via closure_error.
    try:
        closures = simulate_apk_closure(
            by_recipe,
            base_image=base_image,
            timeout=docker_timeout,
            tmp_root=tmp_root,
            apk_token=apk_token,
            private_apk_org=private_apk_org,
        )
    except BuildEnvError as e:
        result.status = "DOCKER_FAILED"
        result.error = str(e)
        return result

    # Wire closures back into the per-recipe records + build the image-wide union.
    name_to_ref = {_recipe_key(r.name): r for r in processed}
    closure_union: set[str] = set()
    errored: list[str] = []
    for key, outcome in closures.items():
        ref = name_to_ref.get(key)
        if ref is not None:
            ref.closure = outcome.packages
            if outcome.exit_code != 0:
                ref.closure_error = outcome.error_summary
                ref.unresolvable_packages = outcome.unresolvable_packages
                offenders = (
                    f" ({', '.join(outcome.unresolvable_packages)})"
                    if outcome.unresolvable_packages else ""
                )
                errored.append(f"{ref.name}{offenders}")
        closure_union.update(outcome.packages)
    result.closure_union = sorted(closure_union)
    result.closure_names = sorted({p.split("=", 1)[0] for p in closure_union})

    if errored:
        result.errored_recipes = sorted(errored)
        result.status = "CLOSURE_INCOMPLETE"

    return result
