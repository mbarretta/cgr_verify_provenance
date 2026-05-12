"""Tests for the build_env module — SBOM walk, GitHub fetch, recipe parsing,
template substitution, and the orchestrator's happy/missing/error paths."""

from __future__ import annotations

import base64
import json
import os
import subprocess
import sys
from typing import Any
from unittest.mock import MagicMock, patch

sys.path.insert(0, "..")

from build_env import (  # noqa: E402
    BuildEnvError,
    BuildEnvResult,
    _parse_apk_error,
    _RecipeClosureOutcome,
    enumerate_build_env,
    extract_recipe_refs,
    fetch_blob,
    fetch_tree,
    parse_pipeline_module,
    parse_recipe,
    simulate_apk_closure,
    substitute_vars,
)

GIT_SHA_A = "a" * 40
GIT_SHA_B = "b" * 40


# ─────────────────────── SBOM walk ───────────────────────


def _sbom_with_recipes(*pairs: tuple[str, str]) -> dict[str, Any]:
    """Build a minimal SPDX predicate from (name, versionInfo) tuples."""
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [{"name": n, "versionInfo": v} for n, v in pairs],
    }


class TestExtractRecipeRefs:
    def test_picks_yaml_with_sha40(self) -> None:
        sbom = _sbom_with_recipes(
            ("mongod-8.2.yaml", GIT_SHA_A),
            ("python-3.14.yaml", GIT_SHA_B),
            ("openssl", "3.6.2-r5"),  # not yaml — skip
            ("plain.txt", GIT_SHA_A),  # not yaml — skip
        )
        refs = extract_recipe_refs(sbom)
        assert [r.name for r in refs] == ["mongod-8.2.yaml", "python-3.14.yaml"]
        assert all(len(r.commit_sha) == 40 for r in refs)

    def test_rejects_non_sha_versioninfo(self) -> None:
        # yaml suffix but versionInfo is not a 40-char hex
        sbom = _sbom_with_recipes(("foo.yaml", "1.2.3"))
        assert extract_recipe_refs(sbom) == []

    def test_dedupes_on_name_sha(self) -> None:
        sbom = _sbom_with_recipes(
            ("foo.yaml", GIT_SHA_A),
            ("foo.yaml", GIT_SHA_A),  # exact dup — drop
            ("foo.yaml", GIT_SHA_B),  # same name, different sha — keep
        )
        refs = extract_recipe_refs(sbom)
        assert len(refs) == 2
        assert {r.commit_sha for r in refs} == {GIT_SHA_A, GIT_SHA_B}

    def test_sorts_for_stable_output(self) -> None:
        sbom = _sbom_with_recipes(
            ("zlib.yaml", GIT_SHA_A),
            ("apache2.yaml", GIT_SHA_B),
        )
        names = [r.name for r in extract_recipe_refs(sbom)]
        assert names == sorted(names)

    def test_non_dict_input(self) -> None:
        assert extract_recipe_refs([]) == []  # type: ignore[arg-type]
        assert extract_recipe_refs({"packages": "nope"}) == []

    def test_missing_packages_field(self) -> None:
        assert extract_recipe_refs({"spdxVersion": "SPDX-2.3"}) == []


# ─────────────────────── Template substitution ───────────────────────


class TestSubstituteVars:
    def test_replaces_var_token(self) -> None:
        assert substitute_vars("php-${{vars.php-version}}", {"php-version": "8.4"}) == "php-8.4"

    def test_strips_version_pin(self) -> None:
        assert substitute_vars("bash=5.3-r12", {}) == "bash"

    def test_no_vars_passthrough(self) -> None:
        assert substitute_vars("openssl-dev", {}) == "openssl-dev"

    def test_handles_special_chars_in_value(self) -> None:
        # A var value containing | would have broken the original sed
        # implementation; the python replacement is safe.
        assert substitute_vars("lib-${{vars.suffix}}", {"suffix": "weird|name"}) == "lib-weird|name"


# ─────────────────────── GitHub API ───────────────────────


def _mock_urlopen(payload: dict[str, Any]) -> MagicMock:
    """Build a mock that mimics `urllib.request.urlopen(...)` returning JSON bytes."""
    resp = MagicMock()
    resp.read.return_value = json.dumps(payload).encode("utf-8")
    resp.__enter__ = lambda self: self
    resp.__exit__ = lambda self, *args: False
    return resp


class TestFetchTree:
    def test_prefers_non_version_data_path(self) -> None:
        payload = {
            "tree": [
                {"type": "blob", "path": "version_data/adminer.yaml"},
                {"type": "blob", "path": "enterprise-packages/adminer.yaml"},
                {"type": "blob", "path": "os/glibc.yaml"},
            ]
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            result = fetch_tree("chainguard-dev/stereo", GIT_SHA_A, "tok")
        # adminer.yaml resolved to non-version_data
        assert result["adminer.yaml"] == "enterprise-packages/adminer.yaml"
        assert result["glibc.yaml"] == "os/glibc.yaml"

    def test_first_wins_when_no_deprioritized_match(self) -> None:
        payload = {
            "tree": [
                {"type": "blob", "path": "os/foo.yaml"},
                {"type": "blob", "path": "enterprise-packages/foo.yaml"},
            ]
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            result = fetch_tree("chainguard-dev/stereo", GIT_SHA_A, "tok")
        # First match wins when neither is deprioritized.
        assert result["foo.yaml"] == "os/foo.yaml"

    def test_skips_non_yaml_and_non_blob(self) -> None:
        payload = {
            "tree": [
                {"type": "tree", "path": "os"},  # directory — skip
                {"type": "blob", "path": "README.md"},  # not yaml — skip
                {"type": "blob", "path": "os/glibc.yaml"},
            ]
        }
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            result = fetch_tree("chainguard-dev/stereo", GIT_SHA_A, "tok")
        assert result == {"glibc.yaml": "os/glibc.yaml"}

    def test_http_error_raises_build_env_error(self) -> None:
        import urllib.error

        def _raise(*args: Any, **kwargs: Any) -> Any:
            raise urllib.error.HTTPError("u", 404, "Not Found", {}, None)  # type: ignore[arg-type]

        with patch("urllib.request.urlopen", side_effect=_raise):
            try:
                fetch_tree("chainguard-dev/stereo", GIT_SHA_A, "tok")
            except BuildEnvError as e:
                assert "404" in str(e)
            else:
                raise AssertionError("expected BuildEnvError")


class TestFetchBlob:
    def test_decodes_base64_content(self) -> None:
        yaml_text = "package:\n  name: foo\n"
        payload = {"content": base64.b64encode(yaml_text.encode("utf-8")).decode("ascii")}
        with patch("urllib.request.urlopen", return_value=_mock_urlopen(payload)):
            result = fetch_blob("chainguard-dev/stereo", GIT_SHA_A, "os/foo.yaml", "tok")
        assert result == yaml_text


# ─────────────────────── Recipe parsing (yq mock) ───────────────────────


def _yq_mock(per_expr: dict[str, Any]) -> Any:
    """Return a subprocess.run mock that responds to yq calls.

    Maps yq expression substrings → JSON strings.
    """

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        # cmd is ["yq", "-o=json", "<expr>", "-"]
        expr = cmd[2] if len(cmd) >= 3 else ""
        for needle, payload in per_expr.items():
            if needle in expr:
                return subprocess.CompletedProcess(
                    cmd, 0, stdout=json.dumps(payload) + "\n", stderr=""
                )
        return subprocess.CompletedProcess(cmd, 0, stdout="null\n", stderr="")

    return _fake_run


class TestParseRecipe:
    def test_extracts_packages_uses_vars(self) -> None:
        m = _yq_mock(
            {
                ".environment.contents.packages": ["bash", "build-base"],
                ".pipeline[]?.uses": ["fetch", "git-checkout"],
                ".vars // {}": {"php-version": "8.4"},
            }
        )
        with patch("subprocess.run", side_effect=m):
            pkgs, uses, vars_map = parse_recipe("dummy: yaml")
        assert pkgs == ["bash", "build-base"]
        assert uses == ["fetch", "git-checkout"]
        assert vars_map == {"php-version": "8.4"}

    def test_empty_recipe_returns_empty_lists(self) -> None:
        m = _yq_mock({})  # everything returns null
        with patch("subprocess.run", side_effect=m):
            pkgs, uses, vars_map = parse_recipe("foo: bar")
        assert pkgs == []
        assert uses == []
        assert vars_map == {}

    def test_yq_failure_raises(self) -> None:
        def _fail(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="yq: parse error")

        with patch("subprocess.run", side_effect=_fail):
            try:
                parse_recipe("invalid")
            except BuildEnvError as e:
                assert "yq" in str(e)
            else:
                raise AssertionError("expected BuildEnvError")


class TestParsePipelineModule:
    def test_returns_needs_packages(self) -> None:
        m = _yq_mock({".needs.packages": ["autoconf", "automake"]})
        with patch("subprocess.run", side_effect=m):
            assert parse_pipeline_module("dummy") == ["autoconf", "automake"]


# ─────────────────────── apk simulate ───────────────────────


class TestSimulateApkClosure:
    def test_returns_empty_for_no_input(self) -> None:
        assert simulate_apk_closure({}) == {}

    def test_parses_install_lines_per_recipe(self, tmp_path: Any) -> None:
        # We mock subprocess.run so docker is never called. The mock writes
        # the expected per-recipe output files into the bind-mount dir.
        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            # cmd looks like [docker, run, ..., -v IN:/in.json:ro, -v OUT:/out, ...]
            out_dir = ""
            for i, a in enumerate(cmd):
                if a == "-v" and i + 1 < len(cmd) and ":/out" in cmd[i + 1]:
                    out_dir = cmd[i + 1].split(":", 1)[0]
            assert out_dir, "could not extract /out bind mount from cmd"
            # Simulate two recipes' worth of install lines.
            with open(os.path.join(out_dir, "foo.txt"), "w") as f:
                f.write("(1/3) Installing bash (5.3-r12)\n")
                f.write("(2/3) Installing libc (2.43-r7)\n")
                f.write("(3/3) Installing zlib (1.3.2-r3)\n")
            with open(os.path.join(out_dir, "bar.txt"), "w") as f:
                f.write("(1/1) Installing curl (8.12.1-r0)\n")
            return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

        with patch("subprocess.run", side_effect=_fake_run):
            result = simulate_apk_closure({"foo": ["bash", "libc"], "bar": ["curl"]})
        assert result["foo"].packages == ["bash=5.3-r12", "libc=2.43-r7", "zlib=1.3.2-r3"]
        assert result["foo"].exit_code == 0
        assert result["bar"].packages == ["curl=8.12.1-r0"]
        assert result["bar"].exit_code == 0

    def test_docker_failure_raises(self) -> None:
        def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
            return subprocess.CompletedProcess(cmd, 1, stdout="", stderr="docker: error")

        with patch("subprocess.run", side_effect=_fake_run):
            try:
                simulate_apk_closure({"foo": ["bash"]})
            except BuildEnvError as e:
                assert "docker simulate" in str(e)
            else:
                raise AssertionError("expected BuildEnvError")


# ─────────────────────── Orchestrator ───────────────────────


def _enumerate_with_mocks(
    sbom: dict[str, Any],
    *,
    tree: dict[str, str],
    recipe_yamls: dict[str, str],
    pipeline_packages: dict[str, list[str]] | None = None,
    yq_response: dict[str, Any] | None = None,
    closures: dict[str, Any] | None = None,
    apk_token: str = "",
    private_apk_org: str = "",
) -> BuildEnvResult:
    """Run enumerate_build_env with all I/O mocked.

    `tree`: basename → path map returned by fetch_tree.
    `recipe_yamls`: path → yaml text returned by fetch_blob for that path.
    `pipeline_packages`: optional pipelines/<mod>.yaml → needs.packages list.
    `yq_response`: fixed yq response (declared, uses, vars) for any recipe.
    `closures`: per-recipe-key apk closure to return from docker.
    """
    pipeline_packages = pipeline_packages or {}
    closures = closures or {}

    def _mock_fetch_tree(repo: str, sha: str, token: str) -> dict[str, str]:
        return tree

    def _mock_fetch_blob(repo: str, sha: str, path: str, token: str) -> str:
        if path in recipe_yamls:
            return recipe_yamls[path]
        # pipelines/<mod>.yaml
        if path in pipeline_packages:
            return f"# {path}\n"  # text doesn't matter, parse is mocked
        raise BuildEnvError(f"path not found: {path}")

    def _mock_parse_recipe(text: str) -> tuple[list[str], list[str], dict[str, str]]:
        r = yq_response or {"declared": [], "uses": [], "vars": {}}
        return list(r.get("declared", [])), list(r.get("uses", [])), dict(r.get("vars", {}))

    def _mock_parse_pipeline(text: str) -> list[str]:
        # Recover module ref from the placeholder body we wrote in _mock_fetch_blob.
        path = text.strip("# \n")
        return pipeline_packages.get(path, [])

    def _mock_simulate(
        by_recipe: dict[str, list[str]], **kwargs: Any
    ) -> dict[str, _RecipeClosureOutcome]:
        # Use the supplied closures if present; else echo the declared set.
        if closures:
            out: dict[str, _RecipeClosureOutcome] = {}
            for k, v in closures.items():
                if isinstance(v, _RecipeClosureOutcome):
                    out[k] = v
                else:
                    out[k] = _RecipeClosureOutcome(packages=list(v))
            return out
        return {
            k: _RecipeClosureOutcome(packages=sorted({f"{p}=1.0-r0" for p in v}))
            for k, v in by_recipe.items()
        }

    with (
        patch("build_env.fetch_tree", side_effect=_mock_fetch_tree),
        patch("build_env.fetch_blob", side_effect=_mock_fetch_blob),
        patch("build_env.parse_recipe", side_effect=_mock_parse_recipe),
        patch("build_env.parse_pipeline_module", side_effect=_mock_parse_pipeline),
        patch("build_env.simulate_apk_closure", side_effect=_mock_simulate),
    ):
        return enumerate_build_env(
            image_ref="cgr.dev/test/img:latest",
            image_digest="sha256:" + "f" * 64,
            sbom_predicate=sbom,
            github_token="tok",
            apk_token=apk_token,
            private_apk_org=private_apk_org,
        )


class TestEnumerateBuildEnv:
    def test_empty_sbom_sets_status(self) -> None:
        result = _enumerate_with_mocks({"packages": []}, tree={}, recipe_yamls={})
        assert result.status == "SBOM_EMPTY"
        assert result.error

    def test_missing_recipe_fails_loudly(self) -> None:
        sbom = _sbom_with_recipes(("missing.yaml", GIT_SHA_A))
        result = _enumerate_with_mocks(
            sbom,
            tree={},  # tree empty → recipe unresolvable
            recipe_yamls={},
        )
        assert result.status == "MISSING_RECIPES"
        assert result.missing_recipes == [f"missing.yaml@{GIT_SHA_A[:8]}"]

    def test_happy_path(self) -> None:
        sbom = _sbom_with_recipes(
            ("foo.yaml", GIT_SHA_A),
            ("bar.yaml", GIT_SHA_A),
        )
        result = _enumerate_with_mocks(
            sbom,
            tree={"foo.yaml": "os/foo.yaml", "bar.yaml": "os/bar.yaml"},
            recipe_yamls={"os/foo.yaml": "foo body", "os/bar.yaml": "bar body"},
            yq_response={
                "declared": ["bash", "build-base"],
                "uses": [],
                "vars": {},
            },
            closures={
                "foo": ["bash=5.3-r12", "libc=2.43-r7"],
                "bar": ["bash=5.3-r12", "openssl=3.6.2-r5"],
            },
        )
        assert result.status == "OK"
        assert {r.name for r in result.recipes} == {"foo.yaml", "bar.yaml"}
        # Both recipes declared the same set, so declared_union is the set itself.
        assert set(result.declared_union) == {"bash", "build-base"}
        # Closure union spans both recipes.
        assert set(result.closure_names) == {"bash", "libc", "openssl"}
        # Per-recipe closures got wired back into the RecipeRef list.
        foo = next(r for r in result.recipes if r.name == "foo.yaml")
        assert foo.closure == ["bash=5.3-r12", "libc=2.43-r7"]

    def test_pipeline_modules_add_packages(self) -> None:
        sbom = _sbom_with_recipes(("foo.yaml", GIT_SHA_A))
        result = _enumerate_with_mocks(
            sbom,
            tree={"foo.yaml": "os/foo.yaml"},
            recipe_yamls={"os/foo.yaml": "foo body"},
            yq_response={
                "declared": ["build-base"],
                "uses": ["python/install"],
                "vars": {},
            },
            pipeline_packages={
                "pipelines/python/install.yaml": ["py3-pip", "python3"],
            },
            closures={"foo": ["build-base=1-r0", "python3=3.14-r0", "py3-pip=26-r0"]},
        )
        assert result.status == "OK"
        # pipeline_module_count reflects the unique `uses:` refs across recipes.
        assert result.pipeline_module_count == 1
        # Recipe declared_packages picked up the pipeline module's deps.
        foo = result.recipes[0]
        assert set(foo.declared_packages) == {"build-base", "py3-pip", "python3"}


# ─────────────────────── v2: private apk repo + per-recipe failures ───────────────────────


class TestParseApkError:
    def test_extracts_unresolvable_packages(self) -> None:
        raw = (
            "ERROR: unable to select packages:\n"
            "  openssl-config-fipshardened (no such package):\n"
            "    required by: world[openssl-config-fipshardened]\n"
            "  chainguard-baselayout (no such package):\n"
            "    required by: world[chainguard-baselayout]\n"
        )
        summary, names = _parse_apk_error(raw)
        assert names == ["openssl-config-fipshardened", "chainguard-baselayout"]
        assert "unable to select packages" in summary

    def test_dedupes_unresolvable_names(self) -> None:
        raw = (
            "  foo (no such package):\n"
            "    required by: world[foo]\n"
            "  foo (no such package):\n"
            "    required by: bar[foo]\n"
        )
        _, names = _parse_apk_error(raw)
        assert names == ["foo"]

    def test_empty_input_returns_empty(self) -> None:
        assert _parse_apk_error("") == ("", [])

    def test_summary_capped_at_200_chars(self) -> None:
        raw = "\n".join(["x" * 100 for _ in range(20)])
        summary, _ = _parse_apk_error(raw)
        assert len(summary) <= 200


def _run_simulate_capturing_cmd(
    apk_token: str,
    private_apk_org: str,
    *,
    write_failure_for: str = "",
    failure_raw: str = "",
) -> tuple[list[str], dict[str, Any]]:
    """Helper: mock subprocess.run, capture the docker cmd, optionally write
    a per-recipe failure (`.rc` + `.raw`) into the bind-mount dir.

    Returns (cmd, result_dict).
    """
    captured: dict[str, list[str]] = {}
    captured_env_file: dict[str, str] = {}

    def _fake_run(cmd: list[str], **kwargs: Any) -> subprocess.CompletedProcess[str]:
        captured["cmd"] = list(cmd)
        out_dir = ""
        env_file_path = ""
        for i, a in enumerate(cmd):
            if a == "-v" and i + 1 < len(cmd) and ":/out" in cmd[i + 1]:
                out_dir = cmd[i + 1].split(":", 1)[0]
            if a == "--env-file" and i + 1 < len(cmd):
                env_file_path = cmd[i + 1]
        assert out_dir, "could not extract /out bind mount from cmd"
        # Write a success line for the "ok" recipe.
        with open(os.path.join(out_dir, "ok.txt"), "w") as f:
            f.write("(1/1) Installing bash (5.3-r12)\n")
        if write_failure_for:
            with open(os.path.join(out_dir, f"{write_failure_for}.rc"), "w") as f:
                f.write("1\n")
            with open(os.path.join(out_dir, f"{write_failure_for}.raw"), "w") as f:
                f.write(failure_raw)
            # The .txt for the failed recipe stays empty.
            open(os.path.join(out_dir, f"{write_failure_for}.txt"), "w").close()
        if env_file_path and os.path.exists(env_file_path):
            with open(env_file_path) as f:
                captured_env_file["contents"] = f.read()
            captured_env_file["mode"] = oct(os.stat(env_file_path).st_mode & 0o777)
        return subprocess.CompletedProcess(cmd, 0, stdout="", stderr="")

    by_recipe = {"ok": ["bash"]}
    if write_failure_for:
        by_recipe[write_failure_for] = ["chainguard-baselayout"]

    with patch("subprocess.run", side_effect=_fake_run):
        outcomes = simulate_apk_closure(
            by_recipe,
            apk_token=apk_token,
            private_apk_org=private_apk_org,
        )
    return captured.get("cmd", []), {"outcomes": outcomes, "env_file": captured_env_file}


class TestSimulateApkClosurePrivateRepo:
    def test_writes_env_file_when_token_set(self) -> None:
        cmd, extra = _run_simulate_capturing_cmd(
            apk_token="jwt-stub-token", private_apk_org="chainguard-private"
        )
        assert "--env-file" in cmd
        env_idx = cmd.index("--env-file")
        env_path = cmd[env_idx + 1]
        # The env-file path lives inside the bind-mount tempdir.
        assert env_path.endswith("apk.env")
        contents = extra["env_file"]["contents"]
        assert "HTTP_AUTH=basic:apk.cgr.dev:user:jwt-stub-token" in contents
        assert "PRIVATE_APK_ORG=chainguard-private" in contents
        # Permissions are 0o600 — token must never be world-readable.
        assert extra["env_file"]["mode"] == "0o600"

    def test_no_env_file_when_token_empty(self) -> None:
        # No token → no --env-file, public-only behavior preserved.
        cmd, extra = _run_simulate_capturing_cmd(apk_token="", private_apk_org="")
        assert "--env-file" not in cmd
        assert extra["env_file"] == {}

    def test_no_env_file_when_org_empty_but_token_set(self) -> None:
        # Defensive: if only one of the two is set, fall back to public-only.
        cmd, _ = _run_simulate_capturing_cmd(apk_token="tok", private_apk_org="")
        assert "--env-file" not in cmd

    def test_captures_per_recipe_failure(self) -> None:
        raw = (
            "ERROR: unable to select packages:\n"
            "  chainguard-baselayout (no such package):\n"
            "    required by: world[chainguard-baselayout]\n"
        )
        _, extra = _run_simulate_capturing_cmd(
            apk_token="",
            private_apk_org="",
            write_failure_for="broken",
            failure_raw=raw,
        )
        outcomes = extra["outcomes"]
        assert outcomes["ok"].exit_code == 0
        assert outcomes["ok"].packages == ["bash=5.3-r12"]
        # Failed recipe: exit_code != 0, packages empty, error parsed.
        broken = outcomes["broken"]
        assert broken.exit_code == 1
        assert broken.packages == []
        assert broken.unresolvable_packages == ["chainguard-baselayout"]
        assert "unable to select packages" in broken.error_summary


class TestEnumerateBuildEnvClosureErrors:
    def test_partial_closure_status(self) -> None:
        sbom = _sbom_with_recipes(
            ("ok.yaml", GIT_SHA_A),
            ("broken.yaml", GIT_SHA_A),
        )
        # Mix: ok resolves; broken fails with one unresolvable package.
        result = _enumerate_with_mocks(
            sbom,
            tree={"ok.yaml": "os/ok.yaml", "broken.yaml": "os/broken.yaml"},
            recipe_yamls={
                "os/ok.yaml": "ok body",
                "os/broken.yaml": "broken body",
            },
            yq_response={"declared": ["bash"], "uses": [], "vars": {}},
            closures={
                "ok": _RecipeClosureOutcome(packages=["bash=5.3-r12"]),
                "broken": _RecipeClosureOutcome(
                    packages=[],
                    exit_code=1,
                    error_summary="ERROR: unable to select packages",
                    unresolvable_packages=["chainguard-baselayout"],
                ),
            },
            private_apk_org="chainguard-private",
        )
        assert result.status == "CLOSURE_INCOMPLETE"
        assert result.errored_recipes == ["broken.yaml (chainguard-baselayout)"]
        assert result.private_apk_org == "chainguard-private"
        # Working recipe's packages still land in closure_names.
        assert "bash" in result.closure_names
        # The failed RecipeRef has closure_error populated.
        broken = next(r for r in result.recipes if r.name == "broken.yaml")
        assert broken.closure_error
        assert broken.unresolvable_packages == ["chainguard-baselayout"]
        assert broken.closure == []
        # The healthy RecipeRef has no closure_error.
        ok = next(r for r in result.recipes if r.name == "ok.yaml")
        assert ok.closure_error == ""
        assert ok.closure == ["bash=5.3-r12"]

    def test_all_recipes_succeed_keeps_status_ok(self) -> None:
        sbom = _sbom_with_recipes(("foo.yaml", GIT_SHA_A))
        result = _enumerate_with_mocks(
            sbom,
            tree={"foo.yaml": "os/foo.yaml"},
            recipe_yamls={"os/foo.yaml": "foo body"},
            yq_response={"declared": ["bash"], "uses": [], "vars": {}},
            closures={"foo": _RecipeClosureOutcome(packages=["bash=5.3-r12"])},
            private_apk_org="chainguard-private",
        )
        assert result.status == "OK"
        assert result.errored_recipes == []
        assert result.private_apk_org == "chainguard-private"


class TestRunBuildDepsModeStrictClosure:
    """Driver-level test: --strict-closure flips the exit code on incomplete closure."""

    def _build_args(self, *, strict_closure: bool) -> Any:
        import argparse as _argparse

        return _argparse.Namespace(
            image="cgr.dev/test/img:latest",
            format="json",
            csv_output=None,
            trusted_root=None,
            max_workers=4,
            docker_timeout=60,
            stereo_repo="chainguard-dev/stereo",
            base_image="cgr.dev/chainguard/wolfi-base",
            cache_dir="",
            apk_org="chainguard-private",
            no_private_apk=True,  # skip chainctl in the test driver
            strict_closure=strict_closure,
            verbose=False,
        )

    def _run(self, status: str, strict: bool) -> int:
        # Lazy import so we can monkey-patch verify_provenance internals.
        sys.path.insert(0, "..")
        import verify_provenance as vp  # noqa: E402

        fake_result = BuildEnvResult(image="cgr.dev/test/img:latest", status=status)

        attest = MagicMock()
        attest.verified = True
        attest.subject_matches = True
        attest.subject_digests = ["sha256:" + "f" * 64]
        attest.predicate = {"packages": []}
        attest.error = ""

        with (
            patch.object(vp, "check_dependencies", return_value=[]),
            patch.object(vp, "run_cmd", return_value=(True, "sha256:" + "f" * 64, "")),
            patch("attestation.retrieve_and_verify_attestation", return_value=attest),
            patch("upstream.github_token", return_value="gh-tok"),
            patch("build_env.enumerate_build_env", return_value=fake_result),
            patch("sys.stdout"),
        ):
            return vp.run_build_deps_mode(self._build_args(strict_closure=strict))

    def test_strict_closure_exits_1_on_incomplete(self) -> None:
        assert self._run("CLOSURE_INCOMPLETE", strict=True) == 1

    def test_non_strict_exits_0_on_incomplete(self) -> None:
        assert self._run("CLOSURE_INCOMPLETE", strict=False) == 0

    def test_ok_exits_0(self) -> None:
        assert self._run("OK", strict=True) == 0

    def test_missing_recipes_exits_1_regardless_of_strict(self) -> None:
        assert self._run("MISSING_RECIPES", strict=False) == 1
