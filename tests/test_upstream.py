"""Tests for the upstream module — SPDX walk + git/http verification glue.

Mocks subprocess (`run_cmd`) and `urllib.request.urlopen` so the suite stays
hermetic. No real network or git binary is exercised.
"""

from __future__ import annotations

import io
import sys
import threading
from typing import Any
from unittest.mock import patch

sys.path.insert(0, "..")

import upstream  # noqa: E402
from upstream import (  # noqa: E402
    UpstreamSource,
    UpstreamSummary,
    UpstreamVerifyResult,
    _cache_key,
    _first_commit_in,
    _inject_github_token,
    _parse_purl,
    _resolve_purl,
    _split_vcs_url,
    download_and_hash,
    github_token,
    resolve_git_commit,
    verify_sources,
    walk_spdx_sources,
)


# ────────────────────────────── purl + walk ──────────────────────────────


class TestParsePurl:
    def test_github_basic(self) -> None:
        ptype, ns, ver, q = _parse_purl("pkg:github/openssl/openssl@openssl-3.6.1")
        assert ptype == "github"
        assert ns == "openssl/openssl"
        assert ver == "openssl-3.6.1"
        assert q == {}

    def test_generic_with_qualifiers(self) -> None:
        purl = (
            "pkg:generic/ca-certs@20251003"
            "?vcs_url=git+https://gitlab.alpinelinux.org/alpine/ca-certificates@ee722aa"
        )
        ptype, ns, ver, q = _parse_purl(purl)
        assert ptype == "generic"
        assert ns == "ca-certs"
        assert ver == "20251003"
        assert "vcs_url" in q
        assert "ee722aa" in q["vcs_url"]

    def test_generic_with_download_and_checksum(self) -> None:
        purl = "pkg:generic/gdbm@1.26?download_url=https://x/g.tar.gz&checksum=sha256:6a24504"
        _, _, _, q = _parse_purl(purl)
        assert q["download_url"] == "https://x/g.tar.gz"
        assert q["checksum"] == "sha256:6a24504"

    def test_handles_subpath(self) -> None:
        ptype, ns, ver, _ = _parse_purl("pkg:github/foo/bar@v1#subdir")
        assert ptype == "github"
        assert ns == "foo/bar"
        assert ver == "v1"

    def test_url_decodes_qualifier(self) -> None:
        purl = "pkg:generic/x@1.0?download_url=https%3A%2F%2Fa.com%2Fb"
        _, _, _, q = _parse_purl(purl)
        assert q["download_url"] == "https://a.com/b"

    def test_non_purl_returns_empty(self) -> None:
        assert _parse_purl("not-a-purl") == ("", "", "", {})


class TestSplitVcsUrl:
    def test_strips_git_plus(self) -> None:
        u, c = _split_vcs_url("git+https://example.com/r@deadbeef")
        assert u == "https://example.com/r"
        assert c == "deadbeef"

    def test_no_commit(self) -> None:
        u, c = _split_vcs_url("https://example.com/r")
        assert u == "https://example.com/r"
        assert c == ""


class TestResolvePurl:
    def test_github_uses_spdxid_commit(self) -> None:
        src = _resolve_purl(
            "pkg:github/openssl/openssl@openssl-3.6.1",
            "SPDXRef-Package-c9a9e5b00000000000000000000000000abcdef0",
            "openssl-3.6.1-r2",
        )
        assert src.source_type == "git"
        assert src.url == "https://github.com/openssl/openssl"
        assert src.tag == "openssl-3.6.1"
        assert src.commit == "c9a9e5b00000000000000000000000000abcdef0"

    def test_gitlab_basic(self) -> None:
        src = _resolve_purl(
            "pkg:gitlab/gnutools/glibc@glibc-2.43",
            "SPDXRef-Package-f762ccfdeadbeefdeadbeefdeadbeefdeadbeef0",
            "glibc-2.43-r2",
        )
        assert src.source_type == "git"
        assert src.url == "https://gitlab.com/gnutools/glibc"
        assert src.tag == "glibc-2.43"

    def test_generic_vcs_url_path(self) -> None:
        purl = (
            "pkg:generic/wolfi-baselayout@20230201-r28"
            "?vcs_url=git+https://github.com/chainguard-dev/stereo@ea04c39"
        )
        src = _resolve_purl(purl, "SPDXRef-Package-foo", "wolfi-baselayout-20230201-r28")
        assert src.source_type == "git"
        assert src.url == "https://github.com/chainguard-dev/stereo"
        assert src.commit == "ea04c39"

    def test_generic_download_url_path(self) -> None:
        purl = (
            "pkg:generic/gdbm@1.26"
            "?download_url=https://ftpmirror.gnu.org/gnu/gdbm/gdbm-1.26.tar.gz"
            "&checksum=sha256:6a24504"
        )
        src = _resolve_purl(purl, "SPDXRef-Package-x", "gdbm-1.26-r2")
        assert src.source_type == "http"
        assert src.url.endswith("gdbm-1.26.tar.gz")
        assert src.checksum == "sha256:6a24504"

    def test_generic_without_qualifiers_falls_back(self) -> None:
        src = _resolve_purl("pkg:generic/foo@1.0", "SPDXRef-Package-foo", "label")
        assert src.source_type == "none"


class TestFirstCommitIn:
    def test_extracts_40hex(self) -> None:
        assert (
            _first_commit_in("SPDXRef-Package-c9a9e5b9d3e60ddc9d8e2c9d8e2c9d8e2c9d8e2c")
            == "c9a9e5b9d3e60ddc9d8e2c9d8e2c9d8e2c9d8e2c"
        )

    def test_no_match_returns_empty(self) -> None:
        assert _first_commit_in("SPDXRef-Package-foo") == ""


def _spdx_pkg(
    spdxid: str,
    name: str,
    version: str = "",
    purls: list[str] | None = None,
) -> dict[str, Any]:
    p: dict[str, Any] = {"SPDXID": spdxid, "name": name}
    if version:
        p["versionInfo"] = version
    if purls:
        p["externalRefs"] = [
            {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl", "referenceLocator": q}
            for q in purls
        ]
    return p


def _spdx_doc(packages: list[dict[str, Any]], rels: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "spdxVersion": "SPDX-2.3",
        "name": "image-sbom",
        "packages": packages,
        "relationships": rels,
    }


class TestWalkSpdxSources:
    def test_generated_from_takes_priority(self) -> None:
        # bin → src via GENERATED_FROM
        bin_pkg = _spdx_pkg("SPDXRef-Package-bin", "openssl", "3.6.1")
        src_pkg = _spdx_pkg(
            "SPDXRef-Package-c9a9e5b9d3e60ddc9d8e2c9d8e2c9d8e2c9d8e2c",
            "openssl-source",
            "openssl-3.6.1",
            ["pkg:github/openssl/openssl@openssl-3.6.1"],
        )
        # Also a DESCRIBED_BY pointing at a melange config — should be ignored
        # because GENERATED_FROM wins.
        cfg_pkg = _spdx_pkg(
            "SPDXRef-Package-cfg",
            "openssl-melange",
            "1",
            ["pkg:generic/openssl@1?download_url=http://x&checksum=sha256:abc"],
        )
        doc = _spdx_doc(
            [bin_pkg, src_pkg, cfg_pkg],
            [
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": src_pkg["SPDXID"],
                    "relationshipType": "GENERATED_FROM",
                },
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": "SPDXRef-Package-cfg",
                    "relationshipType": "DESCRIBED_BY",
                },
            ],
        )
        sources = walk_spdx_sources(doc)
        assert len(sources) == 1
        assert sources[0].source_type == "git"
        assert sources[0].url == "https://github.com/openssl/openssl"

    def test_described_by_fallback(self) -> None:
        bin_pkg = _spdx_pkg("SPDXRef-Package-bin", "ca-certs")
        cfg_pkg = _spdx_pkg(
            "SPDXRef-Package-cfg",
            "ca-certs-config",
            purls=[
                "pkg:generic/ca-certs@20251003"
                "?vcs_url=git+https://gitlab.alpinelinux.org/alpine/ca-certificates@ee722aa"
            ],
        )
        doc = _spdx_doc(
            [bin_pkg, cfg_pkg],
            [
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": "SPDXRef-Package-cfg",
                    "relationshipType": "DESCRIBED_BY",
                }
            ],
        )
        sources = walk_spdx_sources(doc)
        assert len(sources) == 1
        assert sources[0].source_type == "git"
        assert sources[0].commit == "ee722aa"

    def test_no_relationship_yields_no_source(self) -> None:
        # Standalone package with no GENERATED_FROM/DESCRIBED_BY edge → not a
        # candidate for verification.
        bin_pkg = _spdx_pkg("SPDXRef-Package-bin", "thing")
        doc = _spdx_doc([bin_pkg], [])
        assert walk_spdx_sources(doc) == []

    def test_target_package_with_no_purl_skips(self) -> None:
        bin_pkg = _spdx_pkg("SPDXRef-Package-bin", "thing")
        src_pkg = _spdx_pkg("SPDXRef-Package-src", "thing-src")
        doc = _spdx_doc(
            [bin_pkg, src_pkg],
            [
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": "SPDXRef-Package-src",
                    "relationshipType": "GENERATED_FROM",
                }
            ],
        )
        sources = walk_spdx_sources(doc)
        assert len(sources) == 1
        assert sources[0].source_type == "none"

    def test_label_uses_name_version(self) -> None:
        bin_pkg = _spdx_pkg("SPDXRef-Package-bin", "openssl", "3.6.1-r2")
        src_pkg = _spdx_pkg(
            "SPDXRef-Package-c9a9e5b9d3e60ddc9d8e2c9d8e2c9d8e2c9d8e2c",
            "openssl-source",
            purls=["pkg:github/openssl/openssl@openssl-3.6.1"],
        )
        doc = _spdx_doc(
            [bin_pkg, src_pkg],
            [
                {
                    "spdxElementId": "SPDXRef-Package-bin",
                    "relatedSpdxElement": src_pkg["SPDXID"],
                    "relationshipType": "GENERATED_FROM",
                }
            ],
        )
        assert walk_spdx_sources(doc)[0].label == "openssl-3.6.1-r2"

    def test_handles_non_dict_predicate(self) -> None:
        assert walk_spdx_sources(None) == []  # type: ignore[arg-type]
        assert walk_spdx_sources({}) == []
        assert walk_spdx_sources({"packages": "not-a-list", "relationships": []}) == []


# ─────────────────────────── git ls-remote path ───────────────────────────


def _ls_remote_output(refs: dict[str, str]) -> str:
    return "".join(f"{sha}\t{ref}\n" for ref, sha in refs.items())


class TestResolveGitCommit:
    def test_peeled_tag_preferred_over_unpeeled(self) -> None:
        out = _ls_remote_output(
            {
                "refs/tags/v1.0": "1111111111111111111111111111111111111111",
                "refs/tags/v1.0^{}": "2222222222222222222222222222222222222222",
            }
        )
        with patch("upstream.run_cmd", return_value=(True, out, "")):
            commit, err = resolve_git_commit("https://x/repo", "v1.0")
        assert commit == "2222222222222222222222222222222222222222"
        assert err == ""

    def test_lightweight_tag_returns_unpeeled(self) -> None:
        out = _ls_remote_output(
            {
                "refs/tags/v1.0": "3333333333333333333333333333333333333333",
            }
        )
        with patch("upstream.run_cmd", return_value=(True, out, "")):
            commit, err = resolve_git_commit("https://x/repo", "v1.0")
        assert commit == "3333333333333333333333333333333333333333"
        assert err == ""

    def test_tag_not_found(self) -> None:
        with patch("upstream.run_cmd", return_value=(True, "", "")):
            commit, err = resolve_git_commit("https://x/repo", "missing")
        assert commit == ""
        assert "not found" in err

    def test_command_failure_surfaces_stderr(self) -> None:
        with patch("upstream.run_cmd", return_value=(False, "", "fatal: bad ref\nextra")):
            commit, err = resolve_git_commit("https://x/repo", "v1.0")
        assert commit == ""
        assert "extra" in err

    def test_token_redacted_from_error(self) -> None:
        with patch(
            "upstream.run_cmd",
            return_value=(False, "", "fatal: clone https://oauth2:SECRET@host/foo failed"),
        ):
            commit, err = resolve_git_commit("https://host/foo", "v1.0", "SECRET")
        assert "SECRET" not in err
        assert "***" in err

    def test_missing_inputs_short_circuits(self) -> None:
        commit, err = resolve_git_commit("", "v1.0")
        assert commit == ""
        assert "missing" in err


class TestInjectGithubToken:
    def test_inserts_creds_for_github(self) -> None:
        u = _inject_github_token("https://github.com/o/r", "TOK")
        assert u == "https://oauth2:TOK@github.com/o/r"

    def test_no_token_no_change(self) -> None:
        assert _inject_github_token("https://github.com/o/r", "") == "https://github.com/o/r"

    def test_non_github_unchanged(self) -> None:
        assert _inject_github_token("https://gitlab.com/o/r", "TOK") == "https://gitlab.com/o/r"

    def test_creds_already_present_unchanged(self) -> None:
        u = "https://user:pw@github.com/o/r"
        assert _inject_github_token(u, "TOK") == u


class TestGithubToken:
    def test_env_takes_precedence(self) -> None:
        with patch.dict("os.environ", {"GITHUB_TOKEN": "TENV", "GH_TOKEN": "B"}, clear=False):
            assert github_token() == "TENV"

    def test_falls_back_to_gh_cli(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with patch("upstream.run_cmd", return_value=(True, "GHCLI\n", "")):
                assert github_token() == "GHCLI"

    def test_returns_empty_when_nothing(self) -> None:
        with patch.dict("os.environ", {}, clear=True):
            with patch("upstream.run_cmd", return_value=(False, "", "no auth")):
                assert github_token() == ""


# ───────────────────────── http download + hash ─────────────────────────


class _FakeResp:
    """Minimal urllib response with a `read` API and context-manager support."""

    def __init__(self, data: bytes) -> None:
        self._buf = io.BytesIO(data)

    def __enter__(self) -> "_FakeResp":
        return self

    def __exit__(self, *args: Any) -> None:  # noqa: D401
        return None

    def read(self, n: int) -> bytes:
        return self._buf.read(n)


class TestDownloadAndHash:
    def test_sha256_match_path(self) -> None:
        import hashlib

        data = b"hello upstream\n"
        expected = "sha256:" + hashlib.sha256(data).hexdigest()
        with patch("urllib.request.OpenerDirector.open", return_value=_FakeResp(data)):
            got, err = download_and_hash("https://x/y", expected)
        assert err == ""
        assert got == hashlib.sha256(data).hexdigest()

    def test_sha512_match_path(self) -> None:
        import hashlib

        data = b"hello sha512\n"
        expected = "sha512:" + hashlib.sha512(data).hexdigest()
        with patch("urllib.request.OpenerDirector.open", return_value=_FakeResp(data)):
            got, err = download_and_hash("https://x/y", expected)
        assert err == ""
        assert got == hashlib.sha512(data).hexdigest()

    def test_unsupported_algo_rejected(self) -> None:
        got, err = download_and_hash("https://x/y", "md5:abc")
        assert got == ""
        assert "unsupported checksum algo" in err

    def test_malformed_format_rejected(self) -> None:
        got, err = download_and_hash("https://x/y", "abc")
        assert got == ""
        assert "unsupported checksum format" in err

    def test_network_error_surfaced(self) -> None:
        import urllib.error

        with patch(
            "urllib.request.OpenerDirector.open",
            side_effect=urllib.error.URLError("offline"),
        ):
            got, err = download_and_hash("https://x/y", "sha256:abc")
        assert got == ""
        assert "download failed" in err


# ───────────────────────────── verify_sources ─────────────────────────────


class TestVerifySourcesGit:
    def test_verified_when_commit_matches(self) -> None:
        src = UpstreamSource(
            label="x",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="c" * 40,
        )
        out = _ls_remote_output({"refs/tags/v1": "c" * 40})
        with patch("upstream.run_cmd", return_value=(True, out, "")):
            summary = verify_sources([src])
        assert summary.verified == 1
        assert summary.results[0].status == "VERIFIED"

    def test_failed_on_commit_mismatch(self) -> None:
        src = UpstreamSource(
            label="x",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="a" * 40,
        )
        out = _ls_remote_output({"refs/tags/v1": "b" * 40})
        with patch("upstream.run_cmd", return_value=(True, out, "")):
            summary = verify_sources([src])
        assert summary.failed == 1
        r = summary.results[0]
        assert r.status == "FAILED"
        assert "SBOM claims" in r.detail

    def test_error_when_ls_remote_fails(self) -> None:
        src = UpstreamSource(
            label="x",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="a" * 40,
        )
        with patch("upstream.run_cmd", return_value=(False, "", "fatal: bad")):
            summary = verify_sources([src])
        assert summary.errors == 1
        assert summary.results[0].status == "ERROR"

    def test_missing_commit_marks_error(self) -> None:
        # SBOM purl present but no 40-hex commit available — the SBOM didn't
        # actually give us an upstream claim to check against, so we report
        # ERROR (not FAILED).
        src = UpstreamSource(
            label="x",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="",
        )
        summary = verify_sources([src])
        assert summary.errors == 1
        assert "did not provide a commit hash" in summary.results[0].detail


class TestVerifySourcesHttp:
    def test_http_verified_path(self) -> None:
        import hashlib

        data = b"abc"
        sha = hashlib.sha256(data).hexdigest()
        src = UpstreamSource(
            label="x",
            source_type="http",
            url="https://x/y.tar",
            checksum=f"sha256:{sha}",
        )
        with patch("urllib.request.OpenerDirector.open", return_value=_FakeResp(data)):
            summary = verify_sources([src])
        assert summary.verified == 1

    def test_http_mismatch_failed(self) -> None:
        src = UpstreamSource(
            label="x",
            source_type="http",
            url="https://x/y.tar",
            checksum="sha256:" + "0" * 64,
        )
        with patch("urllib.request.OpenerDirector.open", return_value=_FakeResp(b"abc")):
            summary = verify_sources([src])
        assert summary.failed == 1
        assert "mismatch" in summary.results[0].detail


class TestVerifySourcesAggregateAndCache:
    def test_skip_for_none_source(self) -> None:
        src = UpstreamSource(label="x", source_type="none")
        summary = verify_sources([src])
        assert summary.skipped == 1
        assert summary.results[0].status == "SKIP"

    def test_cache_hit_skips_second_lookup(self) -> None:
        s1 = UpstreamSource(
            label="img-a/glibc",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="c" * 40,
        )
        s2 = UpstreamSource(  # same upstream coords, different label
            label="img-b/glibc",
            source_type="git",
            url="https://x/r",
            tag="v1",
            commit="c" * 40,
        )
        cache: dict[tuple[str, str], UpstreamVerifyResult] = {}
        out = _ls_remote_output({"refs/tags/v1": "c" * 40})
        with patch("upstream.run_cmd", return_value=(True, out, "")) as run:
            verify_sources([s1], cache=cache)
            run.reset_mock()
            summary = verify_sources([s2], cache=cache)
            run.assert_not_called()  # cache hit
        assert summary.cache_hits == 1
        assert summary.results[0].label == "img-b/glibc"

    def test_summary_status_failed_dominates(self) -> None:
        out_ok = _ls_remote_output({"refs/tags/v1": "c" * 40})
        out_bad = _ls_remote_output({"refs/tags/v1": "b" * 40})
        srcs = [
            UpstreamSource(
                label="ok", source_type="git", url="https://x/a", tag="v1", commit="c" * 40
            ),
            UpstreamSource(
                label="bad", source_type="git", url="https://x/b", tag="v1", commit="a" * 40
            ),
        ]

        # Multi-call mock keyed on URL via side_effect.
        def fake_run(cmd: list[str], timeout: int = 30) -> tuple[bool, str, str]:
            return (True, out_ok if "/a" in cmd[2] else out_bad, "")

        with patch("upstream.run_cmd", side_effect=fake_run):
            summary = verify_sources(srcs)
        assert summary.as_status() == "FAILED"

    def test_summary_status_error_does_not_dominate_verified(self) -> None:
        out_ok = _ls_remote_output({"refs/tags/v1": "c" * 40})
        srcs = [
            UpstreamSource(
                label="ok", source_type="git", url="https://x/a", tag="v1", commit="c" * 40
            ),
            UpstreamSource(
                label="err", source_type="git", url="https://x/b", tag="v1", commit="a" * 40
            ),
        ]

        # The error case fails its run_cmd call (not reachable upstream).
        def fake_run(cmd: list[str], timeout: int = 30) -> tuple[bool, str, str]:
            if "/a" in cmd[2]:
                return True, out_ok, ""
            return False, "", "network down"

        with patch("upstream.run_cmd", side_effect=fake_run):
            summary = verify_sources(srcs)
        # 1 verified + 1 error → status remains VERIFIED (errors don't demote).
        assert summary.verified == 1
        assert summary.errors == 1
        assert summary.as_status() == "VERIFIED"

    def test_cache_key_separates_git_and_http(self) -> None:
        g = UpstreamSource(label="x", source_type="git", url="u", tag="t", commit="c")
        h = UpstreamSource(label="x", source_type="http", url="u", checksum="sha256:x")
        assert _cache_key(g) != _cache_key(h)


class TestUpstreamSummaryAsStatus:
    def test_na_when_nothing_done(self) -> None:
        assert UpstreamSummary().as_status() == "N/A"

    def test_na_when_only_skips(self) -> None:
        s = UpstreamSummary(total=2, skipped=2)
        assert s.as_status() == "N/A"

    def test_failed_dominates_verified(self) -> None:
        s = UpstreamSummary(total=2, verified=1, failed=1)
        assert s.as_status() == "FAILED"

    def test_error_only_returns_error(self) -> None:
        s = UpstreamSummary(total=1, errors=1)
        assert s.as_status() == "ERROR"


class TestConcurrencyClamp:
    def test_max_workers_capped_to_source_count(self) -> None:
        # One source → 1 worker, even though default is 10. Ensures we don't
        # spin up needless threads on small images.
        srcs = [UpstreamSource(label="x", source_type="none")]
        # We can't observe ThreadPoolExecutor directly, but verify_sources
        # should run cleanly with no live threads left after.
        summary = verify_sources(srcs, max_concurrent=10)
        assert summary.skipped == 1
        # If we leaked threads the test runner would be jittery; assert
        # there are no upstream-related threads left.
        assert all("ThreadPoolExecutor" not in t.name for t in threading.enumerate())


class TestModuleSurface:
    def test_git_installed_callable(self) -> None:
        # Just confirm the helper exists and doesn't crash. We don't assert a
        # boolean — git may or may not be on the test runner's PATH.
        upstream.git_installed()
