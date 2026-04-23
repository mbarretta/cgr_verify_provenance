"""Tests for verify_library module."""

import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, "..")

from verify_library import (  # noqa: E402
    CHAINGUARD_ISSUER_REGEX,
    CSV_COLUMNS,
    OIDC_ISSUER_REGEX,
    acquire_pull_token,
    cache_path_for_url,
    extract_matched_coordinate,
    parse_java_coordinate,
    parse_npm_coordinate,
    parse_python_coordinate,
    resolve_java_url,
    resolve_npm_tarball_url,
    verify_bundle_with_cosign,
)


class TestJavaCoordinate:
    def test_basic(self) -> None:
        gav = parse_java_coordinate("org.apache.commons:commons-compress:1.28.0")
        assert gav["group"] == "org.apache.commons"
        assert gav["group_path"] == "org/apache/commons"
        assert gav["artifact"] == "commons-compress"
        assert gav["version"] == "1.28.0"
        assert gav["filename"] == "commons-compress-1.28.0.jar"

    def test_invalid_raises(self) -> None:
        import pytest
        with pytest.raises(ValueError):
            parse_java_coordinate("org.apache.commons.commons-compress.1.28.0")


class TestJavaUrlShape:
    def test_artifact_and_bundle_urls(self) -> None:
        artifact, bundle = resolve_java_url(
            "org.apache.commons:commons-compress:1.28.0"
        )
        expected = (
            "https://libraries.cgr.dev/java/org/apache/commons/commons-compress/"
            "1.28.0/commons-compress-1.28.0.jar"
        )
        assert artifact == expected
        assert bundle == expected + ".bundle.json"


class TestPythonCoordinate:
    def test_basic(self) -> None:
        p = parse_python_coordinate("requests==2.31.0")
        assert p["pkg"] == "requests"
        assert p["version"] == "2.31.0"

    def test_missing_double_equals(self) -> None:
        import pytest
        with pytest.raises(ValueError):
            parse_python_coordinate("requests-2.31.0")


class TestNpmCoordinate:
    def test_unscoped(self) -> None:
        n = parse_npm_coordinate("lodash@4.17.21")
        assert n["pkg"] == "lodash"
        assert n["version"] == "4.17.21"
        assert n["basename"] == "lodash"

    def test_scoped(self) -> None:
        n = parse_npm_coordinate("@babel/core@7.24.0")
        assert n["pkg"] == "@babel/core"
        assert n["version"] == "7.24.0"
        assert n["basename"] == "core"

    def test_tarball_url_unscoped(self) -> None:
        url = resolve_npm_tarball_url("lodash@4.17.21")
        assert url == "https://libraries.cgr.dev/javascript/lodash/-/lodash-4.17.21.tgz"

    def test_tarball_url_scoped(self) -> None:
        url = resolve_npm_tarball_url("@babel/core@7.24.0")
        assert url == "https://libraries.cgr.dev/javascript/@babel/core/-/core-7.24.0.tgz"


class TestChainctlOutputParsing:
    def test_extract_maven_coordinate(self) -> None:
        details = (
            "Verified via SHA256 checksum comparison with Chainguard repository\n"
            "Maven artifact: org.apache.commons:commons-compress:1.28.0"
        )
        assert extract_matched_coordinate(details) == (
            "org.apache.commons:commons-compress:1.28.0"
        )

    def test_extract_returns_none_when_missing(self) -> None:
        assert extract_matched_coordinate("") is None
        assert extract_matched_coordinate("some unrelated text") is None


class TestAcquirePullToken:
    def test_parses_chainctl_json(self) -> None:
        # Clear the module-level cache before the test
        import verify_library
        verify_library._PULL_TOKEN_CACHE.clear()

        fake_json = json.dumps({
            "identity_id": "pull-token-abc123",
            "token": "eyJh.payload.sig",
        })
        # chainctl emits a line or two before the JSON — include that
        fake_stdout = "Creating new java library pull-token in barretta\n\n" + fake_json

        with patch("verify_library.run_cmd") as m:
            m.return_value = (True, fake_stdout, "")
            user, pw, pretty = acquire_pull_token("java", "barretta")

        assert user == "pull-token-abc123"
        assert pw == "eyJh.payload.sig"
        assert "pull-token create" in pretty
        assert "--repository=java" in pretty
        assert "--parent=barretta" in pretty

    def test_cache_hit(self) -> None:
        import verify_library
        verify_library._PULL_TOKEN_CACHE.clear()
        verify_library._PULL_TOKEN_CACHE["java:foo"] = ("u", "p")

        # Should not call run_cmd — token already cached
        with patch("verify_library.run_cmd") as m:
            user, pw, _ = acquire_pull_token("java", "foo")
            m.assert_not_called()
        assert (user, pw) == ("u", "p")


class TestCosignInvocation:
    def test_arg_list(self, tmp_path: Path) -> None:
        art = tmp_path / "a.jar"
        art.write_bytes(b"x")
        bundle = tmp_path / "a.jar.bundle.json"
        bundle.write_text("{}")

        with patch("verify_library.run_cmd") as m:
            m.return_value = (True, "Verified OK\n", "")
            ok, pretty = verify_bundle_with_cosign(art, bundle)

        assert ok is True
        called_args = m.call_args.args[0]
        assert called_args[0] == "cosign"
        assert called_args[1] == "verify-blob"
        assert "--bundle" in called_args
        assert called_args[called_args.index("--bundle") + 1] == str(bundle)
        assert "--certificate-identity-regexp" in called_args
        assert CHAINGUARD_ISSUER_REGEX in called_args
        assert "--certificate-oidc-issuer-regexp" in called_args
        assert OIDC_ISSUER_REGEX in called_args
        # Artifact is the final positional
        assert called_args[-1] == str(art)
        # Pretty command is multiline with the literal regexps
        assert "--certificate-identity-regexp" in pretty
        assert CHAINGUARD_ISSUER_REGEX in pretty

    def test_trusted_root_forwarded(self, tmp_path: Path) -> None:
        art = tmp_path / "a.jar"
        art.write_bytes(b"x")
        bundle = tmp_path / "a.jar.bundle.json"
        bundle.write_text("{}")

        with patch("verify_library.run_cmd") as m:
            m.return_value = (True, "Verified OK", "")
            verify_bundle_with_cosign(art, bundle, trusted_root="/etc/trusted.json")

        called_args = m.call_args.args[0]
        assert "--trusted-root" in called_args
        assert "/etc/trusted.json" in called_args

    def test_failed_verify(self, tmp_path: Path) -> None:
        art = tmp_path / "a.jar"
        art.write_bytes(b"x")
        bundle = tmp_path / "a.jar.bundle.json"
        bundle.write_text("{}")

        with patch("verify_library.run_cmd") as m:
            m.return_value = (False, "", "error: something broke")
            ok, _ = verify_bundle_with_cosign(art, bundle)
        assert ok is False


class TestCachePath:
    def test_mirror_url_structure(self, tmp_path: Path) -> None:
        url = "https://libraries.cgr.dev/java/org/apache/commons/commons-compress/1.28.0/commons-compress-1.28.0.jar"
        p = cache_path_for_url(tmp_path, url)
        expected = tmp_path / "libraries.cgr.dev" / "java" / "org" / "apache" / "commons" / "commons-compress" / "1.28.0" / "commons-compress-1.28.0.jar"
        assert p == expected


class TestCsvColumns:
    def test_schema_is_stable(self) -> None:
        # Guard against accidental column renames/reorders that would break
        # downstream scripts consuming the CSV.
        assert CSV_COLUMNS[0] == "input_ref"
        assert "chainctl_coverage" in CSV_COLUMNS
        assert "rekor_url" in CSV_COLUMNS
        assert "status" in CSV_COLUMNS
        assert CSV_COLUMNS[-1] == "error"
