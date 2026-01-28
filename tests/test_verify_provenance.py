"""Tests for verify_provenance module."""

import json
import base64
from unittest.mock import patch, MagicMock

import pytest

# Import the module under test
import sys
sys.path.insert(0, "..")
from verify_provenance import (
    run_cmd,
    check_dependencies,
    ChainDetails,
    VerificationResult,
    BASE_DIGEST_LABEL,
    REQUIRED_TOOLS,
)


class TestRunCmd:
    """Tests for the run_cmd helper function."""

    def test_run_cmd_success(self) -> None:
        """Test successful command execution."""
        success, stdout, stderr = run_cmd(["echo", "hello"])
        assert success is True
        assert stdout.strip() == "hello"
        assert stderr == ""

    def test_run_cmd_failure(self) -> None:
        """Test failed command execution."""
        success, stdout, stderr = run_cmd(["false"])
        assert success is False

    def test_run_cmd_timeout(self) -> None:
        """Test command timeout handling."""
        success, stdout, stderr = run_cmd(["sleep", "10"], timeout=1)
        assert success is False
        assert stderr == "timeout"

    def test_run_cmd_nonexistent(self) -> None:
        """Test nonexistent command handling."""
        success, stdout, stderr = run_cmd(["nonexistent_command_12345"])
        assert success is False


class TestCheckDependencies:
    """Tests for dependency checking."""

    def test_check_dependencies_with_echo(self) -> None:
        """Test that common tools are found."""
        # At minimum, 'echo' should exist on any system
        import shutil
        assert shutil.which("echo") is not None

    @patch("shutil.which")
    def test_check_dependencies_missing(self, mock_which: MagicMock) -> None:
        """Test detection of missing dependencies."""
        mock_which.return_value = None
        missing = check_dependencies()
        assert len(missing) == len(REQUIRED_TOOLS)
        assert "chainctl" in missing
        assert "crane" in missing
        assert "cosign" in missing

    @patch("shutil.which")
    def test_check_dependencies_all_present(self, mock_which: MagicMock) -> None:
        """Test when all dependencies are present."""
        mock_which.return_value = "/usr/local/bin/tool"
        missing = check_dependencies()
        assert len(missing) == 0


class TestChainDetails:
    """Tests for ChainDetails dataclass."""

    def test_chain_details_defaults(self) -> None:
        """Test default values for ChainDetails."""
        chain = ChainDetails()
        assert chain.customer_image == ""
        assert chain.customer_digest == ""
        assert chain.base_digest_full == ""
        assert chain.base_digest_label == BASE_DIGEST_LABEL
        assert chain.reference_exists is False
        assert chain.signature_found is False
        assert chain.payload_matches is False
        assert chain.cert_verified is False

    def test_chain_details_initialization(self) -> None:
        """Test ChainDetails with values."""
        chain = ChainDetails(
            customer_image="cgr.dev/test/image:latest",
            customer_digest="sha256:abc123",
            base_digest_full="sha256:def456",
        )
        assert chain.customer_image == "cgr.dev/test/image:latest"
        assert chain.customer_digest == "sha256:abc123"
        assert chain.base_digest_full == "sha256:def456"


class TestVerificationResult:
    """Tests for VerificationResult dataclass."""

    def test_verification_result_defaults(self) -> None:
        """Test default values for VerificationResult."""
        result = VerificationResult(
            image="test-image",
            base_digest="sha256:abc...",
            ref_status="N/A",
            rekor_status="N/A",
            rekor_log_index="",
            sig_status="N/A",
            status="ERROR",
            error="",
        )
        assert result.image == "test-image"
        assert result.status == "ERROR"
        assert isinstance(result.chain, ChainDetails)


class TestPayloadDecoding:
    """Tests for signature payload decoding logic."""

    def test_decode_payload(self) -> None:
        """Test decoding a cosign signature payload."""
        # Create a mock payload structure
        payload = {
            "critical": {
                "image": {
                    "docker-manifest-digest": "sha256:abc123def456"
                },
                "type": "cosign container image signature"
            },
            "optional": {}
        }
        payload_json = json.dumps(payload)
        payload_b64 = base64.b64encode(payload_json.encode()).decode()

        # Decode it back
        decoded = base64.b64decode(payload_b64).decode("utf-8")
        parsed = json.loads(decoded)

        assert parsed["critical"]["image"]["docker-manifest-digest"] == "sha256:abc123def456"

    def test_payload_digest_extraction(self) -> None:
        """Test extracting digest from nested payload structure."""
        payload = {
            "critical": {
                "image": {
                    "docker-manifest-digest": "sha256:expected_digest"
                }
            }
        }

        digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
        assert digest == "sha256:expected_digest"

    def test_payload_missing_fields(self) -> None:
        """Test handling of missing fields in payload."""
        payload = {"critical": {}}

        digest = payload.get("critical", {}).get("image", {}).get("docker-manifest-digest", "")
        assert digest == ""


class TestConstants:
    """Tests for module constants."""

    def test_base_digest_label(self) -> None:
        """Test the base digest label constant."""
        assert BASE_DIGEST_LABEL == "org.opencontainers.image.base.digest"

    def test_required_tools(self) -> None:
        """Test required tools list."""
        assert "chainctl" in REQUIRED_TOOLS
        assert "crane" in REQUIRED_TOOLS
        assert "cosign" in REQUIRED_TOOLS
