"""FORGE ToolPlugin for verify-provenance - verify Chainguard image delivery authenticity.

This module exposes verify-provenance as a FORGE plugin. It requires forge-core:

    pip install "verify-provenance[forge]"

or install via the FORGE plugin manager:

    forge plugin install provenance
"""

from __future__ import annotations

import logging
import subprocess
from pathlib import Path
from typing import Any

from forge_core.context import ExecutionContext
from forge_core.deps import assert_dependencies
from forge_core.plugin import ResultStatus, ToolParam, ToolResult

logger = logging.getLogger(__name__)

__version__ = "0.2.0"

# verify-provenance CLI plus the tools it depends on
REQUIRED_TOOLS: list[str] = ["verify-provenance", "chainctl", "crane", "cosign"]


class ProvenancePlugin:
    """FORGE plugin for verify-provenance - verify Chainguard image delivery authenticity."""

    name = "provenance"
    description = "Verify Chainguard image provenance and delivery authenticity"
    version = __version__

    def get_params(self) -> list[ToolParam]:
        """Declare parameters for verify-provenance."""
        return [
            ToolParam(
                name="customer-org",
                description="Customer organization to verify",
                required=True,
            ),
            ToolParam(
                name="full",
                description="Full verification mode (verify base digest in chainguard-private)",
                type="bool",
            ),
            ToolParam(
                name="verify-signatures",
                description="Enable full cryptographic signature verification",
                type="bool",
            ),
            ToolParam(
                name="limit",
                description="Limit number of images to check (0 = all)",
                type="int",
                default=0,
            ),
        ]

    def run(self, args: dict[str, Any], ctx: ExecutionContext) -> ToolResult:
        """Execute provenance verification."""
        assert_dependencies(REQUIRED_TOOLS)

        customer_org = args["customer_org"]
        ctx.progress(0.0, f"Verifying images for '{customer_org}'")

        cmd = ["verify-provenance", "--customer-org", customer_org]

        if args.get("full"):
            cmd.append("--full")
        if args.get("verify_signatures"):
            cmd.append("--verify-signatures")
        limit = args.get("limit", 0)
        if limit and limit > 0:
            cmd.extend(["--limit", str(limit)])

        result = subprocess.run(cmd, text=True)

        if result.returncode != 0:
            return ToolResult(
                status=ResultStatus.FAILURE,
                summary=(
                    result.stderr
                    or f"verify-provenance failed with exit code {result.returncode}"
                ),
            )

        ctx.progress(1.0, "Verification complete")

        # The upstream tool writes its CSV report to {customer_org}.csv in the CWD
        artifacts: dict[str, str] = {}
        csv_file = Path(f"{customer_org}.csv")
        if csv_file.exists():
            artifacts["report"] = str(csv_file.resolve())

        return ToolResult(
            status=ResultStatus.SUCCESS,
            summary=f"Verified images for '{customer_org}'",
            artifacts=artifacts,
        )


def create_plugin() -> ProvenancePlugin:
    """Entry point for FORGE plugin discovery."""
    return ProvenancePlugin()
