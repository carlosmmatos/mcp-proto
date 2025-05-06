"""
CrowdStrike MCP Server

A Model Context Protocol server that connects to CrowdStrike's Falcon API
and exposes various API capabilities through MCP.
"""

# pylint: disable=wildcard-import,wrong-import-position
import json
import logging
from typing import Dict
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-crowdstrike")

# Initialize FastMCP server
mcp = FastMCP("CrowdStrike MCP")
logger.info("MCP server initialized")


# Helper functions
def format_response(response: Dict, required_scopes: str = None) -> str:
    """Format API response for output

    Args:
        response: The API response dictionary from FalconPy
        required_scopes: The specific API scope(s) required for this operation
    """
    if response.get("status_code") == 403:
        # Special handling for access denied errors
        error_message = (
            response.get("body", {})
            .get("errors", [{"message": "Unknown error"}])[0]
            .get("message", "")
        )

        # Determine if this is an authorization failure
        if (
            "access denied" in error_message.lower()
            or "authorization failed" in error_message.lower()
        ):
            scopes_info = required_scopes or "appropriate API scopes"

            error_msg = (
                f"API Access Denied (403): You don't have the required permissions.\n\n"
                f"Required scope(s): {scopes_info}\n\n"
                f"To resolve this issue:\n"
                f"1. Check that your API client has been granted the {scopes_info} permission(s)\n"
                f"2. Verify your CrowdStrike subscription includes access to this feature\n"
                f"3. Contact your CrowdStrike administrator for assistance\n\n"
                f"Original error: {error_message}"
            )
            return error_msg

    elif response.get("status_code") not in (200, 201):
        # Standard error handling for other error codes
        error_msg = (
            f"API Error: {response.get('status_code')} - "
            f"{response.get('body', {}).get('errors', ['Unknown error'])}"
        )
        return error_msg

    # Success case - format the response body
    return json.dumps(response.get("body", {}), indent=2)


# Now import tools (after mcp is defined)
from mcp_crowdstrike.tools import *


def main() -> None:
    """Run the MCP server for CrowdStrike tools."""
    # Initialize and run the server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
