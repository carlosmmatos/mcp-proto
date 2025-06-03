"""
Utility functions for the CrowdStrike MCP Server.
"""

import json
from typing import Dict


def format_response(response: Dict, required_scopes: str = None) -> str:
    """Format API response for output

    Args:
        response: The API response dictionary from FalconPy
        required_scopes: The specific API scope(s) required for this operation
    """
    # Check for error status codes
    if response.get("status_code") not in (200, 201):
        # Handle access denied errors with helpful guidance
        if response.get("status_code") == 403:
            error_message = (
                response.get("body", {})
                .get("errors", [{"message": "Unknown error"}])[0]
                .get("message", "")
            )

            scopes_info = required_scopes or "appropriate API scopes"

            return (
                f"API Access Denied (403): You don't have the required permissions.\n"
                f"Required scope(s): {scopes_info}\n"
                f"To resolve this issue: Check API client permissions or contact your administrator.\n"
                f"Original error: {error_message}"
            )

        # Standard error handling for other error codes
        return (
            f"API Error: {response.get('status_code')} - "
            f"{response.get('body', {}).get('errors', ['Unknown error'])}"
        )

    # Success case - format the response body
    return json.dumps(response.get("body", {}), indent=2)
