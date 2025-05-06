#!/usr/bin/env python3
"""
CrowdStrike MCP Server

A Model Context Protocol server that connects to CrowdStrike's Falcon API
and exposes various API capabilities through MCP.
"""

import os
import json
from typing import Dict
from mcp.server.fastmcp import FastMCP
from falconpy import Intel, OAuth2

# Initialize FastMCP server
mcp = FastMCP("crowdstrike")

# Authentication details from environment variables
CLIENT_ID = os.environ.get("FALCON_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET")
BASE_URL = os.environ.get("FALCON_BASE_URL")

# Check for required environment variables
if not CLIENT_ID or not CLIENT_SECRET:
    raise ValueError(
        "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set"
    )

creds = dict(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)
if BASE_URL:
    creds["base_url"] = BASE_URL

# Initialize API clients
falcon_auth = OAuth2(**creds)
intel_client = Intel(auth_object=falcon_auth)


# Helper functions
def format_response(response: Dict) -> str:
    """Format API response for output"""
    if response.get("status_code") not in (200, 201):
        error_msg = (
            f"API Error: {response.get('status_code')} - "
            f"{response.get('body', {}).get('errors', ['Unknown error'])}"
        )
        return error_msg

    return json.dumps(response.get("body", {}), indent=2)


# INTEL SERVICE TOOLS
@mcp.tool()
async def list_threat_actors(limit: int = 10) -> str:
    """List threat actors tracked by CrowdStrike.

    Args:
        limit: Maximum number of actors to return (default: 10)
    """
    try:
        # Query for actor IDs
        response = intel_client.query_actor_entities(limit=limit)

        if response.get("status_code") != 200:
            return f"Error querying actor IDs: {response.get('body', {}).get('errors', ['Unknown error'])}"

        actors = response.get("body", {}).get("resources", [])

        if not actors:
            return "No threat actors found"

        return json.dumps({"actors": actors}, indent=2)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.tool()
async def get_actor_details(actor_name: str) -> str:
    """Get detailed information about a specific threat actor.

    Args:
        actor_name: Name of the threat actor to analyze
    """
    try:
        # Combined query for actor
        response = intel_client.query_actor_entities(filter=f"name:'{actor_name}'")

        if response.get("status_code") != 200:
            return f"Error querying actor: {response.get('body', {}).get('errors', ['Unknown error'])}"

        actors = response.get("body", {}).get("resources", [])

        if not actors:
            return "No actor details found"

        actor = actors[0]  # Take the first match
        return json.dumps({"actor": actor}, indent=2)
    except Exception as e:
        return f"Error: {str(e)}"


# Main function to run the server
if __name__ == "__main__":
    mcp.run(transport="stdio")
