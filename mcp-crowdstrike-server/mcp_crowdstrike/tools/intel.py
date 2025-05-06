"""
Tools for interacting with the CrowdStrike Intel Service.
"""

import json
import logging
from falconpy import Intel
from mcp_crowdstrike.auth import falcon_auth
from mcp_crowdstrike.server import mcp, format_response

# Configure logging
logger = logging.getLogger("mcp-crowdstrike")

# Initialize API client
falcon = Intel(auth_object=falcon_auth)

# Define required scopes for Intel operations
INTEL_READ_SCOPE = "ACTORS (FALCON INTELLIGENCE) READ"


@mcp.tool()
async def list_threat_actors(limit: int = 10) -> str:
    """List threat actors tracked by CrowdStrike.

    Args:
        limit: Maximum number of actors to return (default: 10)
    """
    try:
        # Query for actor IDs
        response = falcon.query_actor_entities(limit=limit)

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_READ_SCOPE)

        actors = response.get("body", {}).get("resources", [])

        if not actors:
            return "No threat actors found"

        return json.dumps({"actors": actors}, indent=2)
    except Exception as e:
        logger.exception("Error listing threat actors")
        return f"Error: {str(e)}"


@mcp.tool()
async def get_actor_details(actor_name: str) -> str:
    """Get detailed information about a specific threat actor.

    Args:
        actor_name: Name of the threat actor to analyze
    """
    try:
        # Combined query for actor
        response = falcon.query_actor_entities(filter=f"name:'{actor_name}'")

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_READ_SCOPE)

        actors = response.get("body", {}).get("resources", [])

        if not actors:
            return "No actor details found"

        actor = actors[0]  # Take the first match
        return json.dumps({"actor": actor}, indent=2)
    except Exception as e:
        logger.exception(f"Error getting actor details for '{actor_name}'")
        return f"Error: {str(e)}"
