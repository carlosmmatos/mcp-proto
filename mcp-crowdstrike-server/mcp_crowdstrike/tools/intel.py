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
INTEL_ACTORS_READ_SCOPE = "ACTORS (FALCON INTELLIGENCE) READ"
INTEL_IOC_READ_SCOPE = "INDICATORS (FALCON INTELLIGENCE) READ"


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
            return format_response(response, required_scopes=INTEL_ACTORS_READ_SCOPE)

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
            return format_response(response, required_scopes=INTEL_ACTORS_READ_SCOPE)

        actors = response.get("body", {}).get("resources", [])

        if not actors:
            return "No actor details found"

        actor = actors[0]  # Take the first match
        return json.dumps({"actor": actor}, indent=2)
    except Exception as e:
        logger.exception(f"Error getting actor details for '{actor_name}'")
        return f"Error: {str(e)}"


# Example: Find IOCs matching criteria
@mcp.tool()
async def search_iocs(
    indicator_value: str = None,
    indicator_type: str = None,
    malware_family: str = None,
    threat_type: str = None,
    malicious_confidence: str = None,
    published_after: str = None,
    mitre_technique: str = None,
    limit: int = 10,
) -> str:
    """Search for Indicators of Compromise (IOCs) with various filters.

    Args:
        indicator_value: Specific indicator value to search for (hash, IP, domain, etc.)
        indicator_type: Type of indicator (hash_md5, hash_sha256, ip_address, domain, etc.)
        malware_family: Filter by malware family name
        threat_type: Filter by threat type (Banking, Criminal, APT, etc.)
        malicious_confidence: Filter by confidence level (high, medium, low)
        published_after: ISO date string to filter IOCs published after this date
        mitre_technique: Filter by MITRE ATT&CK technique name
        limit: Maximum number of IOCs to return (default: 10)
    """
    try:
        # Build filter string based on provided parameters
        filters = []
        if indicator_value:
            filters.append(f"indicator:'{indicator_value}'")
        if indicator_type:
            filters.append(f"type:'{indicator_type}'")
        if malware_family:
            filters.append(f"malware_families:'{malware_family}'")
        if threat_type:
            filters.append(f"threat_types:'{threat_type}'")
        if malicious_confidence:
            filters.append(f"malicious_confidence:'{malicious_confidence}'")
        if published_after:
            filters.append(f"published_date:>'{published_after}'")
        if mitre_technique:
            filters.append(f"labels.name:*'MitreATTCK/*{mitre_technique}*'")

        filter_string = "+".join(filters) if filters else None

        response = falcon.query_indicator_entities(filter=filter_string, limit=limit)

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_IOC_READ_SCOPE)

        iocs = response.get("body", {}).get("resources", [])

        if not iocs:
            return "No IOCs found matching the criteria"

        return json.dumps({"iocs": iocs}, indent=2)
    except Exception as e:
        logger.exception("Error searching IOCs")
        return f"Error: {str(e)}"


# Example Prompt: Tell me everything you know about the IOC with the value of 1234567890.
@mcp.tool()
async def get_ioc_details(indicator_value: str) -> str:
    """Get detailed information about a specific IOC.

    Args:
        indicator_value: The specific indicator value to look up (hash, IP, domain, etc.)
    """
    try:
        response = falcon.query_indicator_entities(
            filter=f"indicator:'{indicator_value}'"
        )

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_IOC_READ_SCOPE)

        iocs = response.get("body", {}).get("resources", [])

        if not iocs:
            return f"No IOC found for indicator: {indicator_value}"

        ioc = iocs[0]  # Take the first match

        # Format the detailed information nicely
        details = {
            "indicator": ioc.get("indicator"),
            "type": ioc.get("type"),
            "malicious_confidence": ioc.get("malicious_confidence"),
            "published_date": ioc.get("published_date"),
            "last_updated": ioc.get("last_updated"),
            "malware_families": ioc.get("malware_families", []),
            "threat_types": ioc.get("threat_types", []),
            "actors": ioc.get("actors", []),
            "mitre_techniques": [
                label["name"]
                for label in ioc.get("labels", [])
                if label["name"].startswith("MitreATTCK/")
            ],
            "reports": ioc.get("reports", []),
            "relations": ioc.get("relations", []),
        }

        return json.dumps({"ioc_details": details}, indent=2)
    except Exception as e:
        logger.exception(f"Error getting IOC details for '{indicator_value}'")
        return f"Error: {str(e)}"


# Example Prompt: What IOCs are associated with the actor 'FANCYBEAR'?
@mcp.tool()
async def get_actor_iocs(actor_name: str, limit: int = 20) -> str:
    """Get IOCs associated with a specific threat actor.

    Args:
        actor_name: Name of the threat actor
        limit: Maximum number of IOCs to return (default: 20)
    """
    try:
        response = falcon.query_indicator_entities(
            filter=f"actors:'{actor_name}'", limit=limit
        )

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_IOC_READ_SCOPE)

        iocs = response.get("body", {}).get("resources", [])

        if not iocs:
            return f"No IOCs found for threat actor: {actor_name}"

        # Summarize the IOCs by type for easier reading
        ioc_summary = {}
        for ioc in iocs:
            ioc_type = ioc.get("type", "unknown")
            if ioc_type not in ioc_summary:
                ioc_summary[ioc_type] = []
            ioc_summary[ioc_type].append(
                {
                    "indicator": ioc.get("indicator"),
                    "malicious_confidence": ioc.get("malicious_confidence"),
                    "malware_families": ioc.get("malware_families", []),
                }
            )

        return json.dumps(
            {"actor": actor_name, "total_iocs": len(iocs), "iocs_by_type": ioc_summary},
            indent=2,
        )
    except Exception as e:
        logger.exception(f"Error getting IOCs for actor '{actor_name}'")
        return f"Error: {str(e)}"


# Example Prompt: What new IOCs should I be aware of in the last 7 days?
@mcp.tool()
async def get_recent_iocs(days: int = 7, limit: int = 20) -> str:
    """Get recently published IOCs within the specified time period.

    Args:
        days: Number of days to look back (default: 7)
        limit: Maximum number of IOCs to return (default: 20)
    """
    try:
        from datetime import datetime, timedelta

        # Calculate the date threshold
        threshold_date = datetime.now() - timedelta(days=days)
        date_filter = threshold_date.strftime("%Y-%m-%d")

        response = falcon.query_indicator_entities(
            filter=f"published_date:>'{date_filter}'",
            limit=limit,
            sort="published_date.desc",
        )

        if response.get("status_code") != 200:
            return format_response(response, required_scopes=INTEL_IOC_READ_SCOPE)

        iocs = response.get("body", {}).get("resources", [])

        if not iocs:
            return f"No IOCs published in the last {days} days"

        # Format for readability
        recent_iocs = []
        for ioc in iocs:
            recent_iocs.append(
                {
                    "indicator": ioc.get("indicator"),
                    "type": ioc.get("type"),
                    "published_date": ioc.get("published_date"),
                    "malicious_confidence": ioc.get("malicious_confidence"),
                    "malware_families": ioc.get("malware_families", []),
                    "threat_types": ioc.get("threat_types", []),
                }
            )

        return json.dumps(
            {
                "time_period": f"Last {days} days",
                "total_found": len(recent_iocs),
                "recent_iocs": recent_iocs,
            },
            indent=2,
        )
    except Exception as e:
        logger.exception(f"Error getting recent IOCs")
        return f"Error: {str(e)}"
