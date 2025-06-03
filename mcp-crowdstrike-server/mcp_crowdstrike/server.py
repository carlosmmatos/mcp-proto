"""
CrowdStrike MCP Server

A Model Context Protocol server that connects to CrowdStrike's Falcon API
and exposes various API capabilities through MCP.
"""

# pylint: disable=wildcard-import,wrong-import-position
import logging
from mcp.server.fastmcp import FastMCP

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mcp-crowdstrike")

# Initialize FastMCP server
mcp = FastMCP("CrowdStrike MCP")
logger.info("MCP server initialized")


# Import tools (after mcp is defined)
from mcp_crowdstrike.tools import *


def main() -> None:
    """Run the MCP server for CrowdStrike tools."""
    # Initialize and run the server
    mcp.run(transport="stdio")


if __name__ == "__main__":
    main()
