# mcp-proto

This repository contains the Model Context Protocol (MCP) implementation, which enables Large Language Models (LLMs) to securely access external data sources and APIs. The project includes:

- **[mcp-crowdstrike-server](./mcp-crowdstrike-server/)**: A server implementation that connects to CrowdStrike's Falcon API, allowing LLMs to access security intelligence and threat data, including:
  - Threat actor information and details
  - Indicators of Compromise (IOCs) search and analysis
  - Recent threat intelligence data

The MCP framework facilitates structured communication between AI models and external tools, providing a standardized way for LLMs to retrieve real-time information, perform actions, and access specialized knowledge.

## Getting Started

To use the MCP CrowdStrike server, see the detailed documentation in the [mcp-crowdstrike-server](./mcp-crowdstrike-server/) directory.

## Requirements

- Python 3.12 or higher
- CrowdStrike Falcon API credentials with appropriate permissions
