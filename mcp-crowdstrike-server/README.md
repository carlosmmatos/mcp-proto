# MCP CrowdStrike Server

A Model Context Protocol (MCP) server that connects to CrowdStrike's Falcon API, enabling LLMs to access security intelligence and threat data.

## Overview

This server implements the [Model Context Protocol](https://github.com/llm-mcp/mcp) to provide LLMs with secure access to CrowdStrike's Falcon platform. It allows AI models to retrieve and analyze security intelligence, threat data, and other information from the CrowdStrike ecosystem.

## Features

- Connect to CrowdStrike Falcon Intelligence API
- Retrieve threat intelligence data
- Search for indicators of compromise (IOCs)
- Access security insights for AI-assisted analysis

## Installation

```bash
pip install mcp-crowdstrike
```

For development, you can install directly from the repository:

```bash
git clone https://github.com/your-org/mcp-crowdstrike-server.git
cd mcp-crowdstrike-server
pip install -e .
```

To install with testing dependencies:

```bash
pip install -e ".[test]"
```

## Requirements

- Python 3.12 or higher
- CrowdStrike Falcon API credentials
- Access to CrowdStrike Intelligence modules (for full functionality)

## Configuration

The server requires CrowdStrike Falcon API credentials to function. These can be provided through environment variables or a `.env` file.

### Environment Variables

```terminal
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret
FALCON_BASE_URL=your-base-url  # Optional, defaults to US-1 cloud
```

### Creating a .env File

Create a `.env` file in the root directory of the project:

```terminal
FALCON_CLIENT_ID=your-client-id
FALCON_CLIENT_SECRET=your-client-secret
FALCON_BASE_URL=your-base-url  # Optional
```

## Usage

### Running the Server

You can run the server directly using the installed command:

```bash
mcp-crowdstrike
```

### Development Mode

For development and testing, use the MCP development server:

```bash
# Install the package in development mode first
pip install -e .

# Run the development server
mcp dev mcp_crowdstrike/server.py
```

This will start the MCP Inspector interface, allowing you to interact with the server and test its functionality.

### Using with LLM Platforms

The server implements the Model Context Protocol, making it compatible with any MCP-enabled LLM platform. Refer to your LLM platform's documentation for instructions on connecting to MCP servers.

## Available Tools

### Intelligence Tools

- `list_threat_actors`: Retrieve a list of threat actors tracked by CrowdStrike
- `get_actor_details`: Get detailed information about a specific threat actor

## Development

### Project Structure

```terminal
mcp-crowdstrike-server/
├── mcp_crowdstrike/           # Main package
│   ├── __init__.py            # Package initialization
│   ├── auth.py                # Authentication module
│   ├── server.py              # MCP server implementation
│   └── tools/                 # API tools
│       ├── __init__.py
│       └── intel.py           # Intelligence tools
├── tests/                     # Test suite
│   ├── conftest.py            # Test fixtures
│   └── test_intel.py          # Intel tools tests
├── .env.example               # Example environment variables
├── pyproject.toml             # Project metadata and dependencies
└── README.md                  # This file
```

### Adding New Tools

To add new tools, create a new module in the `mcp_crowdstrike/tools/` directory and import it in `mcp_crowdstrike/tools/__init__.py`.

## Testing

Run the test suite with pytest:

```bash
# Run all tests
pytest

# Run with coverage report
pytest --cov=mcp_crowdstrike

# Run with verbose output
pytest -v
```

The tests require valid CrowdStrike API credentials to be available in environment variables or a `.env` file. Tests will be skipped if credentials are not available.

## API Permissions

Different tools require different CrowdStrike API permissions. Ensure your API client has the necessary scopes:

- Intelligence tools: `ACTORS (FALCON INTELLIGENCE) READ`
- IOC tools: `IOC READ`

If you encounter permission errors, the server will provide guidance on which permissions are required.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Acknowledgments

- [CrowdStrike Falcon API](https://www.crowdstrike.com/products/threat-intelligence/)
- [Model Context Protocol](https://github.com/llm-mcp/mcp)
- [FalconPy SDK](https://github.com/CrowdStrike/falconpy)

## Security Considerations

When using this MCP server with LLMs, consider the following security best practices:

1. **API Credentials**: Never expose your CrowdStrike API credentials in your code or to end users. The server handles authentication internally.

2. **Least Privilege**: Create API clients with only the permissions needed for your use case. Refer to the [CrowdStrike API documentation](https://falcon.crowdstrike.com/documentation/46/crowdstrike-oauth2-based-apis) for details on creating restricted API clients.

3. **Rate Limiting**: Be mindful of API rate limits when integrating with high-volume LLM applications. Consider implementing caching for frequently requested data.

4. **Data Handling**: Be cautious about how security data is presented and used in LLM outputs. Sensitive information should be handled according to your organization's security policies.

## Troubleshooting

### Authentication Issues

If you encounter authentication errors:

1. Verify your API credentials are correct
2. Check that your API client has the necessary permissions
3. Ensure your CrowdStrike subscription includes access to the required modules

### Common Errors

- **403 Forbidden**: Your API client lacks the necessary permissions. The error message will indicate which scopes are required.
- **404 Not Found**: The requested resource doesn't exist or your account doesn't have access to it.
- **429 Too Many Requests**: You've exceeded the API rate limits. Implement backoff and retry logic.

### Logging

The server uses Python's standard logging module. To enable debug logging:

```python
import logging
logging.basicConfig(level=logging.DEBUG)
```

## Versioning

This project follows [Semantic Versioning](https://semver.org/). The current version is 0.1.0, indicating it's in early development.

## Related Projects

- [CrowdStrike FalconPy](https://github.com/CrowdStrike/falconpy): The official Python SDK for CrowdStrike Falcon
- [Model Context Protocol](https://github.com/llm-mcp/mcp): The protocol specification this server implements

## Support

For issues related to this MCP server, please open an issue on the GitHub repository.

For questions about the CrowdStrike API, refer to the [CrowdStrike Developer Portal](https://developer.crowdstrike.com/).
