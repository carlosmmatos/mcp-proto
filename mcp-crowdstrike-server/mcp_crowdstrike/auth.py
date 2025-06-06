"""
Authentication module for CrowdStrike Falcon API.

This module centralizes authentication and provides authenticated clients
for different Falcon API service collections.
"""

import os
import logging
from dotenv import load_dotenv
from falconpy import OAuth2, InvalidCredentials

# Setup logging
logger = logging.getLogger('mcp-crowdstrike')

# Load environment variables if .env file exists
load_dotenv()

# Authentication details from environment variables
CLIENT_ID = os.environ.get("FALCON_CLIENT_ID")
CLIENT_SECRET = os.environ.get("FALCON_CLIENT_SECRET")
BASE_URL = os.environ.get("FALCON_BASE_URL")

# Check for required environment variables
if not CLIENT_ID or not CLIENT_SECRET:
    logger.error("FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set")
    raise ValueError(
        "FALCON_CLIENT_ID and FALCON_CLIENT_SECRET environment variables must be set"
    )

# Create credential dictionary
creds = dict(
    client_id=CLIENT_ID,
    client_secret=CLIENT_SECRET
)
if BASE_URL:
    creds["base_url"] = BASE_URL

# Initialize OAuth2 authentication
falcon_auth = OAuth2(creds=creds)
falcon_auth.login()
if not falcon_auth.token_valid:
    raise InvalidCredentials(message="Invalid credentials supplied. Could not authenticate with the API.")
logger.info("CrowdStrike Falcon authentication initialized")
