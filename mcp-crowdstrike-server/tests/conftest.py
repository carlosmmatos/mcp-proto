import os
import pytest
from dotenv import load_dotenv
from falconpy import OAuth2, Intel


def pytest_configure(config):
    """Load environment variables for tests"""
    load_dotenv()


@pytest.fixture(scope="session")
def falcon_auth():
    """Provide real Falcon OAuth2 client for integration tests"""
    # Load credentials from environment
    client_id = os.environ.get("FALCON_CLIENT_ID")
    client_secret = os.environ.get("FALCON_CLIENT_SECRET")
    base_url = os.environ.get("FALCON_BASE_URL")

    # Skip tests if credentials aren't available
    if not client_id or not client_secret:
        pytest.skip("CrowdStrike API credentials not available")

    # Create credentials dictionary
    creds = {"client_id": client_id, "client_secret": client_secret}
    if base_url:
        creds["base_url"] = base_url

    # Create real auth client
    try:
        auth = OAuth2(creds=creds)
        return auth
    except Exception as e:
        pytest.skip(f"Failed to authenticate with CrowdStrike API: {str(e)}")


@pytest.fixture(scope="session")
def intel_client(falcon_auth):
    """Provide real Falcon Intel client for integration tests"""
    return Intel(auth_object=falcon_auth)


@pytest.fixture
def intel_tools():
    """Import intel tools for testing"""
    # Import directly from the package
    from mcp_crowdstrike.tools import intel
    return intel
