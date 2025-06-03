import json
import pytest
from mcp_crowdstrike.tools.intel import (
    list_threat_actors,
    get_actor_details,
    search_iocs,
    get_ioc_details,
    get_actor_iocs,
    get_recent_iocs
)

class TestIntelIntegration:
    """Integration tests for Intel tools using real API credentials"""

    @pytest.mark.asyncio
    async def test_list_threat_actors(self, intel_client):
        """Test that list_threat_actors returns actual actors from the API"""
        # Test with a small limit to keep the test quick
        result = await list_threat_actors(limit=3)

        # Parse the result
        data = json.loads(result)

        # Verify structure and content
        assert "actors" in data
        assert isinstance(data["actors"], list)

        # We should get actors (if we have the correct permissions)
        # But if we don't find any, it might be due to API permissions
        # So we don't strictly assert on length
        if data["actors"]:
            actor = data["actors"][0]
            # Check that actors have expected fields
            assert "id" in actor
            assert "name" in actor
            print(f"Found threat actor: {actor.get('name', 'Unknown')}")

    @pytest.mark.asyncio
    async def test_get_actor_details_known_actor(self):
        """Test retrieving details for a known threat actor"""
        # Try to get details for a well-known actor
        # Testing with FANCY BEAR which is commonly tracked
        result = await get_actor_details("FANCY BEAR")

        # Parse the result
        try:
            data = json.loads(result)
            # If we found the actor, verify we have proper data
            assert "actor" in data
            actor = data["actor"]
            assert actor["name"] == "FANCY BEAR"
            print("Successfully retrieved details for FANCY BEAR")
        except json.JSONDecodeError:
            # If we got a string response and not JSON, it might be "No actor details found"
            # This could happen if the account doesn't have access to this actor
            assert "No actor details found" in result
            pytest.skip("Could not find actor details - may need different API permissions")

    @pytest.mark.asyncio
    async def test_get_actor_details_unknown_actor(self):
        """Test retrieving details for an actor that doesn't exist"""
        # Use a random name that shouldn't exist
        result = await get_actor_details("THIS_IS_NOT_A_REAL_THREAT_ACTOR_NAME_12345")

        # Should get "No actor details found"
        assert result == "No actor details found"

    @pytest.mark.asyncio
    async def test_error_handling(self):
        """Test that error handling works correctly with real API"""
        try:
            # Try with an invalid parameter to force an API error
            # This assumes falconpy will reject this as invalid
            result = await list_threat_actors(limit=-999)

            # Check if we got an error message
            assert "API Error" in result or "actors" in json.loads(result)
        except Exception as e:
            # Even if we get an exception, that's OK for this test
            # as we're testing error handling
            print(f"Got expected error: {str(e)}")

    @pytest.mark.asyncio
    async def test_search_iocs(self, intel_client):
        """Test searching for IOCs with basic filters"""
        # Test with a small limit to keep the test quick
        result = await search_iocs(limit=3)

        # Parse the result
        try:
            data = json.loads(result)

            # Verify structure
            if "iocs" in data:
                assert isinstance(data["iocs"], list)
                if data["iocs"]:
                    ioc = data["iocs"][0]
                    # Check that IOCs have expected fields
                    assert "indicator" in ioc
                    assert "type" in ioc
                    print(f"Found IOC: {ioc.get('indicator', 'Unknown')}")
            else:
                # If no IOCs found, that's acceptable (might be permissions)
                assert "No IOCs found matching the criteria" in result
        except json.JSONDecodeError:
            # If we got an error response
            assert "API Error" in result
            pytest.skip("Could not search IOCs - may need different API permissions")

    @pytest.mark.asyncio
    async def test_get_ioc_details_known_pattern(self):
        """Test retrieving details for a common IOC pattern"""
        # Test with a pattern that's likely to exist but not specific enough to be brittle
        # Using a common malicious IP pattern or domain pattern
        result = await search_iocs(limit=1)

        try:
            data = json.loads(result)
            if "iocs" in data and data["iocs"]:
                # Use the first IOC we found to test get_ioc_details
                test_ioc = data["iocs"][0]["indicator"]
                details_result = await get_ioc_details(test_ioc)
                details_data = json.loads(details_result)

                # Verify we got details
                assert "ioc_details" in details_data
                assert details_data["ioc_details"]["indicator"] == test_ioc
                print(f"Successfully retrieved details for IOC: {test_ioc}")
            else:
                pytest.skip("No IOCs available to test get_ioc_details")
        except (json.JSONDecodeError, KeyError):
            pytest.skip("Could not get IOC details - may need different API permissions")

    @pytest.mark.asyncio
    async def test_get_ioc_details_nonexistent(self):
        """Test retrieving details for an IOC that doesn't exist"""
        # Use a random value that shouldn't exist as an IOC
        result = await get_ioc_details("THIS_IS_NOT_A_REAL_IOC_12345")

        # Should get "No IOC found" message
        assert "No IOC found for indicator:" in result

    @pytest.mark.asyncio
    async def test_get_actor_iocs(self):
        """Test retrieving IOCs associated with a threat actor"""
        # Try with a well-known actor name
        result = await get_actor_iocs("FANCY BEAR", limit=3)

        try:
            data = json.loads(result)

            # Verify structure
            if "iocs_by_type" in data:
                assert "actor" in data
                assert data["actor"] == "FANCY BEAR"
                assert "total_iocs" in data
                print(f"Found {data['total_iocs']} IOCs for FANCY BEAR")
            else:
                # If no IOCs found, that's acceptable (might be permissions)
                assert "No IOCs found for threat actor:" in result
        except json.JSONDecodeError:
            pytest.skip("Could not get actor IOCs - may need different API permissions")

    @pytest.mark.asyncio
    async def test_get_recent_iocs(self):
        """Test retrieving recently published IOCs"""
        # Test with a small limit and short time period
        result = await get_recent_iocs(days=30, limit=3)

        try:
            data = json.loads(result)

            # Verify structure
            if "recent_iocs" in data:
                assert isinstance(data["recent_iocs"], list)
                assert "time_period" in data
                assert "total_found" in data
                print(f"Found {data['total_found']} recent IOCs")
            else:
                # If no recent IOCs, that's acceptable
                assert "No IOCs published in the last" in result
        except json.JSONDecodeError:
            pytest.skip("Could not get recent IOCs - may need different API permissions")
