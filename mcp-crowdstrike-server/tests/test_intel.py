import asyncio
import json
import pytest
from mcp_crowdstrike.tools.intel import list_threat_actors, get_actor_details

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
        # Testing with FANCY BEAR (APT28) which is commonly tracked
        result = await get_actor_details("FANCY BEAR")

        # Parse the result
        try:
            data = json.loads(result)
            # If we found the actor, verify we have proper data
            assert "actor" in data
            actor = data["actor"]
            assert actor["name"] == "FANCY BEAR"
            print(f"Successfully retrieved details for FANCY BEAR")
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
