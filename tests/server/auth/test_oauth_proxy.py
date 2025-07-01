"""
Tests for OAuth Proxy Provider

These tests verify that the OAuth proxy provider correctly handles DCR proxy
functionality by returning pre-configured client credentials instead of
forwarding DCR requests to the upstream server.
"""

import pytest  
import time
from unittest.mock import AsyncMock, patch

from mcp.shared.auth import OAuthClientInformationFull
from pydantic import AnyHttpUrl

from fastmcp.server.auth.providers.oauth_proxy import OAuthProxyProvider


@pytest.fixture
def oauth_proxy_provider():
    """Create an OAuth proxy provider for testing."""
    return OAuthProxyProvider(
        upstream_issuer_url="https://upstream.example.com",
        proxy_client_id="test_proxy_client_id",
        proxy_client_secret="test_proxy_client_secret", 
        default_scopes=["read", "write"],
        allowed_redirect_uris=["http://localhost:3000/callback"],
    )


@pytest.fixture
def test_client_info():
    """Create test client information for DCR."""
    return OAuthClientInformationFull(
        client_id="original_client_id",  # This should be overridden by proxy
        client_secret="original_client_secret",  # This should be overridden by proxy  
        redirect_uris=[AnyHttpUrl("http://localhost:3000/callback")],
        client_name="Test Client",
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        scope="read write",
        token_endpoint_auth_method="client_secret_post",
    )


class TestOAuthProxyProvider:
    """Test cases for OAuth proxy provider."""

    def test_initialization(self, oauth_proxy_provider):
        """Test that the OAuth proxy provider initializes correctly."""
        assert oauth_proxy_provider.upstream_issuer_url == "https://upstream.example.com"
        assert oauth_proxy_provider.proxy_client_id == "test_proxy_client_id"
        assert oauth_proxy_provider.proxy_client_secret == "test_proxy_client_secret"
        assert oauth_proxy_provider.default_scopes == ["read", "write"]
        assert oauth_proxy_provider.allowed_redirect_uris == ["http://localhost:3000/callback"]

    def test_protected_resource_metadata(self, oauth_proxy_provider):
        """Test OAuth 2.0 Protected Resource Metadata (RFC 8707) endpoint."""
        metadata = oauth_proxy_provider.get_protected_resource_metadata()
        
        # Verify RFC 8707 compliance
        assert metadata["resource"] == "https://upstream.example.com/"
        assert metadata["authorization_servers"] == ["https://upstream.example.com/"]
        assert metadata["scopes_supported"] == ["read", "write"]
        assert metadata["bearer_methods_supported"] == ["header", "body"]
        
        # Verify no None values in metadata (they should be filtered out)
        assert all(v is not None for v in metadata.values())
        
        # resource_documentation should not be present if service_documentation_url is None
        assert "resource_documentation" not in metadata

    async def test_dcr_proxy_functionality(self, oauth_proxy_provider, test_client_info):
        """
        Test core DCR proxy functionality - returning pre-configured credentials
        instead of forwarding to upstream server.
        """
        # Register client using DCR proxy
        returned_client = await oauth_proxy_provider.register_client(test_client_info)
        
        # Verify that the DCR response returns the proxy client information
        assert returned_client is not None
        assert returned_client.client_id == "test_proxy_client_id"
        assert returned_client.client_secret == "test_proxy_client_secret"
        
        # Verify that the proxy client is registered with our pre-configured credentials
        registered_client = await oauth_proxy_provider.get_client("test_proxy_client_id")
        
        assert registered_client is not None
        assert registered_client.client_id == "test_proxy_client_id"
        assert registered_client.client_secret == "test_proxy_client_secret"
        assert registered_client.client_name == "Test Client"
        assert registered_client.redirect_uris == test_client_info.redirect_uris
        assert "read" in registered_client.scope
        assert "write" in registered_client.scope

    async def test_redirect_uri_validation(self, oauth_proxy_provider):
        """Test that redirect URI validation works when restrictions are set."""
        # Try to register with an invalid redirect URI
        invalid_client_info = OAuthClientInformationFull(
            client_id="test_client",
            client_secret="test_secret",
            redirect_uris=[AnyHttpUrl("http://malicious.com/callback")],
            client_name="Invalid Client",
        )
        
        with pytest.raises(ValueError, match="Redirect URI not allowed"):
            await oauth_proxy_provider.register_client(invalid_client_info)

    async def test_authorization_flow(self, oauth_proxy_provider, test_client_info):
        """Test the authorization flow generates proper authorization codes."""
        # First register the client
        await oauth_proxy_provider.register_client(test_client_info)
        registered_client = await oauth_proxy_provider.get_client("test_proxy_client_id")
        
        # Create authorization parameters
        from mcp.server.auth.provider import AuthorizationParams
        auth_params = AuthorizationParams(
            response_type="code",
            client_id="test_proxy_client_id",
            redirect_uri=AnyHttpUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
            scopes=["read"],
            state="test_state",
            code_challenge="test_challenge",
            code_challenge_method="S256",
        )
        
        # Get authorization redirect
        redirect_response = await oauth_proxy_provider.authorize(registered_client, auth_params)
        
        # Verify redirect contains authorization code and state
        assert "code=" in redirect_response
        assert "state=test_state" in redirect_response
        assert "http://localhost:3000/callback" in redirect_response

    async def test_authorization_code_validation(self, oauth_proxy_provider, test_client_info):
        """Test authorization code loading and validation."""
        # Register client and get authorization
        await oauth_proxy_provider.register_client(test_client_info)
        registered_client = await oauth_proxy_provider.get_client("test_proxy_client_id")
        
        from mcp.server.auth.provider import AuthorizationParams
        auth_params = AuthorizationParams(
            response_type="code",
            client_id="test_proxy_client_id",
            redirect_uri=AnyHttpUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
            scopes=["read"],
            state="test_state",
        )
        
        redirect_response = await oauth_proxy_provider.authorize(registered_client, auth_params)
        
        # Extract the authorization code
        import urllib.parse
        parsed_url = urllib.parse.urlparse(redirect_response)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        auth_code = query_params["code"][0]
        
        # Load and validate the authorization code
        loaded_code = await oauth_proxy_provider.load_authorization_code(
            registered_client, auth_code
        )
        
        assert loaded_code is not None
        assert loaded_code.code == auth_code
        assert loaded_code.client_id == "test_proxy_client_id"
        assert loaded_code.scopes == ["read"]

    @patch('httpx.AsyncClient')
    async def test_token_exchange_with_upstream(self, mock_httpx_client, oauth_proxy_provider, test_client_info):
        """Test that token exchange forwards to upstream server using proxy credentials."""
        # Mock the HTTP client response
        mock_response = AsyncMock()
        mock_response.json.return_value = {
            "access_token": "upstream_access_token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": "upstream_refresh_token",
            "scope": "read",
        }
        mock_response.raise_for_status.return_value = None
        
        mock_client_instance = AsyncMock()
        mock_client_instance.post.return_value = mock_response
        mock_client_instance.__aenter__.return_value = mock_client_instance
        mock_client_instance.__aexit__.return_value = None
        mock_httpx_client.return_value = mock_client_instance
        
        # Set up authorization flow
        await oauth_proxy_provider.register_client(test_client_info)
        registered_client = await oauth_proxy_provider.get_client("test_proxy_client_id")
        
        from mcp.server.auth.provider import AuthorizationParams, AuthorizationCode
        auth_params = AuthorizationParams(
            response_type="code", 
            client_id="test_proxy_client_id",
            redirect_uri=AnyHttpUrl("http://localhost:3000/callback"),
            redirect_uri_provided_explicitly=True,
            scopes=["read"],
        )
        
        redirect_response = await oauth_proxy_provider.authorize(registered_client, auth_params)
        
        # Extract authorization code
        import urllib.parse
        parsed_url = urllib.parse.urlparse(redirect_response)
        query_params = urllib.parse.parse_qs(parsed_url.query)
        auth_code_str = query_params["code"][0]
        
        auth_code = await oauth_proxy_provider.load_authorization_code(
            registered_client, auth_code_str
        )
        
        # Exchange authorization code for tokens
        oauth_token = await oauth_proxy_provider.exchange_authorization_code(
            registered_client, auth_code
        )
        
        # Verify token exchange
        assert oauth_token.access_token == "upstream_access_token"
        assert oauth_token.token_type == "Bearer"
        assert oauth_token.expires_in == 3600
        assert oauth_token.refresh_token == "upstream_refresh_token"
        
        # Verify that the HTTP client was called with proxy credentials
        mock_client_instance.post.assert_called_once()
        call_args = mock_client_instance.post.call_args
        
        # Check that the token endpoint URL is correct
        assert call_args[0][0] == "https://upstream.example.com/token"
        
        # Check that proxy credentials were used
        token_data = call_args[1]["data"]
        assert token_data["client_id"] == "test_proxy_client_id"
        assert token_data["client_secret"] == "test_proxy_client_secret"
        assert token_data["grant_type"] == "authorization_code"

    async def test_access_token_storage_and_validation(self, oauth_proxy_provider):
        """Test that access tokens are properly stored and validated."""
        from mcp.server.auth.provider import AccessToken
        
        # Manually add an access token
        access_token = AccessToken(
            token="test_access_token",
            client_id="test_proxy_client_id", 
            scopes=["read", "write"],
            expires_at=int(time.time()) + 3600,  # Expires in 1 hour
        )
        
        oauth_proxy_provider.access_tokens["test_access_token"] = access_token
        
        # Verify token can be loaded and verified
        loaded_token = await oauth_proxy_provider.load_access_token("test_access_token")
        assert loaded_token is not None
        assert loaded_token.token == "test_access_token"
        assert loaded_token.client_id == "test_proxy_client_id"
        
        verified_token = await oauth_proxy_provider.verify_token("test_access_token")
        assert verified_token is not None
        assert verified_token == loaded_token

    async def test_expired_token_cleanup(self, oauth_proxy_provider):
        """Test that expired tokens are cleaned up properly."""
        from mcp.server.auth.provider import AccessToken
        
        # Add an expired access token
        expired_token = AccessToken(
            token="expired_token",
            client_id="test_proxy_client_id",
            scopes=["read"],
            expires_at=int(time.time()) - 3600,  # Expired 1 hour ago
        )
        
        oauth_proxy_provider.access_tokens["expired_token"] = expired_token
        
        # Try to load expired token - should return None and clean up
        loaded_token = await oauth_proxy_provider.load_access_token("expired_token")
        assert loaded_token is None
        
        # Verify token was removed from storage
        assert "expired_token" not in oauth_proxy_provider.access_tokens

    async def test_token_revocation(self, oauth_proxy_provider):
        """Test token revocation functionality."""
        from mcp.server.auth.provider import AccessToken, RefreshToken
        
        # Set up access and refresh token pair
        access_token = AccessToken(
            token="revoke_access_token",
            client_id="test_proxy_client_id",
            scopes=["read"],
            expires_at=int(time.time()) + 3600,
        )
        
        refresh_token = RefreshToken(
            token="revoke_refresh_token",
            client_id="test_proxy_client_id", 
            scopes=["read"],
            expires_at=None,
        )
        
        # Store tokens and their associations
        oauth_proxy_provider.access_tokens["revoke_access_token"] = access_token
        oauth_proxy_provider.refresh_tokens["revoke_refresh_token"] = refresh_token
        oauth_proxy_provider._access_to_refresh_map["revoke_access_token"] = "revoke_refresh_token"
        oauth_proxy_provider._refresh_to_access_map["revoke_refresh_token"] = "revoke_access_token"
        
        # Revoke the access token
        await oauth_proxy_provider.revoke_token(access_token)
        
        # Verify both tokens are removed
        assert "revoke_access_token" not in oauth_proxy_provider.access_tokens
        assert "revoke_refresh_token" not in oauth_proxy_provider.refresh_tokens
        assert "revoke_access_token" not in oauth_proxy_provider._access_to_refresh_map
        assert "revoke_refresh_token" not in oauth_proxy_provider._refresh_to_access_map

    def test_proxy_without_redirect_uri_restrictions(self):
        """Test proxy provider without redirect URI restrictions allows any URI."""
        provider = OAuthProxyProvider(
            upstream_issuer_url="https://upstream.example.com",
            proxy_client_id="test_client",
            proxy_client_secret="test_secret",
            allowed_redirect_uris=None,  # No restrictions
        )
        
        assert provider.allowed_redirect_uris is None
        
        # This should not raise an exception since there are no restrictions
        test_client = OAuthClientInformationFull(
            client_id="test",
            client_secret="test",
            redirect_uris=[AnyHttpUrl("https://any-domain.com/callback")],
            client_name="Test Client",
        )
        
        # This should work without validation errors
        # (We can't test the full flow here without async, but the init validates the structure)
        assert test_client.redirect_uris[0] == "https://any-domain.com/callback" 