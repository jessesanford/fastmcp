#!/usr/bin/env python3
"""
OAuth Proxy Example for FastMCP

This example demonstrates how to set up an OAuth proxy for authorization servers
that don't support Dynamic Client Registration (DCR). The proxy stores pre-configured
client credentials and returns them when clients attempt DCR, while forwarding
the actual OAuth flows to the upstream server.

This is useful when you need to integrate with OAuth providers that don't support
the DCR standard but you still want to use OAuth 2.1 authentication flows.
"""

import asyncio
import os
from pathlib import Path

from fastmcp import FastMCP
from fastmcp.server.auth.providers.oauth_proxy import OAuthProxyProvider


def create_manual_oauth_proxy_server() -> FastMCP:
    """
    Example: Manually configure OAuth proxy provider.
    
    This approach directly instantiates the OAuth proxy provider and passes it
    to FastMCP, similar to how other auth providers like PangeaOAuthProvider
    or InMemoryOAuthProvider are used.
    """
    from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions  # type: ignore
    
    # Can load these from environment variables, secure key management, or configuration files
    UPSTREAM_OAUTH_SERVER = "https://developer.api.autodesk.com"  # Added https:// protocol
    PROXY_CLIENT_ID = "qIbft5FgsUDLRb2d0rprojWgQzbeSomuVoYPhoSWQ50uzjAM" 
    PROXY_CLIENT_SECRET = "VK1MkNFfViCr9iX8Rrncxl0GQu4xGB7pdcz2ssfBqVsrQ9GyI7AQwZxfVLnTC9Ep"
    MCP_SCOPES = ["data:read", "data:write", "data:create", "data:search"]
    MCP_ISSUER_URL = "http://localhost:8000"  # Fixed - should be base URL, not include path
    
    # Create the OAuth proxy provider that will handle DCR by returning
    # pre-configured credentials while forwarding OAuth flows to upstream
    oauth_proxy = OAuthProxyProvider(
        upstream_issuer_url=UPSTREAM_OAUTH_SERVER,
        proxy_client_id=PROXY_CLIENT_ID,
        proxy_client_secret=PROXY_CLIENT_SECRET,
        issuer_url=MCP_ISSUER_URL,  # Override the advertised issuer URL
        upstream_jwks_uri=f"{UPSTREAM_OAUTH_SERVER}/authentication/v2/keys",  # Autodesk JWKS endpoint
        default_scopes=MCP_SCOPES,
        allowed_redirect_uris=[
            "http://localhost:8000/callback",
            "cursor://anysphere.cursor-retrieval/oauth/user-my-demo-mcp-server/callback",
        ],
        client_registration_options=ClientRegistrationOptions(
            enabled=True,
            valid_scopes=MCP_SCOPES,
            default_scopes=MCP_SCOPES,
        ),
        revocation_options=RevocationOptions(enabled=True),
        required_scopes=["data:read"],  # Minimum required scopes for access (Autodesk format)
        httpx_client_kwargs={
            "timeout": 30.0,
            "verify": True,
        },
    )
    
    # Configure FastMCP to use the OAuth proxy provider - same pattern as other providers
    mcp = FastMCP("OAuth Proxy Example", auth=oauth_proxy)
    
    @mcp.tool()
    def get_user_info() -> dict:
        """Get information about the authenticated user from Autodesk JWT token."""
        from fastmcp.server.dependencies import get_access_token
        import json
        
        try:
            # Get the validated access token using MCP's dependency injection
            access_token = get_access_token()
            
            # Decode the JWT token to extract user claims (without verification since it's already validated)
            # Split the JWT to get the payload
            jwt_parts = access_token.token.split('.')
            if len(jwt_parts) != 3:
                return {"error": "Invalid JWT token format"}
            
            # Decode the payload (add padding if needed for base64 decoding)
            import base64
            payload = jwt_parts[1]
            # Add padding if needed
            payload += '=' * (4 - len(payload) % 4)
            jwt_claims = json.loads(base64.b64decode(payload))
            
            # Extract user information from Autodesk JWT claims
            # jti (JWT ID) might be the user ID that fastapi_mcp accesses as 'userid'
            user_id = (jwt_claims.get('sub') or 
                      jwt_claims.get('userid') or 
                      jwt_claims.get('user_id') or 
                      jwt_claims.get('jti') or 
                      "unknown")
            client_id = jwt_claims.get('client_id', 'unknown')
            issuer = jwt_claims.get('iss', 'unknown')
            audience = jwt_claims.get('aud', 'unknown')
            expires_at = jwt_claims.get('exp')
            
            return {
                "user_id": user_id,
                "client_id": client_id,
                "issuer": issuer,
                "audience": audience,
                "expires_at": expires_at,
                "scopes": access_token.scopes,  # These are the validated scopes
                "jwt_claims_keys": list(jwt_claims.keys()),  # Show what claim keys are available
                "jwt_claims_values": jwt_claims,  # Show all actual claim values
                "message": "User information extracted from Autodesk JWT token"
            }
            
        except Exception as e:
            return {
                "error": f"Failed to extract user info from JWT: {str(e)}",
                "message": "Unable to access authentication token or decode JWT"
            }
    
    @mcp.tool() 
    def protected_action(action: str) -> dict:
        """Perform a protected action that requires authentication."""
        return {
            "action": action,
            "status": "success",
            "message": f"Action '{action}' completed successfully via OAuth proxy",
            "upstream_server": UPSTREAM_OAUTH_SERVER,
        }
    
    @mcp.tool()
    def admin_operation(operation: str) -> dict:
        """Admin-only operation that requires elevated scopes."""
        return {
            "operation": operation,
            "status": "authorized", 
            "message": f"Admin operation '{operation}' executed via OAuth proxy",
            "requires_scopes": ["admin"],
        }
    
    return mcp


def create_env_configured_oauth_proxy_server() -> FastMCP:
    """
    Example: Configure OAuth proxy using environment variables.
    
    This approach uses FastMCP's built-in environment variable configuration.
    Set the following environment variables:
    
    FASTMCP_OAUTH_PROXY_ENABLED=true
    FASTMCP_OAUTH_PROXY_CLIENT_ID=your-client-id
    FASTMCP_OAUTH_PROXY_CLIENT_SECRET=your-client-secret  
    FASTMCP_OAUTH_PROXY_UPSTREAM_ISSUER_URL=https://auth.example.com
    FASTMCP_OAUTH_PROXY_SCOPES=read,write
    FASTMCP_OAUTH_PROXY_REDIRECT_URIS=http://localhost:3000/callback,https://your-app.com/oauth/callback
    """
    # When oauth_proxy_enabled=True in settings, FastMCP will automatically
    # create an OAuthProxyProvider using the environment variables
    mcp = FastMCP("OAuth Proxy (Environment Configured)")
    
    @mcp.tool()
    def get_status() -> dict:
        """Get server status with OAuth proxy information."""
        auth_info = "OAuth Proxy enabled via environment variables"
        if mcp.auth:
            auth_info += f" (upstream: {getattr(mcp.auth, 'upstream_issuer_url', 'unknown')})"
        
        return {
            "status": "running",
            "auth": auth_info,
            "proxy_enabled": True,
        }
    
    @mcp.tool()
    def echo_message(message: str) -> dict:
        """Echo a message back (requires authentication)."""
        return {
            "original_message": message,
            "echo": f"Authenticated echo: {message}",
            "auth_method": "OAuth Proxy",
        }
    
    return mcp


async def main():
    """
    Main function to demonstrate both OAuth proxy configuration methods.
    """
    print("FastMCP OAuth Proxy Example")
    print("=" * 50)
    
    # Check if environment variables are set for automatic configuration
    env_configured = all([
        os.getenv("FASTMCP_OAUTH_PROXY_ENABLED") == "true",
        os.getenv("FASTMCP_OAUTH_PROXY_CLIENT_ID"),
        os.getenv("FASTMCP_OAUTH_PROXY_CLIENT_SECRET"),
        os.getenv("FASTMCP_OAUTH_PROXY_UPSTREAM_ISSUER_URL"),
    ])
    
    if env_configured:
        print("Using environment-configured OAuth proxy server...")
        mcp = create_env_configured_oauth_proxy_server()
    else:
        print("Using manually-configured OAuth proxy server...")
        print("\nTo use environment configuration, set these variables:")
        print("  FASTMCP_OAUTH_PROXY_ENABLED=true")
        print("  FASTMCP_OAUTH_PROXY_CLIENT_ID=your-client-id")
        print("  FASTMCP_OAUTH_PROXY_CLIENT_SECRET=your-client-secret")
        print("  FASTMCP_OAUTH_PROXY_UPSTREAM_ISSUER_URL=https://auth.example.com")
        print("  FASTMCP_OAUTH_PROXY_SCOPES=read,write")
        print("  FASTMCP_OAUTH_PROXY_REDIRECT_URIS=http://localhost:3000/callback")
        print()
        
        mcp = create_manual_oauth_proxy_server()
    
    print(f"Starting {mcp.name}...")
    print("OAuth Proxy Configuration:")
    if hasattr(mcp.auth, 'upstream_issuer_url'):
        # Type checker doesn't know mcp.auth is OAuthProxyProvider, but these attributes exist at runtime
        oauth_proxy_auth = mcp.auth  # type: ignore
        print(f"  Upstream OAuth Server: {oauth_proxy_auth.upstream_issuer_url}")
        print(f"  Proxy Client ID: {oauth_proxy_auth.proxy_client_id}")
        print(f"  Default Scopes: {oauth_proxy_auth.default_scopes}")
    
    print("\nThe server will:")
    print("1. Accept DCR requests and return pre-configured client credentials")
    print("2. Forward OAuth authorization flows to the upstream server")
    print("3. Handle token exchange using the proxy credentials")
    print("4. Provide standard OAuth 2.1 endpoints for clients")
    
    print("\nStarting HTTP server on http://localhost:8000")
    print("OAuth Authorization Server metadata: http://localhost:8000/.well-known/oauth-authorization-server")
    print("OAuth Protected Resource metadata: http://localhost:8000/.well-known/oauth-protected-resource")
    print("MCP endpoint available at: http://localhost:8000/mcp/")
    
    # Run the server
    await mcp.run_async(transport="http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    asyncio.run(main()) 