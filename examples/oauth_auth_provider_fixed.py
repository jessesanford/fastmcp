#!/usr/bin/env python3
"""
OAuth Auth Provider - Fixed for Cursor Compatibility

This demonstrates the fixed OAuth auth provider that resolves the circular authentication
dependency by allowing unauthenticated access to OAuth discovery endpoints.

Key fixes applied:
1. OAuthPathBypassMiddleware - allows access to OAuth discovery endpoints without auth
2. BypassAwareBearerAuthBackend - respects bypass flags for OAuth endpoints
3. Proper middleware ordering - bypass middleware comes before authentication

Usage:
    Create .env file with Autodesk credentials:
    ADSK_CLIENT_ID=your_client_id
    ADSK_CLIENT_SECRET=your_client_secret
    
    python oauth_auth_provider_fixed.py
    
Then in Cursor:
    Settings → MCP → Add global MCP server
    URL: http://localhost:8000/mcp/
"""

import asyncio
import os
from pydantic_settings import BaseSettings
from fastmcp import FastMCP
from fastmcp.server.auth.providers.oauth_passthrough import OAuthPassthroughProvider


class Settings(BaseSettings):
    """Settings for the OAuth auth provider example."""
    adsk_client_id: str = "your-client-id"
    adsk_client_secret: str = "your-client-secret" 
    adsk_domain: str = "developer.api.autodesk.com"
    adsk_audience: str = "https://developer.api.autodesk.com/authentication/v2/"
    adsk_scope: str = "data:read data:write data:create data:search"
    
    class Config:
        env_file = ".env"


async def main():
    """Run the OAuth auth provider example with fixes."""
    
    settings = Settings()
    
    # Validate settings
    if settings.adsk_client_id == "your-client-id":
        print("❌ Please set ADSK_CLIENT_ID in your .env file")
        return
    
    print(f"""
🔧 OAuth Auth Provider - Fixed for Cursor
   Client ID: {settings.adsk_client_id}
   Domain: {settings.adsk_domain}
   Audience: {settings.adsk_audience}
   Scopes: {settings.adsk_scope}

🛠️ Applied Fixes:
   ✅ OAuthPathBypassMiddleware - OAuth discovery endpoints accessible without auth
   ✅ BypassAwareBearerAuthBackend - respects bypass flags
   ✅ Proper middleware ordering - no more circular authentication dependency

🎯 OAuth Flow:
   1. Cursor accesses /.well-known/oauth-authorization-server → ✅ No auth required
   2. Cursor performs DCR at /oauth/register → ✅ No auth required  
   3. Cursor redirects to /oauth/authorize → ✅ No auth required
   4. User authorizes with Autodesk → Gets real user token
   5. Cursor uses Bearer token for /mcp/ → ✅ Auth required
""")
    
    # Create OAuth passthrough provider
    auth_provider = OAuthPassthroughProvider(
        upstream_issuer_url=f"https://{settings.adsk_domain}",
        proxy_client_id=settings.adsk_client_id,
        proxy_client_secret=settings.adsk_client_secret,
        upstream_jwks_uri=f"https://{settings.adsk_domain}/authentication/v2/keys",
        audience=settings.adsk_audience,
        default_scopes=settings.adsk_scope.split(),
        required_scopes=["data:read"],  # Match Autodesk scope format
    )
    
    # Create FastMCP server with auth provider
    mcp = FastMCP(
        name="OAuth Auth Provider Fixed Demo",
        instructions="This server uses the fixed OAuth auth provider for Cursor compatibility.",
        auth=auth_provider
    )
    
    @mcp.tool()
    def test_oauth_auth() -> dict:
        """Test that OAuth authentication is working properly."""
        return {
            "status": "OAuth authentication successful!",
            "message": "You are authenticated via OAuth with real user tokens",
            "auth_provider": "OAuthPassthroughProvider (fixed for Cursor)",
            "fixes_applied": [
                "OAuthPathBypassMiddleware",
                "BypassAwareBearerAuthBackend", 
                "Proper middleware ordering"
            ]
        }
    
    @mcp.tool()
    def get_oauth_info() -> dict:
        """Get information about the OAuth configuration."""
        return {
            "oauth_provider": "OAuthPassthroughProvider",
            "upstream_issuer": f"https://{settings.adsk_domain}",
            "client_id": settings.adsk_client_id,
            "scopes": settings.adsk_scope.split(),
            "oauth_endpoints": {
                "metadata": "/.well-known/oauth-authorization-server",
                "registration": "/oauth/register", 
                "authorization": "/oauth/authorize",
                "protected_resource": "/.well-known/oauth-protected-resource"
            },
            "key_insight": "OAuth discovery endpoints are now accessible without authentication!"
        }
    
    print(f"""
🚀 Starting OAuth Auth Provider Server (Fixed)...

📋 Test the fixes:
   curl http://localhost:8000/.well-known/oauth-authorization-server
   curl -X POST http://localhost:8000/oauth/register -H "Content-Type: application/json" -d '{{}}'

🎯 For Cursor:
   Settings → MCP → Add global MCP server
   URL: http://localhost:8000/mcp/

🔍 Expected OAuth Flow:
   1. Cursor fetches metadata → ✅ Bypass middleware allows access
   2. Cursor does DCR → ✅ Bypass middleware allows access
   3. Cursor authorizes → ✅ Bypass middleware allows access
   4. User gets real token from Autodesk → ✅ Direct token exchange
   5. Cursor uses token for MCP → ✅ Authentication required and working
""")
    
    # Run the server
    await mcp.run_async(transport="http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    asyncio.run(main()) 