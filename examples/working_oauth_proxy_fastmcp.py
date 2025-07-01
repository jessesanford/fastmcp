#!/usr/bin/env python3
"""
Working OAuth Proxy with FastMCP - Replicates fastapi_mcp setup_proxies=True

This implementation exactly replicates how fastapi_mcp handles OAuth with setup_proxies=True:
- Proxies OAuth metadata with endpoint overrides
- Returns pre-configured credentials for DCR  
- Redirects authorization to correct Autodesk endpoints
- Does NOT intercept /token - clients get real user tokens directly

Usage:
    Create .env file with your Autodesk credentials (same as your working demo)
    python working_oauth_proxy_fastmcp.py
    
Then in Cursor:
    Settings → MCP → Add global MCP server
    URL: http://localhost:8000/mcp/
"""

import asyncio
import os
import httpx
from typing import Optional
from urllib.parse import urlencode
from pydantic_settings import BaseSettings

from fastmcp import FastMCP
from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.responses import JSONResponse, Response


class Settings(BaseSettings):
    """Use same settings as your working demo"""
    adsk_domain: str = "developer.api.autodesk.com"
    adsk_audience: str = "https://developer.api.autodesk.com/authentication/v2/"
    adsk_client_id: str = "your-client-id"
    adsk_client_secret: str = "your-client-secret"
    adsk_scope: str = "data:read data:write data:create data:search"

    @property
    def adsk_authorize_url(self):
        return f"https://{self.adsk_domain}/authentication/v2/authorize"
    
    @property
    def adsk_token_url(self):
        return f"https://{self.adsk_domain}/authentication/v2/token"
    
    @property
    def adsk_metadata_url(self):
        return f"https://{self.adsk_domain}/.well-known/openid-configuration"

    class Config:
        env_file = ".env"


def create_working_oauth_proxy_server():
    """Create OAuth proxy server that exactly replicates fastapi_mcp setup_proxies=True"""
    
    settings = Settings()
    
    # Validate credentials
    if settings.adsk_client_id == "your-client-id":
        print("❌ Please set ADSK_CLIENT_ID in your .env file")
        return None
    
    print(f"""
🔧 Working OAuth Proxy Configuration (same as your working demo):
   Domain: {settings.adsk_domain}
   Client ID: {settings.adsk_client_id}
   Audience: {settings.adsk_audience}
   Scope: {settings.adsk_scope}
   
🎯 Replicating fastapi_mcp setup_proxies=True behavior:
   ✅ Proxy OAuth metadata with endpoint overrides
   ✅ Return pre-configured credentials for DCR
   ✅ Redirect authorization to {settings.adsk_authorize_url}
   ✅ Do NOT intercept /token - clients hit {settings.adsk_token_url} directly
""")
    
    # Create FastMCP server without auth (we'll add OAuth proxy manually)
    mcp = FastMCP("Working OAuth Proxy Demo")
    
    # Add OAuth proxy endpoints using custom_route decorator
    @mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
    async def oauth_metadata_proxy(request: Request):
        """Proxy OAuth metadata with endpoint overrides (fastapi_mcp behavior)"""
        base_url = str(request.base_url).rstrip("/")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(settings.adsk_metadata_url)
                if response.status_code != 200:
                    return JSONResponse({"error": "Failed to fetch OAuth metadata"})
                
                oauth_metadata = response.json()
                
                # Override endpoints to point to our proxies (key fastapi_mcp behavior!)
                oauth_metadata["authorization_endpoint"] = f"{base_url}/oauth/authorize"
                oauth_metadata["registration_endpoint"] = f"{base_url}/oauth/register"
                # Do NOT override token_endpoint - clients hit Autodesk directly!
                
                print(f"✅ OAuth Metadata Request:")
                print(f"   Authorization: {oauth_metadata['authorization_endpoint']} (proxied)")
                print(f"   Registration: {oauth_metadata['registration_endpoint']} (proxied)")
                print(f"   Token: {oauth_metadata.get('token_endpoint')} (direct to Autodesk)")
                
                return JSONResponse(oauth_metadata)
                
        except Exception as e:
            print(f"❌ Error fetching OAuth metadata: {e}")
            return JSONResponse({"error": "Failed to fetch OAuth metadata"})

    @mcp.custom_route("/oauth/authorize", methods=["GET"])
    async def oauth_authorize_proxy(request: Request):
        """Redirect authorization to correct Autodesk endpoint (fastapi_mcp behavior)"""
        
        # Extract query parameters from request
        response_type = request.query_params.get("response_type", "code")
        client_id = request.query_params.get("client_id")
        redirect_uri = request.query_params.get("redirect_uri")
        scope = request.query_params.get("scope", "")
        state = request.query_params.get("state")
        code_challenge = request.query_params.get("code_challenge")
        code_challenge_method = request.query_params.get("code_challenge_method")
        audience = request.query_params.get("audience")
        
        # Use our pre-configured credentials (fastapi_mcp behavior)
        client_id = settings.adsk_client_id
        scope = scope or settings.adsk_scope
        audience = audience or settings.adsk_audience
        
        # Build authorization URL parameters
        params = {
            "response_type": response_type,
            "client_id": client_id,
            "redirect_uri": redirect_uri,
            "scope": scope,
            "audience": audience,
        }
        
        # Add optional PKCE parameters
        if state:
            params["state"] = state
        if code_challenge:
            params["code_challenge"] = code_challenge
        if code_challenge_method:
            params["code_challenge_method"] = code_challenge_method
        
        # Redirect to CORRECT Autodesk authorization endpoint
        auth_url = f"{settings.adsk_authorize_url}?{urlencode(params)}"
        
        print(f"🔗 Authorization Request:")
        print(f"   Client ID: {client_id}")
        print(f"   Redirect URI: {redirect_uri}")
        print(f"   Scope: {scope}")
        print(f"   ✅ Redirecting to: {auth_url}")
        
        return RedirectResponse(url=auth_url)

    @mcp.custom_route("/oauth/register", methods=["POST"])
    async def oauth_register_proxy(request: Request):
        """Return pre-configured credentials (fastapi_mcp setup_proxies=True behavior)"""
        
        try:
            registration_data = await request.json()
        except:
            registration_data = {}
        
        # Return our pre-configured credentials (fastapi_mcp behavior)
        response_data = {
            "client_name": registration_data.get("client_name", "MCP Client"),
            "client_id": settings.adsk_client_id,        # From .env
            "client_secret": settings.adsk_client_secret, # From .env  
            "redirect_uris": registration_data.get("redirect_uris", []),
            "grant_types": registration_data.get("grant_types", ["authorization_code"]),
            "token_endpoint_auth_method": "client_secret_post",
            "scope": settings.adsk_scope,
        }
        
        print(f"🔗 DCR Request: Returning pre-configured credentials")
        print(f"   Client ID: {settings.adsk_client_id}")
        print(f"   Redirect URIs: {response_data['redirect_uris']}")
        
        return JSONResponse(response_data)

    @mcp.custom_route("/.well-known/oauth-protected-resource", methods=["GET"])
    async def oauth_protected_resource(request: Request):
        """OAuth protected resource metadata (required by MCP spec)"""
        return JSONResponse({
            "resource": "http://localhost:8000/mcp/",
            "authorization_servers": ["http://localhost:8000"],
            "scopes_supported": settings.adsk_scope.split(),
            "bearer_methods_supported": ["header"],
        })

    # Add MCP tools that demonstrate the working OAuth flow
    @mcp.tool()
    def get_oauth_status() -> dict:
        """Get status of the OAuth proxy setup"""
        return {
            "status": "OAuth proxy active",
            "implementation": "Replicates fastapi_mcp setup_proxies=True",
            "oauth_flow": {
                "metadata": "✅ Proxied with endpoint overrides",
                "dcr": "✅ Returns pre-configured credentials",
                "authorization": f"✅ Redirects to {settings.adsk_authorize_url}",
                "token": f"✅ Direct to {settings.adsk_token_url} (not intercepted)",
            },
            "key_difference": "Does NOT intercept /token - clients get real user tokens"
        }

    @mcp.tool()
    def compare_with_fastapi_mcp() -> dict:
        """Compare this implementation with fastapi_mcp setup_proxies=True"""
        return {
            "this_implementation": "FastMCP with manual OAuth proxy endpoints",
            "equivalent_to": "fastapi_mcp with AuthConfig(setup_proxies=True)",
            "exact_same_behavior": {
                "oauth_metadata": "✅ Proxied with endpoint overrides",
                "dcr": "✅ Returns pre-configured credentials from .env",
                "authorization": "✅ Redirects to correct Autodesk endpoint",
                "token": "✅ NOT intercepted - clients hit Autodesk directly",
                "user_tokens": "✅ Real user tokens from Autodesk (preserves userid)",
            },
            "why_this_works": "Same approach as your working my-demo-mcp-server"
        }
    
    return mcp


async def main():
    """Main function to run the working OAuth proxy server"""
    
    mcp = create_working_oauth_proxy_server()
    if not mcp:
        return
    
    print(f"""
🚀 Starting Working OAuth Proxy Server...

📋 This implementation exactly replicates:
   ✅ fastapi_mcp with AuthConfig(setup_proxies=True)
   ✅ Your working my-demo-mcp-server behavior
   ✅ Does NOT intercept /token (same as fastapi_mcp)
   ✅ Uses same .env variables as your working demo

🔧 Test the OAuth endpoints:
   curl http://localhost:8000/.well-known/oauth-authorization-server
   curl -X POST http://localhost:8000/oauth/register -H "Content-Type: application/json" -d '{{}}'

🎯 For Cursor:
   Settings → MCP → Add global MCP server
   URL: http://localhost:8000/mcp/

🔑 Expected OAuth Flow:
   1. Cursor fetches metadata → Gets our proxy endpoints
   2. Cursor does DCR → Gets your .env credentials  
   3. Cursor authorizes → Redirected to Autodesk
   4. Cursor exchanges token → Directly with Autodesk (NOT intercepted)
   5. Cursor uses real user token → For MCP requests
""")
    
    # Run the server
    await mcp.run_async(transport="http", host="0.0.0.0", port=8000)


if __name__ == "__main__":
    asyncio.run(main()) 