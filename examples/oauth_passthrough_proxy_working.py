#!/usr/bin/env python3
"""
OAuth Passthrough Proxy - Working Example

This is a complete working implementation that replicates fastapi_mcp setup_proxies=True behavior:
- Fixes "requested resource does not exist" error by using correct Autodesk endpoints
- Transparently proxies OAuth metadata with endpoint overrides
- Redirects authorization requests to correct Autodesk endpoint
- Returns pre-configured credentials for registration
- Does NOT intercept token endpoint - clients get real user tokens directly

Usage:
    pip install fastapi uvicorn httpx
    python oauth_passthrough_proxy_working.py

Then in Cursor:
    Settings → MCP → Add global MCP server
    URL: http://localhost:8000/mcp
"""

import os
import httpx
from typing import Optional
from urllib.parse import urlencode
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse

# OAuth configuration - set these as environment variables
UPSTREAM_ISSUER_URL = os.getenv("UPSTREAM_ISSUER_URL", "https://developer.api.autodesk.com")
CLIENT_ID = os.getenv("CLIENT_ID", "your_autodesk_client_id")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your_autodesk_client_secret")
AUDIENCE = os.getenv("AUDIENCE", "https://developer.api.autodesk.com")
DEFAULT_SCOPES = "data:read data:write data:create data:search"

# Correct Autodesk endpoints (the key fix!)
UPSTREAM_METADATA_URL = f"{UPSTREAM_ISSUER_URL}/.well-known/openid-configuration"
UPSTREAM_AUTHORIZE_URL = f"{UPSTREAM_ISSUER_URL}/authentication/v2/authorize"  # ✅ CORRECT!
UPSTREAM_TOKEN_URL = f"{UPSTREAM_ISSUER_URL}/authentication/v2/token"  # ✅ CORRECT!

print(f"""
🔧 OAuth Passthrough Proxy Configuration:
   Upstream Issuer: {UPSTREAM_ISSUER_URL}
   Client ID: {CLIENT_ID}
   Audience: {AUDIENCE}
   
🎯 Key Fix - Using CORRECT Autodesk endpoints:
   ✅ Authorization: {UPSTREAM_AUTHORIZE_URL}
   ✅ Token: {UPSTREAM_TOKEN_URL}
   
   (Instead of wrong /authorize and /token paths)
""")

# Create FastAPI app
app = FastAPI(title="OAuth Passthrough Proxy", version="1.0.0")


@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata_proxy(request: Request):
    """
    Proxy OAuth metadata with correct endpoint overrides.
    This is the key to fixing the "requested resource does not exist" error.
    """
    base_url = str(request.base_url).rstrip("/")
    
    try:
        # Fetch upstream OAuth metadata from Autodesk
        async with httpx.AsyncClient() as client:
            response = await client.get(UPSTREAM_METADATA_URL)
            if response.status_code != 200:
                print(f"❌ Failed to fetch metadata: {response.status_code}")
                return {"error": "Failed to fetch OAuth metadata"}
            
            oauth_metadata = response.json()
            
            # Override endpoints to point to our proxies (fastapi_mcp behavior)
            oauth_metadata["authorization_endpoint"] = f"{base_url}/oauth/authorize"
            oauth_metadata["registration_endpoint"] = f"{base_url}/oauth/register"
            
            print(f"✅ Proxied OAuth metadata:")
            print(f"   Authorization endpoint: {oauth_metadata['authorization_endpoint']}")
            print(f"   Registration endpoint: {oauth_metadata['registration_endpoint']}")
            print(f"   Token endpoint: {oauth_metadata.get('token_endpoint')} (not intercepted)")
            
            return oauth_metadata
            
    except Exception as e:
        print(f"❌ Error fetching OAuth metadata: {e}")
        return {"error": "Failed to fetch OAuth metadata"}


@app.get("/oauth/authorize")
async def oauth_authorize_proxy(
    response_type: str = "code",
    client_id: Optional[str] = None,
    redirect_uri: Optional[str] = None,
    scope: str = "",
    state: Optional[str] = None,
    code_challenge: Optional[str] = None,
    code_challenge_method: Optional[str] = None,
    audience: Optional[str] = None,
):
    """
    Proxy authorization requests to correct Autodesk endpoint with parameter defaults.
    This ensures Cursor gets redirected to the right Autodesk URL.
    """
    
    # Use defaults if not provided (fastapi_mcp behavior)
    if not client_id:
        client_id = CLIENT_ID
    if not scope:
        scope = DEFAULT_SCOPES
    if not audience:
        audience = AUDIENCE
    
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
    
    # Use CORRECT Autodesk authorization endpoint
    auth_url = f"{UPSTREAM_AUTHORIZE_URL}?{urlencode(params)}"
    
    print(f"🔗 Authorization redirect:")
    print(f"   Client ID: {client_id}")
    print(f"   Redirect URI: {redirect_uri}")
    print(f"   Scope: {scope}")
    print(f"   Audience: {audience}")
    print(f"   ✅ Redirecting to: {auth_url}")
    
    return RedirectResponse(url=auth_url)


@app.post("/oauth/register")
async def oauth_register_proxy(request: Request):
    """
    Return pre-configured credentials (fake DCR).
    This allows Cursor to get client credentials without actual dynamic registration.
    """
    
    try:
        registration_data = await request.json()
    except:
        registration_data = {}
    
    # Return pre-configured credentials (fastapi_mcp behavior)
    response_data = {
        "client_name": registration_data.get("client_name", "MCP Client"),
        "client_id": CLIENT_ID,
        "client_secret": CLIENT_SECRET,
        "redirect_uris": registration_data.get("redirect_uris", []),
        "grant_types": registration_data.get("grant_types", ["authorization_code"]),
        "token_endpoint_auth_method": registration_data.get("token_endpoint_auth_method", "none"),
    }
    
    print(f"🔗 DCR Request: Returning pre-configured credentials")
    print(f"   Client ID: {CLIENT_ID}")
    print(f"   Redirect URIs: {response_data['redirect_uris']}")
    
    return response_data


@app.get("/mcp")
async def mcp_endpoint():
    """
    MCP endpoint that provides information about this OAuth passthrough proxy.
    In a real implementation, this would be handled by FastMCP.
    """
    return {
        "name": "OAuth Passthrough Proxy Demo",
        "version": "1.0.0",
        "description": "Demonstrates OAuth passthrough proxy with correct Autodesk endpoints",
        "oauth_endpoints": {
            "metadata": "/.well-known/oauth-authorization-server",
            "authorization": f"/oauth/authorize → {UPSTREAM_AUTHORIZE_URL}",
            "registration": "/oauth/register (pre-configured credentials)",
            "token": f"NOT INTERCEPTED → {UPSTREAM_TOKEN_URL}"
        },
        "key_differences": {
            "oauth_proxy": "Manufactures tokens via client_credentials (loses user context)",
            "oauth_passthrough_proxy": "Real user tokens from upstream (preserves userid claims)"
        },
        "endpoint_fix": {
            "wrong_authorization": "https://developer.api.autodesk.com/authorize",
            "correct_authorization": UPSTREAM_AUTHORIZE_URL,
            "wrong_token": "https://developer.api.autodesk.com/token", 
            "correct_token": UPSTREAM_TOKEN_URL
        }
    }


@app.get("/")
async def root():
    """Root endpoint with helpful information"""
    return {
        "message": "OAuth Passthrough Proxy - Working Example",
        "endpoints": {
            "mcp": "/mcp",
            "oauth_metadata": "/.well-known/oauth-authorization-server",
            "oauth_authorize": "/oauth/authorize",
            "oauth_register": "/oauth/register"
        },
        "setup": {
            "environment_variables": {
                "CLIENT_ID": "Set your Autodesk client ID",
                "CLIENT_SECRET": "Set your Autodesk client secret",
                "AUDIENCE": "Set to https://developer.api.autodesk.com"
            },
            "cursor_setup": "Settings → MCP → Add global MCP server → http://localhost:8000/mcp"
        },
        "key_insight": "This fixes 'requested resource does not exist' by using correct Autodesk endpoints"
    }


if __name__ == "__main__":
    print(f"""
🚀 Starting OAuth Passthrough Proxy Server...

📋 This implementation:
   ✅ Uses correct Autodesk endpoints (/authentication/v2/authorize)
   ✅ Transparently proxies OAuth metadata
   ✅ Returns pre-configured credentials for DCR
   ✅ Does NOT intercept /token - clients get real user tokens
   ✅ Fixes "requested resource does not exist" error

🔧 Test the fix:
   curl http://localhost:8000/.well-known/oauth-authorization-server
   curl http://localhost:8000/mcp

🔑 For Cursor:
   Settings → MCP → Add global MCP server
   URL: http://localhost:8000/mcp

⚙️  Environment Variables (optional):
   export CLIENT_ID=your_autodesk_client_id
   export CLIENT_SECRET=your_autodesk_client_secret
   export AUDIENCE=https://developer.api.autodesk.com
""")
    
    # Run the server
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000) 