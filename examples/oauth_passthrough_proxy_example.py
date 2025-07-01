#!/usr/bin/env python3
"""
OAuth Passthrough Proxy URL Fix for FastMCP

🔑 ROOT CAUSE of "requested resource does not exist" error:

The default BearerAuthProvider in FastMCP provides incorrect Autodesk endpoints:
   ❌ authorization_endpoint: "https://developer.api.autodesk.com/authorize"
   ❌ token_endpoint: "https://developer.api.autodesk.com/token"

But Autodesk's ACTUAL endpoints are:
   ✅ authorization_endpoint: "https://developer.api.autodesk.com/authentication/v2/authorize"
   ✅ token_endpoint: "https://developer.api.autodesk.com/authentication/v2/token"

This is why you're getting the "requested resource does not exist" error - 
Cursor is trying to hit /authorize instead of /authentication/v2/authorize!

To implement OAuth passthrough proxy properly in FastMCP, you need to:

1. Create proxy routes that override the OAuth metadata endpoints
2. Redirect authorization requests to the correct Autodesk endpoint
3. Return pre-configured credentials for registration
4. Do NOT intercept the token endpoint

Configuration:
- Set UPSTREAM_ISSUER_URL=https://developer.api.autodesk.com
- Set CLIENT_ID=your_autodesk_client_id  
- Set CLIENT_SECRET=your_autodesk_client_secret
- Set AUDIENCE=https://developer.api.autodesk.com

This example shows the required FastAPI routes (install fastapi and uvicorn first):
   pip install fastapi uvicorn httpx
"""

import os
from typing import Optional
from urllib.parse import urlencode

# OAuth configuration
UPSTREAM_ISSUER_URL = os.getenv("UPSTREAM_ISSUER_URL", "https://developer.api.autodesk.com")
CLIENT_ID = os.getenv("CLIENT_ID", "your_client_id")
CLIENT_SECRET = os.getenv("CLIENT_SECRET", "your_client_secret")
AUDIENCE = os.getenv("AUDIENCE", "https://developer.api.autodesk.com")
DEFAULT_SCOPES = "data:read data:write data:create data:search"

# Correct Autodesk endpoints
UPSTREAM_METADATA_URL = f"{UPSTREAM_ISSUER_URL}/.well-known/openid-configuration"
UPSTREAM_AUTHORIZE_URL = f"{UPSTREAM_ISSUER_URL}/authentication/v2/authorize"  # ✅ CORRECT!
UPSTREAM_TOKEN_URL = f"{UPSTREAM_ISSUER_URL}/authentication/v2/token"  # ✅ CORRECT!

print(f"""
🔧 OAuth Passthrough Proxy Configuration:
   Upstream Issuer: {UPSTREAM_ISSUER_URL}
   Client ID: {CLIENT_ID}
   Audience: {AUDIENCE}
   
🛠️  Required FastAPI Routes (install: pip install fastapi uvicorn httpx):

# Metadata Proxy (overrides endpoints)
@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata_proxy(request):
    import httpx
    async with httpx.AsyncClient() as client:
        response = await client.get("{UPSTREAM_METADATA_URL}")
        oauth_metadata = response.json()
        
        # Override with local proxies
        base_url = str(request.base_url).rstrip("/")
        oauth_metadata["authorization_endpoint"] = f"{{base_url}}/oauth/authorize"
        oauth_metadata["registration_endpoint"] = f"{{base_url}}/oauth/register"
        
        return oauth_metadata

# Authorization Proxy (redirect to correct Autodesk endpoint)  
@app.get("/oauth/authorize")
async def oauth_authorize_proxy(client_id: str = "{CLIENT_ID}", scope: str = "{DEFAULT_SCOPES}", ...):
    from fastapi.responses import RedirectResponse
    
    params = {{
        "response_type": "code",
        "client_id": client_id or "{CLIENT_ID}",
        "scope": scope or "{DEFAULT_SCOPES}",
        "audience": "{AUDIENCE}",
        # ... other OAuth parameters
    }}
    
    # Use CORRECT Autodesk endpoint
    auth_url = "{UPSTREAM_AUTHORIZE_URL}?" + urlencode(params)
    return RedirectResponse(url=auth_url)

# Registration Proxy (return pre-configured credentials)
@app.post("/oauth/register") 
async def oauth_register_proxy(request):
    registration_data = await request.json()
    
    return {{
        "client_id": "{CLIENT_ID}",
        "client_secret": "{CLIENT_SECRET}",
        "redirect_uris": registration_data.get("redirect_uris", []),
        # ... other DCR response fields
    }}

# DO NOT create /token endpoint - let clients hit Autodesk directly!
""")

def show_url_comparison():
    """Show the URL differences that cause the error"""
    print(f"""
🔍 URL COMPARISON - Why you get "requested resource does not exist":

❌ WRONG URLs (what FastMCP BearerAuthProvider provides by default):
   Authorization: https://developer.api.autodesk.com/authorize
   Token:         https://developer.api.autodesk.com/token
   
✅ CORRECT URLs (what Autodesk actually uses):
   Authorization: {UPSTREAM_AUTHORIZE_URL}
   Token:         {UPSTREAM_TOKEN_URL}
   
🔧 SOLUTION:
   Create proxy routes that override the OAuth metadata to use correct endpoints.
   This is exactly what fastapi_mcp with setup_proxies=True does.

💡 TEST THE FIX:
   1. Install dependencies: pip install fastapi uvicorn httpx
   2. Create the FastAPI routes shown above
   3. Run the server and test: curl http://localhost:8000/.well-known/oauth-authorization-server
   4. Verify authorization_endpoint points to correct /authentication/v2/authorize path
""")

def show_working_implementation():
    """Show a complete working implementation"""
    print(f"""
🚀 COMPLETE WORKING IMPLEMENTATION:

Create this file (requires: pip install fastapi uvicorn httpx):

```python
from fastapi import FastAPI, Request
from fastapi.responses import RedirectResponse
import httpx
from urllib.parse import urlencode

app = FastAPI()

@app.get("/.well-known/oauth-authorization-server")
async def oauth_metadata_proxy(request: Request):
    base_url = str(request.base_url).rstrip("/")
    
    async with httpx.AsyncClient() as client:
        response = await client.get("{UPSTREAM_METADATA_URL}")
        oauth_metadata = response.json()
        
        # Override endpoints (fastapi_mcp behavior)
        oauth_metadata["authorization_endpoint"] = f"{{base_url}}/oauth/authorize"
        oauth_metadata["registration_endpoint"] = f"{{base_url}}/oauth/register"
        
        return oauth_metadata

@app.get("/oauth/authorize")
async def oauth_authorize_proxy(
    response_type: str = "code",
    client_id: str = "{CLIENT_ID}",
    redirect_uri: str = None,
    scope: str = "{DEFAULT_SCOPES}",
    audience: str = "{AUDIENCE}",
    state: str = None,
    code_challenge: str = None,
    code_challenge_method: str = None,
):
    params = {{
        "response_type": response_type,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "audience": audience,
    }}
    if state: params["state"] = state
    if code_challenge: params["code_challenge"] = code_challenge
    if code_challenge_method: params["code_challenge_method"] = code_challenge_method
    
    # Redirect to CORRECT Autodesk endpoint
    auth_url = "{UPSTREAM_AUTHORIZE_URL}?" + urlencode(params)
    return RedirectResponse(url=auth_url)

@app.post("/oauth/register")
async def oauth_register_proxy(request: Request):
    try:
        registration_data = await request.json()
    except:
        registration_data = {{}}
    
    return {{
        "client_name": registration_data.get("client_name", "MCP Client"),
        "client_id": "{CLIENT_ID}",
        "client_secret": "{CLIENT_SECRET}",
        "redirect_uris": registration_data.get("redirect_uris", []),
        "grant_types": ["authorization_code"],
        "token_endpoint_auth_method": "none",
    }}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
```

Then run: python your_oauth_proxy.py
""")

if __name__ == "__main__":
    print(f"""
🔑 KEY INSIGHT: Your "requested resource does not exist" error is caused by incorrect URLs!

FastMCP's default BearerAuthProvider uses wrong Autodesk endpoints.
You need to create proxy routes that override these with correct paths.
""")
    
    show_url_comparison()
    show_working_implementation()
    
    print(f"""
✅ NEXT STEPS:
   1. Install FastAPI: pip install fastapi uvicorn httpx
   2. Create the working implementation above
   3. Set your environment variables (CLIENT_ID, CLIENT_SECRET, etc.)
   4. Run the server and test the OAuth metadata endpoint
   5. The authorization URL should now work correctly with Cursor!
   
🎯 This replicates the exact behavior of fastapi_mcp with setup_proxies=True
""") 