# OAuth Passthrough Proxy - Working Example

## 🎯 What This Fixes

Your "requested resource does not exist" error was caused by **incorrect Autodesk endpoint URLs**:

- ❌ **Wrong**: `https://developer.api.autodesk.com/authorize` 
- ✅ **Correct**: `https://developer.api.autodesk.com/authentication/v2/authorize`

This working example implements the same behavior as `fastapi_mcp` with `setup_proxies=True`.

## 🚀 Quick Start

1. **Install dependencies**:
   ```bash
   pip install fastapi uvicorn httpx
   ```

2. **Set environment variables** (optional):
   ```bash
   export CLIENT_ID=your_autodesk_client_id
   export CLIENT_SECRET=your_autodesk_client_secret
   export AUDIENCE=https://developer.api.autodesk.com
   ```

3. **Run the server**:
   ```bash
   python oauth_passthrough_proxy_working.py
   ```

4. **Test the fix**:
   ```bash
   curl http://localhost:8000/.well-known/oauth-authorization-server
   ```

## 🔑 For Cursor

1. **Go to**: Settings → MCP → Add global MCP server
2. **URL**: `http://localhost:8000/mcp`
3. **Cursor will now use correct Autodesk endpoints!**

## 🛠️ How It Works

This implementation:

✅ **Transparently proxies OAuth metadata** with correct endpoint overrides  
✅ **Redirects authorization** to correct Autodesk endpoint (`/authentication/v2/authorize`)  
✅ **Returns pre-configured credentials** for registration (fake DCR)  
✅ **Does NOT intercept token endpoint** - clients get real user tokens directly  
✅ **Preserves user context** (userid claims) unlike OAuth Proxy  

## 📋 Key Differences from OAuth Proxy

| Aspect | OAuth Proxy | OAuth Passthrough Proxy |
|--------|-------------|-------------------------|
| **Token Source** | Manufactured via `client_credentials` | Real user tokens from upstream |
| **User Context** | ❌ Lost (no userid claims) | ✅ Preserved (includes userid) |
| **Token Endpoint** | ❌ Intercepted | ✅ NOT intercepted |
| **Autodesk URLs** | ❌ Wrong (`/authorize`) | ✅ Correct (`/authentication/v2/authorize`) |

## 🔧 Test Results

When you run this example and check the OAuth metadata:

```json
{
  "authorization_endpoint": "http://localhost:8000/oauth/authorize",
  "token_endpoint": "https://developer.api.autodesk.com/authentication/v2/token",
  "registration_endpoint": "http://localhost:8000/oauth/register"
}
```

**Key insight**: The `authorization_endpoint` points to our proxy (which redirects to correct Autodesk URL), but `token_endpoint` points directly to Autodesk - this preserves real user tokens!

## 🎯 Expected Behavior with Cursor

1. **Cursor does DCR** → Gets pre-configured credentials from `/oauth/register`
2. **Cursor redirects to `/oauth/authorize`** → Our proxy redirects to correct Autodesk endpoint
3. **User authorizes** → Gets **real user token** directly from Autodesk  
4. **Cursor uses real user token** → Token contains userid claims
5. **MCP calls work** with real user context

This matches your working `fastapi_mcp` demo behavior while fixing the URL issue! 