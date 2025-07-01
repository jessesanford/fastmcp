"""Example FastMCP server that uses TransparentOAuthProxyProvider.

1.  Copy `.env.example` to `.env` and fill in the upstream values for your
    Authorization Server.
2.  Load the environment variables (e.g. `source .env`) or rely on a tool such
    as `dotenv` to auto-load them.
3.  Run the server:  
    ```bash
    uvicorn examples.transparent_oauth_proxy.server:app --reload --port 8000
    ```

Navigate to `http://localhost:8000/mcp` (or whichever transport you enable) and
connect with an MCP-compatible client such as Cursor.
"""

from __future__ import annotations

"""Transparent OAuth Proxy Example.

This example automatically loads environment variables from a `.env` file (if
present) using *python-dotenv*.  Place the file either in the project root **or**
alongside this script (`examples/transparent_oauth_proxy/.env`).  The file
should contain the five required upstream settings in simple `KEY=value`
format.
"""

import os
from pathlib import Path

from dotenv import load_dotenv

from fastmcp import FastMCP
from fastmcp.server.auth.providers.transparent_proxy import (
    TransparentOAuthProxyProvider,
)
from starlette.responses import RedirectResponse, JSONResponse
from starlette.requests import Request
import httpx
from urllib.parse import urlencode
from starlette.routing import Route  # import locally to avoid top-level circularity
import logging
from fastmcp.server.context import Context
from fastmcp.server.dependencies import get_access_token

# ---------------------------------------------------------------------------
# Load the `.env` file (if present).
# ---------------------------------------------------------------------------

# First look for a .env next to this script; then fall back to the project root.
_THIS_DIR = Path(__file__).resolve().parent
load_dotenv(_THIS_DIR / ".env", override=False)
# Also attempt to load a project-root .env so either location works.
load_dotenv(override=False)

# ---------------------------------------------------------------------------
# Read configuration from environment variables.  In a real deployment you
# would manage these secrets via your orchestrator (Kubernetes, Docker secrets,
# etc.).  For demonstration purposes we simply pull from environment variables.
# ---------------------------------------------------------------------------

REQUIRED_VARS = [
    "UPSTREAM_AUTHORIZATION_ENDPOINT",
    "UPSTREAM_TOKEN_ENDPOINT",
    "UPSTREAM_JWKS_URI",
    "UPSTREAM_CLIENT_ID",
    "UPSTREAM_CLIENT_SECRET",
]

missing = [v for v in REQUIRED_VARS if v not in os.environ]
if missing:
    raise RuntimeError(
        "Missing required environment variables: " + ", ".join(missing)
    )

provider = TransparentOAuthProxyProvider(
    upstream_authorization_endpoint=os.environ["UPSTREAM_AUTHORIZATION_ENDPOINT"],
    upstream_token_endpoint=os.environ["UPSTREAM_TOKEN_ENDPOINT"],
    upstream_jwks_uri=os.environ["UPSTREAM_JWKS_URI"],
    upstream_client_id=os.environ["UPSTREAM_CLIENT_ID"],
    upstream_client_secret=os.environ["UPSTREAM_CLIENT_SECRET"],
    issuer_url="http://localhost:8000",  # Public URL of this FastMCP instance
)

mcp = FastMCP("Transparent-Proxy-Demo", auth=provider)

# Create module-level logger
logger = logging.getLogger("transparent_oauth_proxy")
if not logger.handlers:
    logging.basicConfig(level=logging.INFO)

@mcp.tool
def add(a: int, b: int) -> int:  # noqa: D401
    """Simple demo tool that requires authentication."""

    return a + b


app = mcp.http_app(path="/mcp")

# ---------------------------------------------------------------------------
# Lightweight proxy routes that mirror fastapi_mcp's `setup_proxies=True`.
# These bypass FastMCP's internal Authorization/Token handlers so we do not
# perform local PKCE validation; instead we forward every request to Autodesk
# after swapping in the *pre-registered* upstream client credentials.
# ---------------------------------------------------------------------------


@mcp.custom_route("/authorize", methods=["GET"], include_in_schema=False)
async def proxy_authorize(request: Request):  # noqa: D401
    """Redirect the browser to the upstream authorization endpoint.

    We replace the *dynamic* client_id that Cursor passes with the static
    `upstream_client_id` expected by Autodesk. All other query parameters
    (PKCE, redirect_uri, scopes, etc.) are forwarded untouched.
    """

    params = dict(request.query_params)
    params["client_id"] = provider._upstream_client_id  # pyright: ignore [reportPrivateUsage]

    upstream_url = f"{provider._upstream_authorization_endpoint}?{urlencode(params, doseq=True)}"  # pyright: ignore [reportPrivateUsage]
    logger.info("Redirecting browser to upstream /authorize: %s", upstream_url)
    return RedirectResponse(upstream_url, status_code=302)

# Insert /authorize with highest precedence
app.router.routes.insert(0, Route("/authorize", proxy_authorize, methods=["GET"]))

@mcp.custom_route("/token", methods=["POST"], include_in_schema=False)
async def proxy_token(request: Request):  # noqa: D401
    """Forward the token request to the upstream server.

    We replace `client_id` / `client_secret` with the proxy's static upstream
    credentials and stream the JSON response back to the caller.
    """

    form = await request.form()
    data = dict(form)

    # Upstream expects the *static* client credentials pre-registered for this
    # proxy rather than the dynamic credentials issued to the MCP client.
    data["client_id"] = provider._upstream_client_id  # pyright: ignore [reportPrivateUsage]
    data["client_secret"] = provider._upstream_client_secret.get_secret_value()  # pyright: ignore [reportPrivateUsage]

    # Ensure `redirect_uri` is a string (Starlette form values can be UploadFile/bytes)
    if "redirect_uri" in data:
        data["redirect_uri"] = str(data.get("redirect_uri"))

    redacted = {}
    for k, v in data.items():
        sval = str(v)
        if k in {"code", "client_secret"}:
            sval = sval[:8] + "…"
        redacted[k] = sval
    logger.info("Forwarding token request: %s", redacted)

    async with httpx.AsyncClient(timeout=10) as http:
        upstream_resp = await http.post(
            provider._upstream_token_endpoint,
            data=data,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )  # pyright: ignore [reportPrivateUsage]

    # Dump upstream response body regardless of status
    body_text = upstream_resp.text
    logger.info("Upstream /token response %s — body: %s", upstream_resp.status_code, body_text[:300])

    # Try to relay JSON if possible; otherwise relay plain text
    try:
        payload = upstream_resp.json()
    except ValueError:
        payload = {"error": "upstream_error", "details": body_text}

    return JSONResponse(payload, status_code=upstream_resp.status_code)

# Insert /token with highest precedence
app.router.routes.insert(0, Route("/token", proxy_token, methods=["POST"]))

# Alias /tokens
app.router.routes.insert(0, Route("/tokens", proxy_token, methods=["POST"]))

# ---------------------------------------------------------------------------
# Root-level discovery endpoint (avoids /mcp prefix).
# ---------------------------------------------------------------------------

async def protected_resource_metadata(request: Request):  # noqa: D401
    base = str(request.url.replace(path="")).rstrip("/")
    return JSONResponse(
        {
            "issuer": base,
            "authorization_server": f"{base}/.well-known/oauth-authorization-server",
            "jwks_uri": provider._upstream_jwks_uri,  # pyright: ignore [reportPrivateUsage]
        }
    )

# Insert route with high precedence
app.router.routes.insert(0, Route("/.well-known/oauth-protected-resource", protected_resource_metadata, methods=["GET"]))

# ---------------------------------------------------------------------------
# Additional demo tool: User Info
# ---------------------------------------------------------------------------

@mcp.tool(name="user_info", description="Return information about the currently authenticated OAuth client")
async def user_info(ctx: Context) -> dict[str, str]:  # noqa: D401
    """Return the `client_id` embedded in the bearer token used for this request.

    The access token has already been verified by the TransparentOAuthProxyProvider
    and attached to the request context by FastMCP's auth middleware.  We simply
    pull it out via `get_access_token()` and pluck the *client_id* claim.
    """

    try:
        access_token = get_access_token()
    except RuntimeError:
        # No token available – tool was called without authentication.
        await ctx.error("No access token found in request – are you authenticated?")
        raise ValueError("Unauthorized: missing bearer token")

    client_id = access_token.client_id if access_token else None
    if not client_id:
        await ctx.error("Bearer token did not contain client_id claim")
        raise ValueError("Bearer token missing client_id claim")

    # Minimal payload – extend with more claims if desired.
    return {"client_id": client_id} 