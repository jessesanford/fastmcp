"""
OAuth Passthrough Provider for FastMCP

This provider implements transparent OAuth proxying similar to fastapi_mcp's setup_proxies=True.
It handles DCR by returning pre-configured client credentials and proxies OAuth metadata and 
authorization flows, but does NOT intercept the token endpoint - allowing clients to get 
real user tokens directly from the upstream server.

Key differences from OAuthProxyProvider:
- Does NOT intercept /token endpoint
- Clients get real user tokens directly from upstream 
- Preserves user context (userid claims)
- Uses JWT validation for incoming tokens (like BearerAuthProvider)

This is the equivalent of fastapi_mcp's AuthConfig with setup_proxies=True.
"""

import time
from typing import Any, Dict, Optional
import httpx
import jwt
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import (
    OAuthClientInformationFull,
    OAuthToken,
)
from pydantic import AnyHttpUrl

from fastmcp.server.auth.auth import (
    ClientRegistrationOptions,
    OAuthProvider,
    RevocationOptions,
)
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)




class OAuthPassthroughProvider(OAuthProvider):
    """
    OAuth Passthrough Provider - equivalent to fastapi_mcp's setup_proxies=True.
    
    This provider acts as a transparent proxy for OAuth flows:
    - Proxies OAuth metadata with endpoint overrides 
    - Returns pre-configured credentials for DCR (fake dynamic registration)
    - Redirects authorization requests to correct upstream endpoints
    - Does NOT intercept token endpoint - clients get real user tokens
    - Validates incoming JWT tokens using upstream JWKS (like BearerAuthProvider)
    
    This preserves user context (userid claims) because clients get real tokens
    directly from the upstream OAuth server.
    """

    def __init__(
        self,
        upstream_issuer_url: AnyHttpUrl | str,
        proxy_client_id: str,
        proxy_client_secret: str,
        issuer_url: AnyHttpUrl | str | None = None,
        service_documentation_url: AnyHttpUrl | str | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None,
        required_scopes: list[str] | None = None,
        default_scopes: list[str] | None = None,
        allowed_redirect_uris: list[str] | None = None,
        upstream_jwks_uri: AnyHttpUrl | str | None = None,
        audience: str | None = None,
        httpx_client_kwargs: Dict[str, Any] | None = None,
    ):
        """
        Initialize the OAuth Passthrough Provider.

        Args:
            upstream_issuer_url: URL of the upstream OAuth server
            proxy_client_id: Pre-configured client ID to return for DCR requests
            proxy_client_secret: Pre-configured client secret to return for DCR requests
            issuer_url: URL to advertise as the issuer (defaults to upstream_issuer_url)
            service_documentation_url: Documentation URL for the service
            client_registration_options: Client registration options
            revocation_options: Token revocation options
            required_scopes: Scopes required for all requests
            default_scopes: Default scopes to grant if none specified
            allowed_redirect_uris: List of allowed redirect URIs (None = allow all)
            upstream_jwks_uri: JWKS URI for token validation
            audience: Expected audience in JWT tokens
            httpx_client_kwargs: Additional kwargs for httpx client
        """
        super().__init__(
            issuer_url=issuer_url or upstream_issuer_url,
            service_documentation_url=service_documentation_url,
            client_registration_options=client_registration_options,
            revocation_options=revocation_options,
            required_scopes=required_scopes,
        )
        
        if isinstance(upstream_issuer_url, str):
            upstream_issuer_url = AnyHttpUrl(upstream_issuer_url)
            
        self.upstream_issuer_url = upstream_issuer_url
        self.upstream_jwks_uri = str(upstream_jwks_uri).rstrip("/") if upstream_jwks_uri else None
        self.proxy_client_id = proxy_client_id
        self.proxy_client_secret = proxy_client_secret
        self.default_scopes = default_scopes or ["read", "write"]
        self.allowed_redirect_uris = allowed_redirect_uris
        self.audience = audience
        self.httpx_client_kwargs = httpx_client_kwargs or {}
        
        # Storage for registered clients (DCR proxy)
        self.registered_clients: Dict[str, OAuthClientInformationFull] = {}
        
        # JWT validation setup (like BearerAuthProvider)
        self.jwks_cache: Dict[str, Any] = {}
        self.jwks_cache_expiry: float = 0
        
        logger.info(f"OAuth Passthrough Provider initialized for upstream: {self.upstream_issuer_url}")
        logger.info(f"Token validation via JWKS: {self.upstream_jwks_uri}")
        
        # Pre-register the proxy client
        self._pre_register_proxy_client()

    def _pre_register_proxy_client(self) -> None:
        """Pre-register the proxy client on startup."""
        from pydantic import AnyUrl
        
        # Prepare redirect URIs for pre-registration
        redirect_uris = []
        if self.allowed_redirect_uris:
            for uri_str in self.allowed_redirect_uris:
                try:
                    redirect_uris.append(AnyUrl(uri_str))
                except Exception:
                    logger.warning(f"Could not parse redirect URI: {uri_str}, using placeholder")
                    redirect_uris.append(AnyUrl("http://localhost/placeholder"))
        else:
            redirect_uris = [AnyUrl("http://localhost/placeholder")]
        
        proxy_client = OAuthClientInformationFull(
            client_id=self.proxy_client_id,
            client_secret=self.proxy_client_secret,
            redirect_uris=redirect_uris,
            client_name="OAuth Passthrough Client (Pre-registered)",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=" ".join(self.default_scopes or []),
            token_endpoint_auth_method="client_secret_post",
        )
        
        if self.allowed_redirect_uris:
            setattr(proxy_client, '_original_redirect_uris', self.allowed_redirect_uris.copy())
        
        self.registered_clients[self.proxy_client_id] = proxy_client
        
        logger.info(f"Pre-registered passthrough client with ID: {self.proxy_client_id}")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get client information by client ID."""
        return self.registered_clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
        """
        Register a client by returning pre-configured proxy credentials.
        
        This is the DCR proxy functionality - instead of forwarding to upstream,
        we return our pre-configured client credentials.
        """
        logger.info(f"Passthrough DCR: Returning pre-configured credentials for client: {client_info.client_name}")
        
        # Extract redirect URIs and validate
        redirect_uri_strings = [str(uri) for uri in client_info.redirect_uris]
        
        if self.allowed_redirect_uris:
            for redirect_uri_str in redirect_uri_strings:
                if redirect_uri_str not in self.allowed_redirect_uris:
                    raise ValueError(f"Redirect URI not allowed: {redirect_uri_str}")
        
        # Convert redirect URIs, handling custom schemes
        from pydantic import AnyUrl
        processed_redirect_uris = []
        for uri_str in redirect_uri_strings:
            try:
                processed_redirect_uris.append(AnyUrl(uri_str))
            except Exception:
                logger.warning(f"Custom redirect URI scheme detected: {uri_str}")
                processed_redirect_uris.append(AnyUrl("http://localhost/placeholder"))
        
        # Create the proxy client information
        proxy_client = OAuthClientInformationFull(
            client_id=self.proxy_client_id,
            client_secret=self.proxy_client_secret,
            redirect_uris=processed_redirect_uris,
            client_name=client_info.client_name or "OAuth Passthrough Client",
            grant_types=client_info.grant_types or ["authorization_code", "refresh_token"],
            response_types=client_info.response_types or ["code"],
            scope=" ".join(client_info.scope.split() if client_info.scope else self.default_scopes),
            token_endpoint_auth_method=client_info.token_endpoint_auth_method or "client_secret_post",
        )
        
        # Store original redirect URIs
        setattr(proxy_client, '_original_redirect_uris', redirect_uri_strings)
        
        # Store the client
        self.registered_clients[self.proxy_client_id] = proxy_client
        
        logger.info(f"Passthrough DCR complete: Client ID = {self.proxy_client_id}")
        logger.info(f"Original redirect URIs: {redirect_uri_strings}")
        
        return proxy_client

    async def _fetch_jwks(self) -> Dict[str, Any]:
        """Fetch JWKS from upstream server for JWT validation."""
        current_time = time.time()
        
        # Check cache first (cache for 1 hour)
        if current_time < self.jwks_cache_expiry and self.jwks_cache:
            return self.jwks_cache
        
        try:
            jwks_url = self.upstream_jwks_uri
            if not jwks_url:
                # Try to discover JWKS URL from metadata
                metadata_url = f"{str(self.upstream_issuer_url).rstrip('/')}/.well-known/openid-configuration"
                async with httpx.AsyncClient(**self.httpx_client_kwargs) as client:
                    response = await client.get(metadata_url)
                    if response.status_code == 200:
                        metadata = response.json()
                        jwks_url = metadata.get("jwks_uri")
                    
            if not jwks_url:
                raise ValueError("No JWKS URI available for token validation")
                
            logger.info(f"Fetching JWKS from: {jwks_url}")
            
            async with httpx.AsyncClient(**self.httpx_client_kwargs) as client:
                response = await client.get(jwks_url)
                if response.status_code != 200:
                    raise ValueError(f"Failed to fetch JWKS: HTTP {response.status_code}")
                
                jwks_data = response.json()
                
                # Cache for 1 hour
                self.jwks_cache = jwks_data
                self.jwks_cache_expiry = current_time + 3600
                
                logger.info(f"✅ Successfully fetched JWKS with {len(jwks_data.get('keys', []))} keys")
                return jwks_data
                
        except Exception as e:
            logger.error(f"❌ Failed to fetch JWKS: {e}")
            raise

    async def verify_token(self, token: str) -> dict[str, Any] | None:
        logger.info(f"🔍 Token Verification Request: {token[:20]}...{token[-10:]}")
        logger.info(f"   Token length: {len(token)} characters")
        """
        Verify JWT token using upstream JWKS (like BearerAuthProvider).
        
        This is the key difference from OAuthProxyProvider - we validate
        real JWT tokens from the upstream server instead of our own tokens.
        """
        try:
            # Fetch JWKS for validation
            jwks_data = await self._fetch_jwks()
            
            # Decode JWT header to get key ID
            unverified_header = jwt.get_unverified_header(token)
            kid = unverified_header.get("kid")
            
            # Find the appropriate key
            signing_key = None
            for key in jwks_data.get("keys", []):
                if kid and key.get("kid") == kid:
                    signing_key = key
                    break
                elif not kid and key.get("kty") == "RSA" and key.get("use") == "sig":
                    # Fallback to first RSA signing key if no kid
                    signing_key = key
                    break
            
            if not signing_key:
                logger.error(f"❌ No suitable signing key found (kid: {kid})")
                return None
            
            # Verify the JWT signature and decode claims using the JWK directly
            claims = jwt.decode(
                token,
                signing_key,  # Use the JWK directly
                algorithms=["RS256"],
                audience=self.audience,
                options={"verify_exp": True, "verify_aud": True if self.audience else False}
            )
            
            logger.info(f"✅ JWT validation successful")
            logger.info(f"   Client ID: {claims.get('client_id', 'N/A')}")
            logger.info(f"   Scopes: {claims.get('scope', claims.get('scopes', 'N/A'))}")
            logger.info(f"   User ID: {claims.get('userid', 'N/A')}")
            logger.info(f"   Expires: {claims.get('exp', 'N/A')}")
            
            # Validate required scopes
            token_scopes = []
            if "scope" in claims:
                if isinstance(claims["scope"], str):
                    token_scopes = claims["scope"].split()
                elif isinstance(claims["scope"], list):
                    token_scopes = claims["scope"]
            elif "scopes" in claims:
                if isinstance(claims["scopes"], list):
                    token_scopes = claims["scopes"]
            
            if self.required_scopes:
                for required_scope in self.required_scopes:
                    if required_scope not in token_scopes:
                        logger.error(f"❌ Required scope '{required_scope}' not found in token scopes: {token_scopes}")
                        return None
            
            logger.info(f"✅ Scope validation passed: {token_scopes}")
            
            return claims
            
        except jwt.ExpiredSignatureError:
            logger.error("❌ JWT token has expired")
            return None
        except jwt.InvalidAudienceError:
            logger.error(f"❌ JWT audience validation failed (expected: {self.audience})")
            return None
        except jwt.InvalidSignatureError:
            logger.error("❌ JWT signature validation failed")
            return None
        except Exception as e:
            logger.error(f"❌ JWT validation error: {e}")
            return None

    def create_passthrough_auth_routes(
        self,
        issuer_url: AnyHttpUrl,
        service_documentation_url: AnyHttpUrl | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None,
    ) -> list:
        """
        Create OAuth passthrough routes that proxy metadata, DCR, and authorization.
        
        This creates the transparent proxy behavior similar to fastapi_mcp's setup_proxies=True:
        - Proxies OAuth metadata with endpoint overrides
        - Proxies DCR to return pre-configured credentials
        - Proxies authorization to redirect to correct upstream endpoint  
        - Does NOT create /token route - clients hit upstream directly
        """
        from starlette.routing import Route
        from starlette.responses import JSONResponse, RedirectResponse
        from starlette.requests import Request
        import json
        
        routes = []
        
        # 1. OAuth Authorization Server Metadata (RFC 8414)
        async def oauth_metadata_endpoint(request: Request):
            logger.info(f"🔵 OAuth Metadata Request: {request.method} {request.url.path}")
            logger.info(f"   Client: {request.headers.get('user-agent', 'Unknown')}")
            logger.info(f"   Headers: {dict(request.headers)}")
            """Proxy OAuth metadata with endpoint overrides."""
            try:
                base_url = str(request.base_url).rstrip("/")
                
                # Fetch upstream metadata
                metadata_url = f"{str(self.upstream_issuer_url).rstrip('/')}/.well-known/openid-configuration"
                async with httpx.AsyncClient(**self.httpx_client_kwargs) as client:
                    response = await client.get(metadata_url)
                    if response.status_code != 200:
                        logger.error(f"Failed to fetch upstream metadata: {response.status_code}")
                        return JSONResponse(
                            content={"error": "upstream_metadata_unavailable"}, 
                            status_code=502
                        )
                    
                    oauth_metadata = response.json()
                    
                    # Override endpoints to point to our proxies (key fastapi_mcp behavior)
                    oauth_metadata["authorization_endpoint"] = f"{base_url}/oauth/authorize"
                    oauth_metadata["registration_endpoint"] = f"{base_url}/oauth/register"
                    # Note: token_endpoint stays pointing to upstream - this is the key difference!
                    
                    logger.info(f"✅ Proxied OAuth metadata:")
                    logger.info(f"   Authorization: {oauth_metadata['authorization_endpoint']} (proxied)")
                    logger.info(f"   Registration: {oauth_metadata['registration_endpoint']} (proxied)")
                    logger.info(f"   Token: {oauth_metadata.get('token_endpoint')} (upstream direct)")
                    
                    return JSONResponse(content=oauth_metadata)
                    
            except Exception as e:
                logger.error(f"OAuth metadata proxy error: {e}")
                return JSONResponse(
                    content={"error": "metadata_proxy_failed", "description": str(e)},
                    status_code=500
                )
        
        routes.append(Route("/.well-known/oauth-authorization-server", oauth_metadata_endpoint, methods=["GET"]))
        
        # 2. Dynamic Client Registration endpoint (proxy)
        async def dcr_proxy_endpoint(request: Request):
            logger.info(f"🔵 DCR Request: {request.method} {request.url.path}")
            logger.info(f"   Client: {request.headers.get('user-agent', 'Unknown')}")
            body = await request.body()
            if body:
                logger.info(f"   Body: {body.decode() if len(body) < 500 else f'<{len(body)} bytes>'}")
            """Proxy DCR to return pre-configured credentials."""
            try:
                client_data = await request.json()
                
                # Add temporary values for validation
                if "client_id" not in client_data:
                    client_data["client_id"] = "temp_client_id"
                if "client_secret" not in client_data:
                    client_data["client_secret"] = "temp_client_secret"
                
                from mcp.shared.auth import OAuthClientInformationFull
                client_info = OAuthClientInformationFull.model_validate(client_data)
                
                # Call our passthrough DCR method
                registered_client = await self.register_client(client_info)
                
                # Return the proxy client information
                response_data = registered_client.model_dump(mode="json", exclude={"_original_redirect_uris"})
                
                return JSONResponse(content=response_data, status_code=201)
                
            except Exception as e:
                logger.error(f"DCR proxy error: {e}")
                return JSONResponse(
                    content={
                        "error": "invalid_client_metadata",
                        "error_description": str(e)
                    },
                    status_code=400
                )
        
        routes.append(Route("/oauth/register", dcr_proxy_endpoint, methods=["POST"]))
        
        # 3. Authorization endpoint (proxy/redirect)
        async def authorization_proxy_endpoint(request: Request):
            logger.info(f"🔵 Authorization Request: {request.method} {request.url.path}")
            logger.info(f"   Client: {request.headers.get('user-agent', 'Unknown')}")
            logger.info(f"   Query params: {dict(request.query_params)}")
            """Proxy authorization requests to correct upstream endpoint."""
            try:
                # Extract query parameters
                query_params = dict(request.query_params)
                
                # Use proxy client ID if not provided or different
                if "client_id" not in query_params or query_params["client_id"] != self.proxy_client_id:
                    query_params["client_id"] = self.proxy_client_id
                
                # Add default scopes if not provided
                if "scope" not in query_params:
                    query_params["scope"] = " ".join(self.default_scopes)
                
                # Add audience if required and not provided
                if self.audience and "audience" not in query_params:
                    query_params["audience"] = self.audience
                
                # Build authorization URL with correct upstream endpoint
                from urllib.parse import urlencode
                upstream_auth_url = f"{str(self.upstream_issuer_url).rstrip('/')}/authentication/v2/authorize"
                auth_url = f"{upstream_auth_url}?{urlencode(query_params)}"
                
                logger.info(f"🔗 Authorization proxy redirect:")
                logger.info(f"   Client ID: {query_params.get('client_id')}")
                logger.info(f"   Redirect URI: {query_params.get('redirect_uri')}")
                logger.info(f"   Scope: {query_params.get('scope')}")
                logger.info(f"   ✅ Redirecting to: {auth_url}")
                
                return RedirectResponse(url=auth_url)
                
            except Exception as e:
                logger.error(f"Authorization proxy error: {e}")
                return JSONResponse(
                    content={
                        "error": "invalid_request",
                        "error_description": str(e)
                    },
                    status_code=400
                )
        
        routes.append(Route("/oauth/authorize", authorization_proxy_endpoint, methods=["GET"]))
        
        # 4. Protected Resource Metadata (RFC 8707)
        async def protected_resource_metadata_endpoint(request: Request):
            """OAuth 2.0 Resource Server Metadata endpoint."""
            base_url = str(request.base_url).rstrip("/")
            
            metadata = {
                "resource": str(self.issuer_url),
                "authorization_servers": [str(self.issuer_url)],
                "bearer_methods_supported": ["header"],
                "scopes_supported": self.default_scopes,
            }
            
            if self.service_documentation_url:
                metadata["service_documentation"] = str(self.service_documentation_url)
            
            return JSONResponse(content=metadata)
        
        routes.append(Route("/.well-known/oauth-protected-resource", protected_resource_metadata_endpoint, methods=["GET"]))

        # 5. OAuth Authorization Redirect for MCP endpoints (Cursor-specific fix)
        async def oauth_redirect_for_mcp(request: Request):
            """
            Custom MCP endpoint that redirects to OAuth authorization instead of returning 401.
            This is specifically for Cursor which doesn't properly handle WWW-Authenticate challenges.
            """
            logger.info(f"🔄 MCP OAuth Redirect Request: {request.method} {request.url.path}")
            logger.info(f"   Client: {request.headers.get('user-agent', 'Unknown')}")
            
            # Check if there's already an Authorization header
            auth_header = request.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                logger.info("   Found existing Bearer token - letting normal MCP flow handle it")
                # Let this fall through to normal MCP handling (which will validate the token)
                # We'll return a 404 here so it falls through to the actual MCP endpoint
                from starlette.responses import Response
                return Response(status_code=404)
            
            # No authentication - redirect to OAuth flow
            logger.info("   No authentication found - redirecting to OAuth authorization")
            
            # Generate OAuth authorization URL
            from urllib.parse import urlencode, quote
            
            # Use the pre-registered client ID for this redirect
            client_id = self.proxy_client_id
            
            # Generate state and PKCE for security (in real implementation, these should be stored)
            import secrets
            import base64
            import hashlib
            
            state = secrets.token_urlsafe(32)
            code_verifier = secrets.token_urlsafe(32)
            code_challenge = base64.urlsafe_b64encode(
                hashlib.sha256(code_verifier.encode()).digest()
            ).decode().rstrip("=")
            
            # Build redirect URI - use a special callback for MCP
            base_url = str(request.base_url).rstrip("/")
            redirect_uri = f"{base_url}/oauth/mcp-callback"
            
            # OAuth authorization parameters
            auth_params = {
                "response_type": "code",
                "client_id": client_id,
                "redirect_uri": redirect_uri,
                "scope": " ".join(self.default_scopes),
                "state": state,
                "code_challenge": code_challenge,
                "code_challenge_method": "S256",
            }
            
            if self.audience:
                auth_params["audience"] = self.audience
            
            # Build authorization URL
            upstream_auth_url = f"{str(self.upstream_issuer_url).rstrip('/')}/authentication/v2/authorize"
            auth_url = f"{upstream_auth_url}?{urlencode(auth_params)}"
            
            logger.info(f"   🚀 Redirecting to: {auth_url}")
            logger.info(f"   State: {state}")
            logger.info(f"   Code challenge: {code_challenge}")
            
            return RedirectResponse(url=auth_url, status_code=301)
        
        # Add the OAuth redirect for various MCP paths that Cursor might try
        routes.append(Route("/mcp", oauth_redirect_for_mcp, methods=["GET", "POST"]))
        routes.append(Route("/mcp/", oauth_redirect_for_mcp, methods=["GET", "POST"]))
        
        # 6. OAuth callback handler for MCP
        async def oauth_mcp_callback(request: Request):
            """Handle OAuth callback and redirect back to MCP with token."""
            logger.info(f"🔵 OAuth MCP Callback: {request.url}")
            
            # Extract authorization code and state
            query_params = dict(request.query_params)
            code = query_params.get("code")
            state = query_params.get("state")
            
            if not code:
                error = query_params.get("error", "unknown_error")
                error_description = query_params.get("error_description", "No authorization code received")
                logger.error(f"OAuth callback error: {error} - {error_description}")
                return JSONResponse(
                    content={"error": error, "error_description": error_description},
                    status_code=400
                )
            
            logger.info(f"   Authorization code received: {code[:10]}...")
            logger.info(f"   State: {state}")
            
            # In a real implementation, you would:
            # 1. Exchange the code for a token with the upstream server
            # 2. Store the token securely
            # 3. Redirect the user back to Cursor with instructions
            
            # For now, return a success page with instructions
            html_response = f"""
            <!DOCTYPE html>
            <html>
            <head>
                <title>OAuth Authorization Complete</title>
            </head>
            <body>
                <h1>✅ Authorization Successful!</h1>
                <p>You have successfully authorized access to your Autodesk account.</p>
                <p><strong>Authorization Code:</strong> {code[:10]}...</p>
                <p><strong>Next Steps:</strong></p>
                <ol>
                    <li>The authorization code has been captured</li>
                    <li>Close this browser window</li>
                    <li>Return to Cursor - the MCP connection should now work</li>
                </ol>
                <p><em>Note: In a production system, this would automatically exchange the code for tokens and complete the flow.</em></p>
            </body>
            </html>
            """
            
            from starlette.responses import HTMLResponse
            return HTMLResponse(content=html_response)
        
        routes.append(Route("/oauth/mcp-callback", oauth_mcp_callback, methods=["GET"]))
        
        logger.info(f"✅ Created OAuth passthrough routes:")
        logger.info(f"   /.well-known/oauth-authorization-server (metadata proxy)")
        logger.info(f"   /oauth/register (DCR proxy)")
        logger.info(f"   /oauth/authorize (authorization proxy)")
        logger.info(f"   /.well-known/oauth-protected-resource (resource metadata)")
        logger.info(f"   /mcp, /mcp/ (OAuth redirect for unauthenticated MCP requests)")
        logger.info(f"   /oauth/mcp-callback (OAuth callback handler)")
        logger.info(f"   🚫 NO /token route - clients hit upstream directly!")
        
        return routes

    # --- Abstract method implementations ---
    # These methods are required by OAuthProvider but not used in passthrough mode
    # since we redirect authorization to upstream and don't handle tokens locally

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Not used in passthrough mode - authorization is handled by upstream server.
        This should never be called since we proxy authorization requests directly.
        """
        raise NotImplementedError(
            "Authorization is handled by upstream server in passthrough mode"
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """
        Not used in passthrough mode - tokens come directly from upstream.
        """
        raise NotImplementedError(
            "Authorization codes are handled by upstream server in passthrough mode"
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """
        Not used in passthrough mode - token exchange happens with upstream.
        """
        raise NotImplementedError(
            "Token exchange is handled by upstream server in passthrough mode"
        )

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """
        Not used in passthrough mode - refresh tokens are handled by upstream.
        """
        raise NotImplementedError(
            "Refresh tokens are handled by upstream server in passthrough mode"
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """
        Not used in passthrough mode - refresh token exchange happens with upstream.
        """
        raise NotImplementedError(
            "Refresh token exchange is handled by upstream server in passthrough mode"
        )

    async def load_access_token(self, token: str) -> AccessToken | None:
        """
        Load and validate an access token using JWT verification.
        
        This is the main token validation method used in passthrough mode.
        It validates real JWT tokens from the upstream server.
        """
        try:
            # Use verify_token which implements JWT validation
            claims = await self.verify_token(token)
            if not claims:
                return None
            
            # Convert claims dict to AccessToken object
            return AccessToken(
                token=token,
                client_id=claims.get("client_id", "unknown"),
                scopes=claims.get("scope", "").split() if claims.get("scope") else [],
                expires_at=claims.get("exp"),
            )
            
        except Exception as e:
            logger.error(f"Failed to load access token: {e}")
            return None

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """
        Not used in passthrough mode - token revocation is handled by upstream.
        """
        logger.info("Token revocation not implemented in passthrough mode - tokens managed by upstream")
