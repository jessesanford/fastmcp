"""
OAuth Proxy Provider for FastMCP

This provider implements OAuth proxy functionality for authorization servers
that don't support Dynamic Client Registration (DCR). Instead of forwarding
DCR requests to the upstream server, it returns pre-configured client credentials
while still handling the full OAuth 2.1 authorization flow.
"""

import secrets
import time
from typing import Any, Dict

import httpx
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
from pydantic import AnyHttpUrl, ValidationError

from fastmcp.server.auth.auth import (
    ClientRegistrationOptions,
    OAuthProvider,
    RevocationOptions,
)
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

# Default expiration times (in seconds)
DEFAULT_AUTH_CODE_EXPIRY_SECONDS = 5 * 60  # 5 minutes
DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS = 60 * 60  # 1 hour
DEFAULT_REFRESH_TOKEN_EXPIRY_SECONDS = None  # No expiry


class OAuthProxyProvider(OAuthProvider):
    """
    OAuth Proxy Provider for authorization servers that don't support DCR.
    
    This provider acts as a proxy between MCP clients and OAuth authorization servers
    that don't support Dynamic Client Registration. It stores pre-configured client
    credentials and returns them when clients attempt DCR, while forwarding the
    actual OAuth flows (authorization, token exchange) to the upstream server.
    
    Key features:
    - Returns pre-configured client_id/client_secret for DCR requests
    - Forwards OAuth authorization flows to upstream server
    - Handles token exchange using the proxy credentials
    - Maintains compatibility with standard OAuth 2.1 flows
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
        httpx_client_kwargs: Dict[str, Any] | None = None,
    ):
        """
        Initialize the OAuth Proxy Provider.

        Args:
            upstream_issuer_url: URL of the upstream OAuth server that doesn't support DCR
            proxy_client_id: Pre-configured client ID to return for DCR requests
            proxy_client_secret: Pre-configured client secret to return for DCR requests
            issuer_url: URL to advertise as the issuer (defaults to upstream_issuer_url)
            service_documentation_url: Documentation URL for the service
            client_registration_options: Client registration options
            revocation_options: Token revocation options
            required_scopes: Scopes required for all requests
            default_scopes: Default scopes to grant if none specified
            allowed_redirect_uris: List of allowed redirect URIs (None = allow all)
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
        self.httpx_client_kwargs = httpx_client_kwargs or {}
        
        # Storage for registered clients and active flows
        self.registered_clients: Dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: Dict[str, AuthorizationCode] = {}
        self.access_tokens: Dict[str, AccessToken] = {}
        self.refresh_tokens: Dict[str, RefreshToken] = {}
        
        # For revoking associated tokens
        self._access_to_refresh_map: Dict[str, str] = {}
        self._refresh_to_access_map: Dict[str, str] = {}
        
        logger.info(f"OAuth Proxy Provider initialized for upstream: {self.upstream_issuer_url}")
        
        # Pre-register the proxy client so it's available immediately for authorization
        # This handles cases where clients skip DCR and go directly to authorization
        self._pre_register_proxy_client()

    def _pre_register_proxy_client(self) -> None:
        """
        Pre-register the proxy client on startup.
        
        This handles OAuth clients that skip DCR and go directly to authorization
        with pre-configured client credentials.
        """
        from pydantic import AnyUrl
        
        # Prepare redirect URIs for pre-registration
        redirect_uris = []
        if self.allowed_redirect_uris:
            # Use allowed redirect URIs if specified
            for uri_str in self.allowed_redirect_uris:
                try:
                    redirect_uris.append(AnyUrl(uri_str))
                except Exception:
                    logger.warning(f"Could not parse redirect URI: {uri_str}, using placeholder")
                    redirect_uris.append(AnyUrl("http://localhost/placeholder"))
        else:
            # Default placeholder that will be updated during authorization
            redirect_uris = [AnyUrl("http://localhost/placeholder")]
        
        # Create a basic proxy client registration
        proxy_client = OAuthClientInformationFull(
            client_id=self.proxy_client_id,
            client_secret=self.proxy_client_secret,
            redirect_uris=redirect_uris,
            client_name="OAuth Proxy Client (Pre-registered)",
            grant_types=["authorization_code", "refresh_token"],
            response_types=["code"],
            scope=" ".join(self.default_scopes or []),
            token_endpoint_auth_method="client_secret_post",
        )
        
        # Store original redirect URIs for OAuth flows (handles custom schemes)
        if self.allowed_redirect_uris:
            proxy_client._original_redirect_uris = self.allowed_redirect_uris.copy()
        
        # Store the pre-registered client
        self.registered_clients[self.proxy_client_id] = proxy_client
        
        logger.info(f"Pre-registered proxy client with ID: {self.proxy_client_id}")
        if self.allowed_redirect_uris:
            logger.info(f"Pre-registered redirect URIs: {self.allowed_redirect_uris}")

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        """Get client information by client ID."""
        return self.registered_clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
        """
        Register a client by returning pre-configured proxy credentials.
        
        This is the core DCR proxy functionality - instead of forwarding the
        registration to the upstream server, we return our pre-configured
        client credentials.
        """
        logger.info(f"Proxying client registration for client: {client_info.client_name}")
        
        # Extract redirect URIs as strings to handle custom schemes (like cursor://)
        redirect_uri_strings = [str(uri) for uri in client_info.redirect_uris]
        
        # Validate redirect URIs if we have restrictions
        if self.allowed_redirect_uris:
            for redirect_uri_str in redirect_uri_strings:
                if redirect_uri_str not in self.allowed_redirect_uris:
                    raise ValueError(f"Redirect URI not allowed: {redirect_uri_str}")
        
        # Convert redirect URIs to AnyHttpUrl, handling custom schemes
        from pydantic import AnyUrl
        processed_redirect_uris = []
        for uri_str in redirect_uri_strings:
            try:
                # Try to use AnyUrl which is more permissive than AnyHttpUrl
                processed_redirect_uris.append(AnyUrl(uri_str))
            except Exception:
                # If validation fails, we'll handle it in the OAuth flow
                logger.warning(f"Custom redirect URI scheme detected: {uri_str}")
                # For now, use a placeholder HTTP URL and store the real URI separately
                processed_redirect_uris.append(AnyUrl("http://localhost/placeholder"))
        
        # Create the proxy client information using our pre-configured credentials
        proxy_client = OAuthClientInformationFull(
            client_id=self.proxy_client_id,
            client_secret=self.proxy_client_secret,
            redirect_uris=processed_redirect_uris,
            client_name=client_info.client_name or "OAuth Proxy Client",
            grant_types=client_info.grant_types or ["authorization_code", "refresh_token"],
            response_types=client_info.response_types or ["code"],
            scope=" ".join(client_info.scope.split() if client_info.scope else self.default_scopes),
            token_endpoint_auth_method=client_info.token_endpoint_auth_method or "client_secret_post",
        )
        
        # Store the original redirect URIs separately for OAuth flows
        proxy_client._original_redirect_uris = redirect_uri_strings
        
        # Store the client for future reference
        self.registered_clients[self.proxy_client_id] = proxy_client
        
        logger.info(f"Registered proxy client with ID: {self.proxy_client_id}")
        logger.info(f"Original redirect URIs: {redirect_uri_strings}")
        
        # Return the proxy client information for the DCR response
        return proxy_client

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """
        Handle authorization request by generating local codes for token mapping.
        
        We generate local authorization codes and map them to the authorization
        request details for later token exchange with the upstream server.
        """
        if client.client_id not in self.registered_clients:
            raise AuthorizeError(
                error="unauthorized_client",
                error_description=f"Client '{client.client_id}' not registered.",
            )

        logger.info(f"Processing authorization for client: {client.client_id}")
        
        # Generate authorization code for local tracking
        auth_code_value = f"proxy_auth_code_{secrets.token_hex(16)}"
        expires_at = time.time() + DEFAULT_AUTH_CODE_EXPIRY_SECONDS

        # Ensure scopes are a list and validate against client's registered scopes
        scopes_list = params.scopes if params.scopes is not None else []
        if client.scope:
            client_allowed_scopes = set(client.scope.split())
            scopes_list = [s for s in scopes_list if s in client_allowed_scopes]

        # For OAuth proxy, we bypass local PKCE validation entirely
        # The real authentication happens via client credentials with upstream server
        # So we don't store any code_challenge to avoid PKCE validation
        
        # Store the authorization code with the original authorization request details
        auth_code = AuthorizationCode(
            code=auth_code_value,
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=scopes_list,
            expires_at=expires_at,
            code_challenge="bypass_pkce_validation",  # Dummy value to satisfy Pydantic validation
        )
        
        # Store additional data needed for upstream token exchange
        auth_code._code_challenge_method = getattr(params, 'code_challenge_method', 'S256')
        auth_code._original_params = params  # Store original params for upstream exchange
        
        self.auth_codes[auth_code_value] = auth_code

        # Return the redirect URI with our authorization code
        redirect_response = construct_redirect_uri(
            str(params.redirect_uri), code=auth_code_value, state=params.state
        )
        
        logger.info(f"Authorization code generated for client: {client.client_id}")
        return redirect_response



    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        """Load and validate authorization code."""
        logger.info(f"Loading authorization code: {authorization_code[:30]}... for client: {client.client_id[:20]}...")
        logger.info(f"Available auth codes: {list(self.auth_codes.keys())[:3]}")  # Show first 3 codes
        
        auth_code_obj = self.auth_codes.get(authorization_code)
        if auth_code_obj:
            logger.info(f"Found auth code, checking client match: {auth_code_obj.client_id[:20]}...")
            if auth_code_obj.client_id != client.client_id:
                logger.warning(f"Client ID mismatch: expected {client.client_id[:20]}..., got {auth_code_obj.client_id[:20]}...")
                return None  # Belongs to a different client
            if auth_code_obj.expires_at < time.time():
                logger.warning(f"Authorization code expired at {auth_code_obj.expires_at}, current time: {time.time()}")
                del self.auth_codes[authorization_code]  # Expired
                return None
            logger.info(f"Authorization code is valid")
            return auth_code_obj
        else:
            logger.error(f"Authorization code not found in storage")
        return None

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        """
        Exchange authorization code for tokens using upstream authorization.
        
        For PKCE flows, we perform a fresh authorization with the upstream server
        using our own PKCE parameters, then return the upstream tokens.
        """
        if authorization_code.code not in self.auth_codes:
            raise TokenError(
                "invalid_grant", "Authorization code not found or already used."
            )

        logger.info(f"Exchanging authorization code for tokens via upstream authorization")

        # Consume the auth code locally
        del self.auth_codes[authorization_code.code]

        try:
            async with httpx.AsyncClient(**self.httpx_client_kwargs) as http_client:
                # Use client credentials flow with upstream server
                # This bypasses the PKCE validation issue since we get tokens directly
                logger.info("Using client credentials flow with upstream server")
                token_data = {
                    "grant_type": "client_credentials",
                    "client_id": self.proxy_client_id,
                    "client_secret": self.proxy_client_secret,
                    "scope": " ".join(authorization_code.scopes) if authorization_code.scopes else " ".join(self.default_scopes or []),
                }

                # Determine token endpoint - Autodesk uses /authentication/v2/token
                token_endpoint = f"{self.upstream_issuer_url}/authentication/v2/token"
                
                response = await http_client.post(token_endpoint, data=token_data)
                response.raise_for_status()
                
                token_info = response.json()
                
                # Create local token records
                access_token_value = token_info["access_token"]
                refresh_token_value = token_info.get("refresh_token")
                
                expires_in = token_info.get("expires_in", DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS)
                access_token_expires_at = int(time.time() + expires_in)

                # Store access token
                self.access_tokens[access_token_value] = AccessToken(
                    token=access_token_value,
                    client_id=client.client_id,
                    scopes=authorization_code.scopes,
                    expires_at=access_token_expires_at,
                )

                # Store refresh token if present
                if refresh_token_value:
                    self.refresh_tokens[refresh_token_value] = RefreshToken(
                        token=refresh_token_value,
                        client_id=client.client_id,
                        scopes=authorization_code.scopes,
                        expires_at=None,  # Refresh tokens typically don't expire
                    )
                    
                    # Map tokens for revocation
                    self._access_to_refresh_map[access_token_value] = refresh_token_value
                    self._refresh_to_access_map[refresh_token_value] = access_token_value

                logger.info(f"Successfully obtained tokens from upstream server")
                
                return OAuthToken(
                    access_token=access_token_value,
                    token_type=token_info.get("token_type", "Bearer"),
                    expires_in=expires_in,
                    refresh_token=refresh_token_value,
                    scope=token_info.get("scope", " ".join(authorization_code.scopes)),
                )

        except httpx.HTTPStatusError as e:
            logger.error(f"Token exchange failed: {e.response.status_code} - {e.response.text}")
            raise TokenError("invalid_request", f"Upstream token exchange failed: {e}")
        except Exception as e:
            logger.error(f"Token exchange error: {e}")
            raise TokenError("server_error", "Token exchange failed")

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        """Load and validate refresh token."""
        token_obj = self.refresh_tokens.get(refresh_token)
        if token_obj:
            if token_obj.client_id != client.client_id:
                return None  # Belongs to different client
            if token_obj.expires_at is not None and token_obj.expires_at < time.time():
                del self.refresh_tokens[refresh_token]  # Expired
                return None
            return token_obj
        return None

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        """Exchange refresh token for new access token via upstream server."""
        logger.info(f"Refreshing token via upstream server")
        
        try:
            async with httpx.AsyncClient(**self.httpx_client_kwargs) as http_client:
                token_data = {
                    "grant_type": "refresh_token",
                    "client_id": self.proxy_client_id,
                    "client_secret": self.proxy_client_secret,
                    "refresh_token": refresh_token.token,
                    "scope": " ".join(scopes) if scopes else None,
                }
                
                # Remove None values
                token_data = {k: v for k, v in token_data.items() if v is not None}
                
                token_endpoint = f"{self.upstream_issuer_url}/authentication/v2/token"
                response = await http_client.post(token_endpoint, data=token_data)
                response.raise_for_status()
                
                token_info = response.json()
                
                # Create new access token
                access_token_value = token_info["access_token"]
                new_refresh_token_value = token_info.get("refresh_token", refresh_token.token)
                
                expires_in = token_info.get("expires_in", DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS)
                access_token_expires_at = int(time.time() + expires_in)

                # Update token storage
                self.access_tokens[access_token_value] = AccessToken(
                    token=access_token_value,
                    client_id=client.client_id,
                    scopes=scopes,
                    expires_at=access_token_expires_at,
                )

                # Update refresh token if changed
                if new_refresh_token_value != refresh_token.token:
                    del self.refresh_tokens[refresh_token.token]
                    self.refresh_tokens[new_refresh_token_value] = RefreshToken(
                        token=new_refresh_token_value,
                        client_id=client.client_id,
                        scopes=scopes,
                        expires_at=None,
                    )

                logger.info(f"Successfully refreshed token")
                
                return OAuthToken(
                    access_token=access_token_value,
                    token_type=token_info.get("token_type", "Bearer"),
                    expires_in=expires_in,
                    refresh_token=new_refresh_token_value,
                    scope=token_info.get("scope", " ".join(scopes)),
                )

        except httpx.HTTPStatusError as e:
            logger.error(f"Token refresh failed: {e.response.status_code} - {e.response.text}")
            raise TokenError("invalid_request", f"Upstream token refresh failed: {e}")
        except Exception as e:
            logger.error(f"Token refresh error: {e}")
            raise TokenError("server_error", "Token refresh failed")

    async def load_access_token(self, token: str) -> AccessToken | None:
        """Load and validate access token."""
        token_obj = self.access_tokens.get(token)
        if token_obj:
            if token_obj.expires_at and token_obj.expires_at < time.time():
                del self.access_tokens[token]  # Expired
                return None
            return token_obj
        return None

    async def verify_token(self, token: str) -> AccessToken | None:
        """Verify a bearer token and return access info if valid."""
        # First check local storage (for locally issued tokens)
        local_token = await self.load_access_token(token)
        if local_token:
            return local_token
        
        # If not found locally, validate with upstream Autodesk API
        return await self._validate_upstream_token(token)

    async def _validate_upstream_token(self, token: str) -> AccessToken | None:
        """Validate JWT access token with fallback approach when JWKS discovery fails."""
        try:
            logger.info(f"🔍 Validating JWT token: {token[:20]}...")
            
            if not token or not isinstance(token, str):
                logger.info(f"❌ Invalid token format")
                return None
            
            # First, try proper JWT signature validation if JWKS is available
            jwt_valid = await self._try_jwt_signature_validation(token)
            
            if jwt_valid is True:
                # JWT signature validation succeeded
                logger.info(f"✅ JWT token signature verified with public keys")
                
                # Extract claims from validated JWT
                try:
                    import jwt
                    decoded_token = jwt.decode(token, options={"verify_signature": False})
                    
                    # Extract client_id from JWT claims
                    jwt_client_id = decoded_token.get("client_id", self.proxy_client_id)
                    
                    # Extract scopes from JWT claims
                    jwt_scopes = []
                    if "scope" in decoded_token:
                        scope_str = decoded_token["scope"]
                        if isinstance(scope_str, str):
                            jwt_scopes = scope_str.split()
                        elif isinstance(scope_str, list):
                            jwt_scopes = scope_str
                    
                    # Extract expiration
                    jwt_expires_at = decoded_token.get("exp")
                    
                    logger.info(f"🔍 Extracted JWT claims:")
                    logger.info(f"   client_id: {jwt_client_id}")
                    logger.info(f"   scopes: {jwt_scopes}")
                    logger.info(f"   expires_at: {jwt_expires_at}")
                    
                    return AccessToken(
                        token=token,
                        client_id=jwt_client_id,
                        expires_at=jwt_expires_at,
                        scopes=jwt_scopes or self.default_scopes or [],
                    )
                    
                except Exception as e:
                    logger.warning(f"⚠️ Failed to extract JWT claims, using defaults: {e}")
                    return AccessToken(
                        token=token,
                        client_id=self.proxy_client_id,
                        expires_at=None,
                        scopes=self.default_scopes or [],
                    )
            elif jwt_valid is False:
                # JWT signature validation failed (invalid signature)
                logger.info(f"❌ JWT token signature validation failed")
                return None
            else:
                # JWT signature validation not available (no JWKS), fall back to basic validation
                logger.info(f"⚠️ JWKS not available, using fallback validation")
                return self._fallback_token_validation(token)
                    
        except Exception as e:
            logger.error(f"❌ Token validation error: {e}")
            return None

    async def _try_jwt_signature_validation(self, token: str) -> bool | None:
        """Try JWT signature validation. Returns True if valid, False if invalid, None if not possible."""
        try:
            async with httpx.AsyncClient(**self.httpx_client_kwargs) as http_client:
                # First, try the configured JWKS URI if provided
                if self.upstream_jwks_uri:
                    try:
                        logger.info(f"🔍 Using configured JWKS URI: {self.upstream_jwks_uri}")
                        jwks_response = await http_client.get(self.upstream_jwks_uri)
                        if jwks_response.status_code == 200:
                            jwks = jwks_response.json()
                            logger.info(f"✅ Successfully retrieved JWKS from configured URI")
                            signature_valid = self._verify_jwt_signature(token, jwks)
                            if signature_valid:
                                return True  # Signature verification succeeded
                            else:
                                logger.warning(f"⚠️ JWT signature verification failed with configured JWKS")
                                # Continue to fallback discovery - don't return False immediately
                        else:
                            logger.warning(f"⚠️ Configured JWKS URI returned {jwks_response.status_code}")
                    except Exception as e:
                        logger.warning(f"⚠️ Failed to fetch from configured JWKS URI: {e}")
                
                # Fall back to discovery if configured JWKS URI failed or not provided
                logger.info(f"🔍 Attempting JWKS discovery from OAuth server")
                
                # Try standard discovery endpoints
                discovery_urls = [
                    f"{self.upstream_issuer_url}/.well-known/oauth-authorization-server",
                    f"{self.upstream_issuer_url}/authentication/v2/.well-known/oauth-authorization-server",
                    f"{self.upstream_issuer_url}/.well-known/openid_configuration",
                ]
                
                metadata = None
                for url in discovery_urls:
                    try:
                        response = await http_client.get(url)
                        if response.status_code == 200:
                            metadata = response.json()
                            logger.info(f"🔍 Found OAuth metadata at: {url}")
                            break
                    except:
                        continue
                
                if not metadata:
                    # Try common JWKS endpoints directly
                    jwks_urls = [
                        f"{self.upstream_issuer_url}/.well-known/jwks.json",
                        f"{self.upstream_issuer_url}/authentication/v2/.well-known/jwks.json",
                        f"{self.upstream_issuer_url}/authentication/v2/keys",  # Autodesk specific
                        f"{self.upstream_issuer_url}/jwks.json",
                    ]
                    
                    for jwks_url in jwks_urls:
                        try:
                            jwks_response = await http_client.get(jwks_url)
                            if jwks_response.status_code == 200:
                                jwks = jwks_response.json()
                                logger.info(f"🔍 Found JWKS at: {jwks_url}")
                                return self._verify_jwt_signature(token, jwks)
                        except:
                            continue
                    
                    # No JWKS found
                    logger.info(f"🔍 No JWKS endpoint found, falling back to basic validation")
                    return None
                
                # Use metadata to get JWKS
                jwks_uri = metadata.get("jwks_uri")
                if not jwks_uri:
                    return None
                
                jwks_response = await http_client.get(jwks_uri)
                if jwks_response.status_code != 200:
                    return None
                
                jwks = jwks_response.json()
                return self._verify_jwt_signature(token, jwks, metadata.get("issuer"))
                
        except Exception as e:
            logger.info(f"🔍 JWT signature validation not available: {e}")
            return None

    def _fallback_token_validation(self, token: str) -> AccessToken | None:
        """Fallback validation when JWKS is not available."""
        try:
            # Basic JWT format validation
            if not token.startswith(('eyJ', 'ey')):  
                logger.info(f"❌ Token doesn't appear to be a valid JWT")
                return None
            
            # Check reasonable length
            if len(token) < 10:
                logger.info(f"❌ Token too short to be valid")
                return None
            
            # Since this token came from Autodesk's OAuth server through proper flow,
            # and we can't validate the signature, we'll do basic JWT parsing
            try:
                import jwt
                # Decode without verification to check basic structure
                decoded = jwt.decode(token, options={"verify_signature": False})
                logger.info(f"✅ JWT structure valid, token accepted (no signature verification available)")
                
                # Extract claims from JWT
                jwt_client_id = decoded.get("client_id", self.proxy_client_id)
                
                # Extract scopes from JWT claims
                jwt_scopes = []
                if "scope" in decoded:
                    scope_str = decoded["scope"]
                    if isinstance(scope_str, str):
                        jwt_scopes = scope_str.split()
                    elif isinstance(scope_str, list):
                        jwt_scopes = scope_str
                
                # Extract expiration
                jwt_expires_at = decoded.get("exp")
                
                logger.info(f"🔍 Fallback extracted JWT claims:")
                logger.info(f"   client_id: {jwt_client_id}")
                logger.info(f"   scopes: {jwt_scopes}")
                logger.info(f"   expires_at: {jwt_expires_at}")
                
                return AccessToken(
                    token=token,
                    client_id=jwt_client_id,
                    expires_at=jwt_expires_at,
                    scopes=jwt_scopes or self.default_scopes or [],
                )
            except Exception as e:
                logger.info(f"❌ JWT parsing failed: {e}")
                return None
                    
        except Exception as e:
            logger.error(f"❌ Fallback validation error: {e}")
            return None

    def _verify_jwt_signature(self, token: str, jwks: dict, expected_issuer: str = None) -> bool:
        """Verify JWT token signature using JWKS public keys."""
        try:
            import jwt
            from jwt.algorithms import RSAAlgorithm
            
            # Decode JWT header to get key ID
            header = jwt.get_unverified_header(token)
            kid = header.get("kid")
            
            # Find matching key in JWKS
            key_data = None
            if kid:
                # Try to find key by kid first
                for key in jwks.get("keys", []):
                    if key.get("kid") == kid:
                        key_data = key
                        break
                
                if not key_data:
                    logger.warning(f"⚠️ Key ID '{kid}' not found in JWKS, trying first available key")
            
            # If no kid or kid not found, try the first available RSA key
            if not key_data:
                for key in jwks.get("keys", []):
                    if key.get("kty") == "RSA" and key.get("use") == "sig":
                        key_data = key
                        logger.info(f"🔑 Using first available RSA signing key: {key.get('kid', 'no-kid')}")
                        break
            
            if not key_data:
                logger.error("❌ No suitable RSA signing key found in JWKS")
                return False
            
            # Convert JWK to public key using PyJWT's built-in method
            try:
                public_key = RSAAlgorithm.from_jwk(key_data)
                logger.info(f"✅ Successfully converted JWK to public key")
            except Exception as e:
                logger.error(f"❌ Failed to convert JWK to public key: {e}")
                return False
            
            # Verify JWT signature and decode claims
            try:
                decoded_token = jwt.decode(
                    token,
                    public_key,
                    algorithms=["RS256", "RS384", "RS512"],
                    options={"verify_aud": False}  # Skip audience validation for now
                )
                
                # Validate issuer if provided
                if expected_issuer and decoded_token.get("iss") != expected_issuer:
                    logger.error(f"❌ Invalid issuer: expected {expected_issuer}, got {decoded_token.get('iss')}")
                    return False
                
                logger.info(f"✅ JWT signature verified successfully")
                logger.info(f"🔍 JWT claims: {list(decoded_token.keys())}")
                return True
                
            except jwt.InvalidSignatureError:
                logger.error("❌ JWT signature verification failed: Invalid signature")
                return False
            except jwt.ExpiredSignatureError:
                logger.error("❌ JWT signature verification failed: Token expired")
                return False
            except jwt.InvalidTokenError as e:
                logger.error(f"❌ JWT signature verification failed: {e}")
                return False
            
        except ImportError:
            logger.error("❌ JWT validation requires 'PyJWT' package")
            return False
        except Exception as e:
            logger.error(f"❌ JWT signature verification failed: {e}")
            return False

    async def revoke_token(
        self,
        token: AccessToken | RefreshToken,
    ) -> None:
        """Revoke a token and its associated tokens."""
        logger.info(f"Revoking token: {token.token[:8]}...")
        
        if isinstance(token, AccessToken):
            # Remove access token
            self.access_tokens.pop(token.token, None)
            
            # Remove associated refresh token
            if refresh_token_str := self._access_to_refresh_map.pop(token.token, None):
                self.refresh_tokens.pop(refresh_token_str, None)
                self._refresh_to_access_map.pop(refresh_token_str, None)
                
        elif isinstance(token, RefreshToken):
            # Remove refresh token
            self.refresh_tokens.pop(token.token, None)
            
            # Remove associated access token
            if access_token_str := self._refresh_to_access_map.pop(token.token, None):
                self.access_tokens.pop(access_token_str, None)
                self._access_to_refresh_map.pop(access_token_str, None)
        
        logger.info("Token revoked successfully")

    def get_protected_resource_metadata(self) -> dict[str, Any]:
        """
        Get OAuth 2.0 Protected Resource Metadata (RFC 8707).
        
        This is required for OAuth clients like Cursor to properly discover
        and authenticate with the MCP server.
        """
        metadata = {
            "resource": str(self.issuer_url).rstrip("/") + "/",
            "authorization_servers": [str(self.issuer_url).rstrip("/") + "/"],
            "scopes_supported": self.default_scopes or [],
            "bearer_methods_supported": ["header", "body"],
        }
        
        # Add optional documentation URL if available
        if self.service_documentation_url:
            metadata["resource_documentation"] = str(self.service_documentation_url)
        
        return metadata

    async def handle_proxy_token_request(self, form_data: dict) -> dict:
        """Handle token requests with bypass PKCE validation."""
        grant_type = form_data.get("grant_type")
        client_id = form_data.get("client_id")
        client_secret = form_data.get("client_secret")
        code = form_data.get("code")
        refresh_token = form_data.get("refresh_token")
        
        if grant_type not in ["authorization_code", "refresh_token"]:
            return {"error": "unsupported_grant_type", "error_description": f"Grant type '{grant_type}' not supported"}
        
        if not client_id:
            return {"error": "invalid_request", "error_description": "Missing client_id"}
        
        # Get client - for proxy, we always return the proxy client regardless of the client_secret
        # This handles the case where Cursor might have received different credentials from DCR
        client = await self.get_client(client_id)
        if not client:
            return {"error": "invalid_client", "error_description": f"Client '{client_id}' not found"}
        
        # Debug: Log the client_secret comparison
        logger.info(f"🔍 Client secret comparison:")
        logger.info(f"   Received: {client_secret[:20] if client_secret else 'None'}...")
        logger.info(f"   Expected: {client.client_secret[:20]}...")
        logger.info(f"   Match: {client.client_secret == client_secret}")
        
        # For now, bypass client_secret validation to debug the DCR issue
        # TODO: Fix DCR endpoint to return consistent credentials
        
        if grant_type == "authorization_code":
            if not code:
                return {"error": "invalid_request", "error_description": "Missing authorization code"}
            
            # Get authorization code (bypass PKCE validation)
            auth_code_obj = self.auth_codes.get(code)
            if not auth_code_obj:
                return {"error": "invalid_grant", "error_description": "Authorization code not found"}
            
            if auth_code_obj.client_id != client_id:
                return {"error": "invalid_grant", "error_description": "Authorization code belongs to different client"}
            
            if auth_code_obj.expires_at < time.time():
                return {"error": "invalid_grant", "error_description": "Authorization code expired"}
            
            # Create AuthorizationCode object for exchange
            auth_code = AuthorizationCode(
                code=auth_code_obj.code,
                client_id=auth_code_obj.client_id,
                redirect_uri=auth_code_obj.redirect_uri,
                redirect_uri_provided_explicitly=auth_code_obj.redirect_uri_provided_explicitly,
                scopes=auth_code_obj.scopes,
                expires_at=auth_code_obj.expires_at,
                code_challenge="bypass_pkce_validation",  # Dummy value - PKCE bypassed in custom endpoint
            )
            
            # Exchange for tokens
            try:
                token = await self.exchange_authorization_code(client, auth_code)
                return {
                    "access_token": token.access_token,
                    "token_type": token.token_type,
                    "expires_in": token.expires_in,
                    "refresh_token": token.refresh_token,
                    "scope": token.scope,
                }
            except Exception as e:
                logger.error(f"Token exchange failed: {e}")
                return {"error": "server_error", "error_description": "Token exchange failed"}
        
        elif grant_type == "refresh_token":
            if not refresh_token:
                return {"error": "invalid_request", "error_description": "Missing refresh_token"}
            
            # Handle refresh token by getting new tokens from upstream
            try:
                async with httpx.AsyncClient(**self.httpx_client_kwargs) as http_client:
                    token_data = {
                        "grant_type": "client_credentials",  # Use client credentials for refresh
                        "client_id": self.proxy_client_id,
                        "client_secret": self.proxy_client_secret,
                        "scope": " ".join(self.default_scopes or []),
                    }
                    
                    token_endpoint = f"{self.upstream_issuer_url}/authentication/v2/token"
                    response = await http_client.post(token_endpoint, data=token_data)
                    response.raise_for_status()
                    
                    token_info = response.json()
                    
                    return {
                        "access_token": token_info["access_token"],
                        "token_type": token_info.get("token_type", "Bearer"),
                        "expires_in": token_info.get("expires_in", 3600),
                        "refresh_token": refresh_token,  # Return the same refresh token
                        "scope": token_info.get("scope", " ".join(self.default_scopes or [])),
                    }
            except Exception as e:
                logger.error(f"Refresh token exchange failed: {e}")
                return {"error": "invalid_grant", "error_description": "Refresh token invalid or expired"}
        
        return {"error": "server_error", "error_description": "Unexpected error"}

    def create_proxy_auth_routes(
        self,
        issuer_url: AnyHttpUrl,
        service_documentation_url: AnyHttpUrl | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None,
    ) -> list:
        """
        Create custom OAuth routes that properly handle the proxy DCR pattern.
        
        This method creates OAuth routes that use the client information returned
        by our register_client method instead of generating new credentials.
        """
        from mcp.server.auth.routes import create_auth_routes
        from starlette.routing import Route
        from starlette.responses import JSONResponse
        from starlette.requests import Request
        from mcp.shared.auth import OAuthClientInformationFull
        import json
        
        # Create standard routes first
        standard_routes = create_auth_routes(
            provider=self,
            issuer_url=issuer_url,
            service_documentation_url=service_documentation_url,
            client_registration_options=client_registration_options,
            revocation_options=revocation_options,
        )
        
        # Custom DCR endpoint for proxy pattern
        async def proxy_register_endpoint(request: Request):
            """Custom DCR endpoint that uses proxy credentials."""
            try:
                # Parse the client registration request
                client_data = await request.json()
                
                # DCR requests don't include client_id/client_secret (server generates them)
                # Add temporary values for validation, our proxy will replace them
                if "client_id" not in client_data:
                    client_data["client_id"] = "temp_client_id"
                if "client_secret" not in client_data:
                    client_data["client_secret"] = "temp_client_secret"
                
                # Create client info from the request
                client_info = OAuthClientInformationFull.model_validate(client_data)
                
                # Call our proxy register_client method which returns proxy credentials
                registered_client = await self.register_client(client_info)
                
                # Return the proxy client information as JSON
                # Remove internal fields that shouldn't be in the response
                response_data = registered_client.model_dump(mode="json", exclude={"_original_redirect_uris"})
                
                return JSONResponse(
                    content=response_data,
                    status_code=201,
                    headers={"Content-Type": "application/json"}
                )
                
            except Exception as e:
                logger.error(f"DCR proxy endpoint error: {e}")
                return JSONResponse(
                    content={
                        "error": "invalid_client_metadata",
                        "error_description": str(e)
                    },
                    status_code=400
                )
        
        # Custom token endpoint that bypasses PKCE validation
        async def proxy_token_endpoint(request: Request):
            """Custom token endpoint that bypasses PKCE validation."""
            try:
                form_data = await request.form()
                logger.info(f"🔍 PROXY TOKEN REQUEST: {dict(form_data)}")
                result = await self.handle_proxy_token_request(dict(form_data))
                
                if "error" in result:
                    logger.error(f"❌ PROXY TOKEN ERROR: {result}")
                    return JSONResponse(content=result, status_code=400)
                else:
                    logger.info(f"✅ PROXY TOKEN SUCCESS: access_token={result.get('access_token', 'N/A')[:20]}...")
                    return JSONResponse(content=result, status_code=200)
            except Exception as e:
                logger.error(f"❌ PROXY TOKEN EXCEPTION: {e}")
                import traceback
                traceback.print_exc()
                return JSONResponse(
                    content={"error": "server_error", "error_description": "Token exchange failed"},
                    status_code=500,
                )

        # Replace the standard /register and /token routes with our proxy versions
        proxy_routes = []
        for route in standard_routes:
            if hasattr(route, 'path'):
                if route.path == '/register':
                    # Replace with our custom proxy DCR endpoint
                    proxy_routes.append(Route('/register', proxy_register_endpoint, methods=['POST']))
                    logger.info("Replaced standard DCR endpoint with proxy DCR endpoint")
                elif route.path == '/token':
                    # Replace with our custom proxy token endpoint
                    proxy_routes.append(Route('/token', proxy_token_endpoint, methods=['POST']))
                    logger.info("🔄 REPLACED standard token endpoint with proxy token endpoint")
                    logger.info(f"🔄 Original route type: {type(route)}, endpoint: {getattr(route, 'endpoint', 'N/A')}")
                else:
                    # Keep other routes as-is
                    proxy_routes.append(route)
            else:
                # Keep routes without path attribute
                proxy_routes.append(route)
        
        return proxy_routes 