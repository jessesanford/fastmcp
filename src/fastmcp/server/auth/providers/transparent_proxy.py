from __future__ import annotations

"""Transparent OAuth Proxy Provider.

This provider proxies ("passes through") OAuth 2.1 / OIDC endpoints to an upstream
Authorization Server **except** for Dynamic Client Registration (DCR) which is
implemented locally.  It is conceptually similar to the `setup_proxies=True`
behaviour of `fastapi_mcp`.

*  Well-known metadata (`/.well-known/oauth-authorization-server`) is generated
   using the FastMCP public URL **but** the `authorization_endpoint`,
   `token_endpoint`, `jwks_uri`, and (optionally) `revocation_endpoint`
   all point to the upstream server so that the browser-based portions of the
   flow are handled entirely by the upstream provider.
*  Tool / application **clients** still talk only to FastMCP.  When the client
   hits FastMCP's `/authorize` or `/token` routes the corresponding request is
   forwarded to the upstream server and the response is streamed back.
*  Because many enterprise IdPs disable Dynamic Client Registration, we keep an
   in-memory registry so _local_ clients can register even when the upstream
   provider does not support it.  For every registration we return a locally
   generated `client_id`/`client_secret` pair; when we need to talk to the
   upstream provider we instead use the *pre-configured* `upstream_client_id`
   / `upstream_client_secret`.

Note
----
This implementation purposefully keeps the scope *minimal* so it can be used as
an illustrative example.  Production use would require persistent storage,
robust error handling, caching of JWKS, etc.
"""

from collections.abc import Mapping
import secrets
import time
from typing import Any, Final
from urllib.parse import urlencode

import httpx
from mcp.server.auth.provider import (
    AccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from pydantic import AnyHttpUrl, SecretStr

from fastmcp.server.auth.auth import (
    ClientRegistrationOptions,
    OAuthProvider,
    RevocationOptions,
)
from fastmcp.server.auth.providers.bearer import BearerAuthProvider
from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS: Final[int] = 60 * 60  # 1h
DEFAULT_AUTH_CODE_EXPIRY_SECONDS: Final[int] = 5 * 60  # 5m


class TransparentOAuthProxyProvider(OAuthProvider):
    """An OAuthProvider implementation that proxies most endpoints to an upstream
    Authorization Server while locally implementing Dynamic Client Registration.
    """

    def __init__(
        self,
        *,
        # Upstream details
        upstream_authorization_endpoint: str,
        upstream_token_endpoint: str,
        upstream_jwks_uri: str,
        upstream_client_id: str,
        upstream_client_secret: str,
        # FastMCP (this server) public details
        issuer_url: AnyHttpUrl | str,
        service_documentation_url: AnyHttpUrl | str | None = None,
        client_registration_options: ClientRegistrationOptions | None = None,
        revocation_options: RevocationOptions | None = None,
        required_scopes: list[str] | None = None,
    ) -> None:
        super().__init__(
            issuer_url=issuer_url,
            service_documentation_url=service_documentation_url,
            client_registration_options=client_registration_options
            or ClientRegistrationOptions(enabled=True),
            revocation_options=revocation_options,
            required_scopes=required_scopes,
        )

        self._upstream_authorization_endpoint = upstream_authorization_endpoint
        self._upstream_token_endpoint = upstream_token_endpoint
        self._upstream_jwks_uri = upstream_jwks_uri

        self._upstream_client_id = upstream_client_id
        self._upstream_client_secret = SecretStr(upstream_client_secret)

        # Local state (DCR + auth codes)
        self._clients: dict[str, OAuthClientInformationFull] = {}
        self._auth_codes: dict[str, AuthorizationCode] = {}
        self._access_tokens: dict[str, AccessToken] = {}
        self._refresh_tokens: dict[str, RefreshToken] = {}
        # Map relations for rotation / revocation
        self._access_to_refresh: dict[str, str] = {}
        self._refresh_to_access: dict[str, str] = {}

        # Validate signature and expiration using upstream JWKS, but do NOT enforce
        # issuer matching because the tokens were issued by the upstream provider
        # (e.g., "https://developer.api.autodesk.com"), not by this proxy.
        self._bearer_validator = BearerAuthProvider(
            jwks_uri=self._upstream_jwks_uri,
            issuer=None,
            required_scopes=required_scopes,
        )

    # ---------------------------------------------------------------------
    # Client registration (implemented locally)
    # ---------------------------------------------------------------------

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        return self._clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> OAuthClientInformationFull:
        """Handle Dynamic Client Registration locally.

        Always use the pre-configured upstream credentials so that tools like
        Cursor receive deterministic values that match what they must later
        present during token exchange.  We **ignore** any client_id or
        client_secret provided by the caller.
        """

        upstream_id = self._upstream_client_id
        upstream_secret = self._upstream_client_secret.get_secret_value()

        # Merge the supplied client metadata (redirect URIs, scopes, etc.) with
        # the fixed credentials.
        enriched = OAuthClientInformationFull(  # type: ignore[call-arg]
            **client_info.model_dump(exclude={"client_id", "client_secret"}),
            client_id=upstream_id,
            client_secret=upstream_secret,
        )

        # Store (create or update)
        # Because every registration returns the same credentials, all callers
        # will share a single entry in `_clients`.  Subsequent registrations
        # simply update the stored metadata.
        self._clients[upstream_id] = enriched
        logger.debug("Registered client (shared) %s (redirect URIs: %s)", upstream_id, enriched.redirect_uris)
        return enriched

    # ------------------------------------------------------------------
    # Authorization code grant (browser) – we *redirect* to upstream.
    # ------------------------------------------------------------------

    async def authorize(
        self,
        client: OAuthClientInformationFull,
        params: AuthorizationParams,
    ) -> str:
        # Basic validation: ensure redirect_uri matches client's allowed URIs
        if params.redirect_uri not in client.redirect_uris:
            raise AuthorizeError(
                error="invalid_request",
                error_description="Redirect URI is not registered for this client.",
            )

        # Build upstream authorization URL (PKCE params forwarded as-is)
        query: dict[str, Any] = {
            "response_type": "code",
            "client_id": self._upstream_client_id,
            "redirect_uri": str(params.redirect_uri),
            "state": params.state,
        }
        if params.code_challenge:
            query["code_challenge"] = params.code_challenge
            query["code_challenge_method"] = "S256"
        if params.scopes:
            query["scope"] = " ".join(params.scopes)

        upstream_url = f"{self._upstream_authorization_endpoint}?{urlencode(query)}"
        logger.debug("Proxying authorization request to upstream: %s", upstream_url)
        # The AuthHandler will wrap this in a RedirectResponse for the browser.
        return upstream_url

    # ------------------------------------------------------------------
    # Authorization Code loading/verification (pass-through)
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: str,
    ) -> AuthorizationCode | None:
        # We do not have the ability to introspect the code locally; simply wrap
        # it so that exchange_authorization_code can forward it upstream.
        return AuthorizationCode(
            code=authorization_code,
            client_id=client.client_id,
            # We set redirect_uri to the proxy's issuer URL to satisfy the
            # pydantic type checker, but we will deliberately *omit* the
            # parameter when exchanging the code for a token to avoid
            # provider mismatch errors.
            redirect_uri=self.issuer_url,
            redirect_uri_provided_explicitly=False,
            scopes=[],
            expires_at=int(time.time() + DEFAULT_AUTH_CODE_EXPIRY_SECONDS),
            code_challenge="",  # placeholder – not validated in proxy mode
        )

    async def exchange_authorization_code(
        self,
        client: OAuthClientInformationFull,
        authorization_code: AuthorizationCode,
    ) -> OAuthToken:
        data = {
            "grant_type": "authorization_code",
            "client_id": self._upstream_client_id,
            "client_secret": self._upstream_client_secret.get_secret_value(),
            "code": authorization_code.code,
        }
        # Do NOT include a `redirect_uri` here. Some enterprise providers
        # (including Autodesk Forge) require that the value exactly match the
        # one used during the browser phase and will reject the request if it
        # differs. Since the client supplies its own `redirect_uri` during the
        # authorization step (and the proxy can't easily reproduce it here),
        # we omit it entirely.
        async with httpx.AsyncClient(timeout=10) as http:
            logger.debug("Forwarding token request to upstream %s", self._upstream_token_endpoint)
            resp = await http.post(self._upstream_token_endpoint, data=data)
            if resp.status_code >= 400:
                logger.error("Upstream token endpoint error %s: %s", resp.status_code, resp.text)
                raise TokenError("invalid_grant", "Upstream token exchange failed")
            token_response: Mapping[str, Any] = resp.json()

        # Record tokens locally for refresh / revocation bookkeeping
        access_token_value = token_response["access_token"]
        refresh_token_value = token_response.get("refresh_token") or secrets.token_hex(32)
        expires_in = int(token_response.get("expires_in", DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS))
        expires_at = int(time.time() + expires_in)

        access_token = AccessToken(
            token=access_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
        )
        self._access_tokens[access_token_value] = access_token
        if refresh_token_value:
            refresh_token = RefreshToken(
                token=refresh_token_value,
                client_id=client.client_id,
                scopes=authorization_code.scopes,
                expires_at=None,
            )
            self._refresh_tokens[refresh_token_value] = refresh_token
            self._access_to_refresh[access_token_value] = refresh_token_value
            self._refresh_to_access[refresh_token_value] = access_token_value

        return OAuthToken(**token_response)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Refresh Token grant – forwarded upstream
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: str,
    ) -> RefreshToken | None:
        return self._refresh_tokens.get(refresh_token)

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        data = {
            "grant_type": "refresh_token",
            "client_id": self._upstream_client_id,
            "client_secret": self._upstream_client_secret.get_secret_value(),
            "refresh_token": refresh_token.token,
            "scope": " ".join(scopes) if scopes else "",
        }
        async with httpx.AsyncClient(timeout=10) as http:
            resp = await http.post(self._upstream_token_endpoint, data=data)
            if resp.status_code >= 400:
                logger.error("Upstream refresh_token error %s: %s", resp.status_code, resp.text)
                raise TokenError("invalid_grant", "Upstream refresh token exchange failed")
            token_response: Mapping[str, Any] = resp.json()

        # Update bookkeeping
        new_access = token_response["access_token"]
        self._access_tokens[new_access] = AccessToken(
            token=new_access,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(time.time() + int(token_response.get("expires_in", DEFAULT_ACCESS_TOKEN_EXPIRY_SECONDS))),
        )
        if "refresh_token" in token_response:
            new_refresh = token_response["refresh_token"]
            self._refresh_tokens[new_refresh] = RefreshToken(
                token=new_refresh,
                client_id=client.client_id,
                scopes=scopes,
                expires_at=None,
            )
        return OAuthToken(**token_response)  # type: ignore[arg-type]

    # ------------------------------------------------------------------
    # Access token validation (delegated to BearerAuthProvider)
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> AccessToken | None:
        # Validate signature/claims using upstream JWKS
        return await self._bearer_validator.verify_token(token)

    # ------------------------------------------------------------------
    # Revocation (optional – forward upstream if supported)
    # ------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:  # noqa: D401
        """Revoke tokens locally and attempt upstream revocation (best-effort)."""
        if isinstance(token, AccessToken):
            self._access_tokens.pop(token.token, None)
            paired_refresh = self._access_to_refresh.pop(token.token, None)
            if paired_refresh:
                self._refresh_tokens.pop(paired_refresh, None)
                self._refresh_to_access.pop(paired_refresh, None)
        else:  # RefreshToken
            self._refresh_tokens.pop(token.token, None)
            paired_access = self._refresh_to_access.pop(token.token, None)
            if paired_access:
                self._access_tokens.pop(paired_access, None)
                self._access_to_refresh.pop(paired_access, None)

        # Best-effort upstream revocation (non-fatal)
        revocation_endpoint = None
        if self.revocation_options and hasattr(self.revocation_options, "endpoint"):
            revocation_endpoint = getattr(self.revocation_options, "endpoint")
        if revocation_endpoint:
            try:
                async with httpx.AsyncClient(timeout=10) as http:
                    await http.post(
                        revocation_endpoint,
                        data={"token": token.token},
                        auth=(self._upstream_client_id, self._upstream_client_secret.get_secret_value()),
                    )
            except Exception:  # noqa: BLE001
                logger.warning("Failed to revoke token upstream", exc_info=True)

    # ------------------------------------------------------------------
    # Utility
    # ------------------------------------------------------------------

    def generate_server_metadata(self, base_url: str) -> dict[str, Any]:
        """Return OAuth AS metadata that points browsers at the upstream endpoints
        while keeping discovery under the FastMCP host.
        """
        base = base_url.rstrip("/")
        return {
            "issuer": base,
            # Point browsers/clients at *this* server's endpoints; they will be
            # transparently proxied upstream.
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            # For JWKS we can safely return the upstream URI so that signature
            # validation happens client-side without an extra hop.
            "jwks_uri": self._upstream_jwks_uri,
            "registration_endpoint": f"{base}/oauth/register",
        } 