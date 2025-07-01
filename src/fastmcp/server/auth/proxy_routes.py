from __future__ import annotations

"""Utility to create auth routes that use ProxyTokenHandler instead of the
standard TokenHandler.  This is injected at runtime by TransparentOAuthProxyProvider
so that the proxy-friendly logic is only active when necessary.
"""

from typing import Any

from starlette.routing import Route

from mcp.server.auth.routes import (
    create_auth_routes as _orig_create_auth_routes,
    TOKEN_PATH,
    cors_middleware,
)
from mcp.server.auth.middleware.client_auth import ClientAuthenticator
from mcp.server.auth.provider import OAuthAuthorizationServerProvider
from mcp.server.auth.settings import ClientRegistrationOptions, RevocationOptions
from pydantic import AnyHttpUrl

from .proxy_token_handler import ProxyTokenHandler


def create_proxy_auth_routes(
    *,
    provider: OAuthAuthorizationServerProvider[Any, Any, Any],
    issuer_url: AnyHttpUrl,
    service_documentation_url: AnyHttpUrl | None = None,
    client_registration_options: ClientRegistrationOptions | None = None,
    revocation_options: RevocationOptions | None = None,
):
    """Drop-in replacement for mcp.server.auth.routes.create_auth_routes()."""

    # First build the default route list
    routes = _orig_create_auth_routes(
        provider=provider,
        issuer_url=issuer_url,
        service_documentation_url=service_documentation_url,
        client_registration_options=client_registration_options,
        revocation_options=revocation_options,
    )

    # Build our replacement /token route
    client_authenticator = ClientAuthenticator(provider)
    proxy_handler = ProxyTokenHandler(provider, client_authenticator).handle

    proxy_route = Route(
        TOKEN_PATH,
        endpoint=cors_middleware(proxy_handler, ["POST", "OPTIONS"]),
        methods=["POST", "OPTIONS"],
    )

    # Replace the original token route
    new_routes: list[Route] = []
    for r in routes:
        if isinstance(r, Route) and r.path == TOKEN_PATH:
            continue  # skip original
        new_routes.append(r)
    new_routes.append(proxy_route)
    return new_routes 