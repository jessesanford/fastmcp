from __future__ import annotations as _annotations

import inspect
from pathlib import Path
from typing import Annotated, Any, Literal

from pydantic import Field, model_validator
from pydantic.fields import FieldInfo
from pydantic_settings import (
    BaseSettings,
    EnvSettingsSource,
    PydanticBaseSettingsSource,
    SettingsConfigDict,
)
from typing_extensions import Self

from fastmcp.utilities.logging import get_logger

logger = get_logger(__name__)

LOG_LEVEL = Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"]

DuplicateBehavior = Literal["warn", "error", "replace", "ignore"]


class ExtendedEnvSettingsSource(EnvSettingsSource):
    """
    A special EnvSettingsSource that allows for multiple env var prefixes to be used.

    Raises a deprecation warning if the old `FASTMCP_SERVER_` prefix is used.
    """

    def get_field_value(
        self, field: FieldInfo, field_name: str
    ) -> tuple[Any, str, bool]:
        if prefixes := self.config.get("env_prefixes"):
            for prefix in prefixes:
                self.env_prefix = prefix
                env_val, field_key, value_is_complex = super().get_field_value(
                    field, field_name
                )
                if env_val is not None:
                    if prefix == "FASTMCP_SERVER_":
                        # Deprecated in 2.8.0
                        logger.warning(
                            "Using `FASTMCP_SERVER_` environment variables is deprecated. Use `FASTMCP_` instead.",
                        )
                    return env_val, field_key, value_is_complex

        return super().get_field_value(field, field_name)


class ExtendedSettingsConfigDict(SettingsConfigDict, total=False):
    env_prefixes: list[str] | None


class Settings(BaseSettings):
    """FastMCP settings."""

    model_config = ExtendedSettingsConfigDict(
        env_prefixes=["FASTMCP_", "FASTMCP_SERVER_"],
        env_file=".env",
        extra="ignore",
        env_nested_delimiter="__",
        nested_model_default_partial_update=True,
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # can remove this classmethod after deprecated FASTMCP_SERVER_ prefix is
        # removed
        return (
            init_settings,
            ExtendedEnvSettingsSource(settings_cls),
            dotenv_settings,
            file_secret_settings,
        )

    @property
    def settings(self) -> Self:
        """
        This property is for backwards compatibility with FastMCP < 2.8.0,
        which accessed fastmcp.settings.settings
        """
        # Deprecated in 2.8.0
        logger.warning(
            "Using fastmcp.settings.settings is deprecated. Use fastmcp.settings instead.",
        )
        return self

    home: Path = Path.home() / ".fastmcp"

    test_mode: bool = False
    log_level: LOG_LEVEL = "INFO"
    enable_rich_tracebacks: Annotated[
        bool,
        Field(
            description=inspect.cleandoc(
                """
                If True, will use rich tracebacks for logging.
                """
            )
        ),
    ] = True

    deprecation_warnings: Annotated[
        bool,
        Field(
            description=inspect.cleandoc(
                """
                Whether to show deprecation warnings. You can completely reset
                Python's warning behavior by running `warnings.resetwarnings()`.
                Note this will NOT apply to deprecation warnings from the
                settings class itself.
                """,
            )
        ),
    ] = True

    client_raise_first_exceptiongroup_error: Annotated[
        bool,
        Field(
            default=True,
            description=inspect.cleandoc(
                """
                Many MCP components operate in anyio taskgroups, and raise
                ExceptionGroups instead of exceptions. If this setting is True, FastMCP Clients
                will `raise` the first error in any ExceptionGroup instead of raising
                the ExceptionGroup as a whole. This is useful for debugging, but may
                mask other errors.
                """
            ),
        ),
    ] = True

    resource_prefix_format: Annotated[
        Literal["protocol", "path"],
        Field(
            default="path",
            description=inspect.cleandoc(
                """
                When perfixing a resource URI, either use path formatting (resource://prefix/path)
                or protocol formatting (prefix+resource://path). Protocol formatting was the default in FastMCP < 2.4;
                path formatting is current default.
                """
            ),
        ),
    ] = "path"

    client_init_timeout: Annotated[
        float | None,
        Field(
            description="The timeout for the client's initialization handshake, in seconds. Set to None or 0 to disable.",
        ),
    ] = None

    @model_validator(mode="after")
    def setup_logging(self) -> Self:
        """Finalize the settings."""
        from fastmcp.utilities.logging import configure_logging

        configure_logging(
            self.log_level, enable_rich_tracebacks=self.enable_rich_tracebacks
        )

        return self

    # HTTP settings
    host: str = "127.0.0.1"
    port: int = 8000
    sse_path: str = "/sse/"
    message_path: str = "/messages/"
    streamable_http_path: str = "/mcp/"
    debug: bool = False

    # error handling
    mask_error_details: Annotated[
        bool,
        Field(
            default=False,
            description=inspect.cleandoc(
                """
                If True, error details from user-supplied functions (tool, resource, prompt)
                will be masked before being sent to clients. Only error messages from explicitly
                raised ToolError, ResourceError, or PromptError will be included in responses.
                If False (default), all error details will be included in responses, but prefixed
                with appropriate context.
                """
            ),
        ),
    ] = False

    server_dependencies: Annotated[
        list[str],
        Field(
            default_factory=list,
            description="List of dependencies to install in the server environment",
        ),
    ] = []

    # StreamableHTTP settings
    json_response: bool = False
    stateless_http: bool = (
        False  # If True, uses true stateless mode (new transport per request)
    )

    # Auth settings
    default_auth_provider: Annotated[
        Literal["bearer_env"] | None,
        Field(
            description=inspect.cleandoc(
                """
                Configure the authentication provider. This setting is intended only to
                be used for remote confirugation of providers that fully support
                environment variable configuration.

                If None, no automatic configuration will take place.

                This setting is *always* overriden by any auth provider passed to the
                FastMCP constructor.
                """
            ),
        ),
    ] = None

    # OAuth Proxy settings for servers that don't support DCR
    oauth_proxy_enabled: Annotated[
        bool,
        Field(
            default=False,
            description=inspect.cleandoc(
                """
                Enable OAuth proxy mode for authorization servers that don't support
                Dynamic Client Registration (DCR). When enabled, the server will act
                as a proxy, returning pre-configured client credentials instead of
                performing actual DCR with the upstream OAuth server.
                """
            ),
        ),
    ] = False

    oauth_proxy_client_id: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Pre-configured OAuth client ID to return when clients attempt DCR.
                Required when oauth_proxy_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_proxy_client_secret: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Pre-configured OAuth client secret to return when clients attempt DCR.
                Required when oauth_proxy_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_proxy_upstream_issuer_url: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                URL of the upstream OAuth authorization server that doesn't support DCR.
                The proxy will forward actual OAuth flows (authorization, token exchange)
                to this server using the pre-configured client credentials.
                Required when oauth_proxy_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_proxy_scopes: Annotated[
        list[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Default scopes to include in client registrations when acting as
                an OAuth proxy. If not specified, will use ['read', 'write'].
                Can be provided as a comma-separated string via environment variables.
                """
            ),
        ),
    ] = None

    oauth_proxy_redirect_uris: Annotated[
        list[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Allowed redirect URIs for OAuth proxy client registrations.
                If not specified, will accept any redirect URI provided by the client.
                Can be provided as a comma-separated string via environment variables.
                """
            ),
        ),
    ] = None

    # OAuth Passthrough settings for servers that don't support DCR but need real user tokens
    oauth_passthrough_enabled: Annotated[
        bool,
        Field(
            default=False,
            description=inspect.cleandoc(
                """
                Enable OAuth passthrough mode for authorization servers that don't support
                Dynamic Client Registration (DCR) but where real user tokens with user context
                are required. Unlike OAuth proxy which manufactures tokens, passthrough mode
                passes OAuth flows to the upstream server to get real user JWT tokens.
                """
            ),
        ),
    ] = False

    oauth_passthrough_client_id: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Pre-configured OAuth client ID to return when clients attempt DCR.
                Required when oauth_passthrough_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_passthrough_client_secret: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Pre-configured OAuth client secret to return when clients attempt DCR.
                Required when oauth_passthrough_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_passthrough_upstream_issuer_url: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                URL of the upstream OAuth authorization server that doesn't support DCR.
                The passthrough provider will forward OAuth flows to this server to get
                real user tokens while proxying DCR requests locally.
                Required when oauth_passthrough_enabled is True.
                """
            ),
        ),
    ] = None

    oauth_passthrough_scopes: Annotated[
        list[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Default scopes to include in client registrations when acting as
                an OAuth passthrough provider. If not specified, will use ['read', 'write'].
                Can be provided as a comma-separated string via environment variables.
                """
            ),
        ),
    ] = None

    oauth_passthrough_redirect_uris: Annotated[
        list[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Allowed redirect URIs for OAuth passthrough client registrations.
                If not specified, will accept any redirect URI provided by the client.
                Can be provided as a comma-separated string via environment variables.
                """
            ),
        ),
    ] = None

    oauth_passthrough_upstream_jwks_uri: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                JWKS URI for JWT token validation if different from the standard discovery
                endpoint. If not specified, will use {upstream_issuer_url}/authentication/v2/keys.
                """
            ),
        ),
    ] = None

    oauth_passthrough_audience: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                Expected audience value in JWT tokens for validation. This is critical
                for some OAuth providers like Autodesk to include user context claims
                like 'userid' in the JWT tokens.
                """
            ),
        ),
    ] = None

    oauth_proxy_upstream_jwks_uri: Annotated[
        str | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                URL of the upstream OAuth server's JWKS (JSON Web Key Set) endpoint
                for validating JWT tokens. If not specified, the proxy will attempt
                to discover the JWKS endpoint using standard OAuth discovery methods.
                For Autodesk, this is typically: https://developer.api.autodesk.com/authentication/v2/keys
                """
            ),
        ),
    ] = None

    @model_validator(mode="before")
    @classmethod
    def parse_comma_separated_values(cls, data: Any) -> Any:
        """Parse comma-separated strings into lists for OAuth proxy and passthrough settings."""
        if isinstance(data, dict):
            # Handle oauth_proxy_scopes
            if "oauth_proxy_scopes" in data and isinstance(data["oauth_proxy_scopes"], str):
                data["oauth_proxy_scopes"] = [
                    scope.strip() for scope in data["oauth_proxy_scopes"].split(",") if scope.strip()
                ]
            
            # Handle oauth_proxy_redirect_uris 
            if "oauth_proxy_redirect_uris" in data and isinstance(data["oauth_proxy_redirect_uris"], str):
                data["oauth_proxy_redirect_uris"] = [
                    uri.strip() for uri in data["oauth_proxy_redirect_uris"].split(",") if uri.strip()
                ]
            
            # Handle oauth_passthrough_scopes
            if "oauth_passthrough_scopes" in data and isinstance(data["oauth_passthrough_scopes"], str):
                data["oauth_passthrough_scopes"] = [
                    scope.strip() for scope in data["oauth_passthrough_scopes"].split(",") if scope.strip()
                ]
            
            # Handle oauth_passthrough_redirect_uris 
            if "oauth_passthrough_redirect_uris" in data and isinstance(data["oauth_passthrough_redirect_uris"], str):
                data["oauth_passthrough_redirect_uris"] = [
                    uri.strip() for uri in data["oauth_passthrough_redirect_uris"].split(",") if uri.strip()
                ]
        
        return data

    include_tags: Annotated[
        set[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                If provided, only components that match these tags will be
                exposed to clients. A component is considered to match if ANY of
                its tags match ANY of the tags in the set.
                """
            ),
        ),
    ] = None
    exclude_tags: Annotated[
        set[str] | None,
        Field(
            default=None,
            description=inspect.cleandoc(
                """
                If provided, components that match these tags will be excluded
                from the server. A component is considered to match if ANY of
                its tags match ANY of the tags in the set.
                """
            ),
        ),
    ] = None


settings = Settings()
