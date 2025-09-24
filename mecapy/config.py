"""Configuration constants for MecaPy SDK."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    """
    Configuration for authentication settings.

    This class provides configuration options for authentication with OpenID Connect (OIDC)
    providers. It includes settings for issuer URLs, client identifiers, provider types,
    and optional endpoints for OIDC interaction. These settings enable integration with
    various identity providers such as Keycloak, Auth0, or other generic OIDC providers.

    Attributes
    ----------
    issuer : str
        The URL of the OIDC issuer. Default is "https://auth.mecapy.com/".
    client_id : str
        The client identifier for the application. Default is "mecapy-api-public".
    provider : str
        The type of OIDC provider for specific URL construction (e.g., "keycloak",
        "auth0", or "generic"). Default is "generic".
    authorization_endpoint : str or None
        The authorization endpoint URL if not auto-discovered from the issuer.
    token_endpoint : str or None
        The token endpoint URL if not auto-discovered from the issuer.
    url : str or None
        Deprecated: The direct URL for backward compatibility, particularly with Keycloak.
    realm : str or None
        Deprecated: The realm for backward compatibility, particularly with Keycloak.
    """

    model_config = SettingsConfigDict(env_prefix="mecapy_auth_", case_sensitive=False, extra="ignore")

    # Direct issuer URL (generic for any OIDC provider)
    issuer: str = "https://auth.mecapy.com/"
    client_id: str = "mecapy-api-public"

    # Provider type for specific URL construction if needed
    provider: str = "generic"  # "keycloak", "auth0", "generic"

    # OIDC endpoints (auto-discovered from .well-known if not provided)
    authorization_endpoint: str | None = None
    token_endpoint: str | None = None

    # Backward compatibility for Keycloak (deprecated)
    url: str | None = None
    realm: str | None = None

    def get_oidc_discovery_url(self) -> str:
        """Get the OIDC discovery URL based on issuer."""
        issuer_str = self.issuer.rstrip("/")
        return f"{issuer_str}/.well-known/openid-configuration"


class Config(BaseSettings):
    """
    Configuration for application settings.

    This class provides a configuration setup for the application, using
    default values for various settings like API URL, authentication, and
    timeouts. It leverages the `BaseSettings` from Pydantic to allow validation
    and loading of configuration data from the environment or other external
    sources. Additionally, it enforces specific configurations like environment
    prefix and case sensitivity.

    Attributes
    ----------
    api_url : str
        The base URL of the API used by the application.
    timeout : float
        Timeout duration in seconds for network calls.
    auth : AuthConfig
        Authentication configuration, including details for Keycloak integration.
    """

    model_config = SettingsConfigDict(env_prefix="mecapy_", case_sensitive=False, extra="ignore")

    api_url: str = "https://api.mecapy.com"

    # Authentication configuration
    auth: AuthConfig = AuthConfig()

    # Other defaults
    timeout: float = 30.0


config = Config()
