"""Configuration constants for MecaPy SDK."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
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
        issuer_str = self.issuer.rstrip('/')
        return f"{issuer_str}/.well-known/openid-configuration"


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="mecapy_", case_sensitive=False, extra="ignore")

    api_url: str = "https://api.mecapy.com"

    # Default Keycloak configuration
    # Authentication configuration
    auth: AuthConfig = AuthConfig()

    # Other defaults
    timeout: float = 30.0


config = Config()