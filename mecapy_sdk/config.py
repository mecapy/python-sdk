"""Configuration constants for MecaPy SDK."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="mecapy_auth_", case_sensitive=False, extra="ignore")

    url: str = "https://auth.mecapy.com"
    realm: str = "mecapy"
    client_id: str = "mecapy-api-public"

    @property
    def issuer(self) -> str:
        """Build issuer URL from base URL and realm."""
        return f"{self.url}/realms/{self.realm}"


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="mecapy_", case_sensitive=False, extra="ignore")

    api_url: str = "https://api.mecapy.com"

    # Default Keycloak configuration
    # Authentication configuration
    auth: AuthConfig = AuthConfig()

    # Other defaults
    timeout: float = 30.0


config = Config()