"""Configuration constants for MecaPy SDK."""

from pydantic_settings import BaseSettings, SettingsConfigDict


class AuthConfig(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="mecapy_auth_", case_sensitive=False, extra="ignore")

    url: str = "https://auth.mecapy.com"
    issuer: str = "http://localhost:8080/realms/mecapy"
    realm: str = "mecapy"
    client_id: str = "mecapy-api-public"


class Config(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="mecapy_", case_sensitive=False, extra="ignore")

    api_url: str = "https://api.mecapy.com"

    # Default Keycloak configuration
    # Authentication configuration
    auth: AuthConfig = AuthConfig()

    # Other defaults
    timeout: float = 30.0


config = Config()