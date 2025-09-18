"""Configuration constants for MecaPy SDK."""
import os


class Config:
    MECAPY_API_URL: str = os.getenv("MECAPY_API_URL", "https://api.mecapy.com")
    MECAPY_AUTH_URL: str = os.getenv("MECAPY_AUTH_URL", "https://auth.mecapy.com")

    # Default Keycloak configuration
    DEFAULT_REALM = "mecapy"
    DEFAULT_CLIENT_ID = "mecapy-api-public"

    # Other defaults
    DEFAULT_TIMEOUT = 30.0


