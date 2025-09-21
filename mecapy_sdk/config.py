"""Configuration constants for MecaPy SDK."""
import os


class Config:
    # MECAPY_API_URL: str = os.getenv("MECAPY_API_URL", "https://api.mecapy.com")
    MECAPY_API_URL: str = os.getenv("MECAPY_API_URL", "http://localhost:8000")

    # Default Keycloak configuration
    MECAPY_AUTH_URL: str = os.getenv("MECAPY_AUTH_URL", "https://auth.mecapy.com")
    MECAPY_AUTH_ISSUER = "http://localhost:8080/realms/mecapy"
    MECAPY_AUTH_REALM = "mecapy"
    MECAPY_AUTH_CLIENT_ID = "mecapy-api-public"

    # Other defaults
    DEFAULT_TIMEOUT = 30.0


