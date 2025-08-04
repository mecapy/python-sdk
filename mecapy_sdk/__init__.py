"""MecaPy SDK - Python client for MecaPy API."""

from .__version__ import __version__
from .client import MecaPyClient
from .exceptions import MecaPyError, AuthenticationError, ValidationError, NotFoundError
from .config import DEFAULT_API_URL, DEFAULT_KEYCLOAK_URL, DEFAULT_REALM, DEFAULT_CLIENT_ID

__all__ = [
    "__version__",
    "MecaPyClient",
    "MecaPyError",
    "AuthenticationError", 
    "ValidationError",
    "NotFoundError",
    "DEFAULT_API_URL",
    "DEFAULT_KEYCLOAK_URL",
    "DEFAULT_REALM",
    "DEFAULT_CLIENT_ID",
]