"""MecaPy SDK - Python client for MecaPy API."""

import importlib.metadata

try:
    version = importlib.metadata.version(__name__)
except importlib.metadata.PackageNotFoundError:
    version = "0.0.0"  # Fallback for development mode

from .auth import Auth, AuthBase, DefaultAuth, MecapyAuth, OAuth2Auth, ServiceAccountAuth, TokenAuth
from .client import MecaPyClient
from .config import Config
from .models import AdminResponse, APIResponse, ProtectedResponse, UploadResponse, UserInfo

__all__ = [
    "MecaPyClient",
    "Auth",
    "AuthBase",
    "TokenAuth",
    "ServiceAccountAuth",
    "OAuth2Auth",
    "DefaultAuth",
    "MecapyAuth",  # Backward compatibility
    "Config",
    "APIResponse",
    "UserInfo",
    "ProtectedResponse",
    "AdminResponse",
    "UploadResponse",
    "version",
]
