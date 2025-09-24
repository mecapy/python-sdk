"""MecaPy SDK - Python client for MecaPy API."""

import importlib.metadata

try:
    version = importlib.metadata.version(__name__)
except importlib.metadata.PackageNotFoundError:
    version = "0.0.0"  # Fallback for development mode

from .client import MecaPyClient
from .config import Config

__all__ = [
    "MecaPyClient",
    "Config",
    "version",
]
